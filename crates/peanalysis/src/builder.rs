//! Synthetic PE builder. Produces structurally valid (but non-executable
//! junk) PE files for tests and mutation fuzzing. Never produces real code.

pub const CODE_RX: u32 = 0x6000_0020;
pub const DATA_R: u32 = 0x4000_0040;
pub const DATA_RW: u32 = 0xC000_0040;
pub const RWX: u32 = 0xE000_0060;

#[derive(Clone)]
pub struct Sec {
    pub name: String,
    pub data: Vec<u8>,
    pub vsize: u32,
    pub chars: u32,
}
impl Sec {
    pub fn new(name: &str, data: Vec<u8>, chars: u32) -> Self {
        let vsize = data.len() as u32;
        Self { name: name.into(), data, vsize, chars }
    }
}

#[derive(Clone)]
pub struct PeBuilder {
    pub is64: bool,
    pub dll: bool,
    pub sections: Vec<Sec>,
    pub entry_section: usize,
    pub entry_offset: u32,
    pub imports: Vec<(String, Vec<String>)>,
    pub overlay: Vec<u8>,
    pub signature_blob: bool,
}

pub fn pseudo_random(n: usize, mut x: u64) -> Vec<u8> {
    (0..n)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x >> 24) as u8
        })
        .collect()
}

fn align(v: u32, a: u32) -> u32 {
    (v + a - 1) / a * a
}
fn p16(v: &mut Vec<u8>, x: u16) { v.extend_from_slice(&x.to_le_bytes()) }
fn p32(v: &mut Vec<u8>, x: u32) { v.extend_from_slice(&x.to_le_bytes()) }
fn p64(v: &mut Vec<u8>, x: u64) { v.extend_from_slice(&x.to_le_bytes()) }

impl PeBuilder {
    /// A plain, ordinary-looking program: low-entropy .text, standard names.
    pub fn benign(is64: bool) -> Self {
        let code: Vec<u8> = [0x55u8, 0x8B, 0xEC, 0x83, 0xEC, 0x10, 0x90, 0xC3].iter().cycle().take(0x600).cloned().collect();
        Self {
            is64,
            dll: false,
            sections: vec![
                Sec::new(".text", code, CODE_RX),
                Sec::new(".rdata", b"Hello from a harmless test program\0".repeat(8), DATA_R),
                Sec::new(".data", vec![0u8; 0x100], DATA_RW),
            ],
            entry_section: 0,
            entry_offset: 0,
            imports: vec![
                ("KERNEL32.dll".into(), vec!["ExitProcess".into(), "GetStdHandle".into(), "WriteFile".into()]),
                ("USER32.dll".into(), vec!["MessageBoxA".into()]),
            ],
            overlay: vec![],
            signature_blob: false,
        }
    }

    pub fn build(&self) -> Vec<u8> {
        let opt_size: u32 = if self.is64 { 0xF0 } else { 0xE0 };
        let have_idata = !self.imports.is_empty();
        let nsec = self.sections.len() + have_idata as usize;
        let headers = align(0x58 + opt_size + nsec as u32 * 40, 0x200).max(0x200);
        // virtual addresses
        let mut vas = vec![];
        let mut va = 0x1000u32;
        for s in &self.sections {
            vas.push(va);
            va = align(va + s.vsize.max(s.data.len() as u32).max(1), 0x1000);
        }
        let idata_va = va;
        // import section content
        let mut idata: Vec<u8> = vec![];
        let mut idata_dir_size = 0u32;
        if have_idata {
            let tsz = if self.is64 { 8 } else { 4 };
            let n = self.imports.len();
            idata_dir_size = ((n + 1) * 20) as u32;
            let mut off = idata_dir_size;
            let mut layout = vec![]; // (thunk_off, name_off, hint_offs)
            for (dll, funcs) in &self.imports {
                let thunk_off = off;
                off += ((funcs.len() + 1) * tsz) as u32;
                let name_off = off;
                off += dll.len() as u32 + 1;
                if off % 2 == 1 { off += 1; }
                let mut hints = vec![];
                for f in funcs {
                    hints.push(off);
                    off += 2 + f.len() as u32 + 1;
                    if off % 2 == 1 { off += 1; }
                }
                layout.push((thunk_off, name_off, hints));
            }
            for (i, _) in self.imports.iter().enumerate() {
                let (t, nm, _) = &layout[i];
                p32(&mut idata, idata_va + t);
                p32(&mut idata, 0);
                p32(&mut idata, 0);
                p32(&mut idata, idata_va + nm);
                p32(&mut idata, idata_va + t);
            }
            idata.extend_from_slice(&[0u8; 20]);
            for (i, (dll, funcs)) in self.imports.iter().enumerate() {
                let (_, _, hints) = &layout[i];
                for h in hints {
                    if self.is64 { p64(&mut idata, (idata_va + h) as u64) } else { p32(&mut idata, idata_va + h) }
                }
                if self.is64 { p64(&mut idata, 0) } else { p32(&mut idata, 0) }
                idata.extend_from_slice(dll.as_bytes());
                idata.push(0);
                if idata.len() % 2 == 1 { idata.push(0); }
                for f in funcs {
                    p16(&mut idata, 0);
                    idata.extend_from_slice(f.as_bytes());
                    idata.push(0);
                    if idata.len() % 2 == 1 { idata.push(0); }
                }
            }
        }
        let mut all: Vec<(Sec, u32)> = self.sections.iter().cloned().zip(vas.iter().cloned()).collect();
        if have_idata {
            all.push((Sec::new(".idata", idata, DATA_R), idata_va));
        }
        // raw layout
        let mut raw_ptrs = vec![];
        let mut raw_sizes = vec![];
        let mut cur = headers;
        for (s, _) in &all {
            if s.data.is_empty() {
                raw_ptrs.push(0);
                raw_sizes.push(0);
            } else {
                raw_ptrs.push(cur);
                let rs = align(s.data.len() as u32, 0x200);
                raw_sizes.push(rs);
                cur += rs;
            }
        }
        let size_of_image = {
            let (s, v) = all.last().unwrap();
            align(v + s.vsize.max(s.data.len() as u32).max(1), 0x1000)
        };
        let entry = if self.sections.is_empty() { 0 } else { vas[self.entry_section] + self.entry_offset };

        let mut f: Vec<u8> = vec![0; 0x40];
        f[0] = b'M';
        f[1] = b'Z';
        f[0x3c] = 0x40;
        f.extend_from_slice(b"PE\0\0");
        p16(&mut f, if self.is64 { 0x8664 } else { 0x14c });
        p16(&mut f, nsec as u16);
        p32(&mut f, 0x5F00_0000);
        p32(&mut f, 0);
        p32(&mut f, 0);
        p16(&mut f, opt_size as u16);
        p16(&mut f, if self.dll { 0x2022 } else if self.is64 { 0x0022 } else { 0x0102 });
        // optional header
        p16(&mut f, if self.is64 { 0x20b } else { 0x10b });
        f.extend_from_slice(&[14, 0]);
        p32(&mut f, 0x600);
        p32(&mut f, 0x200);
        p32(&mut f, 0);
        p32(&mut f, entry);
        p32(&mut f, 0x1000);
        if self.is64 {
            p64(&mut f, 0x1_4000_0000);
        } else {
            p32(&mut f, 0x2000);
            p32(&mut f, 0x40_0000);
        }
        p32(&mut f, 0x1000);
        p32(&mut f, 0x200);
        f.extend_from_slice(&[6, 0, 0, 0, 0, 0, 0, 0, 6, 0, 0, 0]);
        p32(&mut f, 0);
        p32(&mut f, size_of_image);
        p32(&mut f, headers);
        p32(&mut f, 0);
        p16(&mut f, 3);
        p16(&mut f, 0x8160);
        let sz = if self.is64 { 8 } else { 4 };
        for _ in 0..4 {
            if sz == 8 { p64(&mut f, 0x100000) } else { p32(&mut f, 0x100000) }
        }
        p32(&mut f, 0);
        p32(&mut f, 16);
        // data directories
        let sig_off = cur;
        for i in 0..16 {
            match i {
                1 if have_idata => {
                    p32(&mut f, idata_va);
                    p32(&mut f, idata_dir_size);
                }
                4 if self.signature_blob => {
                    p32(&mut f, sig_off);
                    p32(&mut f, 64);
                }
                _ => {
                    p32(&mut f, 0);
                    p32(&mut f, 0);
                }
            }
        }
        // section table
        for (i, (s, v)) in all.iter().enumerate() {
            let mut name = [0u8; 8];
            for (k, b) in s.name.bytes().take(8).enumerate() {
                name[k] = b;
            }
            f.extend_from_slice(&name);
            p32(&mut f, s.vsize.max(if s.data.is_empty() { 0 } else { s.data.len() as u32 }));
            p32(&mut f, *v);
            p32(&mut f, raw_sizes[i]);
            p32(&mut f, raw_ptrs[i]);
            p32(&mut f, 0);
            p32(&mut f, 0);
            p16(&mut f, 0);
            p16(&mut f, 0);
            p32(&mut f, s.chars);
        }
        f.resize(headers as usize, 0);
        for (i, (s, _)) in all.iter().enumerate() {
            if !s.data.is_empty() {
                f.extend_from_slice(&s.data);
                f.resize((raw_ptrs[i] + raw_sizes[i]) as usize, 0);
            }
        }
        if self.signature_blob {
            f.extend_from_slice(&[0x30u8; 64]);
        }
        f.extend_from_slice(&self.overlay);
        f
    }
}
