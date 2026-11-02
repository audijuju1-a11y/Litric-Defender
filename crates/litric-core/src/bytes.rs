//! Bounds-checked little-endian reader for hostile binary input.
//!
//! Every accessor returns `Option`/`Result`; there is no unchecked indexing on
//! data that came from a scanned file.

/// A cursor-free view over a byte slice with total (never-panicking) accessors.
#[derive(Clone, Copy)]
pub struct Reader<'a> {
    data: &'a [u8],
}

impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Reader { data }
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    pub fn bytes(&self) -> &'a [u8] {
        self.data
    }

    /// Returns a sub-slice if `off..off+len` is fully in bounds.
    pub fn slice(&self, off: usize, len: usize) -> Option<&'a [u8]> {
        let end = off.checked_add(len)?;
        if end > self.data.len() {
            return None;
        }
        self.data.get(off..end)
    }

    pub fn u8_at(&self, off: usize) -> Option<u8> {
        self.data.get(off).copied()
    }

    pub fn u16_at(&self, off: usize) -> Option<u16> {
        let b = self.slice(off, 2)?;
        Some(u16::from_le_bytes([b[0], b[1]]))
    }

    pub fn u32_at(&self, off: usize) -> Option<u32> {
        let b = self.slice(off, 4)?;
        Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    pub fn u64_at(&self, off: usize) -> Option<u64> {
        let b = self.slice(off, 8)?;
        Some(u64::from_le_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    }

    /// Reads a NUL-terminated, lossily-decoded ASCII string, capped at `max`.
    pub fn cstr(&self, off: usize, max: usize) -> Option<String> {
        if off >= self.data.len() {
            return None;
        }
        let end = (off + max).min(self.data.len());
        let window = self.data.get(off..end)?;
        let nul = window.iter().position(|&b| b == 0).unwrap_or(window.len());
        Some(String::from_utf8_lossy(&window[..nul]).to_string())
    }

    /// Reads a fixed-width, space-padded name field (PE section names, COFF).
    pub fn fixed_name(&self, off: usize, len: usize) -> Option<String> {
        let raw = self.slice(off, len)?;
        let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
        let s = String::from_utf8_lossy(&raw[..end]).trim_end().to_string();
        Some(s)
    }

    /// Reads a UTF-16LE string of up to `chars` code units, stopping at NUL.
    ///
    /// Truncation is clamped rather than rejected: version resources commonly
    /// place a string flush against the end of the blob.
    pub fn utf16_at(&self, off: usize, chars: usize) -> Option<String> {
        if off >= self.data.len() {
            return None;
        }
        let want = chars.checked_mul(2)?;
        let avail = self.data.len() - off;
        // Never split a UTF-16 code unit.
        let byte_len = want.min(avail) & !1;
        if byte_len == 0 {
            return Some(String::new());
        }
        let raw = self.slice(off, byte_len)?;
        let units: Vec<u16> = raw
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .take_while(|&u| u != 0)
            .collect();
        Some(String::from_utf16_lossy(&units))
    }
}

/// Copies an 8-byte-aligned timestamp helper: seconds since the Unix epoch.
pub fn timestamp_to_year(ts: u32) -> i64 {
    // 1970-01-01 + ts seconds, approximated to a year for sanity checks.
    1970 + (ts as i64) / 31_556_952
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounds_are_enforced() {
        let data = [1u8, 2, 3, 4];
        let r = Reader::new(&data);
        assert_eq!(r.u8_at(0), Some(1));
        assert_eq!(r.u16_at(3), None);
        assert_eq!(r.u32_at(1), None);
        assert_eq!(r.slice(2, 3), None);
        assert_eq!(r.u64_at(0), None);
    }

    #[test]
    fn offsets_near_usize_max_do_not_overflow() {
        let data = [0u8; 8];
        let r = Reader::new(&data);
        assert_eq!(r.slice(usize::MAX - 1, 2), None);
    }

    #[test]
    fn cstr_is_capped() {
        let data = b"abcdefgh\0tail";
        let r = Reader::new(data);
        assert_eq!(r.cstr(0, 4).as_deref(), Some("abcd"));
        assert_eq!(r.cstr(0, 100).as_deref(), Some("abcdefgh"));
        assert_eq!(r.cstr(100, 4), None);
    }

    #[test]
    fn utf16_roundtrip() {
        let mut data = Vec::new();
        for u in "Litric".encode_utf16() {
            data.extend_from_slice(&u.to_le_bytes());
        }
        data.extend_from_slice(&[0, 0]);
        let r = Reader::new(&data);
        assert_eq!(r.utf16_at(0, 8).as_deref(), Some("Litric"));
    }
}
