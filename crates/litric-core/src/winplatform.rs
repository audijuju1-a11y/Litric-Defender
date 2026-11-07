//! Windows-only platform services used by the vault and the service host.
//!
//! This is the **only** module in `litric-core` that calls FFI. It is isolated
//! on purpose: everything else in the crate is safe Rust with no `unsafe` and no
//! platform calls. Each function below is a safe wrapper around exactly one
//! Windows API pair, with the error code preserved.
//!
//! * [`dpapi`] wraps/unwraps small secrets with the Data Protection API in
//!   **machine scope**. Machine scope is deliberate: a vault created by the
//!   installed service (LocalSystem) must remain readable by the same machine's
//!   CLI, and the file ACL — not the user identity — is the access boundary.
//!   The trade-off is stated in `docs/LIMITATIONS.md` §11.
//! * [`acl`] replaces a path's DACL with the protected SYSTEM/Administrators/
//!   owner DACL used for service data and local vaults.

#[cfg(windows)]
pub mod dpapi {
    use std::ffi::c_void;

    use windows_sys::Win32::Foundation::{GetLastError, LocalFree};
    use windows_sys::Win32::Security::Cryptography::{
        CryptProtectData, CryptUnprotectData, CRYPTPROTECT_LOCAL_MACHINE,
        CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
    };

    /// Machine scope so the service and the CLI on the same host can read the
    /// same vault. `UI_FORBIDDEN` matters: a service must never show a prompt.
    const FLAGS: u32 = CRYPTPROTECT_LOCAL_MACHINE | CRYPTPROTECT_UI_FORBIDDEN;

    /// Largest plaintext we will unwrap. The vault key is 32 bytes; the cap
    /// stops a corrupt or hostile blob from causing a huge allocation.
    const MAX_PLAINTEXT: u32 = 64 * 1024;

    #[derive(Debug)]
    pub enum DpapiError {
        /// The API failed; `code` is the Win32 error.
        Win32 { op: &'static str, code: u32 },
        /// Input or output was structurally unusable.
        Malformed(&'static str),
    }

    impl std::fmt::Display for DpapiError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                Self::Win32 { op, code } => write!(f, "{op} failed with Win32 error {code}"),
                Self::Malformed(m) => write!(f, "DPAPI blob is unusable: {m}"),
            }
        }
    }

    impl std::error::Error for DpapiError {}

    fn blob(bytes: &mut [u8]) -> CRYPT_INTEGER_BLOB {
        CRYPT_INTEGER_BLOB {
            cbData: bytes.len() as u32,
            pbData: bytes.as_mut_ptr(),
        }
    }

    /// Encrypts `plaintext` for this machine, bound to `entropy`.
    pub fn protect(plaintext: &[u8], entropy: &[u8]) -> Result<Vec<u8>, DpapiError> {
        if plaintext.is_empty() {
            return Err(DpapiError::Malformed("empty plaintext"));
        }
        let mut data = plaintext.to_vec();
        let mut entropy_bytes = entropy.to_vec();
        let input = blob(&mut data);
        let entropy_blob = blob(&mut entropy_bytes);
        let mut output = CRYPT_INTEGER_BLOB {
            cbData: 0,
            pbData: std::ptr::null_mut(),
        };

        // SAFETY: all pointers refer to live buffers for the duration of the
        // call; `output` is written by the API and freed exactly once below.
        let ok = unsafe {
            CryptProtectData(
                &input,
                std::ptr::null(),
                &entropy_blob,
                std::ptr::null(),
                std::ptr::null(),
                FLAGS,
                &mut output,
            )
        };
        if ok == 0 {
            return Err(DpapiError::Win32 {
                op: "CryptProtectData",
                code: unsafe { GetLastError() },
            });
        }

        // SAFETY: on success the API allocated `output.pbData` with `cbData`
        // bytes; we copy before freeing it.
        let bytes = unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize) };
        let copy = bytes.to_vec();
        unsafe {
            LocalFree(output.pbData as *mut c_void);
        }
        Ok(copy)
    }

    /// Decrypts a blob produced by [`protect`] on this machine.
    pub fn unprotect(blob_bytes: &[u8], entropy: &[u8]) -> Result<Vec<u8>, DpapiError> {
        if blob_bytes.is_empty() {
            return Err(DpapiError::Malformed("empty blob"));
        }
        let mut data = blob_bytes.to_vec();
        let mut entropy_bytes = entropy.to_vec();
        let input = blob(&mut data);
        let entropy_blob = blob(&mut entropy_bytes);
        let mut output = CRYPT_INTEGER_BLOB {
            cbData: 0,
            pbData: std::ptr::null_mut(),
        };

        // SAFETY: same contract as `protect`; the description pointer is null
        // because we do not need the display name.
        let ok = unsafe {
            CryptUnprotectData(
                &input,
                std::ptr::null_mut(),
                &entropy_blob,
                std::ptr::null(),
                std::ptr::null(),
                FLAGS,
                &mut output,
            )
        };
        if ok == 0 {
            return Err(DpapiError::Win32 {
                op: "CryptUnprotectData",
                code: unsafe { GetLastError() },
            });
        }
        if output.cbData > MAX_PLAINTEXT {
            unsafe {
                LocalFree(output.pbData as *mut c_void);
            }
            return Err(DpapiError::Malformed("plaintext is larger than the cap"));
        }

        // SAFETY: `output` describes a buffer allocated by the API.
        let bytes = unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize) };
        let copy = bytes.to_vec();
        unsafe {
            LocalFree(output.pbData as *mut c_void);
        }
        Ok(copy)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        const ENTROPY: &[u8] = b"litric-test-entropy";

        #[test]
        fn roundtrip_returns_the_same_bytes() {
            let secret = [7u8; 32];
            let sealed = protect(&secret, ENTROPY).expect("protect");
            assert_ne!(&sealed[..], &secret[..], "blob must not be plaintext");
            let opened = unprotect(&sealed, ENTROPY).expect("unprotect");
            assert_eq!(opened, secret);
        }

        #[test]
        fn tampered_blob_is_rejected_not_panicking() {
            let sealed = protect(&[1u8; 32], ENTROPY).expect("protect");
            let mut broken = sealed.clone();
            let last = broken.len() - 1;
            broken[last] ^= 0xff;
            assert!(unprotect(&broken, ENTROPY).is_err());
        }

        #[test]
        fn wrong_entropy_is_rejected() {
            let sealed = protect(&[2u8; 32], ENTROPY).expect("protect");
            assert!(unprotect(&sealed, b"different-entropy").is_err());
        }
    }
}

/// File identity, alternate data streams, timestamps and handle-bound deletion.
///
/// Quarantine needs more than a path: a path can be replaced between the scan,
/// the copy and the unlink. These wrappers let the vault keep one open handle
/// for the whole operation and remove *that file object* rather than whatever
/// currently sits at the path.
#[cfg(windows)]
pub mod filemeta {
    use std::ffi::c_void;
    use std::fs::{File, OpenOptions};
    use std::io::{self, Read, Write};
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::AsRawHandle;
    use std::path::{Path, PathBuf};
    use std::ptr;
    use std::time::{SystemTime, UNIX_EPOCH};

    use windows_sys::Win32::Foundation::{
        GetLastError, ERROR_HANDLE_EOF, FILETIME, GENERIC_READ, HANDLE, INVALID_HANDLE_VALUE,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        FindClose, FindFirstStreamW, FindNextStreamW, FindStreamInfoStandard,
        GetFileInformationByHandle, SetFileInformationByHandle, SetFileTime,
        BY_HANDLE_FILE_INFORMATION, DELETE, FILE_DISPOSITION_INFO, FILE_SHARE_DELETE,
        FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_WRITE_ATTRIBUTES, FileDispositionInfo,
        WIN32_FIND_STREAM_DATA,
    };

    /// Limits are enforced while reading, not just when the UI asks for them.
    pub const MAX_ALTERNATE_STREAMS: usize = 64;
    pub const MAX_ALTERNATE_STREAM_BYTES: u64 = 16 * 1024 * 1024;
    pub const MAX_ALTERNATE_TOTAL_BYTES: u64 = 64 * 1024 * 1024;

    const SHARE_ALL: u32 = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
    /// Delete-capable quarantine handles deliberately deny new writers for the
    /// short copy/verify/delete window. Existing writers cause the open to fail,
    /// in which case the vault falls back to a read-only copy and retains the
    /// source instead of deleting a file that could still be changing.
    const SHARE_READ_DELETE: u32 = FILE_SHARE_READ | FILE_SHARE_DELETE;
    const UNIX_EPOCH_FILETIME_100NS: u64 = 116_444_736_000_000_000;

    /// Stable identity of an open file object. The volume serial plus the file
    /// index distinguishes a replacement at the same path from the object we
    /// originally opened.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct FileIdentity {
        pub volume_serial: u32,
        pub file_index_high: u32,
        pub file_index_low: u32,
    }

    /// Timestamps captured from the original object. `None` means the
    /// filesystem did not expose that timestamp.
    #[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
    pub struct FileTimes {
        pub created: Option<SystemTime>,
        pub accessed: Option<SystemTime>,
        pub modified: Option<SystemTime>,
    }

    /// One named data stream. The unnamed stream is the file body, so it is
    /// deliberately excluded.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct AlternateStream {
        pub name: String,
        pub data: Vec<u8>,
    }

    fn wide(path: &Path) -> Vec<u16> {
        use std::os::windows::ffi::OsStrExt;
        path.as_os_str().encode_wide().chain(std::iter::once(0)).collect()
    }

    fn win32_error(op: &'static str) -> io::Error {
        let code = unsafe { GetLastError() };
        io::Error::other(format!("{op} failed with Win32 error {code}"))
    }

    fn stream_path(path: &Path, stream_name: &str) -> PathBuf {
        let mut os = path.as_os_str().to_os_string();
        os.push(stream_name);
        PathBuf::from(os)
    }

    /// Validates the stream suffix returned by Windows. Only ordinary
    /// `:name:$DATA` streams are supported; path separators and embedded NULs
    /// are rejected so a crafted stream cannot address another path.
    pub fn validate_stream_name(raw: &str) -> Result<String, String> {
        let rest = raw
            .strip_prefix(':')
            .ok_or_else(|| format!("stream name does not start with ':': {raw}"))?;
        if rest.len() < ":$DATA".len()
            || !rest[rest.len() - ":$DATA".len()..].eq_ignore_ascii_case(":$DATA")
        {
            return Err(format!("stream name is not a $DATA stream: {raw}"));
        }
        let inner = &rest[..rest.len() - ":$DATA".len()];
        if inner.is_empty() {
            return Err("the unnamed data stream is not an alternate stream".into());
        }
        if inner.encode_utf16().count() > 255 {
            return Err(format!("stream name is too long: {raw}"));
        }
        if inner.chars().any(|c| matches!(c, '\0' | '\\' | '/' | ':')) {
            return Err(format!("stream name contains a forbidden character: {raw}"));
        }
        Ok(format!(":{inner}:$DATA"))
    }

    /// Opens the source with read+DELETE access so the same handle can later be
    /// marked for deletion. If DELETE cannot be granted (ACL, sharing mode), the
    /// file is still read through a read-only handle and the caller is told that
    /// removal is unavailable; the vault must then retain the source.
    pub fn open_source(path: &Path, allow_delete: bool) -> io::Result<(File, bool)> {
        if allow_delete {
            let mut opts = OpenOptions::new();
            opts.access_mode(GENERIC_READ | DELETE)
                .share_mode(SHARE_READ_DELETE);
            match opts.open(path) {
                Ok(f) => return Ok((f, true)),
                Err(first) => {
                    let mut ro = OpenOptions::new();
                    ro.read(true).share_mode(SHARE_ALL);
                    return match ro.open(path) {
                        Ok(f) => Ok((f, false)),
                        Err(_) => Err(first),
                    };
                }
            }
        }
        let mut ro = OpenOptions::new();
        ro.read(true).share_mode(SHARE_ALL);
        ro.open(path).map(|f| (f, false))
    }

    pub fn file_identity(file: &File) -> io::Result<FileIdentity> {
        let mut info = BY_HANDLE_FILE_INFORMATION::default();
        // SAFETY: the handle is live for the duration of the call and `info` is
        // a correctly sized out-parameter.
        let ok = unsafe {
            GetFileInformationByHandle(file.as_raw_handle() as HANDLE, &mut info)
        };
        if ok == 0 {
            return Err(win32_error("GetFileInformationByHandle"));
        }
        Ok(FileIdentity {
            volume_serial: info.dwVolumeSerialNumber,
            file_index_high: info.nFileIndexHigh,
            file_index_low: info.nFileIndexLow,
        })
    }

    pub fn path_identity(path: &Path) -> io::Result<FileIdentity> {
        let mut opts = OpenOptions::new();
        opts.read(true).share_mode(SHARE_ALL);
        let f = opts.open(path)?;
        file_identity(&f)
    }

    /// Marks the open file object for deletion on close. This is deliberately
    /// handle-based: a path replacement after the identity check cannot redirect
    /// the delete to a different file.
    pub fn delete_by_handle(file: &File) -> io::Result<()> {
        let info = FILE_DISPOSITION_INFO { DeleteFile: true };
        // SAFETY: the handle is live, and `info` has the size and layout the
        // kernel expects for `FileDispositionInfo`.
        let ok = unsafe {
            SetFileInformationByHandle(
                file.as_raw_handle() as HANDLE,
                FileDispositionInfo,
                &info as *const FILE_DISPOSITION_INFO as *const c_void,
                std::mem::size_of::<FILE_DISPOSITION_INFO>() as u32,
            )
        };
        if ok == 0 {
            return Err(win32_error("SetFileInformationByHandle(FileDispositionInfo)"));
        }
        Ok(())
    }

    fn normalize_stream(raw: &str) -> io::Result<Option<String>> {
        if raw.eq_ignore_ascii_case("::$DATA") {
            return Ok(None);
        }
        match validate_stream_name(raw) {
            Ok(name) => Ok(Some(name)),
            Err(e) => Err(io::Error::new(io::ErrorKind::InvalidData, e)),
        }
    }

    /// Reads every named data stream through the path. The caller must verify
    /// [`path_identity`] before and after this call and delete by handle, not by
    /// path.
    pub fn read_alternate_streams(path: &Path) -> io::Result<Vec<AlternateStream>> {
        let path_w = wide(path);
        let mut find_data = WIN32_FIND_STREAM_DATA::default();
        // SAFETY: `path_w` is NUL-terminated and `find_data` is a correctly
        // sized out-parameter for `FindStreamInfoStandard`.
        let handle = unsafe {
            FindFirstStreamW(
                path_w.as_ptr(),
                FindStreamInfoStandard,
                &mut find_data as *mut WIN32_FIND_STREAM_DATA as *mut c_void,
                0,
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            let err = win32_error("FindFirstStreamW");
            if err.raw_os_error() == Some(ERROR_HANDLE_EOF as i32) {
                return Ok(Vec::new());
            }
            return Err(err);
        }

        let collected = (|| -> io::Result<Vec<AlternateStream>> {
            let mut out = Vec::new();
            let mut total = 0u64;
            loop {
                let raw = {
                    let mut len = 0usize;
                    while len < find_data.cStreamName.len() && find_data.cStreamName[len] != 0 {
                        len += 1;
                    }
                    String::from_utf16_lossy(&find_data.cStreamName[..len])
                };
                if let Some(name) = normalize_stream(&raw)? {
                    if out.len() >= MAX_ALTERNATE_STREAMS {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("more than {MAX_ALTERNATE_STREAMS} alternate streams"),
                        ));
                    }
                    let mut stream = OpenOptions::new()
                        .read(true)
                        .share_mode(SHARE_ALL)
                        .open(stream_path(path, &name))?;
                    let mut data = Vec::new();
                    let mut limited = (&mut stream).take(MAX_ALTERNATE_STREAM_BYTES + 1);
                    limited.read_to_end(&mut data)?;
                    if data.len() as u64 > MAX_ALTERNATE_STREAM_BYTES {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("alternate stream `{name}` exceeds the size limit"),
                        ));
                    }
                    total = total.checked_add(data.len() as u64).ok_or_else(|| {
                        io::Error::new(io::ErrorKind::InvalidData, "alternate-stream total overflow")
                    })?;
                    if total > MAX_ALTERNATE_TOTAL_BYTES {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "alternate streams exceed the total size limit",
                        ));
                    }
                    out.push(AlternateStream { name, data });
                }

                // SAFETY: the find handle is valid until FindClose below.
                let more = unsafe {
                    FindNextStreamW(
                        handle,
                        &mut find_data as *mut WIN32_FIND_STREAM_DATA as *mut c_void,
                    )
                };
                if more == 0 {
                    let code = unsafe { GetLastError() };
                    if code != 0 && code != ERROR_HANDLE_EOF {
                        return Err(io::Error::other(format!(
                            "FindNextStreamW failed with Win32 error {code}"
                        )));
                    }
                    break;
                }
            }
            out.sort_by_key(|s| s.name.to_ascii_lowercase());
            Ok(out)
        })();
        // SAFETY: `handle` was returned by FindFirstStreamW and is closed once.
        unsafe {
            FindClose(handle);
        }
        collected
    }

    /// Writes named streams to a file that Litric created. Every name is
    /// validated again because the payload is untrusted input until AEAD and
    /// structural checks pass.
    pub fn write_alternate_streams(path: &Path, streams: &[AlternateStream]) -> io::Result<()> {
        if streams.len() > MAX_ALTERNATE_STREAMS {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "too many alternate streams",
            ));
        }
        let mut total = 0u64;
        for stream in streams {
            let name = validate_stream_name(&stream.name)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            if stream.data.len() as u64 > MAX_ALTERNATE_STREAM_BYTES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("alternate stream `{name}` exceeds the size limit"),
                ));
            }
            total = total.checked_add(stream.data.len() as u64).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "alternate-stream total overflow")
            })?;
            if total > MAX_ALTERNATE_TOTAL_BYTES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "alternate streams exceed the total size limit",
                ));
            }
            let mut f = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .share_mode(SHARE_ALL)
                .open(stream_path(path, &name))?;
            f.write_all(&stream.data)?;
            f.sync_all()?;
        }
        Ok(())
    }

    fn to_filetime(t: SystemTime) -> io::Result<FILETIME> {
        let intervals = match t.duration_since(UNIX_EPOCH) {
            Ok(d) => {
                let delta = d
                    .as_secs()
                    .checked_mul(10_000_000)
                    .and_then(|v| v.checked_add(d.subsec_nanos() as u64 / 100))
                    .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "timestamp overflow"))?;
                UNIX_EPOCH_FILETIME_100NS.checked_add(delta)
            }
            Err(e) => {
                let d = e.duration();
                let delta = d
                    .as_secs()
                    .checked_mul(10_000_000)
                    .and_then(|v| v.checked_add(d.subsec_nanos() as u64 / 100))
                    .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "timestamp overflow"))?;
                UNIX_EPOCH_FILETIME_100NS.checked_sub(delta)
            }
        }
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "timestamp outside FILETIME range"))?;
        Ok(FILETIME {
            dwLowDateTime: intervals as u32,
            dwHighDateTime: (intervals >> 32) as u32,
        })
    }

    /// Applies creation, access and modification times to an existing path. The
    /// handle is opened with `FILE_WRITE_ATTRIBUTES` only, so content access is
    /// not granted unnecessarily.
    pub fn apply_file_times(path: &Path, times: &FileTimes) -> io::Result<()> {
        let mut opts = OpenOptions::new();
        opts.access_mode(FILE_WRITE_ATTRIBUTES).share_mode(SHARE_ALL);
        let f = opts.open(path)?;
        let created = times.created.map(to_filetime).transpose()?;
        let accessed = times.accessed.map(to_filetime).transpose()?;
        let modified = times.modified.map(to_filetime).transpose()?;
        let created_ptr = created.as_ref().map_or(ptr::null(), |v| v as *const FILETIME);
        let accessed_ptr = accessed.as_ref().map_or(ptr::null(), |v| v as *const FILETIME);
        let modified_ptr = modified.as_ref().map_or(ptr::null(), |v| v as *const FILETIME);
        // SAFETY: the handle is live; each pointer is either null (leave that
        // timestamp unchanged) or points to a FILETIME alive for the call.
        let ok = unsafe {
            SetFileTime(
                f.as_raw_handle() as HANDLE,
                created_ptr,
                accessed_ptr,
                modified_ptr,
            )
        };
        if ok == 0 {
            return Err(win32_error("SetFileTime"));
        }
        Ok(())
    }

    /// Test/diagnostic helper: reads the three timestamps from an open handle.
    pub fn capture_file_times(file: &File) -> io::Result<FileTimes> {
        let meta = file.metadata()?;
        Ok(FileTimes {
            created: meta.created().ok(),
            accessed: meta.accessed().ok(),
            modified: meta.modified().ok(),
        })
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::io::Write;
        use std::time::Duration;

        fn temp_file(tag: &str) -> PathBuf {
            let path = std::env::temp_dir().join(format!(
                "litric-filemeta-{tag}-{}-{}",
                std::process::id(),
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_nanos())
                    .unwrap_or(0)
            ));
            let mut f = File::create(&path).unwrap();
            f.write_all(b"identity fixture").unwrap();
            path
        }

        #[test]
        fn stream_names_are_validated_not_concatenated_blindly() {
            assert_eq!(validate_stream_name(":Zone.Identifier:$DATA").unwrap(), ":Zone.Identifier:$DATA");
            assert!(validate_stream_name(":../escape:$DATA").is_err());
            assert!(validate_stream_name(":foo\\bar:$DATA").is_err());
            assert!(validate_stream_name(":$DATA").is_err());
            assert!(validate_stream_name(":foo").is_err());
        }

        #[test]
        fn alternate_streams_roundtrip() {
            let path = temp_file("ads");
            let streams = vec![
                AlternateStream {
                    name: ":Zone.Identifier:$DATA".into(),
                    data: b"[ZoneTransfer]\r\nZoneId=3\r\n".to_vec(),
                },
                AlternateStream {
                    name: ":LitricTest:$DATA".into(),
                    data: vec![0, 1, 2, 255],
                },
            ];
            write_alternate_streams(&path, &streams).unwrap();
            let read = read_alternate_streams(&path).unwrap();
            let mut expected = streams.clone();
            expected.sort_by_key(|s| s.name.to_ascii_lowercase());
            assert_eq!(read, expected);
            let _ = std::fs::remove_file(&path);
        }

        #[test]
        fn file_times_roundtrip_through_set_file_time() {
            let path = temp_file("times");
            let stamp = UNIX_EPOCH + Duration::from_secs(1_700_000_123);
            let times = FileTimes {
                created: Some(stamp),
                accessed: Some(stamp),
                modified: Some(stamp),
            };
            apply_file_times(&path, &times).unwrap();
            let read = capture_file_times(&File::open(&path).unwrap()).unwrap();
            for (label, actual) in [
                ("created", read.created),
                ("accessed", read.accessed),
                ("modified", read.modified),
            ] {
                let actual = actual.unwrap_or_else(|| panic!("{label} timestamp missing"));
                let secs = actual.duration_since(UNIX_EPOCH).unwrap().as_secs();
                assert_eq!(secs, 1_700_000_123, "{label} timestamp not preserved");
            }
            let _ = std::fs::remove_file(&path);
        }

        #[test]
        fn delete_by_handle_targets_the_open_object_not_a_replacement_path() {
            let original = temp_file("identity-original");
            let replacement = temp_file("identity-replacement");
            let (file, delete_capable) = open_source(&original, true).unwrap();
            assert!(delete_capable, "test fixture should grant DELETE");
            let identity = file_identity(&file).unwrap();

            // Move the open object away and put a different file at the path.
            let moved = original.with_extension("moved");
            let _ = std::fs::remove_file(&moved);
            std::fs::rename(&original, &moved).unwrap();
            let replacement_bytes = std::fs::read(&replacement).unwrap();
            std::fs::write(&original, &replacement_bytes).unwrap();

            assert_ne!(path_identity(&original).unwrap(), identity);
            delete_by_handle(&file).unwrap();
            drop(file);

            assert!(!moved.exists(), "the object opened by the handle must be deleted");
            assert_eq!(
                std::fs::read(&original).unwrap(),
                replacement_bytes,
                "a replacement at the original path must survive"
            );
            let _ = std::fs::remove_file(&original);
            let _ = std::fs::remove_file(&replacement);
        }
    }
}

#[cfg(windows)]
pub mod acl {
    use std::ffi::c_void;
    use std::io;
    use std::path::Path;

    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows_sys::Win32::Security::{SetFileSecurityW, DACL_SECURITY_INFORMATION};

    /// Protected DACL: SYSTEM and Administrators full control, plus owner rights
    /// so the creating user cannot lock themselves out. Inheritance is removed
    /// (`D:P`), otherwise `%ProgramData%`'s `Users: read` ACE would let any local
    /// user read the API token or the vault key.
    pub const SERVICE_DATA_SDDL: &str = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;OW)";

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    /// Reads the effective DACL of `path` as SDDL. Used by tests and by
    /// diagnostics; never by a decision path.
    pub fn dacl_sddl(path: &Path) -> io::Result<String> {
        use windows_sys::Win32::Security::Authorization::ConvertSecurityDescriptorToStringSecurityDescriptorW;
        use windows_sys::Win32::Security::GetFileSecurityW;

        let path_w = wide(&path.to_string_lossy());
        let mut needed = 0u32;
        // SAFETY: first call asks for the required buffer size; a null buffer is
        // the documented way to do that.
        unsafe {
            GetFileSecurityW(
                path_w.as_ptr(),
                DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                0,
                &mut needed,
            );
        }
        if needed == 0 {
            return Err(io::Error::last_os_error());
        }
        let mut descriptor = vec![0u8; needed as usize];
        // SAFETY: the buffer is `needed` bytes and the API writes at most that.
        let ok = unsafe {
            GetFileSecurityW(
                path_w.as_ptr(),
                DACL_SECURITY_INFORMATION,
                descriptor.as_mut_ptr() as *mut c_void,
                needed,
                &mut needed,
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }

        let mut sddl: *mut u16 = std::ptr::null_mut();
        // SAFETY: `descriptor` is a valid security descriptor for this call.
        let ok = unsafe {
            ConvertSecurityDescriptorToStringSecurityDescriptorW(
                descriptor.as_mut_ptr() as *mut c_void,
                SDDL_REVISION_1,
                DACL_SECURITY_INFORMATION,
                &mut sddl,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 || sddl.is_null() {
            return Err(io::Error::last_os_error());
        }
        let mut len = 0usize;
        // SAFETY: the API returns a nul-terminated UTF-16 string.
        while unsafe { *sddl.add(len) } != 0 {
            len += 1;
        }
        let text = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(sddl, len) });
        // SAFETY: the string was allocated by the conversion API.
        unsafe {
            LocalFree(sddl as *mut c_void);
        }
        Ok(text)
    }

    /// Replaces the DACL of `path` (file or directory).
    ///
    /// Returns the Win32 error through `io::Error`, so callers can report the
    /// real reason instead of a generic failure.
    pub fn restrict_to_system_and_admins(path: &Path) -> io::Result<()> {
        let sddl = wide(SERVICE_DATA_SDDL);
        let mut descriptor: *mut c_void = std::ptr::null_mut();
        // SAFETY: `sddl` is nul-terminated and the returned descriptor is freed
        // below on every path.
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }

        let path_w = wide(&path.to_string_lossy());
        // SAFETY: `path_w` is nul-terminated and `descriptor` is a live security
        // descriptor from the call above.
        let applied = unsafe { SetFileSecurityW(path_w.as_ptr(), DACL_SECURITY_INFORMATION, descriptor) };
        let code = if applied == 0 {
            Some(io::Error::last_os_error())
        } else {
            None
        };
        // SAFETY: the descriptor came from LocalAlloc inside the conversion API.
        unsafe {
            LocalFree(descriptor);
        }
        match code {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn sddl_is_protected_and_grants_only_the_expected_principals() {
            assert!(SERVICE_DATA_SDDL.starts_with("D:P"));
            assert!(SERVICE_DATA_SDDL.contains("(A;OICI;FA;;;SY)"));
            assert!(SERVICE_DATA_SDDL.contains("(A;OICI;FA;;;BA)"));
            assert!(SERVICE_DATA_SDDL.contains("(A;OICI;FA;;;OW)"));
            assert!(!SERVICE_DATA_SDDL.contains(";;;WD)"), "world access");
            assert!(!SERVICE_DATA_SDDL.contains(";;;BU)"), "users group access");
        }
    }
}
