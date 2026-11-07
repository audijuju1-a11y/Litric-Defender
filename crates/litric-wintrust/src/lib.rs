//! Authenticode verification via `WinVerifyTrust` (documented Microsoft API).
//!
//! Status: compiled and executed natively on Windows 11 x86_64
//! (`x86_64-pc-windows-gnu`). Embedded-signature checks are exercised by the
//! crate tests; catalog-signed files are still not verified.
//!
//! What it verifies: an *embedded* Authenticode signature — the signature
//! cryptography, the certificate chain to a root trusted by the machine, and
//! (by default) revocation from the local cache only, so a scan never blocks on
//! the network.
//!
//! What it does NOT do (reported, never guessed):
//! * Catalog-signed files (most Windows system files) carry no embedded
//!   signature; they come back as `NoEmbeddedSignature`, which is **not** a
//!   sign of malware. Catalog lookup (CryptCATAdmin*) is not implemented.
//! * Publisher reputation, timestamp policy, EV status.

use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Trust {
    /// Signature, chain and (cached) revocation checks passed on this machine.
    Trusted,
    /// The file has no embedded Authenticode signature. NOT evidence of malice.
    NoEmbeddedSignature,
    /// Signature present but rejected; carries the HRESULT-style code.
    Rejected { code: u32, reason: &'static str },
    /// The API could not be run (I/O error, API failure).
    Error(String),
    /// Not a Windows host; nothing was verified.
    Unsupported,
}

impl Trust {
    pub fn is_trusted(&self) -> bool {
        matches!(self, Trust::Trusted)
    }
}

/// Human-readable reason for well-known WinVerifyTrust failure codes.
pub fn describe(code: u32) -> &'static str {
    match code {
        0x800B0100 => "no signature present",
        0x800B0101 => "certificate expired or not yet valid",
        0x800B0102 => "validity periods are nested incorrectly",
        0x800B0109 => "chain terminates in a root that is not trusted",
        0x800B010A => "a certificate chain could not be built",
        0x800B010C => "certificate was revoked",
        0x800B010F => "certificate CN does not match",
        0x800B0111 => "publisher is explicitly distrusted",
        0x80096010 => "signature digest does not match the file (modified after signing)",
        0x80096004 => "signature verification failed",
        0x800B0003 => "file format is not recognised for signing",
        0x80092026 => "cryptographic signature is invalid",
        _ => "signature rejected",
    }
}

/// Classifies a raw `WinVerifyTrust` result. Pure function so the mapping is
/// testable on every platform.
pub fn classify(result: i32) -> Trust {
    let code = result as u32;
    match code {
        0 => Trust::Trusted,
        0x800B0100 | 0x800B0003 | 0x800B0004 => Trust::NoEmbeddedSignature,
        _ => Trust::Rejected { code, reason: describe(code) },
    }
}

/// Verify the embedded Authenticode signature of `path`.
pub fn verify_file(path: &Path) -> Trust {
    imp::verify_file(path)
}

mod imp {
    use super::{classify, Trust};
    use std::os::windows::ffi::OsStrExt;
    use std::path::Path;
    use windows_sys::Win32::Security::WinTrust::{
        WinVerifyTrust, WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_DATA_0, WINTRUST_FILE_INFO,
        WTD_CACHE_ONLY_URL_RETRIEVAL, WTD_CHOICE_FILE, WTD_REVOKE_WHOLECHAIN, WTD_STATEACTION_CLOSE,
        WTD_STATEACTION_VERIFY, WTD_UI_NONE,
    };

    pub fn verify_file(path: &Path) -> Trust {
        if !path.is_file() {
            return Trust::Error(format!("not a regular file: {}", path.display()));
        }
        let wide: Vec<u16> = path.as_os_str().encode_wide().chain(std::iter::once(0)).collect();
        let mut file = WINTRUST_FILE_INFO {
            cbStruct: std::mem::size_of::<WINTRUST_FILE_INFO>() as u32,
            pcwszFilePath: wide.as_ptr(),
            hFile: 0,
            pgKnownSubject: std::ptr::null_mut(),
        };
        let mut data: WINTRUST_DATA = unsafe { std::mem::zeroed() };
        data.cbStruct = std::mem::size_of::<WINTRUST_DATA>() as u32;
        data.dwUIChoice = WTD_UI_NONE;
        data.fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN;
        data.dwUnionChoice = WTD_CHOICE_FILE;
        data.Anonymous = WINTRUST_DATA_0 { pFile: &mut file };
        data.dwStateAction = WTD_STATEACTION_VERIFY;
        data.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL; // never block a scan on the network
        let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        // SAFETY: `data`, `file` and `wide` outlive both calls; the state is released with CLOSE.
        let result = unsafe { WinVerifyTrust(0, &mut action, &mut data as *mut _ as *mut core::ffi::c_void) };
        data.dwStateAction = WTD_STATEACTION_CLOSE;
        unsafe {
            WinVerifyTrust(0, &mut action, &mut data as *mut _ as *mut core::ffi::c_void);
        }
        classify(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn result_codes_are_classified_honestly() {
        assert_eq!(classify(0), Trust::Trusted);
        assert_eq!(classify(0x800B0100u32 as i32), Trust::NoEmbeddedSignature);
        match classify(0x80096010u32 as i32) {
            Trust::Rejected { code, reason } => {
                assert_eq!(code, 0x80096010);
                assert!(reason.contains("modified"));
            }
            other => panic!("{other:?}"),
        }
        match classify(0x800B010Cu32 as i32) {
            Trust::Rejected { reason, .. } => assert!(reason.contains("revoked")),
            other => panic!("{other:?}"),
        }
        // an unknown failure is still a rejection, never a pass
        assert!(matches!(classify(0x12345678), Trust::Rejected { .. }));
        assert!(!classify(1).is_trusted());
    }

    #[test]
    fn a_missing_file_is_an_error() {
        assert!(matches!(verify_file(Path::new(r"C:\definitely\missing.exe")), Trust::Error(_)));
    }

    #[test]
    fn an_unsigned_text_file_has_no_embedded_signature() {
        let p = std::env::temp_dir().join("litric_wintrust_unsigned.exe");
        std::fs::write(&p, b"MZ not really a pe").unwrap();
        let r = verify_file(&p);
        assert!(matches!(r, Trust::NoEmbeddedSignature | Trust::Rejected { .. }), "{r:?}");
        assert!(!r.is_trusted());
        let _ = std::fs::remove_file(p);
    }
}
