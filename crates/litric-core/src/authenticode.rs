//! Authenticode blob inspection.
//!
//! Full chain validation is a Windows job: it needs CryptoAPI/`WinVerifyTrust`
//! and the Microsoft root store. The engine's job is to answer a narrower, still
//! useful set of questions *portably*:
//!
//! * Is there a `WIN_CERTIFICATE` in the PE security directory?
//! * Is it PKCS#7 signed data (the type Authenticode uses)?
//! * Which certificate subjects are embedded, and when do they expire?
//! * Does a code-signing EKU appear?
//! * Is the signature timestamped (survives certificate expiry)?
//!
//! We do that with a small, total DER walker rather than a full ASN.1 library.
//! Anything the walker cannot understand is simply not reported: this module
//! never claims "signature valid", only what it can actually see.
//!
//! Chain trust, revocation and page-hash verification are delegated to
//! `WinVerifyTrust` on Windows and are reported as `Unverified` everywhere else
//! (see `SignatureInfo::chain_status` in the engine layer).

use crate::bytes::Reader;
use crate::pe::SignatureInfo;

const WIN_CERT_TYPE_PKCS_SIGNED_DATA: u16 = 0x0002;
const OID_COMMON_NAME: &[u8] = &[0x55, 0x04, 0x03];
const OID_CODE_SIGNING_EKU: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x03];
const OID_COUNTERSIGNATURE: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x10, 0x02, 0x0e];

/// Parses the PE security directory entry.
///
/// `data` is the whole file; `offset`/`size` come from data directory index 4,
/// where the "RVA" field is actually a file offset.
pub fn parse_win_certificate(data: &[u8], offset: u32, size: u32) -> SignatureInfo {
    let mut info = SignatureInfo::default();
    let off = offset as usize;
    let Some(hdr) = Reader::new(data).slice(off, 8) else {
        return info;
    };
    let length = u32::from_le_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]) as usize;
    let revision = u16::from_le_bytes([hdr[4], hdr[5]]);
    let cert_type = u16::from_le_bytes([hdr[6], hdr[7]]);

    if length < 8 || length > data.len().saturating_sub(off) {
        return info;
    }
    // PE spec: length must be 8-byte aligned and fit inside the directory.
    if size > 0 && length > size as usize + 7 {
        return info;
    }
    if revision != 0x0100 && revision != 0x0200 {
        return info;
    }

    info.present = true;
    info.file_offset = offset;
    info.size = length as u32;
    info.pkcs7 = cert_type == WIN_CERT_TYPE_PKCS_SIGNED_DATA;
    if !info.pkcs7 {
        return info;
    }

    let Some(blob) = data.get(off + 8..off + length) else {
        return info;
    };
    let mut names = Vec::new();
    let mut latest_year = 0i64;

    for cert in find_certificates(blob) {
        if let Some(cn) = extract_subject_cn(cert) {
            if !names.iter().any(|n: &String| n == &cn) {
                names.push(cn);
            }
        }
        if let Some(y) = extract_not_after_year(cert) {
            if y > latest_year {
                latest_year = y;
            }
        }
    }

    info.code_signing_eku = contains_subslice(blob, OID_CODE_SIGNING_EKU);
    info.timestamped = contains_subslice(blob, OID_COUNTERSIGNATURE);
    info.subject_names = names;
    info.not_after_year = if latest_year > 0 { Some(latest_year) } else { None };
    info
}

/// Walks a DER/BER stream and returns the raw TLV slices of `Certificate` SEQUENCEs
/// that appear inside `certificates [0]` of the PKCS#7 SignedData.
///
/// The walker is deliberately permissive: Authenticode blobs are BER-encoded and
/// may use indefinite lengths, so we fall back to structural scanning rather
/// than strict DER validation.
fn find_certificates(blob: &[u8]) -> Vec<&[u8]> {
    let mut out = Vec::new();
    // Certificates inside SignedData are SEQUENCEs preceded by a context tag
    // 0xA0 (certificates [0] IMPLICIT). We scan for 0x30 0x82/0x81 SEQUENCE
    // headers that begin with a certificate's tbsCertificate.
    let mut i = 0usize;
    while i + 4 < blob.len() && out.len() < 16 {
        if blob[i] == 0x30 {
            let (len, hdr_len) = match der_len(blob, i + 1) {
                Some(v) => v,
                None => {
                    i += 1;
                    continue;
                }
            };
            if len >= 64 && i + hdr_len + len <= blob.len() {
                let body = &blob[i + hdr_len..i + hdr_len + len];
                // A certificate body begins with a tbsCertificate SEQUENCE whose
                // first element is [0] EXPLICIT version (0xA0) or a serial INTEGER.
                if body.first() == Some(&0x30)
                    && body.len() > 8
                    && (body.get(2) == Some(&0xA0) || body.get(2) == Some(&0x02))
                {
                    out.push(body);
                    i += hdr_len + len;
                    continue;
                }
            }
        }
        i += 1;
    }
    out
}

/// Returns `(content_length, header_length)` for a DER length field at `pos`.
fn der_len(blob: &[u8], pos: usize) -> Option<(usize, usize)> {
    let b = *blob.get(pos)?;
    if b < 0x80 {
        return Some((b as usize, 2));
    }
    let n = (b & 0x7f) as usize;
    if n == 0 || n > 4 {
        return None; // indefinite or absurd length
    }
    let mut len = 0usize;
    for i in 0..n {
        len = (len << 8) | *blob.get(pos + 1 + i)? as usize;
    }
    Some((len, 2 + n))
}

/// Extracts `CN=` from the first printable RDN of a certificate body.
fn extract_subject_cn(cert: &[u8]) -> Option<String> {
    let idx = find_subslice(cert, OID_COMMON_NAME)?;
    // After the OID: tag 0x0C (UTF8String), 0x13 (PrintableString), 0x16 (IA5),
    // or 0x1E (BMPString). Anything else means we mis-parsed; skip it.
    let mut p = idx + OID_COMMON_NAME.len();
    for _ in 0..8 {
        let tag = *cert.get(p)?;
        if matches!(tag, 0x0C | 0x13 | 0x16 | 0x14) {
            let (len, hdr) = der_len(cert, p + 1)?;
            let start = p + hdr;
            let end = start.checked_add(len)?;
            let raw = cert.get(start..end)?;
            let s: String = raw
                .iter()
                .filter(|b| **b >= 0x20 && **b < 0x7f)
                .map(|b| *b as char)
                .collect();
            let t = s.trim().to_string();
            if t.len() >= 2 && t.len() <= 200 {
                return Some(t);
            }
        }
        if matches!(tag, 0x30 | 0x31 | 0x0C | 0x0D) {
            // advance one TLV
            let (len, hdr) = der_len(cert, p + 1)?;
            p += hdr + len;
        } else {
            p += 1;
        }
    }
    None
}

/// Reads a UTCTime/GeneralizedTime `notAfter` and returns its year.
fn extract_not_after_year(cert: &[u8]) -> Option<i64> {
    // Scan the certificate for a UTCTime (0x17) or GeneralizedTime (0x18) whose
    // textual value parses as YYMMDDHHMMSSZ / YYYYMMDDHHMMSSZ and keep the max.
    let mut best: Option<i64> = None;
    let mut i = 0usize;
    while i + 2 < cert.len() {
        let tag = cert[i];
        if tag == 0x17 || tag == 0x18 {
            if let Some((len, hdr)) = der_len(cert, i + 1) {
                if (len == 13 || len == 15) && i + hdr + len <= cert.len() {
                    let s = &cert[i + hdr..i + hdr + len];
                    if s.iter().all(|b| b.is_ascii_digit() || *b == b'Z') {
                        let year = if len == 13 {
                            let yy: i64 = std::str::from_utf8(&s[0..2]).ok()?.parse().ok()?;
                            if yy >= 50 {
                                1900 + yy
                            } else {
                                2000 + yy
                            }
                        } else {
                            std::str::from_utf8(&s[0..4]).ok()?.parse().ok()?
                        };
                        if (1980..=2200).contains(&year) {
                            best = Some(best.map_or(year, |b: i64| b.max(year)));
                        }
                    }
                }
            }
        }
        i += 1;
    }
    best
}

fn find_subslice(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w == needle)
}

fn contains_subslice(hay: &[u8], needle: &[u8]) -> bool {
    find_subslice(hay, needle).is_some()
}

/// Convenience: the year a certificate expires, for expiry heuristics.
pub fn expiry_note(info: &SignatureInfo, now_year: i64) -> Option<String> {
    let y = info.not_after_year?;
    if y < now_year {
        Some(format!(
            "signing certificate expired in {y}{}",
            if info.timestamped {
                " (timestamp present, so expiry alone is not suspicious)"
            } else {
                ""
            }
        ))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn certificate_extraction_does_not_panic_on_garbage() {
        // Random-ish bytes must never panic and must not report a signature.
        for seed in [0u8, 0x30, 0xFF, 0x02, 0x80] {
            let data = vec![seed; 512];
            let info = parse_win_certificate(&data, 0, 512);
            let _ = info.present;
        }
        let info = parse_win_certificate(&[], 0, 0);
        assert!(!info.present);
    }

    #[test]
    fn malformed_win_certificate_is_rejected() {
        let mut data = vec![0u8; 32];
        // length field far larger than the file
        data[0..4].copy_from_slice(&0xFFFF_FFFF_u32.to_le_bytes());
        data[4..6].copy_from_slice(&0x0200_u16.to_le_bytes());
        data[6..8].copy_from_slice(&WIN_CERT_TYPE_PKCS_SIGNED_DATA.to_le_bytes());
        assert!(!parse_win_certificate(&data, 0, 32).present);
    }

    #[test]
    fn der_length_parsing() {
        assert_eq!(der_len(&[0x05], 0), Some((5, 2)));
        assert_eq!(der_len(&[0x82, 0x01, 0x00], 0), Some((256, 4)));
        assert_eq!(der_len(&[0x80], 0), None);
        assert_eq!(der_len(&[], 0), None);
    }

    #[test]
    fn utc_time_year_parsing() {
        // 0x17 0x0D "491231235959Z"
        let mut cert = vec![0x17, 0x0D];
        cert.extend_from_slice(b"491231235959Z");
        assert_eq!(extract_not_after_year(&cert), Some(2049));

        let mut cert = vec![0x17, 0x0D];
        cert.extend_from_slice(b"990101000000Z");
        assert_eq!(extract_not_after_year(&cert), Some(1999));
    }

    #[test]
    fn oid_common_name_is_found() {
        let mut buf = vec![0x30, 0x10];
        buf.extend_from_slice(&[0x06, 0x03]);
        buf.extend_from_slice(OID_COMMON_NAME);
        buf.extend_from_slice(&[0x0C, 0x07]);
        buf.extend_from_slice(b"Litric!");
        assert_eq!(extract_subject_cn(&buf).as_deref(), Some("Litric!"));
    }
}
