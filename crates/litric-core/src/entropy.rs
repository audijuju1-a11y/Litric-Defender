//! Shannon entropy and high-entropy analysis.
//!
//! Entropy is used as *one* signal among many. It is never sufficient on its
//! own to call a file malicious: compressed installers, JPEGs and media files
//! are legitimately high entropy. See `ranshield` for how entropy deltas are
//! combined with write-rate and decoy evidence.

/// Shannon entropy in bits per byte, 0.0..=8.0.
pub fn shannon(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let len = data.len() as f64;
    let mut h = 0.0f64;
    for &c in counts.iter() {
        if c > 0 {
            let p = c as f64 / len;
            h -= p * p.log2();
        }
    }
    h
}

/// Entropy of the whole buffer, computed without allocation.
pub fn entropy(data: &[u8]) -> f64 {
    shannon(data)
}

/// Fraction of `windows`-sized blocks whose entropy exceeds `threshold`.
///
/// Used to distinguish "compressed legitimate data" (uniformly high) from
/// "partially encrypted file" (mixed regions), and to detect a file that was
/// just overwritten with ciphertext.
pub fn high_entropy_ratio(data: &[u8], window: usize, threshold: f64) -> f64 {
    if window == 0 || data.len() < window {
        return if entropy(data) > threshold { 1.0 } else { 0.0 };
    }
    let mut high = 0usize;
    let mut total = 0usize;
    for chunk in data.chunks(window) {
        if chunk.len() < window / 2 {
            continue;
        }
        total += 1;
        if shannon(chunk) > threshold {
            high += 1;
        }
    }
    if total == 0 {
        0.0
    } else {
        high as f64 / total as f64
    }
}

/// Entropy of the first `sample` bytes; used by the RansomShield sensor to
/// classify writes without reading whole files.
pub fn sample_entropy(data: &[u8], sample: usize) -> f64 {
    let n = sample.min(data.len());
    entropy(&data[..n])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uniform_bytes_are_zero_entropy() {
        assert!(entropy(&[0u8; 4096]).abs() < f64::EPSILON);
    }

    #[test]
    fn random_bytes_approach_eight() {
        // Deterministic pseudo-random bytes (xorshift) for a stable test.
        let mut s: u64 = 0x2545_F491_4F6C_DD1D;
        let mut data = vec![0u8; 65536];
        for b in data.iter_mut() {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            *b = (s >> 24) as u8;
        }
        let e = entropy(&data);
        assert!(e > 7.9, "entropy was {e}");
    }

    #[test]
    fn half_compressed_data_has_partial_ratio() {
        let mut data = vec![0u8; 8192];
        let mut s: u64 = 0x9E37_79B9_7F4A_7C15;
        for b in data[4096..].iter_mut() {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            *b = (s >> 24) as u8;
        }
        let r = high_entropy_ratio(&data, 1024, 7.0);
        assert!((r - 0.5).abs() < 0.01, "ratio was {r}");
    }

    #[test]
    fn empty_input_is_safe() {
        assert_eq!(entropy(&[]), 0.0);
        assert_eq!(high_entropy_ratio(&[], 1024, 7.0), 0.0);
    }
}
