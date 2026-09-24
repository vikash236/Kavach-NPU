//! Shannon block entropy and differential sparse-block analysis per README and ADR 002.

/// Theoretical maximum Shannon entropy for byte symbols (log2(256) = 8.0 bits/byte).
pub const ENTROPY_MAX: f64 = 8.0;

/// Threshold above which ciphertext/encrypted data is recognized (7.95 bits/byte).
pub const ENTROPY_RANSOMWARE_THRESHOLD: f64 = 7.95;

/// Suspicious entropy threshold indicating dense compression or partial crypto (7.50 bits/byte).
pub const ENTROPY_SUSPICIOUS_THRESHOLD: f64 = 7.50;

/// Standard I/O block size evaluated by the Tripwire engine (4 KB).
pub const DEFAULT_BLOCK_SIZE: usize = 4096;

/// Computes the exact Shannon entropy of a byte slice: H(X) = -sum(p * log2(p)).
///
/// Returns a value between 0.0 (uniform single byte) and 8.0 (uniformly random bytes).
pub fn shannon_entropy(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }

    let mut counts = [0usize; 256];
    for &b in bytes {
        counts[b as usize] += 1;
    }

    let n = bytes.len() as f64;
    let mut entropy = 0.0;

    for &count in &counts {
        if count > 0 {
            let p = (count as f64) / n;
            entropy -= p * p.log2();
        }
    }

    entropy
}

/// Scans a byte buffer in consecutive chunks of `block_size` and returns the entropy of each block.
pub fn block_entropy_scan(data: &[u8], block_size: usize) -> Vec<f64> {
    if data.is_empty() || block_size == 0 {
        return Vec::new();
    }

    data.chunks(block_size).map(shannon_entropy).collect()
}

/// Summary metrics derived from multi-block differential entropy analysis.
#[derive(Debug, Clone, PartialEq)]
pub struct SparseEntropySummary {
    /// Total number of blocks evaluated.
    pub total_blocks: usize,
    /// Arithmetic mean of block entropies.
    pub mean_entropy: f64,
    /// Maximum observed block entropy.
    pub max_entropy: f64,
    /// Minimum observed block entropy.
    pub min_entropy: f64,
    /// Variance across block entropies.
    pub variance: f64,
    /// Ratio of blocks exceeding the ransomware threshold (H >= 7.95).
    pub high_entropy_ratio: f64,
    /// Metric (0.0..=1.0) indicating probability of intermittent/stride encryption.
    pub intermittent_encryption_score: f64,
    /// Whether this pattern triggers ransomware detection (either sustained or intermittent).
    pub is_anomalous: bool,
}

/// Evaluates differential entropy across sparse blocks to defeat intermittent encryption
/// (such as LockBit 3.0 and BlackCat/ALPHV skipping blocks).
pub fn differential_entropy(blocks: &[f64]) -> SparseEntropySummary {
    if blocks.is_empty() {
        return SparseEntropySummary {
            total_blocks: 0,
            mean_entropy: 0.0,
            max_entropy: 0.0,
            min_entropy: 0.0,
            variance: 0.0,
            high_entropy_ratio: 0.0,
            intermittent_encryption_score: 0.0,
            is_anomalous: false,
        };
    }

    let n = blocks.len() as f64;
    let mut sum = 0.0;
    let mut max_e: f64 = 0.0;
    let mut min_e: f64 = ENTROPY_MAX;
    let mut high_count = 0usize;

    for &e in blocks {
        sum += e;
        if e > max_e {
            max_e = e;
        }
        if e < min_e {
            min_e = e;
        }
        if e >= ENTROPY_RANSOMWARE_THRESHOLD {
            high_count += 1;
        }
    }

    let mean = sum / n;

    // Variance calculation
    let mut var_sum = 0.0;
    for &e in blocks {
        let diff = e - mean;
        var_sum += diff * diff;
    }
    let variance = var_sum / n;

    let high_ratio = (high_count as f64) / n;

    // Detect alternating high-low delta transitions characteristic of intermittent encryption
    let mut delta_transitions = 0usize;
    if blocks.len() > 1 {
        for w in blocks.windows(2) {
            let delta = (w[1] - w[0]).abs();
            // Significant transition between low/moderate and high entropy
            if delta >= 2.0
                && (w[0] >= ENTROPY_SUSPICIOUS_THRESHOLD || w[1] >= ENTROPY_SUSPICIOUS_THRESHOLD)
            {
                delta_transitions += 1;
            }
        }
    }

    let transition_ratio = if blocks.len() > 1 {
        (delta_transitions as f64) / ((blocks.len() - 1) as f64)
    } else {
        0.0
    };

    // Intermittent score combines high entropy presence with high variance and transitions
    let intermittent_score = if max_e >= ENTROPY_RANSOMWARE_THRESHOLD && variance >= 1.0 {
        ((transition_ratio * 0.5) + (variance / 8.0 * 0.5)).clamp(0.0, 1.0)
    } else {
        0.0
    };

    // Anomalous if sustained high entropy OR intermittent encryption detected
    let is_anomalous = high_ratio >= 0.7 || (high_count >= 2 && intermittent_score >= 0.35);

    SparseEntropySummary {
        total_blocks: blocks.len(),
        mean_entropy: mean,
        max_entropy: max_e,
        min_entropy: min_e,
        variance,
        high_entropy_ratio: high_ratio,
        intermittent_encryption_score: intermittent_score,
        is_anomalous,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zero_bytes_entropy_zero() {
        let zeros = [0u8; 4096];
        assert_eq!(shannon_entropy(&zeros), 0.0);
    }

    #[test]
    fn test_single_byte_entropy_zero() {
        let repeated = [0x42u8; 1000];
        assert_eq!(shannon_entropy(&repeated), 0.0);
    }

    #[test]
    fn test_ascii_text_entropy_range() {
        let text = b"The quick brown fox jumps over the lazy dog. In cryptography and computer security, entropy measures the degree of randomness or unpredictability in a set of data.";
        let h = shannon_entropy(text);
        // Typical English ASCII text falls between 4.0 and 4.8
        assert!(h > 3.5 && h < 5.0, "actual text entropy: {h}");
    }

    #[test]
    fn test_uniform_random_entropy_near_maximum() {
        // Deterministic pseudo-random generation with high uniform distribution (simulating AES ciphertext)
        let mut pseudo_crypto = [0u8; 4096];
        let mut state = 0x12345678u64;
        for b in pseudo_crypto.iter_mut() {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            *b = (state >> 33) as u8;
        }

        let h = shannon_entropy(&pseudo_crypto);
        assert!(
            h >= ENTROPY_RANSOMWARE_THRESHOLD,
            "actual crypto entropy: {h}"
        );
        assert!(h <= ENTROPY_MAX);
    }

    #[test]
    fn test_block_entropy_scanner() {
        let mut data = Vec::with_capacity(8192);
        // Block 1: zeroes (4096 bytes)
        data.extend_from_slice(&[0u8; 4096]);
        // Block 2: pseudo crypto (4096 bytes)
        let mut crypto = [0u8; 4096];
        let mut state = 0x9abcdef0u64;
        for b in crypto.iter_mut() {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            *b = (state >> 33) as u8;
        }
        data.extend_from_slice(&crypto);

        let blocks = block_entropy_scan(&data, 4096);
        assert_eq!(blocks.len(), 2);
        assert_eq!(blocks[0], 0.0);
        assert!(blocks[1] >= ENTROPY_RANSOMWARE_THRESHOLD);
    }

    #[test]
    fn test_intermittent_encryption_detection() {
        // Alternating blocks: Plaintext -> Encrypted -> Plaintext -> Encrypted
        let text_entropy = 4.2;
        let crypto_entropy = 7.98;

        let intermittent_blocks = vec![
            text_entropy,
            crypto_entropy,
            text_entropy,
            crypto_entropy,
            text_entropy,
            crypto_entropy,
        ];

        let summary = differential_entropy(&intermittent_blocks);
        assert_eq!(summary.total_blocks, 6);
        assert!(summary.max_entropy >= ENTROPY_RANSOMWARE_THRESHOLD);
        assert!(summary.intermittent_encryption_score > 0.35);
        assert!(
            summary.is_anomalous,
            "intermittent encryption must trigger anomaly"
        );
    }

    #[test]
    fn test_normal_file_not_anomalous() {
        // Plaintext file blocks
        let normal_blocks = vec![4.1, 4.2, 4.0, 4.3, 4.1];
        let summary = differential_entropy(&normal_blocks);
        assert!(!summary.is_anomalous);
        assert_eq!(summary.intermittent_encryption_score, 0.0);
    }

    #[test]
    fn test_empty_input_entropy_zero() {
        assert_eq!(shannon_entropy(&[]), 0.0);
    }

    #[test]
    fn test_two_byte_values_entropy_one() {
        let data: Vec<u8> = (0..256).flat_map(|_| [0x00, 0xFF]).collect();
        let h = shannon_entropy(&data);
        assert!((h - 1.0).abs() < 0.001);
    }

    #[test]
    fn test_block_entropy_scan_empty_data() {
        assert!(block_entropy_scan(&[], 4096).is_empty());
    }

    #[test]
    fn test_block_entropy_scan_zero_block_size() {
        assert!(block_entropy_scan(&[0; 100], 0).is_empty());
    }

    #[test]
    fn test_differential_entropy_single_block() {
        let summary = differential_entropy(&[7.98]);
        assert_eq!(summary.total_blocks, 1);
        assert_eq!(summary.high_entropy_ratio, 1.0);
        assert!(summary.is_anomalous);
    }

    #[test]
    fn test_differential_entropy_empty_blocks() {
        let summary = differential_entropy(&[]);
        assert_eq!(summary.total_blocks, 0);
        assert_eq!(summary.mean_entropy, 0.0);
        assert!(!summary.is_anomalous);
    }
}
