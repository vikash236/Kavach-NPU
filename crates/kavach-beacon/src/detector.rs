//! Statistical C2 beacon rhythm and jitter analysis engine per README and ADR 001.

use crate::flow::{FLOW_FEATURES_PER_PACKET, FLOW_WINDOW_SIZE, PacketDirection, RollingFlow};
use sha2::{Digest, Sha256};

/// Maximum coefficient of variation characteristic of machine-driven sleep jitter (0.35).
pub const JITTER_CV_MAX: f64 = 0.35;

/// Minimum mean interval between heartbeats in milliseconds (500 ms).
pub const MIN_BEACON_INTERVAL_MS: f64 = 500.0;

/// Statistical evaluation metrics for a 32-packet flow window.
#[derive(Debug, Clone, PartialEq)]
pub struct BeaconDetectionResult {
    /// Mean inter-arrival delta in milliseconds.
    pub mean_delta_ms: f64,
    /// Standard deviation of inter-arrival deltas in milliseconds.
    pub std_dev_ms: f64,
    /// Coefficient of variation (sigma / mu).
    pub coefficient_of_variation: f64,
    /// Score (0.0..=1.0) indicating probability of randomized sleep jitter (e.g. 60s +/- 20%).
    pub jitter_score: f64,
    /// Score (0.0..=1.0) indicating request/response symmetry (small outbound command checks).
    pub symmetry_score: f64,
    /// Whether this flow exhibits characteristic machine-driven C2 rhythm.
    pub is_c2_beacon: bool,
    /// Confidence estimate (0.0..=1.0).
    pub confidence: f64,
    /// Formatted [32, 4] feature matrix for the NPU Head 2 input tensor.
    pub tensor_matrix: [[f32; FLOW_FEATURES_PER_PACKET]; FLOW_WINDOW_SIZE],
    /// Immutable evidence digest of the packet arrival sequence.
    pub evidence_digest: [u8; 32],
}

/// Evaluates a 32-packet flow window for machine-driven periodicity and randomized sleep jitter.
pub fn evaluate_beacon_rhythm(flow: &RollingFlow) -> Option<BeaconDetectionResult> {
    if !flow.is_full() {
        return None;
    }

    let packets = flow.packets();
    let n = packets.len();

    // 1. Calculate inter-arrival deltas (in milliseconds)
    let mut deltas = Vec::with_capacity(n - 1);
    let mut outbound_count = 0usize;
    let mut inbound_count = 0usize;
    let mut small_payload_count = 0usize;

    for i in 1..n {
        let dt_ns = packets[i]
            .timestamp_ns
            .saturating_sub(packets[i - 1].timestamp_ns);
        let dt_ms = (dt_ns as f64) / 1_000_000.0;
        deltas.push(dt_ms);

        match packets[i].direction {
            PacketDirection::Outbound => outbound_count += 1,
            PacketDirection::Inbound => inbound_count += 1,
        }

        // Heartbeat payloads are typically compact (< 512 bytes)
        if packets[i].payload_bytes <= 512 {
            small_payload_count += 1;
        }
    }

    if deltas.is_empty() {
        return None;
    }

    let count = deltas.len() as f64;
    let mean: f64 = deltas.iter().sum::<f64>() / count;

    // Standard deviation
    let variance: f64 = deltas.iter().map(|&d| (d - mean) * (d - mean)).sum::<f64>() / count;
    let std_dev = variance.sqrt();

    // Coefficient of variation: CV = sigma / mu
    let cv = if mean > 0.0 { std_dev / mean } else { 1.0 };

    // Machine-driven jitter score:
    // C2 with 10%-30% jitter exhibits CV in 0.05..0.35 with mean interval >= 500ms
    let jitter_score = if mean >= MIN_BEACON_INTERVAL_MS && cv <= JITTER_CV_MAX {
        // High score when CV is tight (<= 0.35) and intervals are consistent
        (1.0 - (cv / JITTER_CV_MAX)).clamp(0.0, 1.0)
    } else {
        0.0
    };

    // Request/response direction symmetry (e.g. 1 outbound request -> 1 inbound response)
    let balance_ratio = if outbound_count > 0 && inbound_count > 0 {
        let min_c = outbound_count.min(inbound_count) as f64;
        let max_c = outbound_count.max(inbound_count) as f64;
        min_c / max_c
    } else {
        0.0
    };

    let payload_ratio = (small_payload_count as f64) / count;
    let symmetry_score = (balance_ratio * 0.5 + payload_ratio * 0.5).clamp(0.0, 1.0);

    // C2 beacon flagged if high jitter rhythm score combined with symmetry
    let is_c2_beacon = jitter_score >= 0.5 && symmetry_score >= 0.4;
    let confidence = (jitter_score * 0.6 + symmetry_score * 0.4).clamp(0.0, 1.0);

    let tensor_matrix = flow.build_tensor_matrix()?;

    // Compute immutable SHA-256 evidence digest over timing series
    let mut hasher = Sha256::new();
    for &d in &deltas {
        hasher.update(d.to_be_bytes());
    }
    let evidence_digest: [u8; 32] = hasher.finalize().into();

    Some(BeaconDetectionResult {
        mean_delta_ms: mean,
        std_dev_ms: std_dev,
        coefficient_of_variation: cv,
        jitter_score,
        symmetry_score,
        is_c2_beacon,
        confidence,
        tensor_matrix,
        evidence_digest,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flow::PacketMeta;

    #[test]
    fn test_periodic_c2_beacon_detection() {
        let mut flow = RollingFlow::new();
        let base_ts = 1_000_000_000_000u64;

        // Simulate C2 beacon with 10-second sleep and 20% jitter (8s..12s)
        let intervals_ms = [
            9800, 10200, 10500, 9500, 10100, 9900, 10400, 9600, 10000, 10300, 9700, 10100, 9900,
            10200, 9800, 10000, 10500, 9600, 10200, 9700, 10100, 10400, 9800, 9900, 10000, 10300,
            9700, 10200, 9800, 10100, 9900, 10000,
        ];

        let mut current_ts = base_ts;
        for (i, &int_ms) in intervals_ms.iter().enumerate() {
            current_ts += int_ms * 1_000_000;
            flow.record_packet(PacketMeta {
                timestamp_ns: current_ts,
                payload_bytes: 128,
                direction: if i % 2 == 0 {
                    PacketDirection::Outbound
                } else {
                    PacketDirection::Inbound
                },
            });
        }

        let result = evaluate_beacon_rhythm(&flow).expect("evaluation succeeds");
        assert!(result.mean_delta_ms > 9500.0 && result.mean_delta_ms < 10500.0);
        assert!(
            result.coefficient_of_variation < 0.15,
            "CV must be low for jittered C2"
        );
        assert!(result.jitter_score > 0.6);
        assert!(result.is_c2_beacon, "must flag periodic C2 beacon");
        assert!(result.confidence > 0.6);
    }

    #[test]
    fn test_human_browsing_burst_not_flagged() {
        let mut flow = RollingFlow::new();
        let base_ts = 1_000_000_000_000u64;

        // Human browsing: cluster of 20 rapid packets (2ms apart), then idle 30s, then 11 rapid packets
        let mut current_ts = base_ts;
        for i in 0..FLOW_WINDOW_SIZE {
            let step_ms = if i == 20 { 30_000 } else { 2 };
            current_ts += step_ms * 1_000_000;
            flow.record_packet(PacketMeta {
                timestamp_ns: current_ts,
                payload_bytes: 1400,
                direction: PacketDirection::Inbound,
            });
        }

        let result = evaluate_beacon_rhythm(&flow).expect("evaluation succeeds");
        // Due to the extreme spike (30s vs 2ms), CV will be very large (>> 1.0)
        assert!(result.coefficient_of_variation > 1.0);
        assert_eq!(result.jitter_score, 0.0);
        assert!(
            !result.is_c2_beacon,
            "bursty human browsing must not be flagged"
        );
    }
}
