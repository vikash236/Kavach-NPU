//! Sliding-window write-burst and rename-frequency tracker per README and ADR 002.

use crate::entropy::{DEFAULT_BLOCK_SIZE, SparseEntropySummary, differential_entropy};
use kavach_core::EnforcementAction;
use sha2::{Digest, Sha256};
use std::collections::HashSet;

/// Default sliding window duration in milliseconds (50ms).
pub const DEFAULT_SLIDING_WINDOW_MS: u64 = 50;

/// Number of encrypted files threshold before triggering suspension (3 files per README).
pub const DEFAULT_SUSPENSION_FILE_THRESHOLD: usize = 3;

/// Number of time slots in the Tripwire NPU Head 1 input tensor.
pub const NPU_TIME_SLOTS: usize = 10;

/// Number of features per time slot in the Tripwire NPU Head 1 input tensor.
pub const NPU_FEATURES_PER_SLOT: usize = 4;

/// A recorded file write or rename event from the telemetry stream.
#[derive(Debug, Clone, PartialEq)]
pub struct FileOperationEvent {
    pub pid: u32,
    pub timestamp_ms: u64,
    pub path: String,
    pub bytes_written: usize,
    pub block_entropies: Vec<f64>,
    pub is_rename: bool,
}

/// An evaluation result produced by the Tripwire engine for a specific process.
#[derive(Debug, Clone, PartialEq)]
pub struct ProcessBurstEvaluation {
    pub pid: u32,
    pub window_start_ms: u64,
    pub window_duration_ms: u64,
    pub total_writes: usize,
    pub total_renames: usize,
    pub total_bytes: usize,
    pub distinct_files: Vec<String>,
    pub entropy_summary: SparseEntropySummary,
    /// 10x4 feature matrix formatted for the NPU Head 1 input tensor: [1, 10, 4]
    pub tensor_matrix: [[f32; NPU_FEATURES_PER_SLOT]; NPU_TIME_SLOTS],
    pub recommended_action: EnforcementAction,
    pub corroborating_evidence_count: u8,
    pub evidence_digest: [u8; 32],
}

/// In-memory tracker maintaining sliding windows per process.
#[derive(Debug, Default)]
pub struct WriteBurstTracker {
    window_duration_ms: u64,
    suspension_file_threshold: usize,
    events: Vec<FileOperationEvent>,
}

impl WriteBurstTracker {
    /// Constructs a new tracker with default 50ms window and 3-file suspension threshold.
    pub fn new() -> Self {
        Self {
            window_duration_ms: DEFAULT_SLIDING_WINDOW_MS,
            suspension_file_threshold: DEFAULT_SUSPENSION_FILE_THRESHOLD,
            events: Vec::new(),
        }
    }

    /// Constructs a tracker with custom window duration and file threshold.
    pub fn with_params(window_duration_ms: u64, suspension_file_threshold: usize) -> Self {
        Self {
            window_duration_ms,
            suspension_file_threshold,
            events: Vec::new(),
        }
    }

    /// Records an event and purges events older than the sliding window relative to `now_ms`.
    pub fn record_event(&mut self, event: FileOperationEvent, now_ms: u64) {
        self.events.push(event);
        self.purge_expired(now_ms);
    }

    /// Purges events outside the current sliding window.
    pub fn purge_expired(&mut self, now_ms: u64) {
        let cutoff = now_ms.saturating_sub(self.window_duration_ms);
        self.events.retain(|e| e.timestamp_ms >= cutoff);
    }

    /// Extracts the 10x4 tensor matrix across active events, or a zeroed matrix if empty.
    pub fn build_tensor_matrix(&self) -> [[f32; NPU_FEATURES_PER_SLOT]; NPU_TIME_SLOTS] {
        if let Some(last_event) = self.events.last()
            && let Some(eval) = self.evaluate_pid(last_event.pid, last_event.timestamp_ms)
        {
            return eval.tensor_matrix;
        }
        [[0.0f32; NPU_FEATURES_PER_SLOT]; NPU_TIME_SLOTS]
    }

    /// Evaluates the active sliding window for a given process identifier.
    pub fn evaluate_pid(&self, pid: u32, now_ms: u64) -> Option<ProcessBurstEvaluation> {
        let pid_events: Vec<&FileOperationEvent> =
            self.events.iter().filter(|e| e.pid == pid).collect();

        if pid_events.is_empty() {
            return None;
        }

        let mut total_writes = 0usize;
        let mut total_renames = 0usize;
        let mut total_bytes = 0usize;
        let mut distinct_files = HashSet::new();
        let mut all_block_entropies = Vec::new();

        for e in &pid_events {
            if e.is_rename {
                total_renames += 1;
            } else {
                total_writes += 1;
            }
            total_bytes += e.bytes_written;
            distinct_files.insert(e.path.clone());
            all_block_entropies.extend_from_slice(&e.block_entropies);
        }

        let entropy_summary = differential_entropy(&all_block_entropies);

        // Build the [10, 4] feature matrix across 10 temporal buckets
        let bucket_duration = (self.window_duration_ms as f64) / (NPU_TIME_SLOTS as f64);
        let start_ms = now_ms.saturating_sub(self.window_duration_ms);
        let mut tensor_matrix = [[0.0f32; NPU_FEATURES_PER_SLOT]; NPU_TIME_SLOTS];

        for (i, slot) in tensor_matrix.iter_mut().enumerate().take(NPU_TIME_SLOTS) {
            let b_start = start_ms + (i as f64 * bucket_duration) as u64;
            let b_end = start_ms + ((i + 1) as f64 * bucket_duration) as u64;

            let bucket_events: Vec<&&FileOperationEvent> = pid_events
                .iter()
                .filter(|e| e.timestamp_ms >= b_start && e.timestamp_ms < b_end)
                .collect();

            if bucket_events.is_empty() {
                continue;
            }

            let mut bucket_entropies = Vec::new();
            let mut bucket_renames = 0usize;
            let mut bucket_bytes = 0usize;

            for be in bucket_events {
                bucket_entropies.extend_from_slice(&be.block_entropies);
                if be.is_rename {
                    bucket_renames += 1;
                }
                bucket_bytes += be.bytes_written;
            }

            let b_summary = differential_entropy(&bucket_entropies);

            // Feature 0: Normalized mean entropy (0.0..=1.0)
            slot[0] = (b_summary.mean_entropy / 8.0) as f32;
            // Feature 1: Rename count normalized
            slot[1] = (bucket_renames as f32 / 10.0).clamp(0.0, 1.0);
            // Feature 2: Write volume normalized (relative to 64KB per slot)
            slot[2] = (bucket_bytes as f32 / 65536.0).clamp(0.0, 1.0);
            // Feature 3: Intermittent encryption score
            slot[3] = b_summary.intermittent_encryption_score as f32;
        }

        // Determine recommended action and evidence count
        let mut evidence_count = 0u8;
        if entropy_summary.max_entropy >= 7.95 {
            evidence_count += 1;
        }
        if entropy_summary.is_anomalous {
            evidence_count += 1;
        }
        if total_renames >= 3 {
            evidence_count += 1;
        }
        if distinct_files.len() >= self.suspension_file_threshold {
            evidence_count += 1;
        }

        // Compute immutable evidence digest over affected files and stats
        let mut hasher = Sha256::new();
        hasher.update(pid.to_be_bytes());
        hasher.update((total_bytes as u64).to_be_bytes());
        let mut sorted_files: Vec<String> = distinct_files.into_iter().collect();
        sorted_files.sort();
        for f in &sorted_files {
            hasher.update(f.as_bytes());
        }
        let evidence_digest: [u8; 32] = hasher.finalize().into();

        // Recommend SuspendAndAlert if anomalous encryption touches threshold distinct files
        let recommended_action = if entropy_summary.is_anomalous
            && sorted_files.len() >= self.suspension_file_threshold
        {
            EnforcementAction::SuspendAndAlert
        } else {
            EnforcementAction::Alert
        };

        Some(ProcessBurstEvaluation {
            pid,
            window_start_ms: start_ms,
            window_duration_ms: self.window_duration_ms,
            total_writes,
            total_renames,
            total_bytes,
            distinct_files: sorted_files,
            entropy_summary,
            tensor_matrix,
            recommended_action,
            corroborating_evidence_count: evidence_count,
            evidence_digest,
        })
    }
}

/// Helper creating a file write event with pre-calculated block entropy.
pub fn make_write_event(
    pid: u32,
    timestamp_ms: u64,
    path: &str,
    data: &[u8],
    is_rename: bool,
) -> FileOperationEvent {
    let entropies = crate::entropy::block_entropy_scan(data, DEFAULT_BLOCK_SIZE);
    FileOperationEvent {
        pid,
        timestamp_ms,
        path: path.to_string(),
        bytes_written: data.len(),
        block_entropies: entropies,
        is_rename,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_pseudo_crypto_block() -> [u8; 4096] {
        let mut buf = [0u8; 4096];
        let mut state = 0xdeadbeef12345678u64;
        for b in buf.iter_mut() {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            *b = (state >> 33) as u8;
        }
        buf
    }

    #[test]
    fn test_tracker_burst_suspension_threshold() {
        let mut tracker = WriteBurstTracker::new();
        let crypto = make_pseudo_crypto_block();

        // Simulate ransomware encrypting 3 distinct files within 30ms (< 50ms window)
        tracker.record_event(
            make_write_event(1337, 1000, "C:\\Users\\victim\\doc1.locked", &crypto, true),
            1030,
        );
        tracker.record_event(
            make_write_event(1337, 1010, "C:\\Users\\victim\\doc2.locked", &crypto, true),
            1030,
        );
        tracker.record_event(
            make_write_event(1337, 1020, "C:\\Users\\victim\\doc3.locked", &crypto, true),
            1030,
        );

        let eval = tracker.evaluate_pid(1337, 1030).expect("evaluation exists");
        assert_eq!(eval.distinct_files.len(), 3);
        assert_eq!(eval.total_renames, 3);
        assert!(eval.entropy_summary.is_anomalous);
        assert_eq!(
            eval.recommended_action,
            EnforcementAction::SuspendAndAlert,
            "must recommend SuspendAndAlert when 3 distinct files are encrypted"
        );
        assert!(eval.corroborating_evidence_count >= 3);
    }

    #[test]
    fn test_tracker_purges_old_events() {
        let mut tracker = WriteBurstTracker::new();
        let crypto = make_pseudo_crypto_block();

        // Event at 1000ms
        tracker.record_event(
            make_write_event(100, 1000, "C:\\doc1.txt", &crypto, false),
            1000,
        );

        // At 1100ms (100ms later, > 50ms window), previous event is purged
        tracker.purge_expired(1100);
        let eval = tracker.evaluate_pid(100, 1100);
        assert!(eval.is_none(), "events older than 50ms must be purged");
    }

    #[test]
    fn test_tensor_matrix_format() {
        let mut tracker = WriteBurstTracker::new();
        let crypto = make_pseudo_crypto_block();

        tracker.record_event(
            make_write_event(200, 1020, "C:\\test.bin", &crypto, false),
            1030,
        );

        let eval = tracker.evaluate_pid(200, 1030).unwrap();
        // Matrix must be [10, 4]
        assert_eq!(eval.tensor_matrix.len(), NPU_TIME_SLOTS);
        assert_eq!(eval.tensor_matrix[0].len(), NPU_FEATURES_PER_SLOT);
    }
}
