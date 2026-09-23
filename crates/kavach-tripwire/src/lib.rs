//! Anti-ransomware file write entropy and burst detection engine per README and ADR 002.

pub mod entropy;
pub mod sliding_window;

pub use entropy::{
    DEFAULT_BLOCK_SIZE, ENTROPY_MAX, ENTROPY_RANSOMWARE_THRESHOLD, ENTROPY_SUSPICIOUS_THRESHOLD,
    SparseEntropySummary, block_entropy_scan, differential_entropy, shannon_entropy,
};
pub use sliding_window::{
    DEFAULT_SLIDING_WINDOW_MS, DEFAULT_SUSPENSION_FILE_THRESHOLD, FileOperationEvent,
    NPU_FEATURES_PER_SLOT, NPU_TIME_SLOTS, ProcessBurstEvaluation, WriteBurstTracker,
    make_write_event,
};

/// The primary Tripwire entropy detection engine managing sliding-window write tracking.
#[derive(Debug, Default)]
pub struct EntropyEngine {
    tracker: WriteBurstTracker,
}

impl EntropyEngine {
    /// Constructs a new EntropyEngine with default 50ms sliding window and 3-file threshold.
    pub fn new() -> Self {
        Self {
            tracker: WriteBurstTracker::new(),
        }
    }

    /// Constructs an EntropyEngine with customized parameters.
    pub fn with_params(window_duration_ms: u64, suspension_file_threshold: usize) -> Self {
        Self {
            tracker: WriteBurstTracker::with_params(window_duration_ms, suspension_file_threshold),
        }
    }

    /// Ingests a file write or rename operation, calculates block entropy, and evaluates burst threat.
    pub fn ingest_operation(
        &mut self,
        pid: u32,
        path: &str,
        data: &[u8],
        is_rename: bool,
        now_ms: u64,
    ) -> Option<ProcessBurstEvaluation> {
        let event = make_write_event(pid, now_ms, path, data, is_rename);
        self.tracker.record_event(event, now_ms);
        self.tracker.evaluate_pid(pid, now_ms)
    }

    /// Scans a raw byte slice and returns its Shannon entropy.
    pub fn calculate_entropy(&self, bytes: &[u8]) -> f64 {
        shannon_entropy(bytes)
    }

    /// Returns a reference to the inner WriteBurstTracker.
    pub fn tracker(&self) -> &WriteBurstTracker {
        &self.tracker
    }

    /// Evaluates multi-block differential entropy across sparse blocks.
    pub fn evaluate_blocks(&self, block_entropies: &[f64]) -> SparseEntropySummary {
        differential_entropy(block_entropies)
    }
}
