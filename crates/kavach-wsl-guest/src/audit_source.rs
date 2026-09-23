//! Guest-side file telemetry extraction and record formulation per ADR 005.

use kavach_core::ArtifactVersion;
use kavach_wsl::wire::is_normalized_mnt_path;
use kavach_wsl::{GuestFileOperation, GuestWriteRecord};
use sha2::{Digest, Sha256};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

/// Formats a raw file write into a valid ADR 005 GuestWriteRecord.
pub struct GuestAuditSource {
    distribution_id: [u8; 16],
    sequence_counter: u64,
    start_instant: Instant,
}

impl GuestAuditSource {
    pub fn new(distribution_id: [u8; 16]) -> Self {
        Self {
            distribution_id,
            sequence_counter: 1,
            start_instant: Instant::now(),
        }
    }

    /// Captures a guest file operation and constructs a verified `GuestWriteRecord`.
    pub fn record_operation(
        &mut self,
        pid: u32,
        executable_path: &str,
        normalized_path: &str,
        operation: GuestFileOperation,
        byte_range_start: u64,
        byte_range_length: u64,
    ) -> Result<GuestWriteRecord, String> {
        if !is_normalized_mnt_path(normalized_path) {
            return Err(format!("path '{normalized_path}' is not a normalized /mnt/<drive>/ path"));
        }

        let seq = self.sequence_counter;
        self.sequence_counter += 1;

        let monotonic_ns = self.start_instant.elapsed().as_nanos() as u64;
        let realtime_ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;

        let mut exe_hasher = Sha256::new();
        exe_hasher.update(executable_path.as_bytes());
        let exe_hash: [u8; 32] = exe_hasher.finalize().into();

        // cgroup SHA-256 placeholder or computed from path
        let mut cgroup_hasher = Sha256::new();
        cgroup_hasher.update(format!("/sys/fs/cgroup/user.slice/user-{pid}.slice").as_bytes());
        let cgroup_hash: [u8; 32] = cgroup_hasher.finalize().into();

        Ok(GuestWriteRecord {
            version: ArtifactVersion { major: 1, minor: 0 },
            sequence_number: seq,
            guest_monotonic_ns: monotonic_ns,
            guest_realtime_ns: realtime_ns,
            guest_process_id: pid,
            guest_process_start_ticks: 1000,
            distribution_id: self.distribution_id,
            mount_namespace_id: 4026531840,
            executable_sha256: exe_hash,
            cgroup_sha256: cgroup_hash,
            operation,
            normalized_path: normalized_path.to_string(),
            byte_range_start,
            byte_range_length,
            flags: 0,
        })
    }

    pub fn sequence_number(&self) -> u64 {
        self.sequence_counter
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_guest_audit_record_creation() {
        let dist_id = [0x42; 16];
        let mut source = GuestAuditSource::new(dist_id);

        let record = source
            .record_operation(
                1234,
                "/usr/bin/python3",
                "/mnt/c/Users/test/data.csv",
                GuestFileOperation::Write,
                0,
                4096,
            )
            .expect("record must succeed");

        assert_eq!(record.sequence_number, 1);
        assert_eq!(record.guest_process_id, 1234);
        assert_eq!(record.normalized_path, "/mnt/c/Users/test/data.csv");
        assert_eq!(record.operation, GuestFileOperation::Write);

        // Frame encoding must succeed
        let frame = record.to_frame().expect("to_frame succeeds");
        assert!(!frame.is_empty());
    }

    #[test]
    fn test_non_normalized_path_rejected() {
        let dist_id = [0x42; 16];
        let mut source = GuestAuditSource::new(dist_id);

        let err = source.record_operation(
            1234,
            "/usr/bin/bash",
            "/home/user/test.txt", // not /mnt/
            GuestFileOperation::Write,
            0,
            100,
        );
        assert!(err.is_err());
    }
}
