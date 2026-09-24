//! Cross-boundary guest-to-host file write correlation and confidence classification per ADR 005.

use crate::GuestWriteRecord;
use crate::clock_sync::ClockSynchronizer;
use std::collections::VecDeque;

/// Maximum allowable correlation window in milliseconds (250 ms per ADR 005 and config-schema.md).
pub const MAX_CORRELATION_WINDOW_MS: u64 = 250;

/// Attribution confidence level governing enforcement eligibility per ADR 005.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttributionConfidence {
    /// High confidence: Unique matching host event, matching path & operation, fresh time offset, single guest PID.
    /// Eligible for guest-targeted containment response.
    High,
    /// Medium confidence: Unique path/time match without exact file identity. Alert-only.
    Medium,
    /// Low confidence: Aggregate vmmemWSL.exe activity or stale/uncertain clock sync. Alert-only.
    Low,
}

/// Host-side file write event observed from ETW Kernel-File.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostFileEvent {
    pub host_timestamp_ns: u64,
    pub canonical_windows_path: String,
    pub is_vmmem_process: bool,
    pub bytes_written: u64,
}

/// Attribution outcome produced when correlating guest writes with host ETW activity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WslAttributionResult {
    pub guest_process_id: u32,
    pub distribution_id: [u8; 16],
    pub normalized_path: String,
    pub canonical_windows_path: String,
    pub confidence: AttributionConfidence,
    pub correlation_delta_ms: u64,
    pub allow_pid_enforcement: bool,
}

/// Translates a normalized `/mnt/<drive>/path` to a Windows canonical path `D:\path`.
pub fn translate_mnt_to_windows_path(mnt_path: &str) -> Option<String> {
    if !mnt_path.starts_with("/mnt/") {
        return None;
    }

    let remainder = &mnt_path["/mnt/".len()..];
    let mut parts = remainder.splitn(2, '/');
    let drive_str = parts.next()?;
    if drive_str.len() != 1 {
        return None;
    }

    let drive_char = drive_str.chars().next()?.to_ascii_uppercase();
    let rest = parts.next().unwrap_or("");

    let win_path = if rest.is_empty() {
        format!("{drive_char}:\\")
    } else {
        format!("{drive_char}:\\{}", rest.replace('/', "\\"))
    };

    Some(win_path)
}

/// Correlator managing guest records, host ETW events, and clock synchronization state.
#[derive(Debug)]
pub struct WslCorrelator {
    clock_sync: ClockSynchronizer,
    guest_records: VecDeque<GuestWriteRecord>,
    host_events: VecDeque<HostFileEvent>,
    correlation_window_ms: u64,
}

impl WslCorrelator {
    /// Creates a new correlator with specified distribution ID and correlation window.
    pub fn new(distribution_id: [u8; 16], correlation_window_ms: u64) -> Self {
        Self {
            clock_sync: ClockSynchronizer::new(distribution_id),
            guest_records: VecDeque::new(),
            host_events: VecDeque::new(),
            correlation_window_ms: correlation_window_ms.min(MAX_CORRELATION_WINDOW_MS),
        }
    }

    /// Access the mutable clock synchronizer.
    pub fn clock_sync_mut(&mut self) -> &mut ClockSynchronizer {
        &mut self.clock_sync
    }

    /// Records an observed host ETW file event.
    pub fn record_host_event(&mut self, event: HostFileEvent) {
        self.host_events.push_back(event);
        if self.host_events.len() > 1000 {
            self.host_events.pop_front();
        }
    }

    /// Correlates an incoming guest write record against buffered host events.
    pub fn correlate_guest_record(
        &mut self,
        record: GuestWriteRecord,
        now_host_ns: u64,
    ) -> WslAttributionResult {
        let windows_path = translate_mnt_to_windows_path(&record.normalized_path)
            .unwrap_or_else(|| record.normalized_path.clone());

        // Check clock synchronization freshness
        let clock_estimate = self.clock_sync.get_valid_estimate(now_host_ns);

        let (confidence, delta_ms) = match clock_estimate {
            Some(est) => {
                // Adjust guest monotonic timestamp to host monotonic time:
                // host_time = guest_time + offset
                let adjusted_host_ts =
                    (record.guest_monotonic_ns as i128 + est.offset_ns as i128) as u64;
                let window_ns = self.correlation_window_ms * 1_000_000;

                // Find matching host events targeting the same translated path within correlation window
                let matches: Vec<&HostFileEvent> = self
                    .host_events
                    .iter()
                    .filter(|he| {
                        he.canonical_windows_path
                            .eq_ignore_ascii_case(&windows_path)
                            && (he.host_timestamp_ns.abs_diff(adjusted_host_ts) <= window_ns)
                    })
                    .collect();

                let delta = if let Some(first_match) = matches.first() {
                    first_match.host_timestamp_ns.abs_diff(adjusted_host_ts) / 1_000_000
                } else {
                    0
                };

                if matches.len() == 1 && est.uncertainty_ns <= 50_000_000 {
                    (AttributionConfidence::High, delta)
                } else if !matches.is_empty() {
                    (AttributionConfidence::Medium, delta)
                } else {
                    (AttributionConfidence::Low, delta)
                }
            }
            None => {
                // Clock sync is stale or failed: downgraded to Low confidence
                (AttributionConfidence::Low, 0)
            }
        };

        let allow_pid_enforcement = confidence == AttributionConfidence::High;

        let result = WslAttributionResult {
            guest_process_id: record.guest_process_id,
            distribution_id: record.distribution_id,
            normalized_path: record.normalized_path.clone(),
            canonical_windows_path: windows_path,
            confidence,
            correlation_delta_ms: delta_ms,
            allow_pid_enforcement,
        };

        self.guest_records.push_back(record);
        if self.guest_records.len() > 1000 {
            self.guest_records.pop_front();
        }

        result
    }

    /// Returns the number of recent guest write records retained.
    pub fn guest_record_count(&self) -> usize {
        self.guest_records.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock_sync::{ClockChallenge, ClockResponse};
    use crate::{GuestFileOperation, GuestWriteRecord};
    use kavach_core::ArtifactVersion;

    #[test]
    fn test_mnt_to_windows_path_translation() {
        assert_eq!(
            translate_mnt_to_windows_path("/mnt/c/Users/victim/test.txt").unwrap(),
            "C:\\Users\\victim\\test.txt"
        );
        assert_eq!(
            translate_mnt_to_windows_path("/mnt/d/projects/code/").unwrap(),
            "D:\\projects\\code\\"
        );
        assert!(translate_mnt_to_windows_path("/home/user/file").is_none());
    }

    #[test]
    fn test_high_confidence_attribution() {
        let distro_id = [0x77; 16];
        let mut correlator = WslCorrelator::new(distro_id, 250);

        // Perform valid clock sync
        let challenge = ClockChallenge {
            nonce: [0xaa; 16],
            t0_host_monotonic_ns: 1_000_000_000,
        };
        let response = ClockResponse {
            nonce: [0xaa; 16],
            g1_guest_monotonic_ns: 1_000_000_000,
            g2_guest_monotonic_ns: 1_000_000_000,
        };
        correlator
            .clock_sync_mut()
            .process_response(&challenge, &response, 1_005_000_000)
            .unwrap();

        // Host writes C:\Users\victim\doc.txt at host timestamp 2,000,000,000
        correlator.record_host_event(HostFileEvent {
            host_timestamp_ns: 2_000_000_000,
            canonical_windows_path: "C:\\Users\\victim\\doc.txt".into(),
            is_vmmem_process: true,
            bytes_written: 4096,
        });

        // Guest record arrives for /mnt/c/Users/victim/doc.txt at guest timestamp 1,995,000,000 (5ms delta)
        let guest_rec = GuestWriteRecord {
            version: ArtifactVersion { major: 1, minor: 0 },
            sequence_number: 1,
            guest_monotonic_ns: 1_995_000_000,
            guest_realtime_ns: 0,
            guest_process_id: 4321,
            guest_process_start_ticks: 100,
            distribution_id: distro_id,
            mount_namespace_id: 1,
            executable_sha256: [0; 32],
            cgroup_sha256: [0; 32],
            operation: GuestFileOperation::Write,
            normalized_path: "/mnt/c/Users/victim/doc.txt".into(),
            byte_range_start: 0,
            byte_range_length: 4096,
            flags: 0,
        };

        let result = correlator.correlate_guest_record(guest_rec, 2_010_000_000);
        assert_eq!(result.confidence, AttributionConfidence::High);
        assert!(result.allow_pid_enforcement);
        assert_eq!(result.guest_process_id, 4321);
    }

    #[test]
    fn test_stale_clock_sync_downgrades_to_low() {
        let distro_id = [0x88; 16];
        let mut correlator = WslCorrelator::new(distro_id, 250);

        // Guest write without clock sync
        let guest_rec = GuestWriteRecord {
            version: ArtifactVersion { major: 1, minor: 0 },
            sequence_number: 1,
            guest_monotonic_ns: 1_000_000_000,
            guest_realtime_ns: 0,
            guest_process_id: 5555,
            guest_process_start_ticks: 100,
            distribution_id: distro_id,
            mount_namespace_id: 1,
            executable_sha256: [0; 32],
            cgroup_sha256: [0; 32],
            operation: GuestFileOperation::Write,
            normalized_path: "/mnt/c/file.txt".into(),
            byte_range_start: 0,
            byte_range_length: 100,
            flags: 0,
        };

        let result = correlator.correlate_guest_record(guest_rec, 1_000_000_000);
        assert_eq!(result.confidence, AttributionConfidence::Low);
        assert!(
            !result.allow_pid_enforcement,
            "must disallow PID enforcement on low confidence"
        );
    }

    #[test]
    fn test_no_matching_host_event_yields_low_confidence() {
        let distro_id = [0x99; 16];
        let mut correlator = WslCorrelator::new(distro_id, 250);

        let challenge = ClockChallenge {
            nonce: [0xbb; 16],
            t0_host_monotonic_ns: 1_000_000_000,
        };
        let response = ClockResponse {
            nonce: [0xbb; 16],
            g1_guest_monotonic_ns: 1_000_000_000,
            g2_guest_monotonic_ns: 1_000_000_000,
        };
        correlator
            .clock_sync_mut()
            .process_response(&challenge, &response, 1_005_000_000)
            .unwrap();

        let guest_rec = GuestWriteRecord {
            version: ArtifactVersion { major: 1, minor: 0 },
            sequence_number: 1,
            guest_monotonic_ns: 1_000_000_000,
            guest_realtime_ns: 0,
            guest_process_id: 1234,
            guest_process_start_ticks: 100,
            distribution_id: distro_id,
            mount_namespace_id: 1,
            executable_sha256: [0; 32],
            cgroup_sha256: [0; 32],
            operation: GuestFileOperation::Write,
            normalized_path: "/mnt/c/unmatched.txt".into(),
            byte_range_start: 0,
            byte_range_length: 512,
            flags: 0,
        };

        let result = correlator.correlate_guest_record(guest_rec, 1_010_000_000);
        assert_eq!(result.confidence, AttributionConfidence::Low);
        assert!(!result.allow_pid_enforcement);
    }

    #[test]
    fn test_correlation_window_capped_at_maximum() {
        let correlator = WslCorrelator::new([0; 16], 999);
        assert_eq!(correlator.correlation_window_ms, MAX_CORRELATION_WINDOW_MS);
    }
}
