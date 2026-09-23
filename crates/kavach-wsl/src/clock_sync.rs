//! Challenge-response clock offset estimation protocol per ADR 005 and config-schema.md.

/// Measured host-minus-guest clock relation used to bound correlation confidence under ADR 005.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClockOffsetEstimate {
    /// Guest-agent session to which the estimate applies.
    pub distribution_id: [u8; 16],
    /// Estimated host-minus-guest offset in nanoseconds.
    pub offset_ns: i64,
    /// Conservative one-way uncertainty bound in nanoseconds.
    pub uncertainty_ns: u64,
    /// Host monotonic timestamp at which the estimate was accepted.
    pub accepted_at_host_monotonic_ns: u64,
    /// Host monotonic timestamp after which this estimate is stale.
    pub valid_until_host_monotonic_ns: u64,
}

/// Maximum round-trip time allowed for an accepted clock exchange (100 ms).
pub const MAX_RTT_NS: u64 = 100_000_000;

/// Maximum allowable uncertainty bound for confidence-bounded attribution (50 ms).
pub const MAX_ACCEPTABLE_UNCERTAINTY_NS: u64 = 50_000_000;

/// Duration an accepted clock offset estimate remains fresh (90 seconds).
pub const CLOCK_SYNC_VALIDITY_NS: u64 = 90_000_000_000;

/// Exchange message sent from host to guest over AF_VSOCK.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClockChallenge {
    pub nonce: [u8; 16],
    pub t0_host_monotonic_ns: u64,
}

/// Exchange response returned by the guest agent to the host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClockResponse {
    pub nonce: [u8; 16],
    pub g1_guest_monotonic_ns: u64,
    pub g2_guest_monotonic_ns: u64,
}

/// Host-side clock synchronizer tracking the 5 most recent accepted samples.
#[derive(Debug, Clone)]
pub struct ClockSynchronizer {
    distribution_id: [u8; 16],
    accepted_samples: Vec<ClockSample>,
    current_estimate: Option<ClockOffsetEstimate>,
    consecutive_failures: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ClockSample {
    offset_ns: i64,
    rtt_ns: u64,
    host_timestamp_ns: u64,
}

impl ClockSynchronizer {
    /// Creates a synchronizer for an enrolled guest distribution.
    pub fn new(distribution_id: [u8; 16]) -> Self {
        Self {
            distribution_id,
            accepted_samples: Vec::with_capacity(5),
            current_estimate: None,
            consecutive_failures: 0,
        }
    }

    /// Evaluates a completed challenge-response exchange against host arrival time `t3`.
    pub fn process_response(
        &mut self,
        challenge: &ClockChallenge,
        response: &ClockResponse,
        t3_host_monotonic_ns: u64,
    ) -> Result<ClockOffsetEstimate, ClockSyncError> {
        // 1. Verify nonce matches
        if challenge.nonce != response.nonce {
            self.consecutive_failures += 1;
            return Err(ClockSyncError::NonceMismatch);
        }

        // 2. Check monotonic ordering
        if t3_host_monotonic_ns <= challenge.t0_host_monotonic_ns
            || response.g2_guest_monotonic_ns < response.g1_guest_monotonic_ns
        {
            self.consecutive_failures += 1;
            return Err(ClockSyncError::NonMonotonicTimestamps);
        }

        // 3. Compute Round Trip Time (RTT)
        let rtt = t3_host_monotonic_ns - challenge.t0_host_monotonic_ns;
        if rtt > MAX_RTT_NS {
            self.consecutive_failures += 1;
            return Err(ClockSyncError::RttTooHigh {
                rtt_ns: rtt,
                limit_ns: MAX_RTT_NS,
            });
        }

        // 4. Calculate midpoint offset: host_mid - guest_mid
        let host_mid = (challenge.t0_host_monotonic_ns as i128 + t3_host_monotonic_ns as i128) / 2;
        let guest_mid =
            (response.g1_guest_monotonic_ns as i128 + response.g2_guest_monotonic_ns as i128) / 2;
        let offset_ns = (host_mid - guest_mid) as i64;

        // Record sample in rolling 5-sample buffer
        if self.accepted_samples.len() == 5 {
            self.accepted_samples.remove(0);
        }
        self.accepted_samples.push(ClockSample {
            offset_ns,
            rtt_ns: rtt,
            host_timestamp_ns: t3_host_monotonic_ns,
        });
        self.consecutive_failures = 0;

        // 5. Select lowest RTT sample among recent 5 and compute uncertainty
        let best_sample = self
            .accepted_samples
            .iter()
            .min_by_key(|s| s.rtt_ns)
            .expect("sample exists");

        let min_offset = self
            .accepted_samples
            .iter()
            .map(|s| s.offset_ns)
            .min()
            .unwrap();
        let max_offset = self
            .accepted_samples
            .iter()
            .map(|s| s.offset_ns)
            .max()
            .unwrap();
        let spread_ns = (max_offset - min_offset).unsigned_abs();

        let uncertainty_ns = (best_sample.rtt_ns / 2) + (spread_ns / 2);

        let estimate = ClockOffsetEstimate {
            distribution_id: self.distribution_id,
            offset_ns: best_sample.offset_ns,
            uncertainty_ns,
            accepted_at_host_monotonic_ns: t3_host_monotonic_ns,
            valid_until_host_monotonic_ns: t3_host_monotonic_ns + CLOCK_SYNC_VALIDITY_NS,
        };

        self.current_estimate = Some(estimate);
        Ok(estimate)
    }

    /// Returns the active offset estimate if it is fresh and meets uncertainty constraints.
    pub fn get_valid_estimate(&self, now_host_monotonic_ns: u64) -> Option<&ClockOffsetEstimate> {
        let est = self.current_estimate.as_ref()?;
        if now_host_monotonic_ns > est.valid_until_host_monotonic_ns {
            return None;
        }
        if est.uncertainty_ns > MAX_ACCEPTABLE_UNCERTAINTY_NS {
            return None;
        }
        if self.consecutive_failures >= 3 {
            return None;
        }
        Some(est)
    }
}

/// Errors occurring during clock challenge-response verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClockSyncError {
    NonceMismatch,
    NonMonotonicTimestamps,
    RttTooHigh { rtt_ns: u64, limit_ns: u64 },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clock_synchronization_success() {
        let distro_id = [0x55; 16];
        let mut sync = ClockSynchronizer::new(distro_id);

        let challenge = ClockChallenge {
            nonce: [0x11; 16],
            t0_host_monotonic_ns: 1_000_000_000,
        };

        // Guest response with 10ms RTT and 500ms offset
        let response = ClockResponse {
            nonce: [0x11; 16],
            g1_guest_monotonic_ns: 504_000_000,
            g2_guest_monotonic_ns: 506_000_000,
        };
        let t3 = 1_010_000_000; // 10ms after t0

        let est = sync
            .process_response(&challenge, &response, t3)
            .expect("clock sync succeeds");

        assert_eq!(est.distribution_id, distro_id);
        assert!(est.uncertainty_ns <= 10_000_000, "uncertainty under 10ms");

        // Validate within freshness window
        let active = sync.get_valid_estimate(1_050_000_000);
        assert!(active.is_some());

        // Stale after 90 seconds (relative to t3)
        let stale = sync.get_valid_estimate(t3 + CLOCK_SYNC_VALIDITY_NS + 1);
        assert!(stale.is_none());
    }

    #[test]
    fn test_high_rtt_rejected() {
        let mut sync = ClockSynchronizer::new([0; 16]);
        let challenge = ClockChallenge {
            nonce: [0x22; 16],
            t0_host_monotonic_ns: 1_000_000_000,
        };
        let response = ClockResponse {
            nonce: [0x22; 16],
            g1_guest_monotonic_ns: 1_000_000_000,
            g2_guest_monotonic_ns: 1_000_000_000,
        };
        // 101ms RTT (> 100ms limit)
        let t3 = 1_101_000_000;

        let err = sync
            .process_response(&challenge, &response, t3)
            .unwrap_err();
        assert!(matches!(err, ClockSyncError::RttTooHigh { .. }));
    }
}
