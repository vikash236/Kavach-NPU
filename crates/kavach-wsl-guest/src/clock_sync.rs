//! Guest-side clock sync challenge-response responder per ADR 005.

use kavach_wsl::clock_sync::{ClockChallenge, ClockResponse};
use std::time::Instant;

/// Returns current monotonic time in nanoseconds since program start.
pub fn get_guest_monotonic_ns(start_instant: &Instant) -> u64 {
    start_instant.elapsed().as_nanos() as u64
}

/// Generates a valid ClockResponse adhering to ADR 005 protocol:
/// - g1 sampled upon challenge receipt
/// - g2 sampled immediately before response transmission
pub fn respond_to_challenge(challenge: &ClockChallenge, start_instant: &Instant) -> ClockResponse {
    let g1 = get_guest_monotonic_ns(start_instant);
    // Minimal processing delta
    let g2 = get_guest_monotonic_ns(start_instant);

    ClockResponse {
        nonce: challenge.nonce,
        g1_guest_monotonic_ns: g1,
        g2_guest_monotonic_ns: g2,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_guest_clock_response_generation() {
        let start = Instant::now();
        let challenge = ClockChallenge {
            nonce: [0x7A; 16],
            t0_host_monotonic_ns: 1_000_000,
        };

        let response = respond_to_challenge(&challenge, &start);
        assert_eq!(response.nonce, [0x7A; 16]);
        assert!(response.g2_guest_monotonic_ns >= response.g1_guest_monotonic_ns);
    }
}
