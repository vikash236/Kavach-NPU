//! AF_VSOCK client transport and framing protocol per ADR 005.

use kavach_wsl::GuestWriteRecord;

/// Default host AF_VSOCK port per ADR 005.
pub const DEFAULT_VSOCK_PORT: u32 = 7350;

/// Host CID constant in Linux AF_VSOCK (VMADDR_CID_HOST = 2).
pub const VMADDR_CID_HOST: u32 = 2;

/// Configuration for the guest agent vsock connection.
#[derive(Debug, Clone)]
pub struct VsockConfig {
    pub host_cid: u32,
    pub port: u32,
    pub distribution_id: [u8; 16],
    pub max_reconnect_backoff_ms: u64,
}

impl Default for VsockConfig {
    fn default() -> Self {
        Self {
            host_cid: VMADDR_CID_HOST,
            port: DEFAULT_VSOCK_PORT,
            distribution_id: [0x42; 16],
            max_reconnect_backoff_ms: 60_000,
        }
    }
}

/// Computes exponential backoff interval in milliseconds: min(1000 * 2^attempt, max_backoff_ms).
pub fn compute_backoff_ms(attempt: u32, max_backoff_ms: u64) -> u64 {
    let base: u64 = 1000;
    let shift = attempt.min(6);
    let delay = base * (1u64 << shift);
    delay.min(max_backoff_ms)
}

/// Serializes and frames a `GuestWriteRecord` into wire format ready for transmission.
pub fn prepare_wire_frame(record: &GuestWriteRecord) -> Result<Vec<u8>, String> {
    record
        .to_frame()
        .map_err(|e| format!("failed to format AF_VSOCK wire frame: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_backoff_progression() {
        assert_eq!(compute_backoff_ms(0, 60_000), 1000);
        assert_eq!(compute_backoff_ms(1, 60_000), 2000);
        assert_eq!(compute_backoff_ms(2, 60_000), 4000);
        assert_eq!(compute_backoff_ms(5, 60_000), 32_000);
        assert_eq!(compute_backoff_ms(10, 60_000), 60_000);
    }
}
