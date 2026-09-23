//! No-op surface for the future AF_VSOCK guest-to-host correlation bridge.

use kavach_core::ArtifactVersion;

pub mod clock_sync;
pub mod correlator;
pub mod wire;
pub use clock_sync::{
    CLOCK_SYNC_VALIDITY_NS, ClockChallenge, ClockOffsetEstimate, ClockResponse, ClockSyncError,
    ClockSynchronizer, MAX_ACCEPTABLE_UNCERTAINTY_NS, MAX_RTT_NS,
};
pub use correlator::{
    AttributionConfidence, HostFileEvent, MAX_CORRELATION_WINDOW_MS, WslAttributionResult,
    WslCorrelator, translate_mnt_to_windows_path,
};
pub use wire::{
    FIXED_HEADER_SIZE, LENGTH_PREFIX_SIZE, MAX_PAYLOAD_SIZE, MIN_PAYLOAD_SIZE,
    SUPPORTED_VSOCK_MAJOR, VsockWireError, is_normalized_mnt_path,
};

/// Guest-side file operation encoded in the AF_VSOCK contract governed by ADR 005.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuestFileOperation {
    /// A guest process wrote bytes through a mounted host path.
    Write = 1,
    /// A guest process renamed a mounted host path.
    Rename = 2,
    /// A guest process removed a mounted host path.
    Delete = 3,
}

/// Logical AF_VSOCK guest-write record governed by ADR 005 and ADR 006; it performs no I/O.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestWriteRecord {
    /// Compatible AF_VSOCK record version.
    pub version: ArtifactVersion,
    /// Strictly increasing sequence number for one guest-agent session.
    pub sequence_number: u64,
    /// Guest monotonic timestamp when the operation completed, in nanoseconds.
    pub guest_monotonic_ns: u64,
    /// Guest realtime timestamp when the operation completed, in nanoseconds since Unix epoch.
    pub guest_realtime_ns: u64,
    /// Guest process identifier.
    pub guest_process_id: u32,
    /// Guest process start time in guest monotonic clock ticks.
    pub guest_process_start_ticks: u64,
    /// Stable distribution identity derived during bridge enrollment.
    pub distribution_id: [u8; 16],
    /// Guest mount namespace identifier.
    pub mount_namespace_id: u64,
    /// SHA-256 of the guest executable identity captured by the agent.
    pub executable_sha256: [u8; 32],
    /// SHA-256 of the guest cgroup identity, or all zeroes when unavailable.
    pub cgroup_sha256: [u8; 32],
    /// File operation represented by this event.
    pub operation: GuestFileOperation,
    /// Normalized UTF-8 `/mnt/<drive>/` path, capped by the v1 wire schema.
    pub normalized_path: String,
    /// Byte-range start, or zero when the operation has no byte range.
    pub byte_range_start: u64,
    /// Byte-range length, or zero when the operation has no byte range.
    pub byte_range_length: u64,
    /// V1 feature flags; all bits are zero until a future compatible minor version defines them.
    pub flags: u16,
}

/// Placeholder bridge for confidence-bounded WSL2 attribution defined in ADR 005.
#[derive(Debug, Default)]
pub struct WslBridge;

impl WslBridge {
    /// Construct a bridge without opening AF_VSOCK or attributing guest activity.
    pub fn new() -> Self {
        Self
    }
}
