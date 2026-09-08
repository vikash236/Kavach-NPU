//! No-op surface for the future AF_VSOCK guest-to-host correlation bridge.

use kavach_core::ArtifactVersion;

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

/// Placeholder bridge for confidence-bounded WSL2 attribution defined in ADR 005.
#[derive(Debug, Default)]
pub struct WslBridge;

impl WslBridge {
    /// Construct a bridge without opening AF_VSOCK or attributing guest activity.
    pub fn new() -> Self {
        Self
    }
}
