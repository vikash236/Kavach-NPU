//! Contracts shared by the unprivileged detector and enforcement broker.

/// Version identifier shared by versioned Kavach artifacts under ADR 003 and ADR 006.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArtifactVersion {
    /// Breaking compatibility generation.
    pub major: u16,
    /// Backward-compatible addition generation within `major`.
    pub minor: u16,
}

/// A requested response, evaluated by the privileged broker under ADR 002 and ADR 003.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnforcementAction {
    /// Record an alert without changing host state.
    Alert,
    /// Request a reversible process suspension.
    SuspendAndAlert,
    /// Request an opt-in, high-confidence irreversible termination.
    HardKill,
}

/// Fixed-size verdict contract submitted to the broker under ADR 003 and ADR 006.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    /// Protocol version negotiated for this message.
    pub protocol_version: ArtifactVersion,
    /// Random 128-bit request identifier used for replay detection.
    pub request_id: [u8; 16],
    /// Detector wall-clock issuance time in Unix milliseconds.
    pub issued_at_unix_ms: u64,
    /// Exclusive Unix-millisecond deadline after which the broker rejects this verdict.
    pub expires_at_unix_ms: u64,
    /// Stable 128-bit ID of the detector service instance.
    pub detector_instance_id: [u8; 16],
    /// The action requested by the detector; the broker independently authorizes it.
    pub requested_action: EnforcementAction,
    /// Digest identifying the immutable evidence captured for the verdict.
    pub evidence_digest: [u8; 32],
    /// Digest of the verified model bundle that produced this verdict.
    pub model_bundle_sha256: [u8; 32],
    /// Monotonic administrator policy generation observed by the detector.
    pub policy_generation: u64,
    /// Target Windows process identifier; zero is invalid for process actions.
    pub target_process_id: u32,
    /// Target process creation time in 100-nanosecond Windows FILETIME units.
    pub target_process_start_filetime: u64,
    /// Number of independent evidence items contributing to this verdict.
    pub corroborating_evidence_count: u8,
    /// Reserved feature bits; all bits must be zero in protocol version 1.0.
    pub flags: u8,
}

/// Narrow dispatch interface between low-privilege detection and high-privilege enforcement per ADR 003.
pub trait VerdictDispatcher {
    /// Submit a verdict for broker-side validation and policy evaluation.
    fn dispatch(&self, verdict: &Verdict) -> Result<(), DispatchError>;
}

/// Explicit dispatcher outcomes whose safe states are defined in ADR 003.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DispatchError {
    /// No authenticated broker connection could be established before the deadline.
    BrokerUnreachable,
    /// The detector and broker do not share a compatible major protocol version.
    VersionMismatch,
    /// The broker has already accepted or rejected this request identifier.
    ReplayDetected,
    /// The message failed framing, size, field, or reserved-bit validation.
    MalformedMessage,
    /// The local pipe peer failed service-SID or token validation.
    AuthenticationFailed,
    /// The broker received the verdict after its explicit expiry timestamp.
    Expired,
    /// Broker policy or verified-model state disallowed the requested action.
    ActionDenied,
}
