//! Contracts shared by the unprivileged detector and enforcement broker.

/// A requested response, evaluated by the privileged broker under ADR 002 and ADR 003.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnforcementAction {
    /// Record an alert without changing host state.
    Alert,
    /// Request a reversible process suspension.
    SuspendAndAlert,
    /// Request an opt-in, high-confidence irreversible termination.
    HardKill,
}

/// Immutable detector output submitted to the enforcement boundary under ADR 003.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    /// Protocol version understood by detector and broker.
    pub protocol_version: u16,
    /// The action requested by the detector; the broker independently authorizes it.
    pub requested_action: EnforcementAction,
    /// Digest identifying the immutable evidence captured for the verdict.
    pub evidence_digest: [u8; 32],
}

/// Narrow dispatch interface between low-privilege detection and high-privilege enforcement per ADR 003.
pub trait VerdictDispatcher {
    /// Submit a verdict for broker-side validation and policy evaluation.
    fn dispatch(&self, verdict: &Verdict) -> Result<(), DispatchError>;
}

/// A placeholder error for the versioned dispatch boundary described in ADR 003.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DispatchError;
