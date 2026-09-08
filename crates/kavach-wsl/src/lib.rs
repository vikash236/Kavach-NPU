//! No-op surface for the future AF_VSOCK guest-to-host correlation bridge.

/// Placeholder bridge for confidence-bounded WSL2 attribution defined in ADR 005.
#[derive(Debug, Default)]
pub struct WslBridge;

impl WslBridge {
    /// Construct a bridge without opening AF_VSOCK or attributing guest activity.
    pub fn new() -> Self {
        Self
    }
}
