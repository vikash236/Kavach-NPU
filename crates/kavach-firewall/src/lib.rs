//! No-op surface for the future privileged WFP enforcement broker.

/// Placeholder WFP wrapper restricted to broker-owned enforcement under ADR 003.
#[derive(Debug, Default)]
pub struct WfpClient;

impl WfpClient {
    /// Construct a wrapper without opening WFP or changing firewall policy.
    pub fn new() -> Self {
        Self
    }
}
