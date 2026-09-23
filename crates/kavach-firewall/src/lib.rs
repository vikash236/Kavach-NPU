//! Autonomous NPU Firewall and privileged WFP enforcement broker per README and ADR 003.

pub mod broker;
pub mod rule;

pub use broker::{EnforcedAction, EnforcementBroker};
pub use rule::{
    DynamicFilterRule, FWPM_FILTER_FLAG_CLEAR_ACTION_ON_SHUTDOWN, QuarantineTarget, WfpRuleRegistry,
};

/// High-level client interface for managing Windows Filtering Platform policy rules.
#[derive(Debug, Default)]
pub struct WfpClient {
    registry: WfpRuleRegistry,
}

impl WfpClient {
    /// Constructs a new WfpClient with an empty dynamic rule registry.
    pub fn new() -> Self {
        Self {
            registry: WfpRuleRegistry::new(),
        }
    }

    /// Access the underlying dynamic rule registry.
    pub fn registry(&self) -> &WfpRuleRegistry {
        &self.registry
    }

    /// Access the mutable underlying dynamic rule registry.
    pub fn registry_mut(&mut self) -> &mut WfpRuleRegistry {
        &mut self.registry
    }

    /// Injects an outbound IP/port quarantine rule.
    pub fn quarantine_target(&mut self, target: QuarantineTarget, now_ms: u64) -> u64 {
        self.registry.add_quarantine_rule(target, now_ms)
    }

    /// Removes an existing dynamic quarantine rule.
    pub fn release_quarantine(&mut self, filter_id: u64) -> bool {
        self.registry.remove_rule(filter_id)
    }
}
