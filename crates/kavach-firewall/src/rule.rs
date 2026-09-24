//! Windows Filtering Platform (WFP) dynamic firewall rules and crash-safe teardown per README and ADR 003.

use std::collections::HashMap;
use std::net::IpAddr;

/// Windows Filtering Platform flag: filter is automatically removed when the BFE session closes.
pub const FWPM_FILTER_FLAG_CLEAR_ACTION_ON_SHUTDOWN: u32 = 0x0000_0010;

/// Target resource to be isolated by the autonomous firewall.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum QuarantineTarget {
    /// Remote destination IP and optional port drop.
    DestinationIpPort {
        ip: IpAddr,
        port: Option<u16>,
        protocol: u8,
    },
    /// vEthernet (WSL) virtual switch network quarantine.
    WslVirtualSwitch { switch_name: String },
}

/// A dynamic packet filtering rule injected into WFP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DynamicFilterRule {
    pub filter_id: u64,
    pub target: QuarantineTarget,
    pub created_at_ms: u64,
    pub wfp_flags: u32,
    pub is_active: bool,
}

/// In-memory rule registry managing active dynamic packet filtering rules.
#[derive(Debug, Default)]
pub struct WfpRuleRegistry {
    rules: HashMap<u64, DynamicFilterRule>,
    next_filter_id: u64,
}

impl WfpRuleRegistry {
    /// Creates a new empty WFP rule registry.
    pub fn new() -> Self {
        Self {
            rules: HashMap::new(),
            next_filter_id: 1,
        }
    }

    /// Injects a new dynamic quarantine rule with safe shutdown cleanup flags.
    pub fn add_quarantine_rule(&mut self, target: QuarantineTarget, now_ms: u64) -> u64 {
        let id = self.next_filter_id;
        self.next_filter_id += 1;

        let rule = DynamicFilterRule {
            filter_id: id,
            target,
            created_at_ms: now_ms,
            wfp_flags: FWPM_FILTER_FLAG_CLEAR_ACTION_ON_SHUTDOWN,
            is_active: true,
        };

        self.rules.insert(id, rule);
        id
    }

    /// Removes an existing dynamic quarantine rule (e.g. after authorized administrative unblock).
    pub fn remove_rule(&mut self, filter_id: u64) -> bool {
        self.rules.remove(&filter_id).is_some()
    }

    /// Returns the number of currently active dynamic quarantine rules.
    pub fn active_rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Returns true if a specific target is currently under active quarantine.
    pub fn is_quarantined(&self, target: &QuarantineTarget) -> bool {
        self.rules
            .values()
            .any(|r| r.is_active && &r.target == target)
    }

    /// Clears all rules on shutdown, mirroring the WFP engine session close.
    pub fn clear_all_on_shutdown(&mut self) {
        self.rules.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_add_and_remove_quarantine_rule() {
        let mut registry = WfpRuleRegistry::new();
        let target = QuarantineTarget::DestinationIpPort {
            ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)),
            port: Some(4444),
            protocol: 6,
        };

        let id = registry.add_quarantine_rule(target.clone(), 1_000);
        assert!(registry.is_quarantined(&target));
        assert_eq!(registry.active_rule_count(), 1);

        let removed = registry.remove_rule(id);
        assert!(removed);
        assert!(!registry.is_quarantined(&target));
        assert_eq!(registry.active_rule_count(), 0);
    }

    #[test]
    fn test_shutdown_cleanup() {
        let mut registry = WfpRuleRegistry::new();
        let target = QuarantineTarget::WslVirtualSwitch {
            switch_name: "vEthernet (WSL)".into(),
        };

        registry.add_quarantine_rule(target.clone(), 1_000);
        assert!(registry.is_quarantined(&target));

        registry.clear_all_on_shutdown();
        assert!(!registry.is_quarantined(&target));
        assert_eq!(registry.active_rule_count(), 0);
    }

    #[test]
    fn test_remove_nonexistent_rule_returns_false() {
        let mut registry = WfpRuleRegistry::new();
        assert!(!registry.remove_rule(999));
    }

    #[test]
    fn test_duplicate_target_both_quarantined() {
        let mut registry = WfpRuleRegistry::new();
        let target = QuarantineTarget::WslVirtualSwitch {
            switch_name: "vEthernet (WSL)".into(),
        };

        let id1 = registry.add_quarantine_rule(target.clone(), 1_000);
        let id2 = registry.add_quarantine_rule(target.clone(), 2_000);
        assert_eq!(registry.active_rule_count(), 2);
        assert!(registry.is_quarantined(&target));

        // Removing one rule keeps the target quarantined because the other remains
        assert!(registry.remove_rule(id1));
        assert_eq!(registry.active_rule_count(), 1);
        assert!(registry.is_quarantined(&target));

        // Removing the second clears quarantine
        assert!(registry.remove_rule(id2));
        assert_eq!(registry.active_rule_count(), 0);
        assert!(!registry.is_quarantined(&target));
    }

    #[test]
    fn test_ipv6_quarantine_rule() {
        use std::net::Ipv6Addr;
        let mut registry = WfpRuleRegistry::new();
        let target = QuarantineTarget::DestinationIpPort {
            ip: IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            port: Some(8443),
            protocol: 6,
        };

        let id = registry.add_quarantine_rule(target.clone(), 1_000);
        assert!(registry.is_quarantined(&target));
        assert_eq!(registry.active_rule_count(), 1);

        assert!(registry.remove_rule(id));
        assert!(!registry.is_quarantined(&target));
        assert_eq!(registry.active_rule_count(), 0);
    }
}
