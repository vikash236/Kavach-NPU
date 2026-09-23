//! Privileged enforcement broker and verdict validation pipeline per ADR 002, ADR 003, and ADR 004.

use crate::rule::WfpRuleRegistry;
use kavach_core::{DispatchError, EnforcementAction, Verdict, VerdictDispatcher};
use std::collections::HashMap;

/// Result of an authorized host intervention executed by the privileged broker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnforcedAction {
    /// Target process suspended via NtSuspendProcess and alert persisted.
    ProcessSuspended { pid: u32, evidence_digest: [u8; 32] },
    /// Target process terminated via NtTerminateProcess (opt-in high-confidence hard-kill).
    ProcessTerminated { pid: u32, evidence_digest: [u8; 32] },
    /// Pure diagnostic alert logged without host state modification.
    AlertLogged { evidence_digest: [u8; 32] },
}

/// Privileged broker enforcing policy gates, replay protection, and host control actions.
#[derive(Debug)]
pub struct EnforcementBroker {
    active_policy_generation: u64,
    hard_kill_enabled: bool,
    minimum_corroborating_evidence: u8,
    trusted_model_sha256: [u8; 32],
    is_model_degraded: bool,
    /// Replay cache: maps request_id nonce to retention expiry timestamp (now + expiry + 60s).
    replay_cache: HashMap<[u8; 16], u64>,
    rule_registry: WfpRuleRegistry,
}

impl EnforcementBroker {
    /// Constructs a broker with verified policy and model state.
    pub fn new(
        active_policy_generation: u64,
        hard_kill_enabled: bool,
        minimum_corroborating_evidence: u8,
        trusted_model_sha256: [u8; 32],
        is_model_degraded: bool,
    ) -> Self {
        Self {
            active_policy_generation,
            hard_kill_enabled,
            minimum_corroborating_evidence,
            trusted_model_sha256,
            is_model_degraded,
            replay_cache: HashMap::new(),
            rule_registry: WfpRuleRegistry::new(),
        }
    }

    /// Access the mutable WFP rule registry.
    pub fn rule_registry_mut(&mut self) -> &mut WfpRuleRegistry {
        &mut self.rule_registry
    }

    /// Evaluates a verdict against all ADR 003 broker-side policy gates and executes enforcement.
    pub fn evaluate_and_enforce(
        &mut self,
        verdict: &Verdict,
        now_unix_ms: u64,
    ) -> Result<EnforcedAction, DispatchError> {
        // 1. Version compatibility check (ADR 003 / 006)
        if verdict.protocol_version.major != 1 {
            return Err(DispatchError::VersionMismatch);
        }

        // 2. Reserved flags must be zero
        if verdict.flags != 0 {
            return Err(DispatchError::MalformedMessage);
        }

        // 3. Expiration deadline check
        if now_unix_ms > verdict.expires_at_unix_ms {
            return Err(DispatchError::Expired);
        }

        // 4. Purge expired nonces and check for replay attack
        self.purge_expired_replay_cache(now_unix_ms);
        if self.replay_cache.contains_key(&verdict.request_id) {
            return Err(DispatchError::ReplayDetected);
        }

        // 5. Active policy generation check
        if verdict.policy_generation != self.active_policy_generation {
            return Err(DispatchError::ActionDenied);
        }

        // 6. Model health and bundle digest check (ADR 004)
        if self.is_model_degraded || verdict.model_bundle_sha256 != self.trusted_model_sha256 {
            return Err(DispatchError::ActionDenied);
        }

        // 7. Policy action authorization gates (ADR 002)
        match verdict.requested_action {
            EnforcementAction::HardKill => {
                if !self.hard_kill_enabled {
                    return Err(DispatchError::ActionDenied);
                }
                if verdict.corroborating_evidence_count < self.minimum_corroborating_evidence {
                    return Err(DispatchError::ActionDenied);
                }
                if verdict.target_process_id == 0 {
                    return Err(DispatchError::MalformedMessage);
                }
            }
            EnforcementAction::SuspendAndAlert => {
                if verdict.target_process_id == 0 {
                    return Err(DispatchError::MalformedMessage);
                }
            }
            EnforcementAction::Alert => {
                // Alerts are always permissible without host modification
            }
        }

        // Register request nonce in replay cache with 60-second post-expiry retention
        let retain_until = verdict.expires_at_unix_ms + 60_000;
        self.replay_cache.insert(verdict.request_id, retain_until);

        // Execute authorized action
        match verdict.requested_action {
            EnforcementAction::HardKill => Ok(EnforcedAction::ProcessTerminated {
                pid: verdict.target_process_id,
                evidence_digest: verdict.evidence_digest,
            }),
            EnforcementAction::SuspendAndAlert => Ok(EnforcedAction::ProcessSuspended {
                pid: verdict.target_process_id,
                evidence_digest: verdict.evidence_digest,
            }),
            EnforcementAction::Alert => Ok(EnforcedAction::AlertLogged {
                evidence_digest: verdict.evidence_digest,
            }),
        }
    }

    /// Purges replay nonces whose retention window has passed.
    pub fn purge_expired_replay_cache(&mut self, now_unix_ms: u64) {
        self.replay_cache
            .retain(|_, &mut retain_until| retain_until >= now_unix_ms);
    }

    /// Returns the number of active nonces in the replay cache.
    pub fn replay_cache_size(&self) -> usize {
        self.replay_cache.len()
    }
}

impl VerdictDispatcher for EnforcementBroker {
    fn dispatch(&self, verdict: &Verdict) -> Result<(), DispatchError> {
        // Dispatcher interface contract verification
        if verdict.protocol_version.major != 1 {
            return Err(DispatchError::VersionMismatch);
        }
        if verdict.flags != 0 {
            return Err(DispatchError::MalformedMessage);
        }
        if self.is_model_degraded || verdict.model_bundle_sha256 != self.trusted_model_sha256 {
            return Err(DispatchError::ActionDenied);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kavach_core::ArtifactVersion;

    fn sample_valid_verdict(action: EnforcementAction, pid: u32) -> Verdict {
        Verdict {
            protocol_version: ArtifactVersion { major: 1, minor: 0 },
            request_id: [0x12; 16],
            issued_at_unix_ms: 1_000,
            expires_at_unix_ms: 5_000,
            detector_instance_id: [0x34; 16],
            requested_action: action,
            evidence_digest: [0x56; 32],
            model_bundle_sha256: [0x78; 32],
            policy_generation: 7,
            target_process_id: pid,
            target_process_start_filetime: 12345,
            corroborating_evidence_count: 3,
            flags: 0,
        }
    }

    #[test]
    fn test_broker_accepts_suspend_and_alert() {
        let mut broker = EnforcementBroker::new(7, false, 3, [0x78; 32], false);
        let verdict = sample_valid_verdict(EnforcementAction::SuspendAndAlert, 100);

        let action = broker
            .evaluate_and_enforce(&verdict, 2_000)
            .expect("verdict accepted");

        assert_eq!(
            action,
            EnforcedAction::ProcessSuspended {
                pid: 100,
                evidence_digest: [0x56; 32]
            }
        );
        assert_eq!(broker.replay_cache_size(), 1);
    }

    #[test]
    fn test_broker_rejects_replay() {
        let mut broker = EnforcementBroker::new(7, false, 3, [0x78; 32], false);
        let verdict = sample_valid_verdict(EnforcementAction::Alert, 0);

        broker
            .evaluate_and_enforce(&verdict, 2_000)
            .expect("first accepted");

        // Replay of same request_id
        let err = broker.evaluate_and_enforce(&verdict, 2_500).unwrap_err();
        assert_eq!(err, DispatchError::ReplayDetected);
    }

    #[test]
    fn test_broker_rejects_expired() {
        let mut broker = EnforcementBroker::new(7, false, 3, [0x78; 32], false);
        let verdict = sample_valid_verdict(EnforcementAction::Alert, 0);

        // now_unix_ms = 6_000 > expires_at_unix_ms (5_000)
        let err = broker.evaluate_and_enforce(&verdict, 6_000).unwrap_err();
        assert_eq!(err, DispatchError::Expired);
    }

    #[test]
    fn test_broker_rejects_hard_kill_when_disabled() {
        let mut broker = EnforcementBroker::new(7, false, 3, [0x78; 32], false);
        let verdict = sample_valid_verdict(EnforcementAction::HardKill, 100);

        let err = broker.evaluate_and_enforce(&verdict, 2_000).unwrap_err();
        assert_eq!(err, DispatchError::ActionDenied);
    }

    #[test]
    fn test_broker_accepts_hard_kill_when_opted_in() {
        let mut broker = EnforcementBroker::new(7, true, 3, [0x78; 32], false);
        let verdict = sample_valid_verdict(EnforcementAction::HardKill, 100);

        let action = broker
            .evaluate_and_enforce(&verdict, 2_000)
            .expect("hard kill accepted");
        assert_eq!(
            action,
            EnforcedAction::ProcessTerminated {
                pid: 100,
                evidence_digest: [0x56; 32]
            }
        );
    }

    #[test]
    fn test_broker_rejects_when_model_is_degraded() {
        // Model marked degraded per ADR 004
        let mut broker = EnforcementBroker::new(7, true, 3, [0x78; 32], true);
        let verdict = sample_valid_verdict(EnforcementAction::SuspendAndAlert, 100);

        let err = broker.evaluate_and_enforce(&verdict, 2_000).unwrap_err();
        assert_eq!(err, DispatchError::ActionDenied);
    }
}
