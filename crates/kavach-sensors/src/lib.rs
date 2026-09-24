//! Windows ETW telemetry sensors, WFP driver bindings, and IPC broker per ADR 003.

pub mod etw_event_log;
pub mod etw_kernel_file;
pub mod etw_tcpip;
pub mod pipe_broker;
pub mod wfp_driver;

pub use etw_event_log::EventLogConsumer;
pub use etw_kernel_file::{KernelFileConsumer, KernelFileEvent};
pub use etw_tcpip::{TcpipConsumer, TcpipPacketEvent};
pub use pipe_broker::{KAVACH_BROKER_PIPE_NAME, PipeBrokerServer, PipeVerdictDispatcher};
pub use wfp_driver::WfpDriver;

#[cfg(test)]
mod tests {
    use super::*;
    use kavach_beacon::{FlowKey, PacketDirection, TcnEngine};
    use kavach_core::{
        ArtifactVersion, DispatchError, EnforcementAction, Verdict, VerdictDispatcher,
    };
    use kavach_events::{CriticalEventId, EventSubscriber, SecurityEventRecord};
    use kavach_firewall::EnforcementBroker;
    use kavach_firewall::rule::QuarantineTarget;
    use kavach_tripwire::EntropyEngine;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::{Arc, Mutex};

    #[test]
    fn test_kernel_file_consumer_pipeline() {
        let engine = Arc::new(Mutex::new(EntropyEngine::new()));
        let consumer = KernelFileConsumer::new(engine);

        let pid = 5000;
        let mut alert_fired = false;

        // Ingest high-entropy operations simulating ransomware
        for i in 1..=4 {
            let mut high_entropy = Vec::with_capacity(4096);
            let mut seed = 0x12345678u32.wrapping_add(i as u32 * 17);
            for _ in 0..4096 {
                seed = seed.wrapping_mul(1664525).wrapping_add(1013904223);
                high_entropy.push((seed >> 16) as u8);
            }

            let event = KernelFileEvent {
                process_id: pid,
                file_path: format!("C:\\data\\file_{i}.locked"),
                is_rename: false,
                payload: high_entropy,
                timestamp_unix_ms: 1_700_000_000_000 + i * 10,
            };

            if let Some(burst) = consumer.process_event(event)
                && burst.recommended_action == EnforcementAction::SuspendAndAlert
            {
                alert_fired = true;
                assert_eq!(burst.pid, pid);
                break;
            }
        }

        assert!(
            alert_fired,
            "Ransomware burst should trigger SuspendAndAlert"
        );
    }

    #[test]
    fn test_tcpip_consumer_pipeline() {
        let engine = Arc::new(Mutex::new(TcnEngine::new()));
        let consumer = TcpipConsumer::new(engine);

        let flow = FlowKey::new(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
            49152,
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5)),
            443,
            6,
        );

        let mut beacon_detected = false;
        // Feed 32 strictly periodic packets (CV = 0.0)
        for i in 0..32 {
            let event = TcpipPacketEvent {
                flow_key: flow.clone(),
                payload_bytes: 128,
                direction: PacketDirection::Outbound,
                timestamp_ns: (i as u64) * 1_000_000_000,
            };
            if let Some(res) = consumer.process_packet(event)
                && res.is_c2_beacon
            {
                beacon_detected = true;
                assert!(res.coefficient_of_variation <= 0.35);
            }
        }

        assert!(
            beacon_detected,
            "Periodic packets must be detected as C2 beacon"
        );
    }

    #[test]
    fn test_event_log_consumer_pipeline() {
        let subscriber = Arc::new(Mutex::new(EventSubscriber::new()));
        let consumer = EventLogConsumer::new(subscriber);

        // Feed an Audit Log Cleared event (1102)
        let record = SecurityEventRecord {
            event_id: CriticalEventId::AuditLogCleared,
            timestamp_unix_ms: 1_700_000_000_000,
            process_id: 1234,
            subject_user: "attacker".to_string(),
            target_resource: "Security.evtx".to_string(),
        };

        let alert = consumer.process_event(record).expect("alert expected");
        assert_eq!(
            alert.pattern,
            kavach_events::CorrelationPattern::AuditLogTampering
        );
    }

    #[test]
    fn test_wfp_driver_lifecycle() {
        let mut driver = WfpDriver::new();
        assert_eq!(driver.active_filter_count(), 0);

        driver.open_engine().expect("open engine succeeds");

        let target = QuarantineTarget::DestinationIpPort {
            ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20)),
            port: Some(8443),
            protocol: 6,
        };

        let filter_id = driver
            .add_quarantine(target, 1_700_000_000_000)
            .expect("add quarantine");
        assert_eq!(driver.active_filter_count(), 1);

        driver
            .remove_quarantine(filter_id)
            .expect("remove quarantine");
        assert_eq!(driver.active_filter_count(), 0);
    }

    #[test]
    fn test_pipe_broker_dispatch_and_replay_protection() {
        let broker = Arc::new(Mutex::new(EnforcementBroker::new(
            1, true, 2, [0x77; 32], false,
        )));

        let dispatcher = PipeVerdictDispatcher::with_in_memory_broker(broker.clone());
        let server = PipeBrokerServer::new(broker, KAVACH_BROKER_PIPE_NAME);

        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let verdict = Verdict {
            protocol_version: ArtifactVersion { major: 1, minor: 0 },
            request_id: [0x5A; 16],
            issued_at_unix_ms: now_ms,
            expires_at_unix_ms: now_ms + 10_000,
            detector_instance_id: [0x01; 16],
            requested_action: EnforcementAction::SuspendAndAlert,
            evidence_digest: [0x22; 32],
            model_bundle_sha256: [0x77; 32],
            policy_generation: 1,
            target_process_id: 1234,
            target_process_start_filetime: 133500000000000000,
            corroborating_evidence_count: 2,
            flags: 0,
        };

        // First dispatch should succeed
        let result = dispatcher.dispatch(&verdict);
        assert!(result.is_ok());

        // Replay dispatch with exact same request_id must be rejected
        let replay_result = dispatcher.dispatch(&verdict);
        assert_eq!(replay_result, Err(DispatchError::ReplayDetected));

        // Test server handle_frame on raw bytes
        let mut expired_verdict = verdict.clone();
        expired_verdict.request_id = [0x5B; 16];
        let wire = expired_verdict.to_wire();
        // Evaluating with time past expiry
        let server_result = server.handle_frame(&wire, now_ms + 20_000);
        assert_eq!(server_result, Err(DispatchError::Expired));
    }
}
