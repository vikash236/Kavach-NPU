//! End-to-end integration test verifying live sensor ingestion -> NPU inference -> verified broker verdict dispatch.

use kavach_core::tensor::{IoInputTensor, QuantizationParams};
use kavach_core::wire::VERDICT_WIRE_SIZE;
use kavach_core::{EnforcementAction, KavachConfig, NpuSession, Verdict, VerdictDispatcher};
use kavach_firewall::EnforcementBroker;
use kavach_tripwire::EntropyEngine;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

struct DirectBrokerDispatcher {
    broker: Arc<Mutex<EnforcementBroker>>,
}

impl VerdictDispatcher for DirectBrokerDispatcher {
    fn dispatch(&self, verdict: &Verdict) -> Result<(), kavach_core::DispatchError> {
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        let mut guard = self.broker.lock().unwrap();
        guard.evaluate_and_enforce(verdict, now_ms).map(|_| ())
    }
}

#[test]
fn test_live_threat_detection_and_broker_containment_pipeline() {
    let config = KavachConfig::safe_defaults();

    // 1. Initialize verified NPU session
    let npu_session = NpuSession::from_config(&config, &kavach_core::PINNED_REFERENCE_PUBLIC_KEY);
    assert!(!npu_session.is_degraded(), "NPU session must be active");

    // 2. Initialize Enforcement Broker
    let broker = Arc::new(Mutex::new(EnforcementBroker::new(
        config.allowlist.required_policy_generation,
        config.containment.hard_kill_enabled,
        config.containment.minimum_corroborating_evidence,
        [0x77; 32],
        false,
    )));
    let dispatcher = DirectBrokerDispatcher {
        broker: broker.clone(),
    };

    // 3. Simulate high-entropy ransomware write burst in Tripwire engine
    let mut entropy_engine = EntropyEngine::new();
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    // Generate high-entropy ciphertext payload
    let mut ciphertext = vec![0u8; 4096];
    let mut state: u32 = 0xBADC0DE;
    for b in ciphertext.iter_mut() {
        state = state.wrapping_mul(1664525).wrapping_add(1013904223);
        *b = (state >> 16) as u8;
    }

    // Ingest 10 rapid file encryption writes across distinct files for target PID 9999 spanning the 50ms window
    for i in 0..10 {
        entropy_engine.ingest_operation(
            9999,
            &format!("C:\\data\\encrypted_file_{i}.locked"),
            &ciphertext,
            false,
            now_ms + i * 5,
        );
    }

    // 4. Extract feature tensor matrix and evaluate on NPU
    let tensor_matrix = entropy_engine.tracker().build_tensor_matrix();
    let io_tensor = IoInputTensor::from_f32_matrix(&tensor_matrix, QuantizationParams::default());
    let anomaly_score = npu_session
        .evaluate_io_head(&io_tensor)
        .expect("inference succeeds");

    println!("Simulated Ransomware Anomaly Score: {:.4}", anomaly_score);
    assert!(
        anomaly_score >= 0.60,
        "High-entropy burst must score high anomaly, got {:.4}",
        anomaly_score
    );

    // 5. Construct authenticated Verdict and dispatch to Broker
    let verdict = Verdict {
        protocol_version: kavach_core::ArtifactVersion { major: 1, minor: 0 },
        request_id: [0x55; 16],
        issued_at_unix_ms: now_ms,
        expires_at_unix_ms: now_ms + 10_000,
        detector_instance_id: [0x11; 16],
        requested_action: EnforcementAction::SuspendAndAlert,
        evidence_digest: [0x99; 32],
        model_bundle_sha256: [0x77; 32],
        policy_generation: config.allowlist.required_policy_generation,
        target_process_id: 9999,
        target_process_start_filetime: 133500000000000000,
        corroborating_evidence_count: 3,
        flags: 0,
    };

    let dispatch_res = dispatcher.dispatch(&verdict);
    assert!(
        dispatch_res.is_ok(),
        "Broker must accept and enforce valid verdict"
    );

    // 6. Verify replay protection: identical request_id must be rejected
    let replay_res = dispatcher.dispatch(&verdict);
    assert_eq!(
        replay_res.unwrap_err(),
        kavach_core::DispatchError::ReplayDetected
    );

    // 7. Verify wire representation matches fixed specification size
    let wire = verdict.to_wire();
    assert_eq!(wire.len(), VERDICT_WIRE_SIZE);
}
