//! Numerical parity, boundary condition, and fallback tests for NPU inference engines.
//! Validates parity between ONNX Runtime hardware/CPU sessions and deterministic CPU baseline arithmetic.

use kavach_core::npu_backend::NpuEngine;
#[cfg(feature = "npu-hardware")]
use kavach_core::npu_backend::{
    ExecutionProviderBackend, NpuHardwareInfo, OrtBackendSession, generate_reference_onnx,
};

#[test]
fn test_npu_io_inference_numerical_parity() {
    let engine = NpuEngine::with_reference_model();

    // 1. Benign low-entropy file writes (entropy ~25/127 = 0.197, intermittent = 0)
    let benign_io = [[25i8, 10, 5, 0]; 10];
    let benign_score = engine.run_io_inference(&benign_io);
    // Baseline formula: (25/127 * 0.7 + 0.0) = 0.1378
    let expected_benign = (25.0f32 / 127.0f32) * 0.7;
    assert!(
        (benign_score - expected_benign).abs() < 0.05,
        "Benign score {benign_score} must correlate with expected {expected_benign}"
    );
    assert!(benign_score < 0.30);

    // 2. Burst mixed I/O activity (entropy ~64/127 = 0.504, intermittent ~38/127 = 0.3)
    let burst_io = [[64i8, 50, 20, 38]; 10];
    let burst_score = engine.run_io_inference(&burst_io);
    let expected_burst = (64.0f32 / 127.0f32) * 0.7 + (38.0f32 / 127.0f32) * 0.3;
    assert!(
        (burst_score - expected_burst).abs() < 0.05,
        "Burst score {burst_score} must correlate with expected {expected_burst}"
    );

    // 3. Simulated Ransomware high-entropy write burst (entropy ~115/127 = 0.906, intermittent = 0)
    let ransomware_io = [[115i8, 80, 0, 0]; 10];
    let ransomware_score = engine.run_io_inference(&ransomware_io);
    let expected_rw = (115.0f32 / 127.0f32) * 0.7;
    assert!(
        (ransomware_score - expected_rw).abs() < 0.05,
        "Ransomware score {ransomware_score} must correlate with expected {expected_rw}"
    );
    assert!(ransomware_score >= 0.60);
}

#[test]
fn test_npu_net_inference_numerical_parity() {
    let engine = NpuEngine::with_reference_model();

    // 1. Normal jittered traffic (delta time ~15/127 = 0.118)
    let normal_net = [[15i8, 0, 0, 0]; 32];
    let normal_score = engine.run_net_inference(&normal_net);
    let expected_normal = 15.0f32 / 127.0f32;
    assert!(
        (normal_score - expected_normal).abs() < 0.05,
        "Normal net score {normal_score} must correlate with expected {expected_normal}"
    );
    assert!(normal_score < 0.25);

    // 2. Strict periodic C2 beaconing (delta time ~100/127 = 0.787)
    let beacon_net = [[100i8, 50, 0, 0]; 32];
    let beacon_score = engine.run_net_inference(&beacon_net);
    let expected_beacon = 100.0f32 / 127.0f32;
    assert!(
        (beacon_score - expected_beacon).abs() < 0.05,
        "Beacon score {beacon_score} must correlate with expected {expected_beacon}"
    );
    assert!(beacon_score >= 0.70);
}

#[test]
fn test_npu_audit_inference_numerical_parity() {
    let engine = NpuEngine::with_reference_model();

    // 1. Benign background user logon activity (event anomaly ~10/127 = 0.079)
    let benign_audit = [[10i8, 0, 0, 0]; 16];
    let benign_score = engine.run_audit_inference(&benign_audit);
    let expected_benign = 10.0f32 / 127.0f32;
    assert!(
        (benign_score - expected_benign).abs() < 0.05,
        "Benign audit score {benign_score} must correlate with expected {expected_benign}"
    );
    assert!(benign_score < 0.20);

    // 2. High-frequency brute-force authentication chain (event anomaly ~110/127 = 0.866)
    let brute_audit = [[110i8, 20, 0, 0]; 16];
    let brute_score = engine.run_audit_inference(&brute_audit);
    let expected_brute = 110.0f32 / 127.0f32;
    assert!(
        (brute_score - expected_brute).abs() < 0.05,
        "Brute audit score {brute_score} must correlate with expected {expected_brute}"
    );
    assert!(brute_score >= 0.80);
}

#[test]
fn test_npu_boundary_tensors_clamping() {
    let engine = NpuEngine::with_reference_model();

    // 1. All-zero tensor: anomaly score must be 0.0
    let zero_io = [[0i8; 4]; 10];
    let zero_score = engine.run_io_inference(&zero_io);
    assert_eq!(zero_score, 0.0);

    let zero_net = [[0i8; 4]; 32];
    let zero_net_score = engine.run_net_inference(&zero_net);
    assert_eq!(zero_net_score, 0.0);

    let zero_audit = [[0i8; 4]; 16];
    let zero_audit_score = engine.run_audit_inference(&zero_audit);
    assert_eq!(zero_audit_score, 0.0);

    // 2. Saturated max tensor: values at 127 must clamp <= 1.0
    let max_io = [[127i8; 4]; 10];
    let max_score = engine.run_io_inference(&max_io);
    assert!(max_score <= 1.0);
    assert!(max_score >= 0.99);

    let max_net = [[127i8; 4]; 32];
    let max_net_score = engine.run_net_inference(&max_net);
    assert!(max_net_score <= 1.0);
    assert!(max_net_score >= 0.99);

    // 3. Negative tensors: clamped to 0.0 minimum
    let neg_io = [[-128i8; 4]; 10];
    let neg_score = engine.run_io_inference(&neg_io);
    assert_eq!(neg_score, 0.0);

    let neg_net = [[-128i8; 4]; 32];
    let neg_net_score = engine.run_net_inference(&neg_net);
    assert_eq!(neg_net_score, 0.0);
}

#[test]
fn test_npu_session_fallback_on_corrupt_model() {
    // Intentionally corrupted model bytes (invalid header, non-protobuf)
    let corrupt_bytes = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01, 0x02, 0x03];
    let engine = NpuEngine::with_onnx_bytes(&corrupt_bytes);

    // Engine must fall back to CPU baseline seamlessly without panicking
    let io_data = [[64i8, 0, 0, 32]; 10];
    let score = engine.run_io_inference(&io_data);
    assert!(score > 0.0 && score <= 1.0);

    let net_data = [[50i8, 10, 0, 0]; 32];
    let net_score = engine.run_net_inference(&net_data);
    assert!(net_score > 0.0 && net_score <= 1.0);

    let audit_data = [[40i8, 0, 0, 0]; 16];
    let audit_score = engine.run_audit_inference(&audit_data);
    assert!(audit_score > 0.0 && audit_score <= 1.0);

    assert_eq!(engine.total_inferences(), 3);
}

#[test]
#[cfg(feature = "npu-hardware")]
fn test_ort_multi_head_evaluation_consistency() {
    let info = NpuHardwareInfo::probe();
    if info.runtime_bin_dir.is_none() {
        return;
    }
    let onnx_bytes = generate_reference_onnx();
    assert!(!onnx_bytes.is_empty());

    let session = OrtBackendSession::from_reference_model(&info).expect("reference model session");

    // The ORT session must be operating under a valid execution backend
    let backend = session.backend();
    assert!(
        backend == ExecutionProviderBackend::DirectMlGpu
            || backend == ExecutionProviderBackend::AmdXdnaNpu
            || backend == ExecutionProviderBackend::NativeCpuBaseline
    );

    let io_data = [[75i8, 20, 10, 40]; 10];
    let net_data = [[60i8, 15, 0, 0]; 32];
    let audit_data = [[85i8, 0, 0, 0]; 16];

    // Evaluate each head individually
    let io_single = session.run_io_inference(&io_data).expect("io run");
    let net_single = session.run_net_inference(&net_data).expect("net run");
    let audit_single = session.run_audit_inference(&audit_data).expect("audit run");

    // Evaluate all heads in combined multi-head run
    let (io_multi, net_multi, audit_multi) = session
        .run_multi_head(&io_data, &net_data, &audit_data)
        .expect("multi-head run");

    // Multi-head and single-head evaluations must match within floating point precision
    assert!(
        (io_single - io_multi).abs() < 1e-4,
        "I/O single ({io_single}) and multi ({io_multi}) must be consistent"
    );
    assert!(
        (net_single - net_multi).abs() < 1e-4,
        "Net single ({net_single}) and multi ({net_multi}) must be consistent"
    );
    assert!(
        (audit_single - audit_multi).abs() < 1e-4,
        "Audit single ({audit_single}) and multi ({audit_multi}) must be consistent"
    );
}
