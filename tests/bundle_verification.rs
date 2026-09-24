use kavach_core::config::KavachConfig;
use kavach_core::manifest::{DegradedReason, verify_bundle_dir};
use kavach_core::npu::{NpuSession, NpuState};
use kavach_core::{PINNED_REFERENCE_PUBLIC_KEY, pinned_reference_verifying_key};
use std::fs;
use std::path::PathBuf;

#[test]
fn test_live_active_bundle_verification() {
    let bundle_path = PathBuf::from("models/active");
    let vk = pinned_reference_verifying_key();
    let manifest = verify_bundle_dir(&bundle_path, &vk, 1).expect("bundle must verify");

    assert_eq!(manifest.bundle_version, "0.1.0-reference");
    assert_eq!(manifest.key_id, "reference-model-2026-b");
    assert_eq!(manifest.onnx.opset, 21);
    assert_eq!(manifest.onnx.quantization, "int8_qdq");
    assert_eq!(manifest.tensors.len(), 6);
}

#[test]
fn test_npu_session_active_transitions() {
    let config = KavachConfig::safe_defaults();
    let session = NpuSession::from_config(&config, &PINNED_REFERENCE_PUBLIC_KEY);

    assert!(!session.is_degraded());
    match session.state() {
        NpuState::Active { manifest } => {
            assert_eq!(manifest.onnx.file, "kavach_multitask_int8.onnx");
        }
        _ => panic!("Expected NpuState::Active"),
    }

    let report = session.format_status_report();
    assert!(report.contains("Kavach-NPU status: ACTIVE"));
    assert!(report.contains("enforcement: ENABLED"));
    assert!(report.contains("telemetry: HARDWARE_ACCELERATED"));
}

#[test]
fn test_tampered_signature_degrades_gracefully() {
    let tmp_dir = tempfile_dir("tampered_sig");
    copy_dir("models/active", &tmp_dir);

    // Tamper with signature
    let sig_path = tmp_dir.join("manifest.sig");
    fs::write(&sig_path, "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY3ODkw").unwrap();

    let vk = pinned_reference_verifying_key();
    let err = verify_bundle_dir(&tmp_dir, &vk, 1).unwrap_err();
    assert!(matches!(err, DegradedReason::ManifestSignatureInvalid(_)));

    let mut config = KavachConfig::safe_defaults();
    config.model.bundle_directory = tmp_dir.clone();
    let session = NpuSession::from_config(&config, &PINNED_REFERENCE_PUBLIC_KEY);
    assert!(session.is_degraded());
    assert!(session.format_status_report().contains("manifest_signature_invalid"));

    let _ = fs::remove_dir_all(&tmp_dir);
}

#[test]
fn test_tampered_onnx_degrades_gracefully() {
    let tmp_dir = tempfile_dir("tampered_onnx");
    copy_dir("models/active", &tmp_dir);

    // Tamper with ONNX model file
    let onnx_path = tmp_dir.join("kavach_multitask_int8.onnx");
    fs::write(&onnx_path, b"malicious or corrupted ONNX bytes").unwrap();

    let vk = pinned_reference_verifying_key();
    let err = verify_bundle_dir(&tmp_dir, &vk, 1).unwrap_err();
    assert!(matches!(err, DegradedReason::OnnxHashMismatch { .. }));

    let mut config = KavachConfig::safe_defaults();
    config.model.bundle_directory = tmp_dir.clone();
    let session = NpuSession::from_config(&config, &PINNED_REFERENCE_PUBLIC_KEY);
    assert!(session.is_degraded());
    assert!(session.format_status_report().contains("onnx_hash_mismatch"));

    let _ = fs::remove_dir_all(&tmp_dir);
}

#[test]
fn test_rollback_rejection_degrades_gracefully() {
    let tmp_dir = tempfile_dir("rollback_test");
    copy_dir("models/active", &tmp_dir);

    let vk = pinned_reference_verifying_key();
    // Bundle generation is 1; require 42
    let err = verify_bundle_dir(&tmp_dir, &vk, 42).unwrap_err();
    assert!(matches!(err, DegradedReason::RollbackRejected { minimum: 42, actual: 1 }));

    let mut config = KavachConfig::safe_defaults();
    config.model.bundle_directory = tmp_dir.clone();
    config.model.minimum_rollback_generation = 42;
    let session = NpuSession::from_config(&config, &PINNED_REFERENCE_PUBLIC_KEY);
    assert!(session.is_degraded());
    assert!(session.format_status_report().contains("rollback_rejected"));

    let _ = fs::remove_dir_all(&tmp_dir);
}

fn tempfile_dir(prefix: &str) -> PathBuf {
    let id = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let p = std::env::temp_dir().join(format!("kavach_test_{prefix}_{id}"));
    fs::create_dir_all(&p).unwrap();
    p
}

fn copy_dir(src: &str, dst: &PathBuf) {
    let src_path = std::path::Path::new(src);
    for entry in fs::read_dir(src_path).unwrap() {
        let entry = entry.unwrap();
        let file_name = entry.file_name();
        fs::copy(entry.path(), dst.join(file_name)).unwrap();
    }
}
