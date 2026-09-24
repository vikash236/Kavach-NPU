//! AMD XDNA NPU multi-head inference session manager, hardware probe integration, and degraded observer mode per ADR 004 and model-manifest-v1.md.

use crate::manifest::{DegradedReason, ModelManifest};
use crate::tensor::{AuditInputTensor, IoInputTensor, NetInputTensor};

/// Errors encountered during NPU session initialization or inference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NpuError {
    /// Model is degraded; model-driven actions are disabled.
    DegradedObserver(DegradedReason),
    /// Inference execution error.
    ExecutionFailed(String),
}

impl std::fmt::Display for NpuError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DegradedObserver(reason) => {
                write!(f, "NPU session degraded observer: {reason}")
            }
            Self::ExecutionFailed(msg) => write!(f, "NPU execution failed: {msg}"),
        }
    }
}

impl std::error::Error for NpuError {}

/// Operational state of the NPU runtime session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NpuState {
    /// Model verified and active on the AMD XDNA tile mesh.
    Active { manifest: Box<ModelManifest> },
    /// Model failed verification; running in safe observer-only mode.
    DegradedObserver {
        reason: DegradedReason,
        rollback_minimum: u64,
        expected_key_id: String,
    },
}

/// NPU session manager orchestrating inference across the multi-task model heads.
#[derive(Debug)]
pub struct NpuSession {
    state: NpuState,
    engine: std::sync::Arc<crate::npu_backend::NpuEngine>,
}

impl Clone for NpuSession {
    fn clone(&self) -> Self {
        Self {
            state: self.state.clone(),
            engine: std::sync::Arc::clone(&self.engine),
        }
    }
}

impl NpuSession {
    /// Constructs an active NPU session with a cryptographically verified model manifest.
    pub fn new_active(manifest: ModelManifest) -> Self {
        Self {
            state: NpuState::Active {
                manifest: Box::new(manifest),
            },
            engine: std::sync::Arc::new(crate::npu_backend::NpuEngine::new()),
        }
    }

    /// Constructs a degraded observer session when model verification fails.
    pub fn new_degraded(
        reason: DegradedReason,
        rollback_minimum: u64,
        expected_key_id: &str,
    ) -> Self {
        Self {
            state: NpuState::DegradedObserver {
                reason,
                rollback_minimum,
                expected_key_id: expected_key_id.to_string(),
            },
            engine: std::sync::Arc::new(crate::npu_backend::NpuEngine::new()),
        }
    }

    /// Constructs an NPU session by reading and verifying the bundle directory specified in config.
    /// Returns Active if verification succeeds, or DegradedObserver on any failure. Never panics.
    pub fn from_config(
        config: &crate::config::KavachConfig,
        verifying_key_bytes: &[u8; 32],
    ) -> Self {
        let verifying_key = match ed25519_dalek::VerifyingKey::from_bytes(verifying_key_bytes) {
            Ok(k) => k,
            Err(e) => {
                return Self::new_degraded(
                    DegradedReason::ManifestSignatureInvalid(format!("invalid verifying key: {e}")),
                    config.model.minimum_rollback_generation,
                    "reference-model-2026-b",
                );
            }
        };

        match crate::manifest::verify_bundle_dir(
            &config.model.bundle_directory,
            &verifying_key,
            config.model.minimum_rollback_generation,
        ) {
            Ok(manifest) => Self::new_active(manifest),
            Err(reason) => Self::new_degraded(
                reason,
                config.model.minimum_rollback_generation,
                "reference-model-2026-b",
            ),
        }
    }

    /// Returns the active operational state.
    pub fn state(&self) -> &NpuState {
        &self.state
    }

    /// Returns hardware provider information.
    pub fn hardware_info(&self) -> &crate::npu_backend::NpuHardwareInfo {
        self.engine.info()
    }

    /// Returns total inferences dispatched across all heads.
    pub fn total_inferences(&self) -> u64 {
        self.engine.total_inferences()
    }

    /// Returns true if the session is operating in degraded observer mode.
    pub fn is_degraded(&self) -> bool {
        matches!(self.state, NpuState::DegradedObserver { .. })
    }

    /// Formats the canonical CLI status report conforming to model-manifest-v1.md.
    pub fn format_status_report(&self) -> String {
        let hw = self.engine.info();
        match &self.state {
            NpuState::Active { manifest } => {
                let telemetry = match hw.selected_backend {
                    crate::npu_backend::ExecutionProviderBackend::AmdXdnaNpu => {
                        "CPU_BASELINE (AMD NPU detected, hardware dispatch pending)"
                    }
                    crate::npu_backend::ExecutionProviderBackend::DirectMlGpu => {
                        "CPU_BASELINE (GPU detected, DirectML dispatch pending)"
                    }
                    crate::npu_backend::ExecutionProviderBackend::NativeCpuBaseline => {
                        "CPU_BASELINE"
                    }
                };
                format!(
                    "Kavach-NPU status: ACTIVE\nmodel.bundle: {}\nmodel.version: {}\nmodel.rollback_generation: {}\nmodel.opset: {}\nexecution.provider: {}\nhardware.npu_detected: {}\nenforcement: ENABLED\ntelemetry: {}\n",
                    manifest.onnx.file,
                    manifest.bundle_version,
                    manifest.rollback_generation,
                    manifest.onnx.opset,
                    hw.selected_backend,
                    hw.device_detected,
                    telemetry
                )
            }
            NpuState::DegradedObserver {
                reason,
                rollback_minimum,
                expected_key_id,
            } => {
                let reason_code = match reason {
                    DegradedReason::BundleMissing(_) => "bundle_missing",
                    DegradedReason::ManifestSchemaInvalid(_) => "manifest_schema_invalid",
                    DegradedReason::ManifestSignatureInvalid(_) => "manifest_signature_invalid",
                    DegradedReason::OnnxHashMismatch { .. } => "onnx_hash_mismatch",
                    DegradedReason::RuntimeIncompatible(_) => "runtime_incompatible",
                    DegradedReason::RollbackRejected { .. } => "rollback_rejected",
                    DegradedReason::KeyRevoked(_) => "key_revoked",
                };

                format!(
                    "Kavach-NPU status: DEGRADED_OBSERVER\nmodel.bundle: unavailable\nmodel.reason: {reason_code}\nmodel.expected_key_id: {expected_key_id}\nmodel.rollback_minimum: {rollback_minimum}\nexecution.provider: {}\nenforcement: DISABLED (model-driven actions denied)\ntelemetry: OBSERVER_ONLY\n",
                    hw.selected_backend
                )
            }
        }
    }

    /// Evaluates Head 1: I/O Entropy Autoencoder (Target < 1.2ms on XDNA; evaluated via CPU baseline scorer).
    pub fn evaluate_io_head(&self, input: &IoInputTensor) -> Result<f32, NpuError> {
        match &self.state {
            NpuState::DegradedObserver { reason, .. } => {
                Err(NpuError::DegradedObserver(reason.clone()))
            }
            NpuState::Active { .. } => {
                Ok(self.engine.run_io_inference(&input.data))
            }
        }
    }

    /// Evaluates Head 2: C2 Network Timing TCN (Target < 2.5ms on XDNA; evaluated via CPU baseline scorer).
    pub fn evaluate_net_head(&self, input: &NetInputTensor) -> Result<f32, NpuError> {
        match &self.state {
            NpuState::DegradedObserver { reason, .. } => {
                Err(NpuError::DegradedObserver(reason.clone()))
            }
            NpuState::Active { .. } => {
                Ok(self.engine.run_net_inference(&input.data))
            }
        }
    }

    /// Evaluates Head 3: Event Sequence Embedding (Target < 0.8ms on XDNA; evaluated via CPU baseline scorer).
    pub fn evaluate_audit_head(&self, input: &AuditInputTensor) -> Result<f32, NpuError> {
        match &self.state {
            NpuState::DegradedObserver { reason, .. } => {
                Err(NpuError::DegradedObserver(reason.clone()))
            }
            NpuState::Active { .. } => {
                Ok(self.engine.run_audit_inference(&input.data))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tensor::QuantizationParams;

    fn sample_manifest() -> ModelManifest {
        ModelManifest {
            artifact_version: crate::ArtifactVersion { major: 1, minor: 0 },
            bundle_version: "1.0.0".into(),
            rollback_generation: 42,
            created_at: "2026-09-09T00:00:00Z".into(),
            key_id: "reference-model-2026-b".into(),
            onnx: crate::manifest::OnnxMetadata {
                file: "kavach_multitask_int8.onnx".into(),
                sha256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".into(),
                opset: 21,
                quantization: "int8_qdq".into(),
            },
            tensors: vec![],
            compatibility: crate::manifest::CompatibilityMatrix {
                detector: crate::manifest::SemverRange {
                    min_inclusive: "0.1.0".into(),
                    max_exclusive: "0.2.0".into(),
                },
                onnx_runtime: crate::manifest::SemverRange {
                    min_inclusive: "1.20.0".into(),
                    max_exclusive: "1.22.0".into(),
                },
            },
            evaluation_report_sha256:
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".into(),
            sbom_sha256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".into(),
        }
    }

    #[test]
    fn test_active_session_inference() {
        let manifest = sample_manifest();
        let session = NpuSession::new_active(manifest);
        assert!(!session.is_degraded());

        let io_tensor =
            IoInputTensor::from_f32_matrix(&[[0.8f32; 4]; 10], QuantizationParams::default());
        let score = session
            .evaluate_io_head(&io_tensor)
            .expect("inference succeeds");
        assert!(score > 0.0 && score <= 1.0);
    }

    #[test]
    fn test_degraded_session_fails_safe() {
        let session = NpuSession::new_degraded(
            DegradedReason::ManifestSignatureInvalid("tampered".into()),
            42,
            "reference-model-2026-b",
        );
        assert!(session.is_degraded());

        let io_tensor =
            IoInputTensor::from_f32_matrix(&[[0.8f32; 4]; 10], QuantizationParams::default());
        let err = session.evaluate_io_head(&io_tensor).unwrap_err();
        assert!(matches!(err, NpuError::DegradedObserver(_)));

        let status = session.format_status_report();
        assert!(status.contains("Kavach-NPU status: DEGRADED_OBSERVER"));
        assert!(status.contains("model.reason: manifest_signature_invalid"));
        assert!(status.contains("enforcement: DISABLED (model-driven actions denied)"));
    }
}
