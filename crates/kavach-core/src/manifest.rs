//! Model bundle manifest verification and degraded observer handling per ADR 004, ADR 006, and model-manifest-v1.md.

use crate::ArtifactVersion;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;

/// Degraded observer reasons when model verification fails (ADR 004).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DegradedReason {
    /// Bundle directory or expected files could not be found.
    BundleMissing(String),
    /// Schema validation failed on manifest.json.
    ManifestSchemaInvalid(String),
    /// Detached signature verification failed against the pinned key.
    ManifestSignatureInvalid(String),
    /// SHA-256 of the ONNX model did not match the manifest digest.
    OnnxHashMismatch { expected: String, actual: String },
    /// Runtime or detector version is incompatible with the bundle.
    RuntimeIncompatible(String),
    /// Rollback generation is lower than the active policy minimum.
    RollbackRejected { minimum: u64, actual: u64 },
    /// Signing key has been marked revoked in the active keyring.
    KeyRevoked(String),
}

impl std::fmt::Display for DegradedReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BundleMissing(msg) => write!(f, "bundle_missing: {msg}"),
            Self::ManifestSchemaInvalid(msg) => write!(f, "manifest_schema_invalid: {msg}"),
            Self::ManifestSignatureInvalid(msg) => write!(f, "manifest_signature_invalid: {msg}"),
            Self::OnnxHashMismatch { expected, actual } => {
                write!(
                    f,
                    "onnx_hash_mismatch: expected {expected}, actual {actual}"
                )
            }
            Self::RuntimeIncompatible(msg) => write!(f, "runtime_incompatible: {msg}"),
            Self::RollbackRejected { minimum, actual } => {
                write!(
                    f,
                    "rollback_rejected: bundle generation {actual} < minimum {minimum}"
                )
            }
            Self::KeyRevoked(key_id) => write!(f, "key_revoked: {key_id}"),
        }
    }
}

impl std::error::Error for DegradedReason {}

/// Model bundle manifest conforming to `model-manifest-v1.md`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelManifest {
    pub artifact_version: ArtifactVersion,
    pub bundle_version: String,
    pub rollback_generation: u64,
    pub created_at: String,
    pub key_id: String,
    pub onnx: OnnxMetadata,
    pub tensors: Vec<TensorContract>,
    pub compatibility: CompatibilityMatrix,
    pub evaluation_report_sha256: String,
    pub sbom_sha256: String,
}

/// Metadata for the packed ONNX model file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OnnxMetadata {
    pub file: String,
    pub sha256: String,
    pub opset: u32,
    pub quantization: String,
}

/// Input or output tensor contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TensorContract {
    pub name: String,
    pub direction: String, // "input" or "output"
    pub dtype: String,
    pub shape: Vec<u64>,
}

/// Version compatibility requirements.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompatibilityMatrix {
    pub detector: SemverRange,
    pub onnx_runtime: SemverRange,
}

/// Inclusive-min / exclusive-max version range.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SemverRange {
    pub min_inclusive: String,
    pub max_exclusive: String,
}

/// Decodes standard or URL-safe base64 strings without padding.
pub fn decode_base64(input: &str) -> Result<Vec<u8>, String> {
    let clean = input.trim().replace('=', "");
    let mut bits = 0u32;
    let mut bit_count = 0;
    let mut out = Vec::with_capacity(clean.len() * 3 / 4);

    for c in clean.chars() {
        let val = match c {
            'A'..='Z' => c as u32 - 'A' as u32,
            'a'..='z' => c as u32 - 'a' as u32 + 26,
            '0'..='9' => c as u32 - '0' as u32 + 52,
            '+' | '-' => 62,
            '/' | '_' => 63,
            '\r' | '\n' | ' ' => continue,
            other => return Err(format!("invalid base64 character '{other}'")),
        };
        bits = (bits << 6) | val;
        bit_count += 6;
        if bit_count >= 8 {
            bit_count -= 8;
            out.push(((bits >> bit_count) & 0xff) as u8);
        }
    }

    Ok(out)
}

/// Encodes bytes to standard base64 string.
pub fn encode_base64(bytes: &[u8]) -> String {
    const B64: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut s = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0] as usize;
        let b1 = if chunk.len() > 1 {
            chunk[1] as usize
        } else {
            0
        };
        let b2 = if chunk.len() > 2 {
            chunk[2] as usize
        } else {
            0
        };
        let triple = (b0 << 16) | (b1 << 8) | b2;
        s.push(B64[(triple >> 18) & 0x3f] as char);
        s.push(B64[(triple >> 12) & 0x3f] as char);
        if chunk.len() > 1 {
            s.push(B64[(triple >> 6) & 0x3f] as char);
        } else {
            s.push('=');
        }
        if chunk.len() > 2 {
            s.push(B64[triple & 0x3f] as char);
        } else {
            s.push('=');
        }
    }
    s
}

/// Verifies manifest schema, Ed25519 signature over manifest SHA-256, ONNX file hash, and rollback generation.
pub fn verify_manifest_and_onnx(
    manifest_json_bytes: &[u8],
    sig_str: &str,
    onnx_bytes: &[u8],
    verifying_key: &VerifyingKey,
    min_rollback_generation: u64,
) -> Result<ModelManifest, DegradedReason> {
    // 1. Parse manifest JSON
    let manifest: ModelManifest = serde_json::from_slice(manifest_json_bytes)
        .map_err(|e| DegradedReason::ManifestSchemaInvalid(e.to_string()))?;

    // 2. Artifact version check
    if manifest.artifact_version.major != 1 {
        return Err(DegradedReason::ManifestSchemaInvalid(format!(
            "unsupported major version {}",
            manifest.artifact_version.major
        )));
    }

    // 3. Rollback generation check
    if manifest.rollback_generation < min_rollback_generation {
        return Err(DegradedReason::RollbackRejected {
            minimum: min_rollback_generation,
            actual: manifest.rollback_generation,
        });
    }

    // 4. Verify signature over SHA-256 digest of canonical manifest bytes
    let manifest_digest = Sha256::digest(manifest_json_bytes);
    let sig_bytes = decode_base64(sig_str)
        .map_err(|e| DegradedReason::ManifestSignatureInvalid(format!("base64 decode: {e}")))?;

    if sig_bytes.len() != 64 {
        return Err(DegradedReason::ManifestSignatureInvalid(format!(
            "expected 64 signature bytes, got {}",
            sig_bytes.len()
        )));
    }

    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&sig_bytes);
    let signature = Signature::from_bytes(&sig_arr);

    verifying_key
        .verify_strict(&manifest_digest, &signature)
        .map_err(|e| DegradedReason::ManifestSignatureInvalid(e.to_string()))?;

    // 5. Verify ONNX file hash
    let onnx_digest = Sha256::digest(onnx_bytes);
    let onnx_actual_hex = hex::encode(onnx_digest);
    let expected_hex = manifest.onnx.sha256.to_ascii_lowercase();

    if onnx_actual_hex != expected_hex {
        return Err(DegradedReason::OnnxHashMismatch {
            expected: expected_hex,
            actual: onnx_actual_hex,
        });
    }

    Ok(manifest)
}

/// Verifies a complete on-disk bundle directory containing `manifest.json`, `manifest.sig`, and the ONNX file.
pub fn verify_bundle_dir(
    bundle_dir: &Path,
    verifying_key: &VerifyingKey,
    min_rollback_generation: u64,
) -> Result<ModelManifest, DegradedReason> {
    let manifest_path = bundle_dir.join("manifest.json");
    let sig_path = bundle_dir.join("manifest.sig");

    let manifest_bytes = std::fs::read(&manifest_path)
        .map_err(|e| DegradedReason::BundleMissing(format!("{}: {e}", manifest_path.display())))?;

    let sig_str = std::fs::read_to_string(&sig_path)
        .map_err(|e| DegradedReason::BundleMissing(format!("{}: {e}", sig_path.display())))?;

    // Preliminary parse to locate the ONNX filename
    let manifest_meta: serde_json::Value = serde_json::from_slice(&manifest_bytes)
        .map_err(|e| DegradedReason::ManifestSchemaInvalid(e.to_string()))?;

    let onnx_file_name = manifest_meta
        .pointer("/onnx/file")
        .and_then(|v| v.as_str())
        .ok_or_else(|| DegradedReason::ManifestSchemaInvalid("missing /onnx/file field".into()))?;

    let onnx_path = bundle_dir.join(onnx_file_name);
    let onnx_bytes = std::fs::read(&onnx_path)
        .map_err(|e| DegradedReason::BundleMissing(format!("{}: {e}", onnx_path.display())))?;

    verify_manifest_and_onnx(
        &manifest_bytes,
        &sig_str,
        &onnx_bytes,
        verifying_key,
        min_rollback_generation,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn make_test_keypair() -> (SigningKey, VerifyingKey) {
        let mut seed = [0u8; 32];
        seed[0] = 0x55;
        let signing = SigningKey::from_bytes(&seed);
        let verifying = signing.verifying_key();
        (signing, verifying)
    }

    fn sample_manifest_json(onnx_sha256: &str, rollback: u64) -> String {
        format!(
            r#"{{
  "artifact_version": {{"major": 1, "minor": 0}},
  "bundle_version": "1.0.0",
  "rollback_generation": {rollback},
  "created_at": "2026-09-09T00:00:00Z",
  "key_id": "model-2026-a",
  "onnx": {{
    "file": "kavach_multitask_int8.onnx",
    "sha256": "{onnx_sha256}",
    "opset": 21,
    "quantization": "int8_qdq"
  }},
  "tensors": [
    {{"name": "io_input", "direction": "input", "dtype": "int8", "shape": [1, 10, 4]}},
    {{"name": "io_score", "direction": "output", "dtype": "float32", "shape": [1, 1]}}
  ],
  "compatibility": {{
    "detector": {{"min_inclusive": "0.1.0", "max_exclusive": "0.2.0"}},
    "onnx_runtime": {{"min_inclusive": "1.20.0", "max_exclusive": "1.22.0"}}
  }},
  "evaluation_report_sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
  "sbom_sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
}}"#
        )
    }

    #[test]
    fn test_valid_manifest_and_onnx_verification() {
        let (signing, verifying) = make_test_keypair();
        let onnx_dummy = b"fake-onnx-model-weights";
        let onnx_hash = hex::encode(Sha256::digest(onnx_dummy));

        let manifest_str = sample_manifest_json(&onnx_hash, 42);
        let manifest_digest = Sha256::digest(manifest_str.as_bytes());
        let sig = signing.sign(&manifest_digest);

        // Encode signature as base64
        let sig_b64 = encode_base64(&sig.to_bytes());

        let verified = verify_manifest_and_onnx(
            manifest_str.as_bytes(),
            &sig_b64,
            onnx_dummy,
            &verifying,
            40, // minimum rollback generation 40 <= 42
        )
        .expect("manifest and onnx must verify");

        assert_eq!(verified.rollback_generation, 42);
        assert_eq!(verified.onnx.file, "kavach_multitask_int8.onnx");
    }

    #[test]
    fn test_onnx_hash_tamper_rejected() {
        let (signing, verifying) = make_test_keypair();
        let onnx_dummy = b"fake-onnx-model-weights";
        let onnx_hash = hex::encode(Sha256::digest(onnx_dummy));

        let manifest_str = sample_manifest_json(&onnx_hash, 42);
        let manifest_digest = Sha256::digest(manifest_str.as_bytes());
        let sig = signing.sign(&manifest_digest);
        let sig_bytes = sig.to_bytes();
        let mut sig_b64 = String::new();
        const B64: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        for chunk in sig_bytes.chunks(3) {
            let b0 = chunk[0] as usize;
            let b1 = if chunk.len() > 1 {
                chunk[1] as usize
            } else {
                0
            };
            let b2 = if chunk.len() > 2 {
                chunk[2] as usize
            } else {
                0
            };
            let triple = (b0 << 16) | (b1 << 8) | b2;
            sig_b64.push(B64[(triple >> 18) & 0x3f] as char);
            sig_b64.push(B64[(triple >> 12) & 0x3f] as char);
            if chunk.len() > 1 {
                sig_b64.push(B64[(triple >> 6) & 0x3f] as char);
            }
            if chunk.len() > 2 {
                sig_b64.push(B64[triple & 0x3f] as char);
            }
        }

        // Tamper with onnx content
        let tampered_onnx = b"tampered-onnx-model-weights";

        let err = verify_manifest_and_onnx(
            manifest_str.as_bytes(),
            &sig_b64,
            tampered_onnx,
            &verifying,
            40,
        )
        .unwrap_err();

        assert!(matches!(err, DegradedReason::OnnxHashMismatch { .. }));
    }

    #[test]
    fn test_rollback_rejected() {
        let (_signing, verifying) = make_test_keypair();
        let manifest_str = sample_manifest_json(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            30,
        );

        let err = verify_manifest_and_onnx(
            manifest_str.as_bytes(),
            "dummy_sig",
            b"data",
            &verifying,
            42, // minimum required is 42, but bundle only has 30
        )
        .unwrap_err();

        assert_eq!(
            err,
            DegradedReason::RollbackRejected {
                minimum: 42,
                actual: 30
            }
        );
    }

    #[test]
    fn test_empty_manifest_json_rejected() {
        let (_signing, verifying) = make_test_keypair();
        let err = verify_manifest_and_onnx(b"", "dummy_sig", b"", &verifying, 0).unwrap_err();
        assert!(matches!(err, DegradedReason::ManifestSchemaInvalid(_)));
    }

    #[test]
    fn test_malformed_json_rejected() {
        let (_signing, verifying) = make_test_keypair();
        let err = verify_manifest_and_onnx(b"{not valid json", "dummy_sig", b"", &verifying, 0)
            .unwrap_err();
        assert!(matches!(err, DegradedReason::ManifestSchemaInvalid(_)));
    }

    #[test]
    fn test_unsupported_major_version_rejected() {
        let (signing, verifying) = make_test_keypair();
        let onnx_dummy = b"fake-onnx-model-weights";
        let onnx_hash = hex::encode(Sha256::digest(onnx_dummy));
        let manifest_str = sample_manifest_json(&onnx_hash, 50).replace(
            r#""artifact_version": {"major": 1, "minor": 0}"#,
            r#""artifact_version": {"major": 2, "minor": 0}"#,
        );
        let manifest_digest = Sha256::digest(manifest_str.as_bytes());
        let sig = signing.sign(&manifest_digest);
        let sig_b64 = encode_base64(&sig.to_bytes());

        let err = verify_manifest_and_onnx(
            manifest_str.as_bytes(),
            &sig_b64,
            onnx_dummy,
            &verifying,
            10,
        )
        .unwrap_err();

        match err {
            DegradedReason::ManifestSchemaInvalid(msg) => {
                assert!(msg.contains("unsupported major version 2"));
            }
            other => panic!("expected ManifestSchemaInvalid, got {other:?}"),
        }
    }

    #[test]
    fn test_wrong_signing_key_rejected() {
        let (signing_a, _verifying_a) = make_test_keypair();
        let mut seed_b = [0u8; 32];
        seed_b[0] = 0x99;
        let signing_b = SigningKey::from_bytes(&seed_b);
        let verifying_b = signing_b.verifying_key();

        let onnx_dummy = b"fake-onnx-model-weights";
        let onnx_hash = hex::encode(Sha256::digest(onnx_dummy));
        let manifest_str = sample_manifest_json(&onnx_hash, 42);
        let manifest_digest = Sha256::digest(manifest_str.as_bytes());
        let sig = signing_a.sign(&manifest_digest);
        let sig_b64 = encode_base64(&sig.to_bytes());

        let err = verify_manifest_and_onnx(
            manifest_str.as_bytes(),
            &sig_b64,
            onnx_dummy,
            &verifying_b,
            40,
        )
        .unwrap_err();

        assert!(matches!(err, DegradedReason::ManifestSignatureInvalid(_)));
    }

    #[test]
    fn test_truncated_signature_rejected() {
        let (_signing, verifying) = make_test_keypair();
        let onnx_dummy = b"fake-onnx-model-weights";
        let onnx_hash = hex::encode(Sha256::digest(onnx_dummy));
        let manifest_str = sample_manifest_json(&onnx_hash, 42);

        let short_sig = encode_base64(&[0xaa; 32]);
        let err = verify_manifest_and_onnx(
            manifest_str.as_bytes(),
            &short_sig,
            onnx_dummy,
            &verifying,
            40,
        )
        .unwrap_err();

        match err {
            DegradedReason::ManifestSignatureInvalid(msg) => {
                assert!(msg.contains("expected 64 signature bytes, got 32"));
            }
            other => panic!("expected ManifestSignatureInvalid, got {other:?}"),
        }
    }

    #[test]
    fn test_base64_decode_invalid_chars() {
        let err = decode_base64("!!!invalid!!!").unwrap_err();
        assert!(err.contains("invalid base64 character '!'"));
    }

    #[test]
    fn test_base64_roundtrip_with_padding() {
        let test_cases: [&[u8]; 6] = [b"a", b"ab", b"abc", b"abcd", &[0x42; 32], &[0x7f; 64]];

        for &original in &test_cases {
            let encoded = encode_base64(original);
            let decoded = decode_base64(&encoded).expect("must decode valid base64");
            assert_eq!(decoded.as_slice(), original);
        }
    }
}
