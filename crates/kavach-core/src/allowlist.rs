use crate::ArtifactVersion;
use crate::manifest::decode_base64;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};

/// Maximum number of allowlist entries permitted.
pub const MAX_ALLOWLIST_ENTRIES: usize = 4096;

/// Maximum paths in an entry's path scope.
pub const MAX_PATH_SCOPE_ENTRIES: usize = 32;

/// Maximum length of a path string in bytes.
pub const MAX_PATH_LENGTH_BYTES: usize = 1024;

/// Errors that can occur during allowlist verification or evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AllowlistError {
    /// Schema or JSON parsing error.
    ParseError(String),
    /// Major artifact version is not supported.
    UnsupportedMajorVersion(u16),
    /// Signature verification failed.
    SignatureVerificationFailed(String),
    /// Digest of canonical payload did not match signed_payload_sha256.
    DigestMismatch { expected: String, actual: String },
    /// Allowlist exceeded entry bounds.
    EntryCountExceeded(usize),
    /// Path scope exceeded allowable bounds.
    PathScopeExceeded { entry_id: String, count: usize },
    /// Entry path length exceeded allowable maximum.
    PathLengthExceeded { entry_id: String, len: usize },
    /// Disallowed action included in allowed_actions (only suspend_and_alert is permitted in v1).
    DisallowedAction { entry_id: String, action: String },
    /// Allowlist artifact has expired.
    ArtifactExpired { expires_at: String },
}

impl std::fmt::Display for AllowlistError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ParseError(msg) => write!(f, "allowlist parse error: {msg}"),
            Self::UnsupportedMajorVersion(v) => {
                write!(f, "unsupported allowlist major version: {v}")
            }
            Self::SignatureVerificationFailed(msg) => {
                write!(f, "allowlist signature verification failed: {msg}")
            }
            Self::DigestMismatch { expected, actual } => {
                write!(
                    f,
                    "signed payload digest mismatch: expected {expected}, actual {actual}"
                )
            }
            Self::EntryCountExceeded(c) => {
                write!(f, "entry count {c} exceeds maximum {MAX_ALLOWLIST_ENTRIES}")
            }
            Self::PathScopeExceeded { entry_id, count } => {
                write!(
                    f,
                    "entry '{entry_id}' path count {count} exceeds maximum {MAX_PATH_SCOPE_ENTRIES}"
                )
            }
            Self::PathLengthExceeded { entry_id, len } => {
                write!(
                    f,
                    "entry '{entry_id}' path length {len} exceeds maximum {MAX_PATH_LENGTH_BYTES}"
                )
            }
            Self::DisallowedAction { entry_id, action } => {
                write!(
                    f,
                    "entry '{entry_id}' contains disallowed action '{action}' (only 'suspend_and_alert' permitted)"
                )
            }
            Self::ArtifactExpired { expires_at } => {
                write!(f, "allowlist expired at {expires_at}")
            }
        }
    }
}

impl std::error::Error for AllowlistError {}

/// Authenticode signature identity for an allowlisted binary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthenticodeIdentity {
    pub publisher_subject: String,
    pub thumbprint_sha256: String,
}

/// A single allowlist rule entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AllowlistEntry {
    pub entry_id: String,
    pub image_sha256: String,
    pub authenticode: Option<AuthenticodeIdentity>,
    pub product_name: String,
    pub allowed_actions: Vec<String>,
    pub path_scope: Vec<String>,
    pub expires_at: String,
}

impl AllowlistEntry {
    /// Evaluates whether this entry matches a live binary target.
    pub fn matches(
        &self,
        target_image_sha256: &str,
        target_authenticode: Option<&AuthenticodeIdentity>,
        target_path: Option<&str>,
    ) -> bool {
        // 1. Image hash must match exactly (case-insensitive)
        if !self.image_sha256.eq_ignore_ascii_case(target_image_sha256) {
            return false;
        }

        // 2. If authenticode is specified in allowlist, live target must have matching signer
        if let Some(ref required_auth) = self.authenticode {
            match target_authenticode {
                Some(actual_auth) => {
                    if required_auth.publisher_subject != actual_auth.publisher_subject
                        || !required_auth
                            .thumbprint_sha256
                            .eq_ignore_ascii_case(&actual_auth.thumbprint_sha256)
                    {
                        return false;
                    }
                }
                None => return false,
            }
        }

        // 3. If path scope is specified, target path must match one of the allowed scopes
        if !self.path_scope.is_empty() {
            match target_path {
                Some(path) => {
                    let matched = self
                        .path_scope
                        .iter()
                        .any(|scope| scope.eq_ignore_ascii_case(path));
                    if !matched {
                        return false;
                    }
                }
                None => return false,
            }
        }

        true
    }
}

/// Signed local allowlist manifest conforming to `allowlist-v1.md`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AllowlistManifest {
    pub artifact_version: ArtifactVersion,
    pub allowlist_id: String,
    pub issued_at: String,
    pub expires_at: String,
    pub policy_generation: u64,
    pub signed_payload_sha256: String,
    pub key_id: String,
    pub entries: Vec<AllowlistEntry>,
    pub signature: String,
}

impl AllowlistManifest {
    /// Parses, validates bounds, and cryptographically verifies an allowlist manifest.
    pub fn parse_and_verify(
        json_bytes: &[u8],
        verifying_key: &VerifyingKey,
    ) -> Result<Self, AllowlistError> {
        let manifest: AllowlistManifest = serde_json::from_slice(json_bytes)
            .map_err(|e| AllowlistError::ParseError(e.to_string()))?;

        if manifest.artifact_version.major != 1 {
            return Err(AllowlistError::UnsupportedMajorVersion(
                manifest.artifact_version.major,
            ));
        }

        if manifest.entries.len() > MAX_ALLOWLIST_ENTRIES {
            return Err(AllowlistError::EntryCountExceeded(manifest.entries.len()));
        }

        for entry in &manifest.entries {
            if entry.path_scope.len() > MAX_PATH_SCOPE_ENTRIES {
                return Err(AllowlistError::PathScopeExceeded {
                    entry_id: entry.entry_id.clone(),
                    count: entry.path_scope.len(),
                });
            }

            for p in &entry.path_scope {
                if p.len() > MAX_PATH_LENGTH_BYTES {
                    return Err(AllowlistError::PathLengthExceeded {
                        entry_id: entry.entry_id.clone(),
                        len: p.len(),
                    });
                }
            }

            for action in &entry.allowed_actions {
                if action != "suspend_and_alert" {
                    return Err(AllowlistError::DisallowedAction {
                        entry_id: entry.entry_id.clone(),
                        action: action.clone(),
                    });
                }
            }
        }

        // Verify signature over the 32 raw bytes of signed_payload_sha256
        let payload_digest_bytes = hex::decode(&manifest.signed_payload_sha256)
            .map_err(|e| AllowlistError::ParseError(format!("signed_payload_sha256 hex: {e}")))?;

        let sig_bytes = decode_base64(&manifest.signature).map_err(|e| {
            AllowlistError::SignatureVerificationFailed(format!("base64 decode: {e}"))
        })?;

        if sig_bytes.len() != 64 {
            return Err(AllowlistError::SignatureVerificationFailed(format!(
                "expected 64 signature bytes, got {}",
                sig_bytes.len()
            )));
        }

        let mut sig_arr = [0u8; 64];
        sig_arr.copy_from_slice(&sig_bytes);
        let signature = Signature::from_bytes(&sig_arr);

        verifying_key
            .verify_strict(&payload_digest_bytes, &signature)
            .map_err(|e| AllowlistError::SignatureVerificationFailed(e.to_string()))?;

        Ok(manifest)
    }

    /// Checks if a suspicious target matches any valid allowlist entry.
    pub fn is_exempt(
        &self,
        target_image_sha256: &str,
        target_authenticode: Option<&AuthenticodeIdentity>,
        target_path: Option<&str>,
    ) -> bool {
        self.entries
            .iter()
            .any(|entry| entry.matches(target_image_sha256, target_authenticode, target_path))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use sha2::{Digest, Sha256};

    fn make_keypair() -> (SigningKey, VerifyingKey) {
        let mut seed = [0u8; 32];
        seed[1] = 0x99;
        let signing = SigningKey::from_bytes(&seed);
        let verifying = signing.verifying_key();
        (signing, verifying)
    }

    fn sample_allowlist_json(payload_hash: &str, sig_b64: &str) -> String {
        format!(
            r#"{{
  "artifact_version": {{"major": 1, "minor": 0}},
  "allowlist_id": "local-high-entropy-2026q3",
  "issued_at": "2026-09-09T00:00:00Z",
  "expires_at": "2026-12-31T23:59:59Z",
  "policy_generation": 7,
  "signed_payload_sha256": "{payload_hash}",
  "key_id": "allowlist-2026-a",
  "entries": [
    {{
      "entry_id": "7zip-24.09-x64",
      "image_sha256": "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
      "authenticode": {{
        "publisher_subject": "CN=Igor Pavlov",
        "thumbprint_sha256": "1122334455667788990011223344556677889900112233445566778899001122"
      }},
      "product_name": "7-Zip",
      "allowed_actions": ["suspend_and_alert"],
      "path_scope": ["C:\\Program Files\\7-Zip\\7z.exe"],
      "expires_at": "2026-12-31T23:59:59Z"
    }}
  ],
  "signature": "{sig_b64}"
}}"#
        )
    }

    #[test]
    fn test_valid_allowlist_verification_and_matching() {
        let (signing, verifying) = make_keypair();
        let payload_digest = Sha256::digest(b"canonical-allowlist-payload");
        let payload_hex = hex::encode(payload_digest);
        let sig = signing.sign(&payload_digest);
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

        let json = sample_allowlist_json(&payload_hex, &sig_b64);
        let manifest = AllowlistManifest::parse_and_verify(json.as_bytes(), &verifying)
            .expect("valid allowlist");

        assert_eq!(manifest.entries.len(), 1);

        // Matching test
        let auth = AuthenticodeIdentity {
            publisher_subject: "CN=Igor Pavlov".into(),
            thumbprint_sha256: "1122334455667788990011223344556677889900112233445566778899001122"
                .into(),
        };

        // Exact match
        assert!(manifest.is_exempt(
            "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
            Some(&auth),
            Some("C:\\Program Files\\7-Zip\\7z.exe")
        ));

        // Wrong path
        assert!(!manifest.is_exempt(
            "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
            Some(&auth),
            Some("C:\\Temp\\7z.exe")
        ));

        // Wrong signer
        let bad_auth = AuthenticodeIdentity {
            publisher_subject: "CN=Attacker".into(),
            thumbprint_sha256: "1122334455667788990011223344556677889900112233445566778899001122"
                .into(),
        };
        assert!(!manifest.is_exempt(
            "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
            Some(&bad_auth),
            Some("C:\\Program Files\\7-Zip\\7z.exe")
        ));
    }

    #[test]
    fn test_disallowed_hard_kill_action_rejected() {
        let (_signing, verifying) = make_keypair();
        let json = r#"{
  "artifact_version": {"major": 1, "minor": 0},
  "allowlist_id": "test",
  "issued_at": "2026-09-09T00:00:00Z",
  "expires_at": "2026-12-31T23:59:59Z",
  "policy_generation": 7,
  "signed_payload_sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
  "key_id": "allowlist-2026-a",
  "entries": [
    {
      "entry_id": "bad-action",
      "image_sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
      "authenticode": null,
      "product_name": "Test",
      "allowed_actions": ["hard_kill"],
      "path_scope": [],
      "expires_at": "2026-12-31T23:59:59Z"
    }
  ],
  "signature": "dummy"
}"#;

        let err = AllowlistManifest::parse_and_verify(json.as_bytes(), &verifying).unwrap_err();
        assert!(matches!(err, AllowlistError::DisallowedAction { .. }));
    }
}
