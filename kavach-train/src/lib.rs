//! Inert contract crate for the external training pipeline described by ADR 001.

/// Identifies a versioned dataset manifest accepted by the future training pipeline under ADR 001.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DatasetManifestReference {
    /// Stable dataset identifier assigned by the data steward.
    pub dataset_id: String,
    /// SHA-256 digest of the canonical dataset manifest bytes.
    pub manifest_sha256: [u8; 32],
}
