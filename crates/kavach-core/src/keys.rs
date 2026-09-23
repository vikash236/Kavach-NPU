//! Cryptographic key constants and release keyring bindings per ADR 004.

use ed25519_dalek::{SigningKey, VerifyingKey};

/// Seed used to generate the deterministic development keypair for local builds.
pub const DEV_SEED: &[u8; 32] = b"kavach-npu-dev-ed25519-seed-2026";

/// The corresponding Ed25519 public key bytes for `DEV_SEED`.
pub const PINNED_DEV_PUBLIC_KEY: [u8; 32] = [
    37, 54, 218, 81, 216, 45, 38, 69, 195, 161, 121, 211, 185, 198, 4, 112, 17, 62, 67, 101,
    174, 179, 234, 233, 95, 226, 58, 203, 208, 178, 241, 1,
];

/// Hex-encoded string of `PINNED_DEV_PUBLIC_KEY`.
pub const PINNED_DEV_PUBLIC_KEY_HEX: &str =
    "2536da51d82d2645c3a179d3b9c60470113e4365aeb3eae95fe23acbd0b2f101";

/// Returns the development signing key.
pub fn dev_signing_key() -> SigningKey {
    SigningKey::from_bytes(DEV_SEED)
}

/// Returns the development verifying key.
pub fn dev_verifying_key() -> VerifyingKey {
    dev_signing_key().verifying_key()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pinned_dev_key_consistency() {
        let vk = dev_verifying_key();
        let bytes = vk.to_bytes();
        assert_eq!(bytes, PINNED_DEV_PUBLIC_KEY);
        assert_eq!(hex::encode(bytes), PINNED_DEV_PUBLIC_KEY_HEX);
    }
}
