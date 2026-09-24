//! Public verification-key bindings per ADR 004 and ADR 009.

use ed25519_dalek::VerifyingKey;

/// Rotated Ed25519 public key for the explicitly non-production reference bundle.
///
/// The value is replaced during the audited rotation procedure in ADR 009. Private
/// signing material is deliberately never compiled into or committed to this crate.
pub const PINNED_REFERENCE_PUBLIC_KEY: [u8; 32] = [
    216, 16, 13, 239, 132, 89, 195, 213, 92, 112, 152, 19, 86, 109, 193, 194, 113, 140, 2, 74, 6,
    25, 162, 54, 197, 120, 188, 223, 15, 14, 234, 175,
];

/// Returns the pinned reference-bundle verification key.
pub fn pinned_reference_verifying_key() -> VerifyingKey {
    VerifyingKey::from_bytes(&PINNED_REFERENCE_PUBLIC_KEY)
        .expect("the compiled-in reference public key must be valid")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pinned_reference_key_is_valid() {
        let vk = pinned_reference_verifying_key();
        let bytes = vk.to_bytes();
        assert_eq!(bytes, PINNED_REFERENCE_PUBLIC_KEY);
    }
}
