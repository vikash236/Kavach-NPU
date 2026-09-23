//! Binary wire codec for the 139-byte fixed-size Verdict IPC contract per ADR 003, ADR 006, and verdict-v1.md.

use crate::{ArtifactVersion, DispatchError, EnforcementAction, Verdict};

/// The exact byte length of a v1 Verdict wire payload.
pub const VERDICT_WIRE_SIZE: usize = 139;

/// The supported protocol major version.
pub const SUPPORTED_PROTOCOL_MAJOR: u16 = 1;

/// Maximum allowed validity window (30 seconds in milliseconds).
pub const MAX_EXPIRY_WINDOW_MS: u64 = 30_000;

/// Wire decoding and validation errors for Verdict payloads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireError {
    /// Payload buffer length did not match the expected wire size.
    InvalidLength { expected: usize, actual: usize },
    /// Protocol major version is not supported by this broker.
    UnsupportedMajorVersion(u16),
    /// Unrecognized requested action byte.
    InvalidAction(u8),
    /// Reserved flags byte contained nonzero bits.
    NonzeroFlags(u8),
    /// Issued timestamp was strictly after the expiration timestamp.
    TimestampOrderViolation { issued_at: u64, expires_at: u64 },
    /// Expiration timestamp exceeded the maximum 30-second window from issuance.
    ExcessiveExpiryWindow { delta_ms: u64 },
    /// Process-level containment action (suspend/kill) requested with PID 0.
    ZeroTargetProcessId { action: EnforcementAction },
}

impl std::fmt::Display for WireError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidLength { expected, actual } => {
                write!(f, "invalid wire length: expected {expected}, got {actual}")
            }
            Self::UnsupportedMajorVersion(major) => {
                write!(
                    f,
                    "unsupported major protocol version {major}; expected {SUPPORTED_PROTOCOL_MAJOR}"
                )
            }
            Self::InvalidAction(action) => {
                write!(f, "invalid requested action byte: {action}")
            }
            Self::NonzeroFlags(flags) => {
                write!(f, "nonzero reserved flags byte: 0x{flags:02x}")
            }
            Self::TimestampOrderViolation {
                issued_at,
                expires_at,
            } => {
                write!(
                    f,
                    "timestamp order violation: issued_at ({issued_at}) > expires_at ({expires_at})"
                )
            }
            Self::ExcessiveExpiryWindow { delta_ms } => {
                write!(
                    f,
                    "expiry window ({delta_ms} ms) exceeds maximum allowed {MAX_EXPIRY_WINDOW_MS} ms"
                )
            }
            Self::ZeroTargetProcessId { action } => {
                write!(f, "invalid zero target_process_id for action {action:?}")
            }
        }
    }
}

impl std::error::Error for WireError {}

impl From<WireError> for DispatchError {
    fn from(err: WireError) -> Self {
        match err {
            WireError::UnsupportedMajorVersion(_) => DispatchError::VersionMismatch,
            WireError::InvalidLength { .. }
            | WireError::InvalidAction(_)
            | WireError::NonzeroFlags(_)
            | WireError::TimestampOrderViolation { .. }
            | WireError::ExcessiveExpiryWindow { .. }
            | WireError::ZeroTargetProcessId { .. } => DispatchError::MalformedMessage,
        }
    }
}

impl Verdict {
    /// Serializes the verdict into a fixed 139-byte big-endian wire buffer.
    pub fn to_wire(&self) -> [u8; VERDICT_WIRE_SIZE] {
        let mut buf = [0u8; VERDICT_WIRE_SIZE];

        buf[0..2].copy_from_slice(&self.protocol_version.major.to_be_bytes());
        buf[2..4].copy_from_slice(&self.protocol_version.minor.to_be_bytes());
        buf[4..20].copy_from_slice(&self.request_id);
        buf[20..28].copy_from_slice(&self.issued_at_unix_ms.to_be_bytes());
        buf[28..36].copy_from_slice(&self.expires_at_unix_ms.to_be_bytes());
        buf[36..52].copy_from_slice(&self.detector_instance_id);
        buf[52] = self.requested_action as u8;
        buf[53..85].copy_from_slice(&self.evidence_digest);
        buf[85..117].copy_from_slice(&self.model_bundle_sha256);
        buf[117..125].copy_from_slice(&self.policy_generation.to_be_bytes());
        buf[125..129].copy_from_slice(&self.target_process_id.to_be_bytes());
        buf[129..137].copy_from_slice(&self.target_process_start_filetime.to_be_bytes());
        buf[137] = self.corroborating_evidence_count;
        buf[138] = self.flags;

        buf
    }

    /// Deserializes and strictly validates a verdict from a 139-byte buffer.
    pub fn from_wire(buf: &[u8; VERDICT_WIRE_SIZE]) -> Result<Self, WireError> {
        let major = u16::from_be_bytes([buf[0], buf[1]]);
        if major != SUPPORTED_PROTOCOL_MAJOR {
            return Err(WireError::UnsupportedMajorVersion(major));
        }

        let minor = u16::from_be_bytes([buf[2], buf[3]]);

        let mut request_id = [0u8; 16];
        request_id.copy_from_slice(&buf[4..20]);

        let issued_at_unix_ms = u64::from_be_bytes([
            buf[20], buf[21], buf[22], buf[23], buf[24], buf[25], buf[26], buf[27],
        ]);
        let expires_at_unix_ms = u64::from_be_bytes([
            buf[28], buf[29], buf[30], buf[31], buf[32], buf[33], buf[34], buf[35],
        ]);

        if issued_at_unix_ms > expires_at_unix_ms {
            return Err(WireError::TimestampOrderViolation {
                issued_at: issued_at_unix_ms,
                expires_at: expires_at_unix_ms,
            });
        }

        let delta = expires_at_unix_ms - issued_at_unix_ms;
        if delta > MAX_EXPIRY_WINDOW_MS {
            return Err(WireError::ExcessiveExpiryWindow { delta_ms: delta });
        }

        let mut detector_instance_id = [0u8; 16];
        detector_instance_id.copy_from_slice(&buf[36..52]);

        let requested_action = match buf[52] {
            0 => EnforcementAction::Alert,
            1 => EnforcementAction::SuspendAndAlert,
            2 => EnforcementAction::HardKill,
            other => return Err(WireError::InvalidAction(other)),
        };

        let mut evidence_digest = [0u8; 32];
        evidence_digest.copy_from_slice(&buf[53..85]);

        let mut model_bundle_sha256 = [0u8; 32];
        model_bundle_sha256.copy_from_slice(&buf[85..117]);

        let policy_generation = u64::from_be_bytes([
            buf[117], buf[118], buf[119], buf[120], buf[121], buf[122], buf[123], buf[124],
        ]);

        let target_process_id = u32::from_be_bytes([buf[125], buf[126], buf[127], buf[128]]);

        if target_process_id == 0 && requested_action != EnforcementAction::Alert {
            return Err(WireError::ZeroTargetProcessId {
                action: requested_action,
            });
        }

        let target_process_start_filetime = u64::from_be_bytes([
            buf[129], buf[130], buf[131], buf[132], buf[133], buf[134], buf[135], buf[136],
        ]);

        let corroborating_evidence_count = buf[137];
        let flags = buf[138];

        if flags != 0 {
            return Err(WireError::NonzeroFlags(flags));
        }

        Ok(Verdict {
            protocol_version: ArtifactVersion { major, minor },
            request_id,
            issued_at_unix_ms,
            expires_at_unix_ms,
            detector_instance_id,
            requested_action,
            evidence_digest,
            model_bundle_sha256,
            policy_generation,
            target_process_id,
            target_process_start_filetime,
            corroborating_evidence_count,
            flags,
        })
    }

    /// Deserializes a verdict from an arbitrary slice, enforcing exact size and wire validation.
    pub fn from_slice(slice: &[u8]) -> Result<Self, WireError> {
        if slice.len() != VERDICT_WIRE_SIZE {
            return Err(WireError::InvalidLength {
                expected: VERDICT_WIRE_SIZE,
                actual: slice.len(),
            });
        }

        let mut buf = [0u8; VERDICT_WIRE_SIZE];
        buf.copy_from_slice(slice);
        Self::from_wire(&buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_verdict(action: EnforcementAction, pid: u32) -> Verdict {
        Verdict {
            protocol_version: ArtifactVersion { major: 1, minor: 0 },
            request_id: [0x42; 16],
            issued_at_unix_ms: 1_700_000_000_000,
            expires_at_unix_ms: 1_700_000_005_000, // 5s window
            detector_instance_id: [0xaa; 16],
            requested_action: action,
            evidence_digest: [0xbb; 32],
            model_bundle_sha256: [0xcc; 32],
            policy_generation: 7,
            target_process_id: pid,
            target_process_start_filetime: 133_000_000_000_000_000,
            corroborating_evidence_count: 3,
            flags: 0,
        }
    }

    #[test]
    fn test_verdict_wire_roundtrip() {
        let v = sample_verdict(EnforcementAction::SuspendAndAlert, 1337);
        let wire = v.to_wire();
        assert_eq!(wire.len(), VERDICT_WIRE_SIZE);

        let decoded = Verdict::from_wire(&wire).expect("valid verdict roundtrip");
        assert_eq!(decoded, v);

        let from_slice = Verdict::from_slice(&wire).expect("from_slice roundtrip");
        assert_eq!(from_slice, v);
    }

    #[test]
    fn test_alert_with_zero_pid_allowed() {
        let v = sample_verdict(EnforcementAction::Alert, 0);
        let wire = v.to_wire();
        let decoded = Verdict::from_wire(&wire).expect("alert with pid 0 is valid");
        assert_eq!(decoded.target_process_id, 0);
    }

    #[test]
    fn test_suspend_with_zero_pid_rejected() {
        let v = sample_verdict(EnforcementAction::SuspendAndAlert, 0);
        let wire = v.to_wire();
        let err = Verdict::from_wire(&wire).unwrap_err();
        assert_eq!(
            err,
            WireError::ZeroTargetProcessId {
                action: EnforcementAction::SuspendAndAlert,
            }
        );
    }

    #[test]
    fn test_hard_kill_with_zero_pid_rejected() {
        let v = sample_verdict(EnforcementAction::HardKill, 0);
        let wire = v.to_wire();
        let err = Verdict::from_wire(&wire).unwrap_err();
        assert_eq!(
            err,
            WireError::ZeroTargetProcessId {
                action: EnforcementAction::HardKill,
            }
        );
    }

    #[test]
    fn test_unsupported_major_version_rejected() {
        let v = sample_verdict(EnforcementAction::Alert, 100);
        let mut wire = v.to_wire();
        wire[0..2].copy_from_slice(&2u16.to_be_bytes()); // major = 2

        let err = Verdict::from_wire(&wire).unwrap_err();
        assert_eq!(err, WireError::UnsupportedMajorVersion(2));
        assert_eq!(DispatchError::from(err), DispatchError::VersionMismatch);
    }

    #[test]
    fn test_invalid_action_rejected() {
        let v = sample_verdict(EnforcementAction::Alert, 100);
        let mut wire = v.to_wire();
        wire[52] = 3; // invalid action 3

        let err = Verdict::from_wire(&wire).unwrap_err();
        assert_eq!(err, WireError::InvalidAction(3));
        assert_eq!(DispatchError::from(err), DispatchError::MalformedMessage);
    }

    #[test]
    fn test_nonzero_flags_rejected() {
        let v = sample_verdict(EnforcementAction::Alert, 100);
        let mut wire = v.to_wire();
        wire[138] = 0x01; // flags must be zero in v1.0

        let err = Verdict::from_wire(&wire).unwrap_err();
        assert_eq!(err, WireError::NonzeroFlags(0x01));
    }

    #[test]
    fn test_timestamp_order_violation_rejected() {
        let mut v = sample_verdict(EnforcementAction::Alert, 100);
        v.issued_at_unix_ms = 1_000_000;
        v.expires_at_unix_ms = 999_999; // expires before issued
        let wire = v.to_wire();

        let err = Verdict::from_wire(&wire).unwrap_err();
        assert_eq!(
            err,
            WireError::TimestampOrderViolation {
                issued_at: 1_000_000,
                expires_at: 999_999,
            }
        );
    }

    #[test]
    fn test_excessive_expiry_window_rejected() {
        let mut v = sample_verdict(EnforcementAction::Alert, 100);
        v.issued_at_unix_ms = 1_000_000;
        v.expires_at_unix_ms = 1_030_001; // 30,001 ms delta (> 30s)
        let wire = v.to_wire();

        let err = Verdict::from_wire(&wire).unwrap_err();
        assert_eq!(err, WireError::ExcessiveExpiryWindow { delta_ms: 30_001 });
    }

    #[test]
    fn test_invalid_length_slice_rejected() {
        let short = [0u8; 100];
        let err = Verdict::from_slice(&short).unwrap_err();
        assert_eq!(
            err,
            WireError::InvalidLength {
                expected: 139,
                actual: 100,
            }
        );
    }
}
