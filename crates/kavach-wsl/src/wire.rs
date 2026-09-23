//! Binary wire framing and validation for WSL2 AF_VSOCK guest-write records per ADR 005 and wsl-vsock-record-v1.md.

use crate::{GuestFileOperation, GuestWriteRecord};
use kavach_core::ArtifactVersion;

/// Supported protocol major version for WSL AF_VSOCK records.
pub const SUPPORTED_VSOCK_MAJOR: u16 = 1;

/// Fixed-size prefix of a v1 AF_VSOCK payload before the variable path bytes.
pub const FIXED_HEADER_SIZE: usize = 149;

/// Minimum allowed payload size (149 bytes header + 1 byte minimum path).
pub const MIN_PAYLOAD_SIZE: usize = 150;

/// Maximum allowed payload size (149 bytes header + 4096 bytes maximum path).
pub const MAX_PAYLOAD_SIZE: usize = 4245;

/// Length prefix byte count.
pub const LENGTH_PREFIX_SIZE: usize = 4;

/// Errors that can occur during AF_VSOCK wire decoding and validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VsockWireError {
    /// Total frame length is smaller than the minimum 4-byte length prefix + header.
    FrameTooSmall {
        expected_at_least: usize,
        actual: usize,
    },
    /// Payload length prefix violates the allowed bounds (150..=4245).
    PayloadLengthOutOfBounds { length: usize },
    /// Actual frame length did not match the 4-byte length prefix.
    PayloadLengthMismatch { declared: usize, actual: usize },
    /// Protocol major version is unsupported.
    UnsupportedMajorVersion(u16),
    /// Sequence number must be strictly positive (> 0).
    ZeroSequenceNumber,
    /// Unrecognized operation byte (expected 1: Write, 2: Rename, 3: Delete).
    InvalidOperation(u8),
    /// Reserved flags must be zero in v1.0.
    NonzeroFlags(u16),
    /// Declared path length does not match available payload bytes.
    PathLengthMismatch { declared: usize, actual: usize },
    /// Path bytes are not valid UTF-8.
    InvalidUtf8Path,
    /// Path violates the normalized `/mnt/<drive>/` specification.
    NonNormalizedPath(String),
}

impl std::fmt::Display for VsockWireError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FrameTooSmall {
                expected_at_least,
                actual,
            } => {
                write!(
                    f,
                    "frame too small: expected at least {expected_at_least} bytes, got {actual}"
                )
            }
            Self::PayloadLengthOutOfBounds { length } => {
                write!(
                    f,
                    "payload length {length} out of bounds ({MIN_PAYLOAD_SIZE}..={MAX_PAYLOAD_SIZE})"
                )
            }
            Self::PayloadLengthMismatch { declared, actual } => {
                write!(
                    f,
                    "declared payload length {declared} does not match actual length {actual}"
                )
            }
            Self::UnsupportedMajorVersion(major) => {
                write!(
                    f,
                    "unsupported major version {major}; expected {SUPPORTED_VSOCK_MAJOR}"
                )
            }
            Self::ZeroSequenceNumber => {
                write!(f, "sequence number must be strictly positive (got 0)")
            }
            Self::InvalidOperation(op) => {
                write!(f, "invalid file operation byte: {op}")
            }
            Self::NonzeroFlags(flags) => {
                write!(f, "nonzero reserved flags: 0x{flags:04x}")
            }
            Self::PathLengthMismatch { declared, actual } => {
                write!(
                    f,
                    "path length mismatch: declared {declared}, available {actual}"
                )
            }
            Self::InvalidUtf8Path => {
                write!(f, "path is not valid UTF-8")
            }
            Self::NonNormalizedPath(path) => {
                write!(
                    f,
                    "path '{path}' is not a normalized absolute /mnt/<drive>/ path"
                )
            }
        }
    }
}

impl std::error::Error for VsockWireError {}

/// Validates that a path is normalized: absolute `/mnt/<drive>/...`, with no `.` or `..` components and no empty components.
pub fn is_normalized_mnt_path(path: &str) -> bool {
    if !path.starts_with("/mnt/") {
        return false;
    }

    let remainder = &path["/mnt/".len()..];
    if remainder.is_empty() {
        return false;
    }

    // Must have at least a drive identifier segment
    let segments: Vec<&str> = path.split('/').collect();
    // E.g., "/mnt/c/foo" -> ["", "mnt", "c", "foo"]
    for (i, &seg) in segments.iter().enumerate() {
        if i == 0 {
            // Leading empty string before leading slash is expected
            continue;
        }
        if i == segments.len() - 1 && seg.is_empty() {
            // Trailing slash e.g. "/mnt/c/" is allowed for directory operations
            continue;
        }
        if seg.is_empty() || seg == "." || seg == ".." {
            return false;
        }
    }

    true
}

impl GuestWriteRecord {
    /// Serializes the record into an AF_VSOCK frame with 4-byte big-endian length prefix.
    pub fn to_frame(&self) -> Result<Vec<u8>, VsockWireError> {
        if !is_normalized_mnt_path(&self.normalized_path) {
            return Err(VsockWireError::NonNormalizedPath(
                self.normalized_path.clone(),
            ));
        }

        let path_bytes = self.normalized_path.as_bytes();
        let path_len = path_bytes.len();
        if !(1..=4096).contains(&path_len) {
            return Err(VsockWireError::PathLengthMismatch {
                declared: path_len,
                actual: path_len,
            });
        }

        let payload_len = FIXED_HEADER_SIZE + path_len;
        if !(MIN_PAYLOAD_SIZE..=MAX_PAYLOAD_SIZE).contains(&payload_len) {
            return Err(VsockWireError::PayloadLengthOutOfBounds {
                length: payload_len,
            });
        }

        let mut frame = Vec::with_capacity(LENGTH_PREFIX_SIZE + payload_len);

        // 4-byte big-endian payload length prefix
        frame.extend_from_slice(&(payload_len as u32).to_be_bytes());

        // 149-byte fixed header
        frame.extend_from_slice(&self.version.major.to_be_bytes());
        frame.extend_from_slice(&self.version.minor.to_be_bytes());
        frame.extend_from_slice(&self.sequence_number.to_be_bytes());
        frame.extend_from_slice(&self.guest_monotonic_ns.to_be_bytes());
        frame.extend_from_slice(&self.guest_realtime_ns.to_be_bytes());
        frame.extend_from_slice(&self.guest_process_id.to_be_bytes());
        frame.extend_from_slice(&self.guest_process_start_ticks.to_be_bytes());
        frame.extend_from_slice(&self.distribution_id);
        frame.extend_from_slice(&self.mount_namespace_id.to_be_bytes());
        frame.extend_from_slice(&self.executable_sha256);
        frame.extend_from_slice(&self.cgroup_sha256);
        frame.push(self.operation as u8);
        frame.extend_from_slice(&self.byte_range_start.to_be_bytes());
        frame.extend_from_slice(&self.byte_range_length.to_be_bytes());
        frame.extend_from_slice(&self.flags.to_be_bytes());
        frame.extend_from_slice(&(path_len as u16).to_be_bytes());

        // Variable path bytes
        frame.extend_from_slice(path_bytes);

        Ok(frame)
    }

    /// Deserializes a record from a full AF_VSOCK frame (including 4-byte length prefix).
    pub fn from_frame(frame: &[u8]) -> Result<Self, VsockWireError> {
        if frame.len() < LENGTH_PREFIX_SIZE + MIN_PAYLOAD_SIZE {
            return Err(VsockWireError::FrameTooSmall {
                expected_at_least: LENGTH_PREFIX_SIZE + MIN_PAYLOAD_SIZE,
                actual: frame.len(),
            });
        }

        let declared_payload_len =
            u32::from_be_bytes([frame[0], frame[1], frame[2], frame[3]]) as usize;
        let actual_payload_len = frame.len() - LENGTH_PREFIX_SIZE;

        if declared_payload_len != actual_payload_len {
            return Err(VsockWireError::PayloadLengthMismatch {
                declared: declared_payload_len,
                actual: actual_payload_len,
            });
        }

        Self::from_payload(&frame[LENGTH_PREFIX_SIZE..])
    }

    /// Deserializes a record directly from payload bytes (excluding the 4-byte length prefix).
    pub fn from_payload(payload: &[u8]) -> Result<Self, VsockWireError> {
        if !(MIN_PAYLOAD_SIZE..=MAX_PAYLOAD_SIZE).contains(&payload.len()) {
            return Err(VsockWireError::PayloadLengthOutOfBounds {
                length: payload.len(),
            });
        }

        let major = u16::from_be_bytes([payload[0], payload[1]]);
        if major != SUPPORTED_VSOCK_MAJOR {
            return Err(VsockWireError::UnsupportedMajorVersion(major));
        }

        let minor = u16::from_be_bytes([payload[2], payload[3]]);

        let sequence_number = u64::from_be_bytes([
            payload[4],
            payload[5],
            payload[6],
            payload[7],
            payload[8],
            payload[9],
            payload[10],
            payload[11],
        ]);
        if sequence_number == 0 {
            return Err(VsockWireError::ZeroSequenceNumber);
        }

        let guest_monotonic_ns = u64::from_be_bytes([
            payload[12],
            payload[13],
            payload[14],
            payload[15],
            payload[16],
            payload[17],
            payload[18],
            payload[19],
        ]);
        let guest_realtime_ns = u64::from_be_bytes([
            payload[20],
            payload[21],
            payload[22],
            payload[23],
            payload[24],
            payload[25],
            payload[26],
            payload[27],
        ]);

        let guest_process_id =
            u32::from_be_bytes([payload[28], payload[29], payload[30], payload[31]]);

        let guest_process_start_ticks = u64::from_be_bytes([
            payload[32],
            payload[33],
            payload[34],
            payload[35],
            payload[36],
            payload[37],
            payload[38],
            payload[39],
        ]);

        let mut distribution_id = [0u8; 16];
        distribution_id.copy_from_slice(&payload[40..56]);

        let mount_namespace_id = u64::from_be_bytes([
            payload[56],
            payload[57],
            payload[58],
            payload[59],
            payload[60],
            payload[61],
            payload[62],
            payload[63],
        ]);

        let mut executable_sha256 = [0u8; 32];
        executable_sha256.copy_from_slice(&payload[64..96]);

        let mut cgroup_sha256 = [0u8; 32];
        cgroup_sha256.copy_from_slice(&payload[96..128]);

        let operation = match payload[128] {
            1 => GuestFileOperation::Write,
            2 => GuestFileOperation::Rename,
            3 => GuestFileOperation::Delete,
            other => return Err(VsockWireError::InvalidOperation(other)),
        };

        let byte_range_start = u64::from_be_bytes([
            payload[129],
            payload[130],
            payload[131],
            payload[132],
            payload[133],
            payload[134],
            payload[135],
            payload[136],
        ]);

        let byte_range_length = u64::from_be_bytes([
            payload[137],
            payload[138],
            payload[139],
            payload[140],
            payload[141],
            payload[142],
            payload[143],
            payload[144],
        ]);

        let flags = u16::from_be_bytes([payload[145], payload[146]]);
        if flags != 0 {
            return Err(VsockWireError::NonzeroFlags(flags));
        }

        let declared_path_len = u16::from_be_bytes([payload[147], payload[148]]) as usize;
        let available_path_len = payload.len() - FIXED_HEADER_SIZE;

        if declared_path_len != available_path_len {
            return Err(VsockWireError::PathLengthMismatch {
                declared: declared_path_len,
                actual: available_path_len,
            });
        }

        let path_str = std::str::from_utf8(&payload[FIXED_HEADER_SIZE..])
            .map_err(|_| VsockWireError::InvalidUtf8Path)?;

        if !is_normalized_mnt_path(path_str) {
            return Err(VsockWireError::NonNormalizedPath(path_str.to_string()));
        }

        Ok(GuestWriteRecord {
            version: ArtifactVersion { major, minor },
            sequence_number,
            guest_monotonic_ns,
            guest_realtime_ns,
            guest_process_id,
            guest_process_start_ticks,
            distribution_id,
            mount_namespace_id,
            executable_sha256,
            cgroup_sha256,
            operation,
            normalized_path: path_str.to_string(),
            byte_range_start,
            byte_range_length,
            flags,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_record() -> GuestWriteRecord {
        GuestWriteRecord {
            version: ArtifactVersion { major: 1, minor: 0 },
            sequence_number: 1,
            guest_monotonic_ns: 12_345_678,
            guest_realtime_ns: 1_700_000_000_000_000,
            guest_process_id: 1024,
            guest_process_start_ticks: 99_999,
            distribution_id: [0xdd; 16],
            mount_namespace_id: 4026531840,
            executable_sha256: [0xee; 32],
            cgroup_sha256: [0; 32],
            operation: GuestFileOperation::Write,
            normalized_path: "/mnt/c/Users/victim/Documents/thesis.docx".to_string(),
            byte_range_start: 0,
            byte_range_length: 4096,
            flags: 0,
        }
    }

    #[test]
    fn test_guest_write_record_roundtrip() {
        let rec = sample_record();
        let frame = rec.to_frame().expect("serialize to frame");

        assert_eq!(
            frame.len(),
            LENGTH_PREFIX_SIZE + FIXED_HEADER_SIZE + rec.normalized_path.len()
        );

        let decoded = GuestWriteRecord::from_frame(&frame).expect("deserialize from frame");
        assert_eq!(decoded, rec);
    }

    #[test]
    fn test_zero_sequence_number_rejected() {
        let mut rec = sample_record();
        rec.sequence_number = 0;
        let mut frame = sample_record().to_frame().unwrap();
        // Overwrite sequence number (offset 4 in payload = offset 8 in frame)
        frame[8..16].copy_from_slice(&0u64.to_be_bytes());

        let err = GuestWriteRecord::from_frame(&frame).unwrap_err();
        assert_eq!(err, VsockWireError::ZeroSequenceNumber);
    }

    #[test]
    fn test_unsupported_major_rejected() {
        let mut frame = sample_record().to_frame().unwrap();
        // Overwrite major (offset 0 in payload = offset 4 in frame)
        frame[4..6].copy_from_slice(&2u16.to_be_bytes());

        let err = GuestWriteRecord::from_frame(&frame).unwrap_err();
        assert_eq!(err, VsockWireError::UnsupportedMajorVersion(2));
    }

    #[test]
    fn test_invalid_operation_rejected() {
        let mut frame = sample_record().to_frame().unwrap();
        // Operation is at offset 128 in payload = offset 132 in frame
        frame[132] = 4; // invalid operation

        let err = GuestWriteRecord::from_frame(&frame).unwrap_err();
        assert_eq!(err, VsockWireError::InvalidOperation(4));
    }

    #[test]
    fn test_nonzero_flags_rejected() {
        let mut frame = sample_record().to_frame().unwrap();
        // Flags is at offset 145 in payload = offset 149 in frame
        frame[149] = 1;

        let err = GuestWriteRecord::from_frame(&frame).unwrap_err();
        assert_eq!(err, VsockWireError::NonzeroFlags(0x0100));
    }

    #[test]
    fn test_non_normalized_paths_rejected() {
        assert!(!is_normalized_mnt_path("/home/user/file"));
        assert!(!is_normalized_mnt_path("/mnt/c/../etc/passwd"));
        assert!(!is_normalized_mnt_path("/mnt/c/./file.txt"));
        assert!(!is_normalized_mnt_path("/mnt/"));
        assert!(!is_normalized_mnt_path("/mnt//c/file"));
        assert!(is_normalized_mnt_path("/mnt/c/file.txt"));
        assert!(is_normalized_mnt_path("/mnt/d/projects/code/"));
    }

    #[test]
    fn test_payload_length_mismatch_rejected() {
        let mut frame = sample_record().to_frame().unwrap();
        // Modify length prefix (offsets 0..4)
        frame[0..4].copy_from_slice(&500u32.to_be_bytes());

        let err = GuestWriteRecord::from_frame(&frame).unwrap_err();
        assert!(matches!(err, VsockWireError::PayloadLengthMismatch { .. }));
    }
}
