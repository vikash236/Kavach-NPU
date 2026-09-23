//! Multi-head tensor packing and static INT8 QDQ quantization per README and model-manifest-v1.md.

/// Quantization parameters for mapping FP32 continuous features to INT8 tensors.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct QuantizationParams {
    /// Scaling factor.
    pub scale: f32,
    /// Quantization zero-point offset (-128..=127).
    pub zero_point: i8,
}

impl Default for QuantizationParams {
    /// Default symmetric unit-scale quantization for [0.0, 1.0] normalized inputs.
    fn default() -> Self {
        Self {
            scale: 1.0 / 127.0,
            zero_point: 0,
        }
    }
}

/// Quantizes an FP32 value to INT8 using standard QDQ formula:
/// q = clamp(round(val / scale) + zero_point, -128, 127)
pub fn quantize_f32_to_i8(val: f32, params: QuantizationParams) -> i8 {
    let scaled = (val / params.scale).round() + (params.zero_point as f32);
    scaled.clamp(-128.0, 127.0) as i8
}

/// Dequantizes an INT8 value back to FP32:
/// val = (q - zero_point) * scale
pub fn dequantize_i8_to_f32(q: i8, params: QuantizationParams) -> f32 {
    ((q as f32) - (params.zero_point as f32)) * params.scale
}

// ---------------------------------------------------------------------------
// Head 1: I/O Entropy Tensor [1, 10, 4]
// ---------------------------------------------------------------------------

/// Head 1 input tensor: 10 time slots x 4 features = 40 INT8 values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IoInputTensor {
    pub data: [[i8; 4]; 10],
}

impl IoInputTensor {
    /// Constructs a tensor from a raw [10, 4] FP32 matrix using specified quantization parameters.
    pub fn from_f32_matrix(matrix: &[[f32; 4]; 10], params: QuantizationParams) -> Self {
        let mut data = [[0i8; 4]; 10];
        for (i, row) in matrix.iter().enumerate() {
            for (j, &val) in row.iter().enumerate() {
                data[i][j] = quantize_f32_to_i8(val, params);
            }
        }
        Self { data }
    }

    /// Serializes into a contiguous 40-byte buffer for zero-copy DMA transfer to NPU pinned memory.
    pub fn as_bytes(&self) -> [u8; 40] {
        let mut buf = [0u8; 40];
        let mut idx = 0;
        for row in &self.data {
            for &val in row {
                buf[idx] = val as u8;
                idx += 1;
            }
        }
        buf
    }
}

// ---------------------------------------------------------------------------
// Head 2: Network Timing Tensor [1, 32, 4]
// ---------------------------------------------------------------------------

/// Head 2 input tensor: 32 packet slots x 4 features = 128 INT8 values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetInputTensor {
    pub data: [[i8; 4]; 32],
}

impl NetInputTensor {
    /// Constructs a tensor from a raw [32, 4] FP32 matrix using specified quantization parameters.
    pub fn from_f32_matrix(matrix: &[[f32; 4]; 32], params: QuantizationParams) -> Self {
        let mut data = [[0i8; 4]; 32];
        for (i, row) in matrix.iter().enumerate() {
            for (j, &val) in row.iter().enumerate() {
                data[i][j] = quantize_f32_to_i8(val, params);
            }
        }
        Self { data }
    }

    /// Serializes into a contiguous 128-byte buffer for zero-copy DMA transfer to NPU pinned memory.
    pub fn as_bytes(&self) -> [u8; 128] {
        let mut buf = [0u8; 128];
        let mut idx = 0;
        for row in &self.data {
            for &val in row {
                buf[idx] = val as u8;
                idx += 1;
            }
        }
        buf
    }
}

// ---------------------------------------------------------------------------
// Head 3: Event Sequence Tensor [1, 16, 4]
// ---------------------------------------------------------------------------

/// Head 3 input tensor: 16 event slots x 4 features = 64 INT8 values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuditInputTensor {
    pub data: [[i8; 4]; 16],
}

impl AuditInputTensor {
    /// Constructs a tensor from a raw [16, 4] FP32 matrix using specified quantization parameters.
    pub fn from_f32_matrix(matrix: &[[f32; 4]; 16], params: QuantizationParams) -> Self {
        let mut data = [[0i8; 4]; 16];
        for (i, row) in matrix.iter().enumerate() {
            for (j, &val) in row.iter().enumerate() {
                data[i][j] = quantize_f32_to_i8(val, params);
            }
        }
        Self { data }
    }

    /// Serializes into a contiguous 64-byte buffer for zero-copy DMA transfer to NPU pinned memory.
    pub fn as_bytes(&self) -> [u8; 64] {
        let mut buf = [0u8; 64];
        let mut idx = 0;
        for row in &self.data {
            for &val in row {
                buf[idx] = val as u8;
                idx += 1;
            }
        }
        buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_quantize_dequantize_roundtrip() {
        let params = QuantizationParams {
            scale: 0.01,
            zero_point: 0,
        };

        let original = 0.50f32;
        let q = quantize_f32_to_i8(original, params);
        assert_eq!(q, 50);

        let recovered = dequantize_i8_to_f32(q, params);
        assert!((recovered - original).abs() < 1e-4);
    }

    #[test]
    fn test_quantize_clamping_limits() {
        let params = QuantizationParams {
            scale: 1.0,
            zero_point: 0,
        };

        assert_eq!(quantize_f32_to_i8(200.0, params), 127);
        assert_eq!(quantize_f32_to_i8(-200.0, params), -128);
    }

    #[test]
    fn test_io_input_tensor_byte_layout() {
        let matrix = [[0.5f32; 4]; 10];
        let tensor = IoInputTensor::from_f32_matrix(&matrix, QuantizationParams::default());
        let bytes = tensor.as_bytes();
        assert_eq!(bytes.len(), 40);
        // All 40 bytes should be identically quantized
        assert_eq!(bytes[0], bytes[39]);
    }

    #[test]
    fn test_net_input_tensor_byte_layout() {
        let matrix = [[0.25f32; 4]; 32];
        let tensor = NetInputTensor::from_f32_matrix(&matrix, QuantizationParams::default());
        let bytes = tensor.as_bytes();
        assert_eq!(bytes.len(), 128);
    }

    #[test]
    fn test_audit_input_tensor_byte_layout() {
        let matrix = [[0.75f32; 4]; 16];
        let tensor = AuditInputTensor::from_f32_matrix(&matrix, QuantizationParams::default());
        let bytes = tensor.as_bytes();
        assert_eq!(bytes.len(), 64);
    }
}
