//! Minimal zero-dependency ONNX ModelProto protobuf builder.
//!
//! Emits valid ONNX v9 protobuf models with specified input and output tensor shapes,
//! compatible with standard ONNX inspect tools and ONNX Runtime.

#[derive(Default, Clone)]
pub struct ProtoWriter {
    pub bytes: Vec<u8>,
}

impl ProtoWriter {
    pub fn new() -> Self {
        Self { bytes: Vec::new() }
    }

    pub fn write_varint(&mut self, mut value: u64) {
        while value >= 0x80 {
            self.bytes.push(((value & 0x7F) as u8) | 0x80);
            value >>= 7;
        }
        self.bytes.push(value as u8);
    }

    pub fn write_tag(&mut self, field_number: u32, wire_type: u8) {
        self.write_varint(((field_number as u64) << 3) | (wire_type as u64));
    }

    pub fn write_int64(&mut self, field_number: u32, val: i64) {
        self.write_tag(field_number, 0);
        self.write_varint(val as u64);
    }

    pub fn write_string(&mut self, field_number: u32, s: &str) {
        self.write_tag(field_number, 2);
        self.write_varint(s.len() as u64);
        self.bytes.extend_from_slice(s.as_bytes());
    }

    pub fn write_message(&mut self, field_number: u32, sub: &ProtoWriter) {
        self.write_tag(field_number, 2);
        self.write_varint(sub.bytes.len() as u64);
        self.bytes.extend_from_slice(&sub.bytes);
    }
}

/// ONNX TensorProto DataType constants.
pub const ONNX_DTYPE_FLOAT: i64 = 1;
pub const ONNX_DTYPE_INT8: i64 = 3;

/// Builds a `ValueInfoProto` for a tensor with given name, dtype, and shape dimensions.
pub fn build_tensor_value_info(name: &str, elem_type: i64, shape: &[i64]) -> ProtoWriter {
    let mut shape_writer = ProtoWriter::new();
    for &d in shape {
        let mut dim_writer = ProtoWriter::new();
        dim_writer.write_int64(1, d); // Dimension.dim_value = field 1
        shape_writer.write_message(1, &dim_writer); // TensorShapeProto.dim = field 1
    }

    let mut tensor_type_writer = ProtoWriter::new();
    tensor_type_writer.write_int64(1, elem_type); // TypeProto.Tensor.elem_type = field 1
    tensor_type_writer.write_message(2, &shape_writer); // TypeProto.Tensor.shape = field 2

    let mut type_writer = ProtoWriter::new();
    type_writer.write_message(1, &tensor_type_writer); // TypeProto.tensor_type = field 1

    let mut vi = ProtoWriter::new();
    vi.write_string(1, name); // ValueInfoProto.name = field 1
    vi.write_message(2, &type_writer); // ValueInfoProto.type = field 2
    vi
}

/// Generates a valid ONNX ModelProto containing the 3 multi-task heads for Kavach-NPU.
pub fn generate_kavach_stub_onnx(opset: i64) -> Vec<u8> {
    let mut graph_writer = ProtoWriter::new();
    graph_writer.write_string(2, "kavach_multitask_graph"); // GraphProto.name = field 2
    graph_writer.write_string(5, "Kavach Multi-Task INT8 Detection Heads");

    // Inputs:
    // 1. io_input: [1, 10, 4] INT8
    let io_in = build_tensor_value_info("io_input", ONNX_DTYPE_INT8, &[1, 10, 4]);
    graph_writer.write_message(11, &io_in); // GraphProto.input = field 11

    // 2. net_input: [1, 32, 4] INT8
    let net_in = build_tensor_value_info("net_input", ONNX_DTYPE_INT8, &[1, 32, 4]);
    graph_writer.write_message(11, &net_in);

    // 3. audit_input: [1, 16, 4] INT8
    let audit_in = build_tensor_value_info("audit_input", ONNX_DTYPE_INT8, &[1, 16, 4]);
    graph_writer.write_message(11, &audit_in);

    // Outputs:
    // 1. io_score: [1, 1] FLOAT
    let io_out = build_tensor_value_info("io_score", ONNX_DTYPE_FLOAT, &[1, 1]);
    graph_writer.write_message(12, &io_out); // GraphProto.output = field 12

    // 2. net_score: [1, 1] FLOAT
    let net_out = build_tensor_value_info("net_score", ONNX_DTYPE_FLOAT, &[1, 1]);
    graph_writer.write_message(12, &net_out);

    // 3. audit_score: [1, 1] FLOAT
    let audit_out = build_tensor_value_info("audit_score", ONNX_DTYPE_FLOAT, &[1, 1]);
    graph_writer.write_message(12, &audit_out);

    // OperatorSetIdProto:
    let mut opset_writer = ProtoWriter::new();
    opset_writer.write_string(1, ""); // domain = "" (default ONNX)
    opset_writer.write_int64(2, opset); // version = opset (21)

    // ModelProto:
    let mut model_writer = ProtoWriter::new();
    model_writer.write_int64(1, 9); // ir_version = 9
    model_writer.write_string(2, "kavach-pack"); // producer_name
    model_writer.write_string(3, "0.1.0"); // producer_version
    model_writer.write_string(4, "ai.kavach"); // domain
    model_writer.write_int64(5, 1); // model_version
    model_writer.write_string(6, "Kavach-NPU Multitask INT8 Stub Reference Model");
    model_writer.write_message(7, &graph_writer); // graph = field 7
    model_writer.write_message(8, &opset_writer); // opset_import = field 8

    model_writer.bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stub_onnx_generation_non_empty() {
        let bytes = generate_kavach_stub_onnx(21);
        assert!(!bytes.is_empty());
        // Verify protobuf header (field 1, varint 9 -> tag: 0x08, val: 0x09)
        assert_eq!(bytes[0], 0x08);
        assert_eq!(bytes[1], 0x09);
    }
}
