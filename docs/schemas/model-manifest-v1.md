# Model bundle manifest v1

**Governing ADRs:** ADR 004 and ADR 006.  
**Files:** `kavach_multitask_int8.onnx`, `manifest.json`, and `manifest.sig`. `manifest.json` is UTF-8 JSON canonicalized with RFC 8785. `manifest.sig` is a base64url Ed25519 signature over the SHA-256 digest of the canonical manifest bytes. It is detached so signature bytes cannot change the signed payload.

```json
{
  "artifact_version": {"major": 1, "minor": 0},
  "bundle_version": "1.0.0",
  "rollback_generation": 42,
  "created_at": "2026-09-09T00:00:00Z",
  "key_id": "model-2026-a",
  "onnx": {
    "file": "kavach_multitask_int8.onnx",
    "sha256": "<64 lowercase hex>",
    "opset": 21,
    "quantization": "int8_qdq"
  },
  "tensors": [
    {"name": "io_input", "direction": "input", "dtype": "int8", "shape": [1, 10, 4]},
    {"name": "io_score", "direction": "output", "dtype": "float32", "shape": [1, 1]}
  ],
  "compatibility": {
    "detector": {"min_inclusive": "0.1.0", "max_exclusive": "0.2.0"},
    "onnx_runtime": {"min_inclusive": "1.20.0", "max_exclusive": "1.22.0"}
  },
  "evaluation_report_sha256": "<64 lowercase hex>",
  "sbom_sha256": "<64 lowercase hex>"
}
```

All fields are required. `rollback_generation` is a nonzero `u64`; the active local policy specifies the minimum accepted generation. Tensor `name` is ASCII and unique, `direction` is `input` or `output`, `dtype` is an allowlisted ONNX type, and every `shape` dimension is a positive `u64` except explicitly documented dynamic dimensions (none in v1). Compatibility ranges use SemVer and are inclusive/exclusive exactly as named. Unknown fields, non-canonical bytes, an unexpected file name, duplicate tensors, an unsupported opset/quantization/tensor contract, or any signature/hash mismatch invalidates the bundle before ONNX Runtime receives it.

## Degraded observer status output

`kavach status` is not implemented yet, but its model failure state is contractually represented as:

```text
Kavach-NPU status: DEGRADED_OBSERVER
model.bundle: unavailable
model.reason: manifest_signature_invalid
model.expected_key_id: model-2026-a
model.rollback_minimum: 42
enforcement: DISABLED (model-driven actions denied)
telemetry: OBSERVER_ONLY
```

The reason is a stable, non-secret code such as `bundle_missing`, `manifest_schema_invalid`, `manifest_signature_invalid`, `onnx_hash_mismatch`, `runtime_incompatible`, `rollback_rejected`, or `key_revoked`. Detailed local audit records may add diagnostics but never disclose key material.
