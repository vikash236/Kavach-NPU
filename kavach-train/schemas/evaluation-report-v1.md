# Evaluation report v1

**Governing ADR:** ADR 001.  
**Encoding:** UTF-8 JSON, canonicalized according to RFC 8785 before hashing. The model manifest in ADR 004 stores the SHA-256 of these canonical bytes. Numeric rates are JSON numbers in the inclusive range `0.0..=1.0`; durations are unsigned integer microseconds.

Every field below is required unless marked optional. Reports are release evidence, not runtime inputs, and contain no raw telemetry.

```json
{
  "schema_version": "1.0",
  "report_id": "eval-2026q3-001",
  "model_bundle_version": "1.0.0",
  "created_at": "2026-09-09T00:00:00Z",
  "dataset_manifests": [
    {"dataset_id": "io-benign-corpus-2026q3", "manifest_sha256": "<64 lowercase hex>"}
  ],
  "feature_schema_ids": ["io-window-v1", "c2-flow-v1", "event-sequence-v1"],
  "split_strategy": "host_campaign_time_v1",
  "quantization": {"format": "int8_qdq", "parity_max_score_delta": 0.01},
  "false_positive_rates": [
    {"tool": "7-Zip", "version": "24.09", "workload": "archive-create", "windows": 1000, "false_positives": 0, "rate": 0.0},
    {"tool": "VeraCrypt", "version": "1.26", "workload": "volume-write", "windows": 1000, "false_positives": 0, "rate": 0.0}
  ],
  "latency_us": [
    {"head": "io_entropy", "device": "xdna", "p50": 900, "p95": 1200, "p99": 1500, "samples": 10000}
  ],
  "drift": {
    "reference_report_sha256": "<64 lowercase hex>",
    "method": "population_stability_index_v1",
    "per_feature": [{"feature": "block_entropy", "score": 0.03, "limit": 0.10}],
    "release_gate_passed": true
  },
  "release_gate": {"passed": true, "exceptions": []}
}
```

`false_positive_rates` must include all policy-named high-entropy tools in the release’s supported platform matrix, at minimum 7-Zip, VeraCrypt, ffmpeg, git-lfs, and the approved backup tools. `windows` is the denominator and `false_positives` cannot exceed it. `latency_us` must include p50/p95/p99 and sample count for every enabled head on the target runtime/device combination. Drift compares the held-out release data to a named, immutable prior report; no reference report is allowed only for the first formally approved baseline, which records `reference_report_sha256: null` and an explicit release-gate exception.
