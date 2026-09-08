# ADR 001: Model provenance and training pipeline

**Status:** Proposed  
**Date:** 2026-09-09

## Problem

`kavach_multitask_int8.onnx` is named in the architecture, but no model, data lineage, labels, evaluation record, or reproducible export process exists. Shipping an unexplained model would make a security verdict neither reviewable nor safely updatable.

## Options considered

1. Hand-author entropy and timing thresholds and call the result a model. This is quick and deterministic, but does not supply the promised multi-head model or a defensible calibration record.
2. Train all heads on mixed, public security datasets. This simplifies collection, but blends incompatible feature definitions and licenses; it also omits the normal enterprise workloads responsible for many false positives.
3. Maintain a separate `kavach-train` pipeline that builds head-specific, versioned datasets and exports one reviewed ONNX artifact. Only the artifact, manifest, and evaluation summary are release inputs to this repository.

## Recommendation

Adopt option 3. `kavach-train` is a separate, access-controlled training project; this repository never contains raw customer telemetry or training credentials.

Each dataset release records source, license/consent, collection window, feature schema, label policy, split seed, and cryptographic digest. Splits are by host/campaign/time period, never random events alone, to prevent leakage.

| Head | Data source | Labeling approach |
|---|---|---|
| I/O entropy | Consent-based clean workload traces (archives, backup, media transcode, source control), public ransomware execution traces where licensing permits, and isolated lab executions | File-write windows receive benign/ransomware/destructive labels from controlled ground truth; analyst review resolves ambiguous tools. High entropy by itself is explicitly a benign-capable feature. |
| C2 timing | Isolated replay/capture corpus of approved C2 frameworks and benign SaaS, update, streaming, VPN, and developer traffic | Scenario manifest supplies flow labels; analysts verify destination and process lineage. Augmentation is limited to timing perturbation and documented. |
| Event sequences | Sanitized Windows Event Log and Linux audit/eBPF sequences from test ranges plus consented normal baselines | Attack-run playbooks establish labels and MITRE technique tags; sequence labels require event ordering and host/process identity, not event ID alone. |

The pipeline shape is: ingest and redact -> validate schema/license -> derive stable features -> label and adjudicate -> host-separated train/validation/test -> calibrate per-head thresholds -> evaluate against benign edge cases -> train/export FP32 -> static INT8 QDQ quantize -> ONNX checker and CPU/NPU parity checks -> produce signed model manifest, SBOM, and evaluation report. The release gate includes false-positive rates for named high-entropy software, latency, model drift checks, and rollback compatibility.

## Trade-offs and failure modes

This costs collection and analyst time, and public malware corpora cannot represent every enterprise. A stale corpus can overfit old ransomware or label a new backup product as malicious. Data poisoning, accidental customer identifiers, train/test leakage, and quantization-induced score drift are material risks. Versioned provenance, redaction review, host-separated splits, approval gates, and held-out benign workloads reduce those risks but do not eliminate them. A model that lacks its manifest or required evaluation evidence is not eligible for release.
