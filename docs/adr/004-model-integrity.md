# ADR 004: Verify model bundles before ONNX Runtime binding

**Status:** Proposed  
**Date:** 2026-09-09

## Problem

Loading an unverified `.onnx` file before `Ort::IoBinding` permits model replacement, compatibility confusion, and malformed-artifact attack surface. A hash alone cannot establish who approved an update.

## Options considered

1. Rely on installation ACLs and load the model directly. ACLs are important but do not detect rollback, installer compromise, or post-install tampering.
2. Store an unsigned SHA-256 beside the model. This detects accidental corruption but an attacker able to replace the model can replace the hash.
3. Ship a signed manifest that binds the model hash and compatibility metadata to a pinned release key.

## Recommendation

Adopt option 3. A model bundle contains the ONNX file, a canonical signed manifest, and an evaluation/SBOM reference. Before any ONNX Runtime session or I/O binding is created, the detector reads the manifest from a restrictive installation directory, validates its schema and signature against a public release key compiled into the binary, hashes the exact ONNX bytes with SHA-256, and compares it to the manifest.

The manifest includes bundle/model version, SHA-256, ONNX opset, tensor names/shapes/dtypes, quantization type, minimum/maximum compatible detector and ONNX Runtime versions, creation date, key ID, and rollback generation. Updates are staged, verified, and atomically activated only after all checks pass.

`docs/schemas/model-manifest-v1.md` is the normative artifact format and status contract. The evaluation report digest in that manifest binds the runtime artifact to the release evidence specified by ADR 001.

On absent, invalid, expired, incompatible, or mismatched bundles, Kavach must not load the model and must not emit model-driven enforcement verdicts. The service may start in a visible **degraded observer** state to report health and collect no-op diagnostics; it must not silently substitute thresholds or claim NPU protection. Administrators receive a local event and status result with the failure reason. A signed last-known-good bundle may be selected only when its rollback generation is allowed by local policy.

### Key rotation and revocation

The installed detector contains a pinned root public key and a signed keyring, rather than a single immortal model key. The root key signs a versioned keyring containing key IDs, public keys, purpose (`model`, `allowlist`, or `keyring`), validity interval, and revocation status. A bundle is valid only if its signing key is present, purpose-authorized, within its validity interval, and not revoked in the locally accepted keyring.

Rotation proceeds by shipping a root-signed keyring that overlaps the old and new model keys, then signing new bundles with the new key; the old key remains usable only through its configured retirement date. Emergency revocation ships a higher keyring generation that marks the compromised key revoked and sets a minimum acceptable keyring generation in administrator policy. The previous keyring/bundle remains only as a recovery candidate when it is not revoked and satisfies rollback policy. If keyring verification, freshness policy, or a required revocation update fails, the detector enters degraded observer mode rather than trusting a key selected by the artifact itself. Root-key replacement requires an explicitly signed dual-root transition package installed through the product update channel and cannot be triggered by an ONNX bundle.

## Trade-offs and failure modes

Pinned keys and strict compatibility can delay emergency model changes and can leave protection degraded during an update incident. Key compromise, canonicalization mistakes, hash implementation defects, and anti-rollback policy mistakes remain serious risks. Offline key rotation, dual-signature transition support, audit logs, atomic updates, and test vectors mitigate them. Fail-closed enforcement favors host safety over availability: an unavailable or untrusted model cannot trigger a destructive action.
