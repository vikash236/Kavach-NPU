# Signed local allowlist v1

**Governing ADRs:** ADR 002, ADR 004, ADR 006.  
**Encoding:** UTF-8 JSON, canonicalized with RFC 8785. `signature` is excluded while computing `signed_payload_sha256`; the Ed25519 signature covers the 32 raw SHA-256 bytes. The verification key is identified by `key_id` and is trusted only through the signed keyring in ADR 004.

```json
{
  "artifact_version": {"major": 1, "minor": 0},
  "allowlist_id": "local-high-entropy-2026q3",
  "issued_at": "2026-09-09T00:00:00Z",
  "expires_at": "2026-12-31T23:59:59Z",
  "policy_generation": 7,
  "signed_payload_sha256": "<64 lowercase hex>",
  "key_id": "allowlist-2026-a",
  "entries": [
    {
      "entry_id": "7zip-24.09-x64",
      "image_sha256": "<64 lowercase hex>",
      "authenticode": {
        "publisher_subject": "CN=Igor Pavlov",
        "thumbprint_sha256": "<64 lowercase hex>"
      },
      "product_name": "7-Zip",
      "allowed_actions": ["suspend_and_alert"],
      "path_scope": ["C:\\Program Files\\7-Zip\\7z.exe"],
      "expires_at": "2026-12-31T23:59:59Z"
    }
  ],
  "signature": "<base64url 64-byte Ed25519 signature>"
}
```

All top-level fields and every entry field are required except `authenticode`, which may be `null` only for a hash-pinned internal executable approved by policy. `artifact_version.major` is a `u16`; `minor` is a `u16`; `policy_generation` is a monotonically increasing `u64`; timestamps are RFC 3339 UTC strings; IDs are ASCII `[a-z0-9][a-z0-9._-]{0,63}`; digests are lowercase SHA-256 hex. `entries` is bounded to 4,096 items and `path_scope` to 32 paths of at most 1,024 UTF-8 bytes each.

An entry matches only when the image hash matches and, if `authenticode` is present, both subject and thumbprint match the verified image signature. `path_scope` narrows a match; it never authorizes by path alone. `allowed_actions` may contain only `suspend_and_alert`; `hard_kill` is deliberately invalid in v1. Duplicate `entry_id`, duplicate image/hash/signer/scope tuples, unknown fields, an expired artifact or entry, an untrusted/revoked key, or any signature/hash failure invalidates the entire artifact. A valid allowlist suppresses automatic containment but never suppresses evidence collection or non-file-write protections.
