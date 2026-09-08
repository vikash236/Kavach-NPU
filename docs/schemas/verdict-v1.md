# Verdict IPC wire schema v1

**Governing ADRs:** ADR 003 and ADR 006.  
**Transport:** a local named-pipe message. The payload is exactly 139 bytes, with multi-byte unsigned integers encoded big-endian. No Rust memory layout is used as serialization.

| Offset | Size | Field | Type and validity |
|---:|---:|---|---|
| 0 | 2 | `major` | `u16`; broker accepts only supported major `1`. |
| 2 | 2 | `minor` | `u16`; unknown additions require zero/default semantics. |
| 4 | 16 | `request_id` | 128-bit cryptographically random nonce; retained in replay cache through expiry plus 60 seconds. |
| 20 | 8 | `issued_at_unix_ms` | `u64`; diagnostic only; must not be later than expiry. |
| 28 | 8 | `expires_at_unix_ms` | `u64`; maximum 30 seconds after issue. |
| 36 | 16 | `detector_instance_id` | 128-bit authenticated service-instance identifier. |
| 52 | 1 | `requested_action` | `u8`: 0 alert, 1 suspend-and-alert, 2 hard-kill; other values invalid. |
| 53 | 32 | `evidence_digest` | SHA-256 of immutable evidence record. |
| 85 | 32 | `model_bundle_sha256` | SHA-256 of the ADR 004 verified model bundle. |
| 117 | 8 | `policy_generation` | `u64`, must equal the broker’s active policy generation. |
| 125 | 4 | `target_process_id` | `u32`; nonzero for suspend/hard-kill. |
| 129 | 8 | `target_process_start_filetime` | `u64`; must match the live process to prevent PID reuse. |
| 137 | 1 | `corroborating_evidence_count` | `u8`; hard-kill policy requires the configured minimum. |
| 138 | 1 | `flags` | `u8`; zero in v1.0. |

Named-pipe ACL/token authentication supplies peer identity; this payload is not a substitute for it. The detector cannot assert that a model is healthy: the broker obtains verified/degraded state from its own trusted local state and treats `model_bundle_sha256` only as a binding check. The Rust `Verdict` type is a design contract for these fields, not a serializer.
