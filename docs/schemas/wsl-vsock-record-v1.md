# WSL AF_VSOCK guest-write record v1

**Governing ADRs:** ADR 005 and ADR 006.  
**Framing:** each AF_VSOCK message starts with a 4-byte big-endian `u32` payload length. V1 permits 150 through 4,245 payload bytes. The fixed 149-byte prefix is big-endian; it is followed by `path_length` UTF-8 bytes. Rust memory layout is never sent directly.

| Offset | Size | Field |
|---:|---:|---|
| 0 | 2 | `major` (`u16`, supported value 1) |
| 2 | 2 | `minor` (`u16`) |
| 4 | 8 | `sequence_number` (`u64`, strictly increasing per enrolled session) |
| 12 | 8 | `guest_monotonic_ns` (`u64`) |
| 20 | 8 | `guest_realtime_ns` (`u64`) |
| 28 | 4 | `guest_process_id` (`u32`) |
| 32 | 8 | `guest_process_start_ticks` (`u64`) |
| 40 | 16 | `distribution_id` (enrollment UUID bytes) |
| 56 | 8 | `mount_namespace_id` (`u64`) |
| 64 | 32 | `executable_sha256` |
| 96 | 32 | `cgroup_sha256` (all-zero only when unavailable) |
| 128 | 1 | `operation` (`u8`: 1 write, 2 rename, 3 delete) |
| 129 | 8 | `byte_range_start` (`u64`) |
| 137 | 8 | `byte_range_length` (`u64`) |
| 145 | 2 | `flags` (`u16`, zero in v1.0) |
| 147 | 2 | `path_length` (`u16`, 1–4096) |
| 149 | variable | `normalized_path` (UTF-8, absolute `/mnt/<drive>/` path with no `.` or `..` components) |

The receiving bridge rejects zero/duplicate sequence numbers, unknown distribution IDs, nonzero v1.0 flags, invalid UTF-8/path normalization, impossible lengths, or unsupported versions before correlation. The `GuestWriteRecord` Rust type is the inert logical representation.
