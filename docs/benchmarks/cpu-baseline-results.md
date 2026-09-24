# CPU Baseline Benchmark Results

## System Environment & Hardware Specifications

- **Processor:** AMD Ryzen 7 7840HS w/ Radeon 780M Graphics (8 physical cores, 16 logical processors)
- **Host Memory:** 15.29 GB physical RAM
- **Operating System:** Microsoft Windows 11 Pro, Version 10.0.26200
- **Rust Toolchain:** `rustc 1.97.1 (8bab26f4f 2026-07-14)`
- **Cargo Profile:** `bench [optimized]`
- **Benchmark Framework:** Criterion v0.5.1
- **Date Measured:** September 2026

---

## Criterion Measurement Summary

All measurements below report Criterion 95% confidence intervals `[lower_bound, estimate, upper_bound]` collected across 100 samples (10 samples for the multi-engine concurrent stress benchmark) in release mode.

### 1. Tripwire Suite (`benches/tripwire.rs`)

| Benchmark Target | Lower Bound | Point Estimate | Upper Bound | Unit |
| :--- | :--- | :--- | :--- | :--- |
| `tripwire/shannon_4kb_block` | 1.5576 | **1.6415** | 1.7151 | µs |
| `tripwire/shannon_1mb_file` | 506.69 | **512.02** | 517.14 | µs |
| `tripwire/differential_10_blocks` | 60.481 | **60.932** | 61.440 | µs |
| `tripwire/sliding_window_burst_eval` | 5.2948 | **5.7089** | 6.1157 | µs |
| `tripwire/npu_tensor_pack_io` | 179.08 | **181.32** | 183.95 | ns |
| `tripwire/npu_session_io_inference` | 29.695 | **30.058** | 30.439 | ns |

### 2. Beacon Suite (`benches/beacon.rs`)

| Benchmark Target | Lower Bound | Point Estimate | Upper Bound | Unit |
| :--- | :--- | :--- | :--- | :--- |
| `beacon/flow_key_hash` | 58.913 | **59.531** | 60.106 | ns |
| `beacon/rolling_ring_32pkt_ingest` | 12.592 | **13.017** | 13.486 | ns |
| `beacon/c2_beacon_eval_full` | 1.3592 | **1.3707** | 1.3818 | µs |
| `beacon/tcn_engine_ingest_and_eval` | 1.4544 | **1.4656** | 1.4779 | µs |
| `beacon/npu_tensor_pack_net` | 638.18 | **642.42** | 647.16 | ns |
| `beacon/npu_session_net_inference` | 50.505 | **50.989** | 51.545 | ns |

### 3. Events Suite (`benches/events.rs`)

| Benchmark Target | Lower Bound | Point Estimate | Upper Bound | Unit |
| :--- | :--- | :--- | :--- | :--- |
| `events/event_ingest_single` | 346.50 | **356.59** | 364.44 | ns |
| `events/brute_force_pattern_detection` | 473.72 | **479.69** | 485.59 | ns |
| `events/build_tensor_matrix_16x4` | 1.6451 | **1.6621** | 1.6780 | µs |
| `events/npu_tensor_pack_audit` | 322.72 | **336.04** | 349.30 | ns |
| `events/npu_session_audit_inference` | 23.745 | **23.907** | 24.075 | ns |

### 4. WSL Bridge Suite (`benches/wsl.rs`)

| Benchmark Target | Lower Bound | Point Estimate | Upper Bound | Unit |
| :--- | :--- | :--- | :--- | :--- |
| `wsl/path_translation_single` | 323.14 | **326.36** | 329.67 | ns |
| `wsl/clock_sync_estimate` | 23.252 | **23.406** | 23.569 | ns |
| `wsl/correlate_guest_record` | 1.4995 | **1.5105** | 1.5204 | µs |

### 5. Multi-Engine Stress Suite (`benches/stress.rs`)

| Benchmark Target | Lower Bound | Point Estimate | Upper Bound | Unit |
| :--- | :--- | :--- | :--- | :--- |
| `stress/concurrent_4engine_stress_iteration` | 701.01 | **800.32** | 921.92 | µs |

---

## Raw Execution Notes

- All 5 benchmark binaries completed with exit code 0 and zero panics.
- Benchmarks executed against the deterministic CPU baseline scoring fallback (`NpuEngine` INT8 matrix multiply on host CPU).
- No direct NPU hardware offload session is active during these measurements; direct hardware dispatch remains pending native vendor runtime integration.
