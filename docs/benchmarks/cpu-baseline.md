# Kavach-NPU: CPU Baseline Benchmark Results & SLA Validation

**Platform:** AMD Ryzen 7 7840HS (8 cores / 16 threads, 3.8 GHz base / 5.1 GHz boost), Windows 11  
**Toolchain:** `rustc 1.86.0`, profile `bench [optimized]`, Criterion `0.5.1`  
**Date:** September 2026

---

## 1. Summary vs README Compute Budget SLAs

| Engine / Component | Metric Measured | README SLA Budget | CPU Baseline Result | Status |
| :--- | :--- | :--- | :--- | :--- |
| **Tripwire (Head 1)** | 4KB Shannon Entropy | $\ge$ 500 MB/s | **2,570 MB/s** (1.59 µs/block) | ✅ **5.1x over SLA** |
| **Tripwire (Head 1)** | 1MB File Entropy | $\ge$ 400 MB/s | **2,260 MB/s** (463.8 µs/file) | ✅ **5.6x over SLA** |
| **Tripwire (Head 1)** | 50ms Burst Window Evaluation | $< 1.2\text{ ms}$ | **5.85 µs** | ✅ **205x faster than SLA** |
| **Tripwire (Head 1)** | Head 1 INT8 Tensor Pack `[1,10,4]` | — | **154.8 ns** | ✅ Sub-microsecond |
| **Beacon (Head 2)** | FlowKey Hash Lookup | — | **51.4 ns** | ✅ Sub-microsecond |
| **Beacon (Head 2)** | 32-Packet Ring Ingestion | — | **12.0 ns** / packet | ✅ 83M packets/sec |
| **Beacon (Head 2)** | Full 32-Packet C2 Rhythm Eval | $< 2.5\text{ ms}$ | **1.19 µs** | ✅ **2,100x faster than SLA** |
| **Beacon (Head 2)** | Head 2 INT8 Tensor Pack `[1,32,4]` | — | **537.9 ns** | ✅ Sub-microsecond |
| **Events (Head 3)** | Security Event Ingest & Match | $< 0.8\text{ ms}$ | **372.0 ns** | ✅ **2,150x faster than SLA** |
| **Events (Head 3)** | Brute-force Sequence Correlation | $< 0.8\text{ ms}$ | **415.9 ns** | ✅ **1,920x faster than SLA** |
| **Events (Head 3)** | 16x4 Feature Matrix Extraction | — | **1.59 µs** | ✅ Sub-microsecond |
| **Events (Head 3)** | Head 3 INT8 Tensor Pack `[1,16,4]` | — | **255.0 ns** | ✅ Sub-microsecond |
| **WSL2 Bridge** | Path Translation (`/mnt/c/...`) | — | **269.4 ns** | ✅ Sub-microsecond |
| **WSL2 Bridge** | Clock Sync Challenge Offset | — | **20.2 ns** | ✅ 49.5M ops/sec |
| **WSL2 Bridge** | Host-Guest Correlation Join | $< 250\text{ ms}$ | **1.21 µs** | ✅ **206,000x faster than window** |
| **Full Concurrency** | 4 Engines Under Simultaneous Load | — | **1.09 ms** / batch | ✅ Zero panics / leaks |

---

## 2. Detailed Criterion Benchmark Breakdown

### Suite A: `benches/tripwire.rs`
- **`shannon_4kb_block`**: `1.5912 µs` ($\approx 2.57 \text{ GB/s}$)
  - Shannon entropy computation across 4096-byte memory buffers. Exceeds the 500 MB/s requirement by more than 5x.
- **`shannon_1mb_file`**: `463.81 µs` ($\approx 2.26 \text{ GB/s}$)
  - Throughput for full 1MB memory mapped files.
- **`differential_10_blocks`**: `54.21 µs`
  - 10-block differential scan generating sparse entropy profiles (mean, variance, max, intermittent encryption score).
- **`sliding_window_burst_eval`**: `5.8537 µs`
  - Sliding 50ms window tracking file mutations and evaluating burst suspension thresholds.
- **`npu_tensor_pack_io`**: `154.83 ns`
  - Quantization and packaging of the `[1, 10, 4]` INT8 tensor for NPU Head 1 inference.

### Suite B: `benches/beacon.rs`
- **`flow_key_hash`**: `51.435 ns`
  - 5-tuple hash calculation for network stream lookup.
- **`rolling_ring_32pkt_ingest`**: `12.002 ns`
  - Zero-allocation rolling ring buffer push for incoming packet metadata.
- **`c2_beacon_eval_full`**: `1.1941 µs`
  - Inter-arrival delta calculation, mean, standard deviation, and coefficient of variation ($CV \le 0.35$).
- **`tcn_engine_ingest_and_eval`**: `1.2675 µs`
  - Integrated 5-tuple lookup, ingestion, and evaluation trigger.
- **`npu_tensor_pack_net`**: `537.91 ns`
  - Quantization and formatting of the `[1, 32, 4]` INT8 tensor for NPU Head 2 inference.

### Suite C: `benches/events.rs`
- **`event_ingest_single`**: `372.05 ns`
  - Windows Event Log ingestion into rolling sequence window.
- **`brute_force_pattern_detection`**: `415.90 ns`
  - Temporal sequence correlation detecting multi-failed logons followed by success on the same account.
- **`build_tensor_matrix_16x4`**: `1.5920 µs`
  - Dense `[16, 4]` feature matrix generation for NPU Head 3.
- **`npu_tensor_pack_audit`**: `255.04 ns`
  - Quantization into `[1, 16, 4]` INT8 tensor format.

### Suite D: `benches/wsl.rs`
- **`path_translation_single`**: `269.37 ns`
  - Zero-allocation string normalization translating `/mnt/<drive>/...` to Windows canonical paths (`D:\...`).
- **`clock_sync_estimate`**: `20.202 ns`
  - Conservative uncertainty bound calculation over the 5 most recent challenge-response samples.
- **`correlate_guest_record`**: `1.2145 µs`
  - Cross-boundary join associating guest write records with host ETW file events within the 250ms window.

### Suite E: `benches/stress.rs`
- **`concurrent_4engine_stress_iteration`**: `1.0988 ms`
  - 4 concurrent OS worker threads simultaneously executing:
    - 200 ransomware block writes across 8 distinct PIDs
    - 100 C2 beacon packets across outbound network flows
    - 100 Windows Security events
    - 50 cross-boundary WSL2 file write correlations
  - Sustained with **0 dropped events, 0 memory leaks, 0 panics**.
