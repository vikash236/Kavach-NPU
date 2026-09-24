# Real Hardware NPU / DirectML Benchmark Results

## System Environment & Hardware Specifications

- **Processor:** AMD Ryzen 7 7840HS w/ Radeon 780M Graphics (8 physical cores, 16 logical threads)
- **NPU Hardware Device:** AMD IPU (`PCI\VEN_1022&DEV_1502`)
- **NPU Driver Version:** `32.0.20102.3930`
- **Host Memory:** 15.29 GB physical RAM
- **Operating System:** Microsoft Windows 11 Pro, Version 10.0.26200
- **Rust Toolchain:** `rustc 1.97.1 (8bab26f4f 2026-07-14)`
- **Cargo Feature Flag:** `--features npu-hardware`
- **Active Execution Provider:** DirectML (DirectX 12 Compute Pipeline on AMD Phoenix GPU/NPU)
- **ONNX Runtime Framework:** `ort v2.0.0-rc.13` dynamic binding to `onnxruntime.dll`
- **Benchmark Framework:** Criterion v0.5.1
- **Date Measured:** September 2026

---

## Criterion Measurement Summary

All measurements below report Criterion 95% confidence intervals `[lower_bound, estimate, upper_bound]` collected across 100 samples in release mode with physical hardware execution active.

### Hardware Offload Latency vs. Service Level Agreement (SLA)

| Benchmark Target | Lower Bound | Point Estimate | Upper Bound | Unit | README SLA Target | SLA Compliance |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `tripwire/npu_hardware_io_direct_dispatch` | 486.69 | **497.10** | 507.48 | µs | < 1,200 µs (1.2 ms) | **PASS** (58.6% margin) |
| `beacon/npu_hardware_net_direct_dispatch` | 446.10 | **454.62** | 462.38 | µs | < 2,500 µs (2.5 ms) | **PASS** (81.8% margin) |
| `events/npu_hardware_audit_direct_dispatch` | 415.66 | **427.22** | 437.61 | µs | < 800 µs (0.8 ms) | **PASS** (46.6% margin) |

---

## Architectural Comparison: Hardware Offload vs. CPU Baseline Scorer

| Metric / Property | CPU Baseline Arithmetic Scorer | Hardware Offload (DirectML / NPU Pipeline) |
| :--- | :--- | :--- |
| **Execution Medium** | Host CPU ALU & SIMD registers | AMD Phoenix GPU / NPU compute units via DirectX 12 |
| **Typical Latency** | 16.8 ns – 51.0 ns | 427.2 µs – 497.1 µs |
| **Memory Bus Traversal** | Zero (L1 / L2 cache resident) | CPU-to-GPU/NPU tensor allocation and command queue submission |
| **Host CPU Core Starvation** | Consumes host CPU cycles during inference | Near-zero host CPU overhead (offloaded to dedicated silicon) |
| **Driver & OS Dependency** | Pure Rust, zero external dynamic libraries | Requires Windows Display Driver Model (WDDM) / DirectX 12 / ORT DLLs |
| **Model Complexity Capacity**| Fixed linear weights only | Full ONNX computation graphs (CNN, TCN, Attention, INT8/FP16) |

---

## Systems Engineering Analysis

1. **Why Hardware Offload Latency is ~450 µs:**
   Executing an ONNX model via DirectML or Vitis AI entails allocating GPU/NPU descriptor heaps, staging input tensors across the PCI-e / memory bus, recording commands into the DirectX 12 command queue, and awaiting GPU fencing. On modern APUs, this fixed dispatch overhead is ~400–450 µs. Once submitted, the compute cores execute the tensor arithmetic in parallel.

2. **Why the CPU Baseline is ~17 ns:**
   The deterministic CPU fallback in `kavach-core` performs a tight unrolled arithmetic loop directly over the 40 INT8 values. Because the working set fits entirely within registers and L1 cache, the CPU executes it in a handful of clock cycles.

3. **Production Deployment Strategy:**
   - **Endpoint Background Monitoring:** The system routes high-volume continuous telemetry through hardware offload to ensure zero thermal or CPU throttling of user applications.
   - **Emergency Fallback:** If the GPU/NPU is under heavy graphic/compute load, or if runtime dynamic libraries are missing, Kavach falls back instantly to the CPU baseline scorer without dropping packets or missing containment deadlines.
