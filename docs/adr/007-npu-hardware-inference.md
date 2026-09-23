# ADR 007: Hardware NPU Inference via AMD XDNA and Vitis AI Execution Provider

**Status:** Proposed  
**Date:** 2026-09-24  
**Author:** Kavach-NPU Engineering  

## Problem

Kavach-NPU requires real-time inference across three threat detection heads:
1. `io_head`: Process file encryption & burst entropy analysis (`[1, 10, 4]`)
2. `net_head`: Command & Control packet inter-arrival rhythms (`[1, 32, 4]`)
3. `audit_head`: Windows Event security sequence patterns (`[1, 16, 4]`)

Running continuous neural inference on the host CPU competes for L3 cache and execution pipelines with critical user/system workloads and introduces thermal throttling on mobile workstations. To achieve true hardware-isolated EDR inference with sub-millisecond dispatch and low host-CPU interference, Kavach-NPU must offload tensor execution to the on-die AMD XDNA Neural Processing Unit (NPU).

## Options Considered

1. **DirectML Execution Provider (GPU/NPU generic)**:
   * *Pros:* Broad driver compatibility via DirectX 12; works on integrated Radeon 780M GPU and Windows Copilot+ NPUs.
   * *Cons:* Higher dispatch overhead due to D3D12 command list recording; lacks custom Phoenix X1 AIE tile optimization.
2. **Native XRT / XDNA C-API directly**:
   * *Pros:* Lowest possible dispatch overhead.
   * *Cons:* Requires bespoke model compilation per driver release; completely loses ONNX graph operator support and ecosystem updates.
3. **Microsoft ONNX Runtime + Vitis AI Execution Provider (VOE) with DirectML & CPU Fallbacks**:
   * *Pros:* Official AMD Ryzen AI deployment stack. Auto-partitions INT8 QDQ graphs onto Phoenix AIE2 tiles via `.xclbin`. Falls back to DirectML or SIMD CPU when hardware is unavailable or in non-NPU CI environments.
   * *Cons:* Requires local installation of Ryzen AI SDK and dynamic library resolution.

## Recommendation

Adopt **Option 3**. Kavach-NPU wraps ONNX Runtime sessions behind the existing `NpuSession` abstraction:
- When compiled with `--features npu-runtime` and running on hardware with the AMD NPU driver and Ryzen AI SDK present:
  - Configure Vitis AI EP with target `X1` and Phoenix microcode (`voe-4.0-win_amd64\xclbins\phoenix\1x4.xclbin`).
  - Dynamic DLL loading ensures graceful fallback if SDK environment variables are missing.
- When compiled without `npu-runtime` or when NPU hardware is absent:
  - The runtime smoothly executes the high-speed CPU weighted arithmetic baseline verified in Criterion benchmarks (sub-microsecond latency).
- Cryptographic model bundle integrity is validated **before** ONNX Runtime graph ingestion.

## Target Hardware Configuration

- **APU:** AMD Ryzen 7 7840HS (Phoenix / PHX)
- **Target EP Option:** `target: "X1"`
- **Quantization:** INT8 QDQ (symmetric, signed)
- **Fallback Chain:** Vitis AI EP (NPU) -> DirectML (Radeon 780M GPU) -> Native SIMD (Zen 4 CPU)
