# Kavach-NPU: Hardware & NPU Integration Architecture

**Platform Target:** AMD Ryzen 7 7840HS (Phoenix / PHX APU)  
**NPU IP:** AMD XDNA 1 Neural Processing Unit (AIE2 Array)  
**Host OS:** Windows 11 64-bit  
**Driver Target:** `32.0.20102.3930` (OEM HP / Production) or >= 32.0.203.280 (WHQL)  
**Execution Providers:** Vitis AI Execution Provider (VOE 4.0), DirectML (fallback)  
**Date:** September 2026

---

## 1. System Hardware & Topology

On the AMD Ryzen 7 7840HS platform, the NPU hardware topology is configured as follows:

```
+-----------------------------------------------------------------------+
|                       AMD Ryzen 7 7840HS APU                          |
|                                                                       |
|  +--------------------+   +--------------------+   +---------------+  |
|  | Zen 4 CPU (8C/16T) |   | Radeon 780M (RDNA3)|   | AMD XDNA NPU  |  |
|  |  - Kernel Sensors  |   |  - Optional GPU EP |   |  (AIE2 Array) |  |
|  |  - ETW / WFP       |   |                    |   |  - 4x4 Tiles  |  |
|  |  - Feature Pack    |   |                    |   |  - Local SRAM |  |
|  +---------+----------+   +--------------------+   +-------+-------+  |
|            |                                               |          |
|            +-----------------------+-----------------------+          |
|                                    |                                  |
|                            Infinity Fabric                            |
|                                    |                                  |
|            +-----------------------+-----------------------+          |
|            |                                               |          |
|  +---------+----------+                        +-----------+-------+  |
|  | Host System RAM    |                        | GTT / Shared VRAM |  |
|  | (16 - 64 GB DDR5)  |                        | (7.6 GB Reserved) |  |
|  +--------------------+                        +-------------------+  |
+-----------------------------------------------------------------------+
```

### Hardware Identifiers
- **PCI Location:** `PCI bus 6, device 0, function 1`
- **Device Hardware ID:** `PCI\VEN_1022&DEV_1502&SUBSYS_8BD5103C&REV_00`
- **APU Generation:** Phoenix 1 (`PHX`) / Hawk Point (`HPT`)
- **Compute Subsystem:** Windows 11 Compute Accelerator Subsystem (`Compute0`)
- **Shared Memory Window:** Up to **7.6 GB** dynamic host-shared aperture mapped to the NPU driver.

---

## 2. NPU Driver & Runtime Stack Analysis

### Driver Version Clarification
| Driver Version | Release Branch | Status & Compatibility |
| :--- | :--- | :--- |
| `32.0.203.280` | AMD Developer Portal (WHQL) | Baseline certified minimum for Ryzen AI SDK 1.8.0. |
| `32.0.203.376` | AMD Developer Portal (WHQL) | Unified update for Phoenix + Strix point. |
| `32.0.20102.3930` | **HP OEM / Windows Update (Active)** | **Newer production build**. Fully satisfies the >= 280 requirement. Retains HP Victus thermal/power management hooks. |

> **Note:** Device Manager reports driver `32.0.20102.3930` under **Compute Accelerators -> NPU Compute Accelerator Device**. Rolling back or changing drivers can be done non-destructively through standard Windows Device Manager driver properties.

---

## 3. Why the Ryzen AI SDK is ~3.3 GB

The user installer (`ryzen-ai-1.8.0.exe`) bundles several distinct compiler and hardware-specific assets:

1. **Hardware Microcode (`.xclbin`)**:
   The XDNA NPU uses an array of spatial AI Engine (AIE) tiles with local interconnects and program memory. Unlike x86 CPU instructions, the NPU requires compiled spatial overlays (`.xclbin` bitstreams) that program the tiles and data streaming crossbar:
   - Phoenix / Hawk Point (`xclbins\phoenix\`)
   - Strix Point (`xclbins\strix\`)
2. **Dynamic JIT/AOT Sub-Graph Partitioning Engines**:
   - `aiecompiler_client.dll`: Graph compiler that inspects incoming ONNX computation graphs and carves out supported subgraphs for NPU offloading.
   - `dyn_dispatch_core.dll`: Hardware instruction dispatcher to the NPU kernel mode driver.
   - `onnxruntime_vitisai_ep.dll` / `onnxruntime_providers_vitisai.dll`: Vitis AI Execution Provider (VOE 4.0) plug-in for Microsoft ONNX Runtime.
3. **Multi-Provider Fallbacks**:
   Includes `DirectML.dll` to allow graceful fallback to the integrated Radeon 780M GPU if an ONNX operator is not supported on the NPU tile array.
4. **Quantization Suite**:
   Vitis-AI quantizer toolchain for converting FP32/FP16 models into INT8 QDQ format (QuantizeLinear/DequantizeLinear).

---

## 4. Software Architecture & Dispatch Flow

### End-to-End Pipeline
```
[Sensor Ingest (ETW / WFP / WSL)]
              |
              v
[Feature Extraction & Ring Buffers]
   - Tripwire: 10-block entropy vector
   - Beacon: 32-packet delta/CV vector
   - Events: 16-event sequence matrix
              |
              v
[INT8 Tensor Pack & Quantization]
   - Pack into [1, 10, 4], [1, 32, 4], [1, 16, 4]
              |
              v
[Kavach NPU Session (npu_backend.rs)]
              |
      +-------+-------+
      |               |
(NPU Available)   (NPU Unavailable / Disabled)
      |               |
      v               v
[ONNX Runtime Session]   [Native CPU Weighted Kernel]
 - EP: VitisAI (Target X1)  - 0-overhead fallback
 - Binary: Phoenix xclbin   - Deterministic SLA (< 10 us)
 - Fallback: DirectML / CPU
              |
              v
[Inference Output -> Verdict Aggregator]
              |
              v
[Enforcement Action (WFP Block / Process Suspend)]
```

### Execution Provider Target Configuration for 7840HS
For Phoenix APUs, Vitis AI EP configuration requires explicit targeting:
```json
{
  "target": "X1",
  "vaip_config": {
    "xclbin": "%RYZEN_AI_INSTALLATION_PATH%\\voe-4.0-win_amd64\\xclbins\\phoenix\\1x4.xclbin"
  }
}
```
*(Strix Point uses target `X2`, whereas Phoenix/Hawk Point uses `X1`)*.

---

## 5. Security & Isolation Considerations

1. **Privilege Boundary**:
   The NPU hardware driver communicates via Windows kernel-mode driver (`amdnpu.sys`). Kavach-NPU runs with elevated EDR broker privileges, ensuring unprivileged malware cannot seize or corrupt NPU shared memory rings.
2. **Model Integrity**:
   Every ONNX model executed on the NPU is packaged inside an **Ed25519-signed bundle** (`bundle.kavach`) containing the SHA-256 fingerprint of the `.onnx` graph and metadata. Before initializing an ONNX Runtime session, the signature is cryptographically verified against the Kavach root trust key.
3. **Deterministic Fail-Open / Fail-Closed Resilience**:
   If the NPU hardware hangs, times out, or encounters an invalid driver state, the NpuSession automatically logs an ETW diagnostic event and falls back to the SIMD CPU baseline within <= 50 us, preventing security blindspots.
