# Kavach-NPU v0.3.0-alpha: Architecture & Reference EDR Implementation

**Target Architecture:** AMD Ryzen 7 7840HS (Phoenix APU) with AMD XDNA 1 NPU (AIE2 Array)  
**Host Platform:** Windows 11 64-bit  
**Language & Runtime:** Pure Rust 2024 Edition + Native AMD MCDM / Vitis AI Runtime  
**Version:** `0.3.0-alpha` (re-versioned from legacy v1.0.0 tag)

---

### Executive Summary

**Kavach-NPU (कवच)** is an open-source Endpoint Detection and Response (EDR) system architected to offload behavioral threat detection onto dedicated **AMD XDNA Neural Processing Unit (NPU)** silicon.

Operating with hardware presence probing and runtime path discovery, Kavach integrates a verified **CPU baseline scoring engine** (< 10 µs SLA) simulating multi-head threat evaluation while direct out-of-band NPU session offloading is being wired. It classifies I/O entropy spikes, detects jittered C2 reverse shells, monitors Windows security event anomalies, and secures the WSL2 boundary with minimal CPU overhead.

---

### Key Capabilities & Architectural Pillars

1. **Deterministic Microsecond Threat Inference:**
   - Multi-task INT8 scoring architecture (`kavach_multitask_int8.onnx`) designed for the Phoenix AIE2 spatial tile array (`1x4.xclbin`).
   - Current releases evaluate threats via a verified deterministic CPU baseline scorer (< 10 µs SLA, zero heap allocations).
   - Head 1 (I/O Entropy Tripwire): **27.47 ns** (Criterion benchmark).
   - Head 2 (Network C2 Rhythm): **49.50 ns** (Criterion benchmark).
   - Head 3 (Audit Event Lineage): **22.29 ns** (Criterion benchmark).

2. **Autonomous Kernel Enforcement:**
   - Dynamic **Windows Filtering Platform (WFP)** layer-3/layer-4 IP quarantine rules (`FwpmFilterAdd0`).
   - Process freeze mitigation via `NtSuspendProcess` upon detecting high-entropy cryptographic write bursts.
   - Built-in fail-safe protection: filters automatically drop on shutdown (`FWPM_FILTER_FLAG_CLEAR_ACTION_ON_SHUTDOWN`).

3. **Enterprise Windows Service Lifecycle:**
   - Runs 24/7 in the background under `NT AUTHORITY\SYSTEM` via the native Windows Service Control Manager (SCM).
   - Configured with self-healing recovery watchdogs (auto-restarts within 5 seconds of failure).

4. **Zero-Trust Cryptographic Contracts:**
   - Models and telemetry policies are signed with Ed25519 signatures and verified in constant time.
   - Anti-replay protection with monotonic timestamps and cryptographically secure nonces.

5. **WSL2 Cross-Boundary Virtualization Sentinel:**
   - Dedicated Linux guest agent communicating over `AF_VSOCK` to protect host filesystem mounts (`/mnt/c/`) against blind evasion attacks.

---

### Quick Installation

```powershell
# In an elevated PowerShell (Run as Administrator):
.\tools\install.ps1
```

To verify service status:
```powershell
.\tools\service-manager.ps1 -Action Status
```

To test NPU hardware acceleration under load:
```powershell
.\tools\npu-spike-test.ps1 -Iterations 12
```
