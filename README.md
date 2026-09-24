# Kavach-NPU (कवच)

**Hardware-Enforced Zero-Trust Endpoint Defense & WSL Sentinel Powered by AMD XDNA Silicon.**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Target: AMD XDNA](https://img.shields.io/badge/Hardware-AMD%20XDNA%20(10%20TOPS)-orange.svg)](https://www.amd.com/en/products/processors/laptop/ryzen/7000-series.html)
[![Language: Rust](https://img.shields.io/badge/Language-Rust%202024-red.svg)](https://www.rust-lang.org/)
[![Platform: Windows 11 & WSL2](https://img.shields.io/badge/Platform-Windows%2011%20%7C%20WSL2%20(Kali%2FUbuntu)-blueviolet.svg)]()

> *"Kavach (कवच) — The ancient Sanskrit archetype of impenetrable, form-fitted armor that deflects weapon strikes while granting complete freedom of motion."*

---

## 1. Executive Vision

Traditional Endpoint Detection and Response (EDR) software is built on an inherently flawed paradigm: **it runs on the exact same CPU cores that malware is actively attempting to exploit, saturate, or blind.** 

When modern ransomware or aggressive exploits strike:
* They spawn dozens of encryption threads to pin the CPU to 100%, causing software-based detection hooks to lag.
* They patch user-mode API hooks (`ntdll!EtwEventWrite`) to blind event logging.
* They abuse virtualization boundaries like **WSL2 (Windows Subsystem for Linux)** to silently tamper with host files (`/mnt/c/`) while evading Windows Defender.

**Kavach-NPU is designed to move behavioral defense onto dedicated, isolated hardware: the AMD XDNA NPU (10 TOPS).**

The architectural vision targets continuous, sub-watt perceptual monitoring using dedicated DMA pipelines and spatial AIE-ML tiles. Kavach is architected to classify I/O entropy spikes, detect jittered C2 reverse shells, monitor Windows event anomalies, and lock down the WSL2 boundary in sub-2ms with minimal CPU overhead and zero discrete GPU power consumption. *(Note: Current implementation executes deterministic SIMD/CPU baseline scoring under < 10 µs SLA while direct ONNX Runtime hardware dispatch is being integrated.)*

---

## 2. Architectural Overview

```
 ┌────────────────────────── WINDOWS 11 HOST ──────────────────────────┐  ┌─────────── WSL2 CONTAINER (Hyper-V) ───────────┐
 │                                                                     │  │                                                   │
 │  [ ETW Kernel-File ]    [ ETW TCPIP & DNS ]   [ Windows Event Logs] │  │  [ Kali / Ubuntu Linux Sentry ]                   │
 │  • Real-time writes     • Packet arrival Δt   • Event 4624/4625     │  │  • Linux eBPF / auditd socket telemetry           │
 │  • Block-level entropy  • Payload variance    • Event 7045 / 1102   │  │  • /mnt/c/ host boundary write protection         │
 │  • Mass renames         • DNS query entropy   • Event 4104 (Psh)    │  │  • Offensive lab containment (Metasploit/Burp)    │
 └──────────────────────┬──────────────────────────────┬───────────────┘  └─────────────────────────┬─────────────────────────┘
                        │                              │                                            │
                        │ (In-Memory Ring Buffers)     │                                            │ (AF_VSOCK / Named Pipe Bridge)
                        ▼                              ▼                                            ▼
 ┌────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
 │                                         kavach-core (Central Dispatcher Daemon)                                            │
 │                                                                                                                            │
 │   • Zero-Copy Tensor Packing into 64-byte Pinned Host Memory (`Ort::IoBinding`)                                            │
 │   • Shared Hardware Execution Channel (Lock-free MPSC Queue)                                                               │
 └──────────────────────────────────────────────────────┬─────────────────────────────────────────────────────────────────────┘
                                                        │
                                                        ▼
 ┌────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
 │                                   AMD XDNA NPU (10 TOPS AIE-ML Tile Mesh)                                                  │
 │                                                                                                                            │
 │   • Model: `kavach_multitask_int8.onnx` (Static INT8 QDQ Quantization)                                                     │
 │   • Head 1 (I/O): 1D-CNN Autoencoder for Ransomware & Burst Destruction (<1.2ms)                                           │
 │   • Head 2 (Network): Dilated Temporal Convolutional Network (TCN) for C2 Beacon Jitter (<2.5ms)                             │
 │   • Head 3 (Audit): Sequence Embedding for Windows & Linux Event Lineage (<0.8ms)                                           │
 └──────────────────────────────────────────────────────┬─────────────────────────────────────────────────────────────────────┘
                                                        │
                        ┌───────────────────────────────┴───────────────────────────────┐
                        ▼ (Anomaly Detected)                                            ▼ (C2 / Malicious Flow)
 ┌──────────────────────────────────────────────┐              ┌────────────────────────────────────────────────┐
 │           Host Process Mitigation            │              │      Autonomous NPU Firewall (kavach-firewall) │
 │  • Instant `NtSuspendProcess(PID)`           │              │  • Windows Filtering Platform (WFP) Injection  │
 │  • Terminal & Desktop Alert Notification     │              │  • Dynamic Outbound IP / Subnet Quarantine     │
 │  • Volume Write Permission Revocation        │              │  • `vEthernet (WSL)` Virtual Switch Isolation  │
 └──────────────────────────────────────────────┘              └────────────────────────────────────────────────┘
```

---

## 3. The 5 Core Defense Engines

### 1. The Anti-Ransomware Tripwire (`kavach-tripwire`)
* **The Physics:** All cryptographic algorithms (AES, ChaCha20, RSA) output maximum Shannon entropy ($H \ge 7.95 \text{ bits/byte}$). 
* **The Defense:** Hooks `Microsoft-Windows-Kernel-File` ETW. Evaluates 4KB block-level entropy and rename frequency in a sliding 50ms window.
* **Anti-Intermittent Encryption:** Calculates differential block entropy across sparse regions, defeating modern ransomware (LockBit 3.0 / BlackCat) that skips blocks to fool whole-file scanners.
* **Response:** Invokes `NtSuspendProcess(pid)` to freeze all threads within 3 encrypted files.

### 2. Stealth Exfiltration & C2 Beaconing Detector (`kavach-beacon`)
* **The Physics:** Command & Control reverse shells (Cobalt Strike, Mythic, Sliver) communicate on a programmatic schedule with randomized sleep jitter (e.g., 60s $\pm$ 20%).
* **The Defense:** Collects rolling 32-packet flow matrices `[1, 32, 4]` via `Microsoft-Windows-TCPIP` ETW without decrypting TLS 1.3 payloads.
* **Temporal Convolutional Network (TCN):** Evaluates inter-arrival deltas ($\Delta t$), byte variance, and directionality ratios to spot machine-driven rhythm in under 2.5ms.

### 3. The Autonomous NPU Firewall (`kavach-firewall`)
* **Native Kernel Filtering:** Directly programs the **Windows Filtering Platform (WFP)** via `FwpmFilterAdd0`.
* **Dynamic Behavioral Quarantine:** If `kavach-beacon` flags an active C2 session, the firewall injects an immediate layer-3/layer-4 packet drop rule targeting the destination IP and port.
* **Safe Crash Recovery:** Uses `FWPM_FILTER_FLAG_CLEAR_ACTION_ON_SHUTDOWN` so network connectivity is never permanently locked if the service stops.

### 4. Windows Event Intelligence (`kavach-events`)
* **Kernel Subscription:** Real-time event streaming via `wevtapi.dll` (`EvtSubscribe`) consuming <0.1% CPU.
* **Critical Correlated IDs:**
  * `4625` $\to$ `4624`: Brute-force attacks followed by compromised account access.
  * `7045` / `4697`: New unauthorized Windows Service installation (persistence).
  * `1102`: Audit log cleared (attacker covering tracks).
  * `4104`: PowerShell ScriptBlock execution (catches obfuscated Empire/Mimikatz scripts).
  * `1001`: BugCheck / BSOD analysis to detect kernel driver exploit attempts.

### 5. WSL2 Cross-Boundary Sentinel (`kavach-wsl`)
* **The Problem:** Kali and Ubuntu run in Hyper-V. Malware inside WSL can manipulate `/mnt/c/` files, but Windows sees all operations as coming from a single opaque process: `vmmemWSL.exe`.
* **The Protection:**
  * **Host Boundary Sentinel:** Monitors `/mnt/c/` file system modifications from `vmmemWSL.exe`. If unauthorized mass writes occur outside allowed build workspaces, triggers emergency suspension.
  * **Virtual Switch Sentry:** Inspects traffic on the `vEthernet (WSL)` virtual network switch.
  * **Lab Mode Toggle:** Allows unrestricted network scanning (Nmap, Burp, Metasploit) on virtual adapters while strictly enforcing a one-way read-only air-gap on host sensitive directories (`.ssh/`, `.aws/`, personal documents).

---

## 4. Hardware Compute Budget & Architectural Targets (AMD Ryzen 7 7840HS XDNA)

Kavach-NPU operates on **1D statistical vectors and tabular time-series**, avoiding heavy 2D vision matrices.

> [!NOTE]
> The figures below represent **architectural design targets** for physical NPU silicon dispatch. Current releases execute deterministic CPU baseline scoring algorithms under < 10 µs SLA.

| Engine | Input Tensor | Target Latency on 10 TOPS NPU | Target Frequency | Target Duty Cycle |
| :--- | :--- | :--- | :--- | :--- |
| **Tripwire (I/O)** | `[1, 10, 4]` (Entropy) | **~1.2 ms** | Write bursts only | ~0.6% |
| **Beaconing (Net)** | `[1, 32, 4]` (Timing) | **~2.5 ms** | Every 32 packets | ~0.8% |
| **Event Intel (Log)** | `[1, 16, 4]` (Sequence) | **~0.8 ms** | Event triggers | ~0.2% |
| **WSL Boundary (VM)** | `[1, 16, 4]` (Cross-I/O) | **~1.0 ms** | VM disk bursts | ~0.3% |
| **Combined System** | **Unified Multi-Task Model** | **< 2.0 ms** | **Event-Driven** | **< 2.0% Total** |

* **Target Average Power Draw:** **< 0.8W** (NPU sleeps 98% of the time).
* **Target Host CPU Overhead:** **< 0.3%** across 8 cores / 16 threads.
* **dGPU (RTX 3050):** **Completely powered off (0W).**
* **Target RAM Usage:** **< 75 MB** in memory.

---

## 5. Workspace Architecture

Kavach-NPU is architected as a modular Rust workspace:

```
kavach-npu/
├── Cargo.toml
├── README.md
├── models/
│   └── kavach_multitask_int8.onnx  <-- Unified Multi-Head INT8 Model
├── crates/
│   ├── kavach-core/                <-- Central dispatcher, DMA buffers, NPU session
│   ├── kavach-tripwire/            <-- ETW Kernel-File listener & block-entropy engine
│   ├── kavach-beacon/              <-- ETW TCPIP listener & packet timing TCN
│   ├── kavach-firewall/            <-- Windows Filtering Platform (WFP) dynamic rules
│   ├── kavach-events/              <-- Real-time Windows EventLog subscriber
│   └── kavach-wsl/                 <-- Named pipe / VSOCK bridge for Kali & Ubuntu
└── src/
    └── main.rs                     <-- Service runner & CLI control plane
```

---

## 6. Synergy with Existing Ecosystem

Kavach-NPU completes a sovereign, multi-layered defensive security ecosystem:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  AI Agent Layer:  AgentGuard-MCP  (Model Context Protocol Tool Firewall)   │
├─────────────────────────────────────────────────────────────────────────────┤
│  Build Layer:     SupplyChain-Guard (Sandboxing build.rs & postinstall)     │
├─────────────────────────────────────────────────────────────────────────────┤
│  Host & OS Layer: Kavach-NPU        (Hardware-Accelerated Zero-Trust EDR)   │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 7. Quickstart (Development Setup)

### Prerequisites
* Windows 11 (22H2 or newer)
* AMD Ryzen AI Processor with XDNA NPU (Phoenix 7040 / Hawk Point 8040 series)
* AMD IPU Driver installed (`PCI\VEN_1022&DEV_1502` active in Device Manager, driver version >= `32.0.203.280` or OEM `32.0.20102.3930`)
* Rust toolchain (2024 edition) with Administrator privileges for ETW / WFP.

### One-Click Production Deployment
```powershell
# In an elevated PowerShell (Run as Administrator):
.\tools\install.ps1
```

### Build from Source
```bash
git clone https://github.com/vikash236/Kavach-NPU.git
cd Kavach-NPU
cargo build --release
```

### Windows Background Service Management
```powershell
# Check background service status:
.\tools\service-manager.ps1 -Action Status

# Start or Stop service:
.\tools\service-manager.ps1 -Action Start
.\tools\service-manager.ps1 -Action Stop

# View SCM Event Logs:
.\tools\service-manager.ps1 -Action Logs
```

### CLI Commands
```powershell
kavach-npu status                  # Display NPU session health, model bundle verification, and active sentinels
kavach-npu npu-check               # Probe physical AMD XDNA NPU hardware device, driver version, and runtime bitstreams
kavach-npu daemon --live -c        # Run foreground live sentinel with continuous 100ms NPU heartbeat
kavach-npu service status          # Query native Windows SCM service state
kavach-npu tripwire --test [path]  # Run Shannon block entropy and sliding-window burst test
kavach-npu wsl --lab-mode          # Execute WSL2 cross-boundary AF_VSOCK correlation simulation
```

### Inference Engine Microbenchmarks (Criterion Validated)

> [!NOTE]
> Benchmarks measure the deterministic in-memory CPU baseline scoring engine over quantized INT8 feature tensors. These benchmarks validate zero-allocation throughput and ensure algorithms execute well within SLA budgets before physical NPU hardware offloading.

| Threat Head | Execution Mode | SLA Target | Measured Latency (CPU Baseline) | Margin vs SLA |
| :--- | :--- | :--- | :--- | :--- |
| **Head 1 (I/O Entropy)** | CPU Baseline Scorer | $< 1.200\text{ ms}$ | **27.47 ns** | **Well within SLA** |
| **Head 2 (Network C2)** | CPU Baseline Scorer | $< 2.500\text{ ms}$ | **49.50 ns** | **Well within SLA** |
| **Head 3 (Audit Lineage)**| CPU Baseline Scorer | $< 0.800\text{ ms}$ | **22.29 ns** | **Well within SLA** |

---

## 8. Security & Ethical Philosophy

Kavach-NPU is designed for **defenders, security researchers, and systems programmers**. It enforces total local privacy:
* **100% Offline & In-Memory:** No telemetry or metrics are ever transmitted to cloud servers.
* **Deterministic Remediation:** Actions are governed by mathematically verifiable thresholds (entropy and statistical rhythm), eliminating algorithmic hallucination.

---

## 9. License

MIT License. Designed and developed for sovereign computing and hardware-enforced endpoint resilience.

