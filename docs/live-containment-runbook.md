# Kavach-NPU: Live Threat Simulation & Containment Runbook

**Audience:** Security Engineers, Detection Engineers, System Administrators  
**Platform Target:** AMD Ryzen 7 7840HS (Phoenix APU), Windows 11 64-bit  
**Components Involved:** `kavach-npu` (Sentinel Daemon), `threat-injector` (Harness), `kavach-firewall` (Enforcement Broker)  
**Security Architecture:** Zero-Trust Signed Model Verification $\to$ NPU Hardware Inference $\to$ Authenticated Named-Pipe IPC $\to$ Real-Time WFP / Process Suspension  

---

## 1. Executive Overview

This runbook guides operators through executing live attack simulations against the **Kavach-NPU** sentinel daemon and validating automated real-time hardware-accelerated containment.

### Containment Flow Pipeline
```
[Threat Injector] (Ransomware / C2 / Event Tamper)
        |
        v
[Kernel & System Sensors] (ETW File I/O, ETW Net, WinEventLog)
        |
        v
[Sliding Window Aggregators] (Shannon Entropy, TCN Jitter, Event Matrix)
        |
        v
[AMD XDNA NPU Engine] (Vitis AI / Sub-Microsecond Multi-Head Inference)
        |
        v  (Score >= 0.60 Anomaly Trigger)
[Ed25519 Signed Verdict] (SHA-256 Digest + Hardware Timestamp + Replay Nonce)
        |
        v  (Named Pipe IPC: \\.\pipe\kavach-npu-enforcement)
[Enforcement Broker]
   ├── Process Suspension (NtSuspendProcess / Terminate)
   └── Network Quarantine (Windows Filtering Platform dynamic block rule)
```

---

## 2. Prerequisites & Preflight Verification

Before starting live containment testing, verify system environment and model bundle integrity:

### 2.1 Administrator Elevation
Ensure your PowerShell terminal is launched with **Run as Administrator** to allow ETW sensor ingestion, Named Pipe IPC creation, WFP firewall filter configuration, and process suspension.

### 2.2 NPU & Bundle Preflight Check
Run the automated preflight diagnostic script:

```powershell
.\tools\npu-preflight.ps1
```

Expected output:
```
[1/4] Checking AMD NPU PCI Device...            PASS (PCI\VEN_1022&DEV_1502)
[2/4] Checking NPU Driver Status...             PASS (Version: 32.0.20102.3930)
[3/4] Checking Signed Model Bundle...           PASS (Digest matches manifest)
[4/4] Checking Model Signature...               PASS (Ed25519 Valid)
All preflight checks passed. NPU hardware is ready.
```

If the bundle is missing or invalid, compile and re-sign the model bundle:
```powershell
cargo run -p kavach-pack -- build --output kavach-model.bundle --private-key ./tests/keys/test_ed25519_key.pem
```

---

## 3. Step-by-Step Operator Runbook

### Step 1: Launch the Sentinel Daemon (Terminal 1)

Open an elevated PowerShell terminal and launch `kavach-npu` in live sentinel mode:

```powershell
cargo run -p kavach-npu -- daemon --live --model-bundle kavach-model.bundle
```

**Observed Startup Banner:**
```text
================================================================================
                    KAVACH-NPU SENTINEL DAEMON (LIVE MODE)
================================================================================
[INFO] Model bundle verified: kavach-model.bundle (Ed25519 Signature OK)
[INFO] NPU hardware detected: AMD Phoenix XDNA 1.0 (4x4 AIE Array)
[INFO] Sensor Sliding Windows Active:
       - File Entropy Engine: 100-event window, threshold 7.20 bits
       - Network TCN Engine: 64-event window, 100-tick history
       - Event Log Consumer: Security Channel Subscribed
[INFO] Named pipe IPC broker listening: \\.\pipe\kavach-npu-enforcement
[INFO] Sentinel heartbeat running at 100ms tick interval. Monitoring active...
```

The daemon will now perform sub-microsecond NPU inferences on every tick, waiting for sensor anomalies.

---

### Step 2: Execute Threat Simulations (Terminal 2)

Open a second elevated PowerShell window to run `threat-injector`.

#### Scenario A: High-Entropy Ransomware Burst
Simulates a multi-threaded ransomware burst that generates high-entropy ciphertext files and rapid renames:

```powershell
cargo run -p threat-injector -- --mode ransomware --target-dir .\test-canary-dir --file-count 50 --threads 4
```

**Expected Sensor & NPU Response in Terminal 1:**
```text
[ALERT] Process PID 14820 exceeded write burst threshold: 10 rapid writes in window.
[INFERENCE] Head 1 (Ransomware Tripwire): Entropy=7.94 bits, BurstScore=0.925 -> HIGH RISK
[SENTINEL] Anomaly detected! Dispatching Ed25519 signed Verdict to EnforcementBroker:
           - Action: Suspend
           - Target PID: 14820
           - Score: 0.925
           - Nonce: 0x93F8...
[BROKER] IPC Verdict Received: Signature VALID, Model Status ACTIVE.
[BROKER] Executing NtSuspendProcess(PID=14820) -> SUCCESS. Process suspended.
```

#### Scenario B: Command & Control (C2) Beaconing
Simulates regular or jittered network beaconing to a command-and-control server:

```powershell
cargo run -p threat-injector -- --mode c2 --dest-ip 198.51.100.4 --dest-port 4444 --interval-ms 200 --duration-secs 10
```

**Expected Sensor & NPU Response in Terminal 1:**
```text
[INFERENCE] Head 2 (Network Beacon TCN): Periodicity Jitter=0.012, FlowCount=32 -> Score=0.884
[SENTINEL] C2 Beaconing Detected on Remote IP 198.51.100.4:4444!
[BROKER] Dynamic WFP Quarantine Rule Injected:
         - Protocol: TCP
         - Remote Address: 198.51.100.4
         - Action: Block (Inbound & Outbound)
```

#### Scenario C: Security Event Log Tampering
Simulates an attacker attempting to clear the Windows Security log (Event 1102) and execute brute-force authentication attempts:

```powershell
cargo run -p threat-injector -- --mode audit --iterations 5
```

**Expected Sensor & NPU Response in Terminal 1:**
```text
[EVENT] EventID 1102 Ingested: The audit log was cleared by user!
[INFERENCE] Head 3 (Event Anomaly Engine): Sequence Pattern Match -> Score=0.950
[SENTINEL] Security Log Tamper Detected! Immediate high-priority alert dispatched.
```

#### Scenario D: Full Coordinated Multi-Vector Campaign
Runs all attack vectors concurrently to evaluate multi-head NPU pipeline under load:

```powershell
cargo run -p threat-injector -- --mode full-scenario
```

---

## 4. Verification & Validation

To independently verify that the enforcement actions were applied by the kernel:

### 4.1 Process Suspension Verification
In PowerShell, query the status of the simulated target process:

```powershell
Get-Process -Id <TargetPID> | Select-Object Id, ProcessName, Responding, Threads
```
The thread states will indicate `Wait:Suspended`, and the process will be unresponsive to further user-mode scheduling.

### 4.2 WFP Network Block Verification
Verify the dynamic firewall filter injected by `kavach-firewall`:

```powershell
netsh advfirewall firewall show rule name="Kavach-Quarantine-198.51.100.4"
```

### 4.3 Replay Protection & Integrity Audit
The broker maintains an internal monotonic nonce registry and timestamp verification window ($\pm 5.0$ seconds). Any replayed verdict packets sent over the IPC pipe will trigger:

```text
[BROKER-WARN] Replay attack or stale verdict detected (Nonce duplicate: 0x93F8...). Dropping packet.
```

---

## 5. Teardown & Clean Recovery

1. **Stop Sentinel Daemon:** In Terminal 1, press `Ctrl+C`. The daemon initiates a graceful shutdown:
   - Resumes any temporarily quarantined processes if configured for automatic fail-safe release.
   - Flushes dynamic WFP filter handles.
   - Cleans up the named pipe broker.
2. **Clean Canary Directory:**
   ```powershell
   Remove-Item -Recurse -Force .\test-canary-dir
   ```

---

## 6. Troubleshooting

| Symptom | Cause | Resolution |
| :--- | :--- | :--- |
| `Access Denied` on Named Pipe | Client not elevated | Run terminal as Administrator. |
| Model falls back to `DEGRADED` | Bundle hash mismatch or invalid Ed25519 signature | Re-run `kavach-pack` with valid key and verify bundle path. |
| NPU inference falls back to CPU | DirectML / MCDM driver busy or locked by another process | Check Task Manager Compute Accelerators; ensure driver is active. |
| Sensor events not streaming | Windows Event Log service disabled | Start `EventLog` service via `Start-Service EventLog`. |
