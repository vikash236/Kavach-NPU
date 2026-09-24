# Kavach-NPU: Windows Background Service Architecture & Operator Guide

**Platform:** Windows 11 64-bit  
**Service Name:** `KavachNpuSentinel`  
**Security Context:** `NT AUTHORITY\SYSTEM`  
**Hardware Engine:** AMD XDNA NPU (Phoenix APU / 7840HS)  

---

## 1. Overview

The Kavach-NPU Windows Service provides 24/7 autonomous endpoint defense without requiring an active terminal or interactive user logon. It runs natively under the Windows Service Control Manager (SCM), streaming real-time ETW telemetry, evaluating sliding windows on the AMD XDNA NPU hardware, and dynamically enforcing containment rules via the Windows Filtering Platform (WFP) and process suspension.

```
       [ Windows Boot / System Initialization ]
                          │
                          ▼
        [ Service Control Manager (SCM) ]
                          │  (sc.exe start KavachNpuSentinel)
                          ▼
       [ kavach-npu service run ]
            ├── RegisterServiceCtrlHandlerExW()
            ├── Report SERVICE_START_PENDING (5000ms)
            ├── Initialize NPU Session (VitisAI Target X1)
            ├── Report SERVICE_RUNNING (Accept: STOP | SHUTDOWN)
            │
            ├── [Worker Thread: 100ms NPU Evaluation Loop]
            │    ├── ETW File Entropy Ingestion
            │    ├── ETW TCPIP Flow Tracking
            │    ├── Windows Event Log Subscriptions
            │    └── AMD XDNA INT8 Tensor Dispatch
            │
            └── [Shutdown / Stop Event Received]
                 ├── Report SERVICE_STOP_PENDING (5000ms)
                 ├── Atomic Sentinel Loop Termination
                 ├── WFP Dynamic Filter Flushed
                 └── Report SERVICE_STOPPED
```

---

## 2. Service Management Operations

### 2.1 Using the Kavach CLI

The `kavach-npu` binary provides direct management subcommands:

```powershell
# Query current service status
kavach-npu service status

# Install service with Auto-Start and recovery watchdog
kavach-npu service install

# Start the background service
kavach-npu service start

# Stop the background service
kavach-npu service stop

# Uninstall and remove the service from SCM
kavach-npu service uninstall
```

---

### 2.2 Using the PowerShell Service Automation Tool

For administrative convenience, use `tools/service-manager.ps1`:

```powershell
# Elevated PowerShell Terminal (Run as Administrator)

# 1. Install service
.\tools\service-manager.ps1 -Action Install

# 2. Start service
.\tools\service-manager.ps1 -Action Start

# 3. Check status
.\tools\service-manager.ps1 -Action Status

# 4. View SCM event logs
.\tools\service-manager.ps1 -Action Logs

# 5. Stop or Uninstall
.\tools\service-manager.ps1 -Action Stop
.\tools\service-manager.ps1 -Action Uninstall
```

---

### 2.3 Using Native Windows Tools

The service can also be managed using standard Windows utilities:

```powershell
# Using PowerShell Service Cmdlets:
Get-Service -Name KavachNpuSentinel
Start-Service -Name KavachNpuSentinel
Stop-Service -Name KavachNpuSentinel

# Using sc.exe:
sc.exe query KavachNpuSentinel
sc.exe qc KavachNpuSentinel
sc.exe qfailure KavachNpuSentinel
```

---

## 3. SCM Watchdog & Resilience Configuration

The service is pre-configured with recovery actions to ensure continuous availability:

| Parameter | Configuration | Purpose |
| :--- | :--- | :--- |
| **Startup Type** | `Auto` (`SERVICE_AUTO_START`) | Starts automatically during Windows cold boot. |
| **Recovery Action 1** | Restart after 5,000 ms (5s) | Fast recovery from transient faults. |
| **Recovery Action 2** | Restart after 10,000 ms (10s) | Secondary retry backoff. |
| **Recovery Action 3** | Restart after 60,000 ms (60s) | Long-term backoff for persistent issues. |
| **Reset Counter** | 86,400 seconds (24 hours) | Clears failure count after 24h stable operation. |

---

## 4. Diagnostics & Troubleshooting

### Viewing SCM Diagnostic Events
Windows records all service transitions and crashes in the System Event Log:

```powershell
Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='Service Control Manager'} -MaxEvents 20 |
    Where-Object { $_.Message -like "*KavachNpuSentinel*" } |
    Format-Table TimeCreated, Id, Message -Wrap
```

| Event ID | Description |
| :---: | :--- |
| **7036** | Service entered the Running or Stopped state. |
| **7031** | Service crashed unexpectedly; crash recovery action triggered. |
| **7045** | Service was successfully installed into the system. |

---

## 5. Security Model & Fail-Safe Cleanup

1. **Privilege Elevation:** Running under `LocalSystem` grants the required privileges (`SeDebugPrivilege`, `SeLoadDriverPrivilege`, `SeAuditPrivilege`) to intercept kernel ETW sessions and suspend malicious processes.
2. **Dynamic WFP Protection:** When dynamic quarantine rules are applied, they specify `FWPM_FILTER_FLAG_CLEAR_ACTION_ON_SHUTDOWN`. If the service is stopped or the machine loses power, the Windows kernel clears the filter locks automatically, preventing network disconnection.
