# ADR 008: Windows Service Control Manager (SCM) Integration & Autonomous Sentinel Lifecycle

**Status:** Accepted  
**Date:** September 2026  
**Author:** Kavach-NPU Engineering Team  
**Components Affected:** `kavach-npu` binary, Windows Service Control Manager, `kavach-sensors` (WFP/ETW)  

---

## 1. Context & Problem Statement

Endpoint Detection and Response (EDR) agents cannot rely on interactive user sessions or console windows for operational persistence. In an enterprise security deployment:
1. The detection and containment runtime must initialize during system boot before user logon.
2. The runtime must execute with high privileges (`NT AUTHORITY\SYSTEM`) to program the Windows Filtering Platform (WFP), access the kernel ETW telemetry infrastructure, and invoke `NtSuspendProcess` on unprivileged and system-level malicious processes.
3. The runtime must gracefully respond to OS shutdown and restart events, safely releasing WFP dynamic quarantine locks so network connectivity is never bricked.
4. The service must support automated recovery (watchdog restarts) if killed or crashed.

---

## 2. Decision

We integrate Kavach-NPU directly with the **Windows Service Control Manager (SCM)** using native Win32 APIs via `windows-sys` (`Win32_System_Services`):

1. **Service Identity:**
   - **Service Name:** `KavachNpuSentinel`
   - **Display Name:** `Kavach-NPU (कवच) Hardware-Enforced EDR Sentinel`
   - **Start Type:** `SERVICE_AUTO_START` (`start= auto`)
   - **Account:** `NT AUTHORITY\SYSTEM` (LocalSystem)

2. **SCM Protocol & State Transitions:**
   - Entry point: `kavach-npu service run` dispatches to `StartServiceCtrlDispatcherW`.
   - States reported via `SetServiceStatus`:
     - Initialization: `SERVICE_START_PENDING` (Wait hint: 5,000 ms)
     - Active monitoring: `SERVICE_RUNNING` (Accepted controls: `SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN`)
     - Teardown: `SERVICE_STOP_PENDING` (Wait hint: 5,000 ms)
     - Final state: `SERVICE_STOPPED`

3. **Graceful Teardown & Fail-Safe Cleanup:**
   - Upon receiving `SERVICE_CONTROL_STOP` or `SERVICE_CONTROL_SHUTDOWN`, the control handler sets the atomic `SERVICE_RUNNING` flag to `false`.
   - The worker thread terminates its 100ms NPU polling loop, safely cleans up named pipe listeners, and flushes WFP dynamic filter rules.
   - All dynamic WFP rules use `FWPM_FILTER_FLAG_CLEAR_ACTION_ON_SHUTDOWN` ensuring that even in the event of an abrupt kernel power cut, filters are auto-cleared by the Windows kernel.

4. **Self-Healing Watchdog Recovery:**
   - Configured via SCM failure actions:
     - 1st Failure: Restart service after 5,000 ms
     - 2nd Failure: Restart service after 10,000 ms
     - Subsequent Failures: Restart service after 60,000 ms
     - Reset failure counter: 86,400 seconds (24 hours).

---

## 3. Alternatives Considered

| Alternative | Pros | Cons | Reason for Rejection |
| :--- | :--- | :--- | :--- |
| **Task Scheduler (`schtasks`)** | Easy to script | Lacks formal SCM lifecycle callbacks, health polling, and clean shutdown hooks | Inadequate for an enterprise security daemon. |
| **Third-Party Wrapper (NSSM / WinSW)** | Simple CLI wrapper | Introduces external binary dependency and extra process layer | Security liability; native Win32 SCM is safer and self-contained. |
| **Native Win32 SCM Integration (Selected)** | Zero external dependencies, pure Rust, zero-alloc state reporting, full SCM compliance | Requires unsafe Win32 FFI callbacks | Safely encapsulated with atomic state flags and unit tests. |

---

## 4. Consequences

### Positive
- Kavach-NPU boots before user login, guaranteeing continuous defense from cold start.
- Native SCM monitoring enables standard management via `sc.exe`, `Get-Service`, `Start-Service`, and PowerShell.
- SCM watchdog automatically recovers the sentinel process if killed.

### Compliance
- Conforms to Microsoft Windows Service guidelines and Windows Security Baseline.
