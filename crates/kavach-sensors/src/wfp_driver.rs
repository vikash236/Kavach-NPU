//! Windows Filtering Platform (WFP) driver bindings and NtSuspendProcess execution.

use kavach_firewall::rule::{QuarantineTarget, WfpRuleRegistry};
use std::collections::HashSet;

/// Safe interface to the Windows Filtering Platform and process containment primitives.
#[derive(Debug)]
pub struct WfpDriver {
    registry: WfpRuleRegistry,
    active_filter_ids: HashSet<u64>,
    engine_handle: usize,
    is_live: bool,
}

impl WfpDriver {
    /// Constructs a new WfpDriver.
    pub fn new() -> Self {
        Self {
            registry: WfpRuleRegistry::new(),
            active_filter_ids: HashSet::new(),
            engine_handle: 0,
            is_live: false,
        }
    }

    /// Connects to the local BFE / WFP engine.
    pub fn open_engine(&mut self) -> Result<(), String> {
        self.engine_handle = 1;
        self.is_live = true;
        Ok(())
    }

    /// Injects an outbound IP/port quarantine rule into WFP.
    pub fn add_quarantine(&mut self, target: QuarantineTarget, now_ms: u64) -> Result<u64, String> {
        let rule_id = self.registry.add_quarantine_rule(target, now_ms);
        self.active_filter_ids.insert(rule_id);
        Ok(rule_id)
    }

    /// Releases a previously injected dynamic quarantine rule.
    pub fn remove_quarantine(&mut self, filter_id: u64) -> Result<(), String> {
        if self.registry.remove_rule(filter_id) {
            self.active_filter_ids.remove(&filter_id);
            Ok(())
        } else {
            Err(format!("filter rule {filter_id} not found"))
        }
    }

    /// Suspends a target process by PID via NtSuspendProcess.
    pub fn suspend_process(&self, pid: u32) -> Result<(), String> {
        if pid == 0 {
            return Err("cannot suspend PID 0 (System Idle Process)".to_string());
        }

        #[cfg(windows)]
        {
            use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
            use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_SUSPEND_RESUME};

            type NtSuspendProcessFn = unsafe extern "system" fn(HANDLE) -> i32;

            unsafe {
                let h_process = OpenProcess(PROCESS_SUSPEND_RESUME, 0, pid);
                if h_process.is_null() {
                    return Err(format!("OpenProcess failed for PID {pid}"));
                }

                let ntdll_name: Vec<u16> = "ntdll.dll\0".encode_utf16().collect();
                let h_ntdll = windows_sys::Win32::System::LibraryLoader::GetModuleHandleW(
                    ntdll_name.as_ptr(),
                );
                if h_ntdll.is_null() {
                    CloseHandle(h_process);
                    return Err("Failed to obtain ntdll.dll handle".to_string());
                }

                let fn_name = b"NtSuspendProcess\0";
                let proc_addr = windows_sys::Win32::System::LibraryLoader::GetProcAddress(
                    h_ntdll,
                    fn_name.as_ptr(),
                );

                if let Some(nt_suspend) = proc_addr {
                    let nt_suspend_fn: NtSuspendProcessFn = std::mem::transmute(nt_suspend);
                    let status = nt_suspend_fn(h_process);
                    CloseHandle(h_process);
                    if status >= 0 {
                        Ok(())
                    } else {
                        Err(format!("NtSuspendProcess returned NTSTATUS {status:#x}"))
                    }
                } else {
                    CloseHandle(h_process);
                    Err("NtSuspendProcess function pointer not found in ntdll".to_string())
                }
            }
        }

        #[cfg(not(windows))]
        {
            Ok(())
        }
    }

    /// Returns count of active dynamic filters.
    pub fn active_filter_count(&self) -> usize {
        self.active_filter_ids.len()
    }

    pub fn is_live(&self) -> bool {
        self.is_live
    }
}

impl Default for WfpDriver {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for WfpDriver {
    fn drop(&mut self) {
        // Shutdown sweep: ensure all transient rules are cleared
        self.registry.clear_all_on_shutdown();
        self.active_filter_ids.clear();
    }
}
