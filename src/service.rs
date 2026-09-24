//! Windows Service Control Manager (SCM) Integration for Kavach-NPU.
//!
//! Implements the background service lifecycle conforming to enterprise EDR requirements:
//! - Automated launch on Windows boot under NT AUTHORITY\SYSTEM.
//! - SCM status reporting: SERVICE_START_PENDING -> SERVICE_RUNNING -> SERVICE_STOP_PENDING -> SERVICE_STOPPED.
//! - Graceful shutdown and stop handler with clean WFP dynamic filter teardown.
//! - CLI control commands for install, uninstall, start, stop, and status querying.

use std::sync::atomic::AtomicBool;

pub const SERVICE_NAME: &str = "KavachNpuSentinel";
pub const SERVICE_DISPLAY_NAME: &str = "Kavach-NPU (कवच) Hardware-Enforced EDR Sentinel";
pub const SERVICE_DESCRIPTION: &str = "Hardware-accelerated Zero-Trust EDR utilizing AMD XDNA NPU for real-time ransomware, C2, and cross-boundary threat containment.";

/// Global shutdown signal accessed by the service control handler.
pub static SERVICE_RUNNING: AtomicBool = AtomicBool::new(true);

#[cfg(windows)]
pub mod win_service {
    use super::*;
    use std::ptr;
    use std::sync::atomic::{AtomicPtr, Ordering};
    use std::sync::mpsc;
    use windows_sys::Win32::Foundation::{ERROR_CALL_NOT_IMPLEMENTED, NO_ERROR};
    use windows_sys::Win32::System::Services::{
        RegisterServiceCtrlHandlerExW, SERVICE_ACCEPT_SHUTDOWN, SERVICE_ACCEPT_STOP,
        SERVICE_CONTROL_INTERROGATE, SERVICE_CONTROL_SHUTDOWN, SERVICE_CONTROL_STOP,
        SERVICE_RUNNING as SCM_SERVICE_RUNNING, SERVICE_START_PENDING, SERVICE_STATUS,
        SERVICE_STOPPED, SERVICE_STOP_PENDING, SERVICE_TABLE_ENTRYW,
        SERVICE_WIN32_OWN_PROCESS, SetServiceStatus, StartServiceCtrlDispatcherW,
    };

    static STATUS_HANDLE: AtomicPtr<std::ffi::c_void> = AtomicPtr::new(ptr::null_mut());

    /// Encodes a standard string into a null-terminated UTF-16 wide string.
    pub fn to_wide_null(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    /// Updates the service status with Windows Service Control Manager.
    fn update_service_status(
        handle: *mut std::ffi::c_void,
        current_state: u32,
        controls_accepted: u32,
        win32_exit_code: u32,
        wait_hint_ms: u32,
    ) -> bool {
        if handle.is_null() {
            return false;
        }

        let mut status = SERVICE_STATUS {
            dwServiceType: SERVICE_WIN32_OWN_PROCESS,
            dwCurrentState: current_state,
            dwControlsAccepted: controls_accepted,
            dwWin32ExitCode: win32_exit_code,
            dwServiceSpecificExitCode: 0,
            dwCheckPoint: 0,
            dwWaitHint: wait_hint_ms,
        };

        unsafe { SetServiceStatus(handle, &mut status) != 0 }
    }

    /// SCM control handler callback.
    unsafe extern "system" fn service_control_handler(
        control: u32,
        _event_type: u32,
        _event_data: *mut std::ffi::c_void,
        _context: *mut std::ffi::c_void,
    ) -> u32 {
        match control {
            SERVICE_CONTROL_STOP | SERVICE_CONTROL_SHUTDOWN => {
                SERVICE_RUNNING.store(false, Ordering::SeqCst);
                let handle = STATUS_HANDLE.load(Ordering::SeqCst);
                update_service_status(
                    handle,
                    SERVICE_STOP_PENDING,
                    0,
                    NO_ERROR,
                    10_000,
                );
                NO_ERROR
            }
            SERVICE_CONTROL_INTERROGATE => NO_ERROR,
            _ => ERROR_CALL_NOT_IMPLEMENTED,
        }
    }

    /// ServiceMain entrypoint called by SCM when the service is started.
    unsafe extern "system" fn service_main(_argc: u32, _argv: *mut *mut u16) {
        let service_name_wide = to_wide_null(SERVICE_NAME);
        let handle = unsafe {
            RegisterServiceCtrlHandlerExW(
                service_name_wide.as_ptr(),
                Some(service_control_handler),
                ptr::null_mut(),
            )
        };

        if handle.is_null() {
            return;
        }
        STATUS_HANDLE.store(handle, Ordering::SeqCst);

        // 1. Report START_PENDING
        update_service_status(
            handle,
            SERVICE_START_PENDING,
            0,
            NO_ERROR,
            5_000,
        );

        // 2. Report RUNNING with STOP and SHUTDOWN controls accepted
        update_service_status(
            handle,
            SCM_SERVICE_RUNNING,
            SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN,
            NO_ERROR,
            0,
        );

        // 3. Launch Sentinel Daemon loop on worker thread
        let (tx, rx) = mpsc::channel();
        let daemon_thread = std::thread::spawn(move || {
            let config = kavach_core::config::KavachConfig::safe_defaults();
            crate::run_live_sentinel_daemon_ext(&config, true, 0);
            let _ = tx.send(());
        });

        // 4. Poll running flag until SCM signals STOP / SHUTDOWN
        while SERVICE_RUNNING.load(Ordering::SeqCst) {
            std::thread::sleep(std::time::Duration::from_millis(250));
        }

        // 5. Report STOP_PENDING while shutting down
        update_service_status(
            handle,
            SERVICE_STOP_PENDING,
            0,
            NO_ERROR,
            5_000,
        );

        // Wait for worker thread to exit cleanly (max 5s)
        let _ = rx.recv_timeout(std::time::Duration::from_secs(5));
        let _ = daemon_thread.join();

        // 6. Report STOPPED
        update_service_status(
            handle,
            SERVICE_STOPPED,
            0,
            NO_ERROR,
            0,
        );
    }

    /// Main entry point when invoked as a Windows Service (`kavach-npu service run`).
    pub fn run_service_dispatcher() -> Result<(), String> {
        let service_name_wide = to_wide_null(SERVICE_NAME);
        let service_table = [
            SERVICE_TABLE_ENTRYW {
                lpServiceName: service_name_wide.as_ptr() as *mut u16,
                lpServiceProc: Some(service_main),
            },
            SERVICE_TABLE_ENTRYW {
                lpServiceName: ptr::null_mut(),
                lpServiceProc: None,
            },
        ];

        unsafe {
            if StartServiceCtrlDispatcherW(service_table.as_ptr()) != 0 {
                Ok(())
            } else {
                let err = std::io::Error::last_os_error();
                Err(format!("StartServiceCtrlDispatcherW failed: {}", err))
            }
        }
    }
}

/// SCM service management commands (cross-platform interface).
pub mod manager {
    use super::*;
    use std::process::Command;

    /// Installs the Kavach-NPU Sentinel as an auto-start Windows Service.
    pub fn install_service(binary_path: Option<&str>) -> Result<String, String> {
        let current_exe = match binary_path {
            Some(p) => std::path::PathBuf::from(p),
            None => std::env::current_exe().map_err(|e| format!("Failed to get current exe path: {}", e))?,
        };

        let bin_str = current_exe.to_str().ok_or("Invalid executable path string")?;
        let bin_cmd = format!("\"{}\" service run", bin_str);

        // 1. Create service via sc.exe
        let create_output = Command::new("sc.exe")
            .args([
                "create",
                SERVICE_NAME,
                &format!("binPath= {}", bin_cmd),
                "start= auto",
                &format!("DisplayName= {}", SERVICE_DISPLAY_NAME),
            ])
            .output()
            .map_err(|e| format!("Failed to execute sc.exe create: {}", e))?;

        if !create_output.status.success() {
            let stderr = String::from_utf8_lossy(&create_output.stderr);
            let stdout = String::from_utf8_lossy(&create_output.stdout);
            return Err(format!("sc create failed: {} {}", stdout, stderr));
        }

        // 2. Set service description
        let _ = Command::new("sc.exe")
            .args(["description", SERVICE_NAME, SERVICE_DESCRIPTION])
            .output();

        // 3. Set recovery restart actions (restart after 5s, 10s, 60s)
        let _ = Command::new("sc.exe")
            .args([
                "failure",
                SERVICE_NAME,
                "reset= 86400",
                "actions= restart/5000/restart/10000/restart/60000",
            ])
            .output();

        Ok(format!(
            "Service '{}' successfully installed (Auto-Start, Recovery enabled).\nBinary: {}",
            SERVICE_NAME, bin_cmd
        ))
    }

    /// Uninstalls and removes the Kavach-NPU Sentinel Windows Service.
    pub fn uninstall_service() -> Result<String, String> {
        // Stop the service first if running
        let _ = stop_service();

        let output = Command::new("sc.exe")
            .args(["delete", SERVICE_NAME])
            .output()
            .map_err(|e| format!("Failed to execute sc.exe delete: {}", e))?;

        if output.status.success() {
            Ok(format!("Service '{}' successfully uninstalled.", SERVICE_NAME))
        } else {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            Err(format!("sc delete failed: {} {}", stdout, stderr))
        }
    }

    /// Starts the Kavach-NPU Sentinel Windows Service.
    pub fn start_service() -> Result<String, String> {
        let output = Command::new("sc.exe")
            .args(["start", SERVICE_NAME])
            .output()
            .map_err(|e| format!("Failed to execute sc.exe start: {}", e))?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        if output.status.success() {
            Ok(format!("Service '{}' start signal dispatched:\n{}", SERVICE_NAME, stdout.trim()))
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            Err(format!("sc start failed: {} {}", stdout, stderr))
        }
    }

    /// Sends a graceful stop signal to the Kavach-NPU Sentinel Windows Service.
    pub fn stop_service() -> Result<String, String> {
        let output = Command::new("sc.exe")
            .args(["stop", SERVICE_NAME])
            .output()
            .map_err(|e| format!("Failed to execute sc.exe stop: {}", e))?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        if output.status.success() {
            Ok(format!("Service '{}' stop signal dispatched:\n{}", SERVICE_NAME, stdout.trim()))
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            Err(format!("sc stop failed: {} {}", stdout, stderr))
        }
    }

    /// Queries the current status of the Kavach-NPU Sentinel Windows Service.
    pub fn query_status() -> Result<String, String> {
        let output = Command::new("sc.exe")
            .args(["query", SERVICE_NAME])
            .output()
            .map_err(|e| format!("Failed to execute sc.exe query: {}", e))?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        if output.status.success() {
            Ok(stdout.trim().to_string())
        } else if stdout.contains("1060") || stderr.contains("1060") {
            Ok(format!(
                "Service '{}' is NOT installed.\nTo install, run: kavach-npu service install",
                SERVICE_NAME
            ))
        } else {
            Err(format!("Service query failed: {} {}", stdout, stderr))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_service_constants_validity() {
        assert_eq!(SERVICE_NAME, "KavachNpuSentinel");
        assert!(SERVICE_DISPLAY_NAME.contains("Kavach-NPU"));
        assert!(SERVICE_DESCRIPTION.contains("AMD XDNA NPU"));
        assert!(SERVICE_DESCRIPTION.contains("ransomware"));
    }

    #[test]
    fn test_service_running_flag_atomic_flip() {
        SERVICE_RUNNING.store(true, std::sync::atomic::Ordering::SeqCst);
        assert!(SERVICE_RUNNING.load(std::sync::atomic::Ordering::SeqCst));
        SERVICE_RUNNING.store(false, std::sync::atomic::Ordering::SeqCst);
        assert!(!SERVICE_RUNNING.load(std::sync::atomic::Ordering::SeqCst));
        SERVICE_RUNNING.store(true, std::sync::atomic::Ordering::SeqCst);
    }

    #[cfg(windows)]
    #[test]
    fn test_utf16_conversion() {
        let wide = win_service::to_wide_null("TestService");
        assert_eq!(wide.last(), Some(&0));
        assert_eq!(wide.len(), 12);

        // Unicode with Hindi character test
        let wide_unicode = win_service::to_wide_null("कवच");
        assert_eq!(wide_unicode.last(), Some(&0));
        assert!(wide_unicode.len() >= 4);
    }
}
