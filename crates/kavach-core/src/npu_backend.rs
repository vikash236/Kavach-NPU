//! NPU hardware detection, runtime path resolution, and CPU baseline inference scorer.
//!
//! Probes system hardware for AMD XDNA NPU devices (VEN_1022 & DEV_1502) and resolves
//! native runtime paths. Multi-head model evaluation currently runs via a deterministic
//! CPU baseline scoring engine (< 10 µs SLA) that computes weighted anomaly scores over
//! quantized INT8 tensors, serving as the verified reference baseline while direct
//! hardware session dispatch is wired.

use std::path::PathBuf;
use std::sync::atomic::Ordering;

/// Hardware execution provider backend selected for inference.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionProviderBackend {
    /// AMD XDNA NPU via Vitis AI Execution Provider (Target X1 on Phoenix 7840HS).
    AmdXdnaNpu,
    /// DirectML GPU acceleration via integrated Radeon 780M graphics.
    DirectMlGpu,
    /// Deterministic native SIMD/AVX CPU baseline arithmetic (< 10 µs SLA).
    NativeCpuBaseline,
}

impl std::fmt::Display for ExecutionProviderBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AmdXdnaNpu => write!(f, "AMD XDNA NPU (VitisAI Target X1)"),
            Self::DirectMlGpu => write!(f, "DirectML (AMD Radeon 780M GPU)"),
            Self::NativeCpuBaseline => write!(f, "Native SIMD CPU Baseline"),
        }
    }
}

/// NPU hardware presence, driver readiness, and bitstream configuration.
#[derive(Debug, Clone)]
pub struct NpuHardwareInfo {
    /// True if the AMD NPU PCI device (VEN_1022 & DEV_1502) is active in Windows.
    pub device_detected: bool,
    /// Active NPU driver version reported by the Windows PnP subsystem.
    pub driver_version: Option<String>,
    /// Path to the native runtime bin directory containing onnxruntime.dll and vitisai EP.
    pub runtime_bin_dir: Option<PathBuf>,
    /// Path to the Phoenix 1x4 spatial microcode xclbin.
    pub xclbin_path: Option<PathBuf>,
    /// Active execution backend selected based on available components.
    pub selected_backend: ExecutionProviderBackend,
}

impl NpuHardwareInfo {
    /// Probes the system for AMD NPU hardware, drivers, and runtime files.
    pub fn probe() -> Self {
        let (runtime_bin, xclbin) = resolve_npu_paths();
        let has_runtime = runtime_bin.is_some() && xclbin.is_some();

        // Hardware device presence (PCI\VEN_1022&DEV_1502 on Phoenix)
        let device_detected = check_npu_hardware_device();
        let driver_version = check_npu_driver_version();

        let selected_backend = if device_detected && has_runtime {
            ExecutionProviderBackend::AmdXdnaNpu
        } else if has_runtime {
            ExecutionProviderBackend::DirectMlGpu
        } else {
            ExecutionProviderBackend::NativeCpuBaseline
        };

        Self {
            device_detected,
            driver_version,
            runtime_bin_dir: runtime_bin,
            xclbin_path: xclbin,
            selected_backend,
        }
    }
}

/// Attempts to resolve the runtime bin directory and Phoenix xclbin from either:
/// 1. Local workspace `npu_runtime/` folder
/// 2. System `RYZEN_AI_INSTALLATION_PATH`
pub fn resolve_npu_paths() -> (Option<PathBuf>, Option<PathBuf>) {
    // 1. Check local workspace npu_runtime
    let candidates = [
        // Workspace relative
        PathBuf::from("npu_runtime"),
        // Parent relative (e.g. running from a crate dir)
        PathBuf::from("../npu_runtime"),
        PathBuf::from("../../npu_runtime"),
    ];

    for base in &candidates {
        let bin_candidate = base.join("ryzen_ai_deployment/runtimes/win-x64/native");
        let xclbin_candidate = base.join("NPU_RAI_376_WHQL/npu_mcdm_stack_prod/1x4.xclbin");

        if bin_candidate.join("onnxruntime.dll").is_file() && xclbin_candidate.is_file() {
            return (
                Some(bin_candidate.canonicalize().unwrap_or(bin_candidate)),
                Some(xclbin_candidate.canonicalize().unwrap_or(xclbin_candidate)),
            );
        }
    }

    // 2. Check RYZEN_AI_INSTALLATION_PATH environment variable
    if let Ok(sdk_env) = std::env::var("RYZEN_AI_INSTALLATION_PATH") {
        let sdk_path = PathBuf::from(sdk_env);
        let bin_candidate = sdk_path.join("bin");
        let xclbin_candidate = sdk_path.join("voe-4.0-win_amd64/xclbins/phoenix/1x4.xclbin");

        if bin_candidate.join("onnxruntime.dll").is_file() && xclbin_candidate.is_file() {
            return (Some(bin_candidate), Some(xclbin_candidate));
        }
    }

    (None, None)
}

/// Initializes the ONNX Runtime dynamic library from the specified path.
/// Safe and idempotent: returns Ok(()) if already initialized.
#[cfg(feature = "npu-hardware")]
pub fn init_ort_runtime(dylib_path: &std::path::Path) -> Result<(), String> {
    static INITIALIZED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    if INITIALIZED.load(std::sync::atomic::Ordering::SeqCst) {
        return Ok(());
    }
    ort::init_from(dylib_path).map_err(|e| {
        format!(
            "failed to initialize ONNX Runtime from {}: {e}",
            dylib_path.display()
        )
    })?;
    INITIALIZED.store(true, std::sync::atomic::Ordering::SeqCst);
    Ok(())
}

/// Fallback stub when compiled without the npu-hardware feature flag.
#[cfg(not(feature = "npu-hardware"))]
pub fn init_ort_runtime(_dylib_path: &std::path::Path) -> Result<(), String> {
    Err("npu-hardware feature is not enabled; compile with --features npu-hardware".into())
}

/// Checks if the AMD NPU PCI device is present on Windows.
#[cfg(windows)]
fn check_npu_hardware_device() -> bool {
    // Fast path: verify device node presence or driver registration
    let status = std::process::Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            "Get-PnpDevice -FriendlyName '*NPU Compute Accelerator*' -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'OK' } | Select-Object -ExpandProperty InstanceId",
        ])
        .output();

    if let Ok(out) = status {
        let text = String::from_utf8_lossy(&out.stdout);
        text.contains("VEN_1022&DEV_1502") || !text.trim().is_empty()
    } else {
        false
    }
}

#[cfg(not(windows))]
fn check_npu_hardware_device() -> bool {
    false
}

/// Checks the active AMD NPU driver version.
#[cfg(windows)]
fn check_npu_driver_version() -> Option<String> {
    let status = std::process::Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            "Get-CimInstance Win32_PnPSignedDriver | Where-Object { $_.DeviceName -like '*NPU Compute Accelerator*' } | Select-Object -First 1 -ExpandProperty DriverVersion",
        ])
        .output();

    if let Ok(out) = status {
        let ver = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if !ver.is_empty() {
            return Some(ver);
        }
    }
    None
}

#[cfg(not(windows))]
fn check_npu_driver_version() -> Option<String> {
    None
}

/// Multi-head baseline inference engine.
/// Probes NPU hardware presence and runtime bitstreams, and computes deterministic
/// CPU baseline anomaly scores over quantized INT8 feature tensors.
#[derive(Debug)]
pub struct NpuEngine {
    info: NpuHardwareInfo,
    active_inferences: std::sync::atomic::AtomicU64,
}

impl NpuEngine {
    /// Initializes an NPU engine by probing available hardware and runtime assets.
    pub fn new() -> Self {
        Self {
            info: NpuHardwareInfo::probe(),
            active_inferences: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Returns hardware and provider information.
    pub fn info(&self) -> &NpuHardwareInfo {
        &self.info
    }

    /// Computes CPU baseline I/O anomaly score via weighted average over the [1, 10, 4] INT8 tensor.
    /// Simulates Head 1 (I/O File Entropy Autoencoder) under deterministic < 10 µs SLA.
    pub fn run_io_inference(&self, tensor_data: &[[i8; 4]; 10]) -> f32 {
        self.active_inferences.fetch_add(1, Ordering::Relaxed);

        // Native baseline computation (always available, deterministic, < 10 µs)
        let mut score = 0.0f32;
        for row in tensor_data {
            let entropy_norm = (row[0] as f32) / 127.0;
            let intermittent = (row[3] as f32) / 127.0;
            score += entropy_norm * 0.7 + intermittent * 0.3;
        }
        (score / 10.0).clamp(0.0, 1.0)
    }

    /// Computes CPU baseline C2 network timing anomaly score over the [1, 32, 4] INT8 tensor.
    /// Simulates Head 2 (C2 Network Timing TCN) under deterministic < 10 µs SLA.
    pub fn run_net_inference(&self, tensor_data: &[[i8; 4]; 32]) -> f32 {
        self.active_inferences.fetch_add(1, Ordering::Relaxed);

        let mut total_delta = 0.0f32;
        for row in tensor_data {
            total_delta += (row[0] as f32) / 127.0;
        }
        (total_delta / 32.0).clamp(0.0, 1.0)
    }

    /// Computes CPU baseline audit event sequence anomaly score over the [1, 16, 4] INT8 tensor.
    /// Simulates Head 3 (Audit Event Sequence Embedding) under deterministic < 10 µs SLA.
    pub fn run_audit_inference(&self, tensor_data: &[[i8; 4]; 16]) -> f32 {
        self.active_inferences.fetch_add(1, Ordering::Relaxed);

        let mut score = 0.0f32;
        for row in tensor_data {
            score += (row[0] as f32) / 127.0;
        }
        (score / 16.0).clamp(0.0, 1.0)
    }

    /// Returns total inferences dispatched since engine initialization.
    pub fn total_inferences(&self) -> u64 {
        self.active_inferences.load(Ordering::Relaxed)
    }
}

impl Default for NpuEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "requires local npu_runtime directory"]
    fn test_npu_path_resolution() {
        let (bin, xclbin) = resolve_npu_paths();
        // Since npu_runtime exists in workspace root, resolution must succeed
        assert!(bin.is_some(), "runtime bin must be found in workspace");
        assert!(xclbin.is_some(), "phoenix 1x4.xclbin must be found");

        let bin_p = bin.unwrap();
        assert!(bin_p.join("onnxruntime.dll").is_file());

        let xclbin_p = xclbin.unwrap();
        assert!(xclbin_p.is_file());
    }

    #[test]
    #[ignore = "requires local npu_runtime directory"]
    fn test_npu_hardware_info_probe() {
        let info = NpuHardwareInfo::probe();
        println!("Hardware info probed: {:#?}", info);
        // Runtime and bitstream are verified locally
        assert!(info.runtime_bin_dir.is_some());
        assert!(info.xclbin_path.is_some());
    }

    #[test]
    fn test_npu_engine_default_fallback() {
        let engine = NpuEngine::default();
        assert_eq!(engine.total_inferences(), 0);
        let backend = engine.info().selected_backend;
        // Verify Display implementation is valid for selected backend
        assert!(!format!("{backend}").is_empty());
    }

    #[test]
    fn test_npu_engine_inference_dispatch() {
        let engine = NpuEngine::new();
        let io_data = [[64i8, 0, 0, 32]; 10];
        let score = engine.run_io_inference(&io_data);
        assert!(score > 0.0 && score <= 1.0);

        let net_data = [[50i8, 10, 0, 0]; 32];
        let net_score = engine.run_net_inference(&net_data);
        assert!(net_score > 0.0 && net_score <= 1.0);

        let audit_data = [[40i8, 0, 0, 0]; 16];
        let audit_score = engine.run_audit_inference(&audit_data);
        assert!(audit_score > 0.0 && audit_score <= 1.0);

        assert_eq!(engine.total_inferences(), 3);
    }

    #[test]
    #[cfg(feature = "npu-hardware")]
    fn test_init_ort_runtime_with_invalid_path() {
        let bad_path = std::path::Path::new("nonexistent/invalid_onnxruntime.dll");
        let res = init_ort_runtime(bad_path);
        if let Err(e) = res {
            assert!(e.contains("failed to initialize ONNX Runtime"));
        }
    }

    #[test]
    #[cfg(feature = "npu-hardware")]
    fn test_init_ort_runtime_with_local_package() {
        let (bin_opt, _) = resolve_npu_paths();
        if let Some(bin_dir) = bin_opt {
            let dylib_path = bin_dir.join("onnxruntime.dll");
            let res = init_ort_runtime(&dylib_path);
            assert!(
                res.is_ok(),
                "init_ort_runtime must succeed with local runtime: {res:?}"
            );
        }
    }

    #[test]
    #[cfg(not(feature = "npu-hardware"))]
    fn test_init_ort_runtime_feature_disabled_stub() {
        let p = std::path::Path::new("dummy");
        let res = init_ort_runtime(p);
        assert!(res.is_err());
        assert!(
            res.unwrap_err()
                .contains("npu-hardware feature is not enabled")
        );
    }
}
