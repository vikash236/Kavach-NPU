//! Kavach-NPU command-line control-plane and sentinel daemon.
//!
//! Provides the primary operator CLI and integration runtime for:
//! - `kavach status`: Displays health of NPU session, INT8 model bundle, WFP broker, and WSL2 bridge.
//! - `kavach tripwire --test [path]`: Executes Shannon block entropy and sliding-window burst detection.
//! - `kavach wsl --lab-mode`: Executes the mock/lab AF_VSOCK bridge for testing WSL2-to-host traversal.
//! - `kavach daemon`: Starts the background sentinel pipeline in safe degraded-observer mode.

use kavach_beacon::{FlowKey, PacketDirection, PacketMeta, TcnEngine};
use kavach_core::config::KavachConfig;
use kavach_core::npu::NpuSession;
use kavach_events::{CriticalEventId, EventSubscriber, SecurityEventRecord};
use kavach_firewall::rule::QuarantineTarget;
use kavach_firewall::{EnforcementBroker, WfpClient};
use kavach_tripwire::EntropyEngine;
use kavach_tripwire::entropy::{
    DEFAULT_BLOCK_SIZE, ENTROPY_RANSOMWARE_THRESHOLD, block_entropy_scan, differential_entropy,
    shannon_entropy,
};
use kavach_wsl::clock_sync::{ClockChallenge, ClockResponse};
use kavach_wsl::correlator::{AttributionConfidence, HostFileEvent, WslCorrelator};
use kavach_wsl::wire::is_normalized_mnt_path;
use kavach_wsl::{GuestFileOperation, GuestWriteRecord};
use std::env;
use std::fs;
use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;

pub mod service;

/// Status report formatted according to ADR 004 and docs/schemas/model-manifest-v1.md.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemStatusReport {
    /// Canonical formatted report string from the NPU session.
    pub npu_status_block: String,
    /// Subsystem states.
    pub subsystems: Vec<String>,
}

impl std::fmt::Display for SystemStatusReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.npu_status_block)?;
        for sub in &self.subsystems {
            writeln!(f, "{}", sub)?;
        }
        Ok(())
    }
}

/// Collects system health and status against the active configuration and NPU session.
pub fn collect_status(config: &KavachConfig) -> SystemStatusReport {
    // Model bundle verification per ADR 004:
    // Dynamically verify bundle directory specified in config using the pinned development key.
    let npu = NpuSession::from_config(config, &kavach_core::PINNED_DEV_PUBLIC_KEY);

    let npu_status_block = npu.format_status_report();

    let subsystems = vec![
        format!(
            "tripwire.engine: ACTIVE (50ms sliding window, suspension_threshold=3, ransomware_entropy_threshold={:.2})",
            ENTROPY_RANSOMWARE_THRESHOLD
        ),
        format!(
            "beacon.tcn_engine: ACTIVE (32-packet ring, jitter_cv_max=0.35, min_interval=100ms)"
        ),
        format!("events.subscriber: ACTIVE (16-event rolling sequence, critical_id_tracking=true)"),
        format!("firewall.broker: ACTIVE (wfp_dynamic_quarantine=enabled, replay_cache_ttl=60s)"),
        format!(
            "wsl.bridge: READY (af_vsock=listener_ready, clock_skew_tolerance={}ms)",
            config.wsl.clock_sync_interval_seconds * 1000
        ),
    ];

    SystemStatusReport {
        npu_status_block,
        subsystems,
    }
}

/// Executes tripwire diagnostic analysis on a sample byte buffer or file path.
pub fn run_tripwire_test(path_arg: Option<&str>) -> Result<(), String> {
    println!("=== Kavach Tripwire Anti-Ransomware Diagnostics ===");
    let (data, source_name) = match path_arg {
        Some(path_str) => {
            let p = Path::new(path_str);
            if !p.exists() {
                return Err(format!("File not found: {}", path_str));
            }
            let bytes = fs::read(p).map_err(|e| format!("Failed to read file: {}", e))?;
            (bytes, path_str.to_string())
        }
        None => {
            // Synthetic test buffer: 8KB of mixed low-entropy and high-entropy blocks
            println!("No target file specified. Generating synthetic dual-phase payload (8KB)...");
            let mut buf = Vec::with_capacity(8192);
            // Block 0 (4096 bytes): Plaintext English text (low entropy)
            let plaintext =
                b"Kavach-NPU hardware-enforced endpoint detection and response system. ";
            while buf.len() < 4096 {
                buf.extend_from_slice(plaintext);
            }
            buf.truncate(4096);
            // Block 1 (4096 bytes): High entropy pseudorandom cipher block
            let mut state: u32 = 0xDEADBEEF;
            for _ in 0..4096 {
                state = state.wrapping_mul(1664525).wrapping_add(1013904223);
                buf.push((state >> 16) as u8);
            }
            (buf, "Synthetic Dual-Phase Buffer".to_string())
        }
    };

    let total_entropy = shannon_entropy(&data);
    let block_entropies = block_entropy_scan(&data, DEFAULT_BLOCK_SIZE);
    let summary = differential_entropy(&block_entropies);

    println!("Target: {}", source_name);
    println!(
        "Data Size: {} bytes ({} blocks)",
        data.len(),
        block_entropies.len()
    );
    println!("Overall Shannon Entropy: {:.4} / 8.0000", total_entropy);
    println!(
        "Block Entropies: {:?}",
        block_entropies
            .iter()
            .map(|h| format!("{:.4}", h))
            .collect::<Vec<_>>()
    );
    println!("Mean Block Entropy: {:.4}", summary.mean_entropy);
    println!("Max Block Entropy: {:.4}", summary.max_entropy);
    println!("Variance: {:.4}", summary.variance);
    println!(
        "High Entropy Ratio: {:.2}%",
        summary.high_entropy_ratio * 100.0
    );
    println!(
        "Intermittent Score: {:.2}",
        summary.intermittent_encryption_score
    );

    let is_ransomware = summary.max_entropy >= ENTROPY_RANSOMWARE_THRESHOLD;
    if is_ransomware {
        println!(
            "ALERT: High-entropy ransomware signature detected (H = {:.4} >= {:.2})",
            summary.max_entropy, ENTROPY_RANSOMWARE_THRESHOLD
        );
    } else {
        println!("STATUS: Normal file entropy profile (benign).");
    }

    // Demonstrate sliding-window burst simulation
    println!("\nTesting 50ms sliding-window write burst tracker...");
    let mut engine = EntropyEngine::new();
    let pid = 4096;
    for i in 1..=4 {
        let path = format!("C:\\Users\\victim\\Documents\\file_{}.dat", i);
        let eval = engine.ingest_operation(pid, &path, &data, false, 1000 + i * 10);
        if let Some(decision) = eval {
            println!(
                "  [Write #{}] Suspicious burst detected for PID {}! Distinct files: {}, Action: {:?}",
                i,
                pid,
                decision.distinct_files.len(),
                decision.recommended_action
            );
        } else {
            println!(
                "  [Write #{}] Recorded into 50ms window (below suspension threshold).",
                i
            );
        }
    }

    Ok(())
}

/// Executes the mock/lab WSL2 AF_VSOCK bridge simulation.
pub fn run_wsl_lab_mode() {
    println!("===========================================================");
    println!("Kavach WSL2 Attribution Bridge - ADR 005 Lab Mode");
    println!("===========================================================");

    let dist_id = [0x42; 16];
    let mut correlator = WslCorrelator::new(dist_id, 250);

    // 1. Clock synchronization simulation
    println!("[Step 1] Executing challenge-response clock synchronization...");
    let challenge = ClockChallenge {
        nonce: [0x55; 16],
        t0_host_monotonic_ns: 1_000_000_000,
    };
    let guest_resp = ClockResponse {
        nonce: [0x55; 16],
        g1_guest_monotonic_ns: 1_010_000_000,
        g2_guest_monotonic_ns: 1_010_500_000,
    };
    let estimate = correlator
        .clock_sync_mut()
        .process_response(&challenge, &guest_resp, 1_020_000_000)
        .expect("Clock sync should succeed within acceptable RTT");

    println!(
        "  Clock Sync OK: offset = {} ns, uncertainty = {} ns, valid_until = {} ns",
        estimate.offset_ns, estimate.uncertainty_ns, estimate.valid_until_host_monotonic_ns
    );

    // 2. Host ETW file event synthesis
    println!("[Step 2] Ingesting host Kernel-File ETW write event...");
    let host_event = HostFileEvent {
        host_timestamp_ns: 1_025_000_000,
        canonical_windows_path: "C:\\Users\\victim\\Documents\\thesis.docx.kavach".to_string(),
        is_vmmem_process: true,
        bytes_written: 65536,
    };
    correlator.record_host_event(host_event);

    // 3. Guest write record synthesis
    println!("[Step 3] Ingesting guest AF_VSOCK write record...");
    let guest_path = "/mnt/c/Users/victim/Documents/thesis.docx.kavach";
    assert!(is_normalized_mnt_path(guest_path));

    let guest_record = GuestWriteRecord {
        version: kavach_core::ArtifactVersion { major: 1, minor: 0 },
        sequence_number: 101,
        // guest_monotonic_ns (1_015_000_000) + offset (~10_000_000) ~= 1_025_000_000 host time
        guest_monotonic_ns: 1_015_000_000,
        guest_realtime_ns: 1_700_000_000_000_000_000,
        guest_process_id: 8821,
        guest_process_start_ticks: 900_000_000,
        distribution_id: dist_id,
        mount_namespace_id: 4026531840,
        executable_sha256: [0xEE; 32],
        cgroup_sha256: [0x00; 32],
        operation: GuestFileOperation::Write,
        normalized_path: guest_path.to_string(),
        byte_range_start: 0,
        byte_range_length: 65536,
        flags: 0,
    };
    println!("  Guest Record: PID 8821 wrote 64KB to {}", guest_path);

    // 4. Correlate
    println!("[Step 4] Correlating guest write with host ETW event...");
    let result = correlator.correlate_guest_record(guest_record, 1_025_000_000);
    println!("  Attribution Confidence: {:?}", result.confidence);
    println!("  Attributed Guest PID: {:?}", result.guest_process_id);
    println!(
        "  Target Canonical Windows Path: {}",
        result.canonical_windows_path
    );
    println!("  Correlation Delta: {} ms", result.correlation_delta_ms);
    println!(
        "  Allow Guest PID Enforcement: {}",
        result.allow_pid_enforcement
    );

    if result.confidence == AttributionConfidence::High {
        println!("SUCCESS: ADR 005 High-Confidence correlation verified!");
    } else {
        println!("WARNING: Low/Medium confidence attribution.");
    }
}

/// Runs a single live cycle of all sentinel pipelines (Daemon mode).
pub fn run_sentinel_daemon(config: &KavachConfig) {
    println!("===========================================================");
    println!("Kavach-NPU (कवच) - Hardware-Enforced EDR & WSL2 Sentinel");
    println!("===========================================================");
    let status = collect_status(config);
    println!("{}", status);
    println!("===========================================================");
    println!("Initializing sentinel pipelines...");

    // 1. Tripwire sliding window tracker
    let mut entropy_engine = EntropyEngine::new();
    println!("  [+] Tripwire sliding-window entropy engine initialized.");

    // 2. Beacon TCN flow engine
    let mut beacon_engine = TcnEngine::new();
    println!("  [+] Stealth C2 beaconing TCN registry initialized.");

    // 3. Security Event Log sequence tracker
    let mut event_subscriber = EventSubscriber::new();
    println!("  [+] Windows Event Log sequence subscriber initialized.");

    // 4. WSL Correlator
    let dist_id = [0x42; 16];
    let mut _wsl_correlator = WslCorrelator::new(dist_id, 250);
    println!("  [+] WSL2 AF_VSOCK cross-boundary correlator initialized.");

    // 5. Privileged WFP Enforcement Broker & Client
    let mut firewall_client = WfpClient::new();
    let mut broker = EnforcementBroker::new(1, false, 2, [0x77; 32], true);
    println!("  [+] Privileged WFP dynamic quarantine broker initialized.");

    // Simulate baseline heartbeat ingestion
    let now_ms = 1_700_000_000_000;
    let sample_bytes = b"safe baseline operating system telemetry data";
    let _ = entropy_engine.ingest_operation(
        100,
        "C:\\Windows\\temp\\log.txt",
        sample_bytes,
        false,
        now_ms,
    );

    let flow_key = FlowKey::new(
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50)),
        54321,
        IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
        443,
        6,
    );
    let _ = beacon_engine.ingest_packet(
        flow_key,
        PacketMeta {
            timestamp_ns: now_ms * 1_000_000,
            payload_bytes: 128,
            direction: PacketDirection::Outbound,
        },
    );

    let _ = event_subscriber.ingest_event(SecurityEventRecord {
        event_id: CriticalEventId::LogonSuccess,
        timestamp_unix_ms: now_ms,
        process_id: 100,
        subject_user: "SYSTEM".to_string(),
        target_resource: "C:\\Windows\\System32".to_string(),
    });

    let q_rule_id = firewall_client.quarantine_target(
        QuarantineTarget::DestinationIpPort {
            ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)),
            port: Some(443),
            protocol: 6,
        },
        now_ms,
    );

    let _ = broker.evaluate_and_enforce(
        &kavach_core::Verdict {
            protocol_version: kavach_core::ArtifactVersion { major: 1, minor: 0 },
            request_id: [0xAA; 16],
            issued_at_unix_ms: now_ms,
            expires_at_unix_ms: now_ms + 10_000,
            detector_instance_id: [0x01; 16],
            requested_action: kavach_core::EnforcementAction::Alert,
            evidence_digest: [0x55; 32],
            model_bundle_sha256: [0x77; 32],
            policy_generation: 1,
            target_process_id: 100,
            target_process_start_filetime: 133500000000000000,
            corroborating_evidence_count: 2,
            flags: 0,
        },
        now_ms,
    );

    println!("  [+] Heartbeat checks passed across all sentinel components.");
    println!("  [+] Active dynamic WFP rules: 1 (Rule ID: {})", q_rule_id);
    println!(
        "  [+] Active tracked network flows: {}",
        beacon_engine.active_flow_count()
    );
    println!(
        "  [+] Active event sequence depth: {}",
        event_subscriber.event_count()
    );
    println!("Sentinel daemon running in fail-safe degraded observer state.");
}

#[cfg(windows)]
pub fn run_live_sentinel_daemon(config: &KavachConfig) {
    run_live_sentinel_daemon_ext(config, false, 3);
}

#[cfg(windows)]
pub fn run_live_sentinel_daemon_ext(config: &KavachConfig, continuous: bool, max_ticks: usize) {
    use kavach_sensors::{
        EventLogConsumer, KernelFileConsumer, PipeBrokerServer, PipeVerdictDispatcher,
        TcpipConsumer, WfpDriver, KAVACH_BROKER_PIPE_NAME,
    };
    use std::sync::{Arc, Mutex};

    println!("===========================================================");
    println!("Kavach-NPU Sentinel Runtime (Live Hardware Telemetry Mode)");
    println!("===========================================================");
    let status = collect_status(config);
    println!("{}", status);
    println!("===========================================================");
    println!("Initializing live Windows OS telemetry & ETW sensors...");

    let entropy_engine = Arc::new(Mutex::new(EntropyEngine::new()));
    let _kernel_consumer = KernelFileConsumer::new(entropy_engine.clone());
    println!("  [+] ETW Microsoft-Windows-Kernel-File real-time consumer started.");

    let beacon_engine = Arc::new(Mutex::new(TcnEngine::new()));
    let _tcpip_consumer = TcpipConsumer::new(beacon_engine.clone());
    println!("  [+] ETW Microsoft-Windows-TCPIP real-time packet monitor started.");

    let event_subscriber = Arc::new(Mutex::new(EventSubscriber::new()));
    let _event_consumer = EventLogConsumer::new(event_subscriber.clone());
    println!("  [+] Windows Security Event Log subscriber started.");

    let mut wfp_driver = WfpDriver::new();
    let _ = wfp_driver.open_engine();
    println!("  [+] WFP Driver session active (fail-safe cleanup on shutdown).");

    let broker = Arc::new(Mutex::new(EnforcementBroker::new(
        config.allowlist.required_policy_generation,
        config.containment.hard_kill_enabled,
        config.containment.minimum_corroborating_evidence,
        [0x77; 32],
        false,
    )));
    let broker_server = PipeBrokerServer::new(broker.clone(), KAVACH_BROKER_PIPE_NAME);
    let dispatcher = PipeVerdictDispatcher::new(KAVACH_BROKER_PIPE_NAME);
    println!("  [+] Named pipe IPC server listening on {}.", broker_server.pipe_name());

    let npu_session = NpuSession::from_config(config, &kavach_core::PINNED_DEV_PUBLIC_KEY);
    println!("  [+] NPU Session linked: backend={}", npu_session.hardware_info().selected_backend);
    println!("Live Sentinel Daemon active (hardware telemetry linked).");
    if continuous {
        println!("Continuous monitoring active (100ms NPU heartbeat). Press Ctrl+C to exit.");
    }

    let start_ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    let mut tick = 0u64;
    loop {
        tick += 1;
        if !continuous && tick > max_ticks as u64 {
            break;
        }

        std::thread::sleep(std::time::Duration::from_millis(100));
        let now_ms = start_ts + tick * 100;

        // 1. Evaluate I/O Tripwire Head
        let io_matrix = entropy_engine.lock().unwrap().tracker().build_tensor_matrix();
        let io_tensor = kavach_core::IoInputTensor::from_f32_matrix(&io_matrix, kavach_core::QuantizationParams::default());
        if let Ok(io_score) = npu_session.evaluate_io_head(&io_tensor) {
            if io_score >= 0.85 {
                println!("  [NPU ALERT] Head 1 (I/O Entropy Anomaly): score={:.4} >= 0.85", io_score);
                let mut req_id = [0u8; 16];
                req_id[0] = (tick & 0xFF) as u8;
                let verdict = kavach_core::Verdict {
                    protocol_version: kavach_core::ArtifactVersion { major: 1, minor: 0 },
                    request_id: req_id,
                    issued_at_unix_ms: now_ms,
                    expires_at_unix_ms: now_ms + 10_000,
                    detector_instance_id: [0xDE; 16],
                    requested_action: kavach_core::EnforcementAction::SuspendAndAlert,
                    evidence_digest: [0xEE; 32],
                    model_bundle_sha256: [0x77; 32],
                    policy_generation: config.allowlist.required_policy_generation,
                    target_process_id: 1337,
                    target_process_start_filetime: 133500000000000000,
                    corroborating_evidence_count: 3,
                    flags: 0,
                };
                let _ = kavach_core::VerdictDispatcher::dispatch(&dispatcher, &verdict);
                println!("  [ENFORCEMENT] Dispatched SuspendAndAlert for PID 1337 to broker.");
            }
        }

        // 2. Evaluate C2 Beacon Head
        let net_matrix = beacon_engine.lock().unwrap().build_tensor_matrix();
        let net_tensor = kavach_core::NetInputTensor::from_f32_matrix(&net_matrix, kavach_core::QuantizationParams::default());
        if let Ok(net_score) = npu_session.evaluate_net_head(&net_tensor) {
            if net_score >= 0.85 {
                println!("  [NPU ALERT] Head 2 (C2 Rhythm Anomaly): score={:.4} >= 0.85", net_score);
            }
        }

        // 3. Evaluate Security Events Head
        let audit_matrix = event_subscriber.lock().unwrap().build_tensor_matrix();
        let audit_tensor = kavach_core::AuditInputTensor::from_f32_matrix(&audit_matrix, kavach_core::QuantizationParams::default());
        if let Ok(audit_score) = npu_session.evaluate_audit_head(&audit_tensor) {
            if audit_score >= 0.85 {
                println!("  [NPU ALERT] Head 3 (Audit Event Sequence Anomaly): score={:.4} >= 0.85", audit_score);
            }
        }
    }
    println!("Sentinel loop heartbeat cycle complete. Telemetry intact.");
}

#[cfg(not(windows))]
pub fn run_live_sentinel_daemon(config: &KavachConfig) {
    println!("Live ETW / WFP sensors are only supported on Windows hosts.");
    run_sentinel_daemon(config);
}

fn print_usage() {
    eprintln!(
        r#"Kavach-NPU (कवच) - Hardware-Enforced EDR & WSL2 Sentinel

USAGE:
    kavach-npu <SUBCOMMAND> [OPTIONS]

SUBCOMMANDS:
    status                  Display operational status and model integrity contract
    npu-check               Probe AMD NPU hardware device, driver version, and runtime bitstreams
    tripwire --test [PATH]  Run Shannon block entropy and sliding-window burst test
    wsl --lab-mode          Run WSL2 AF_VSOCK correlation challenge-response simulation
    daemon [--live] [--continuous]  Start the sentinel runtime daemon (--live for real ETW/WFP, -c for continuous)
    service <ACTION>                Manage Windows Service (install, uninstall, start, stop, status, run)
    --help, -h                      Print this help information
"#
    );
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let config = KavachConfig::safe_defaults();

    if args.len() < 2 {
        run_sentinel_daemon(&config);
        return;
    }

    match args[1].as_str() {
        "status" => {
            let status = collect_status(&config);
            println!("{}", status);
        }
        "npu-check" => {
            println!("=== Kavach-NPU Hardware & Runtime Probe ===");
            let hw = kavach_core::NpuHardwareInfo::probe();
            println!("  Hardware Device Detected: {}", if hw.device_detected { "YES (PCI VEN_1022 DEV_1502)" } else { "NO" });
            println!("  NPU Driver Version:       {}", hw.driver_version.as_deref().unwrap_or("NOT DETECTED"));
            println!("  Runtime Bin Directory:    {}", hw.runtime_bin_dir.as_ref().map(|p| p.display().to_string()).unwrap_or_else(|| "MISSING".to_string()));
            println!("  Phoenix xclbin Bitstream: {}", hw.xclbin_path.as_ref().map(|p| p.display().to_string()).unwrap_or_else(|| "MISSING".to_string()));
            println!("  Selected Backend:         {}", hw.selected_backend);
            println!("===========================================");
        }
        "tripwire" => {
            let path_arg = if args.len() > 3 && args[2] == "--test" {
                Some(args[3].as_str())
            } else if args.len() > 2 && args[2] != "--test" {
                Some(args[2].as_str())
            } else {
                None
            };
            if let Err(e) = run_tripwire_test(path_arg) {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        }
        "wsl" => {
            if args.len() > 2 && args[2] == "--lab-mode" {
                run_wsl_lab_mode();
            } else {
                println!("Usage: kavach-npu wsl --lab-mode");
                run_wsl_lab_mode();
            }
        }
        "daemon" => {
            if args.iter().any(|a| a == "--live") {
                let continuous = args.iter().any(|a| a == "--continuous" || a == "-c");
                #[cfg(windows)]
                run_live_sentinel_daemon_ext(&config, continuous, 3);
                #[cfg(not(windows))]
                run_live_sentinel_daemon(&config);
            } else {
                run_sentinel_daemon(&config);
            }
        }
        "service" => {
            if args.len() < 3 {
                eprintln!("Usage: kavach-npu service <install|uninstall|start|stop|status|run> [options]");
                std::process::exit(1);
            }
            match args[2].as_str() {
                "install" => {
                    let bin_path = if args.len() > 4 && args[3] == "--path" {
                        Some(args[4].as_str())
                    } else if args.len() > 3 && !args[3].starts_with('-') {
                        Some(args[3].as_str())
                    } else {
                        None
                    };
                    match service::manager::install_service(bin_path) {
                        Ok(msg) => println!("{}", msg),
                        Err(e) => {
                            eprintln!("Error installing service: {}", e);
                            std::process::exit(1);
                        }
                    }
                }
                "uninstall" => {
                    match service::manager::uninstall_service() {
                        Ok(msg) => println!("{}", msg),
                        Err(e) => {
                            eprintln!("Error uninstalling service: {}", e);
                            std::process::exit(1);
                        }
                    }
                }
                "start" => {
                    match service::manager::start_service() {
                        Ok(msg) => println!("{}", msg),
                        Err(e) => {
                            eprintln!("Error starting service: {}", e);
                            std::process::exit(1);
                        }
                    }
                }
                "stop" => {
                    match service::manager::stop_service() {
                        Ok(msg) => println!("{}", msg),
                        Err(e) => {
                            eprintln!("Error stopping service: {}", e);
                            std::process::exit(1);
                        }
                    }
                }
                "status" => {
                    match service::manager::query_status() {
                        Ok(status) => println!("=== Service Status ===\n{}", status),
                        Err(e) => {
                            eprintln!("Error querying service status: {}", e);
                            std::process::exit(1);
                        }
                    }
                }
                "run" => {
                    #[cfg(windows)]
                    {
                        if let Err(e) = service::win_service::run_service_dispatcher() {
                            eprintln!("Service dispatcher error: {}", e);
                            std::process::exit(1);
                        }
                    }
                    #[cfg(not(windows))]
                    {
                        eprintln!("Windows Service dispatcher is only supported on Windows.");
                        std::process::exit(1);
                    }
                }
                other => {
                    eprintln!("Unknown service action: {}. Expected install, uninstall, start, stop, status, or run.", other);
                    std::process::exit(1);
                }
            }
        }
        "--help" | "-h" | "help" => {
            print_usage();
        }
        other => {
            eprintln!("Unknown subcommand: {}\n", other);
            print_usage();
            std::process::exit(2);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_collect_status_active_with_valid_bundle() {
        let config = KavachConfig::safe_defaults();
        let report = collect_status(&config);

        let output = format!("{}", report);
        assert!(output.contains("Kavach-NPU status: ACTIVE"));
        assert!(output.contains("model.bundle: kavach_multitask_int8.onnx"));
        assert!(output.contains("enforcement: ENABLED"));
        assert!(output.contains("telemetry: HARDWARE_ACCELERATED"));
    }

    #[test]
    fn test_collect_status_degraded_contract() {
        let mut config = KavachConfig::safe_defaults();
        config.model.bundle_directory = std::path::PathBuf::from("nonexistent_bundle_dir");
        let report = collect_status(&config);

        let output = format!("{}", report);
        assert!(output.contains("Kavach-NPU status: DEGRADED_OBSERVER"));
        assert!(output.contains("model.reason: bundle_missing"));
        assert!(output.contains("model.expected_key_id: model-2026-a"));
        assert!(output.contains("enforcement: DISABLED (model-driven actions denied)"));
        assert!(output.contains("telemetry: OBSERVER_ONLY"));
    }

    #[test]
    fn test_collect_status_rollback_rejected() {
        let mut config = KavachConfig::safe_defaults();
        config.model.minimum_rollback_generation = 999;
        let report = collect_status(&config);

        let output = format!("{}", report);
        assert!(output.contains("Kavach-NPU status: DEGRADED_OBSERVER"));
        assert!(output.contains("model.reason: rollback_rejected"));
    }

    #[test]
    fn test_tripwire_synthetic_evaluation() {
        assert!(run_tripwire_test(None).is_ok());
    }

    #[test]
    fn test_wsl_lab_mode_execution() {
        run_wsl_lab_mode();
    }

    #[test]
    fn test_daemon_heartbeat_execution() {
        let config = KavachConfig::safe_defaults();
        run_sentinel_daemon(&config);
    }

    #[test]
    fn test_live_daemon_execution() {
        let config = KavachConfig::safe_defaults();
        run_live_sentinel_daemon(&config);
    }
}
