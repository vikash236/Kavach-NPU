//! threat-injector: Multi-vector synthetic threat simulation tool for Kavach-NPU.
//!
//! Generates controlled, safe simulated attack patterns to test real-time detection
//! and containment across all three multi-task heads:
//! 1. Ransomware burst encryption (Tripwire Head 1)
//! 2. Periodic low-jitter C2 beaconing (Beacon Head 2)
//! 3. Brute-force credential dumping sequence (Events Head 3)
//! 4. WSL2 cross-boundary file tampering (WSL Bridge)

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;

fn print_usage() {
    eprintln!(
        r#"threat-injector: Synthetic Attack Scenario Generator for Kavach-NPU

USAGE:
    threat-injector <SUBCOMMAND> [OPTIONS]

SUBCOMMANDS:
    ransomware      Simulate intermittent/full ransomware encryption bursts
                    Options:
                        --target <DIR>       Target scratch directory (default: ./target/sandbox)
                        --files <COUNT>      Number of files to encrypt (default: 10)
                        --intermittent       Use 50% alternating block encryption

    c2              Simulate Command & Control rhythmic packet beaconing
                    Options:
                        --packets <COUNT>    Number of beacon pulses (default: 32)
                        --interval-ms <MS>   Nominal sleep between pulses (default: 200)
                        --jitter <PCT>       Jitter percentage 0-50 (default: 10)

    audit           Simulate brute-force logon sequence and credential elevation
                    Options:
                        --events <COUNT>     Number of failed logons before success (default: 5)

    full-scenario   Simulate all 3 vectors concurrently to test full EDR stress

    help            Display this help message
"#
    );
}

/// Generates a high-entropy pseudo-random block simulating AES/ChaCha20 ciphertext.
fn generate_ciphertext_block(size: usize, seed: u32) -> Vec<u8> {
    let mut state = seed;
    let mut buf = Vec::with_capacity(size);
    for _ in 0..size {
        state = state.wrapping_mul(1664525).wrapping_add(1013904223);
        buf.push((state >> 16) as u8);
    }
    buf
}

/// Generates low-entropy ASCII text simulating user documents.
fn generate_plaintext_block(size: usize) -> Vec<u8> {
    let text = b"Confidential business report and accounting records. Authorized access only. ";
    let mut buf = Vec::with_capacity(size);
    while buf.len() < size {
        buf.extend_from_slice(text);
    }
    buf.truncate(size);
    buf
}

pub fn run_ransomware_simulation(
    target_dir: &Path,
    file_count: usize,
    intermittent: bool,
) -> Result<(), String> {
    println!("=== Simulating Ransomware Encryption Burst ===");
    println!("  Target Directory: {}", target_dir.display());
    println!("  File Count:       {}", file_count);
    println!(
        "  Mode:             {}",
        if intermittent {
            "Intermittent (alternating high/low blocks)"
        } else {
            "Full Encryption"
        }
    );

    fs::create_dir_all(target_dir).map_err(|e| format!("create dir: {e}"))?;

    for i in 1..=file_count {
        let file_path = target_dir.join(format!("document_{i:03}.docx"));
        let mut file_content = Vec::with_capacity(40960); // 10 blocks of 4KB

        for b in 0..10 {
            if intermittent && (b % 2 == 1) {
                // Intermittent mode leaves every odd block unencrypted
                file_content.extend_from_slice(&generate_plaintext_block(4096));
            } else {
                // Encrypted block
                file_content.extend_from_slice(&generate_ciphertext_block(
                    4096,
                    0x1337 + (i * 10 + b) as u32,
                ));
            }
        }

        fs::write(&file_path, &file_content)
            .map_err(|e| format!("write {}: {e}", file_path.display()))?;
        println!(
            "  [+] Encrypted: {} ({} bytes)",
            file_path.display(),
            file_content.len()
        );
        thread::sleep(Duration::from_millis(5));
    }

    println!("[OK] Ransomware burst simulation completed.");
    Ok(())
}

pub fn run_c2_simulation(
    packet_count: usize,
    interval_ms: u64,
    jitter_pct: u32,
) -> Result<(), String> {
    println!("=== Simulating C2 Rhythmic Network Beaconing ===");
    println!("  Pulse Count:       {}", packet_count);
    println!("  Nominal Interval:  {} ms", interval_ms);
    println!(
        "  Target Jitter CV:  < 0.35 (simulated {}% variance)",
        jitter_pct
    );

    let mut state: u32 = 0x5EED;
    for i in 1..=packet_count {
        state = state.wrapping_mul(1103515245).wrapping_add(12345);
        let jitter_factor = ((state % (jitter_pct * 2 + 1)) as f32 - (jitter_pct as f32)) / 100.0;
        let sleep_ms = ((interval_ms as f32) * (1.0 + jitter_factor)).max(10.0) as u64;

        println!(
            "  [Pulse {:02}/{}] Outbound C2 beacon -> 198.51.100.10:443 (sleeping {} ms)",
            i, packet_count, sleep_ms
        );
        thread::sleep(Duration::from_millis(sleep_ms));
    }

    println!("[OK] C2 beaconing simulation completed.");
    Ok(())
}

pub fn run_audit_simulation(failed_count: usize) -> Result<(), String> {
    println!("=== Simulating Credential Tampering & Elevation ===");
    println!("  Failed Logons:     {}", failed_count);
    println!("  Follow-up Action:  LogonSuccess -> LSASS Access");

    for i in 1..=failed_count {
        println!(
            "  [Event {:02}] EventID 4625 (LogonFailure) user='Administrator' workstation='WORKSTATION'",
            i
        );
        thread::sleep(Duration::from_millis(20));
    }

    println!(
        "  [Event {:02}] EventID 4624 (LogonSuccess) user='Administrator' (Elevated)",
        failed_count + 1
    );
    thread::sleep(Duration::from_millis(20));
    println!(
        "  [Event {:02}] EventID 4672 (SpecialPrivilegesAssigned) user='Administrator'",
        failed_count + 2
    );

    println!("[OK] Credential elevation simulation completed.");
    Ok(())
}

pub fn run_full_scenario() -> Result<(), String> {
    println!("============================================================");
    println!("     Kavach-NPU Full Synthetic Multi-Vector Attack Test     ");
    println!("============================================================");

    let target_dir = PathBuf::from("target/threat_sandbox");
    run_ransomware_simulation(&target_dir, 5, true)?;
    println!();
    run_c2_simulation(8, 50, 5)?;
    println!();
    run_audit_simulation(3)?;
    println!("============================================================");
    println!("All 3 attack vectors dispatched. Check Kavach-NPU daemon logs!");
    Ok(())
}

fn parse_arg_aliases(args: &[String], flags: &[&str]) -> Option<String> {
    for i in 0..args.len() {
        for flag in flags {
            if args[i] == *flag && i + 1 < args.len() {
                return Some(args[i + 1].clone());
            }
        }
    }
    None
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        print_usage();
        return;
    }

    // Support both positional subcommand (`threat-injector ransomware`) and flag style (`threat-injector --mode ransomware`)
    let mode = if let Some(m) = parse_arg_aliases(&args, &["--mode", "-m"]) {
        m
    } else {
        args[1].clone()
    };

    let result = match mode.as_str() {
        "ransomware" => {
            let target_str = parse_arg_aliases(&args, &["--target", "--target-dir", "-t"])
                .unwrap_or_else(|| "target/sandbox".to_string());
            let files: usize = parse_arg_aliases(&args, &["--files", "--file-count", "-f", "-n"])
                .and_then(|s| s.parse().ok())
                .unwrap_or(10);
            let intermittent = args.iter().any(|a| a == "--intermittent");
            run_ransomware_simulation(Path::new(&target_str), files, intermittent)
        }
        "c2" => {
            let packets: usize = parse_arg_aliases(&args, &["--packets", "--packet-count", "-p"])
                .and_then(|s| s.parse().ok())
                .unwrap_or(32);
            let interval: u64 = parse_arg_aliases(&args, &["--interval-ms", "--interval", "-i"])
                .and_then(|s| s.parse().ok())
                .unwrap_or(200);
            let jitter: u32 = parse_arg_aliases(&args, &["--jitter", "-j"])
                .and_then(|s| s.parse().ok())
                .unwrap_or(10);
            run_c2_simulation(packets, interval, jitter)
        }
        "audit" => {
            let count: usize =
                parse_arg_aliases(&args, &["--events", "--iterations", "--count", "-e"])
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(5);
            run_audit_simulation(count)
        }
        "full-scenario" => run_full_scenario(),
        "--help" | "-h" | "help" => {
            print_usage();
            Ok(())
        }
        other => {
            eprintln!("Unknown subcommand or mode: {}\n", other);
            print_usage();
            std::process::exit(1);
        }
    };

    if let Err(e) = result {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}
