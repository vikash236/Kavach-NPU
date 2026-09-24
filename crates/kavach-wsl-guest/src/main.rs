//! kavach-wsl-guest: WSL2 guest agent for cross-boundary telemetry and clock sync.
//!
//! Conforms to ADR 005, ADR 006, and docs/schemas/wsl-vsock-record-v1.md.

pub mod audit_source;
pub mod clock_sync;
pub mod vsock;

use audit_source::GuestAuditSource;
use clock_sync::respond_to_challenge;
use kavach_wsl::GuestFileOperation;
use kavach_wsl::clock_sync::ClockChallenge;
use std::env;
use std::time::Instant;
use vsock::{DEFAULT_VSOCK_PORT, VMADDR_CID_HOST, prepare_wire_frame};

fn print_usage() {
    eprintln!(
        r#"kavach-wsl-guest - Linux WSL2 Guest Agent for Kavach-NPU

USAGE:
    kavach-wsl-guest [OPTIONS]

OPTIONS:
    --host-cid <CID>        AF_VSOCK host CID (default: 2 / VMADDR_CID_HOST)
    --port <PORT>           AF_VSOCK host listener port (default: 7350)
    --distribution-id <HEX> 16-byte distribution UUID hex (default: 4242...42)
    --test-emit <PATH>      Format and emit a test GuestWriteRecord frame for a path
    --daemon                Run continuous guest background agent
    --help, -h              Display this help message
"#
    );
}

fn parse_arg(args: &[String], flag: &str) -> Option<String> {
    for i in 0..args.len() {
        if args[i] == flag && i + 1 < args.len() {
            return Some(args[i + 1].clone());
        }
    }
    None
}

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.iter().any(|a| a == "--help" || a == "-h") {
        print_usage();
        return;
    }

    let host_cid: u32 = parse_arg(&args, "--host-cid")
        .and_then(|s| s.parse().ok())
        .unwrap_or(VMADDR_CID_HOST);

    let port: u32 = parse_arg(&args, "--port")
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_VSOCK_PORT);

    let dist_id: [u8; 16] = if let Some(hex_str) = parse_arg(&args, "--distribution-id") {
        let clean = hex_str.trim();
        let bytes = hex::decode(clean).unwrap_or_else(|_| vec![0x42; 16]);
        let mut arr = [0x42u8; 16];
        let len = bytes.len().min(16);
        arr[..len].copy_from_slice(&bytes[..len]);
        arr
    } else {
        [0x42; 16]
    };

    println!("=== Kavach WSL2 Linux Guest Agent ===");
    println!("  Target Host CID:    {host_cid}");
    println!("  Target Host Port:   {port}");
    println!("  Distribution ID:    {}", hex::encode(dist_id));

    if let Some(path) = parse_arg(&args, "--test-emit") {
        let mut source = GuestAuditSource::new(dist_id);
        println!("\nGenerating diagnostic telemetry record for path: {path}...");

        match source.record_operation(
            std::process::id(),
            "/usr/bin/python3",
            &path,
            GuestFileOperation::Write,
            0,
            4096,
        ) {
            Ok(record) => {
                let frame = prepare_wire_frame(&record).expect("frame prep");
                println!(
                    "[OK] Wire frame created successfully ({} bytes):",
                    frame.len()
                );
                println!("  Sequence:  {}", record.sequence_number);
                println!("  Guest PID: {}", record.guest_process_id);
                println!("  Operation: {:?}", record.operation);
                println!("  Path:      {}", record.normalized_path);
                println!(
                    "  Hex:       {}",
                    hex::encode(&frame[..frame.len().min(64)])
                );
            }
            Err(e) => {
                eprintln!("[ERROR] Failed to record operation: {e}");
                std::process::exit(1);
            }
        }
        return;
    }

    // Default simulation / run mode
    let start_instant = Instant::now();
    let mut source = GuestAuditSource::new(dist_id);

    println!("\nSimulating guest agent operational heartbeat...");
    let sample_path = "/mnt/c/Users/Developer/workspace/project.rs";
    let record = source
        .record_operation(
            std::process::id(),
            "/usr/bin/cargo",
            sample_path,
            GuestFileOperation::Write,
            0,
            8192,
        )
        .expect("record write");

    let wire_frame = prepare_wire_frame(&record).expect("wire frame");
    println!(
        "  [+] Generated write record frame ({} bytes).",
        wire_frame.len()
    );

    let challenge = ClockChallenge {
        nonce: [0x55; 16],
        t0_host_monotonic_ns: 100_000_000,
    };
    let response = respond_to_challenge(&challenge, &start_instant);
    println!(
        "  [+] Responded to host clock challenge (nonce: {}, g1: {}, g2: {}).",
        hex::encode(response.nonce),
        response.g1_guest_monotonic_ns,
        response.g2_guest_monotonic_ns
    );

    println!("WSL2 guest agent initialized in ready state.");
}

#[cfg(test)]
mod tests {
    use super::*;
    use kavach_wsl::GuestWriteRecord;

    #[test]
    fn test_guest_agent_full_flow() {
        let dist_id = [0x42; 16];
        let mut source = GuestAuditSource::new(dist_id);
        let start = Instant::now();

        let record = source
            .record_operation(
                9999,
                "/bin/bash",
                "/mnt/c/Windows/Temp/test.log",
                GuestFileOperation::Write,
                0,
                512,
            )
            .expect("record");

        let frame = prepare_wire_frame(&record).expect("wire");
        assert!(frame.len() >= 150);

        // Verify decoding on host side using kavach-wsl
        let decoded = GuestWriteRecord::from_frame(&frame).expect("host decode");
        assert_eq!(decoded.guest_process_id, 9999);
        assert_eq!(decoded.normalized_path, "/mnt/c/Windows/Temp/test.log");

        // Verify clock response
        let challenge = ClockChallenge {
            nonce: [0xAA; 16],
            t0_host_monotonic_ns: 50_000_000,
        };
        let response = respond_to_challenge(&challenge, &start);
        assert_eq!(response.nonce, [0xAA; 16]);
    }
}
