use criterion::{Criterion, black_box, criterion_group, criterion_main};
use kavach_beacon::{FlowKey, PacketDirection, PacketMeta, TcnEngine};
use kavach_core::ArtifactVersion;
use kavach_events::{CriticalEventId, EventSubscriber, SecurityEventRecord};
use kavach_tripwire::EntropyEngine;
use kavach_wsl::correlator::{HostFileEvent, WslCorrelator};
use kavach_wsl::{GuestFileOperation, GuestWriteRecord};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

fn bench_stress(c: &mut Criterion) {
    let mut group = c.benchmark_group("stress");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(5));

    group.bench_function("concurrent_4engine_stress_iteration", |b| {
        b.iter(|| {
            let running = Arc::new(AtomicBool::new(true));

            // Engine 1: Tripwire Ransomware Burst Tracker
            let tripwire_engine = Arc::new(Mutex::new(EntropyEngine::new()));
            let tw_clone = tripwire_engine.clone();
            let r1 = running.clone();
            let h1 = thread::spawn(move || {
                let payload = vec![0xDDu8; 4096];
                let mut ts = 1_700_000_000_000u64;
                let mut count = 0;
                while r1.load(Ordering::Relaxed) && count < 200 {
                    ts += 2;
                    let mut eng = tw_clone.lock().unwrap();
                    let pid = 1000 + (count % 8);
                    eng.ingest_operation(pid, "C:\\work\\file.enc", &payload, false, ts);
                    count += 1;
                }
            });

            // Engine 2: Beacon TCN Engine
            let beacon_engine = Arc::new(Mutex::new(TcnEngine::new()));
            let bc_clone = beacon_engine.clone();
            let r2 = running.clone();
            let h2 = thread::spawn(move || {
                let flow = FlowKey::new(
                    IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                    12345,
                    IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2)),
                    443,
                    6,
                );
                let mut ts = 1_000_000_000u64;
                let mut count = 0;
                while r2.load(Ordering::Relaxed) && count < 100 {
                    ts += 100_000_000;
                    let mut eng = bc_clone.lock().unwrap();
                    eng.ingest_packet(
                        flow.clone(),
                        PacketMeta {
                            timestamp_ns: ts,
                            payload_bytes: 64,
                            direction: PacketDirection::Outbound,
                        },
                    );
                    count += 1;
                }
            });

            // Engine 3: Event Subscriber
            let event_sub = Arc::new(Mutex::new(EventSubscriber::new()));
            let ev_clone = event_sub.clone();
            let r3 = running.clone();
            let h3 = thread::spawn(move || {
                let mut ts = 1_700_000_000_000u64;
                let mut count = 0;
                while r3.load(Ordering::Relaxed) && count < 100 {
                    ts += 10;
                    let mut sub = ev_clone.lock().unwrap();
                    sub.ingest_event(SecurityEventRecord {
                        event_id: CriticalEventId::LogonSuccess,
                        timestamp_unix_ms: ts,
                        process_id: 500,
                        subject_user: "user".to_string(),
                        target_resource: "system".to_string(),
                    });
                    count += 1;
                }
            });

            // Engine 4: WSL Correlator
            let correlator = Arc::new(Mutex::new(WslCorrelator::new([0x33; 16], 250)));
            let wsl_clone = correlator.clone();
            let r4 = running.clone();
            let h4 = thread::spawn(move || {
                let mut count = 0;
                while r4.load(Ordering::Relaxed) && count < 50 {
                    let mut corr = wsl_clone.lock().unwrap();
                    corr.record_host_event(HostFileEvent {
                        host_timestamp_ns: 1_000_000 + count * 1_000_000,
                        canonical_windows_path: "C:\\Users\\file.bin".to_string(),
                        is_vmmem_process: true,
                        bytes_written: 1024,
                    });
                    corr.correlate_guest_record(
                        GuestWriteRecord {
                            version: ArtifactVersion { major: 1, minor: 0 },
                            sequence_number: count + 1,
                            guest_monotonic_ns: 1_000_000 + count * 1_000_000,
                            guest_realtime_ns: 1_700_000_000_000_000_000,
                            guest_process_id: 111,
                            guest_process_start_ticks: 10,
                            distribution_id: [0x33; 16],
                            mount_namespace_id: 1,
                            executable_sha256: [0x11; 32],
                            cgroup_sha256: [0x22; 32],
                            operation: GuestFileOperation::Write,
                            normalized_path: "/mnt/c/Users/file.bin".to_string(),
                            byte_range_start: 0,
                            byte_range_length: 1024,
                            flags: 0,
                        },
                        1_000_000 + count * 1_000_000,
                    );
                    count += 1;
                }
            });

            // Wait for all 4 worker threads to complete their batch
            h1.join().unwrap();
            h2.join().unwrap();
            h3.join().unwrap();
            h4.join().unwrap();
            black_box(());
        });
    });

    group.finish();
}

criterion_group!(benches, bench_stress);
criterion_main!(benches);
