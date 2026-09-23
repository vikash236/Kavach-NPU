use criterion::{Criterion, black_box, criterion_group, criterion_main};
use kavach_core::ArtifactVersion;
use kavach_wsl::clock_sync::{ClockChallenge, ClockResponse, ClockSynchronizer};
use kavach_wsl::correlator::{
    HostFileEvent, WslCorrelator, translate_mnt_to_windows_path,
};
use kavach_wsl::{GuestFileOperation, GuestWriteRecord};

fn bench_wsl(c: &mut Criterion) {
    let mut group = c.benchmark_group("wsl");

    // 1. Path Translation Throughput (/mnt/c/... -> C:\...)
    let mnt_path = "/mnt/c/Users/Developer/source/repos/kavach-npu/crates/kavach-core/src/lib.rs";

    group.bench_function("path_translation_single", |b| {
        b.iter(|| {
            translate_mnt_to_windows_path(black_box(mnt_path));
        });
    });

    // 2. Clock Synchronization Challenge-Response Offset Estimation
    group.bench_function("clock_sync_estimate", |b| {
        let dist_id = [0x55; 16];
        let mut sync = ClockSynchronizer::new(dist_id);
        let challenge = ClockChallenge {
            nonce: [0x01; 16],
            t0_host_monotonic_ns: 1_000_000,
        };
        let response = ClockResponse {
            nonce: [0x01; 16],
            g1_guest_monotonic_ns: 1_005_000,
            g2_guest_monotonic_ns: 1_006_000,
        };

        b.iter(|| {
            sync.process_response(
                black_box(&challenge),
                black_box(&response),
                black_box(1_012_000),
            )
            .unwrap();
        });
    });

    // 3. WSL Correlator Join Window Performance
    let dist_id = [0x55; 16];
    let mut correlator = WslCorrelator::new(dist_id, 250);

    // Warm up clock sync so confidence can reach High
    let challenge = ClockChallenge {
        nonce: [0x01; 16],
        t0_host_monotonic_ns: 1_000_000,
    };
    let response = ClockResponse {
        nonce: [0x01; 16],
        g1_guest_monotonic_ns: 1_001_000,
        g2_guest_monotonic_ns: 1_002_000,
    };
    let _ = correlator
        .clock_sync_mut()
        .process_response(&challenge, &response, 1_004_000);

    // Preload host events
    for i in 0..100 {
        correlator.record_host_event(HostFileEvent {
            host_timestamp_ns: 1_000_000 + i * 1_000_000,
            canonical_windows_path: format!("C:\\Users\\Developer\\file_{i}.txt"),
            is_vmmem_process: true,
            bytes_written: 4096,
        });
    }

    let record = GuestWriteRecord {
        version: ArtifactVersion { major: 1, minor: 0 },
        sequence_number: 1,
        guest_monotonic_ns: 1_001_000 + 50 * 1_000_000,
        guest_realtime_ns: 1_700_000_000_000_000_000,
        guest_process_id: 4200,
        guest_process_start_ticks: 100,
        distribution_id: dist_id,
        mount_namespace_id: 1,
        executable_sha256: [0xAA; 32],
        cgroup_sha256: [0xBB; 32],
        operation: GuestFileOperation::Write,
        normalized_path: "/mnt/c/Users/Developer/file_50.txt".to_string(),
        byte_range_start: 0,
        byte_range_length: 4096,
        flags: 0,
    };

    group.bench_function("correlate_guest_record", |b| {
        b.iter(|| {
            correlator.correlate_guest_record(black_box(record.clone()), black_box(1_000_000 + 50 * 1_000_000));
        });
    });

    group.finish();
}

criterion_group!(benches, bench_wsl);
criterion_main!(benches);
