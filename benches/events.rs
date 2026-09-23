use criterion::{Criterion, black_box, criterion_group, criterion_main};
use kavach_core::tensor::{AuditInputTensor, QuantizationParams};
use kavach_events::{CriticalEventId, EventSubscriber, SecurityEventRecord};

fn bench_events(c: &mut Criterion) {
    let mut group = c.benchmark_group("events");

    // 1. Single SecurityEventRecord Ingestion (Target: < 0.8ms P99 README SLA)
    group.bench_function("event_ingest_single", |b| {
        let mut subscriber = EventSubscriber::new();
        let mut ts = 1_700_000_000_000u64;

        b.iter(|| {
            ts += 10;
            let record = SecurityEventRecord {
                event_id: CriticalEventId::LogonSuccess,
                timestamp_unix_ms: ts,
                process_id: 1000,
                subject_user: "Administrator".to_string(),
                target_resource: "LSASS.exe".to_string(),
            };
            subscriber.ingest_event(black_box(record));
        });
    });

    // 2. Brute Force Sequence Correlation Detection
    group.bench_function("brute_force_pattern_detection", |b| {
        let mut subscriber = EventSubscriber::new();
        let mut ts = 1_700_000_000_000u64;
        let mut toggle = false;

        b.iter(|| {
            ts += 50;
            toggle = !toggle;
            let event_id = if toggle {
                CriticalEventId::LogonFailure
            } else {
                CriticalEventId::LogonSuccess
            };

            let record = SecurityEventRecord {
                event_id,
                timestamp_unix_ms: ts,
                process_id: 4444,
                subject_user: "target_account".to_string(),
                target_resource: "Workstation".to_string(),
            };
            subscriber.ingest_event(black_box(record));
        });
    });

    // 3. 16-Event Rolling Sequence Feature Matrix Build
    let mut subscriber = EventSubscriber::new();
    for i in 0..16 {
        subscriber.ingest_event(SecurityEventRecord {
            event_id: CriticalEventId::PowerShellScriptBlock,
            timestamp_unix_ms: 1_700_000_000_000 + i * 10,
            process_id: 2000,
            subject_user: "dev".to_string(),
            target_resource: "powershell.exe".to_string(),
        });
    }

    group.bench_function("build_tensor_matrix_16x4", |b| {
        b.iter(|| {
            subscriber.build_tensor_matrix();
        });
    });

    // 4. NPU Head 3 Tensor Packing
    let f32_matrix = [[0.7f32; 4]; 16];
    let qparams = QuantizationParams::default();

    group.bench_function("npu_tensor_pack_audit", |b| {
        b.iter(|| {
            AuditInputTensor::from_f32_matrix(black_box(&f32_matrix), black_box(qparams));
        });
    });

    // 5. Complete NPU Head 3 Hardware Dispatch (< 0.8ms README SLA)
    let config = kavach_core::KavachConfig::safe_defaults();
    let npu_session = kavach_core::NpuSession::from_config(&config, &kavach_core::PINNED_DEV_PUBLIC_KEY);
    let audit_tensor = AuditInputTensor::from_f32_matrix(&f32_matrix, qparams);

    group.bench_function("npu_session_audit_inference", |b| {
        b.iter(|| {
            npu_session.evaluate_audit_head(black_box(&audit_tensor)).unwrap();
        });
    });

    group.finish();
}

criterion_group!(benches, bench_events);
criterion_main!(benches);
