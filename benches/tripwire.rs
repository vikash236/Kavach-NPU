use criterion::{Criterion, black_box, criterion_group, criterion_main};
use kavach_core::tensor::{IoInputTensor, QuantizationParams};
use kavach_tripwire::EntropyEngine;
use kavach_tripwire::entropy::{
    DEFAULT_BLOCK_SIZE, block_entropy_scan, differential_entropy, shannon_entropy,
};

fn bench_tripwire(c: &mut Criterion) {
    let mut group = c.benchmark_group("tripwire");

    // 1. 4KB Block Shannon Entropy (Target: >= 500 MB/s throughput, latency << 10 µs)
    let mut block_4kb = vec![0u8; 4096];
    for (i, b) in block_4kb.iter_mut().enumerate() {
        *b = (i % 256) as u8;
    }

    group.bench_function("shannon_4kb_block", |b| {
        b.iter(|| {
            shannon_entropy(black_box(&block_4kb));
        });
    });

    // 2. 1MB File Shannon Entropy (Target: >= 400 MB/s throughput)
    let mut file_1mb = vec![0u8; 1024 * 1024];
    for (i, b) in file_1mb.iter_mut().enumerate() {
        *b = ((i * 31) % 256) as u8;
    }

    group.bench_function("shannon_1mb_file", |b| {
        b.iter(|| {
            shannon_entropy(black_box(&file_1mb));
        });
    });

    // 3. Differential 10-block Scan
    let mut ten_blocks = vec![0u8; 4096 * 10];
    for (i, b) in ten_blocks.iter_mut().enumerate() {
        *b = ((i * 13) % 256) as u8;
    }

    group.bench_function("differential_10_blocks", |b| {
        b.iter(|| {
            let scans = block_entropy_scan(black_box(&ten_blocks), DEFAULT_BLOCK_SIZE);
            differential_entropy(black_box(&scans));
        });
    });

    // 4. Sliding Window 50ms Burst Tracker (Target: < 1.2ms README SLA)
    group.bench_function("sliding_window_burst_eval", |b| {
        let mut engine = EntropyEngine::new();
        let payload = vec![0xAAu8; 4096];
        let mut ts = 1_700_000_000_000u64;

        b.iter(|| {
            ts += 5;
            engine.ingest_operation(
                black_box(4096),
                black_box("C:\\target\\document.docx"),
                black_box(&payload),
                black_box(false),
                black_box(ts),
            );
        });
    });

    // 5. NPU Head 1 Tensor Packing
    let f32_matrix = [[0.85f32; 4]; 10];
    let qparams = QuantizationParams::default();

    group.bench_function("npu_tensor_pack_io", |b| {
        b.iter(|| {
            IoInputTensor::from_f32_matrix(black_box(&f32_matrix), black_box(qparams));
        });
    });

    // 6. Complete NPU Head 1 Hardware Dispatch (< 1.2ms README SLA)
    let config = kavach_core::KavachConfig::safe_defaults();
    let npu_session =
        kavach_core::NpuSession::from_config(&config, &kavach_core::PINNED_REFERENCE_PUBLIC_KEY);
    let io_tensor = IoInputTensor::from_f32_matrix(&f32_matrix, qparams);

    group.bench_function("npu_session_io_inference", |b| {
        b.iter(|| {
            npu_session.evaluate_io_head(black_box(&io_tensor)).unwrap();
        });
    });

    group.finish();
}

criterion_group!(benches, bench_tripwire);
criterion_main!(benches);
