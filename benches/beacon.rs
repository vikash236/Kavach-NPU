use criterion::{Criterion, black_box, criterion_group, criterion_main};
use kavach_beacon::{
    FlowKey, PacketDirection, PacketMeta, RollingFlow, TcnEngine, evaluate_beacon_rhythm,
};
use kavach_core::tensor::{NetInputTensor, QuantizationParams};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::net::{IpAddr, Ipv4Addr};

fn bench_beacon(c: &mut Criterion) {
    let mut group = c.benchmark_group("beacon");

    let flow_key = FlowKey::new(
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, 55)),
        51234,
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10)),
        443,
        6,
    );

    // 1. FlowKey Hash throughput
    group.bench_function("flow_key_hash", |b| {
        b.iter(|| {
            let mut hasher = DefaultHasher::new();
            black_box(&flow_key).hash(&mut hasher);
            hasher.finish()
        });
    });

    // 2. 32-Packet Ring Insertion Throughput
    group.bench_function("rolling_ring_32pkt_ingest", |b| {
        let mut ring = RollingFlow::new();
        let mut ts = 1_000_000_000u64;

        b.iter(|| {
            ts += 100_000_000;
            let meta = PacketMeta {
                timestamp_ns: ts,
                payload_bytes: 128,
                direction: PacketDirection::Outbound,
            };
            ring.record_packet(black_box(meta));
        });
    });

    // 3. C2 Beacon Rhythm Evaluation (Target: < 2.5ms P99 README SLA)
    let mut full_flow = RollingFlow::new();
    for i in 0..32 {
        full_flow.record_packet(PacketMeta {
            timestamp_ns: (i as u64) * 1_000_000_000,
            payload_bytes: 64,
            direction: PacketDirection::Outbound,
        });
    }

    group.bench_function("c2_beacon_eval_full", |b| {
        b.iter(|| {
            evaluate_beacon_rhythm(black_box(&full_flow));
        });
    });

    // 4. End-to-end TCN Engine Flow Ingest and Evaluation
    group.bench_function("tcn_engine_ingest_and_eval", |b| {
        let mut engine = TcnEngine::new();
        let mut ts = 1_000_000_000u64;

        b.iter(|| {
            ts += 100_000_000;
            let meta = PacketMeta {
                timestamp_ns: ts,
                payload_bytes: 128,
                direction: PacketDirection::Outbound,
            };
            engine.ingest_packet(black_box(flow_key.clone()), black_box(meta));
        });
    });

    // 5. NPU Head 2 Tensor Packing
    let f32_matrix = [[0.5f32; 4]; 32];
    let qparams = QuantizationParams::default();

    group.bench_function("npu_tensor_pack_net", |b| {
        b.iter(|| {
            NetInputTensor::from_f32_matrix(black_box(&f32_matrix), black_box(qparams));
        });
    });

    // 6. Complete NPU Head 2 Hardware Dispatch (< 2.5ms README SLA)
    let config = kavach_core::KavachConfig::safe_defaults();
    let npu_session =
        kavach_core::NpuSession::from_config(&config, &kavach_core::PINNED_REFERENCE_PUBLIC_KEY);
    let net_tensor = NetInputTensor::from_f32_matrix(&f32_matrix, qparams);

    group.bench_function("npu_session_net_inference", |b| {
        b.iter(|| {
            npu_session
                .evaluate_net_head(black_box(&net_tensor))
                .unwrap();
        });
    });

    #[cfg(feature = "npu-hardware")]
    {
        let info = kavach_core::npu_backend::NpuHardwareInfo::probe();
        if let Ok(ort_session) =
            kavach_core::npu_backend::OrtBackendSession::from_reference_model(&info)
        {
            group.bench_function("npu_hardware_net_direct_dispatch", |b| {
                b.iter(|| {
                    ort_session
                        .run_net_inference(black_box(&net_tensor.data))
                        .unwrap();
                });
            });
        }
    }

    group.finish();
}

criterion_group!(benches, bench_beacon);
criterion_main!(benches);
