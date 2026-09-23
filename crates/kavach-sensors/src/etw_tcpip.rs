//! TCPIP ETW event consumer.

use kavach_beacon::{BeaconDetectionResult, FlowKey, PacketDirection, PacketMeta, TcnEngine};
use std::sync::{Arc, Mutex};

/// Network packet event captured from ETW Microsoft-Windows-TCPIP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpipPacketEvent {
    pub flow_key: FlowKey,
    pub payload_bytes: usize,
    pub direction: PacketDirection,
    pub timestamp_ns: u64,
}

/// ETW TCPIP consumer feeding packets into TcnEngine.
pub struct TcpipConsumer {
    engine: Arc<Mutex<TcnEngine>>,
    is_running: bool,
}

impl TcpipConsumer {
    pub fn new(engine: Arc<Mutex<TcnEngine>>) -> Self {
        Self {
            engine,
            is_running: false,
        }
    }

    /// Ingests a packet event and evaluates C2 beaconing if 32 packets accumulated.
    pub fn process_packet(&self, event: TcpipPacketEvent) -> Option<BeaconDetectionResult> {
        let mut engine = self.engine.lock().unwrap();
        let meta = PacketMeta {
            timestamp_ns: event.timestamp_ns,
            payload_bytes: event.payload_bytes as u32,
            direction: event.direction,
        };
        engine.ingest_packet(event.flow_key, meta)
    }

    pub fn is_running(&self) -> bool {
        self.is_running
    }
}
