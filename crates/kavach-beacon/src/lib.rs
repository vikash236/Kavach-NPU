//! Stealth Exfiltration & C2 Beaconing Detector engine per README and ADR 001.

pub mod detector;
pub mod flow;

pub use detector::{
    BeaconDetectionResult, JITTER_CV_MAX, MIN_BEACON_INTERVAL_MS, evaluate_beacon_rhythm,
};
pub use flow::{
    FLOW_FEATURES_PER_PACKET, FLOW_WINDOW_SIZE, FlowKey, PacketDirection, PacketMeta, RollingFlow,
};

use std::collections::HashMap;

/// Primary Temporal Convolutional Network (TCN) and statistical beaconing engine.
#[derive(Debug, Default)]
pub struct TcnEngine {
    flows: HashMap<FlowKey, RollingFlow>,
}

impl TcnEngine {
    /// Constructs a new TcnEngine with an empty flow registry.
    pub fn new() -> Self {
        Self {
            flows: HashMap::new(),
        }
    }

    /// Ingests an observed packet into its respective flow buffer.
    ///
    /// If the flow buffer has accumulated 32 packets, evaluates it for C2 beacon rhythm
    /// and returns the detection result.
    pub fn ingest_packet(
        &mut self,
        key: FlowKey,
        meta: PacketMeta,
    ) -> Option<BeaconDetectionResult> {
        let flow = self.flows.entry(key).or_default();
        let ready = flow.record_packet(meta);
        if ready {
            evaluate_beacon_rhythm(flow)
        } else {
            None
        }
    }

    /// Returns the number of currently tracked active network flows.
    pub fn active_flow_count(&self) -> usize {
        self.flows.len()
    }

    /// Clears all tracked flows.
    pub fn clear(&mut self) {
        self.flows.clear();
    }
}
