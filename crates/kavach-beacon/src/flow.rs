//! Network flow aggregation and rolling 32-packet matrix builder for C2 beaconing analysis.

use std::collections::VecDeque;
use std::net::IpAddr;

/// Number of packets per rolling evaluation window (32 packets per README and NPU budget).
pub const FLOW_WINDOW_SIZE: usize = 32;

/// Number of features per packet in the NPU Head 2 input tensor: [1, 32, 4].
pub const FLOW_FEATURES_PER_PACKET: usize = 4;

/// Direction of network traffic relative to the protected endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketDirection {
    /// Packet sent from local endpoint to remote peer.
    Outbound,
    /// Packet received from remote peer by local endpoint.
    Inbound,
}

/// Metadata captured for a single IP packet without inspecting payload content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacketMeta {
    /// High-resolution timestamp in nanoseconds.
    pub timestamp_ns: u64,
    /// Layer-4 payload byte count (excluding IP/TCP headers).
    pub payload_bytes: u32,
    /// Directionality of the transfer.
    pub direction: PacketDirection,
}

/// Unique identifier for a bidirectional communication channel.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub local_addr: IpAddr,
    pub local_port: u16,
    pub remote_addr: IpAddr,
    pub remote_port: u16,
    pub protocol: u8,
}

impl FlowKey {
    /// Constructs a flow key from endpoint endpoints.
    pub fn new(
        local_addr: IpAddr,
        local_port: u16,
        remote_addr: IpAddr,
        remote_port: u16,
        protocol: u8,
    ) -> Self {
        Self {
            local_addr,
            local_port,
            remote_addr,
            remote_port,
            protocol,
        }
    }
}

/// A rolling ring buffer capturing the most recent 32 packets of a network flow.
#[derive(Debug, Clone)]
pub struct RollingFlow {
    packets: VecDeque<PacketMeta>,
    total_packets_seen: u64,
}

impl Default for RollingFlow {
    fn default() -> Self {
        Self::new()
    }
}

impl RollingFlow {
    /// Creates a new rolling flow buffer with capacity 32.
    pub fn new() -> Self {
        Self {
            packets: VecDeque::with_capacity(FLOW_WINDOW_SIZE),
            total_packets_seen: 0,
        }
    }

    /// Records an arriving packet. Returns true if the window is full (32 packets ready).
    pub fn record_packet(&mut self, meta: PacketMeta) -> bool {
        if self.packets.len() == FLOW_WINDOW_SIZE {
            self.packets.pop_front();
        }
        self.packets.push_back(meta);
        self.total_packets_seen += 1;
        self.packets.len() == FLOW_WINDOW_SIZE
    }

    /// Returns the number of packets currently held in the window.
    pub fn len(&self) -> usize {
        self.packets.len()
    }

    /// Returns true if the rolling window holds exactly 32 packets.
    pub fn is_full(&self) -> bool {
        self.packets.len() == FLOW_WINDOW_SIZE
    }

    /// Returns true if the window contains no packets.
    pub fn is_empty(&self) -> bool {
        self.packets.is_empty()
    }

    /// Returns a slice-like view of all packets in chronological order.
    pub fn packets(&self) -> &VecDeque<PacketMeta> {
        &self.packets
    }

    /// Extracts the [32, 4] feature matrix formatted for the NPU Head 2 input tensor [1, 32, 4].
    ///
    /// - Feature 0: Scaled inter-arrival delta (log10(1 + delta_ms) / 5.0)
    /// - Feature 1: Normalized payload size (min(bytes, 1500) / 1500.0)
    /// - Feature 2: Directionality (+1.0 for Outbound, -1.0 for Inbound)
    /// - Feature 3: Cumulative window delta progress (0.0..=1.0)
    pub fn build_tensor_matrix(
        &self,
    ) -> Option<[[f32; FLOW_FEATURES_PER_PACKET]; FLOW_WINDOW_SIZE]> {
        if !self.is_full() {
            return None;
        }

        let mut matrix = [[0.0f32; FLOW_FEATURES_PER_PACKET]; FLOW_WINDOW_SIZE];
        let first_ts = self.packets[0].timestamp_ns;
        let last_ts = self.packets[FLOW_WINDOW_SIZE - 1].timestamp_ns;
        let total_span_ns = (last_ts.saturating_sub(first_ts)).max(1) as f32;

        let mut prev_ts = first_ts;

        for (i, p) in self.packets.iter().enumerate() {
            // Delta t from previous packet in milliseconds
            let delta_ms = if i == 0 {
                0.0
            } else {
                (p.timestamp_ns.saturating_sub(prev_ts) as f64) / 1_000_000.0
            };
            prev_ts = p.timestamp_ns;

            // Feature 0: Log-scaled delta t (bounds 0ms..100s into 0.0..1.0)
            let scaled_delta = ((1.0 + delta_ms).log10() / 5.0).clamp(0.0, 1.0) as f32;

            // Feature 1: Payload size normalized to standard MTU (1500 bytes)
            let scaled_payload = ((p.payload_bytes.min(1500)) as f32 / 1500.0).clamp(0.0, 1.0);

            // Feature 2: Directionality
            let direction = match p.direction {
                PacketDirection::Outbound => 1.0f32,
                PacketDirection::Inbound => -1.0f32,
            };

            // Feature 3: Cumulative time fraction across the 32-packet window
            let time_fraction =
                ((p.timestamp_ns.saturating_sub(first_ts)) as f32 / total_span_ns).clamp(0.0, 1.0);

            matrix[i] = [scaled_delta, scaled_payload, direction, time_fraction];
        }

        Some(matrix)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_flow_key_creation() {
        let key = FlowKey::new(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
            54321,
            IpAddr::V4(Ipv4Addr::new(104, 21, 55, 2)),
            443,
            6, // TCP
        );
        assert_eq!(key.local_port, 54321);
        assert_eq!(key.remote_port, 443);
        assert_eq!(key.protocol, 6);
    }

    #[test]
    fn test_rolling_flow_window_accumulation() {
        let mut flow = RollingFlow::new();
        assert!(!flow.is_full());
        assert_eq!(flow.len(), 0);

        for i in 0..31 {
            let ready = flow.record_packet(PacketMeta {
                timestamp_ns: i * 1_000_000_000,
                payload_bytes: 64,
                direction: PacketDirection::Outbound,
            });
            assert!(!ready);
        }

        // 32nd packet completes the window
        let ready = flow.record_packet(PacketMeta {
            timestamp_ns: 31 * 1_000_000_000,
            payload_bytes: 64,
            direction: PacketDirection::Inbound,
        });
        assert!(ready);
        assert!(flow.is_full());
        assert_eq!(flow.len(), FLOW_WINDOW_SIZE);

        // 33rd packet maintains 32-packet capacity
        flow.record_packet(PacketMeta {
            timestamp_ns: 32 * 1_000_000_000,
            payload_bytes: 64,
            direction: PacketDirection::Outbound,
        });
        assert_eq!(flow.len(), FLOW_WINDOW_SIZE);
    }

    #[test]
    fn test_tensor_matrix_dimensions_and_ranges() {
        let mut flow = RollingFlow::new();
        let base_ts = 1_000_000_000_000u64;

        for i in 0..FLOW_WINDOW_SIZE {
            flow.record_packet(PacketMeta {
                timestamp_ns: base_ts + (i as u64 * 50_000_000), // 50ms interval
                payload_bytes: if i % 2 == 0 { 128 } else { 1024 },
                direction: if i % 2 == 0 {
                    PacketDirection::Outbound
                } else {
                    PacketDirection::Inbound
                },
            });
        }

        let matrix = flow.build_tensor_matrix().expect("matrix produced");
        assert_eq!(matrix.len(), FLOW_WINDOW_SIZE);
        assert_eq!(matrix[0].len(), FLOW_FEATURES_PER_PACKET);

        for row in &matrix {
            assert!(row[0] >= 0.0 && row[0] <= 1.0, "delta feature in range");
            assert!(row[1] >= 0.0 && row[1] <= 1.0, "payload feature in range");
            assert!(
                row[2] == 1.0 || row[2] == -1.0,
                "directionality feature valid"
            );
            assert!(row[3] >= 0.0 && row[3] <= 1.0, "time fraction in range");
        }
    }
}
