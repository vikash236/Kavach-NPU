//! No-op surface for the future timing-based beacon detector.

/// Placeholder temporal-convolutional-network engine whose future model inputs follow ADR 001 and ADR 004.
#[derive(Debug, Default)]
pub struct TcnEngine;

impl TcnEngine {
    /// Construct an engine without subscribing to network telemetry or loading a model.
    pub fn new() -> Self {
        Self
    }
}
