//! No-op surface for the future file-write anomaly detector.

/// Placeholder entropy engine governed by the reversible containment policy in ADR 002.
#[derive(Debug, Default)]
pub struct EntropyEngine;

impl EntropyEngine {
    /// Construct an engine without connecting to ETW or evaluating file content.
    pub fn new() -> Self {
        Self
    }
}
