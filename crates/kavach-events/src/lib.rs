//! No-op surface for the future Windows Event Log collector.

/// Placeholder event subscriber that remains unprivileged in the split architecture of ADR 003.
#[derive(Debug, Default)]
pub struct EventSubscriber;

impl EventSubscriber {
    /// Construct a subscriber without calling Windows Event Log APIs.
    pub fn new() -> Self {
        Self
    }
}
