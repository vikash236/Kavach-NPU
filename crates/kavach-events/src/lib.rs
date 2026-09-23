//! Windows Event Log intelligence and sequence correlation engine per README and ADR 003.

pub mod events;

pub use events::{
    CorrelationPattern, CriticalEventId, EVENT_FEATURES_PER_ROW, EVENT_SEQUENCE_WINDOW_SIZE,
    EventAnomalyAlert, EventSequenceTracker, SecurityEventRecord,
};

/// Event subscriber orchestrating unprivileged Windows Event Log ingestion and sequence analysis.
#[derive(Debug, Default)]
pub struct EventSubscriber {
    tracker: EventSequenceTracker,
}

impl EventSubscriber {
    /// Constructs a new EventSubscriber with an empty sequence window.
    pub fn new() -> Self {
        Self {
            tracker: EventSequenceTracker::new(),
        }
    }

    /// Ingests a captured event into the rolling sequence and checks for multi-event correlations.
    pub fn ingest_event(&mut self, record: SecurityEventRecord) -> Option<EventAnomalyAlert> {
        self.tracker.record_event(record)
    }

    /// Extracts the rolling 16x4 feature matrix for NPU Head 3 evaluation.
    pub fn build_tensor_matrix(
        &self,
    ) -> [[f32; EVENT_FEATURES_PER_ROW]; EVENT_SEQUENCE_WINDOW_SIZE] {
        self.tracker.build_tensor_matrix()
    }

    /// Returns the number of events currently held in the window.
    pub fn event_count(&self) -> usize {
        self.tracker.len()
    }
}
