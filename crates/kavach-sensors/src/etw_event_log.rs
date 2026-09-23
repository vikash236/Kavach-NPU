//! Windows Security Event Log subscriber.

use kavach_events::{EventAnomalyAlert, EventSubscriber, SecurityEventRecord};
use std::sync::{Arc, Mutex};

/// Windows Event Log consumer feeding events into EventSubscriber.
pub struct EventLogConsumer {
    subscriber: Arc<Mutex<EventSubscriber>>,
    is_running: bool,
}

impl EventLogConsumer {
    pub fn new(subscriber: Arc<Mutex<EventSubscriber>>) -> Self {
        Self {
            subscriber,
            is_running: false,
        }
    }

    /// Ingests a SecurityEventRecord and checks for correlation pattern alerts.
    pub fn process_event(&self, record: SecurityEventRecord) -> Option<EventAnomalyAlert> {
        let mut sub = self.subscriber.lock().unwrap();
        sub.ingest_event(record)
    }

    pub fn is_running(&self) -> bool {
        self.is_running
    }
}
