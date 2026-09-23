//! Kernel-File ETW event consumer.

use kavach_tripwire::EntropyEngine;
use kavach_tripwire::sliding_window::ProcessBurstEvaluation;
use std::sync::{Arc, Mutex};

/// Kernel file operation event captured from ETW.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KernelFileEvent {
    pub process_id: u32,
    pub file_path: String,
    pub is_rename: bool,
    pub payload: Vec<u8>,
    pub timestamp_unix_ms: u64,
}

/// ETW Kernel-File consumer feeding operations into EntropyEngine.
pub struct KernelFileConsumer {
    engine: Arc<Mutex<EntropyEngine>>,
    is_running: bool,
}

impl KernelFileConsumer {
    pub fn new(engine: Arc<Mutex<EntropyEngine>>) -> Self {
        Self {
            engine,
            is_running: false,
        }
    }

    /// Ingests a raw file operation event and evaluates sliding-window burst.
    pub fn process_event(&self, event: KernelFileEvent) -> Option<ProcessBurstEvaluation> {
        let mut engine = self.engine.lock().unwrap();
        engine.ingest_operation(
            event.process_id,
            &event.file_path,
            &event.payload,
            event.is_rename,
            event.timestamp_unix_ms,
        )
    }

    pub fn is_running(&self) -> bool {
        self.is_running
    }
}
