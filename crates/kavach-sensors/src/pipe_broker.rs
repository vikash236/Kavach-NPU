//! Named pipe IPC client and server for ADR 003 privilege separation.

use kavach_core::wire::VERDICT_WIRE_SIZE;
use kavach_core::{DispatchError, Verdict, VerdictDispatcher};
use kavach_firewall::EnforcementBroker;
use std::sync::{Arc, Mutex};

/// Default local named pipe path per ADR 003.
pub const KAVACH_BROKER_PIPE_NAME: &str = r"\\.\pipe\kavach-broker";

/// Named Pipe Verdict Dispatcher (Client side, used by low-privilege detector).
#[derive(Debug, Clone)]
pub struct PipeVerdictDispatcher {
    pipe_name: String,
    broker_fallback: Option<Arc<Mutex<EnforcementBroker>>>,
}

impl PipeVerdictDispatcher {
    /// Constructs a dispatcher targeting the named pipe.
    pub fn new(pipe_name: &str) -> Self {
        Self {
            pipe_name: pipe_name.to_string(),
            broker_fallback: None,
        }
    }

    /// Constructs a dispatcher with an in-memory broker fallback for testing or standalone mode.
    pub fn with_in_memory_broker(broker: Arc<Mutex<EnforcementBroker>>) -> Self {
        Self {
            pipe_name: KAVACH_BROKER_PIPE_NAME.to_string(),
            broker_fallback: Some(broker),
        }
    }
}

impl VerdictDispatcher for PipeVerdictDispatcher {
    fn dispatch(&self, verdict: &Verdict) -> Result<(), DispatchError> {
        // If an in-memory broker is registered (e.g. simulation or test), execute directly
        if let Some(ref broker_mutex) = self.broker_fallback {
            let mut broker = broker_mutex.lock().unwrap();
            let now_ms = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64;
            broker
                .evaluate_and_enforce(verdict, now_ms)
                .map(|_| ())
        } else {
            // Live named pipe transmission
            let wire_bytes = verdict.to_wire();
            assert_eq!(wire_bytes.len(), VERDICT_WIRE_SIZE);

            #[cfg(windows)]
            {
                use std::fs::OpenOptions;
                use std::io::{Read, Write};

                let mut file = match OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(&self.pipe_name)
                {
                    Ok(f) => f,
                    Err(_) => return Err(DispatchError::BrokerUnreachable),
                };

                if file.write_all(&wire_bytes).is_err() {
                    return Err(DispatchError::BrokerUnreachable);
                }

                let mut response = [0u8; 1];
                if file.read_exact(&mut response).is_err() {
                    return Err(DispatchError::BrokerUnreachable);
                }

                match response[0] {
                    0 => Ok(()),
                    1 => Err(DispatchError::VersionMismatch),
                    2 => Err(DispatchError::ReplayDetected),
                    3 => Err(DispatchError::MalformedMessage),
                    4 => Err(DispatchError::AuthenticationFailed),
                    5 => Err(DispatchError::Expired),
                    6 => Err(DispatchError::ActionDenied),
                    _ => Err(DispatchError::BrokerUnreachable),
                }
            }

            #[cfg(not(windows))]
            {
                Err(DispatchError::BrokerUnreachable)
            }
        }
    }
}

/// Named pipe broker listener service running on privileged side.
pub struct PipeBrokerServer {
    broker: Arc<Mutex<EnforcementBroker>>,
    pipe_name: String,
    is_running: bool,
}

impl PipeBrokerServer {
    pub fn new(broker: Arc<Mutex<EnforcementBroker>>, pipe_name: &str) -> Self {
        Self {
            broker,
            pipe_name: pipe_name.to_string(),
            is_running: false,
        }
    }

    /// Evaluates a single 139-byte wire frame against the broker.
    pub fn handle_frame(&self, frame: &[u8], now_unix_ms: u64) -> Result<(), DispatchError> {
        let verdict = Verdict::from_slice(frame).map_err(DispatchError::from)?;

        let mut broker = self.broker.lock().unwrap();
        broker
            .evaluate_and_enforce(&verdict, now_unix_ms)
            .map(|_| ())
    }

    pub fn is_running(&self) -> bool {
        self.is_running
    }

    pub fn pipe_name(&self) -> &str {
        &self.pipe_name
    }
}
