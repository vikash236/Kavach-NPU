//! Configuration parser and bounds validator for `kavach.toml` per config-schema.md and ADR 002, 004, 005, 006.

use crate::ArtifactVersion;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Root configuration loaded from `kavach.toml`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KavachConfig {
    /// Artifact version envelope (must be major = 1).
    pub artifact_version: ArtifactVersion,
    /// Containment and process intervention policies.
    #[serde(default)]
    pub containment: ContainmentConfig,
    /// Allowlist policy reference.
    #[serde(default)]
    pub allowlist: AllowlistConfig,
    /// NPU model bundle and verification policies.
    #[serde(default)]
    pub model: ModelConfig,
    /// WSL2 cross-boundary telemetry and containment configuration.
    #[serde(default)]
    pub wsl: WslConfig,
}

/// Containment policy settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContainmentConfig {
    /// Whether irreversible hard-kill actions are enabled (requires explicit opt-in).
    #[serde(default = "default_false")]
    pub hard_kill_enabled: bool,
    /// Minimum independent evidence signals required for hard-kill (1..=255).
    #[serde(default = "default_min_evidence")]
    pub minimum_corroborating_evidence: u8,
    /// Action audit retention TTL in seconds (60..=86400).
    #[serde(default = "default_suspend_ttl")]
    pub suspend_action_ttl_seconds: u32,
}

/// Local signed allowlist settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AllowlistConfig {
    /// Relative path beneath protected configuration directory to allowlist JSON.
    #[serde(default = "default_allowlist_manifest")]
    pub manifest_path: PathBuf,
    /// Required monotonic policy generation.
    #[serde(default)]
    pub required_policy_generation: u64,
}

/// NPU model bundle loading settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelConfig {
    /// Relative directory containing the verified active model bundle.
    #[serde(default = "default_model_bundle_dir")]
    pub bundle_directory: PathBuf,
    /// Minimum acceptable rollback generation.
    #[serde(default)]
    pub minimum_rollback_generation: u64,
    /// Minimum acceptable keyring generation.
    #[serde(default)]
    pub minimum_keyring_generation: u64,
    /// Whether last-known-good bundle fallback is permitted.
    #[serde(default = "default_true")]
    pub allow_last_known_good: bool,
}

/// WSL2 cross-boundary sentinel settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WslConfig {
    /// Maximum correlation window in milliseconds (10..=250).
    #[serde(default = "default_correlation_window_ms")]
    pub correlation_window_ms: u32,
    /// Maximum allowed clock uncertainty in milliseconds (1..=50).
    #[serde(default = "default_max_clock_uncertainty_ms")]
    pub maximum_clock_uncertainty_ms: u32,
    /// Challenge-response interval in seconds (fixed at 30 in v1).
    #[serde(default = "default_clock_sync_interval")]
    pub clock_sync_interval_seconds: u32,
    /// Timestamp age after which clock sync is considered stale (fixed at 90 in v1).
    #[serde(default = "default_clock_sync_stale")]
    pub clock_sync_stale_after_seconds: u32,
    /// Whether to enable reversible distribution-wide virtual switch quarantine.
    #[serde(default = "default_false")]
    pub ambiguous_vm_containment_enabled: bool,
}

fn default_false() -> bool {
    false
}

fn default_true() -> bool {
    true
}

fn default_min_evidence() -> u8 {
    3
}

fn default_suspend_ttl() -> u32 {
    3600
}

fn default_allowlist_manifest() -> PathBuf {
    PathBuf::from("policy/allowlist.json")
}

fn default_model_bundle_dir() -> PathBuf {
    PathBuf::from("models/active")
}

fn default_correlation_window_ms() -> u32 {
    250
}

fn default_max_clock_uncertainty_ms() -> u32 {
    50
}

fn default_clock_sync_interval() -> u32 {
    30
}

fn default_clock_sync_stale() -> u32 {
    90
}

impl Default for ContainmentConfig {
    fn default() -> Self {
        Self {
            hard_kill_enabled: default_false(),
            minimum_corroborating_evidence: default_min_evidence(),
            suspend_action_ttl_seconds: default_suspend_ttl(),
        }
    }
}

impl Default for AllowlistConfig {
    fn default() -> Self {
        Self {
            manifest_path: default_allowlist_manifest(),
            required_policy_generation: 0,
        }
    }
}

impl Default for ModelConfig {
    fn default() -> Self {
        Self {
            bundle_directory: default_model_bundle_dir(),
            minimum_rollback_generation: 0,
            minimum_keyring_generation: 0,
            allow_last_known_good: default_true(),
        }
    }
}

impl Default for WslConfig {
    fn default() -> Self {
        Self {
            correlation_window_ms: default_correlation_window_ms(),
            maximum_clock_uncertainty_ms: default_max_clock_uncertainty_ms(),
            clock_sync_interval_seconds: default_clock_sync_interval(),
            clock_sync_stale_after_seconds: default_clock_sync_stale(),
            ambiguous_vm_containment_enabled: default_false(),
        }
    }
}

impl KavachConfig {
    /// Returns the compiled-in safe defaults per config-schema.md and ADR 002/006.
    pub fn safe_defaults() -> Self {
        Self {
            artifact_version: ArtifactVersion { major: 1, minor: 0 },
            containment: ContainmentConfig::default(),
            allowlist: AllowlistConfig::default(),
            model: ModelConfig::default(),
            wsl: WslConfig::default(),
        }
    }

    /// Deserializes and validates configuration from a TOML string.
    pub fn from_toml_str(toml_str: &str) -> Result<Self, ConfigError> {
        let config: KavachConfig =
            toml::from_str(toml_str).map_err(|e| ConfigError::ParseError(e.to_string()))?;
        config.validate()?;
        Ok(config)
    }

    /// Validates all fields against the normative bounds in config-schema.md.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.artifact_version.major != 1 {
            return Err(ConfigError::UnsupportedMajorVersion(
                self.artifact_version.major,
            ));
        }

        if self.containment.minimum_corroborating_evidence == 0 {
            return Err(ConfigError::InvalidBounds(
                "minimum_corroborating_evidence must be between 1 and 255".into(),
            ));
        }

        if !(60..=86400).contains(&self.containment.suspend_action_ttl_seconds) {
            return Err(ConfigError::InvalidBounds(format!(
                "suspend_action_ttl_seconds ({}) must be between 60 and 86400",
                self.containment.suspend_action_ttl_seconds
            )));
        }

        if !(10..=250).contains(&self.wsl.correlation_window_ms) {
            return Err(ConfigError::InvalidBounds(format!(
                "correlation_window_ms ({}) must be between 10 and 250 in v1",
                self.wsl.correlation_window_ms
            )));
        }

        if !(1..=50).contains(&self.wsl.maximum_clock_uncertainty_ms) {
            return Err(ConfigError::InvalidBounds(format!(
                "maximum_clock_uncertainty_ms ({}) must be between 1 and 50",
                self.wsl.maximum_clock_uncertainty_ms
            )));
        }

        if self.wsl.clock_sync_interval_seconds != 30 {
            return Err(ConfigError::InvalidBounds(format!(
                "clock_sync_interval_seconds ({}) is fixed at 30 in v1",
                self.wsl.clock_sync_interval_seconds
            )));
        }

        if self.wsl.clock_sync_stale_after_seconds != 90 {
            return Err(ConfigError::InvalidBounds(format!(
                "clock_sync_stale_after_seconds ({}) is fixed at 90 in v1",
                self.wsl.clock_sync_stale_after_seconds
            )));
        }

        Ok(())
    }

    /// Loads configuration from file path, falling back to compiled-in safe defaults on any failure.
    pub fn load_or_safe_defaults(path: &Path) -> (Self, Option<ConfigError>) {
        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(e) => {
                return (
                    Self::safe_defaults(),
                    Some(ConfigError::IoError(e.to_string())),
                );
            }
        };

        match Self::from_toml_str(&content) {
            Ok(cfg) => (cfg, None),
            Err(err) => (Self::safe_defaults(), Some(err)),
        }
    }
}

/// Errors that can occur during configuration loading and bounds validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigError {
    /// File could not be read from disk.
    IoError(String),
    /// Syntax error parsing TOML content.
    ParseError(String),
    /// Major artifact version is not supported.
    UnsupportedMajorVersion(u16),
    /// A configuration value was outside its specified boundary.
    InvalidBounds(String),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IoError(msg) => write!(f, "configuration I/O error: {msg}"),
            Self::ParseError(msg) => write!(f, "configuration syntax error: {msg}"),
            Self::UnsupportedMajorVersion(v) => {
                write!(f, "unsupported configuration major version: {v}")
            }
            Self::InvalidBounds(msg) => write!(f, "configuration bounds violation: {msg}"),
        }
    }
}

impl std::error::Error for ConfigError {}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_VALID_TOML: &str = r#"
artifact_version = { major = 1, minor = 0 }

[containment]
hard_kill_enabled = false
minimum_corroborating_evidence = 3
suspend_action_ttl_seconds = 3600

[allowlist]
manifest_path = "policy/allowlist.json"
required_policy_generation = 7

[model]
bundle_directory = "models/active"
minimum_rollback_generation = 42
minimum_keyring_generation = 9
allow_last_known_good = true

[wsl]
correlation_window_ms = 250
maximum_clock_uncertainty_ms = 50
clock_sync_interval_seconds = 30
clock_sync_stale_after_seconds = 90
ambiguous_vm_containment_enabled = false
"#;

    #[test]
    fn test_valid_config_parsing() {
        let cfg = KavachConfig::from_toml_str(SAMPLE_VALID_TOML).expect("valid config parses");
        assert_eq!(cfg.artifact_version.major, 1);
        assert_eq!(cfg.containment.minimum_corroborating_evidence, 3);
        assert_eq!(cfg.containment.suspend_action_ttl_seconds, 3600);
        assert_eq!(cfg.allowlist.required_policy_generation, 7);
        assert_eq!(cfg.model.minimum_rollback_generation, 42);
        assert_eq!(cfg.wsl.correlation_window_ms, 250);
        assert_eq!(cfg.wsl.maximum_clock_uncertainty_ms, 50);
    }

    #[test]
    fn test_minimal_config_uses_defaults() {
        let toml = "artifact_version = { major = 1, minor = 0 }\n";
        let cfg = KavachConfig::from_toml_str(toml).expect("minimal config parses");
        assert_eq!(cfg, KavachConfig::safe_defaults());
    }

    #[test]
    fn test_unsupported_major_version() {
        let toml = "artifact_version = { major = 2, minor = 0 }\n";
        let err = KavachConfig::from_toml_str(toml).unwrap_err();
        assert_eq!(err, ConfigError::UnsupportedMajorVersion(2));
    }

    #[test]
    fn test_invalid_suspend_ttl_bounds() {
        let toml = r#"
artifact_version = { major = 1, minor = 0 }
[containment]
suspend_action_ttl_seconds = 59
"#;
        let err = KavachConfig::from_toml_str(toml).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidBounds(_)));
    }

    #[test]
    fn test_invalid_wsl_correlation_window() {
        let toml = r#"
artifact_version = { major = 1, minor = 0 }
[wsl]
correlation_window_ms = 300
"#;
        let err = KavachConfig::from_toml_str(toml).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidBounds(_)));
    }

    #[test]
    fn test_invalid_clock_sync_interval() {
        let toml = r#"
artifact_version = { major = 1, minor = 0 }
[wsl]
clock_sync_interval_seconds = 60
"#;
        let err = KavachConfig::from_toml_str(toml).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidBounds(_)));
    }
}
