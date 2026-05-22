//! Shared constants and lightweight validation helpers for Ottto connector manifests.
//!
//! The Python generator owns TOML parsing in M1. This crate gives future Rust
//! collectors and local-platform code one place to share schema version strings,
//! vocabulary, and v1 guardrails without depending on generated registry JSON.

use std::fmt;

pub const SOURCE_MANIFEST_SCHEMA_VERSION: &str = "source_manifest.v1";
pub const COLLECTOR_MANIFEST_SCHEMA_VERSION: &str = "collector_manifest.v1";
pub const CONNECTOR_REGISTRY_SCHEMA_VERSION: &str = "connector_registry.v1";

pub const FORBIDDEN_V1_FIELDS: &[&str] = &[
    "supported_platforms",
    "routing_provider",
    "route_chain",
    "marketplace_rank",
];

pub const REQUIRED_REDACTION_CLASSES: &[&str] = &[
    "prompt",
    "response",
    "tool_output",
    "command_output",
    "local_path",
    "credential",
];

pub const FORBIDDEN_SAMPLE_KEYS: &[&str] = &[
    "api_key",
    "command_output",
    "cookie",
    "credential",
    "credentials",
    "local_path",
    "password",
    "prompt",
    "prompts",
    "raw_content",
    "raw_prompt",
    "raw_response",
    "response",
    "responses",
    "secret",
    "tool_output",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ReviewTier {
    Official,
    OtttoLabs,
    ReviewedCommunity,
    Community,
    CustomLocal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Maturity {
    Stable,
    Beta,
    Experimental,
    UndocumentedSurface,
    WritesConfig,
    LocalOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Operation {
    Detect,
    Verify,
    Repair,
    CollectUsage,
    MonitorQuota,
    UploadSnapshot,
    Diagnostics,
    UninstallRestore,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DataSourceKind {
    LocalEnriched,
    LiveTelemetry,
    IntegrationConnector,
    CloudBillingConnector,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DefaultState {
    Enabled,
    RequiresSetup,
    Disabled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RiskClass {
    AuthAdjacent,
    NetworkCalls,
    HiddenCredentialRead,
    RawPromptOrOutput,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseVocabularyError {
    field: &'static str,
    value: String,
}

impl ParseVocabularyError {
    pub fn new(field: &'static str, value: impl Into<String>) -> Self {
        Self {
            field,
            value: value.into(),
        }
    }
}

impl fmt::Display for ParseVocabularyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "unsupported connector manifest {} value '{}'",
            self.field, self.value
        )
    }
}

impl std::error::Error for ParseVocabularyError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidateConnectorValueError {
    field: &'static str,
    value: String,
    expected: &'static str,
}

impl ValidateConnectorValueError {
    pub fn new(field: &'static str, value: impl Into<String>, expected: &'static str) -> Self {
        Self {
            field,
            value: value.into(),
            expected,
        }
    }
}

impl fmt::Display for ValidateConnectorValueError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "invalid connector manifest {} value '{}': expected {}",
            self.field, self.value, self.expected
        )
    }
}

impl std::error::Error for ValidateConnectorValueError {}

impl ReviewTier {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Official => "official",
            Self::OtttoLabs => "ottto_labs",
            Self::ReviewedCommunity => "reviewed_community",
            Self::Community => "community",
            Self::CustomLocal => "custom_local",
        }
    }

    pub fn parse(value: &str) -> Result<Self, ParseVocabularyError> {
        match value {
            "official" => Ok(Self::Official),
            "ottto_labs" => Ok(Self::OtttoLabs),
            "reviewed_community" => Ok(Self::ReviewedCommunity),
            "community" => Ok(Self::Community),
            "custom_local" => Ok(Self::CustomLocal),
            _ => Err(ParseVocabularyError::new("review_tier", value)),
        }
    }
}

impl Maturity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Stable => "stable",
            Self::Beta => "beta",
            Self::Experimental => "experimental",
            Self::UndocumentedSurface => "undocumented_surface",
            Self::WritesConfig => "writes_config",
            Self::LocalOnly => "local_only",
        }
    }

    pub fn parse(value: &str) -> Result<Self, ParseVocabularyError> {
        match value {
            "stable" => Ok(Self::Stable),
            "beta" => Ok(Self::Beta),
            "experimental" => Ok(Self::Experimental),
            "undocumented_surface" => Ok(Self::UndocumentedSurface),
            "writes_config" => Ok(Self::WritesConfig),
            "local_only" => Ok(Self::LocalOnly),
            _ => Err(ParseVocabularyError::new("maturity", value)),
        }
    }
}

impl Operation {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Detect => "detect",
            Self::Verify => "verify",
            Self::Repair => "repair",
            Self::CollectUsage => "collect_usage",
            Self::MonitorQuota => "monitor_quota",
            Self::UploadSnapshot => "upload_snapshot",
            Self::Diagnostics => "diagnostics",
            Self::UninstallRestore => "uninstall_restore",
        }
    }

    pub fn parse(value: &str) -> Result<Self, ParseVocabularyError> {
        match value {
            "detect" => Ok(Self::Detect),
            "verify" => Ok(Self::Verify),
            "repair" => Ok(Self::Repair),
            "collect_usage" => Ok(Self::CollectUsage),
            "monitor_quota" => Ok(Self::MonitorQuota),
            "upload_snapshot" => Ok(Self::UploadSnapshot),
            "diagnostics" => Ok(Self::Diagnostics),
            "uninstall_restore" => Ok(Self::UninstallRestore),
            _ => Err(ParseVocabularyError::new("operations", value)),
        }
    }
}

impl DataSourceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LocalEnriched => "local_enriched",
            Self::LiveTelemetry => "live_telemetry",
            Self::IntegrationConnector => "integration_connector",
            Self::CloudBillingConnector => "cloud_billing_connector",
        }
    }

    pub fn parse(value: &str) -> Result<Self, ParseVocabularyError> {
        match value {
            "local_enriched" => Ok(Self::LocalEnriched),
            "live_telemetry" => Ok(Self::LiveTelemetry),
            "integration_connector" => Ok(Self::IntegrationConnector),
            "cloud_billing_connector" => Ok(Self::CloudBillingConnector),
            _ => Err(ParseVocabularyError::new("data_source_kind", value)),
        }
    }
}

impl DefaultState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Enabled => "enabled",
            Self::RequiresSetup => "requires_setup",
            Self::Disabled => "disabled",
        }
    }

    pub fn parse(value: &str) -> Result<Self, ParseVocabularyError> {
        match value {
            "enabled" => Ok(Self::Enabled),
            "requires_setup" => Ok(Self::RequiresSetup),
            "disabled" => Ok(Self::Disabled),
            _ => Err(ParseVocabularyError::new("default_state", value)),
        }
    }
}

impl RiskClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AuthAdjacent => "auth_adjacent",
            Self::NetworkCalls => "network_calls",
            Self::HiddenCredentialRead => "hidden_credential_read",
            Self::RawPromptOrOutput => "raw_prompt_or_output",
        }
    }

    pub fn parse(value: &str) -> Result<Self, ParseVocabularyError> {
        match value {
            "auth_adjacent" => Ok(Self::AuthAdjacent),
            "network_calls" => Ok(Self::NetworkCalls),
            "hidden_credential_read" => Ok(Self::HiddenCredentialRead),
            "raw_prompt_or_output" => Ok(Self::RawPromptOrOutput),
            _ => Err(ParseVocabularyError::new("risk_classes", value)),
        }
    }
}

pub fn is_forbidden_v1_field(field_name: &str) -> bool {
    FORBIDDEN_V1_FIELDS.contains(&field_name)
}

pub fn is_required_redaction_class(value: &str) -> bool {
    REQUIRED_REDACTION_CLASSES.contains(&value)
}

pub fn is_forbidden_sample_key(value: &str) -> bool {
    let normalized = value.to_ascii_lowercase();
    FORBIDDEN_SAMPLE_KEYS
        .iter()
        .any(|forbidden| *forbidden == normalized)
}

pub fn is_valid_manifest_id(value: &str) -> bool {
    let len = value.len();
    if !(2..=64).contains(&len) {
        return false;
    }
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    first.is_ascii_lowercase()
        && chars.all(|char| {
            char.is_ascii_lowercase() || char.is_ascii_digit() || char == '_' || char == '-'
        })
}

pub fn is_valid_emit_name(value: &str) -> bool {
    let len = value.len();
    if !(2..=97).contains(&len) {
        return false;
    }
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    first.is_ascii_lowercase()
        && chars.all(|char| char.is_ascii_lowercase() || char.is_ascii_digit() || char == '_')
}

pub fn validate_manifest_id(
    field: &'static str,
    value: &str,
) -> Result<(), ValidateConnectorValueError> {
    if is_valid_manifest_id(value) {
        Ok(())
    } else {
        Err(ValidateConnectorValueError::new(
            field,
            value,
            "^[a-z][a-z0-9_-]{1,63}$",
        ))
    }
}

pub fn validate_emit_name(
    field: &'static str,
    value: &str,
) -> Result<(), ValidateConnectorValueError> {
    if is_valid_emit_name(value) {
        Ok(())
    } else {
        Err(ValidateConnectorValueError::new(
            field,
            value,
            "^[a-z][a-z0-9_]{1,96}$",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn review_tier_round_trips_v1_values() {
        assert_eq!(ReviewTier::Official.as_str(), "official");
        assert_eq!(
            ReviewTier::parse("ottto_labs").unwrap(),
            ReviewTier::OtttoLabs
        );
        assert!(ReviewTier::parse("high_risk").is_err());
    }

    #[test]
    fn all_vocabulary_enums_parse_v1_values() {
        assert_eq!(Maturity::parse("local_only").unwrap(), Maturity::LocalOnly);
        assert_eq!(
            Operation::parse("collect_usage").unwrap(),
            Operation::CollectUsage
        );
        assert_eq!(
            DataSourceKind::parse("live_telemetry").unwrap(),
            DataSourceKind::LiveTelemetry
        );
        assert_eq!(
            DefaultState::parse("requires_setup").unwrap(),
            DefaultState::RequiresSetup
        );
        assert_eq!(
            RiskClass::parse("hidden_credential_read").unwrap(),
            RiskClass::HiddenCredentialRead
        );
        assert!(Maturity::parse("legacy").is_err());
        assert!(Operation::parse("shell_out").is_err());
        assert!(RiskClass::parse("private_state").is_err());
    }

    #[test]
    fn forbidden_fields_include_supported_platforms() {
        assert!(is_forbidden_v1_field("supported_platforms"));
        assert!(!is_forbidden_v1_field("source_id"));
    }

    #[test]
    fn manifest_ids_and_emit_names_match_schema_patterns() {
        assert!(is_valid_manifest_id("claude_code"));
        assert!(is_valid_manifest_id("claude-code"));
        assert!(!is_valid_manifest_id("Claude"));
        assert!(!is_valid_manifest_id("x"));
        assert!(validate_manifest_id("source_id", "codex").is_ok());

        assert!(is_valid_emit_name("local_usage_snapshots"));
        assert!(!is_valid_emit_name("local-usage"));
        assert!(validate_emit_name("emits", "agent_status_snapshots").is_ok());
    }

    #[test]
    fn redaction_vocabularies_cover_raw_content_boundaries() {
        assert!(is_required_redaction_class("prompt"));
        assert!(is_forbidden_sample_key("raw_prompt"));
        assert!(is_forbidden_sample_key("API_KEY"));
        assert!(!is_forbidden_sample_key("token_count"));
    }
}
