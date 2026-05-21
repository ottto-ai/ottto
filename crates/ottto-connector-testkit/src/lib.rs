//! Test helpers for source and collector package manifests.

use std::collections::{BTreeSet, HashSet};
use std::fmt;

use ottto_connector_sdk::{
    is_forbidden_sample_key, is_forbidden_v1_field, validate_emit_name, validate_manifest_id,
    DataSourceKind, DefaultState, Maturity, Operation, ReviewTier, RiskClass,
    REQUIRED_REDACTION_CLASSES,
};

#[derive(Debug, Clone, Copy)]
pub struct SourceManifestContract<'a> {
    pub source_id: &'a str,
    pub app_slug: &'a str,
    pub display_name: &'a str,
    pub publisher: &'a str,
    pub review_tier: &'a str,
    pub maturity: &'a str,
    pub operations: &'a [&'a str],
    pub collectors: &'a [&'a str],
    pub fields: &'a [&'a str],
}

#[derive(Debug, Clone, Copy)]
pub struct CollectorManifestContract<'a> {
    pub source_id: &'a str,
    pub collector_id: &'a str,
    pub display_name: &'a str,
    pub operations: &'a [&'a str],
    pub data_source_kind: &'a str,
    pub default_state: &'a str,
    pub review_tier: &'a str,
    pub maturity: &'a str,
    pub risk_classes: &'a [&'a str],
    pub uploads_raw_content: bool,
    pub emits: &'a [&'a str],
    pub fields: &'a [&'a str],
}

#[derive(Debug, Clone, Copy)]
pub struct CollectorFixtureContract<'a> {
    pub source_id: &'a str,
    pub collector_id: &'a str,
    pub upload_policy: FixtureUploadPolicyContract<'a>,
    pub emitted_records: &'a [EmittedRecordContract<'a>],
}

#[derive(Debug, Clone, Copy)]
pub struct FixtureUploadPolicyContract<'a> {
    pub uploads_raw_content: bool,
    pub redacts: &'a [&'a str],
}

#[derive(Debug, Clone, Copy)]
pub struct EmittedRecordContract<'a> {
    pub record_type: &'a str,
    pub sample_key_paths: &'a [&'a str],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectorTestkitError {
    DuplicateId {
        kind: String,
        id: String,
    },
    ForbiddenField {
        field: String,
    },
    InvalidEmitName {
        field: String,
        value: String,
    },
    InvalidManifestId {
        field: String,
        value: String,
    },
    EmptyField {
        field: String,
    },
    EmptyValues {
        field: String,
    },
    UnsupportedValue {
        field: String,
        value: String,
    },
    RawContentUploadAllowed {
        collector_id: String,
    },
    RiskyDefaultEnabled {
        collector_id: String,
        reason: String,
    },
    UploadPolicyMismatch {
        expected: bool,
        actual: bool,
    },
    MissingRequiredRedactionClass {
        class: String,
    },
    RecordTypeMismatch {
        expected: Vec<String>,
        actual: Vec<String>,
    },
    RawContentKey {
        path: String,
    },
    SourceMismatch {
        expected: String,
        actual: String,
    },
    CollectorMismatch {
        expected: String,
        actual: String,
    },
}

impl fmt::Display for ConnectorTestkitError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateId { kind, id } => write!(formatter, "duplicate {} id '{}'", kind, id),
            Self::ForbiddenField { field } => {
                write!(
                    formatter,
                    "field '{}' is forbidden in connector manifest v1",
                    field
                )
            }
            Self::InvalidEmitName { field, value } => {
                write!(formatter, "invalid {} emit name '{}'", field, value)
            }
            Self::InvalidManifestId { field, value } => {
                write!(formatter, "invalid {} manifest id '{}'", field, value)
            }
            Self::EmptyField { field } => write!(formatter, "{} must not be empty", field),
            Self::EmptyValues { field } => write!(formatter, "{} must not be empty", field),
            Self::UnsupportedValue { field, value } => {
                write!(formatter, "unsupported {} value '{}'", field, value)
            }
            Self::RawContentUploadAllowed { collector_id } => write!(
                formatter,
                "collector '{}' must not upload raw content in the safe v1 testkit",
                collector_id
            ),
            Self::RiskyDefaultEnabled {
                collector_id,
                reason,
            } => write!(
                formatter,
                "collector '{}' must not default-enable risky collection: {}",
                collector_id, reason
            ),
            Self::UploadPolicyMismatch { expected, actual } => write!(
                formatter,
                "fixture upload policy mismatch: expected uploads_raw_content={}, got {}",
                expected, actual
            ),
            Self::MissingRequiredRedactionClass { class } => {
                write!(
                    formatter,
                    "fixture upload policy is missing redaction class '{}'",
                    class
                )
            }
            Self::RecordTypeMismatch { expected, actual } => write!(
                formatter,
                "fixture emitted record types mismatch: expected {:?}, got {:?}",
                expected, actual
            ),
            Self::RawContentKey { path } => {
                write!(
                    formatter,
                    "fixture sample exposes raw content key '{}'",
                    path
                )
            }
            Self::SourceMismatch { expected, actual } => {
                write!(
                    formatter,
                    "source mismatch: expected '{}', got '{}'",
                    expected, actual
                )
            }
            Self::CollectorMismatch { expected, actual } => write!(
                formatter,
                "collector mismatch: expected '{}', got '{}'",
                expected, actual
            ),
        }
    }
}

impl std::error::Error for ConnectorTestkitError {}

pub fn assert_unique_ids<I, S>(kind: &str, ids: I) -> Result<(), ConnectorTestkitError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut seen = HashSet::new();
    for id in ids {
        let id = id.as_ref();
        if !seen.insert(id.to_string()) {
            return Err(ConnectorTestkitError::DuplicateId {
                kind: kind.to_string(),
                id: id.to_string(),
            });
        }
    }
    Ok(())
}

pub fn assert_no_forbidden_v1_fields<I, S>(fields: I) -> Result<(), ConnectorTestkitError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    for field in fields {
        let field = field.as_ref();
        if is_forbidden_v1_field(field) {
            return Err(ConnectorTestkitError::ForbiddenField {
                field: field.to_string(),
            });
        }
    }
    Ok(())
}

pub fn assert_source_manifest_contract(
    manifest: &SourceManifestContract<'_>,
) -> Result<(), ConnectorTestkitError> {
    assert_no_forbidden_v1_fields(manifest.fields.iter().copied())?;
    validate_manifest_id("source_id", manifest.source_id).map_err(|_| {
        ConnectorTestkitError::InvalidManifestId {
            field: "source_id".to_string(),
            value: manifest.source_id.to_string(),
        }
    })?;
    validate_manifest_id("app_slug", manifest.app_slug).map_err(|_| {
        ConnectorTestkitError::InvalidManifestId {
            field: "app_slug".to_string(),
            value: manifest.app_slug.to_string(),
        }
    })?;
    require_non_empty("display_name", manifest.display_name)?;
    require_non_empty("publisher", manifest.publisher)?;
    parse_review_tier(manifest.review_tier)?;
    parse_maturity(manifest.maturity)?;
    assert_operation_values(manifest.operations)?;
    assert_unique_ids("collector", manifest.collectors.iter().copied())?;
    for collector_id in manifest.collectors {
        validate_manifest_id("collectors", collector_id).map_err(|_| {
            ConnectorTestkitError::InvalidManifestId {
                field: "collectors".to_string(),
                value: (*collector_id).to_string(),
            }
        })?;
    }
    Ok(())
}

pub fn assert_collector_manifest_contract(
    manifest: &CollectorManifestContract<'_>,
) -> Result<(), ConnectorTestkitError> {
    assert_no_forbidden_v1_fields(manifest.fields.iter().copied())?;
    validate_manifest_id("source_id", manifest.source_id).map_err(|_| {
        ConnectorTestkitError::InvalidManifestId {
            field: "source_id".to_string(),
            value: manifest.source_id.to_string(),
        }
    })?;
    validate_manifest_id("collector_id", manifest.collector_id).map_err(|_| {
        ConnectorTestkitError::InvalidManifestId {
            field: "collector_id".to_string(),
            value: manifest.collector_id.to_string(),
        }
    })?;
    require_non_empty("display_name", manifest.display_name)?;
    assert_operation_values(manifest.operations)?;
    let data_source_kind = parse_data_source_kind(manifest.data_source_kind)?;
    let default_state = parse_default_state(manifest.default_state)?;
    parse_review_tier(manifest.review_tier)?;
    let maturity = parse_maturity(manifest.maturity)?;
    let risk_classes = assert_risk_class_values(manifest.risk_classes)?;
    if manifest.uploads_raw_content {
        return Err(ConnectorTestkitError::RawContentUploadAllowed {
            collector_id: manifest.collector_id.to_string(),
        });
    }
    assert_default_risk_policy(
        manifest,
        data_source_kind,
        default_state,
        maturity,
        &risk_classes,
    )?;
    assert_unique_ids("emit", manifest.emits.iter().copied())?;
    for emit in manifest.emits {
        validate_emit_name("emits", emit).map_err(|_| ConnectorTestkitError::InvalidEmitName {
            field: "emits".to_string(),
            value: (*emit).to_string(),
        })?;
    }
    Ok(())
}

pub fn assert_collector_fixture_contract(
    manifest: &CollectorManifestContract<'_>,
    fixture: &CollectorFixtureContract<'_>,
) -> Result<(), ConnectorTestkitError> {
    if fixture.source_id != manifest.source_id {
        return Err(ConnectorTestkitError::SourceMismatch {
            expected: manifest.source_id.to_string(),
            actual: fixture.source_id.to_string(),
        });
    }
    if fixture.collector_id != manifest.collector_id {
        return Err(ConnectorTestkitError::CollectorMismatch {
            expected: manifest.collector_id.to_string(),
            actual: fixture.collector_id.to_string(),
        });
    }
    if fixture.upload_policy.uploads_raw_content != manifest.uploads_raw_content {
        return Err(ConnectorTestkitError::UploadPolicyMismatch {
            expected: manifest.uploads_raw_content,
            actual: fixture.upload_policy.uploads_raw_content,
        });
    }
    if fixture.upload_policy.uploads_raw_content {
        return Err(ConnectorTestkitError::RawContentUploadAllowed {
            collector_id: fixture.collector_id.to_string(),
        });
    }
    assert_required_redactions(fixture.upload_policy.redacts)?;
    assert_unique_ids(
        "record_type",
        fixture
            .emitted_records
            .iter()
            .map(|record| record.record_type),
    )?;
    let expected = sorted_strings(manifest.emits);
    let actual = sorted_strings(
        &fixture
            .emitted_records
            .iter()
            .map(|record| record.record_type)
            .collect::<Vec<_>>(),
    );
    if expected != actual {
        return Err(ConnectorTestkitError::RecordTypeMismatch { expected, actual });
    }
    for record in fixture.emitted_records {
        for path in record.sample_key_paths {
            assert_sample_key_path_safe(path)?;
        }
    }
    Ok(())
}

pub fn assert_sample_key_path_safe(path: &str) -> Result<(), ConnectorTestkitError> {
    let exposes_raw_key = path
        .split(|char| matches!(char, '.' | '[' | ']'))
        .filter(|part| !part.is_empty())
        .any(is_forbidden_sample_key);
    if exposes_raw_key {
        Err(ConnectorTestkitError::RawContentKey {
            path: path.to_string(),
        })
    } else {
        Ok(())
    }
}

fn require_non_empty(field: &str, value: &str) -> Result<(), ConnectorTestkitError> {
    if value.trim().is_empty() {
        Err(ConnectorTestkitError::EmptyField {
            field: field.to_string(),
        })
    } else {
        Ok(())
    }
}

fn assert_operation_values(values: &[&str]) -> Result<(), ConnectorTestkitError> {
    if values.is_empty() {
        return Err(ConnectorTestkitError::EmptyValues {
            field: "operations".to_string(),
        });
    }
    assert_unique_ids("operation", values.iter().copied())?;
    for value in values {
        Operation::parse(value).map_err(|_| ConnectorTestkitError::UnsupportedValue {
            field: "operations".to_string(),
            value: (*value).to_string(),
        })?;
    }
    Ok(())
}

fn assert_risk_class_values(values: &[&str]) -> Result<Vec<RiskClass>, ConnectorTestkitError> {
    assert_unique_ids("risk_class", values.iter().copied())?;
    values
        .iter()
        .map(|value| {
            RiskClass::parse(value).map_err(|_| ConnectorTestkitError::UnsupportedValue {
                field: "risk_classes".to_string(),
                value: (*value).to_string(),
            })
        })
        .collect()
}

fn assert_default_risk_policy(
    manifest: &CollectorManifestContract<'_>,
    data_source_kind: DataSourceKind,
    default_state: DefaultState,
    maturity: Maturity,
    risk_classes: &[RiskClass],
) -> Result<(), ConnectorTestkitError> {
    if default_state != DefaultState::Enabled {
        return Ok(());
    }

    let mut reasons = Vec::new();
    if manifest.uploads_raw_content || risk_classes.contains(&RiskClass::RawPromptOrOutput) {
        reasons.push("raw prompt/output upload");
    }
    if risk_classes.contains(&RiskClass::HiddenCredentialRead) {
        reasons.push("hidden credential reads");
    }
    if risk_classes.contains(&RiskClass::NetworkCalls) {
        reasons.push("network calls");
    }
    if data_source_kind == DataSourceKind::LiveTelemetry {
        reasons.push("live telemetry");
    }
    if maturity == Maturity::WritesConfig {
        reasons.push("config writes");
    }
    if maturity == Maturity::UndocumentedSurface {
        if risk_classes.contains(&RiskClass::AuthAdjacent) {
            reasons.push("auth-adjacent undocumented surfaces");
        }
        if risk_classes.contains(&RiskClass::NetworkCalls) {
            reasons.push("network calls to undocumented surfaces");
        }
    }

    if reasons.is_empty() {
        Ok(())
    } else {
        Err(ConnectorTestkitError::RiskyDefaultEnabled {
            collector_id: manifest.collector_id.to_string(),
            reason: reasons.join(", "),
        })
    }
}

fn parse_review_tier(value: &str) -> Result<ReviewTier, ConnectorTestkitError> {
    ReviewTier::parse(value).map_err(|_| ConnectorTestkitError::UnsupportedValue {
        field: "review_tier".to_string(),
        value: value.to_string(),
    })
}

fn parse_maturity(value: &str) -> Result<Maturity, ConnectorTestkitError> {
    Maturity::parse(value).map_err(|_| ConnectorTestkitError::UnsupportedValue {
        field: "maturity".to_string(),
        value: value.to_string(),
    })
}

fn parse_data_source_kind(value: &str) -> Result<DataSourceKind, ConnectorTestkitError> {
    DataSourceKind::parse(value).map_err(|_| ConnectorTestkitError::UnsupportedValue {
        field: "data_source_kind".to_string(),
        value: value.to_string(),
    })
}

fn parse_default_state(value: &str) -> Result<DefaultState, ConnectorTestkitError> {
    DefaultState::parse(value).map_err(|_| ConnectorTestkitError::UnsupportedValue {
        field: "default_state".to_string(),
        value: value.to_string(),
    })
}

fn assert_required_redactions(values: &[&str]) -> Result<(), ConnectorTestkitError> {
    let present: HashSet<String> = values
        .iter()
        .map(|value| value.to_ascii_lowercase())
        .collect();
    for class in REQUIRED_REDACTION_CLASSES {
        if !present.contains(*class) {
            return Err(ConnectorTestkitError::MissingRequiredRedactionClass {
                class: (*class).to_string(),
            });
        }
    }
    Ok(())
}

fn sorted_strings(values: &[&str]) -> Vec<String> {
    values
        .iter()
        .map(|value| (*value).to_string())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SOURCE_FIELDS: &[&str] = &[
        "schema_version",
        "source_id",
        "app_slug",
        "display_name",
        "publisher",
        "review_tier",
        "maturity",
        "operations",
        "collectors",
    ];

    const COLLECTOR_FIELDS: &[&str] = &[
        "schema_version",
        "source_id",
        "collector_id",
        "display_name",
        "operations",
        "data_source_kind",
        "default_state",
        "review_tier",
        "maturity",
        "risk_classes",
        "uploads_raw_content",
        "emits",
    ];

    fn source_contract() -> SourceManifestContract<'static> {
        SourceManifestContract {
            source_id: "codex",
            app_slug: "codex",
            display_name: "Codex",
            publisher: "ottto",
            review_tier: "official",
            maturity: "stable",
            operations: &["detect", "verify", "collect_usage"],
            collectors: &["local_sessions"],
            fields: SOURCE_FIELDS,
        }
    }

    fn collector_contract() -> CollectorManifestContract<'static> {
        CollectorManifestContract {
            source_id: "codex",
            collector_id: "local_sessions",
            display_name: "Local sessions",
            operations: &["collect_usage", "upload_snapshot", "diagnostics"],
            data_source_kind: "local_enriched",
            default_state: "enabled",
            review_tier: "official",
            maturity: "stable",
            risk_classes: &[],
            uploads_raw_content: false,
            emits: &["local_usage_snapshots", "local_usage_collector_statuses"],
            fields: COLLECTOR_FIELDS,
        }
    }

    #[test]
    fn duplicate_ids_fail_fast() {
        let error = assert_unique_ids("collector", ["local_sessions", "local_sessions"])
            .expect_err("duplicate id should fail");

        assert_eq!(
            error,
            ConnectorTestkitError::DuplicateId {
                kind: "collector".to_string(),
                id: "local_sessions".to_string()
            }
        );
    }

    #[test]
    fn forbidden_supported_platforms_fails_fast() {
        let error = assert_no_forbidden_v1_fields(["source_id", "supported_platforms"])
            .expect_err("supported_platforms should stay out of v1");

        assert_eq!(
            error,
            ConnectorTestkitError::ForbiddenField {
                field: "supported_platforms".to_string()
            }
        );
    }

    #[test]
    fn source_manifest_contract_accepts_safe_manifest() {
        assert!(assert_source_manifest_contract(&source_contract()).is_ok());
    }

    #[test]
    fn source_manifest_contract_rejects_bad_ids_and_values() {
        let mut contract = source_contract();
        contract.source_id = "Codex";
        let error = assert_source_manifest_contract(&contract).unwrap_err();
        assert!(matches!(
            error,
            ConnectorTestkitError::InvalidManifestId { .. }
        ));

        let mut contract = source_contract();
        contract.operations = &["detect", "detect"];
        let error = assert_source_manifest_contract(&contract).unwrap_err();
        assert!(matches!(error, ConnectorTestkitError::DuplicateId { .. }));
    }

    #[test]
    fn collector_manifest_contract_accepts_safe_manifest() {
        assert!(assert_collector_manifest_contract(&collector_contract()).is_ok());
    }

    #[test]
    fn collector_manifest_contract_rejects_raw_uploads_and_bad_emits() {
        let mut contract = collector_contract();
        contract.uploads_raw_content = true;
        let error = assert_collector_manifest_contract(&contract).unwrap_err();
        assert!(matches!(
            error,
            ConnectorTestkitError::RawContentUploadAllowed { .. }
        ));

        let mut contract = collector_contract();
        contract.emits = &["local-usage"];
        let error = assert_collector_manifest_contract(&contract).unwrap_err();
        assert!(matches!(
            error,
            ConnectorTestkitError::InvalidEmitName { .. }
        ));
    }

    #[test]
    fn collector_manifest_contract_rejects_default_enabled_risky_collectors() {
        let mut contract = collector_contract();
        contract.risk_classes = &["hidden_credential_read"];
        let error = assert_collector_manifest_contract(&contract).unwrap_err();
        assert!(matches!(
            error,
            ConnectorTestkitError::RiskyDefaultEnabled { .. }
        ));

        let mut contract = collector_contract();
        contract.maturity = "undocumented_surface";
        contract.risk_classes = &["auth_adjacent"];
        let error = assert_collector_manifest_contract(&contract).unwrap_err();
        assert!(matches!(
            error,
            ConnectorTestkitError::RiskyDefaultEnabled { .. }
        ));

        let mut contract = collector_contract();
        contract.risk_classes = &["network_calls"];
        contract.default_state = "requires_setup";
        assert!(assert_collector_manifest_contract(&contract).is_ok());
    }

    #[test]
    fn collector_fixture_contract_checks_records_redaction_and_raw_keys() {
        let manifest = collector_contract();
        let fixture = CollectorFixtureContract {
            source_id: "codex",
            collector_id: "local_sessions",
            upload_policy: FixtureUploadPolicyContract {
                uploads_raw_content: false,
                redacts: &[
                    "prompt",
                    "response",
                    "tool_output",
                    "command_output",
                    "local_path",
                    "credential",
                ],
            },
            emitted_records: &[
                EmittedRecordContract {
                    record_type: "local_usage_snapshots",
                    sample_key_paths: &["usage.input_tokens", "usage.output_tokens"],
                },
                EmittedRecordContract {
                    record_type: "local_usage_collector_statuses",
                    sample_key_paths: &["collector.status", "collector.parser_version"],
                },
            ],
        };

        assert!(assert_collector_fixture_contract(&manifest, &fixture).is_ok());

        let fixture = CollectorFixtureContract {
            emitted_records: &[EmittedRecordContract {
                record_type: "local_usage_snapshots",
                sample_key_paths: &["payload.raw_prompt"],
            }],
            ..fixture
        };
        let error = assert_collector_fixture_contract(&manifest, &fixture).unwrap_err();
        assert!(matches!(
            error,
            ConnectorTestkitError::RecordTypeMismatch { .. }
        ));

        let fixture = CollectorFixtureContract {
            emitted_records: &[
                EmittedRecordContract {
                    record_type: "local_usage_snapshots",
                    sample_key_paths: &["payload.raw_prompt.text"],
                },
                EmittedRecordContract {
                    record_type: "local_usage_collector_statuses",
                    sample_key_paths: &["collector.status"],
                },
            ],
            ..fixture
        };
        let error = assert_collector_fixture_contract(&manifest, &fixture).unwrap_err();
        assert!(matches!(error, ConnectorTestkitError::RawContentKey { .. }));

        assert!(assert_sample_key_path_safe("payload.token_count").is_ok());
        assert!(matches!(
            assert_sample_key_path_safe("payload.raw_prompt.text"),
            Err(ConnectorTestkitError::RawContentKey { .. })
        ));
    }
}
