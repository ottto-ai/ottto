use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use ottto_connector_sdk::{COLLECTOR_MANIFEST_SCHEMA_VERSION, SOURCE_MANIFEST_SCHEMA_VERSION};
use ottto_connector_testkit::{
    assert_collector_fixture_contract, assert_collector_manifest_contract,
    assert_source_manifest_contract, CollectorFixtureContract, CollectorManifestContract,
    EmittedRecordContract, FixtureUploadPolicyContract, SourceManifestContract,
};
use serde::Deserialize;
use serde_json::Value;

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

const REQUIRED_GOVERNANCE_PHRASES: &[&str] = &[
    "documented surfaces",
    "undocumented surfaces",
    "local-only behavior",
    "upload boundaries",
];

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceManifestFile {
    schema_version: String,
    source_id: String,
    app_slug: String,
    display_name: String,
    publisher: String,
    review_tier: String,
    maturity: String,
    operations: Vec<String>,
    collectors: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CollectorManifestFile {
    schema_version: String,
    source_id: String,
    collector_id: String,
    display_name: String,
    operations: Vec<String>,
    data_source_kind: String,
    default_state: String,
    review_tier: String,
    maturity: String,
    risk_classes: Vec<String>,
    uploads_raw_content: bool,
    emits: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CollectorFixtureFile {
    schema_version: String,
    source_id: String,
    collector_id: String,
    input_fixture_paths: Vec<String>,
    emitted_records: Vec<CollectorFixtureRecordFile>,
    upload_policy: CollectorFixtureUploadPolicyFile,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CollectorFixtureRecordFile {
    record_type: String,
    sample: Value,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CollectorFixtureUploadPolicyFile {
    uploads_raw_content: bool,
    boundary: String,
    redacts: Vec<String>,
}

#[test]
fn first_party_source_packages_satisfy_public_testkit_contracts() {
    let sources = load_first_party_sources();
    let source_ids = sources
        .iter()
        .map(|source| source.manifest.source_id.as_str())
        .collect::<BTreeSet<_>>();
    assert_eq!(source_ids, BTreeSet::from(["claude_code", "codex", "pi"]));

    for source in &sources {
        assert_source_package_contract(source);
    }
}

fn assert_source_package_contract(source: &LoadedSource) {
    assert_eq!(
        source.manifest.schema_version,
        SOURCE_MANIFEST_SCHEMA_VERSION,
        "{}",
        source.manifest_path.display()
    );

    let operations = as_strs(&source.manifest.operations);
    let collectors = as_strs(&source.manifest.collectors);
    let source_contract = SourceManifestContract {
        source_id: &source.manifest.source_id,
        app_slug: &source.manifest.app_slug,
        display_name: &source.manifest.display_name,
        publisher: &source.manifest.publisher,
        review_tier: &source.manifest.review_tier,
        maturity: &source.manifest.maturity,
        operations: &operations,
        collectors: &collectors,
        fields: SOURCE_FIELDS,
    };
    assert_source_manifest_contract(&source_contract).unwrap_or_else(|error| {
        panic!(
            "{} violates source contract: {}",
            source.manifest_path.display(),
            error
        )
    });

    assert_source_docs_cover_collectors(source);

    let actual_collectors = source
        .collectors
        .iter()
        .map(|collector| collector.manifest.collector_id.as_str())
        .collect::<BTreeSet<_>>();
    let declared_collectors = source
        .manifest
        .collectors
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    assert_eq!(
        actual_collectors, declared_collectors,
        "{} collectors do not match manifests on disk",
        source.manifest.source_id
    );

    for collector in &source.collectors {
        assert_collector_package_contract(source, collector);
    }
}

fn assert_collector_package_contract(source: &LoadedSource, collector: &LoadedCollector) {
    assert_eq!(
        collector.manifest.schema_version,
        COLLECTOR_MANIFEST_SCHEMA_VERSION,
        "{}",
        collector.manifest_path.display()
    );
    assert_eq!(collector.manifest.source_id, source.manifest.source_id);
    assert_safe_default_posture(collector);

    let operations = as_strs(&collector.manifest.operations);
    let risk_classes = as_strs(&collector.manifest.risk_classes);
    let emits = as_strs(&collector.manifest.emits);
    let collector_contract = CollectorManifestContract {
        source_id: &collector.manifest.source_id,
        collector_id: &collector.manifest.collector_id,
        display_name: &collector.manifest.display_name,
        operations: &operations,
        data_source_kind: &collector.manifest.data_source_kind,
        default_state: &collector.manifest.default_state,
        review_tier: &collector.manifest.review_tier,
        maturity: &collector.manifest.maturity,
        risk_classes: &risk_classes,
        uploads_raw_content: collector.manifest.uploads_raw_content,
        emits: &emits,
        fields: COLLECTOR_FIELDS,
    };
    assert_collector_manifest_contract(&collector_contract).unwrap_or_else(|error| {
        panic!(
            "{} violates collector contract: {}",
            collector.manifest_path.display(),
            error
        )
    });

    assert!(
        !collector.fixtures.is_empty(),
        "{} has no collector fixtures",
        collector.manifest_path.display()
    );
    for fixture in &collector.fixtures {
        assert_collector_fixture(source, collector, &collector_contract, fixture);
    }
}

fn assert_collector_fixture(
    source: &LoadedSource,
    collector: &LoadedCollector,
    collector_contract: &CollectorManifestContract<'_>,
    fixture: &LoadedFixture,
) {
    assert_eq!(fixture.payload.schema_version, "collector_fixture.v1");
    assert_eq!(fixture.payload.source_id, source.manifest.source_id);
    assert_eq!(
        fixture.payload.collector_id,
        collector.manifest.collector_id
    );
    assert!(
        !fixture.payload.upload_policy.boundary.trim().is_empty(),
        "{} upload boundary is empty",
        fixture.path.display()
    );

    for input_path in &fixture.payload.input_fixture_paths {
        let unresolved = fixture.path.parent().unwrap().join(input_path);
        let resolved = fs::canonicalize(&unresolved)
            .unwrap_or_else(|error| panic!("{}: {}", unresolved.display(), error));
        let root = fs::canonicalize(repo_root()).expect("repository root exists");
        assert!(
            resolved.is_file(),
            "{} references missing input fixture {}",
            fixture.path.display(),
            input_path
        );
        assert!(
            resolved.starts_with(&root),
            "{} references input outside repository: {}",
            fixture.path.display(),
            input_path
        );
    }

    let redacts = as_strs(&fixture.payload.upload_policy.redacts);
    let sample_key_paths = fixture
        .payload
        .emitted_records
        .iter()
        .map(|record| sample_key_paths(&record.sample))
        .collect::<Vec<_>>();
    let sample_key_refs = sample_key_paths
        .iter()
        .map(|paths| paths.iter().map(String::as_str).collect::<Vec<_>>())
        .collect::<Vec<_>>();
    let emitted_records = fixture
        .payload
        .emitted_records
        .iter()
        .zip(sample_key_refs.iter())
        .map(|(record, paths)| EmittedRecordContract {
            record_type: &record.record_type,
            sample_key_paths: paths,
        })
        .collect::<Vec<_>>();
    let fixture_contract = CollectorFixtureContract {
        source_id: &fixture.payload.source_id,
        collector_id: &fixture.payload.collector_id,
        upload_policy: FixtureUploadPolicyContract {
            uploads_raw_content: fixture.payload.upload_policy.uploads_raw_content,
            redacts: &redacts,
        },
        emitted_records: &emitted_records,
    };
    assert_collector_fixture_contract(collector_contract, &fixture_contract).unwrap_or_else(
        |error| {
            panic!(
                "{} violates fixture contract: {}",
                fixture.path.display(),
                error
            )
        },
    );
}

fn assert_safe_default_posture(collector: &LoadedCollector) {
    assert!(
        !collector.manifest.uploads_raw_content,
        "{} must not upload raw content",
        collector.manifest_path.display()
    );
    if collector.manifest.data_source_kind == "live_telemetry"
        || collector.manifest.maturity == "writes_config"
        || collector
            .manifest
            .risk_classes
            .iter()
            .any(|risk| risk == "network_calls")
    {
        assert_eq!(
            collector.manifest.default_state,
            "requires_setup",
            "{} live/config/network collectors must require setup",
            collector.manifest_path.display()
        );
    }
    if collector
        .manifest
        .risk_classes
        .iter()
        .any(|risk| risk == "hidden_credential_read")
    {
        assert_ne!(
            collector.manifest.default_state,
            "enabled",
            "{} hidden credential reads must not default on",
            collector.manifest_path.display()
        );
    }
}

fn assert_source_docs_cover_collectors(source: &LoadedSource) {
    let readme = fs::read_to_string(&source.readme_path)
        .unwrap_or_else(|error| panic!("{}: {}", source.readme_path.display(), error));
    let governance = fs::read_to_string(&source.policy_path)
        .unwrap_or_else(|error| panic!("{}: {}", source.policy_path.display(), error));
    let readme_lower = readme.to_ascii_lowercase();
    let governance_lower = governance.to_ascii_lowercase();

    assert!(
        readme_lower.contains("collectors:"),
        "{} must list collectors",
        source.readme_path.display()
    );
    for collector_id in &source.manifest.collectors {
        assert!(
            readme_lower.contains(collector_id),
            "{} must document collector {}",
            source.readme_path.display(),
            collector_id
        );
    }
    for phrase in REQUIRED_GOVERNANCE_PHRASES {
        assert!(
            governance_lower.contains(phrase),
            "{} missing governance phrase '{}'",
            source.policy_path.display(),
            phrase
        );
    }
}

fn load_first_party_sources() -> Vec<LoadedSource> {
    read_dir_sorted(&repo_root().join("connectors/sources"))
        .into_iter()
        .filter(|path| path.join("source.toml").is_file())
        .map(|source_dir| {
            let manifest_path = source_dir.join("source.toml");
            let manifest = read_toml(&manifest_path);
            let collectors = read_dir_sorted(&source_dir.join("collectors"))
                .into_iter()
                .filter(|path| path.join("collector.toml").is_file())
                .map(|collector_dir| {
                    let manifest_path = collector_dir.join("collector.toml");
                    let manifest = read_toml(&manifest_path);
                    let fixtures = read_dir_sorted(&collector_dir.join("fixtures"))
                        .into_iter()
                        .filter(|path| {
                            path.extension()
                                .is_some_and(|extension| extension == "json")
                        })
                        .map(|path| LoadedFixture {
                            payload: read_json(&path),
                            path,
                        })
                        .collect();
                    LoadedCollector {
                        manifest,
                        manifest_path,
                        fixtures,
                    }
                })
                .collect();
            LoadedSource {
                readme_path: source_dir.join("README.md"),
                policy_path: source_dir.join("POLICY.md"),
                manifest,
                manifest_path,
                collectors,
            }
        })
        .collect()
}

fn sample_key_paths(value: &Value) -> Vec<String> {
    let mut paths = Vec::new();
    collect_sample_key_paths(value, "", &mut paths);
    paths
}

fn collect_sample_key_paths(value: &Value, prefix: &str, paths: &mut Vec<String>) {
    match value {
        Value::Object(object) => {
            for (key, child) in object {
                let path = if prefix.is_empty() {
                    key.clone()
                } else {
                    format!("{prefix}.{key}")
                };
                paths.push(path.clone());
                collect_sample_key_paths(child, &path, paths);
            }
        }
        Value::Array(items) => {
            for (index, child) in items.iter().enumerate() {
                let path = format!("{prefix}[{index}]");
                collect_sample_key_paths(child, &path, paths);
            }
        }
        _ => {}
    }
}

fn as_strs(values: &[String]) -> Vec<&str> {
    values.iter().map(String::as_str).collect()
}

fn read_toml<T>(path: &Path) -> T
where
    T: for<'de> Deserialize<'de>,
{
    let text =
        fs::read_to_string(path).unwrap_or_else(|error| panic!("{}: {}", path.display(), error));
    toml::from_str(&text).unwrap_or_else(|error| panic!("{}: {}", path.display(), error))
}

fn read_json<T>(path: &Path) -> T
where
    T: for<'de> Deserialize<'de>,
{
    let text =
        fs::read_to_string(path).unwrap_or_else(|error| panic!("{}: {}", path.display(), error));
    serde_json::from_str(&text).unwrap_or_else(|error| panic!("{}: {}", path.display(), error))
}

fn read_dir_sorted(path: &Path) -> Vec<PathBuf> {
    let mut entries = fs::read_dir(path)
        .unwrap_or_else(|error| panic!("{}: {}", path.display(), error))
        .map(|entry| {
            entry
                .unwrap_or_else(|error| panic!("{}: {}", path.display(), error))
                .path()
        })
        .collect::<Vec<_>>();
    entries.sort();
    entries
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("connector testkit lives under crates/")
        .to_path_buf()
}

struct LoadedSource {
    manifest: SourceManifestFile,
    manifest_path: PathBuf,
    readme_path: PathBuf,
    policy_path: PathBuf,
    collectors: Vec<LoadedCollector>,
}

struct LoadedCollector {
    manifest: CollectorManifestFile,
    manifest_path: PathBuf,
    fixtures: Vec<LoadedFixture>,
}

struct LoadedFixture {
    payload: CollectorFixtureFile,
    path: PathBuf,
}
