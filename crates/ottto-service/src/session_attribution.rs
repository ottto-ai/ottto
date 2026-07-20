//! Privacy-safe, evidence-first session attribution.
//!
//! This module converts provider-native metadata already read by the incremental
//! transcript scanner into a compact fact list. It never receives raw paths,
//! process arguments, or logs. Prompt/template and skill grouping use a
//! backend-issued, tenant-scoped HMAC key; provider schedule definitions are
//! read locally on a six-hour cache and reduced to opaque identifiers before
//! facts can leave this module.

use crate::snapshots::{SnapshotOrigin, SnapshotSource};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use hmac::{Hmac, Mac};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};
use toml_edit::DocumentMut;
use zeroize::Zeroizing;

pub const SESSION_ATTRIBUTION_SCHEMA_VERSION: &str = "session_attribution.v1";
pub const MAX_SESSION_ATTRIBUTION_FACTS: usize = 24;
pub const MAX_SESSION_ATTRIBUTION_FACT_VALUE_BYTES: usize = 128;
pub const MAX_SESSION_ATTRIBUTION_SOURCE_VERSION_BYTES: usize = 32;
pub const MAX_SESSION_ATTRIBUTION_EVIDENCE_REF_BYTES: usize = 96;
pub const MAX_SESSION_ATTRIBUTION_PAYLOAD_BYTES: usize = 2_048;
pub const SESSION_ATTRIBUTION_HMAC_KEY_VERSION: &str = "hmac-sha256:v1";

const MAX_TEMPLATE_MATERIAL_CHARS: usize = 4_096;
const MAX_PROVIDER_SCHEDULE_FILES: usize = 256;
const MAX_PROVIDER_SCHEDULE_FILE_BYTES: u64 = 64 * 1_024;
const MAX_PROVIDER_SCHEDULE_PROMPT_SIGNATURE_CHARS: usize = 96;
const MIN_PROVIDER_SCHEDULE_PROMPT_SIGNATURE_CHARS: usize = 24;
const PROVIDER_SCHEDULE_CACHE_TTL: Duration = Duration::from_secs(6 * 60 * 60);

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct SessionFieldEvidence {
    pub kind: String,
    pub strength: String,
    pub observed_at: String,
    pub source_version: String,
    pub evidence_ref: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct SessionAttributionFact {
    pub field: String,
    pub value: String,
    pub evidence: SessionFieldEvidence,
}

#[derive(Clone)]
struct ProviderScheduleDefinition {
    opaque_id: String,
    prompt_signature: String,
}

#[derive(Clone, Default)]
struct ProviderScheduleInventory {
    definitions: Vec<ProviderScheduleDefinition>,
}

struct CachedProviderScheduleInventory {
    loaded_at: Instant,
    home: PathBuf,
    key_fingerprint: String,
    inventory: ProviderScheduleInventory,
    files: BTreeMap<PathBuf, CachedProviderScheduleFile>,
}

#[derive(Clone)]
struct CachedProviderScheduleFile {
    size_bytes: u64,
    modified_unix_nanos: u128,
    definition: Option<ProviderScheduleDefinition>,
}

/// Per-cycle privacy context negotiated through the existing activity hint.
///
/// The raw HMAC key remains zeroized process memory. Schedule prompts are read
/// only from the provider's local configuration, normalized into short
/// in-memory signatures, and never serialized into a snapshot.
pub struct SessionAttributionContext {
    key: Zeroizing<Vec<u8>>,
    provider_schedules: ProviderScheduleInventory,
    external_schedulers: crate::external_scheduler_attribution::ExternalSchedulerInventory,
}

pub struct SessionAttributionGroupingInput<'a> {
    pub source: SnapshotSource,
    pub origin: Option<&'a SnapshotOrigin>,
    pub source_session_id: &'a str,
    pub observed_at: &'a str,
    pub source_version: &'a str,
    pub first_prompt: Option<&'a str>,
    pub provider_skills: &'a BTreeSet<String>,
    pub repository_hash: Option<&'a str>,
    pub source_started_at: Option<&'a str>,
    pub transcript_path: &'a Path,
}

impl SessionAttributionContext {
    /// Short local-only namespace for the incremental scan index. It changes
    /// when the HMAC key or either scheduler inventory changes, without putting
    /// raw key/configuration material into the index filename.
    pub fn cache_namespace(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(b"session-attribution-context:v1");
        hasher.update(self.key.as_slice());
        for definition in &self.provider_schedules.definitions {
            hasher.update([0]);
            hasher.update(definition.opaque_id.as_bytes());
            hasher.update([0]);
            hasher.update(definition.prompt_signature.as_bytes());
        }
        hasher.update([0]);
        hasher.update(self.external_schedulers.cache_fingerprint().as_bytes());
        format!("{:x}", hasher.finalize())[..16].to_string()
    }

    pub fn from_activity_hint(
        source: SnapshotSource,
        home: &Path,
        enabled: bool,
        encoded_key: Option<&str>,
        key_version: Option<&str>,
    ) -> Option<Self> {
        if !enabled || key_version != Some(SESSION_ATTRIBUTION_HMAC_KEY_VERSION) {
            return None;
        }
        let key = URL_SAFE_NO_PAD.decode(encoded_key?).ok()?;
        if key.len() != 32 {
            return None;
        }
        let key = Zeroizing::new(key);
        let provider_schedules = if source == SnapshotSource::Codex {
            cached_codex_schedule_inventory(home, &key)
        } else {
            ProviderScheduleInventory::default()
        };
        let external_schedulers =
            crate::external_scheduler_attribution::ExternalSchedulerInventory::cached(home, &key);
        Some(Self {
            key,
            provider_schedules,
            external_schedulers,
        })
    }

    pub fn grouping_facts(
        &self,
        input: SessionAttributionGroupingInput<'_>,
    ) -> Vec<SessionAttributionFact> {
        let mut facts = Vec::new();
        let evidence_context = EvidenceContext {
            source_session_id: input.source_session_id,
            observed_at: input.observed_at,
            source_version: input.source_version,
        };
        let normalized_template = input.first_prompt.and_then(normalize_template_material);
        if let Some(template) = normalized_template.as_deref() {
            if let Some(value) = opaque_hmac_id(&self.key, "template_group", template) {
                push_fact(
                    &mut facts,
                    "template_group_id",
                    &value,
                    "local_template",
                    "direct",
                    &evidence_context,
                );
            }

            if input.source == SnapshotSource::Codex
                && input
                    .origin
                    .and_then(|value| value.thread_source.as_deref())
                    == Some("automation")
            {
                if let Some(value) = self.provider_schedules.matching_id(template) {
                    push_fact(
                        &mut facts,
                        "schedule_definition_id",
                        value,
                        "provider_artifact",
                        "corroborated",
                        &evidence_context,
                    );
                }
            }
        }

        for skill in input.provider_skills.iter().take(8) {
            if let Some(value) = opaque_hmac_id(&self.key, "skill", skill) {
                push_fact(
                    &mut facts,
                    "skill_id",
                    &value,
                    "provider_native",
                    "direct",
                    &evidence_context,
                );
            }
        }
        if let Some(skill) = input.first_prompt.and_then(slash_skill_name) {
            if !input.provider_skills.contains(&skill) {
                if let Some(value) = opaque_hmac_id(&self.key, "skill", &skill) {
                    push_fact(
                        &mut facts,
                        "skill_id",
                        &value,
                        "local_template",
                        "direct",
                        &evidence_context,
                    );
                }
            }
        }

        let provider_origin_known = input.origin.map(provider_origin_is_known).unwrap_or(false);
        if let Some(matched) = (!provider_origin_known)
            .then(|| {
                self.external_schedulers.correlate(
                    crate::external_scheduler_attribution::ExternalSchedulerSession {
                        source: input.source,
                        normalized_template: normalized_template.as_deref(),
                        repository_hash: input.repository_hash,
                        source_started_at: input.source_started_at,
                        transcript_path: input.transcript_path,
                    },
                )
            })
            .flatten()
        {
            push_fact(
                &mut facts,
                "origin_kind",
                "external_scheduler",
                matched.evidence_kind,
                matched.evidence_strength,
                &evidence_context,
            );
            push_fact(
                &mut facts,
                "scheduler_kind",
                matched.scheduler_kind,
                matched.evidence_kind,
                matched.evidence_strength,
                &evidence_context,
            );
            push_fact(
                &mut facts,
                "schedule_definition_id",
                &matched.schedule_definition_id,
                matched.evidence_kind,
                matched.evidence_strength,
                &evidence_context,
            );
        }

        enforce_fact_limits(&mut facts);
        facts
    }
}

fn provider_origin_is_known(origin: &SnapshotOrigin) -> bool {
    matches!(
        origin.thread_source.as_deref(),
        Some("automation" | "subagent")
    ) || origin.source_subagent == Some(true)
        || origin.is_sidechain == Some(true)
}

impl ProviderScheduleInventory {
    fn matching_id(&self, normalized_template: &str) -> Option<&str> {
        let mut best: Option<&ProviderScheduleDefinition> = None;
        let mut ambiguous = false;
        for definition in &self.definitions {
            if definition.prompt_signature.chars().count()
                < MIN_PROVIDER_SCHEDULE_PROMPT_SIGNATURE_CHARS
                || !normalized_template.contains(&definition.prompt_signature)
            {
                continue;
            }
            match best {
                None => {
                    best = Some(definition);
                    ambiguous = false;
                }
                Some(current)
                    if definition.prompt_signature.len() > current.prompt_signature.len() =>
                {
                    best = Some(definition);
                    ambiguous = false;
                }
                Some(current)
                    if definition.prompt_signature.len() == current.prompt_signature.len()
                        && definition.opaque_id != current.opaque_id =>
                {
                    ambiguous = true;
                }
                _ => {}
            }
        }
        (!ambiguous)
            .then_some(best)
            .flatten()
            .map(|definition| definition.opaque_id.as_str())
    }
}

struct EvidenceContext<'a> {
    source_session_id: &'a str,
    observed_at: &'a str,
    source_version: &'a str,
}

fn cached_codex_schedule_inventory(home: &Path, key: &[u8]) -> ProviderScheduleInventory {
    static CACHE: OnceLock<Mutex<Option<CachedProviderScheduleInventory>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(None));
    let key_fingerprint = sha256_hex(key);
    let previous_files = if let Ok(guard) = cache.lock() {
        if let Some(cached) = guard.as_ref() {
            if cached.home == home
                && cached.key_fingerprint == key_fingerprint
                && cached.loaded_at.elapsed() < PROVIDER_SCHEDULE_CACHE_TTL
            {
                return cached.inventory.clone();
            }
            if cached.home == home && cached.key_fingerprint == key_fingerprint {
                cached.files.clone()
            } else {
                BTreeMap::new()
            }
        } else {
            BTreeMap::new()
        }
    } else {
        BTreeMap::new()
    };

    let (inventory, files) = refresh_codex_schedule_inventory(home, key, &previous_files);
    if let Ok(mut guard) = cache.lock() {
        *guard = Some(CachedProviderScheduleInventory {
            loaded_at: Instant::now(),
            home: home.to_path_buf(),
            key_fingerprint,
            inventory: inventory.clone(),
            files,
        });
    }
    inventory
}

#[cfg(test)]
fn load_codex_schedule_inventory(home: &Path, key: &[u8]) -> ProviderScheduleInventory {
    refresh_codex_schedule_inventory(home, key, &BTreeMap::new()).0
}

fn refresh_codex_schedule_inventory(
    home: &Path,
    key: &[u8],
    previous_files: &BTreeMap<PathBuf, CachedProviderScheduleFile>,
) -> (
    ProviderScheduleInventory,
    BTreeMap<PathBuf, CachedProviderScheduleFile>,
) {
    let root = home.join(".codex").join("automations");
    let Ok(entries) = fs::read_dir(root) else {
        return (ProviderScheduleInventory::default(), BTreeMap::new());
    };
    let mut paths = entries
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .collect::<Vec<_>>();
    paths.sort();
    paths.truncate(MAX_PROVIDER_SCHEDULE_FILES);

    let mut definitions = Vec::new();
    let mut files = BTreeMap::new();
    for path in paths {
        let Ok(directory_metadata) = fs::symlink_metadata(&path) else {
            continue;
        };
        if directory_metadata.file_type().is_symlink() || !directory_metadata.is_dir() {
            continue;
        }
        let definition_path = path.join("automation.toml");
        let Ok(metadata) = fs::symlink_metadata(&definition_path) else {
            continue;
        };
        if metadata.file_type().is_symlink()
            || !metadata.is_file()
            || metadata.len() > MAX_PROVIDER_SCHEDULE_FILE_BYTES
        {
            continue;
        }
        let modified_unix_nanos = metadata
            .modified()
            .ok()
            .and_then(|value| value.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|value| value.as_nanos())
            .unwrap_or_default();
        let definition = previous_files
            .get(&definition_path)
            .filter(|cached| {
                cached.size_bytes == metadata.len()
                    && cached.modified_unix_nanos == modified_unix_nanos
            })
            .map(|cached| cached.definition.clone())
            .unwrap_or_else(|| parse_codex_schedule_definition(&definition_path, key));
        if let Some(definition) = definition.as_ref() {
            definitions.push(definition.clone());
        }
        files.insert(
            definition_path,
            CachedProviderScheduleFile {
                size_bytes: metadata.len(),
                modified_unix_nanos,
                definition,
            },
        );
    }
    definitions.sort_by(|left, right| left.opaque_id.cmp(&right.opaque_id));
    definitions.dedup_by(|left, right| left.opaque_id == right.opaque_id);
    (ProviderScheduleInventory { definitions }, files)
}

fn parse_codex_schedule_definition(
    definition_path: &Path,
    key: &[u8],
) -> Option<ProviderScheduleDefinition> {
    let document = read_bounded_toml(definition_path)?;
    let id = document.get("id").and_then(|item| item.as_str())?;
    let prompt = document.get("prompt").and_then(|item| item.as_str())?;
    if id.is_empty() || id.len() > 128 {
        return None;
    }
    let normalized_prompt = normalize_template_material(prompt)?;
    let prompt_signature = normalized_prompt
        .chars()
        .take(MAX_PROVIDER_SCHEDULE_PROMPT_SIGNATURE_CHARS)
        .collect::<String>();
    let opaque_id = opaque_hmac_id(key, "schedule_definition", id)?;
    Some(ProviderScheduleDefinition {
        opaque_id,
        prompt_signature,
    })
}

fn read_bounded_toml(path: &Path) -> Option<DocumentMut> {
    let mut bytes = Vec::new();
    File::open(path)
        .ok()?
        .take(MAX_PROVIDER_SCHEDULE_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .ok()?;
    if bytes.len() as u64 > MAX_PROVIDER_SCHEDULE_FILE_BYTES {
        return None;
    }
    std::str::from_utf8(&bytes).ok()?.parse().ok()
}

pub(crate) fn opaque_hmac_id(key: &[u8], domain: &str, material: &str) -> Option<String> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).ok()?;
    mac.update(b"ottto:session-attribution:");
    mac.update(domain.as_bytes());
    mac.update(b":v1\0");
    mac.update(material.as_bytes());
    Some(format!(
        "{SESSION_ATTRIBUTION_HMAC_KEY_VERSION}:{}",
        URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
    ))
}

pub(crate) fn normalize_template_material(raw: &str) -> Option<String> {
    let collapsed = raw
        .split_whitespace()
        .take(MAX_TEMPLATE_MATERIAL_CHARS)
        .map(|token| {
            let comparable =
                token.trim_matches(|character: char| !character.is_ascii_alphanumeric());
            if looks_volatile(comparable) {
                "<dynamic>"
            } else {
                token
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase();
    let bounded = collapsed
        .chars()
        .take(MAX_TEMPLATE_MATERIAL_CHARS)
        .collect::<String>();
    (!bounded.is_empty()).then_some(bounded)
}

fn looks_volatile(token: &str) -> bool {
    let ascii = token.as_bytes();
    let uuid_like = ascii.len() == 36
        && [8, 13, 18, 23]
            .iter()
            .all(|index| ascii.get(*index) == Some(&b'-'))
        && ascii
            .iter()
            .enumerate()
            .all(|(index, byte)| [8, 13, 18, 23].contains(&index) || byte.is_ascii_hexdigit());
    let date_like = ascii.len() >= 10
        && ascii.get(4) == Some(&b'-')
        && ascii.get(7) == Some(&b'-')
        && ascii[..4].iter().all(u8::is_ascii_digit)
        && ascii[5..7].iter().all(u8::is_ascii_digit)
        && ascii[8..10].iter().all(u8::is_ascii_digit);
    let long_integer = ascii.len() >= 4 && ascii.iter().all(u8::is_ascii_digit);
    let long_hex = ascii.len() >= 16 && ascii.iter().all(u8::is_ascii_hexdigit);
    uuid_like || date_like || long_integer || long_hex
}

fn slash_skill_name(first_prompt: &str) -> Option<String> {
    let token = first_prompt.split_whitespace().next()?;
    let name = token.strip_prefix('/')?.trim_end_matches([':', ',', '.']);
    if name.is_empty()
        || name.len() > 64
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        || matches!(
            name.to_ascii_lowercase().as_str(),
            "compact" | "help" | "login" | "logout" | "model" | "review" | "status"
        )
    {
        return None;
    }
    Some(name.to_ascii_lowercase())
}

fn sha256_hex(value: &[u8]) -> String {
    format!("{:x}", Sha256::digest(value))
}

/// Convert direct provider metadata into allowlisted facts.
///
/// Absence means omission. In particular, no fact in this function claims a
/// human launch. Raw Codex transport values such as `vscode` are deliberately
/// not mapped to customer-facing provider surfaces.
pub fn direct_provider_facts(
    source: SnapshotSource,
    origin: Option<&SnapshotOrigin>,
    source_session_id: &str,
    observed_at: &str,
    source_version: &str,
) -> Vec<SessionAttributionFact> {
    let mut facts = Vec::new();
    let origin = origin.cloned().unwrap_or_default();
    let evidence_context = EvidenceContext {
        source_session_id,
        observed_at,
        source_version,
    };

    match source {
        SnapshotSource::Codex => {
            match origin.thread_source.as_deref() {
                Some("automation") => {
                    push_fact(
                        &mut facts,
                        "origin_kind",
                        "provider_scheduled_task",
                        "provider_native",
                        "direct",
                        &evidence_context,
                    );
                    push_fact(
                        &mut facts,
                        "scheduler_kind",
                        "codex_scheduled",
                        "provider_native",
                        "direct",
                        &evidence_context,
                    );
                }
                Some("subagent") => push_fact(
                    &mut facts,
                    "origin_kind",
                    "subagent",
                    "provider_native",
                    "direct",
                    &evidence_context,
                ),
                _ if origin.source_subagent == Some(true) => push_fact(
                    &mut facts,
                    "origin_kind",
                    "subagent",
                    "provider_native",
                    "direct",
                    &evidence_context,
                ),
                _ => {}
            }

            let provider_surface = if origin.originator.as_deref() == Some("Codex Desktop") {
                Some("codex_desktop")
            } else {
                match origin.source.as_deref() {
                    Some("cli") => Some("codex_cli"),
                    Some("exec") => Some("codex_exec"),
                    _ => None,
                }
            };
            if let Some(value) = provider_surface {
                push_fact(
                    &mut facts,
                    "provider_surface",
                    value,
                    "provider_native",
                    "direct",
                    &evidence_context,
                );
            }
            if origin.source.as_deref() == Some("exec") {
                push_fact(
                    &mut facts,
                    "execution_mode",
                    "headless",
                    "provider_native",
                    "direct",
                    &evidence_context,
                );
            }
        }
        SnapshotSource::ClaudeCode => {
            if origin.is_sidechain == Some(true) {
                push_fact(
                    &mut facts,
                    "origin_kind",
                    "subagent",
                    "provider_native",
                    "direct",
                    &evidence_context,
                );
            }
            let provider_surface = match origin.entrypoint.as_deref() {
                Some("claude-desktop") => Some("claude_desktop"),
                Some("cli") => Some("claude_cli"),
                Some("sdk-cli") => Some("claude_sdk"),
                _ => None,
            };
            if let Some(value) = provider_surface {
                push_fact(
                    &mut facts,
                    "provider_surface",
                    value,
                    "provider_native",
                    "direct",
                    &evidence_context,
                );
            }
            let execution_mode = if origin.session_kind.as_deref() == Some("bg") {
                Some("background")
            } else if origin.entrypoint.as_deref() == Some("sdk-cli") {
                Some("headless")
            } else {
                None
            };
            if let Some(value) = execution_mode {
                push_fact(
                    &mut facts,
                    "execution_mode",
                    value,
                    "provider_native",
                    "direct",
                    &evidence_context,
                );
            }
        }
        SnapshotSource::Pi => push_fact(
            &mut facts,
            "provider_surface",
            "pi_cli",
            "provider_native",
            "direct",
            &evidence_context,
        ),
    }

    if let Some(parent_session_ref) = origin.parent_session_ref.as_deref() {
        push_fact(
            &mut facts,
            "parent_session_ref",
            parent_session_ref,
            "provider_native",
            "direct",
            &evidence_context,
        );
    }
    if origin.used_workflow_orchestration == Some(true) {
        push_fact(
            &mut facts,
            "workflow_orchestration",
            "dynamic",
            "provider_artifact",
            "direct",
            &evidence_context,
        );
    }

    enforce_fact_limits(&mut facts);
    facts
}

pub(crate) fn enforce_fact_limits(facts: &mut Vec<SessionAttributionFact>) {
    facts.truncate(MAX_SESSION_ATTRIBUTION_FACTS);
    while facts.len() > 1
        && serde_json::to_vec(facts)
            .map(|payload| payload.len() > MAX_SESSION_ATTRIBUTION_PAYLOAD_BYTES)
            .unwrap_or(true)
    {
        facts.pop();
    }
}

fn push_fact(
    facts: &mut Vec<SessionAttributionFact>,
    field: &str,
    value: &str,
    kind: &str,
    strength: &str,
    context: &EvidenceContext<'_>,
) {
    if facts.len() >= MAX_SESSION_ATTRIBUTION_FACTS
        || value.is_empty()
        || value.len() > MAX_SESSION_ATTRIBUTION_FACT_VALUE_BYTES
        || context.source_version.len() > MAX_SESSION_ATTRIBUTION_SOURCE_VERSION_BYTES
    {
        return;
    }
    let evidence_ref = evidence_ref(context.source_session_id, field, value);
    if evidence_ref.len() > MAX_SESSION_ATTRIBUTION_EVIDENCE_REF_BYTES {
        return;
    }
    facts.push(SessionAttributionFact {
        field: field.to_string(),
        value: value.to_string(),
        evidence: SessionFieldEvidence {
            kind: kind.to_string(),
            strength: strength.to_string(),
            observed_at: context.observed_at.to_string(),
            source_version: context.source_version.to_string(),
            evidence_ref,
        },
    });
}

fn evidence_ref(source_session_id: &str, field: &str, value: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(b"session-attribution-evidence:v1\0");
    digest.update(source_session_id.as_bytes());
    digest.update(b"\0");
    digest.update(field.as_bytes());
    digest.update(b"\0");
    digest.update(value.as_bytes());
    format!("sha256:{:x}", digest.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn origin() -> SnapshotOrigin {
        SnapshotOrigin::default()
    }

    #[test]
    fn codex_provider_automation_is_direct_scheduled_origin() {
        let mut origin = origin();
        origin.thread_source = Some("automation".to_string());
        origin.originator = Some("Codex Desktop".to_string());
        let facts = direct_provider_facts(
            SnapshotSource::Codex,
            Some(&origin),
            "session-1",
            "2026-07-19T00:00:00Z",
            "codex_jsonl:v21",
        );
        assert!(facts.iter().any(|fact| {
            fact.field == "origin_kind"
                && fact.value == "provider_scheduled_task"
                && fact.evidence.strength == "direct"
        }));
        assert!(facts
            .iter()
            .any(|fact| fact.field == "scheduler_kind" && fact.value == "codex_scheduled"));
        assert!(facts
            .iter()
            .any(|fact| fact.field == "provider_surface" && fact.value == "codex_desktop"));
    }

    #[test]
    fn raw_vscode_transport_does_not_become_provider_surface() {
        let mut origin = origin();
        origin.source = Some("vscode".to_string());
        let facts = direct_provider_facts(
            SnapshotSource::Codex,
            Some(&origin),
            "session-2",
            "2026-07-19T00:00:00Z",
            "codex_jsonl:v21",
        );
        assert!(!facts.iter().any(|fact| fact.field == "provider_surface"));
        assert!(!facts.iter().any(|fact| fact.field == "origin_kind"));
    }

    #[test]
    fn headless_and_workflow_are_neutral_without_origin_fact() {
        let mut origin = origin();
        origin.entrypoint = Some("sdk-cli".to_string());
        origin.used_workflow_orchestration = Some(true);
        let facts = direct_provider_facts(
            SnapshotSource::ClaudeCode,
            Some(&origin),
            "session-3",
            "2026-07-19T00:00:00Z",
            "claude_code_jsonl:v18",
        );
        assert!(facts
            .iter()
            .any(|fact| fact.field == "execution_mode" && fact.value == "headless"));
        assert!(facts
            .iter()
            .any(|fact| fact.field == "workflow_orchestration"));
        assert!(!facts.iter().any(|fact| fact.field == "origin_kind"));
    }

    #[test]
    fn parent_reference_and_subagent_are_separate_direct_facts() {
        let mut origin = origin();
        origin.source_subagent = Some(true);
        origin.parent_session_ref = Some("019f-parent".to_string());
        let facts = direct_provider_facts(
            SnapshotSource::Codex,
            Some(&origin),
            "session-4",
            "2026-07-19T00:00:00Z",
            "codex_jsonl:v21",
        );
        assert!(facts
            .iter()
            .any(|fact| fact.field == "origin_kind" && fact.value == "subagent"));
        assert!(facts
            .iter()
            .any(|fact| { fact.field == "parent_session_ref" && fact.value == "019f-parent" }));
    }

    #[test]
    fn direct_fact_payload_is_bounded_and_content_free() {
        let mut origin = origin();
        origin.thread_source = Some("automation".to_string());
        origin.originator = Some("Codex Desktop".to_string());
        origin.parent_session_ref = Some("019f-parent".to_string());
        let facts = direct_provider_facts(
            SnapshotSource::Codex,
            Some(&origin),
            "session-5",
            "2026-07-19T00:00:00Z",
            "codex_jsonl:v21",
        );
        let payload = serde_json::to_vec(&facts).expect("serialize facts");
        assert!(payload.len() <= MAX_SESSION_ATTRIBUTION_PAYLOAD_BYTES);
        let text = String::from_utf8(payload).expect("json");
        for forbidden in [
            "prompt_text",
            "transcript_text",
            "filesystem_path",
            "working_directory",
            "remote_url",
            "process_argv",
            "process_environment",
            "scheduler_definition",
            "raw_log",
        ] {
            assert!(!text.contains(forbidden));
        }
    }

    #[test]
    fn hint_context_fails_closed_for_unknown_or_invalid_keys() {
        let home = Path::new("/nonexistent");
        assert!(SessionAttributionContext::from_activity_hint(
            SnapshotSource::Codex,
            home,
            false,
            None,
            None,
        )
        .is_none());
        assert!(SessionAttributionContext::from_activity_hint(
            SnapshotSource::Codex,
            home,
            true,
            Some("not-base64"),
            Some(SESSION_ATTRIBUTION_HMAC_KEY_VERSION),
        )
        .is_none());
        let encoded = URL_SAFE_NO_PAD.encode([7_u8; 32]);
        assert!(SessionAttributionContext::from_activity_hint(
            SnapshotSource::Codex,
            home,
            true,
            Some(&encoded),
            Some("hmac-sha256:v2"),
        )
        .is_none());
    }

    #[test]
    fn cache_namespace_changes_with_key_and_inventory_without_exposing_material() {
        let context = SessionAttributionContext {
            key: Zeroizing::new(vec![1_u8; 32]),
            provider_schedules: ProviderScheduleInventory::default(),
            external_schedulers:
                crate::external_scheduler_attribution::ExternalSchedulerInventory::default(),
        };
        let rotated = SessionAttributionContext {
            key: Zeroizing::new(vec![2_u8; 32]),
            provider_schedules: ProviderScheduleInventory::default(),
            external_schedulers:
                crate::external_scheduler_attribution::ExternalSchedulerInventory::default(),
        };
        let changed_inventory = SessionAttributionContext {
            key: Zeroizing::new(vec![1_u8; 32]),
            provider_schedules: ProviderScheduleInventory {
                definitions: vec![ProviderScheduleDefinition {
                    opaque_id: "hmac-sha256:v1:opaque".to_string(),
                    prompt_signature: "private schedule prompt material".to_string(),
                }],
            },
            external_schedulers:
                crate::external_scheduler_attribution::ExternalSchedulerInventory::default(),
        };

        let namespace = context.cache_namespace();
        assert_eq!(namespace.len(), 16);
        assert_ne!(namespace, rotated.cache_namespace());
        assert_ne!(namespace, changed_inventory.cache_namespace());
        assert!(!changed_inventory
            .cache_namespace()
            .contains("private schedule prompt material"));
    }

    #[test]
    fn template_normalization_removes_common_run_specific_values() {
        let first = normalize_template_material("Review build 123456 at 2026-07-19T09:30:00Z now")
            .expect("first");
        let second =
            normalize_template_material("Review   build 987654 at 2026-08-20T10:45:00Z now")
                .expect("second");

        assert_eq!(first, second);
        assert_eq!(first, "review build <dynamic> at <dynamic> now");
    }

    #[test]
    fn grouping_facts_are_opaque_and_keep_dimensions_separate() {
        let key = Zeroizing::new(vec![9_u8; 32]);
        let scheduled_prompt =
            "Inspect the landing queue, verify every required check, and report only safe results.";
        let normalized_schedule =
            normalize_template_material(scheduled_prompt).expect("normalized schedule");
        let schedule_id =
            opaque_hmac_id(&key, "schedule_definition", "schedule-1").expect("schedule id");
        let context = SessionAttributionContext {
            key,
            provider_schedules: ProviderScheduleInventory {
                definitions: vec![ProviderScheduleDefinition {
                    opaque_id: schedule_id.clone(),
                    prompt_signature: normalized_schedule
                        .chars()
                        .take(MAX_PROVIDER_SCHEDULE_PROMPT_SIGNATURE_CHARS)
                        .collect(),
                }],
            },
            external_schedulers:
                crate::external_scheduler_attribution::ExternalSchedulerInventory::default(),
        };
        let origin = SnapshotOrigin {
            thread_source: Some("automation".to_string()),
            ..SnapshotOrigin::default()
        };
        let mut skills = BTreeSet::new();
        skills.insert("landing-lander".to_string());
        let first_prompt =
            format!("An automation named Landing has fired. Its prompt is: {scheduled_prompt}");

        let facts = context.grouping_facts(SessionAttributionGroupingInput {
            source: SnapshotSource::Codex,
            origin: Some(&origin),
            source_session_id: "session-opaque",
            observed_at: "2026-07-19T00:00:00Z",
            source_version: "codex_jsonl:v21",
            first_prompt: Some(&first_prompt),
            provider_skills: &skills,
            repository_hash: None,
            source_started_at: None,
            transcript_path: Path::new("/missing"),
        });

        assert!(facts.iter().any(|fact| fact.field == "template_group_id"));
        assert!(facts.iter().any(|fact| {
            fact.field == "schedule_definition_id"
                && fact.value == schedule_id
                && fact.evidence.strength == "corroborated"
        }));
        assert!(facts.iter().any(|fact| fact.field == "skill_id"));
        assert!(facts.iter().all(|fact| {
            fact.value.starts_with("hmac-sha256:v1:")
                || !matches!(
                    fact.field.as_str(),
                    "template_group_id" | "schedule_definition_id" | "skill_id"
                )
        }));
        let wire = serde_json::to_string(&facts).expect("facts");
        assert!(!wire.contains("landing-lander"));
        assert!(!wire.contains("Inspect the landing queue"));
        assert!(wire.len() <= MAX_SESSION_ATTRIBUTION_PAYLOAD_BYTES);
    }

    #[test]
    fn explicit_slash_skill_excludes_builtin_commands() {
        assert_eq!(
            slash_skill_name("/frontend-flow-change please update this"),
            Some("frontend-flow-change".to_string())
        );
        assert_eq!(slash_skill_name("/compact"), None);
        assert_eq!(slash_skill_name("ordinary prompt"), None);
    }

    #[test]
    fn codex_schedule_inventory_reads_only_bounded_definition_fields() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let home = std::env::temp_dir().join(format!(
            "ottto-session-attribution-{}-{unique}",
            std::process::id()
        ));
        let schedule_dir = home.join(".codex/automations/schedule-1");
        fs::create_dir_all(&schedule_dir).expect("schedule dir");
        fs::write(
            schedule_dir.join("automation.toml"),
            r#"
id = "schedule-1"
name = "Private local name"
prompt = "Inspect the landing queue, verify required checks, and report safe results."
rrule = "FREQ=HOURLY"
status = "ACTIVE"
"#,
        )
        .expect("schedule");

        let inventory = load_codex_schedule_inventory(&home, &[3_u8; 32]);

        assert_eq!(inventory.definitions.len(), 1);
        assert!(inventory.definitions[0]
            .opaque_id
            .starts_with("hmac-sha256:v1:"));
        assert!(!inventory.definitions[0].opaque_id.contains("schedule-1"));
        fs::remove_dir_all(home).expect("cleanup");
    }
}
