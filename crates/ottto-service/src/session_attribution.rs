//! Privacy-safe, evidence-first session attribution.
//!
//! This module converts provider-native metadata already read by the incremental
//! transcript scanner into a compact fact list. It never receives raw paths,
//! process arguments, or logs. Prompt/template and skill grouping use a
//! backend-issued, tenant-scoped HMAC key; provider schedule definitions are
//! read locally on a six-hour cache and reduced to opaque identifiers before
//! facts can leave this module. Optional display labels contain only a
//! sanitized 96-byte prompt prefix or allowlisted skill name; upload policy
//! removes them unless the existing session-title privacy consent and the
//! backend capability are both active.

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
pub const MAX_SESSION_ATTRIBUTION_DISPLAY_LABEL_BYTES: usize = 96;
pub const MAX_SESSION_ATTRIBUTION_DISPLAY_LABEL_SOURCE_BYTES: usize = 32;
/// Wire budget for one session's attribution facts.
///
/// Raised 2,048 → 4,096 → 8,192. This number and the backend's
/// `MAX_SESSION_ATTRIBUTION_PAYLOAD_BYTES` are one contract and must be equal:
/// a daemon budget BELOW the backend's silently trims facts the backend would
/// have accepted, and a daemon budget ABOVE it converts that silent trim into a
/// hard 422 on the whole batch. So the backend always moves first — it is
/// already deployed at 8,192, which is why this side may follow.
///
/// The intended ordering at 8 KiB is that the 24-fact count cap binds first and
/// the byte budget only stops pathological values. An ordinary fact carries a
/// mandatory `sha256:` evidence reference and costs ~290 bytes, so a full
/// 24-fact list lands near 7 KiB and fits; only facts near the
/// `MAX_SESSION_ATTRIBUTION_FACT_VALUE_BYTES` ceiling can still reach the byte
/// budget before the count cap.
pub const MAX_SESSION_ATTRIBUTION_PAYLOAD_BYTES: usize = 8_192;
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_label: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_label_source: Option<String>,
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
    launch_events: crate::launch_events::LaunchEventInventory,
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
    /// Short local-only identity namespace for the incremental scan index.
    ///
    /// Only the HMAC key epoch belongs in checkpoint identity. Scheduler
    /// inventory is semantic input for sessions parsed after it changes, but an
    /// unrelated automation definition must not invalidate every transcript
    /// checkpoint and replay local history. Historical re-evaluation remains an
    /// explicit backfill/replay operation.
    pub fn checkpoint_namespace(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(b"session-attribution-checkpoint:v2");
        hasher.update(self.key.as_slice());
        format!("{:x}", hasher.finalize())[..16].to_string()
    }

    /// Pre-v2 namespace retained only to adopt the exact current legacy index
    /// during upgrade without forcing a one-time historical replay.
    pub fn legacy_cache_namespace(&self) -> String {
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
        // Gated with everything else in this constructor: launch-event intake
        // rides the same `session_attribution_enabled` policy and the same
        // backend-issued key epoch that already govern every attribution fact.
        // Attribution off means the drop directory is not even listed.
        let launch_events = crate::launch_events::LaunchEventInventory::cached(home);
        Some(Self {
            key,
            provider_schedules,
            external_schedulers,
            launch_events,
        })
    }

    /// Direct lineage facts for a worker session an instrumented launcher
    /// started, or nothing at all.
    ///
    /// Kept out of `grouping_facts` on purpose. Grouping facts are derived
    /// signals that trim first under the payload budget; these are the exact
    /// controller edge and belong immediately behind the provider-native facts,
    /// which is where `into_items` appends them.
    ///
    /// The caller drops any field it has already filled from provider-native
    /// evidence, so a launcher can add an edge the provider never knew about but
    /// can never overwrite one the provider owns.
    pub fn launch_event_facts(
        &self,
        worker_session_ref: &str,
        observed_at: &str,
    ) -> Vec<SessionAttributionFact> {
        let mut facts = Vec::new();
        let Some(event) = self.launch_events.matching(worker_session_ref) else {
            return facts;
        };
        let evidence_context = EvidenceContext {
            source_session_id: worker_session_ref,
            observed_at,
            source_version: crate::launch_events::LAUNCH_EVENT_SOURCE_VERSION,
        };
        let kind = crate::launch_events::LAUNCH_EVENT_EVIDENCE_KIND;
        push_fact(
            &mut facts,
            "parent_session_ref",
            &event.controller_session_ref,
            kind,
            "direct",
            &evidence_context,
        );
        push_fact(
            &mut facts,
            "origin_kind",
            "agent_spawn",
            kind,
            "direct",
            &evidence_context,
        );
        push_fact(
            &mut facts,
            "workflow_ref",
            &event.workflow_ref,
            kind,
            "direct",
            &evidence_context,
        );
        push_fact(
            &mut facts,
            "agent_kind",
            event.agent_kind,
            kind,
            "direct",
            &evidence_context,
        );
        facts
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
                let display_label = input.first_prompt.and_then(prompt_prefix_display_label);
                push_labeled_fact(
                    &mut facts,
                    "template_group_id",
                    &value,
                    display_label.as_deref(),
                    Some("prompt_prefix"),
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
                let display_label = skill_name_display_label(skill);
                push_labeled_fact(
                    &mut facts,
                    "skill_id",
                    &value,
                    display_label.as_deref(),
                    Some("skill_name"),
                    "provider_native",
                    "direct",
                    &evidence_context,
                );
            }
        }
        if let Some(skill) = input.first_prompt.and_then(slash_skill_name) {
            if !input.provider_skills.contains(&skill) {
                if let Some(value) = opaque_hmac_id(&self.key, "skill", &skill) {
                    let display_label = skill_name_display_label(&skill);
                    push_labeled_fact(
                        &mut facts,
                        "skill_id",
                        &value,
                        display_label.as_deref(),
                        Some("skill_name"),
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
    let raw = prompt_without_injected_scaffolding(raw);
    if raw.is_empty() {
        return None;
    }
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

fn prompt_prefix_display_label(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || contains_private_prompt_scaffolding(trimmed) {
        return None;
    }

    // Codex scheduled sessions wrap the configured prompt in a stable sentence.
    // The useful label is the configured prompt's prefix, not that shared wrapper.
    let lowered = trimmed.to_ascii_lowercase();
    let candidate = lowered
        .find("its prompt is:")
        .map(|index| &trimmed[index + "its prompt is:".len()..])
        .unwrap_or(trimmed)
        .trim();
    if candidate.is_empty() || contains_private_prompt_scaffolding(candidate) {
        return None;
    }

    let mut label = String::new();
    for token in candidate.split_whitespace() {
        let safe_token = if looks_like_local_path(token) {
            "[path]"
        } else {
            token
        };
        let separator_bytes = usize::from(!label.is_empty());
        if label.len() + separator_bytes + safe_token.len()
            > MAX_SESSION_ATTRIBUTION_DISPLAY_LABEL_BYTES
        {
            break;
        }
        if !label.is_empty() {
            label.push(' ');
        }
        label.push_str(safe_token);
    }

    let label = label
        .trim_matches(|character: char| character.is_control())
        .trim();
    (!label.is_empty()).then(|| label.to_string())
}

fn skill_name_display_label(raw: &str) -> Option<String> {
    let label = raw.trim().trim_start_matches('/');
    if label.is_empty()
        || label.len() > 64
        || !label
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        return None;
    }
    Some(label.to_string())
}

fn contains_private_prompt_scaffolding(value: &str) -> bool {
    let lowered = value.to_ascii_lowercase();
    lowered.contains("<instructions>")
        || lowered.contains("<environment_context>")
        || lowered.contains("agents.md instructions")
        || lowered.contains("knowledge cutoff:")
        || lowered.contains("current date:")
}

pub(crate) fn prompt_without_injected_scaffolding(mut value: &str) -> &str {
    loop {
        value = value.trim_start();
        let lowered = value.to_ascii_lowercase();
        let consumed = if lowered.starts_with("<recommended_plugins>") {
            scaffold_block_end(&lowered, "</recommended_plugins>")
        } else if lowered.starts_with("# agents.md instructions for ") {
            lowered.find("<instructions>").and_then(|start| {
                scaffold_block_end(&lowered[start..], "</instructions>").map(|end| start + end)
            })
        } else if lowered.starts_with("<environment_context>") {
            scaffold_block_end(&lowered, "</environment_context>")
                .filter(|end| lowered[..*end].contains("<cwd>"))
        } else {
            None
        };
        let Some(consumed) = consumed else {
            return value;
        };
        value = &value[consumed..];
    }
}

fn scaffold_block_end(value: &str, closing_tag: &str) -> Option<usize> {
    value
        .find(closing_tag)
        .map(|start| start + closing_tag.len())
}

fn looks_like_local_path(token: &str) -> bool {
    let comparable = token.trim_matches(|character: char| {
        matches!(
            character,
            '"' | '\'' | '(' | ')' | '[' | ']' | '{' | '}' | ',' | ';'
        )
    });
    let lowered = comparable.to_ascii_lowercase();
    let windows_absolute = comparable.as_bytes().get(1) == Some(&b':')
        && comparable
            .as_bytes()
            .get(2)
            .is_some_and(|byte| matches!(byte, b'\\' | b'/'));
    let unix_absolute = comparable.starts_with('/')
        && comparable[1..].contains('/')
        && !comparable.starts_with("//");
    let relative_path =
        (!comparable.starts_with('/') && comparable.contains('/')) || comparable.contains('\\');
    windows_absolute
        || unix_absolute
        || relative_path
        || comparable.starts_with("~/")
        || lowered.starts_with("file://")
        || lowered.contains("/users/")
        || lowered.contains("/home/")
        || lowered.contains("/volumes/")
        || lowered.contains("/private/")
        || lowered.contains("/var/folders/")
        || lowered.contains("/tmp/")
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

            let provider_surface = provider_surface(SnapshotSource::Codex, Some(&origin));
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
            let provider_surface = provider_surface(SnapshotSource::ClaudeCode, Some(&origin));
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

/// Local subagent-tree descriptor for a Claude Code transcript, derived from the
/// transcript's path plus its provider-written `*.meta.json` sidecar.
///
/// Every field is a provider-native identifier or an integer. No prompt text, no
/// agent description, and no local filesystem path reaches this struct.
pub struct ClaudeSubagentAttribution<'a> {
    /// The top-level human session that owns the whole subagent tree, always the
    /// raw session UUID regardless of nesting depth. This is the rollup key.
    pub root_session_ref: &'a str,
    /// `agentType` from the sidecar, e.g. `workflow-subagent`, `Explore`.
    pub agent_kind: Option<&'a str>,
    /// The provider agent id (transcript file stem with `agent-` stripped).
    pub agent_ref: Option<&'a str>,
    /// `spawnDepth` from the sidecar, stringified.
    pub spawn_depth: Option<&'a str>,
    /// The `wf_*` workflow directory when the agent ran under the Workflow tool.
    pub workflow_ref: Option<&'a str>,
}

/// Fixed-name attribution facts for one Claude Code subagent session.
///
/// The field names here are a contract shared with the backend session
/// attribution reader (`root_session_ref`, `agent_kind`, `agent_ref`,
/// `spawn_depth`, `workflow_ref`); the DIRECT parent edge is emitted separately
/// as `parent_session_ref` by `direct_provider_facts` from
/// `SnapshotOrigin::parent_session_ref`. Facts are ordered most- to
/// least-load-bearing because the caller trims from the tail to stay inside the
/// bounded payload budget.
pub fn claude_subagent_facts(
    attribution: &ClaudeSubagentAttribution<'_>,
    source_session_id: &str,
    observed_at: &str,
    source_version: &str,
) -> Vec<SessionAttributionFact> {
    let mut facts = Vec::new();
    let evidence_context = EvidenceContext {
        source_session_id,
        observed_at,
        source_version,
    };
    push_fact(
        &mut facts,
        "root_session_ref",
        attribution.root_session_ref,
        "provider_native",
        "direct",
        &evidence_context,
    );
    // The sidecar is provider-written metadata rather than a transcript record,
    // so it is evidence of kind `provider_artifact` -- same classification the
    // workflow-orchestration footprint already uses.
    if let Some(agent_kind) = attribution.agent_kind {
        push_fact(
            &mut facts,
            "agent_kind",
            agent_kind,
            "provider_artifact",
            "direct",
            &evidence_context,
        );
    }
    if let Some(agent_ref) = attribution.agent_ref {
        push_fact(
            &mut facts,
            "agent_ref",
            agent_ref,
            "provider_native",
            "direct",
            &evidence_context,
        );
    }
    if let Some(workflow_ref) = attribution.workflow_ref {
        push_fact(
            &mut facts,
            "workflow_ref",
            workflow_ref,
            "provider_native",
            "direct",
            &evidence_context,
        );
    }
    if let Some(spawn_depth) = attribution.spawn_depth {
        push_fact(
            &mut facts,
            "spawn_depth",
            spawn_depth,
            "provider_artifact",
            "direct",
            &evidence_context,
        );
    }
    facts
}

/// Exact Codex family facts joined from `state_5.sqlite.thread_spawn_edges`.
///
/// The database supplies only provider-native thread ids and graph edges. No
/// prompt, title, command, path, or tool output enters this contract.
pub fn codex_subagent_facts(
    root_session_ref: &str,
    source_session_id: &str,
    spawn_depth: Option<u64>,
    observed_at: &str,
    source_version: &str,
) -> Vec<SessionAttributionFact> {
    let mut facts = Vec::new();
    let evidence_context = EvidenceContext {
        source_session_id,
        observed_at,
        source_version,
    };
    push_fact(
        &mut facts,
        "root_session_ref",
        root_session_ref,
        "provider_artifact",
        "direct",
        &evidence_context,
    );
    push_fact(
        &mut facts,
        "agent_kind",
        "codex_subagent",
        "provider_artifact",
        "direct",
        &evidence_context,
    );
    push_fact(
        &mut facts,
        "agent_ref",
        source_session_id,
        "provider_artifact",
        "direct",
        &evidence_context,
    );
    if let Some(spawn_depth) = spawn_depth {
        push_fact(
            &mut facts,
            "spawn_depth",
            &spawn_depth.to_string(),
            "provider_artifact",
            "direct",
            &evidence_context,
        );
    }
    enforce_fact_limits(&mut facts);
    facts
}

pub(crate) fn provider_surface(
    source: SnapshotSource,
    origin: Option<&SnapshotOrigin>,
) -> Option<&'static str> {
    match source {
        SnapshotSource::Codex => origin.and_then(codex_provider_surface),
        SnapshotSource::ClaudeCode => match origin.and_then(|value| value.entrypoint.as_deref()) {
            Some("claude-desktop") => Some("claude_desktop"),
            Some("cli") => Some("claude_cli"),
            Some("sdk-cli") => Some("claude_sdk"),
            _ => None,
        },
        SnapshotSource::Pi => Some("pi_cli"),
    }
}

fn codex_provider_surface(origin: &SnapshotOrigin) -> Option<&'static str> {
    let originator = origin.originator.as_deref().map(str::trim);
    if originator.is_some_and(|value| {
        value.eq_ignore_ascii_case("Codex Desktop")
            || value.eq_ignore_ascii_case("codex_work_desktop")
            || value.eq_ignore_ascii_case("codex_desktop")
    }) {
        return Some("codex_desktop");
    }
    if originator.is_some_and(|value| {
        value.eq_ignore_ascii_case("codex_cli_rs")
            || value.eq_ignore_ascii_case("codex-tui")
            || value.eq_ignore_ascii_case("codex_tui")
    }) {
        return Some("codex_cli");
    }
    if originator.is_some_and(|value| value.eq_ignore_ascii_case("codex_exec")) {
        return Some("codex_exec");
    }
    match origin.source.as_deref().map(str::trim) {
        Some(value)
            if value.eq_ignore_ascii_case("cli")
                || value.eq_ignore_ascii_case("codex_cli")
                || value.eq_ignore_ascii_case("codex_cli_rs") =>
        {
            Some("codex_cli")
        }
        Some(value)
            if value.eq_ignore_ascii_case("exec") || value.eq_ignore_ascii_case("codex_exec") =>
        {
            Some("codex_exec")
        }
        _ => None,
    }
}

/// Bound a fact list to the wire contract, reporting anything dropped.
///
/// Truncation is real attribution loss, so it must never be silent. At the
/// 8 KiB budget the `MAX_SESSION_ATTRIBUTION_FACTS` count cap is what normally
/// binds: one fact carries a mandatory `sha256:` evidence reference and costs
/// roughly 290 bytes, so a full 24-fact list lands near 7 KiB and fits. The byte
/// budget now only catches lists whose values crowd the
/// `MAX_SESSION_ATTRIBUTION_FACT_VALUE_BYTES` ceiling. Under both caps facts are
/// dropped from the tail, which is exactly where grouping evidence
/// (`template_group_id`, `schedule_definition_id`, `skill_id`) is appended after
/// the direct provider and subagent-identity facts, so a skill-heavy session
/// loses its grouping signals first.
///
/// Only field names and counts are reported. Fact values carry opaque
/// org-keyed identifiers and never belong in a log line.
pub(crate) fn enforce_fact_limits(facts: &mut Vec<SessionAttributionFact>) {
    let before = facts.len();
    let mut dropped_fields: Vec<String> = Vec::new();

    if facts.len() > MAX_SESSION_ATTRIBUTION_FACTS {
        dropped_fields.extend(
            facts[MAX_SESSION_ATTRIBUTION_FACTS..]
                .iter()
                .map(|fact| fact.field.clone()),
        );
        facts.truncate(MAX_SESSION_ATTRIBUTION_FACTS);
    }
    let over_count_cap = before - facts.len();

    while facts.len() > 1
        && serde_json::to_vec(facts)
            .map(|payload| payload.len() > MAX_SESSION_ATTRIBUTION_PAYLOAD_BYTES)
            .unwrap_or(true)
    {
        if let Some(fact) = facts.pop() {
            dropped_fields.push(fact.field);
        }
    }

    let dropped = before - facts.len();
    if dropped == 0 {
        return;
    }
    dropped_fields.sort();
    dropped_fields.dedup();
    eprintln!(
        "ottto-service: dropped {dropped} attribution fact(s) to fit the wire contract \
         ({over_count_cap} over the {MAX_SESSION_ATTRIBUTION_FACTS}-fact cap, {} over the \
         {MAX_SESSION_ATTRIBUTION_PAYLOAD_BYTES}-byte budget); kept {}; affected fields: {}. \
         Session attribution for this session is incomplete.",
        dropped - over_count_cap,
        facts.len(),
        dropped_fields.join(", "),
    );
}

pub(crate) fn strip_display_labels(facts: &mut [SessionAttributionFact]) -> bool {
    let mut changed = false;
    for fact in facts {
        if fact.display_label.take().is_some() {
            changed = true;
        }
        if fact.display_label_source.take().is_some() {
            changed = true;
        }
    }
    changed
}

pub(crate) fn validate_fact_limits(facts: &[SessionAttributionFact]) -> Result<(), String> {
    if facts.len() > MAX_SESSION_ATTRIBUTION_FACTS {
        return Err(format!(
            "more than {MAX_SESSION_ATTRIBUTION_FACTS} attribution facts"
        ));
    }
    if serde_json::to_vec(facts)
        .map(|payload| payload.len() > MAX_SESSION_ATTRIBUTION_PAYLOAD_BYTES)
        .unwrap_or(true)
    {
        return Err(format!(
            "attribution facts exceed {MAX_SESSION_ATTRIBUTION_PAYLOAD_BYTES} bytes"
        ));
    }
    for fact in facts {
        if fact.value.is_empty() || fact.value.len() > MAX_SESSION_ATTRIBUTION_FACT_VALUE_BYTES {
            return Err("attribution fact value is empty or oversized".to_string());
        }
        if fact.evidence.source_version.len() > MAX_SESSION_ATTRIBUTION_SOURCE_VERSION_BYTES
            || fact.evidence.evidence_ref.len() > MAX_SESSION_ATTRIBUTION_EVIDENCE_REF_BYTES
        {
            return Err("attribution evidence is oversized".to_string());
        }
        match (
            fact.display_label.as_deref(),
            fact.display_label_source.as_deref(),
        ) {
            (None, None) => {}
            (Some(label), Some(source)) => {
                if label.is_empty()
                    || label.len() > MAX_SESSION_ATTRIBUTION_DISPLAY_LABEL_BYTES
                    || label.chars().any(char::is_control)
                    || label.split_whitespace().any(looks_like_local_path)
                    || source.is_empty()
                    || source.len() > MAX_SESSION_ATTRIBUTION_DISPLAY_LABEL_SOURCE_BYTES
                {
                    return Err("attribution display label is unsafe or oversized".to_string());
                }
                let allowed = matches!(
                    (fact.field.as_str(), source),
                    ("template_group_id", "prompt_prefix") | ("skill_id", "skill_name")
                );
                if !allowed {
                    return Err("attribution display label source is invalid for field".to_string());
                }
            }
            _ => return Err("attribution display label is incomplete".to_string()),
        }
    }
    Ok(())
}

fn push_fact(
    facts: &mut Vec<SessionAttributionFact>,
    field: &str,
    value: &str,
    kind: &str,
    strength: &str,
    context: &EvidenceContext<'_>,
) {
    push_labeled_fact(facts, field, value, None, None, kind, strength, context);
}

#[allow(clippy::too_many_arguments)]
fn push_labeled_fact(
    facts: &mut Vec<SessionAttributionFact>,
    field: &str,
    value: &str,
    display_label: Option<&str>,
    display_label_source: Option<&str>,
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
    let (display_label, display_label_source) = match (display_label, display_label_source) {
        (Some(label), Some(source))
            if !label.is_empty()
                && label.len() <= MAX_SESSION_ATTRIBUTION_DISPLAY_LABEL_BYTES
                && !source.is_empty()
                && source.len() <= MAX_SESSION_ATTRIBUTION_DISPLAY_LABEL_SOURCE_BYTES =>
        {
            (Some(label.to_string()), Some(source.to_string()))
        }
        _ => (None, None),
    };
    facts.push(SessionAttributionFact {
        field: field.to_string(),
        value: value.to_string(),
        display_label,
        display_label_source,
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
    fn codex_provider_surface_recognizes_current_desktop_cli_and_exec_markers() {
        let cases = [
            ("codex_work_desktop", None, "codex_desktop"),
            ("codex_cli_rs", Some("vscode"), "codex_cli"),
            ("codex_exec", None, "codex_exec"),
        ];
        for (originator, source, expected) in cases {
            let mut origin = origin();
            origin.originator = Some(originator.to_string());
            origin.source = source.map(str::to_string);
            let facts = direct_provider_facts(
                SnapshotSource::Codex,
                Some(&origin),
                "surface-session",
                "2026-07-19T00:00:00Z",
                "codex_jsonl:v21",
            );
            assert!(facts.iter().any(|fact| {
                fact.field == "provider_surface"
                    && fact.value == expected
                    && fact.evidence.strength == "direct"
            }));
        }
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
    fn checkpoint_namespace_changes_only_with_key_epoch() {
        let context = SessionAttributionContext {
            key: Zeroizing::new(vec![1_u8; 32]),
            provider_schedules: ProviderScheduleInventory::default(),
            external_schedulers:
                crate::external_scheduler_attribution::ExternalSchedulerInventory::default(),
            launch_events: crate::launch_events::LaunchEventInventory::default(),
        };
        let rotated = SessionAttributionContext {
            key: Zeroizing::new(vec![2_u8; 32]),
            provider_schedules: ProviderScheduleInventory::default(),
            external_schedulers:
                crate::external_scheduler_attribution::ExternalSchedulerInventory::default(),
            launch_events: crate::launch_events::LaunchEventInventory::default(),
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
            launch_events: crate::launch_events::LaunchEventInventory::default(),
        };

        let namespace = context.checkpoint_namespace();
        assert_eq!(namespace.len(), 16);
        assert_ne!(namespace, rotated.checkpoint_namespace());
        assert_eq!(namespace, changed_inventory.checkpoint_namespace());
    }

    fn launch_context(events: Vec<crate::launch_events::LaunchEvent>) -> SessionAttributionContext {
        SessionAttributionContext {
            key: Zeroizing::new(vec![7_u8; 32]),
            provider_schedules: ProviderScheduleInventory::default(),
            external_schedulers:
                crate::external_scheduler_attribution::ExternalSchedulerInventory::default(),
            launch_events: crate::launch_events::LaunchEventInventory::from_events(events),
        }
    }

    fn launch_event() -> crate::launch_events::LaunchEvent {
        crate::launch_events::LaunchEvent {
            controller_session_ref: "a9789dcf-1e4a-4a6e-8abd-f30094efb269".to_string(),
            worker_session_ref: "019f6822-403f-7652-a308-b0c12142e337".to_string(),
            workflow_ref: "402d846d-c13c-4743-8326-580e4ca70e30".to_string(),
            agent_kind: "pr-fixer",
        }
    }

    #[test]
    fn launch_event_facts_state_the_controller_edge_as_direct_evidence() {
        let event = launch_event();
        let context = launch_context(vec![event.clone()]);

        let facts = context.launch_event_facts(&event.worker_session_ref, "2026-08-09T15:20:00Z");

        let by_field: BTreeMap<&str, &SessionAttributionFact> = facts
            .iter()
            .map(|fact| (fact.field.as_str(), fact))
            .collect();
        assert_eq!(
            by_field["parent_session_ref"].value,
            event.controller_session_ref
        );
        assert_eq!(by_field["workflow_ref"].value, event.workflow_ref);
        assert_eq!(by_field["origin_kind"].value, "agent_spawn");
        assert_eq!(by_field["agent_kind"].value, "pr-fixer");
        // Ordering is load-bearing: `enforce_fact_limits` trims from the tail,
        // so the edge itself must never be the first thing dropped.
        assert_eq!(facts[0].field, "parent_session_ref");
        for fact in &facts {
            assert_eq!(fact.evidence.strength, "direct");
            assert_eq!(fact.evidence.kind, "launcher_event");
            // The backend hard-rejects a source_version outside this shape, and
            // a raise there 422s the whole batch rather than one fact.
            assert_eq!(fact.evidence.source_version, "launcher_event:v1");
            assert!(fact.evidence.evidence_ref.starts_with("sha256:"));
            assert!(fact.display_label.is_none());
            assert!(fact.display_label_source.is_none());
        }
        validate_fact_limits(&facts).expect("launch facts fit the wire contract");
    }

    #[test]
    fn a_session_with_no_launch_event_gets_no_launch_facts() {
        let context = launch_context(vec![launch_event()]);

        assert!(context
            .launch_event_facts(
                "11111111-2222-3333-4444-555555555555",
                "2026-08-09T15:20:00Z"
            )
            .is_empty());
        assert!(launch_context(Vec::new())
            .launch_event_facts(&launch_event().worker_session_ref, "2026-08-09T15:20:00Z")
            .is_empty());
    }

    #[test]
    fn legacy_cache_namespace_still_identifies_exact_upgrade_source() {
        let context = SessionAttributionContext {
            key: Zeroizing::new(vec![1_u8; 32]),
            provider_schedules: ProviderScheduleInventory::default(),
            external_schedulers:
                crate::external_scheduler_attribution::ExternalSchedulerInventory::default(),
            launch_events: crate::launch_events::LaunchEventInventory::default(),
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
            launch_events: crate::launch_events::LaunchEventInventory::default(),
        };

        let namespace = context.legacy_cache_namespace();
        assert_ne!(namespace, changed_inventory.legacy_cache_namespace());
        assert!(!changed_inventory
            .legacy_cache_namespace()
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
    fn template_normalization_rejects_injected_prompt_scaffolding() {
        assert_eq!(
            normalize_template_material(
                "# AGENTS.md instructions for /repo\n\
                 <INSTRUCTIONS>Shared agent setup</INSTRUCTIONS>\n\
                 <environment_context><cwd>/repo</cwd></environment_context>"
            ),
            None
        );
    }

    #[test]
    fn template_normalization_keeps_human_prompts_that_mention_markers() {
        assert_eq!(
            normalize_template_material(
                "Update the AGENTS.md instructions and parse the current date: field"
            )
            .as_deref(),
            Some("update the agents.md instructions and parse the current date: field")
        );
    }

    #[test]
    fn template_normalization_keeps_task_after_injected_prefix() {
        assert_eq!(
            normalize_template_material(
                "<recommended_plugins>Plugins</recommended_plugins>\n\
                 # AGENTS.md instructions for /repo\n\
                 <INSTRUCTIONS>Shared setup</INSTRUCTIONS>\n\
                 <environment_context><cwd>/repo</cwd></environment_context>\n\
                 Explain how this XML is parsed"
            )
            .as_deref(),
            Some("explain how this xml is parsed")
        );
    }

    #[test]
    fn grouping_facts_keep_opaque_ids_and_bounded_private_labels_separate() {
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
            launch_events: crate::launch_events::LaunchEventInventory::default(),
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
        assert!(facts.iter().any(|fact| {
            fact.field == "template_group_id"
                && fact.display_label.as_deref() == Some(scheduled_prompt)
                && fact.display_label_source.as_deref() == Some("prompt_prefix")
        }));
        assert!(facts.iter().any(|fact| {
            fact.field == "skill_id"
                && fact.display_label.as_deref() == Some("landing-lander")
                && fact.display_label_source.as_deref() == Some("skill_name")
        }));
        assert!(facts.iter().all(|fact| {
            fact.value.starts_with("hmac-sha256:v1:")
                || !matches!(
                    fact.field.as_str(),
                    "template_group_id" | "schedule_definition_id" | "skill_id"
                )
        }));
        let wire = serde_json::to_string(&facts).expect("facts");
        assert!(wire.contains("landing-lander"));
        assert!(wire.contains("Inspect the landing queue"));
        assert!(wire.len() <= MAX_SESSION_ATTRIBUTION_PAYLOAD_BYTES);
    }

    #[test]
    fn prompt_prefix_label_is_bounded_single_line_and_redacts_paths() {
        let label = prompt_prefix_display_label(
            "An automation named Review has fired. Its prompt is:\nInspect /Users/alice/secret/repo, C:\\work\\private, and src/internal/config.rs then report a concise result that keeps going beyond the display limit until it is truncated.",
        )
        .expect("display label");

        assert!(label.starts_with("Inspect [path] [path] and [path]"));
        assert!(!label.contains("alice"));
        assert!(!label.contains("private"));
        assert!(!label.contains('\n'));
        assert!(label.len() <= MAX_SESSION_ATTRIBUTION_DISPLAY_LABEL_BYTES);
    }

    #[test]
    fn prompt_prefix_label_omits_private_scaffolding_and_keeps_slash_skills() {
        assert_eq!(
            prompt_prefix_display_label("# AGENTS.md instructions for /private/repo"),
            None
        );
        assert_eq!(
            prompt_prefix_display_label("/frontend-flow-change improve the filter"),
            Some("/frontend-flow-change improve the filter".to_string())
        );
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

    fn budget_fact(field: &str) -> SessionAttributionFact {
        SessionAttributionFact {
            field: field.to_string(),
            value: "b".repeat(32),
            display_label: None,
            display_label_source: None,
            evidence: SessionFieldEvidence {
                kind: "provider_native".to_string(),
                strength: "direct".to_string(),
                observed_at: "2026-07-26T07:20:49Z".to_string(),
                source_version: "claude_code_jsonl:v19".to_string(),
                evidence_ref: format!("sha256:{}", "a".repeat(64)),
            },
        }
    }

    /// A fact whose value sits exactly on the per-value ceiling.
    ///
    /// At 8 KiB an ordinary `budget_fact` can no longer reach the byte budget
    /// before the 24-fact count cap does — that ordering is the point of the
    /// raise. Probing the byte budget therefore needs the widest fact the
    /// contract still accepts, which is the only shape that can still exhaust
    /// the payload budget inside the count cap.
    fn wide_budget_fact(field: &str) -> SessionAttributionFact {
        SessionAttributionFact {
            value: "w".repeat(MAX_SESSION_ATTRIBUTION_FACT_VALUE_BYTES),
            ..budget_fact(field)
        }
    }

    fn fits_wire_budget(facts: &[SessionAttributionFact]) -> bool {
        serde_json::to_vec(facts).expect("serialize").len() <= MAX_SESSION_ATTRIBUTION_PAYLOAD_BYTES
    }

    /// The count cap binds before the byte budget for ordinary facts.
    ///
    /// This is the invariant the 8 KiB budget is chosen to produce, and the
    /// reason several tests below must use `wide_budget_fact` to reach the byte
    /// budget at all. Pinned once here so a future budget change that quietly
    /// reverses the ordering fails loudly instead of turning the count-cap tests
    /// into byte-budget tests.
    #[test]
    fn the_fact_count_cap_binds_before_the_byte_budget_for_ordinary_facts() {
        let full: Vec<SessionAttributionFact> = (0..MAX_SESSION_ATTRIBUTION_FACTS)
            .map(|_| budget_fact("skill_id"))
            .collect();

        assert!(
            fits_wire_budget(&full),
            "a full {MAX_SESSION_ATTRIBUTION_FACTS}-fact list of ordinary facts must fit in \
             {MAX_SESSION_ATTRIBUTION_PAYLOAD_BYTES} bytes"
        );
        // The byte budget must still be reachable by pathological values, or it
        // would be dead code rather than a backstop.
        let wide: Vec<SessionAttributionFact> = (0..MAX_SESSION_ATTRIBUTION_FACTS)
            .map(|_| wide_budget_fact("skill_id"))
            .collect();
        assert!(
            !fits_wire_budget(&wide),
            "values at the {MAX_SESSION_ATTRIBUTION_FACT_VALUE_BYTES}-byte ceiling must still be \
             able to exhaust the payload budget"
        );
    }

    #[test]
    fn enforce_fact_limits_keeps_a_within_budget_list_intact() {
        let mut facts = vec![
            budget_fact("origin_kind"),
            budget_fact("provider_surface"),
            budget_fact("execution_mode"),
        ];
        assert!(fits_wire_budget(&facts));

        enforce_fact_limits(&mut facts);

        assert_eq!(facts.len(), 3);
        assert!(fits_wire_budget(&facts));
    }

    #[test]
    fn enforce_fact_limits_drops_trailing_grouping_facts_over_the_byte_budget() {
        // When the byte budget does bind, facts are dropped from the tail, so a
        // skill-heavy session loses the grouping evidence appended after its
        // direct provider facts. At 8 KiB only values at the per-value ceiling
        // can reach the byte budget inside the 24-fact cap, so the list is built
        // from `wide_budget_fact`. It grows to the first over-budget length
        // rather than a hardcoded count so the test keeps testing the byte
        // budget when it next moves.
        let mut facts = vec![
            wide_budget_fact("origin_kind"),
            wide_budget_fact("provider_surface"),
            wide_budget_fact("execution_mode"),
            wide_budget_fact("template_group_id"),
        ];
        while fits_wire_budget(&facts) && facts.len() < MAX_SESSION_ATTRIBUTION_FACTS {
            facts.push(wide_budget_fact("skill_id"));
        }
        let skills_before = facts.iter().filter(|fact| fact.field == "skill_id").count();
        let before = facts.len();
        assert!(
            before < MAX_SESSION_ATTRIBUTION_FACTS,
            "the byte budget must bind before the {MAX_SESSION_ATTRIBUTION_FACTS}-fact cap"
        );
        assert!(!fits_wire_budget(&facts));

        enforce_fact_limits(&mut facts);

        assert!(facts.len() < before);
        assert!(fits_wire_budget(&facts));
        // Truncation is tail-first, so the leading direct provider facts survive
        // intact while the trailing skill evidence is what actually gets lost.
        assert_eq!(facts[0].field, "origin_kind");
        assert_eq!(facts[1].field, "provider_surface");
        assert_eq!(facts[2].field, "execution_mode");
        assert_eq!(facts[3].field, "template_group_id");
        let surviving_skills = facts.iter().filter(|fact| fact.field == "skill_id").count();
        assert!(
            surviving_skills < skills_before,
            "expected skill evidence to be dropped"
        );
    }

    /// The near-limit attribution case of the two-language fixture corpus.
    ///
    /// This is the exact shape that produced the 422 at the old 2 KiB budget, so
    /// it is the one case both implementations must agree on byte-for-byte: the
    /// daemon must emit it and the backend must accept it. The facts are carried
    /// verbatim (synthetic values only) so the other language can replay the
    /// payload instead of reconstructing a guess at it.
    #[test]
    fn attribution_budget_corpus_pins_the_near_limit_payload() {
        const RETIRED_PAYLOAD_BUDGET_BYTES: usize = 2_048;
        const PREVIOUS_PAYLOAD_BUDGET_BYTES: usize = 4_096;
        fn case(facts: &[SessionAttributionFact]) -> serde_json::Value {
            let payload = serde_json::to_vec(facts).expect("serialize");
            let mut digest = Sha256::new();
            digest.update(&payload);
            serde_json::json!({
                "fact_count": facts.len(),
                "payload_bytes": payload.len(),
                "payload_sha256": format!("{:x}", digest.finalize()),
                "accepted_by_retired_budget":
                    payload.len() <= RETIRED_PAYLOAD_BUDGET_BYTES,
                "accepted_by_previous_budget":
                    payload.len() <= PREVIOUS_PAYLOAD_BUDGET_BYTES,
                "accepted_by_current_budget":
                    payload.len() <= MAX_SESSION_ATTRIBUTION_PAYLOAD_BYTES,
                "facts": facts,
            })
        }

        let mut facts = vec![
            budget_fact("origin_kind"),
            budget_fact("provider_surface"),
            budget_fact("execution_mode"),
            budget_fact("template_group_id"),
        ];
        // First list that the retired 2 KiB budget refused: the original
        // regression, and still accepted today.
        while serde_json::to_vec(&facts).expect("serialize").len() <= RETIRED_PAYLOAD_BUDGET_BYTES {
            facts.push(budget_fact("skill_id"));
        }
        let over_retired = facts.clone();
        // First list the superseded 4 KiB budget refused: the band this raise
        // newly admits, and the one the deployed backend already accepts.
        while serde_json::to_vec(&facts).expect("serialize").len() <= PREVIOUS_PAYLOAD_BUDGET_BYTES
        {
            facts.push(budget_fact("skill_id"));
        }
        let over_previous = facts.clone();
        // Largest list the current budget still accepts: the acceptance
        // boundary. One more fact must 422, and that is the whole value of the
        // case — a budget nobody probes at its edge is a budget nobody agrees
        // on. Ordinary facts can no longer reach that edge inside the 24-fact
        // cap, so the boundary cases carry values at the per-value ceiling.
        let mut near_limit = vec![
            wide_budget_fact("origin_kind"),
            wide_budget_fact("provider_surface"),
            wide_budget_fact("execution_mode"),
            wide_budget_fact("template_group_id"),
        ];
        loop {
            let mut candidate = near_limit.clone();
            candidate.push(wide_budget_fact("skill_id"));
            if serde_json::to_vec(&candidate).expect("serialize").len()
                > MAX_SESSION_ATTRIBUTION_PAYLOAD_BYTES
            {
                break;
            }
            near_limit = candidate;
        }
        let mut over_current = near_limit.clone();
        over_current.push(wide_budget_fact("skill_id"));

        let actual = serde_json::json!({
            "schema_version": "attribution_budget_golden:v2",
            "attribution_schema_version": SESSION_ATTRIBUTION_SCHEMA_VERSION,
            "max_payload_bytes": MAX_SESSION_ATTRIBUTION_PAYLOAD_BYTES,
            "previous_max_payload_bytes": PREVIOUS_PAYLOAD_BUDGET_BYTES,
            "retired_max_payload_bytes": RETIRED_PAYLOAD_BUDGET_BYTES,
            "max_facts": MAX_SESSION_ATTRIBUTION_FACTS,
            "max_fact_value_bytes": MAX_SESSION_ATTRIBUTION_FACT_VALUE_BYTES,
            "over_retired_budget_case": case(&over_retired),
            "over_previous_budget_case": case(&over_previous),
            "near_limit_case": case(&near_limit),
            "over_current_budget_case": case(&over_current),
        });
        if std::env::var_os("UPDATE_ATTRIBUTION_BUDGET_GOLDEN").is_some() {
            fs::write(
                Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("../../fixtures/snapshot-audit/attribution-budget-golden.json"),
                format!(
                    "{}\n",
                    serde_json::to_string_pretty(&actual).expect("serialize golden")
                ),
            )
            .expect("write attribution budget golden");
        }
        let expected: serde_json::Value = serde_json::from_str(include_str!(
            "../../../fixtures/snapshot-audit/attribution-budget-golden.json"
        ))
        .expect("parse attribution budget golden");
        assert_eq!(actual, expected);
        assert!(over_previous.len() > over_retired.len());
        assert!(near_limit.len() <= MAX_SESSION_ATTRIBUTION_FACTS);
        validate_fact_limits(&over_retired).expect("over-retired payload is valid now");
        validate_fact_limits(&over_previous).expect("over-previous payload is valid now");
        validate_fact_limits(&near_limit).expect("near-limit payload is valid");
        // The refusal must come from the byte budget, not the count cap, or the
        // corpus would stop describing the budget it claims to pin.
        assert!(
            over_current.len() <= MAX_SESSION_ATTRIBUTION_FACTS,
            "the over-budget case must stay inside the fact-count cap"
        );
        let refusal =
            validate_fact_limits(&over_current).expect_err("one fact past the budget must fail");
        assert!(
            refusal.contains(&MAX_SESSION_ATTRIBUTION_PAYLOAD_BYTES.to_string()),
            "expected a byte-budget refusal, got: {refusal}"
        );
    }

    #[test]
    fn the_raised_byte_budget_keeps_a_list_the_old_budget_would_have_trimmed() {
        // The regression each raise fixes: a fact list above a superseded
        // ceiling used to lose its tail. Grown past the most recent superseded
        // budget (4 KiB), so it also covers the older 2 KiB one. Nothing is
        // trimmed now.
        const RETIRED_PAYLOAD_BUDGET_BYTES: usize = 2_048;
        const PREVIOUS_PAYLOAD_BUDGET_BYTES: usize = 4_096;
        let mut facts = vec![
            budget_fact("origin_kind"),
            budget_fact("provider_surface"),
            budget_fact("execution_mode"),
            budget_fact("template_group_id"),
        ];
        while serde_json::to_vec(&facts).expect("serialize").len() <= PREVIOUS_PAYLOAD_BUDGET_BYTES
        {
            facts.push(budget_fact("skill_id"));
        }
        let payload_bytes = serde_json::to_vec(&facts).expect("serialize").len();
        assert!(payload_bytes > RETIRED_PAYLOAD_BUDGET_BYTES);
        assert!(payload_bytes > PREVIOUS_PAYLOAD_BUDGET_BYTES);
        assert!(payload_bytes <= MAX_SESSION_ATTRIBUTION_PAYLOAD_BYTES);
        let before = facts.len();

        enforce_fact_limits(&mut facts);

        assert_eq!(facts.len(), before);
        validate_fact_limits(&facts).expect("near-limit list is valid");
    }

    #[test]
    fn enforce_fact_limits_applies_the_count_cap_before_the_byte_budget() {
        let mut facts: Vec<SessionAttributionFact> = (0..MAX_SESSION_ATTRIBUTION_FACTS + 5)
            .map(|_| budget_fact("skill_id"))
            .collect();

        enforce_fact_limits(&mut facts);

        assert!(facts.len() <= MAX_SESSION_ATTRIBUTION_FACTS);
        assert!(fits_wire_budget(&facts));
    }
}
