//! Lightweight, privacy-safe external scheduler correlation.
//!
//! Inventory is local-only and cached for a day. Definitions are reduced to
//! opaque ids, schedule constraints, provider hints, short prompt signatures,
//! and privacy-safe repository hashes. Raw plist/crontab/script text and paths
//! never enter a session fact.

use crate::context_footprint::resolve_repository_identity;
use crate::session_attribution::{normalize_template_material, opaque_hmac_id};
use crate::snapshots::SnapshotSource;
use plist::{Dictionary, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
#[cfg(any(target_os = "macos", test))]
use std::process::Command;
#[cfg(target_os = "macos")]
use std::process::Stdio;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};
use time::{format_description::well_known::Rfc3339, OffsetDateTime, UtcOffset};

const INVENTORY_TTL: Duration = Duration::from_secs(24 * 60 * 60);
const MAX_LAUNCHD_FILES: usize = 256;
const MAX_LAUNCHD_FILE_BYTES: u64 = 128 * 1_024;
const MAX_WRAPPER_FILES_PER_REFRESH: usize = 32;
const MAX_WRAPPER_FILE_BYTES: u64 = 128 * 1_024;
const MAX_PROMPT_SIGNATURE_CHARS: usize = 96;
const MIN_PROMPT_SIGNATURE_CHARS: usize = 24;
#[cfg(target_os = "macos")]
const MAX_CRONTAB_BYTES: usize = 256 * 1_024;
#[cfg(target_os = "macos")]
const MAX_LIVE_CANDIDATES: usize = 4;
#[cfg(target_os = "macos")]
const MAX_ANCESTOR_DEPTH: usize = 8;
#[cfg(target_os = "macos")]
const MAX_PROCESS_TABLE_BYTES: usize = 1024 * 1024;
#[cfg(target_os = "macos")]
const LOCAL_COMMAND_TIMEOUT: Duration = Duration::from_secs(1);

#[derive(Clone, Default)]
pub(crate) struct ExternalSchedulerInventory {
    definitions: Vec<ExternalSchedulerDefinition>,
}

#[derive(Clone)]
struct ExternalSchedulerDefinition {
    scheduler_kind: ExternalSchedulerKind,
    opaque_id: String,
    launchd_label: Option<String>,
    provider_source: Option<SnapshotSource>,
    prompt_signature: Option<String>,
    repository_hash: Option<String>,
    schedule: ScheduleConstraint,
}

/// Platform adapter discriminator. Future systemd, Windows Task Scheduler, and
/// CI adapters add a variant and inventory loader while reusing the same
/// evidence threshold and privacy-safe match output.
#[derive(Clone, Copy, PartialEq, Eq)]
enum ExternalSchedulerKind {
    Launchd,
    Cron,
}

impl ExternalSchedulerKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Launchd => "launchd",
            Self::Cron => "cron",
        }
    }
}

#[derive(Clone, Default)]
struct ScheduleConstraint {
    calendar: Vec<CalendarConstraint>,
}

#[derive(Clone, Default)]
struct CalendarConstraint {
    minute: Option<u8>,
    hour: Option<u8>,
    weekday: Option<u8>,
    day: Option<u8>,
    month: Option<u8>,
}

#[derive(Clone)]
struct CachedDefinitionFile {
    size_bytes: u64,
    modified_unix_nanos: u128,
    definition: Option<ExternalSchedulerDefinition>,
}

struct CachedInventory {
    loaded_at: Instant,
    home: PathBuf,
    key_fingerprint: String,
    inventory: ExternalSchedulerInventory,
    launchd_files: BTreeMap<PathBuf, CachedDefinitionFile>,
    crontab_digest: Option<String>,
    crontab_definitions: Vec<ExternalSchedulerDefinition>,
}

pub(crate) struct ExternalSchedulerMatch {
    pub(crate) scheduler_kind: &'static str,
    pub(crate) schedule_definition_id: String,
    pub(crate) evidence_kind: &'static str,
    pub(crate) evidence_strength: &'static str,
}

#[derive(Clone, Copy)]
pub(crate) struct ExternalSchedulerSession<'a> {
    pub(crate) source: SnapshotSource,
    pub(crate) normalized_template: Option<&'a str>,
    pub(crate) repository_hash: Option<&'a str>,
    pub(crate) source_started_at: Option<&'a str>,
    pub(crate) transcript_path: &'a Path,
}

impl ExternalSchedulerInventory {
    pub(crate) fn cached(home: &Path, key: &[u8]) -> Self {
        static CACHE: OnceLock<Mutex<Option<CachedInventory>>> = OnceLock::new();
        let cache = CACHE.get_or_init(|| Mutex::new(None));
        let key_fingerprint = sha256_hex(key);
        let (previous_files, previous_crontab_digest, previous_crontab_definitions) =
            if let Ok(guard) = cache.lock() {
                if let Some(cached) = guard.as_ref() {
                    if cached.home == home
                        && cached.key_fingerprint == key_fingerprint
                        && cached.loaded_at.elapsed() < INVENTORY_TTL
                    {
                        return cached.inventory.clone();
                    }
                    if cached.home == home && cached.key_fingerprint == key_fingerprint {
                        (
                            cached.launchd_files.clone(),
                            cached.crontab_digest.clone(),
                            cached.crontab_definitions.clone(),
                        )
                    } else {
                        (BTreeMap::new(), None, Vec::new())
                    }
                } else {
                    (BTreeMap::new(), None, Vec::new())
                }
            } else {
                (BTreeMap::new(), None, Vec::new())
            };

        let (mut definitions, launchd_files) =
            refresh_launchd_inventory(home, key, &previous_files);
        let (crontab_digest, crontab_definitions) =
            refresh_crontab_inventory(key, previous_crontab_digest, previous_crontab_definitions);
        definitions.extend(crontab_definitions.clone());
        definitions.sort_by(|left, right| left.opaque_id.cmp(&right.opaque_id));
        definitions.dedup_by(|left, right| left.opaque_id == right.opaque_id);
        let inventory = Self { definitions };
        if let Ok(mut guard) = cache.lock() {
            *guard = Some(CachedInventory {
                loaded_at: Instant::now(),
                home: home.to_path_buf(),
                key_fingerprint,
                inventory: inventory.clone(),
                launchd_files,
                crontab_digest,
                crontab_definitions,
            });
        }
        inventory
    }

    pub(crate) fn correlate(
        &self,
        session: ExternalSchedulerSession<'_>,
    ) -> Option<ExternalSchedulerMatch> {
        self.correlate_with_live_labels(session, &live_launchd_labels(self, &session))
    }

    fn correlate_with_live_labels(
        &self,
        session: ExternalSchedulerSession<'_>,
        live_labels: &BTreeSet<String>,
    ) -> Option<ExternalSchedulerMatch> {
        let started_at = session
            .source_started_at
            .and_then(|value| OffsetDateTime::parse(value, &Rfc3339).ok())
            .map(local_schedule_time);
        let mut best: Option<(&ExternalSchedulerDefinition, u8, bool)> = None;
        let mut ambiguous = false;

        for definition in &self.definitions {
            let provider_matches = definition
                .provider_source
                .map(|source| source == session.source)
                .unwrap_or(false);
            if definition.provider_source.is_some() && !provider_matches {
                continue;
            }
            let prompt_matches = definition
                .prompt_signature
                .as_deref()
                .zip(session.normalized_template)
                .map(|(signature, template)| {
                    signature.chars().count() >= MIN_PROMPT_SIGNATURE_CHARS
                        && template.contains(signature)
                })
                .unwrap_or(false);
            let repository_matches = definition
                .repository_hash
                .as_deref()
                .zip(session.repository_hash)
                .map(|(left, right)| left == right)
                .unwrap_or(false);
            let time_matches = started_at
                .map(|value| definition.schedule.matches(value))
                .unwrap_or(false);
            let live_matches = definition
                .launchd_label
                .as_ref()
                .map(|label| live_labels.contains(label))
                .unwrap_or(false);

            // A live job PID tied to the transcript is direct evidence, but
            // still requires one definition/session correlation signal.
            let live_qualified =
                live_matches && (provider_matches || prompt_matches || repository_matches);
            // Static evidence requires a schedule-time match plus every
            // available identity dimension. An interval alone has no phase
            // anchor and never passes.
            let static_signal_count = u8::from(provider_matches)
                + u8::from(prompt_matches)
                + u8::from(repository_matches);
            // Only calendar/cron constraints anchor a wall-clock start.
            // launchd StartInterval has no stable phase and cannot qualify
            // without live PID evidence. Static correlation also requires the
            // prompt signature, provider, and repository; any two plus a
            // coincident time can still describe a manual session.
            let static_qualified = time_matches
                && !definition.schedule.calendar.is_empty()
                && prompt_matches
                && provider_matches
                && repository_matches;
            if !live_qualified && !static_qualified {
                continue;
            }
            let score = if live_qualified {
                100 + static_signal_count
            } else {
                10 + static_signal_count
            };
            match best {
                None => {
                    best = Some((definition, score, live_qualified));
                    ambiguous = false;
                }
                Some((_, current_score, _)) if score > current_score => {
                    best = Some((definition, score, live_qualified));
                    ambiguous = false;
                }
                Some((current, current_score, _))
                    if score == current_score && current.opaque_id != definition.opaque_id =>
                {
                    ambiguous = true;
                }
                _ => {}
            }
        }

        let (definition, _, live) = (!ambiguous).then_some(best).flatten()?;
        Some(ExternalSchedulerMatch {
            scheduler_kind: definition.scheduler_kind.as_str(),
            schedule_definition_id: definition.opaque_id.clone(),
            evidence_kind: if live {
                "live_process"
            } else {
                "scheduler_inventory"
            },
            evidence_strength: if live { "direct" } else { "corroborated" },
        })
    }

    #[cfg(target_os = "macos")]
    fn candidate_launchd_labels(&self, session: &ExternalSchedulerSession<'_>) -> Vec<&str> {
        self.definitions
            .iter()
            .filter(|definition| definition.scheduler_kind == ExternalSchedulerKind::Launchd)
            .filter(|definition| {
                definition
                    .provider_source
                    .map(|source| source == session.source)
                    .unwrap_or(true)
            })
            .filter(|definition| {
                let prompt_matches = definition
                    .prompt_signature
                    .as_deref()
                    .zip(session.normalized_template)
                    .map(|(signature, template)| template.contains(signature))
                    .unwrap_or(false);
                let repository_matches = definition
                    .repository_hash
                    .as_deref()
                    .zip(session.repository_hash)
                    .map(|(left, right)| left == right)
                    .unwrap_or(false);
                prompt_matches || repository_matches
            })
            .filter_map(|definition| definition.launchd_label.as_deref())
            .take(MAX_LIVE_CANDIDATES)
            .collect()
    }
}

fn refresh_launchd_inventory(
    home: &Path,
    key: &[u8],
    previous: &BTreeMap<PathBuf, CachedDefinitionFile>,
) -> (
    Vec<ExternalSchedulerDefinition>,
    BTreeMap<PathBuf, CachedDefinitionFile>,
) {
    let mut paths = Vec::new();
    collect_plists(&home.join("Library/LaunchAgents"), &mut paths);
    collect_plists(Path::new("/Library/LaunchAgents"), &mut paths);
    paths.sort();
    paths.dedup();
    paths.truncate(MAX_LAUNCHD_FILES);

    let mut definitions = Vec::new();
    let mut files = BTreeMap::new();
    let mut wrapper_budget = MAX_WRAPPER_FILES_PER_REFRESH;
    for path in paths {
        let Ok(metadata) = fs::symlink_metadata(&path) else {
            continue;
        };
        if metadata.file_type().is_symlink()
            || !metadata.is_file()
            || metadata.len() > MAX_LAUNCHD_FILE_BYTES
        {
            continue;
        }
        let modified_unix_nanos = metadata
            .modified()
            .ok()
            .and_then(|value| value.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|value| value.as_nanos())
            .unwrap_or_default();
        let definition = previous
            .get(&path)
            .filter(|cached| {
                cached.size_bytes == metadata.len()
                    && cached.modified_unix_nanos == modified_unix_nanos
            })
            .map(|cached| cached.definition.clone())
            .unwrap_or_else(|| parse_launchd_definition(&path, key, &mut wrapper_budget));
        if let Some(definition) = definition.as_ref() {
            definitions.push(definition.clone());
        }
        files.insert(
            path,
            CachedDefinitionFile {
                size_bytes: metadata.len(),
                modified_unix_nanos,
                definition,
            },
        );
    }
    (definitions, files)
}

fn collect_plists(root: &Path, paths: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(root) else {
        return;
    };
    paths.extend(
        entries
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| path.extension().and_then(|value| value.to_str()) == Some("plist")),
    );
}

fn parse_launchd_definition(
    path: &Path,
    key: &[u8],
    wrapper_budget: &mut usize,
) -> Option<ExternalSchedulerDefinition> {
    let value = Value::from_file(path).ok()?;
    let root = value.as_dictionary()?;
    let label = root.get("Label")?.as_string()?.trim();
    if label.is_empty() || label.len() > 256 {
        return None;
    }
    let arguments = launchd_arguments(root);
    let mut command_material = arguments.join(" ");
    let mut referenced_path = referenced_local_file(&arguments);
    if let Some(wrapper_path) = referenced_path.as_deref() {
        if *wrapper_budget > 0 {
            if let Some(wrapper) = read_bounded_text(wrapper_path, MAX_WRAPPER_FILE_BYTES) {
                command_material.push('\n');
                command_material.push_str(&wrapper);
                *wrapper_budget -= 1;
            }
        }
    }
    let (provider_source, prompt_signature) = provider_and_prompt_signature(&command_material);
    let workspace_path = root
        .get("WorkingDirectory")
        .and_then(Value::as_string)
        .map(PathBuf::from)
        .or_else(|| {
            referenced_path
                .take()
                .and_then(|value| value.parent().map(Path::to_path_buf))
        });
    let repository_hash = workspace_path
        .as_deref()
        .and_then(|workspace| resolve_repository_identity(workspace, false).repository_hash);
    let schedule = launchd_schedule(root);
    let opaque_id = opaque_hmac_id(key, "external_schedule_definition", label)?;
    Some(ExternalSchedulerDefinition {
        scheduler_kind: ExternalSchedulerKind::Launchd,
        opaque_id,
        launchd_label: Some(label.to_string()),
        provider_source,
        prompt_signature,
        repository_hash,
        schedule,
    })
}

fn launchd_arguments(root: &Dictionary) -> Vec<String> {
    let mut values = Vec::new();
    if let Some(program) = root.get("Program").and_then(Value::as_string) {
        values.push(program.chars().take(4096).collect());
    }
    if let Some(arguments) = root.get("ProgramArguments").and_then(Value::as_array) {
        values.extend(
            arguments
                .iter()
                .filter_map(Value::as_string)
                .take(64)
                .map(|value| value.chars().take(4096).collect()),
        );
    }
    values
}

fn referenced_local_file(arguments: &[String]) -> Option<PathBuf> {
    let candidates = arguments
        .iter()
        // The first value is the launch executable itself. Inspect only an
        // explicitly referenced wrapper/config argument, never /bin/sh or the
        // provider binary.
        .skip(1)
        .map(PathBuf::from)
        .filter(|path| path.is_absolute() && path.is_file())
        .collect::<Vec<_>>();
    candidates
        .iter()
        .rev()
        .find(|path| {
            matches!(
                path.extension().and_then(|value| value.to_str()),
                Some("sh" | "bash" | "zsh" | "py" | "js" | "ts" | "rb" | "pl")
            )
        })
        .cloned()
        .or_else(|| {
            candidates
                .into_iter()
                .rev()
                .find(|path| !matches!(path.to_str(), Some("/bin/sh" | "/bin/bash" | "/bin/zsh")))
        })
}

fn launchd_schedule(root: &Dictionary) -> ScheduleConstraint {
    let mut schedule = ScheduleConstraint::default();
    if let Some(value) = root.get("StartCalendarInterval") {
        if let Some(dictionary) = value.as_dictionary() {
            schedule.calendar.push(calendar_from_dictionary(dictionary));
        } else if let Some(values) = value.as_array() {
            schedule.calendar.extend(
                values
                    .iter()
                    .filter_map(Value::as_dictionary)
                    .map(calendar_from_dictionary),
            );
        }
    }
    schedule
}

fn calendar_from_dictionary(value: &Dictionary) -> CalendarConstraint {
    CalendarConstraint {
        minute: bounded_calendar_value(value, "Minute", 0, 59),
        hour: bounded_calendar_value(value, "Hour", 0, 23),
        weekday: bounded_calendar_value(value, "Weekday", 0, 7),
        day: bounded_calendar_value(value, "Day", 1, 31),
        month: bounded_calendar_value(value, "Month", 1, 12),
    }
}

fn bounded_calendar_value(value: &Dictionary, key: &str, minimum: i64, maximum: i64) -> Option<u8> {
    let parsed = value.get(key).and_then(value_integer)?;
    (minimum..=maximum)
        .contains(&parsed)
        .then_some(parsed as u8)
}

fn value_integer(value: &Value) -> Option<i64> {
    match value {
        Value::Integer(value) => value.as_signed(),
        _ => None,
    }
}

fn refresh_crontab_inventory(
    key: &[u8],
    previous_digest: Option<String>,
    previous_definitions: Vec<ExternalSchedulerDefinition>,
) -> (Option<String>, Vec<ExternalSchedulerDefinition>) {
    #[cfg(not(target_os = "macos"))]
    {
        let _ = key;
        return (previous_digest, previous_definitions);
    }
    #[cfg(target_os = "macos")]
    {
        let Some(raw) = read_user_crontab() else {
            return (None, Vec::new());
        };
        let digest = sha256_hex(raw.as_bytes());
        if previous_digest.as_deref() == Some(&digest) {
            return (Some(digest), previous_definitions);
        }
        let definitions = parse_crontab(&raw, key);
        (Some(digest), definitions)
    }
}

#[cfg(target_os = "macos")]
fn read_user_crontab() -> Option<String> {
    bounded_command_stdout("/usr/bin/crontab", &["-l"], MAX_CRONTAB_BYTES)
        .and_then(|value| String::from_utf8(value).ok())
}

#[cfg(any(target_os = "macos", test))]
fn parse_crontab(raw: &str, key: &[u8]) -> Vec<ExternalSchedulerDefinition> {
    raw.lines()
        .filter_map(|line| parse_crontab_line(line, key))
        .take(256)
        .collect()
}

#[cfg(any(target_os = "macos", test))]
fn parse_crontab_line(line: &str, key: &[u8]) -> Option<ExternalSchedulerDefinition> {
    let trimmed = line.trim();
    if trimmed.is_empty()
        || trimmed.starts_with('#')
        || trimmed.contains('=') && !trimmed.contains(' ')
    {
        return None;
    }
    let mut parts = trimmed.split_whitespace();
    let minute = cron_single_value(parts.next()?, 0, 59)?;
    let hour = cron_single_value(parts.next()?, 0, 23)?;
    let day = cron_single_value(parts.next()?, 1, 31)?;
    let month = cron_single_value(parts.next()?, 1, 12)?;
    let weekday = cron_single_value(parts.next()?, 0, 7)?;
    let command = parts.collect::<Vec<_>>().join(" ");
    if command.is_empty() {
        return None;
    }
    let (provider_source, prompt_signature) = provider_and_prompt_signature(&command);
    let repository_hash = command_working_directory(&command)
        .as_deref()
        .and_then(|workspace| resolve_repository_identity(workspace, false).repository_hash);
    let opaque_id = opaque_hmac_id(key, "external_schedule_definition", trimmed)?;
    Some(ExternalSchedulerDefinition {
        scheduler_kind: ExternalSchedulerKind::Cron,
        opaque_id,
        launchd_label: None,
        provider_source,
        prompt_signature,
        repository_hash,
        schedule: ScheduleConstraint {
            calendar: vec![CalendarConstraint {
                minute,
                hour,
                weekday,
                day,
                month,
            }],
        },
    })
}

#[cfg(any(target_os = "macos", test))]
fn cron_single_value(raw: &str, minimum: u8, maximum: u8) -> Option<Option<u8>> {
    if raw == "*" {
        return Some(None);
    }
    let parsed = raw.parse::<u8>().ok()?;
    (minimum..=maximum)
        .contains(&parsed)
        .then_some(Some(parsed))
}

#[cfg(any(target_os = "macos", test))]
fn command_working_directory(command: &str) -> Option<PathBuf> {
    let after_cd = command.split_once("cd ")?.1;
    let value = after_cd
        .split([';', '&'])
        .next()?
        .trim()
        .trim_matches(['\'', '"']);
    let path = PathBuf::from(value);
    path.is_absolute().then_some(path)
}

fn provider_and_prompt_signature(
    command_material: &str,
) -> (Option<SnapshotSource>, Option<String>) {
    let lower = command_material.to_ascii_lowercase();
    let (source, marker_end) = if let Some(index) = find_command_marker(&lower, "codex exec") {
        (Some(SnapshotSource::Codex), index + "codex exec".len())
    } else if let Some(index) = find_command_marker(&lower, "claude --print") {
        (
            Some(SnapshotSource::ClaudeCode),
            index + "claude --print".len(),
        )
    } else if let Some(index) = find_command_marker(&lower, "claude -p") {
        (Some(SnapshotSource::ClaudeCode), index + "claude -p".len())
    } else {
        let source = command_material.split_whitespace().find_map(provider_token);
        (source, 0)
    };
    let prompt = (marker_end > 0)
        .then(|| command_material.get(marker_end..))
        .flatten()
        .and_then(normalize_template_material)
        .map(|value| {
            value
                .trim_matches(['\'', '"'])
                .chars()
                .take(MAX_PROMPT_SIGNATURE_CHARS)
                .collect::<String>()
        })
        .filter(|value| value.chars().count() >= MIN_PROMPT_SIGNATURE_CHARS);
    (source, prompt)
}

fn find_command_marker(haystack: &str, marker: &str) -> Option<usize> {
    haystack.rfind(marker)
}

fn provider_token(token: &str) -> Option<SnapshotSource> {
    let token = token
        .trim_matches(|character: char| matches!(character, '\'' | '"' | '(' | ')' | ';' | '&'))
        .rsplit('/')
        .next()?
        .to_ascii_lowercase();
    match token.as_str() {
        "codex" => Some(SnapshotSource::Codex),
        "claude" => Some(SnapshotSource::ClaudeCode),
        _ => None,
    }
}

fn read_bounded_text(path: &Path, maximum: u64) -> Option<String> {
    let metadata = fs::symlink_metadata(path).ok()?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > maximum {
        return None;
    }
    let mut bytes = Vec::new();
    File::open(path)
        .ok()?
        .take(maximum + 1)
        .read_to_end(&mut bytes)
        .ok()?;
    if bytes.len() as u64 > maximum {
        return None;
    }
    String::from_utf8(bytes).ok()
}

impl ScheduleConstraint {
    fn matches(&self, started_at: OffsetDateTime) -> bool {
        self.calendar
            .iter()
            .any(|constraint| constraint.matches(started_at))
    }
}

impl CalendarConstraint {
    fn matches(&self, started_at: OffsetDateTime) -> bool {
        let weekday = started_at.weekday().number_days_from_sunday();
        self.minute
            .map(|value| value == started_at.minute())
            .unwrap_or(true)
            && self
                .hour
                .map(|value| value == started_at.hour())
                .unwrap_or(true)
            && self
                .weekday
                .map(|value| value % 7 == weekday)
                .unwrap_or(true)
            && self
                .day
                .map(|value| value == started_at.day())
                .unwrap_or(true)
            && self
                .month
                .map(|value| value == u8::from(started_at.month()))
                .unwrap_or(true)
    }
}

#[cfg(unix)]
fn local_schedule_time(value: OffsetDateTime) -> OffsetDateTime {
    let timestamp = value.unix_timestamp();
    // SAFETY: `localtime_r` writes only to the supplied initialized `tm`, and
    // both pointers remain valid for the duration of the call.
    let mut local: libc::tm = unsafe { std::mem::zeroed() };
    let result = unsafe { libc::localtime_r(&timestamp, &mut local) };
    if result.is_null() {
        return value;
    }
    i32::try_from(local.tm_gmtoff)
        .ok()
        .and_then(|seconds| UtcOffset::from_whole_seconds(seconds).ok())
        .map(|offset| value.to_offset(offset))
        .unwrap_or(value)
}

#[cfg(not(unix))]
fn local_schedule_time(value: OffsetDateTime) -> OffsetDateTime {
    value
}

fn live_launchd_labels(
    inventory: &ExternalSchedulerInventory,
    session: &ExternalSchedulerSession<'_>,
) -> BTreeSet<String> {
    #[cfg(not(target_os = "macos"))]
    {
        let _ = inventory;
        let _ = session;
        BTreeSet::new()
    }
    #[cfg(target_os = "macos")]
    {
        let candidate_labels = inventory.candidate_launchd_labels(session);
        if candidate_labels.is_empty() {
            return BTreeSet::new();
        }
        let owner_pids = transcript_owner_pids(session.transcript_path);
        if owner_pids.is_empty() {
            return BTreeSet::new();
        }
        let parent_map = process_parent_map();
        let ancestors = owner_pids
            .into_iter()
            .flat_map(|pid| process_ancestors(pid, &parent_map))
            .collect::<BTreeSet<_>>();
        candidate_labels
            .into_iter()
            .filter_map(|label| launchd_job_pid(label).map(|pid| (label, pid)))
            .filter(|(_, pid)| ancestors.contains(pid))
            .map(|(label, _)| label.to_string())
            .collect()
    }
}

#[cfg(target_os = "macos")]
fn transcript_owner_pids(path: &Path) -> BTreeSet<u32> {
    let Some(path) = path.to_str() else {
        return BTreeSet::new();
    };
    bounded_command_stdout("/usr/sbin/lsof", &["-t", "--", path], 4096)
        .and_then(|value| String::from_utf8(value).ok())
        .map(|value| {
            value
                .lines()
                .filter_map(|line| line.trim().parse::<u32>().ok())
                .take(8)
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(target_os = "macos")]
fn process_parent_map() -> BTreeMap<u32, u32> {
    bounded_command_stdout("/bin/ps", &["-axo", "pid=,ppid="], MAX_PROCESS_TABLE_BYTES)
        .and_then(|value| String::from_utf8(value).ok())
        .map(|value| {
            value
                .lines()
                .filter_map(|line| {
                    let mut values = line.split_whitespace();
                    Some((
                        values.next()?.parse::<u32>().ok()?,
                        values.next()?.parse::<u32>().ok()?,
                    ))
                })
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(target_os = "macos")]
fn process_ancestors(mut pid: u32, parents: &BTreeMap<u32, u32>) -> BTreeSet<u32> {
    let mut values = BTreeSet::new();
    for _ in 0..MAX_ANCESTOR_DEPTH {
        if pid == 0 || !values.insert(pid) {
            break;
        }
        let Some(parent) = parents.get(&pid).copied() else {
            break;
        };
        pid = parent;
    }
    values
}

#[cfg(target_os = "macos")]
fn launchd_job_pid(label: &str) -> Option<u32> {
    // SAFETY: `geteuid` has no preconditions and does not access memory.
    let domain = format!("gui/{}/{}", unsafe { libc::geteuid() }, label);
    let body = bounded_command_stdout(
        "/bin/launchctl",
        &["print", &domain],
        MAX_LAUNCHD_FILE_BYTES as usize,
    )
    .and_then(|value| String::from_utf8(value).ok())?;
    body.lines().find_map(|line| {
        line.trim()
            .strip_prefix("pid = ")
            .and_then(|value| value.trim().parse::<u32>().ok())
    })
}

#[cfg(target_os = "macos")]
fn bounded_command_stdout(program: &str, arguments: &[&str], maximum: usize) -> Option<Vec<u8>> {
    let mut child = Command::new(program)
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let stdout = child.stdout.take()?;
    let reader = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        stdout
            .take(maximum as u64 + 1)
            .read_to_end(&mut bytes)
            .ok()
            .map(|_| bytes)
    });
    let started = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) if started.elapsed() >= LOCAL_COMMAND_TIMEOUT => {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(10)),
            Err(_) => break None,
        }
    };
    let bytes = reader.join().ok().flatten()?;
    status
        .filter(|value| value.success())
        .filter(|_| bytes.len() <= maximum)
        .map(|_| bytes)
}

fn sha256_hex(value: &[u8]) -> String {
    format!("{:x}", Sha256::digest(value))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_dir(name: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        std::env::temp_dir().join(format!("ottto-{name}-{unique}"))
    }

    #[test]
    fn launchd_definition_reduces_wrapper_to_safe_match_material() {
        let home = temp_dir("external-launchd");
        let launch_agents = home.join("Library/LaunchAgents");
        let repository = home.join("repo");
        fs::create_dir_all(&launch_agents).expect("launch agents");
        fs::create_dir_all(&repository).expect("repository");
        Command::new("git")
            .args(["init", "-q"])
            .current_dir(&repository)
            .status()
            .expect("git init");
        let wrapper = repository.join("nightly.sh");
        fs::write(
            &wrapper,
            "#!/bin/sh\ncodex exec 'Inspect the landing queue and report safe results.'\n",
        )
        .expect("wrapper");
        let mut root = Dictionary::new();
        root.insert(
            "Label".to_string(),
            Value::String("com.example.nightly".to_string()),
        );
        root.insert(
            "ProgramArguments".to_string(),
            Value::Array(vec![
                Value::String("/bin/sh".to_string()),
                Value::String(wrapper.to_string_lossy().to_string()),
            ]),
        );
        let mut calendar = Dictionary::new();
        calendar.insert("Hour".to_string(), Value::from(3_i64));
        calendar.insert("Minute".to_string(), Value::from(0_i64));
        root.insert(
            "StartCalendarInterval".to_string(),
            Value::Dictionary(calendar),
        );
        Value::Dictionary(root)
            .to_file_xml(launch_agents.join("nightly.plist"))
            .expect("plist");

        let mut wrapper_budget = MAX_WRAPPER_FILES_PER_REFRESH;
        let definition = parse_launchd_definition(
            &launch_agents.join("nightly.plist"),
            &[7_u8; 32],
            &mut wrapper_budget,
        )
        .expect("definition");
        assert_eq!(definition.provider_source, Some(SnapshotSource::Codex));
        assert!(definition.prompt_signature.is_some());
        assert!(definition.repository_hash.is_some());
        assert!(!definition.opaque_id.contains("com.example"));
        let _ = fs::remove_dir_all(home);
    }

    #[test]
    fn static_correlation_requires_time_prompt_provider_and_repository() {
        let key = [9_u8; 32];
        let prompt =
            normalize_template_material("Inspect the landing queue and report safe results.")
                .expect("prompt");
        let definition = ExternalSchedulerDefinition {
            scheduler_kind: ExternalSchedulerKind::Launchd,
            opaque_id: opaque_hmac_id(&key, "external_schedule_definition", "job").expect("id"),
            launchd_label: Some("job".to_string()),
            provider_source: Some(SnapshotSource::Codex),
            prompt_signature: Some(prompt.clone()),
            repository_hash: Some("repository".to_string()),
            schedule: ScheduleConstraint {
                calendar: vec![CalendarConstraint::default()],
            },
        };
        let inventory = ExternalSchedulerInventory {
            definitions: vec![definition],
        };
        let session = ExternalSchedulerSession {
            source: SnapshotSource::Codex,
            normalized_template: Some(&prompt),
            repository_hash: Some("repository"),
            source_started_at: Some("2026-07-19T03:00:00Z"),
            transcript_path: Path::new("/missing"),
        };
        let matched = inventory
            .correlate_with_live_labels(session, &BTreeSet::new())
            .expect("corroborated match");
        assert_eq!(matched.scheduler_kind, "launchd");
        assert_eq!(matched.evidence_strength, "corroborated");
    }

    #[test]
    fn headless_or_repeated_session_without_scheduler_proof_is_unattributed() {
        let inventory = ExternalSchedulerInventory::default();
        let session = ExternalSchedulerSession {
            source: SnapshotSource::Codex,
            normalized_template: Some("repeat this every day"),
            repository_hash: None,
            source_started_at: Some("2026-07-19T03:00:00Z"),
            transcript_path: Path::new("/missing"),
        };
        assert!(inventory
            .correlate_with_live_labels(session, &BTreeSet::new())
            .is_none());
    }

    #[test]
    fn interval_job_requires_live_pid_relationship() {
        let definition = ExternalSchedulerDefinition {
            scheduler_kind: ExternalSchedulerKind::Launchd,
            opaque_id: "opaque-job".to_string(),
            launchd_label: Some("com.example.interval".to_string()),
            provider_source: None,
            prompt_signature: None,
            repository_hash: Some("repository".to_string()),
            schedule: ScheduleConstraint::default(),
        };
        let inventory = ExternalSchedulerInventory {
            definitions: vec![definition],
        };
        let session = ExternalSchedulerSession {
            source: SnapshotSource::Codex,
            normalized_template: None,
            repository_hash: Some("repository"),
            source_started_at: Some("2026-07-19T03:00:00Z"),
            transcript_path: Path::new("/missing"),
        };
        assert!(inventory
            .correlate_with_live_labels(session, &BTreeSet::new())
            .is_none());
        let matched = inventory
            .correlate_with_live_labels(
                session,
                &BTreeSet::from(["com.example.interval".to_string()]),
            )
            .expect("live match");
        assert_eq!(matched.evidence_kind, "live_process");
        assert_eq!(matched.evidence_strength, "direct");
    }

    #[test]
    fn equally_strong_scheduler_matches_fail_closed() {
        let definitions = ["job-a", "job-b"]
            .into_iter()
            .map(|id| ExternalSchedulerDefinition {
                scheduler_kind: ExternalSchedulerKind::Launchd,
                opaque_id: id.to_string(),
                launchd_label: Some(id.to_string()),
                provider_source: Some(SnapshotSource::Codex),
                prompt_signature: Some("inspect the landing queue safely".to_string()),
                repository_hash: Some("repository".to_string()),
                schedule: ScheduleConstraint {
                    calendar: vec![CalendarConstraint::default()],
                },
            })
            .collect();
        let inventory = ExternalSchedulerInventory { definitions };
        let session = ExternalSchedulerSession {
            source: SnapshotSource::Codex,
            normalized_template: Some("inspect the landing queue safely"),
            repository_hash: Some("repository"),
            source_started_at: Some("2026-07-19T03:00:00Z"),
            transcript_path: Path::new("/missing"),
        };
        assert!(inventory
            .correlate_with_live_labels(session, &BTreeSet::new())
            .is_none());
    }

    #[test]
    fn cron_parser_accepts_only_simple_schedule_fields() {
        let definitions = parse_crontab(
            "0 3 * * * cd /tmp && claude -p 'Review provider changes safely.'\n\
             */5 * * * * codex exec 'unsupported cadence'\n",
            &[4_u8; 32],
        );
        assert_eq!(definitions.len(), 1);
        assert_eq!(
            definitions[0].provider_source,
            Some(SnapshotSource::ClaudeCode)
        );
        assert!(definitions[0].scheduler_kind == ExternalSchedulerKind::Cron);
    }
}
