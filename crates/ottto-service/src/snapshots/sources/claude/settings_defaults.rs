//! Claude Code runtime defaults read from the settings file chain.

use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use std::path::Path;

/// Defensive size ceiling for a Claude Code settings file. Real settings files
/// are a few KiB; anything larger is not a config file we should be parsing.
const MAX_CLAUDE_SETTINGS_FILE_BYTES: u64 = 1024 * 1024;

/// Most models reported in `reasoning_effort_by_model`. Real files hold a
/// handful; the cap only bounds a pathological one.
const MAX_CLAUDE_EFFORT_BY_MODEL_ENTRIES: usize = 16;

/// Models that still take the user file's legacy top-level `effortLevel` when
/// nothing else sets their effort, as listed by Claude Code 2.1.300. Newer models
/// ignore that key, so its stale value is never reported for them.
const CLAUDE_LEGACY_EFFORT_MODELS: &[&str] = &[
    "claude-3-5-haiku",
    "claude-3-5-sonnet",
    "claude-3-7-sonnet",
    "claude-haiku-4-5",
    "claude-sonnet-4-0",
    "claude-sonnet-4-5",
    "claude-sonnet-4-6",
    "claude-sonnet-5",
    "claude-opus-4-0",
    "claude-opus-4-1",
    "claude-opus-4-5",
    "claude-opus-4-6",
    "claude-opus-4-7",
    "claude-opus-4-8",
    "claude-opus-5",
    "claude-fable-5",
    "claude-fable-5-1",
    "claude-mythos-5",
    "claude-mythos-5-1",
];

/// Display-safe Claude Code runtime defaults resolved across the settings chain.
///
/// The Codex sibling is `CodexConfigDefaults`; the same rules apply. These are
/// configured defaults, not evidence a session actually ran with them.
/// `selector_context` carries the resolved value per field and
/// `selector_sources` carries the `claude_code.<scope>.<json key path>`
/// provenance of the file that won, so the UI can name the file each value came
/// from instead of implying one global config.
///
/// `reasoning_effort` comes from Claude Code's durable effort setting. Current
/// Claude Code saves `/effort` per model under `modelSettings.<model>.effortLevel`;
/// the user file's top-level `effortLevel` is the legacy key it no longer
/// updates. See `effort_for_key` and `resolve_claude_effort` for which value
/// wins. The value is reported exactly as configured; nothing is normalized and
/// no default is invented when the key is absent. `reasoning_effort_by_model` reports every saved per-model effort
/// on its own, so a `/effort` change shows even when no model is saved.
///
/// `fast_mode_enabled` is the one field with a default: Claude Code's Fast is
/// off until `fastMode` is saved, so a readable chain without that key reports
/// `false` with the `claude_code.default.fastMode` source.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct ClaudeConfigDefaults {
    pub model: Option<String>,
    pub reasoning_effort: Option<String>,
    /// Canonical `modelSettings` key to its effort; see `claude_effort_by_model`.
    pub reasoning_effort_by_model: BTreeMap<String, String>,
    pub approval_policy: Option<String>,
    pub fast_mode_enabled: Option<bool>,
    pub sandbox_mode: Option<String>,
    pub selector_context: BTreeMap<String, String>,
    pub selector_sources: BTreeMap<String, String>,
}

/// `selector_sources` label for a Fast default that no settings key sets.
const CLAUDE_FAST_MODE_DEFAULT_SOURCE: &str = "claude_code.default.fastMode";

/// Result of reading the Claude Code settings chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ClaudeConfigDefaultsOutcome {
    /// At least one settings file parsed cleanly. Fast mode is always known
    /// then: a chain without `fastMode` reports Claude Code's default, off.
    Configured(ClaudeConfigDefaults),
    /// No settings file in the chain could be read and parsed, so nothing is
    /// reported, not even the Fast default.
    Unreadable,
}

/// One Claude Code settings file in precedence order.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ClaudeSettingsScope<'a> {
    /// `selector_sources` prefix identifying the file, e.g. `claude_code.settings`.
    pub label: &'a str,
    pub path: &'a Path,
}

/// Raw per-key capture with the scope label that supplied it. Kept separate from
/// `ClaudeConfigDefaults` so a higher-precedence file that sets only one half of
/// a derived pair (for example `sandbox.autoAllowBashIfSandboxed` without
/// `sandbox.enabled`) still wins for the key it actually sets.
#[derive(Debug, Clone, Default)]
struct ClaudeSettingsRaw {
    model: Option<(String, String)>,
    /// `modelSettings` key for the highest-precedence `model`, even one too
    /// unusual to display (such as `claude-opus-4-7[1m]`). Used only to look up
    /// a saved effort; never reported.
    model_key: Option<String>,
    /// One entry per readable file, lowest precedence first. Effort is resolved
    /// only after the winning `model` is known, because the per-model key it
    /// selects may come from a different file.
    effort_scopes: Vec<ClaudeEffortScope>,
    /// The user file's top-level `effortLevel`, which Claude Code treats as
    /// legacy; see `resolve_claude_effort`.
    legacy_effort: Option<(String, String)>,
    permission_mode: Option<(String, String)>,
    fast_mode: Option<(bool, String)>,
    fast_mode_per_session_opt_in: Option<(bool, String)>,
    sandbox_enabled: Option<(bool, String)>,
    sandbox_auto_allow_bash: Option<(bool, String)>,
}

/// Effort keys from one Claude Code settings file.
#[derive(Debug, Clone, Default)]
struct ClaudeEffortScope {
    label: String,
    /// Top-level `effortLevel`, except in the user file (see `legacy_effort`).
    top_level: Option<String>,
    /// `modelSettings.<key>.effortLevel` by canonical model key.
    by_model: BTreeMap<String, String>,
}

/// Resolve display-safe Claude Code defaults from the settings chain.
///
/// `scopes` must be ordered lowest precedence first, starting with the user file
/// (`~/.claude/settings.json`); each readable file overwrites the keys it sets,
/// so the highest-precedence file wins per key.
/// Only specifically-named keys are ever read: `model`, `effortLevel`,
/// `modelSettings.<model>.effortLevel`, `permissions.defaultMode`, `fastMode`/`fastModePerSessionOptIn`, and
/// `sandbox.enabled`/`sandbox.autoAllowBashIfSandboxed`. `env`,
/// `permissions.allow`/`ask`/`deny`, `apiKeyHelper`, `statusLine`,
/// `sandbox.credentials`, and `sandbox.filesystem` are never read, so no path,
/// environment value, token, or permission rule can ride along. Environment
/// variables are never consulted either, so `CLAUDE_CODE_EFFORT_LEVEL` cannot
/// leak in through this path.
pub(crate) fn load_claude_settings_defaults(
    scopes: &[ClaudeSettingsScope<'_>],
) -> ClaudeConfigDefaultsOutcome {
    let mut raw = ClaudeSettingsRaw::default();
    let mut any_readable = false;
    for (index, scope) in scopes.iter().enumerate() {
        let Some(document) = load_claude_settings_document(scope.path) else {
            continue;
        };
        any_readable = true;
        apply_claude_settings_scope(&mut raw, scope.label, index == 0, &document);
    }
    if !any_readable {
        return ClaudeConfigDefaultsOutcome::Unreadable;
    }

    let mut defaults = ClaudeConfigDefaults::default();
    let insert = |defaults: &mut ClaudeConfigDefaults, field: &str, value: String, source: &str| {
        defaults.selector_context.insert(field.to_string(), value);
        defaults
            .selector_sources
            .insert(field.to_string(), source.to_string());
    };

    if let Some((model, source)) = raw.model.clone() {
        insert(&mut defaults, "model", model.clone(), &source);
        defaults.model = Some(model);
    }
    // Reported exactly as configured. `low`/`medium`/`high`/`xhigh` persist
    // across sessions; `max` is session-only unless the environment sets it, but
    // if the settings file says `max` then that is what the file says, and the
    // Configuration tab's contract is to show the config file. Normalizing or
    // dropping a value here would misreport the customer's own config.
    if let Some((effort, source)) = resolve_claude_effort(&raw) {
        insert(&mut defaults, "reasoning_effort", effort.clone(), &source);
        defaults.reasoning_effort = Some(effort);
    }
    if let Some((by_model, source)) = claude_effort_by_model(&raw.effort_scopes) {
        defaults
            .selector_sources
            .insert("reasoning_effort_by_model".to_string(), source);
        defaults.reasoning_effort_by_model = by_model;
    }
    if let Some((mode, source)) = raw.permission_mode.clone() {
        insert(&mut defaults, "approval_policy", mode.clone(), &source);
        defaults.approval_policy = Some(mode);
    }
    // `fastModePerSessionOptIn` means Fast never persists across sessions, so
    // the durable default is off regardless of a stored `fastMode` flag. This
    // mirrors how Codex's `fast_default_opt_out` overrides `[features].fast_mode`.
    // At least one file was read, so a chain without `fastMode` means Claude
    // Code's own default: off. That default is labelled as such, never as a key.
    let (fast_mode_enabled, fast_mode_source) =
        match (&raw.fast_mode_per_session_opt_in, &raw.fast_mode) {
            (Some((true, source)), _) => (false, source.clone()),
            (_, Some((enabled, source))) => (*enabled, source.clone()),
            _ => (false, CLAUDE_FAST_MODE_DEFAULT_SOURCE.to_string()),
        };
    insert(
        &mut defaults,
        "fast_mode_enabled",
        fast_mode_enabled.to_string(),
        &fast_mode_source,
    );
    defaults.fast_mode_enabled = Some(fast_mode_enabled);
    // `autoAllowBashIfSandboxed` only means something once the sandbox is on,
    // so an unset `sandbox.enabled` stays quiet rather than guessing a mode.
    let sandbox_mode = match &raw.sandbox_enabled {
        Some((false, source)) => Some(("disabled", source.clone())),
        Some((true, source)) => match &raw.sandbox_auto_allow_bash {
            Some((false, auto_allow_source)) => {
                Some(("regular_permissions", auto_allow_source.clone()))
            }
            // Auto-allow is Claude Code's default once the sandbox is enabled.
            _ => Some(("auto_allow", source.clone())),
        },
        None => None,
    };
    if let Some((mode, source)) = sandbox_mode {
        insert(&mut defaults, "sandbox_mode", mode.to_string(), &source);
        defaults.sandbox_mode = Some(mode.to_string());
    }

    ClaudeConfigDefaultsOutcome::Configured(defaults)
}

/// Read one Claude Code settings file into JSON; `None` for any failure.
fn load_claude_settings_document(path: &Path) -> Option<Value> {
    match read_claude_settings_document(path) {
        ClaudeSettingsDocument::Parsed(document) => Some(document),
        ClaudeSettingsDocument::Missing | ClaudeSettingsDocument::Failed => None,
    }
}

/// One Claude Code settings file: absent, present but not usable (unreadable,
/// not a regular file, oversized or malformed), or parsed.
#[derive(Debug)]
pub(crate) enum ClaudeSettingsDocument {
    Missing,
    Failed,
    Parsed(Value),
}

/// Read line-by-line to satisfy the streaming guard (no whole-file reads in this
/// module); settings files are small, so the accumulated string is fine.
pub(crate) fn read_claude_settings_document(path: &Path) -> ClaudeSettingsDocument {
    let opened = fs::metadata(path).and_then(|metadata| {
        if !metadata.is_file() || metadata.len() > MAX_CLAUDE_SETTINGS_FILE_BYTES {
            return Err(std::io::Error::other("not a bounded settings file"));
        }
        File::open(path)
    });
    let file = match opened {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return ClaudeSettingsDocument::Missing
        }
        Err(_) => return ClaudeSettingsDocument::Failed,
    };
    let mut raw = String::new();
    for line in BufReader::new(file).lines() {
        let Ok(line) = line else {
            return ClaudeSettingsDocument::Failed;
        };
        raw.push_str(line.as_str());
        raw.push('\n');
    }
    match serde_json::from_str::<Value>(&raw) {
        Ok(document) => ClaudeSettingsDocument::Parsed(document),
        Err(_) => ClaudeSettingsDocument::Failed,
    }
}

fn apply_claude_settings_scope(
    raw: &mut ClaudeSettingsRaw,
    label: &str,
    user_file: bool,
    document: &Value,
) {
    // The winning `model` both names the model and selects its effort, so a
    // model too unusual to display clears a lower file's model rather than
    // pairing it with this model's effort.
    if let Some(model) = document
        .get("model")
        .and_then(Value::as_str)
        .filter(|model| !model.trim().is_empty())
    {
        raw.model =
            display_safe_config_scalar(model).map(|model| (model, format!("{label}.model")));
        raw.model_key = Some(claude_model_settings_key(model));
    }
    let mut top_level = document
        .get("effortLevel")
        .and_then(Value::as_str)
        .and_then(display_safe_config_scalar);
    if user_file {
        raw.legacy_effort = top_level
            .take()
            .map(|level| (level, format!("{label}.effortLevel")));
    }
    let mut effort = ClaudeEffortScope {
        label: label.to_string(),
        top_level,
        by_model: BTreeMap::new(),
    };
    if let Some(model_settings) = document.get("modelSettings").and_then(Value::as_object) {
        for (key, settings) in model_settings {
            let Some(canonical) = display_safe_config_scalar(&claude_model_settings_key(key))
            else {
                continue;
            };
            let Some(level) = settings
                .get("effortLevel")
                .and_then(Value::as_str)
                .and_then(display_safe_config_scalar)
            else {
                continue;
            };
            // Like Claude Code, a key already in canonical form beats an alias
            // spelling of the same model.
            if *key == canonical || !effort.by_model.contains_key(&canonical) {
                effort.by_model.insert(canonical, level);
            }
        }
    }
    raw.effort_scopes.push(effort);
    if let Some(mode) = document
        .get("permissions")
        .and_then(|permissions| permissions.get("defaultMode"))
        .and_then(Value::as_str)
        .and_then(claude_permission_mode_default)
    {
        raw.permission_mode = Some((mode, format!("{label}.permissions.defaultMode")));
    }
    if let Some(fast_mode) = document.get("fastMode").and_then(Value::as_bool) {
        raw.fast_mode = Some((fast_mode, format!("{label}.fastMode")));
    }
    if let Some(opt_in) = document
        .get("fastModePerSessionOptIn")
        .and_then(Value::as_bool)
    {
        raw.fast_mode_per_session_opt_in =
            Some((opt_in, format!("{label}.fastModePerSessionOptIn")));
    }
    if let Some(sandbox) = document.get("sandbox") {
        if let Some(enabled) = sandbox.get("enabled").and_then(Value::as_bool) {
            raw.sandbox_enabled = Some((enabled, format!("{label}.sandbox.enabled")));
        }
        if let Some(auto_allow) = sandbox
            .get("autoAllowBashIfSandboxed")
            .and_then(Value::as_bool)
        {
            raw.sandbox_auto_allow_bash = Some((
                auto_allow,
                format!("{label}.sandbox.autoAllowBashIfSandboxed"),
            ));
        }
    }
}

/// The effort Claude Code applies to the model with canonical `modelSettings`
/// key `key`, as Claude Code 2.1.300 resolves it: the highest file that answers
/// wins, with its entry for `key`, or else its top-level `effortLevel`. The user
/// file's top-level value is legacy and never answers here. Returns the effort,
/// the file's label, and whether the value is the file's per-model entry.
fn effort_for_key<'a>(
    scopes: &'a [ClaudeEffortScope],
    key: &str,
) -> Option<(&'a str, &'a str, bool)> {
    scopes
        .iter()
        .rev()
        .find_map(|scope| match scope.by_model.get(key) {
            Some(effort) => Some((effort.as_str(), scope.label.as_str(), true)),
            None => scope
                .top_level
                .as_deref()
                .map(|effort| (effort, scope.label.as_str(), false)),
        })
}

/// Pick the configured effort and the key that supplied it.
///
/// - With a saved `model`, `effort_for_key` for it. If no file answers, the
///   user file's legacy top-level `effortLevel`, but only for the older models
///   Claude Code still applies it to.
/// - Without one, the effort depends on which model Claude Code starts with,
///   which the settings do not say. It is reported only when a top-level
///   `effortLevel` sets every model, that is, when its file is higher than
///   every `modelSettings` entry. Each entry is still reported on its own in
///   `reasoning_effort_by_model`.
fn resolve_claude_effort(raw: &ClaudeSettingsRaw) -> Option<(String, String)> {
    let Some(key) = raw.model_key.as_deref() else {
        for scope in raw.effort_scopes.iter().rev() {
            if !scope.by_model.is_empty() {
                return None;
            }
            if let Some(effort) = &scope.top_level {
                return Some((effort.clone(), format!("{}.effortLevel", scope.label)));
            }
        }
        return None;
    };
    match effort_for_key(&raw.effort_scopes, key) {
        Some((effort, label, true)) => Some((
            effort.to_string(),
            format!("{label}.modelSettings.{key}.effortLevel"),
        )),
        Some((effort, label, false)) => Some((effort.to_string(), format!("{label}.effortLevel"))),
        None => raw
            .legacy_effort
            .clone()
            .filter(|_| CLAUDE_LEGACY_EFFORT_MODELS.contains(&key)),
    }
}

/// `effort_for_key` for every model with a `modelSettings` entry in any file,
/// plus a source naming each file and field (`modelSettings` or `effortLevel`)
/// that supplied a value, lowest precedence first. Keys are canonical
/// `modelSettings` keys, already display-safe. Past
/// `MAX_CLAUDE_EFFORT_BY_MODEL_ENTRIES` the first keys in sort order are kept.
fn claude_effort_by_model(
    scopes: &[ClaudeEffortScope],
) -> Option<(BTreeMap<String, String>, String)> {
    let keys: BTreeSet<&str> = scopes
        .iter()
        .flat_map(|scope| scope.by_model.keys().map(String::as_str))
        .collect();
    let mut by_model = BTreeMap::new();
    let mut supplied = BTreeSet::new();
    for key in keys.into_iter().take(MAX_CLAUDE_EFFORT_BY_MODEL_ENTRIES) {
        if let Some((effort, label, per_model)) = effort_for_key(scopes, key) {
            by_model.insert(key.to_string(), effort.to_string());
            supplied.insert((label, per_model));
        }
    }
    if by_model.is_empty() {
        return None;
    }
    let mut sources = Vec::new();
    for scope in scopes {
        for (per_model, field) in [(true, "modelSettings"), (false, "effortLevel")] {
            if supplied.contains(&(scope.label.as_str(), per_model)) {
                sources.push(format!("{}.{field}", scope.label));
            }
        }
    }
    Some((by_model, sources.join(",")))
}

/// The `modelSettings` key Claude Code uses for a model id.
///
/// Mirrors Claude Code's canonical key: lowercase, without a `[1m]` context
/// suffix, provider path or `<region>.anthropic.` prefix, release date, version,
/// `-latest`, or `-fast` suffix. So `us.anthropic.claude-opus-4-1-20250805-v1:0`
/// and `claude-opus-4-1[1m]` both select `claude-opus-4-1`. Aliases such as
/// `opus` are left as written: what they resolve to depends on the Claude Code
/// version and plan, so they only match a key saved under the alias itself.
fn claude_model_settings_key(model: &str) -> String {
    let lowered = model.trim().to_ascii_lowercase();
    let mut key = lowered.as_str();
    for suffix in ["[1m]", "[2m]"] {
        if let Some(head) = key.strip_suffix(suffix) {
            key = head;
        }
    }
    key = key.rsplit('/').next().unwrap_or_default();
    if let Some(index) = key.find("anthropic.claude-") {
        let region = &key[..index];
        if region.is_empty()
            || region.strip_suffix('.').is_some_and(|region| {
                !region.is_empty() && region.chars().all(|ch| ch.is_ascii_lowercase())
            })
        {
            key = &key[index + "anthropic.".len()..];
        }
    }
    let all_digits = |text: &str, min: usize, max: usize| {
        (min..=max).contains(&text.len()) && text.chars().all(|ch| ch.is_ascii_digit())
    };
    // Bedrock version, e.g. `-v1:0`.
    if let Some((head, version)) = key.rsplit_once("-v") {
        let (major, minor) = version.split_once(':').unwrap_or((version, "0"));
        if all_digits(major, 1, 3) && all_digits(minor, 1, 3) {
            key = head;
        }
    }
    // Release date, e.g. `-20250805` or Vertex `@20250805`.
    if let Some(index) = key.rfind(['-', '@']) {
        if all_digits(&key[index + 1..], 8, 8) {
            key = &key[..index];
        }
    }
    for suffix in ["-latest", "-fast"] {
        if let Some(head) = key.strip_suffix(suffix) {
            key = head;
            break;
        }
    }
    key.to_string()
}

/// Canonical display value for `permissions.defaultMode`.
///
/// `bypassPermissions` is a local safety posture, never a cost-relevant default,
/// so it is dropped rather than uploaded. Unknown values are dropped too: a
/// future mode name is not something we should forward blind.
fn claude_permission_mode_default(value: &str) -> Option<String> {
    match value.trim() {
        // `manual` is the CLI alias for the canonical `default` config value.
        "default" | "manual" => Some("default".to_string()),
        "acceptEdits" => Some("acceptEdits".to_string()),
        "plan" => Some("plan".to_string()),
        "auto" => Some("auto".to_string()),
        "dontAsk" => Some("dontAsk".to_string()),
        _ => None,
    }
}

/// Accept only short, scalar, display-safe config text.
///
/// Anything path-like, URL-like, quoted, whitespace-bearing, or long is dropped
/// instead of forwarded, so free-form settings text can never leak a path, an
/// environment value, or a credential through a config-defaults field. The
/// backend-facing `redacted_for_backend` guard is the second line of defence.
fn display_safe_config_scalar(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.len() > 64 {
        return None;
    }
    if !trimmed
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-' | ':'))
    {
        return None;
    }
    Some(trimmed.to_string())
}
