//! Advisory replay of cloned transcripts through the real snapshot page owner.
//! The manifest's private containing directory is the clone boundary. Nothing
//! here starts serve, provider status, relays, MCP, login recovery or launchd.
#![cfg(feature = "replay-harness")]
use super::loopback_backend::{synthetic_device, Backend, EnvVarGuard};
use super::*;
use crate::source_rotation::{Owner, Step};
use hmac::{Hmac, Mac};
use std::cell::RefCell;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::sync::Arc;

const MARKER: &str = ".replay-harness";
const MARKER_BYTES: &[u8] = b"ottto isolated replay v1\n";
const INPUT_LIMIT: u64 = 1024 * 1024;
const PLATFORM_QUALIFICATION: &str = "platform: durable retention unsupported on this layout; restore is qualified on macOS by the native durable_tail/#865 fixtures in normal macOS CI";

#[derive(Debug, clap::Args)]
pub struct Args {
    #[arg(long)]
    pub support_dir: PathBuf,
    /// Private clone boundary: the directory containing this manifest.
    #[arg(long)]
    pub roots_manifest: PathBuf,
    #[arg(long, value_enum)]
    pub pass: Pass,
    /// Aggregate JSONL file inside the scratch support directory.
    #[arg(long)]
    pub out: PathBuf,
    /// Read-only private 32-byte key shared by the chain and independent COLD.
    #[arg(long)]
    pub blinding_key_file: PathBuf,
    /// Frozen RFC3339 collection clock, identical for the chain and COLD.
    #[arg(long)]
    pub collected_at: String,
    /// Optional {"files": [clone-relative paths]} inventory, prepared by the driver.
    /// The driver truncates/appends copies; the harness never edits transcripts.
    #[arg(long)]
    pub hold_back: Option<PathBuf>,
    #[arg(long)]
    pub kill_after_pages: Option<usize>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum, Serialize)]
pub enum Pass {
    #[value(name = "P0")]
    P0,
    #[value(name = "P1")]
    P1,
    #[value(name = "P2")]
    P2,
    #[value(name = "P3")]
    P3,
    #[value(name = "COLD")]
    #[serde(rename = "COLD")]
    Cold,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Roots {
    claude: Vec<PathBuf>,
    codex: Vec<PathBuf>,
    pi: Vec<PathBuf>,
}
impl Roots {
    fn get(&self, source: SnapshotSource) -> &[PathBuf] {
        match source {
            SnapshotSource::ClaudeCode => &self.claude,
            SnapshotSource::Codex => &self.codex,
            SnapshotSource::Pi => &self.pi,
        }
    }
}
thread_local! {
    // An in-memory fake slot registry, installed only after isolation validation.
    static REGISTRY: RefCell<Option<Roots>> = const { RefCell::new(None) };
}
pub(crate) fn registered_roots(source: SnapshotSource) -> Option<Vec<PathBuf>> {
    REGISTRY.with(|registry| {
        registry
            .borrow()
            .as_ref()
            .map(|roots| roots.get(source).to_vec())
    })
}
struct RegistryGuard;
impl Drop for RegistryGuard {
    fn drop(&mut self) {
        REGISTRY.with(|registry| registry.borrow_mut().take());
    }
}

struct Isolation {
    support: PathBuf,
    secrets: PathBuf,
    roots: Roots,
    out: PathBuf,
    held_files: usize,
    key: Vec<u8>,
}

fn private_dir(path: &Path) -> Result<PathBuf> {
    let metadata = fs::symlink_metadata(path)?;
    anyhow::ensure!(
        metadata.is_dir() && !metadata.file_type().is_symlink(),
        "private directory required"
    );
    // SAFETY: geteuid has no preconditions.
    anyhow::ensure!(
        metadata.uid() == unsafe { libc::geteuid() } && metadata.mode() & 0o077 == 0,
        "private directory required"
    );
    Ok(fs::canonicalize(path)?)
}

fn read_fixed(path: &Path, length: usize) -> Result<Vec<u8>> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let meta = file.metadata()?;
    anyhow::ensure!(
        meta.is_file() && meta.len() == length as u64,
        "invalid fixed input"
    );
    let mut bytes = Vec::with_capacity(length);
    file.take(length as u64 + 1).read_to_end(&mut bytes)?;
    anyhow::ensure!(bytes.len() == length, "invalid fixed input");
    Ok(bytes)
}

fn bounded_json(path: &Path) -> Result<serde_json::Value> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let meta = file.metadata()?;
    anyhow::ensure!(
        meta.is_file() && meta.len() <= INPUT_LIMIT,
        "manifest bound"
    );
    let mut bytes = Vec::new();
    file.take(INPUT_LIMIT + 1).read_to_end(&mut bytes)?;
    anyhow::ensure!(bytes.len() as u64 <= INPUT_LIMIT, "manifest bound");
    Ok(serde_json::from_slice(&bytes)?)
}

/// Reject symlinks (including nested ones), hard links, special files and
/// escapes before collection. APFS copy-on-write clones have independent inodes.
/// Private, driver-owned directories must not be edited concurrently with a pass.
fn isolated_tree(path: &Path, boundary: &Path) -> Result<()> {
    fn visit(path: &Path, boundary: &Path, depth: usize) -> Result<()> {
        anyhow::ensure!(depth <= 128, "directory depth bound");
        let meta = fs::symlink_metadata(path)?;
        anyhow::ensure!(!meta.file_type().is_symlink(), "symlink refused");
        anyhow::ensure!(
            fs::canonicalize(path)?.starts_with(boundary),
            "path escapes clone"
        );
        if meta.is_dir() {
            for entry in fs::read_dir(path)? {
                visit(&entry?.path(), boundary, depth + 1)?;
            }
        } else {
            anyhow::ensure!(
                meta.is_file() && meta.nlink() == 1,
                "non-private file refused"
            );
        }
        Ok(())
    }
    visit(path, boundary, 0)
}

impl Isolation {
    fn validate(args: &Args) -> Result<Self> {
        OffsetDateTime::parse(
            &args.collected_at,
            &time::format_description::well_known::Rfc3339,
        )?;
        let support = private_dir(&args.support_dir)?;
        // The account database still identifies live provider/support roots
        // when the driver has already replaced HOME with a scratch directory.
        let account_home = ottto_core::session_launch::launch_user()
            .ok_or_else(|| anyhow!("account home unavailable"))?
            .home;
        let mut homes = vec![fs::canonicalize(account_home)?];
        if let Some(home) = std::env::var_os("HOME") {
            let home = fs::canonicalize(home)?;
            if !homes.contains(&home) {
                homes.push(home);
            }
        }
        let configured = std::env::var_os("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR")
            .ok_or_else(|| anyhow!("scratch support environment required"))?;
        anyhow::ensure!(fs::canonicalize(configured)? == support, "support mismatch");
        let secrets = std::env::var_os(ottto_core::OTTTO_SECRET_FALLBACK_DIR_ENV)
            .ok_or_else(|| anyhow!("file secrets required"))?;
        let secrets = private_dir(Path::new(&secrets))?;
        anyhow::ensure!(secrets.starts_with(&support), "secrets outside scratch");
        isolated_tree(&support, &support)?;
        // An empty directory is admitted once. Subsequent passes must carry our
        // marker; an existing daemon state cannot accidentally become scratch.
        if support.join(MARKER).exists() {
            anyhow::ensure!(args.pass != Pass::Cold, "COLD requires fresh scratch");
            anyhow::ensure!(
                read_fixed(&support.join(MARKER), MARKER_BYTES.len())? == MARKER_BYTES,
                "scratch marker invalid"
            );
        } else {
            anyhow::ensure!(
                fs::read_dir(&support)?.all(|entry| entry.is_ok_and(|e| e.path() == secrets
                    && secrets != support
                    && fs::read_dir(&secrets).is_ok_and(|mut entries| entries.next().is_none()))),
                "non-scratch support refused"
            );
        }
        let manifest = fs::canonicalize(&args.roots_manifest)?;
        let clone = private_dir(
            manifest
                .parent()
                .ok_or_else(|| anyhow!("clone boundary missing"))?,
        )?;
        anyhow::ensure!(
            !homes.iter().any(|home| home.starts_with(&clone))
                && !support.starts_with(&clone)
                && !clone.starts_with(&support),
            "clone and scratch must be separate private directories"
        );
        let mut protected = Vec::new();
        for home in &homes {
            if home != &homes[0] && home.starts_with(&support) {
                continue; // A driver may already have installed a scratch HOME.
            }
            for provider in [
                ".claude",
                ".codex",
                ".pi",
                "Library/Application Support/Ottto",
            ] {
                protected.push(home.join(provider));
            }
        }
        for variable in ["CLAUDE_CONFIG_DIR", "CODEX_HOME", "PI_CODING_AGENT_DIR"] {
            if let Some(path) = std::env::var_os(variable) {
                let path = PathBuf::from(path);
                let effective = match fs::canonicalize(&path) {
                    Ok(path) => path,
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => path.clone(),
                    Err(error) => return Err(error.into()),
                };
                if !effective.starts_with(&support) {
                    protected.push(path);
                }
            }
        }
        for path in protected {
            let physical = match fs::canonicalize(&path) {
                Ok(path) => Some(path),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
                Err(error) => return Err(error.into()),
            };
            for live in std::iter::once(path).chain(physical) {
                anyhow::ensure!(
                    !clone.starts_with(&live)
                        && !live.starts_with(&clone)
                        && !support.starts_with(&live)
                        && !live.starts_with(&support),
                    "live provider or support directory refused"
                );
            }
        }
        isolated_tree(&clone, &clone)?;
        anyhow::ensure!(
            !support.join("connection.json").exists(),
            "scratch connection binding refused"
        );
        let mut roots: Roots = serde_json::from_value(bounded_json(&manifest)?)?;
        for root in roots
            .claude
            .iter_mut()
            .chain(&mut roots.codex)
            .chain(&mut roots.pi)
        {
            let original = if root.is_absolute() {
                root.clone()
            } else {
                clone.join(&*root)
            };
            // Refuse symlink components even when their target happens to be in clone.
            let canonical = fs::canonicalize(&original)?;
            anyhow::ensure!(
                canonical.starts_with(&clone) && canonical != clone,
                "root outside clone"
            );
            for ancestor in original.ancestors() {
                if fs::canonicalize(ancestor)? == clone {
                    break;
                }
                anyhow::ensure!(
                    !fs::symlink_metadata(ancestor)?.file_type().is_symlink(),
                    "root symlink refused"
                );
            }
            anyhow::ensure!(canonical.is_dir(), "transcript root must be a directory");
            isolated_tree(&canonical, &clone)?;
            *root = canonical;
        }
        anyhow::ensure!(
            !roots.claude.is_empty() || !roots.codex.is_empty() || !roots.pi.is_empty(),
            "no roots"
        );
        let out_parent = fs::canonicalize(
            args.out
                .parent()
                .ok_or_else(|| anyhow!("output parent missing"))?,
        )?;
        anyhow::ensure!(
            out_parent.starts_with(&support)
                && args.out.extension().is_some_and(|ext| ext == "jsonl"),
            "output must be scratch JSONL"
        );
        let out = out_parent.join(
            args.out
                .file_name()
                .ok_or_else(|| anyhow!("output name missing"))?,
        );
        if out.exists() {
            anyhow::ensure!(
                fs::symlink_metadata(&out)?.is_file(),
                "output must be regular"
            );
        }
        anyhow::ensure!(
            args.kill_after_pages.is_none()
                || (args.pass == Pass::P3 && args.kill_after_pages.is_some_and(|n| n > 0)),
            "kill requires P3 and a positive page count"
        );
        let held_files = if let Some(path) = &args.hold_back {
            let path = fs::canonicalize(path)?;
            anyhow::ensure!(path.starts_with(&clone), "hold-back outside clone");
            #[derive(Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Held {
                files: Vec<PathBuf>,
            }
            let held: Held = serde_json::from_value(bounded_json(&path)?)?;
            for path in &held.files {
                let path = fs::canonicalize(clone.join(path))?;
                anyhow::ensure!(
                    roots
                        .claude
                        .iter()
                        .chain(&roots.codex)
                        .chain(&roots.pi)
                        .any(|root| path.starts_with(root)),
                    "hold-back outside registered roots"
                );
            }
            held.files.len()
        } else {
            0
        };
        let key = blinding_key(&args.blinding_key_file)?;
        Ok(Self {
            support,
            secrets,
            roots,
            out,
            held_files,
            key,
        })
    }
}

/// Main uses explicit exit codes and a content-free error message. Source errors
/// never become the public CLI error, which could disclose cloned paths.
pub fn run(args: Args) -> i32 {
    let isolation = match Isolation::validate(&args) {
        Ok(isolation) => isolation,
        Err(_) => {
            eprintln!("replay-harness: isolation refused");
            return 2;
        }
    };
    match execute(&args, isolation) {
        Ok(()) => 0,
        Err(_) => {
            eprintln!("replay-harness: pass failed");
            3
        }
    }
}

fn open_private(path: &Path) -> std::io::Result<File> {
    OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
}
fn write_record(out: &mut File, value: &serde_json::Value) -> std::io::Result<()> {
    serde_json::to_writer(&mut *out, value)?;
    out.write_all(b"\n")?;
    out.sync_data()
}
fn blinding_key(path: &Path) -> Result<Vec<u8>> {
    let file = OpenOptions::new()
        .read(true)
        // A FIFO must not block open before the opened-FD regular-file check.
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let meta = file.metadata()?;
    // SAFETY: geteuid has no preconditions. Validate the open FD before reading.
    anyhow::ensure!(
        meta.is_file()
            && meta.nlink() == 1
            && meta.len() == 32
            && meta.uid() == unsafe { libc::geteuid() }
            && meta.mode() & 0o077 == 0,
        "private 32-byte blinding key required"
    );
    let mut key = Vec::with_capacity(32);
    file.take(33).read_to_end(&mut key)?;
    anyhow::ensure!(key.len() == 32, "invalid blinding key");
    Ok(key)
}
fn blinded(key: &[u8], domain: &[u8], value: &[u8]) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(domain);
    mac.update(value);
    format!("{:x}", mac.finalize().into_bytes())
}
// Exact wire-field equality for all 15 fields in the shared money oracle.
// Structured/string values may contain provider labels or account selectors:
// commit to their complete value AND presence, never export them verbatim.
const MONEY_FIELDS: [&str; 15] = [
    "input_tokens",
    "output_tokens",
    "cache_read_tokens",
    "cache_creation_5m_tokens",
    "cache_creation_1h_tokens",
    "reasoning_output_tokens",
    "unattributed_total_tokens",
    "request_count",
    "cost",
    "usage_buckets",
    "model_usage",
    "removed_usage",
    "removed_request_count",
    "usage_accounting_contract",
    "telemetry_owned_complete",
];

struct EmissionSink {
    out: Arc<Mutex<File>>,
    key: Vec<u8>,
    pass: Pass,
    collected_at: String,
}
thread_local! {
    static EMISSION_SINK: RefCell<Option<EmissionSink>> = const { RefCell::new(None) };
}
struct EmissionGuard;
impl Drop for EmissionGuard {
    fn drop(&mut self) {
        EMISSION_SINK.with(|slot| slot.borrow_mut().take());
    }
}

/// Only the real scan's collection input clock is overridden. Keep the emitted
/// clock bytes in the digest; no wall-clock normalization is permitted.
pub(crate) fn collection_timestamp() -> Option<String> {
    EMISSION_SINK.with(|slot| slot.borrow().as_ref().map(|sink| sink.collected_at.clone()))
}

/// Feature-only observation after the HTTP exchange succeeds. No sink is
/// installed by serve. The typed request is required to reuse the existing
/// sentinel/envelope computation; the body is the exact pre-compression wire.
pub(crate) fn observe_emitted_batch(request: &SnapshotBatchRequest, body: &[u8]) -> Result<()> {
    EMISSION_SINK.with(|slot| {
        let sink = slot.borrow();
        let Some(sink) = sink.as_ref() else {
            return Ok(());
        };
        let wire: serde_json::Value = serde_json::from_slice(body)?;
        let mut out = sink.out.lock().map_err(|_| anyhow!("output poisoned"))?;
        observe_batch(&mut out, &sink.key, sink.pass, request, &wire)
    })
}

fn observe_batch(
    out: &mut File,
    key: &[u8],
    pass: Pass,
    request: &SnapshotBatchRequest,
    batch: &serde_json::Value,
) -> Result<()> {
    let source = match request.source.as_str() {
        "claude_code" => SnapshotSource::ClaudeCode,
        "codex" => SnapshotSource::Codex,
        "pi" => SnapshotSource::Pi,
        _ => return Err(anyhow!("unknown synthetic batch source")),
    };
    let items = batch["snapshots"]
        .as_array()
        .ok_or_else(|| anyhow!("missing snapshots"))?;
    anyhow::ensure!(
        items.len() == request.snapshots.len(),
        "wire item count mismatch"
    );
    for (item, typed) in items.iter().zip(&request.snapshots) {
        let mut body = item.clone();
        let envelope = body
            .as_object_mut()
            .ok_or_else(|| anyhow!("wire item missing"))?
            .remove("semantic_envelope")
            .ok_or_else(|| anyhow!("wire envelope missing"))?;
        anyhow::ensure!(body == serde_json::to_value(typed)?, "wire item mismatch");
        anyhow::ensure!(
            envelope
                == serde_json::to_value(crate::snapshots::snapshot_semantic_envelope(
                    source,
                    typed,
                    request.upload_policy
                ))?,
            "wire envelope mismatch"
        );

        // Same sentinel and production hash computation as money_equivalence.
        // Never normalize money, labels, policies, identities or body evidence.
        let mut normalized = typed.clone();
        normalized.source_file_fingerprint = Some("physical-identity:excluded".into());
        body["source_file_fingerprint"] = serde_json::json!(normalized.source_file_fingerprint);
        let normalized_envelope =
            serde_json::to_value(crate::snapshots::snapshot_semantic_envelope(
                source,
                &normalized,
                request.upload_policy,
            ))?;
        // Fail closed if physical identity ever starts changing another field.
        let mut before = envelope;
        for name in ["revision_hash", "revision_v2_hash"] {
            before[name] = normalized_envelope[name].clone();
        }
        anyhow::ensure!(
            before == normalized_envelope,
            "sentinel changed semantic content"
        );
        body["semantic_envelope"] = normalized_envelope;
        let bytes = crate::canonical_json::canonicalize(&body)?;
        let mut totals = serde_json::Map::new();
        for &name in &MONEY_FIELDS[..7] {
            let value = if name == "unattributed_total_tokens" && item.get(name).is_none() {
                0
            } else {
                item[name]
                    .as_u64()
                    .ok_or_else(|| anyhow!("missing numeric token total"))?
            };
            totals.insert(name.into(), serde_json::Value::from(value));
        }
        let money = money_commitments(key, item)?;
        write_record(
            out,
            &serde_json::json!({"kind":"session", "pass":pass,
            "blinded_session_hash":blinded(key, b"replay-session-v1\0", format!("{}\0{}",source.api_slug(),typed.source_session_id).as_bytes()),
            "source":source.api_slug(), "token_totals":totals, "entity_count":1,
            "money_oracle":money, "money_oracle_encoding":"keyed-field-digests-v1",
            "emitted_body_digest":blinded(key, b"replay-emitted-body-v1\0", &bytes)}),
        )?;
    }
    Ok(())
}

fn money_commitments(key: &[u8], item: &serde_json::Value) -> Result<serde_json::Value> {
    let mut money = serde_json::Map::new();
    for name in MONEY_FIELDS {
        // Presence is significant (absent != explicit null). Every field is
        // committed independently; no arbitrary input keys leave this module.
        let value = serde_json::json!([item.get(name).is_some(), item.get(name)]);
        let bytes = crate::canonical_json::canonicalize(&value)?;
        let domain = format!("replay-money-field-v1\0{name}\0");
        money.insert(
            name.into(),
            serde_json::Value::String(blinded(key, domain.as_bytes(), &bytes)),
        );
    }
    Ok(serde_json::Value::Object(money))
}

#[cfg(test)]
mod oracle_tests {
    use super::*;

    #[test]
    fn every_money_field_and_its_presence_are_bound_without_exporting_content() {
        let key = [11; 32];
        let baseline = money_commitments(&key, &serde_json::json!({})).unwrap();
        for field in MONEY_FIELDS {
            let null = serde_json::json!({field: null});
            let value =
                serde_json::json!({field: {"private-selector-canary": "private-path-canary"}});
            let null = money_commitments(&key, &null).unwrap();
            let changed = money_commitments(&key, &value).unwrap();
            assert_ne!(baseline[field], null[field], "presence lost: {field}");
            assert_ne!(null[field], changed[field], "value lost: {field}");
            for sibling in MONEY_FIELDS {
                if sibling != field {
                    assert_eq!(baseline[sibling], changed[sibling]);
                }
            }
            let text = changed.to_string();
            assert!(!text.contains("private-selector-canary"));
            assert!(!text.contains("private-path-canary"));
        }
        assert_ne!(baseline["cost"], baseline["removed_usage"]);
        assert_ne!(
            baseline,
            money_commitments(&[12; 32], &serde_json::json!({})).unwrap()
        );
    }
}

fn fake_collection(source: SnapshotSource) -> AgentStatusCollection {
    use ottto_protocol::{AgentStatusCollectionMethod, AgentStatusState};
    let status = AgentStatusSnapshot {
        source: source_kind(source),
        status: AgentStatusState::Available,
        collection_method: AgentStatusCollectionMethod::ManualFallback,
        captured_at: current_rfc3339(),
        expires_at: "2099-01-01T00:00:00Z".into(),
        account: None,
        model: None,
        quota_windows: Vec::new(),
        credit_balances: Vec::new(),
        context: None,
        capabilities: Vec::new(),
        plan_observations: Vec::new(),
        diagnostics: Vec::new(),
        runtime_defaults: None,
    };
    AgentStatusCollection {
        snapshots: vec![status.clone()],
        source_health_snapshot: status,
        codex_scan_homes: Vec::new(),
        codex_home_bindings: Vec::new(),
    }
}

struct ReplayOwner<'a> {
    inner: SnapshotCycleOwner<'a>,
    complete: Option<bool>,
}
impl Owner for ReplayOwner<'_> {
    type Source = SnapshotSource;
    type Frame = SourcePreparation;
    type Completed = (SourcePreparation, ScanIndex, SourceScanResult);
    fn prepare(
        &mut self,
        source: SnapshotSource,
        remaining: Option<usize>,
    ) -> Result<Option<Self::Frame>> {
        self.inner.prepare(source, remaining)
    }
    fn validate(&mut self, frame: &Self::Frame) -> Result<()> {
        self.inner.validate(frame)
    }
    fn step(
        &mut self,
        frame: Self::Frame,
        remaining: Option<usize>,
    ) -> Step<Self::Frame, Self::Completed> {
        self.inner.step(frame, remaining)
    }
    fn bound(&self, frame: &Self::Frame, limit: usize) -> Option<usize> {
        self.inner.bound(frame, limit)
    }
    fn finish(&mut self, completed: Self::Completed, remaining: Option<usize>) -> Result<()> {
        let complete = completed.2.census_complete;
        self.inner.finish(completed, remaining)?;
        self.complete = Some(complete);
        Ok(())
    }
    fn outcome(&mut self, source: SnapshotSource, result: Result<()>) {
        self.inner.outcome(source, result)
    }
    fn monotonic(&self) -> Duration {
        self.inner.monotonic()
    }
    fn parked(&mut self, bytes: usize) {
        self.inner.parked(bytes)
    }
    fn retained_bound(&self, limit: usize) -> Option<usize> {
        self.inner.retained_bound(limit)
    }
    fn discard_retained(&mut self) {
        self.inner.discard_retained()
    }
    fn boundary(&mut self, busy: impl Iterator<Item = SnapshotSource>) {
        self.inner.boundary(busy)
    }
}

fn execute(args: &Args, isolation: Isolation) -> Result<()> {
    // The exact listener address is known before any scratch mutation.
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let url = format!("http://{}", listener.local_addr()?);
    let endpoint_ok =
        std::env::var_os("OTTTO_API_BASE_URL").map_or(true, |value| value == url.as_str());
    let connection_ok = FileConnectionStore::default()
        .load()?
        .map_or(true, |binding| binding.api_base_url == url);
    if !endpoint_ok || !connection_ok {
        eprintln!("replay-harness: isolation refused");
        std::process::exit(2);
    }
    let locked = crate::locked_state_dir::LockedStateDir::acquire(&isolation.support)?;
    crate::locked_state_dir::hold_for_process(locked);
    let output = Arc::new(Mutex::new(open_private(&isolation.out)?));
    let backend = Backend::with_listener(listener, None)?;
    EMISSION_SINK.with(|slot| {
        *slot.borrow_mut() = Some(EmissionSink {
            out: Arc::clone(&output),
            key: isolation.key,
            pass: args.pass,
            collected_at: args.collected_at.clone(),
        });
    });
    let _emissions = EmissionGuard;
    fs::write(isolation.support.join(MARKER), MARKER_BYTES)?;
    let home = isolation.support.join("home");
    fs::create_dir_all(&home)?;
    fs::set_permissions(&home, fs::Permissions::from_mode(0o700))?;
    let _home = EnvVarGuard::set_path("HOME", &home);
    let _pi = EnvVarGuard::set_path("PI_CODING_AGENT_DIR", &home.join(".pi/agent"));
    let _claude = EnvVarGuard::set_path("CLAUDE_CONFIG_DIR", &home.join(".claude"));
    let _codex = EnvVarGuard::set_path("CODEX_HOME", &home.join(".codex"));
    let sources: Vec<_> = [
        SnapshotSource::ClaudeCode,
        SnapshotSource::Codex,
        SnapshotSource::Pi,
    ]
    .into_iter()
    .filter(|source| !isolation.roots.get(*source).is_empty())
    .collect();
    let (device, _environment) = synthetic_device(
        &isolation.support,
        &isolation.secrets,
        &backend.url,
        sources
            .iter()
            .map(|source| source.api_slug().into())
            .collect(),
    )?;
    REGISTRY.with(|registry| *registry.borrow_mut() = Some(isolation.roots));
    let _registry = RegistryGuard;
    let daemon = LocalDaemon::new(
        ottto_protocol::MachineIdentity {
            machine_id: "otm_test".into(),
            installation_id: "install_test".into(),
            display_name: "Synthetic replay".into(),
            hostname: "synthetic.invalid".into(),
            os: ottto_protocol::OperatingSystem::Macos,
            arch: "arm64".into(),
            local_platform_version: ottto_core::compiled_release_version(),
            hardware_uuid: None,
            account_scope: None,
        },
        crate::ControlToken::new("synthetic-replay-control")?,
        current_rfc3339(),
    );
    let _proxies: Vec<_> = [
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
    ]
    .into_iter()
    .map(EnvVarGuard::remove)
    .collect();
    let client = SnapshotApiClient::new(backend.url.clone());
    let mut retry = live_snapshot_retry::LiveRetryOwner::closed();
    let mut transport = crate::net_resilience::TransportCycleOutcome::default();
    let mut totals = Totals::default();
    let mut pages = 0;
    write_record(
        &mut *output.lock().map_err(|_| anyhow!("output poisoned"))?,
        &serde_json::json!({"kind":"pass_started", "pass":args.pass, "held_files":isolation.held_files}),
    )?;
    for &source in &sources {
        loop {
            // The CLI explicitly requests already-due pages, without sleeping
            // for serve's cadence between pages. No receipt/index state resets.
            source_cadences()
                .lock()
                .map_err(|_| anyhow!("cadence poisoned"))?
                .remove(source.api_slug());
            let mut failed = Vec::new();
            let (complete, records) = crate::local_resource_diagnostics::capture(|| {
                crate::agent_status_refresh::with_collection(fake_collection(source), || {
                    let mut owner = ReplayOwner {
                        inner: SnapshotCycleOwner {
                            retry: &mut retry,
                            account_witness: daemon.snapshot_scan_account_witness()?,
                            client: &client,
                            device: &device,
                            device_secret: "device-secret",
                            machine_id: "otm_test",
                            home: &home,
                            support_dir: &isolation.support,
                            daemon: &daemon,
                            transport_cycle: &mut transport,
                            failed_sources: &mut failed,
                            started: Instant::now(),
                            codex_started: None,
                        },
                        complete: None,
                    };
                    crate::source_rotation::run(
                        &mut owner,
                        &[source],
                        crate::source_rotation::PARKED_BUDGET,
                    );
                    Ok::<_, anyhow::Error>(owner.complete)
                })
            });
            let complete = complete?;
            let mut out = output.lock().map_err(|_| anyhow!("output poisoned"))?;
            for record in records {
                totals.observe(&record);
                write_record(
                    &mut out,
                    &serde_json::json!({"kind":"local_resources", "pass":args.pass, "record":record}),
                )?;
            }
            anyhow::ensure!(
                failed.is_empty() && complete.is_some(),
                "source page failed or deferred"
            );
            pages += 1;
            write_record(
                &mut out,
                &serde_json::json!({"kind":"page_finished", "pass":args.pass, "pages":pages, "source":source.api_slug(), "census_complete":complete}),
            )?;
            if args.kill_after_pages == Some(pages) {
                // Aggregate records and emitted entities are durable before this
                // deterministic edge. The OS releases the real state-dir lock.
                unsafe {
                    libc::kill(libc::getpid(), libc::SIGKILL);
                }
                return Err(anyhow!("kill injection failed"));
            }
            if complete == Some(true) {
                break;
            }
        }
    }
    // Count only this harness's own store entries after the real P0 save.
    // Later quiet passes keep their zero durable-store I/O contract.
    let durable_records_after_save = if args.pass == Pass::P0 {
        let mut total = Some(0u64);
        for &source in &sources {
            let row = durable_after_save_diagnostics(
                &daemon.transcript_cache,
                &isolation.support,
                source,
            );
            total = total
                .zip(row["records_after_save"].as_u64())
                .map(|(a, b)| a + b);
            write_record(
                &mut *output.lock().map_err(|_| anyhow!("output poisoned"))?,
                &row,
            )?;
        }
        total
    } else {
        None
    };
    let durable_store_io = durable_store_io(&daemon.transcript_cache, &sources);
    write_record(
        &mut *output.lock().map_err(|_| anyhow!("output poisoned"))?,
        &serde_json::json!({"kind":"pass_totals", "pass":args.pass, "pages":pages,
        "full_reads":(!totals.unknown).then_some(totals.full), "tail_reads":(!totals.unknown).then_some(totals.tail), "restored":totals.restored, "bytes_read":(!totals.unknown).then_some(totals.bytes),
        "index_reuse_skips":totals.index_reuse_skips, "durable_store_io":durable_store_io,
        "durable_records_after_save":durable_records_after_save,
        "emitted_entities":backend.stats.items.load(std::sync::atomic::Ordering::Relaxed),
        "read_units":"sampled acquisition selections; completed native + guard bytes", "advisory_only":true}),
    )?;
    Ok(())
}

#[derive(Default)]
struct Totals {
    unknown: bool,
    full: u64,
    tail: u64,
    restored: u64,
    bytes: u64,
    index_reuse_skips: u64,
}
impl Totals {
    fn observe(&mut self, row: &serde_json::Value) {
        if row["stage"] != "native_collection_page" {
            return;
        }
        let counts = &row["counts"];
        self.index_reuse_skips += counts["index_reuse_skips"].as_u64().unwrap_or(0);
        let reads = &counts["sampled_acquisition"];
        self.unknown |= !reads.is_object();
        self.full += reads["full_selections"].as_u64().unwrap_or(0);
        self.tail += reads["tail_selections"].as_u64().unwrap_or(0);
        self.bytes += reads["completed_native_bytes"].as_u64().unwrap_or(0)
            + reads["completed_guard_bytes"].as_u64().unwrap_or(0);
        self.restored += counts["full_causes"]["restore_outcome"]["restored"]
            .as_u64()
            .unwrap_or(0);
    }
}

#[derive(Default, Serialize)]
struct DurableStoreIo {
    restore_attempts: u64,
    records_read: u64,
    bytes_read: u64,
}

/// Existing process-lifetime store evidence, read without opening any files.
/// Missing/unsupported telemetry stays unavailable; it is never an idle zero.
fn durable_store_io(
    cache: &crate::snapshots::sampled_scan::SharedCache,
    sources: &[SnapshotSource],
) -> Option<DurableStoreIo> {
    let mut io = DurableStoreIo::default();
    let mut observed = false;
    for &source in sources {
        let (counts, store) = cache.durable_counters(source)?;
        observed = true;
        // Every source view repeats the same global restore count.
        io.restore_attempts = io.restore_attempts.max(counts.restore_attempts);
        io.records_read += store.records_read + store.gc_records_read;
        io.bytes_read += store.bytes_read
            + store.guard_header_bytes
            + store.guard_verify_bytes
            + store.delete_verify_bytes
            + store.overwrite_verify_bytes
            + store.gc_bytes_read;
    }
    observed.then_some(io)
}

/// Directory metadata only: no store header, body, transcript or key reads.
/// An inaccessible/unsafe/over-bound inventory is unavailable, never zero.
fn count_scratch_records(dir: &Path, support: &Path) -> (Option<u64>, &'static str) {
    if !dir.starts_with(support) {
        return (None, "outside_scratch");
    }
    match fs::symlink_metadata(dir) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return (Some(0), "directory_absent");
        }
        Err(_) => return (None, "metadata_failed"),
        Ok(_) => {}
    }
    if !private_dir(dir).is_ok_and(|path| path.starts_with(support)) {
        return (None, "unsafe_directory");
    }
    let Ok(entries) = fs::read_dir(dir) else {
        return (None, "inventory_failed");
    };
    let mut count = 0u64;
    for (visited, entry) in entries.enumerate() {
        if visited >= crate::durable_tail_store::INVENTORY_BOUND * 2 {
            return (None, "inventory_bound");
        }
        let Ok(entry) = entry else {
            return (None, "entry_failed");
        };
        let name = entry.file_name();
        let Some(digest) = name.to_str().and_then(|name| name.strip_suffix(".rec")) else {
            continue;
        };
        if digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            continue;
        }
        match entry.file_type() {
            Ok(kind) if kind.is_file() => count += 1,
            _ => return (None, "unsafe_record_entry"),
        }
    }
    (Some(count), "counted")
}

fn durable_after_save_diagnostics(
    cache: &crate::snapshots::sampled_scan::SharedCache,
    support: &Path,
    source: SnapshotSource,
) -> serde_json::Value {
    // Slot inspection does not initialize anything. No cache/store lock is
    // held during the count, and no path or filesystem error is serialized.
    let metadata = cache.durable_replay_store(source);
    let (records, inventory) = metadata.as_ref().map_or((None, "unavailable"), |(dir, _)| {
        count_scratch_records(dir, support)
    });
    let disabled = metadata.as_ref().and_then(|(_, reason)| *reason);
    let counters = cache.durable_counters(source).map(|(counts, store)| {
        serde_json::json!({
            "not_persisted":counts.not_persisted,
            "write_unlocked":counts.write_unlocked,
            "write_deferred":counts.write_deferred,
            "records_written":store.records_written,
            "records_clean":store.records_clean,
            "records_deferred":store.records_deferred,
            "batches":store.batches,
            "budget_refused":store.budget_refused,
            "store_write_skipped":store.store_write_skipped,
            "format_hold":store.format_hold,
            "t14_rebuild":store.t14_rebuild,
            "records_invalidated":store.records_invalidated,
            "gc_records_deleted":store.gc_records_deleted,
            "disk_records":store.disk_records,
        })
    });
    let layout_supported = crate::heap_layout_bound::layout_supported();
    let store_state = if metadata.is_none() {
        "unavailable"
    } else if disabled.is_some() {
        "disabled"
    } else if !layout_supported {
        "degraded_unsupported_heap_layout"
    } else {
        "enabled"
    };
    serde_json::json!({
        "kind":"durable_after_save_diagnostics", "pass":"P0", "source":source.api_slug(),
        "state_lock_held":crate::locked_state_dir::held_for(support).is_some(),
        "heap_layout_supported":layout_supported, "store_state":store_state,
        "platform_qualification":(!layout_supported).then_some(PLATFORM_QUALIFICATION),
        "store_initialized":metadata.is_some(), "store_disabled":disabled,
        "records_after_save":records, "inventory":inventory, "write_counters":counters,
        "counter_scope":"process lifetime; write/refusal totals; source store totals",
    })
}
