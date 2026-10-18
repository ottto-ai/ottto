//! Offline producer of h527 diagnostic candidates from one explicit input
//! bundle (`h527_producer_input:v1`).
//!
//! It reads only the files the bundle names: the 18 target transcripts and
//! every `.jsonl` file under the named peer roots. It never touches a scan
//! index, upload progress, sidecar, network or daemon state, and it writes only
//! to its own new output directory.
//!
//! Steps, in this order:
//!
//! 1. Parse each target with the unchanged Claude parser. A target needs a
//!    complete parse, exactly one item, a native id on every counted request
//!    and totals equal to the sum of its per-request usage.
//! 2. Stream every peer file once and compare native request ids exactly, in
//!    memory, against all 18 targets. Fork-copied lines belong to the session
//!    they name. A cap, a changed or unreadable file, a compressed transcript or
//!    an unparseable id-bearing line leaves coverage unknown, and then every
//!    target is held without a body.
//! 3. Fix the counting allocation (B2) for the whole batch before any body or
//!    money exists: an id seen in any peer is excluded from every target; an
//!    id shared only by targets is kept by the first-ACKed target, else the
//!    smaller session key hash. B2 is counting only. It is not ownership.
//! 4. Re-parse each target with the same parser, dropping only the lines of
//!    its excluded request ids, and reconcile kept ids, per-request usage, item
//!    totals and usage rows exactly. The ordinary daemon serializer then writes
//!    the one-item batch body.
//! 5. Record, for every kept shared request, the keeping root and its tag
//!    state. This producer has no Contract-5 permit, so every request stays
//!    untagged under its starting subscription; a body carrying request
//!    evidence is held as unsupported.
//!
//! Bodies go only into the unqualified diagnostic artifact. The operator
//! packet for the same run keeps every member held without a body.
use super::{
    local_exclusion_disclosure_json, ordinary_batch_body, sha256_hex, validate_members,
    validate_scope, ApprovedMember, Conservation, CopyScreen, ExcludedTokenCounts, HeldReason,
    LocalExclusionSummary, OperatorScope, Packet, PacketMember, ProducerBuild,
    CANDIDATES_CONTRACT_VERSION, DISCLOSED_RESIDUAL_STATEMENT,
};
use crate::snapshots::{
    apply_claude_code_line, apply_upload_policy, claude_code_delta_usage,
    claude_fork_line_provenance, claude_request_id_set_fingerprint, claude_subagent_identity,
    opened_object_identity, parse_opened_jsonl_file, scan_file_fingerprint_with_opened_identity,
    string_at, ClaudeForkLineProvenance, ClaudeTitleMetadata, SnapshotAccumulator, SnapshotItem,
    SnapshotSource, SnapshotUploadPolicy, UsageTotals, MAX_JSONL_FILE_BYTES, MAX_JSONL_LINE_BYTES,
};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Write};
#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

pub(crate) const PRODUCER_INPUT_CONTRACT_VERSION: &str = "h527_producer_input:v1";
pub(crate) const PRODUCER_ARTIFACT_CONTRACT_VERSION: &str = "h527_producer_diagnostic:v1";
const PRODUCER_SUMMARY_CONTRACT_VERSION: &str = "h527_producer_summary:v1";
const PRODUCER_DISCLOSURES_CONTRACT_VERSION: &str = "h527_producer_disclosures:v1";
const B2_ALLOCATION_RULE: &str =
    "peer_excludes_all_targets_then_first_acked_else_smaller_session_key_sha256:v1";
const REQUEST_WITNESS_SCHEME: &str = "sha256_hex(native_request_id):v1";
const PATH_WITNESS_SCHEME: &str = "sha256_hex(canonical_path_utf8_lossy):v1";
const ESTIMATE_LABEL: &str =
    "EXPORTER ESTIMATE at catalog prices; never server canonical admitted money";
const COPY_SCREEN_NOT_RUN_REASON: &str =
    "server copy screen was not run by the local producer; no screen artifact exists";
const MAX_INPUT_BUNDLE_BYTES: u64 = 4 * 1024 * 1024;
/// Exact decimal rates are stored as integers of 1e-12 USD per million tokens.
const RATE_FRACTION_DIGITS: usize = 12;
/// Tokens x (1e-12 USD per 1e6 tokens) => 1e-18 USD units.
const COST_FRACTION_DIGITS: usize = 18;
const PEER_ROOT_CLASSES: [&str; 6] = ["projects", "slot", "held", "archive", "quarantine", "other"];
const COMPRESSED_EXTENSIONS: [&str; 7] = ["zst", "gz", "xz", "bz2", "lz4", "br", "zip"];
/// Pipeline stages this offline producer does not reproduce. Each one is
/// disclosed rather than imitated; SESSION's read-only prepare and the SOURCE,
/// COST and SI reviews see their effect on the actual body.
const NOT_REPRODUCED_STAGES: [&str; 6] = [
    "claude_local_evidence_and_contract5_permit: no request tags, untagged rows",
    "session_account_binding: no sidecar account evidence attached, creator gate not evaluated",
    "desktop_title_metadata: no desktop-store title or identity evidence",
    "attribution_context: no launch attribution facts",
    "backfill_cutoff: not evaluated",
    "cache_head_identity: cache observations not attached, as with cache upload disabled",
];

// ---------------------------------------------------------------------------
// Input bundle

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProducerInput {
    pub(crate) contract_version: String,
    pub(crate) scope: InputScope,
    /// Deterministic body collection timestamp (RFC 3339).
    pub(crate) collected_at: String,
    pub(crate) upload_policy: InputUploadPolicy,
    pub(crate) context_curve_enabled: bool,
    pub(crate) targets: Vec<InputTarget>,
    pub(crate) peer_roots: Vec<InputPeerRoot>,
    pub(crate) bounds: InputBounds,
    #[serde(default)]
    pub(crate) catalog_prices: Option<CatalogPrices>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct InputScope {
    pub(crate) operation_id: String,
    pub(crate) user_id: String,
    pub(crate) organization_id: String,
    pub(crate) device_id: String,
    pub(crate) machine_id: String,
    pub(crate) producer_revision: String,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct InputUploadPolicy {
    pub(crate) session_titles_enabled: bool,
    pub(crate) workspace_labels_enabled: bool,
    pub(crate) session_artifacts_enabled: bool,
    pub(crate) session_attribution_enabled: bool,
    pub(crate) session_attribution_labels_enabled: bool,
}

impl From<InputUploadPolicy> for SnapshotUploadPolicy {
    fn from(policy: InputUploadPolicy) -> Self {
        Self {
            session_titles_enabled: policy.session_titles_enabled,
            workspace_labels_enabled: policy.workspace_labels_enabled,
            session_artifacts_enabled: policy.session_artifacts_enabled,
            session_attribution_enabled: policy.session_attribution_enabled,
            session_attribution_labels_enabled: policy.session_attribution_labels_enabled,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct InputTarget {
    pub(crate) source_session_id: String,
    pub(crate) session_key_sha256: String,
    pub(crate) prior_refusal_body_witness: String,
    pub(crate) transcript_path: PathBuf,
    /// SOURCE's first-ACK order for this session's accepted history, if known.
    /// Lower is earlier. Absent sorts after every known value.
    pub(crate) b2_first_ack_order: Option<u64>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct InputPeerRoot {
    pub(crate) class: String,
    pub(crate) path: PathBuf,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct InputBounds {
    pub(crate) max_peer_files: u64,
    pub(crate) max_peer_total_bytes: u64,
    pub(crate) max_peer_file_bytes: u64,
    pub(crate) max_line_bytes: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CatalogPrices {
    pub(crate) publication: CatalogPublication,
    /// Keyed `<model>|<context_bucket>`, the parser's own selector bucket.
    pub(crate) rates_usd_per_mtok: BTreeMap<String, CatalogRates>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CatalogPublication {
    pub(crate) source: String,
    pub(crate) revision: String,
    pub(crate) sha256: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CatalogRates {
    pub(crate) input: String,
    pub(crate) output: String,
    pub(crate) cache_read: String,
    pub(crate) cache_creation_5m: String,
    pub(crate) cache_creation_1h: String,
}

// ---------------------------------------------------------------------------
// Output

#[derive(Debug, Clone)]
pub(crate) struct ProducerOutput {
    /// Unqualified diagnostic artifact. Local review evidence only.
    pub(crate) artifact_json: String,
    pub(crate) artifact_sha256: String,
    /// The frozen operator packet; every member held, no body fields.
    pub(crate) candidate_bundle_json: String,
    pub(crate) candidate_bundle_sha256: String,
    /// Per-target disclosure records, only when a catalog estimate exists.
    pub(crate) disclosures_json: Option<String>,
    /// Content-free run summary.
    pub(crate) summary: Value,
}

/// Operator entry: read the bundle, produce, and write the outputs into a new
/// private directory. Returns the content-free summary as JSON text.
pub fn run_operator_producer(input_path: &Path, out_dir: &Path) -> Result<String, String> {
    let input_bytes = read_bounded(input_path, MAX_INPUT_BUNDLE_BYTES)
        .map_err(|error| format!("input bundle: {error}"))?;
    let input: ProducerInput =
        serde_json::from_slice(&input_bytes).map_err(|error| format!("input bundle: {error}"))?;
    let producer = ProducerBuild::current()?;
    let output = produce(&input, &sha256_hex(&input_bytes), &producer)?;
    write_outputs(out_dir, &output)?;
    serde_json::to_string_pretty(&output.summary).map_err(|error| format!("summary: {error}"))
}

fn write_outputs(out_dir: &Path, output: &ProducerOutput) -> Result<(), String> {
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    builder.mode(0o700);
    builder
        .create(out_dir)
        .map_err(|error| format!("output directory must be new: {error}"))?;
    let mut files = vec![
        ("artifact.json", output.artifact_json.as_str()),
        (
            "candidate-bundle.json",
            output.candidate_bundle_json.as_str(),
        ),
    ];
    if let Some(disclosures) = output.disclosures_json.as_deref() {
        files.push(("disclosures.json", disclosures));
    }
    let summary = serde_json::to_string_pretty(&output.summary)
        .map_err(|error| format!("summary: {error}"))?;
    files.push(("summary.json", summary.as_str()));
    for (name, contents) in files {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
        let mut file = options
            .open(out_dir.join(name))
            .map_err(|error| format!("write {name}: {error}"))?;
        file.write_all(contents.as_bytes())
            .and_then(|()| file.sync_all())
            .map_err(|error| format!("write {name}: {error}"))?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Token dimensions

/// The eight counters the producer reconciles. Transcript usage has no
/// separate unattributed cache-creation dimension, so the disclosure's
/// `cache_creation_unattributed_input_tokens` is zero by construction.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct Dims {
    input: u64,
    output: u64,
    cache_read: u64,
    cache_creation_5m: u64,
    cache_creation_1h: u64,
    reasoning_output: u64,
    unattributed_total: u64,
    request_count: u64,
}

impl Dims {
    fn of_usage(usage: &UsageTotals) -> Self {
        Self {
            input: usage.input_tokens,
            output: usage.output_tokens,
            cache_read: usage.cache_read_tokens,
            cache_creation_5m: usage.cache_creation_5m_tokens,
            cache_creation_1h: usage.cache_creation_1h_tokens,
            reasoning_output: usage.reasoning_output_tokens,
            unattributed_total: usage.unattributed_total_tokens,
            request_count: usage.request_count,
        }
    }

    fn of_item(item: &SnapshotItem) -> Self {
        Self {
            input: item.input_tokens,
            output: item.output_tokens,
            cache_read: item.cache_read_tokens,
            cache_creation_5m: item.cache_creation_5m_tokens,
            cache_creation_1h: item.cache_creation_1h_tokens,
            reasoning_output: item.reasoning_output_tokens,
            unattributed_total: item.unattributed_total_tokens,
            request_count: item.request_count,
        }
    }

    fn of_row(row: &crate::snapshots::SnapshotModelUsage) -> Self {
        Self {
            input: row.input_tokens,
            output: row.output_tokens,
            cache_read: row.cache_read_tokens,
            cache_creation_5m: row.cache_creation_5m_tokens,
            cache_creation_1h: row.cache_creation_1h_tokens,
            reasoning_output: row.reasoning_output_tokens,
            unattributed_total: row.unattributed_total_tokens,
            request_count: row.request_count,
        }
    }

    fn fields(self) -> [u64; 8] {
        [
            self.input,
            self.output,
            self.cache_read,
            self.cache_creation_5m,
            self.cache_creation_1h,
            self.reasoning_output,
            self.unattributed_total,
            self.request_count,
        ]
    }

    fn from_fields(fields: [u64; 8]) -> Self {
        Self {
            input: fields[0],
            output: fields[1],
            cache_read: fields[2],
            cache_creation_5m: fields[3],
            cache_creation_1h: fields[4],
            reasoning_output: fields[5],
            unattributed_total: fields[6],
            request_count: fields[7],
        }
    }

    fn checked_add(self, other: Self) -> Option<Self> {
        let (a, b) = (self.fields(), other.fields());
        let mut out = [0_u64; 8];
        for index in 0..8 {
            out[index] = a[index].checked_add(b[index])?;
        }
        Some(Self::from_fields(out))
    }

    fn checked_sub(self, other: Self) -> Option<Self> {
        let (a, b) = (self.fields(), other.fields());
        let mut out = [0_u64; 8];
        for index in 0..8 {
            out[index] = a[index].checked_sub(b[index])?;
        }
        Some(Self::from_fields(out))
    }

    fn json(self) -> Value {
        json!({
            "input_tokens": self.input,
            "output_tokens": self.output,
            "cache_read_tokens": self.cache_read,
            "cache_creation_5m_tokens": self.cache_creation_5m,
            "cache_creation_1h_tokens": self.cache_creation_1h,
            "cache_creation_unattributed_input_tokens": 0,
            "reasoning_output_tokens": self.reasoning_output,
            "unattributed_total_tokens": self.unattributed_total,
            "request_count": self.request_count,
        })
    }

    fn excluded_token_counts(self) -> ExcludedTokenCounts {
        ExcludedTokenCounts {
            input_tokens: self.input,
            output_tokens: self.output,
            cache_read_tokens: self.cache_read,
            cache_creation_5m_tokens: self.cache_creation_5m,
            cache_creation_1h_tokens: self.cache_creation_1h,
            cache_creation_unattributed_input_tokens: 0,
            reasoning_output_tokens: self.reasoning_output,
            unattributed_total_tokens: self.unattributed_total,
        }
    }
}

fn sum_dims<'a>(usages: impl IntoIterator<Item = &'a UsageTotals>) -> Option<Dims> {
    usages.into_iter().try_fold(Dims::default(), |sum, usage| {
        sum.checked_add(Dims::of_usage(usage))
    })
}

// ---------------------------------------------------------------------------
// Canonical parse with an optional exact request-id exclusion

thread_local! {
    /// Request ids the current re-parse drops. Set only inside
    /// `parse_target_transcript` and cleared by its guard.
    static EXCLUDED_REQUEST_IDS: RefCell<Option<BTreeSet<String>>> = const { RefCell::new(None) };
}

struct ExclusionGuard;

impl ExclusionGuard {
    fn install(excluded: BTreeSet<String>) -> Self {
        EXCLUDED_REQUEST_IDS.with(|cell| *cell.borrow_mut() = Some(excluded));
        Self
    }
}

impl Drop for ExclusionGuard {
    fn drop(&mut self) {
        EXCLUDED_REQUEST_IDS.with(|cell| *cell.borrow_mut() = None);
    }
}

fn line_request_id(value: &Value) -> Option<String> {
    string_at(value, &["requestId"]).or_else(|| string_at(value, &["request_id"]))
}

/// The ordinary Claude line step, except that an owned line whose request id
/// is excluded is skipped whole: its usage, tools, timing and content leave
/// the session exactly as a fork-copied line does. Fork-marked lines always
/// reach the ordinary step unchanged, so their own provenance handling holds.
fn apply_claude_code_line_excluding(value: &Value, accumulator: &mut SnapshotAccumulator) {
    let excluded = claude_fork_line_provenance(value) == ClaudeForkLineProvenance::None
        && line_request_id(value).is_some_and(|request_id| {
            EXCLUDED_REQUEST_IDS.with(|cell| {
                cell.borrow()
                    .as_ref()
                    .is_some_and(|excluded| excluded.contains(&request_id))
            })
        });
    if excluded {
        // Same first step as the ordinary line: the session id is file-level.
        if accumulator.source_session_id.is_none() {
            accumulator.source_session_id = string_at(value, &["sessionId"])
                .or_else(|| string_at(value, &["session_id"]))
                .or_else(|| string_at(value, &["conversation_id"]));
        }
        return;
    }
    apply_claude_code_line(value, accumulator);
}

struct ParsedTarget {
    complete: bool,
    snapshots: Vec<SnapshotItem>,
}

/// The production open, opened-object identity and fingerprint, then the
/// ordinary parser. The scan fingerprint carries no sidecar part, because
/// sidecars are not read here.
fn parse_target_transcript(
    path: &Path,
    collected_at: &str,
    artifacts_enabled: bool,
    context_curve_enabled: bool,
    excluded: Option<BTreeSet<String>>,
) -> Result<ParsedTarget, String> {
    let source = SnapshotSource::ClaudeCode;
    let mut file = File::open(path).map_err(|error| format!("open: {error}"))?;
    let opened =
        opened_object_identity(source, &mut file).map_err(|error| format!("open: {error}"))?;
    let metadata = file.metadata().map_err(|error| format!("stat: {error}"))?;
    let modified_unix_nanos = metadata
        .modified()
        .ok()
        .and_then(|value| value.duration_since(UNIX_EPOCH).ok())
        .map(|duration| duration.as_nanos().min(u128::from(u64::MAX)) as u64)
        .unwrap_or_default();
    let fingerprint = scan_file_fingerprint_with_opened_identity(
        path,
        metadata.len(),
        modified_unix_nanos,
        source.scan_identity_version(),
        "",
        &opened,
    );
    let (apply_line, _guard): (fn(&Value, &mut SnapshotAccumulator), _) = match excluded {
        Some(excluded) => (
            apply_claude_code_line_excluding,
            Some(ExclusionGuard::install(excluded)),
        ),
        None => (apply_claude_code_line, None),
    };
    let parsed = parse_opened_jsonl_file(
        file,
        &opened,
        path,
        collected_at,
        fingerprint,
        source,
        apply_line,
        None,
        Some(&ClaudeTitleMetadata::default()),
        None,
        None,
        artifacts_enabled,
        None,
        context_curve_enabled,
    )
    .map_err(|error| format!("parse: {error:#}"))?;
    Ok(ParsedTarget {
        complete: parsed.complete(),
        snapshots: parsed.snapshots,
    })
}

// ---------------------------------------------------------------------------
// Producer

#[derive(Debug, Clone)]
struct TargetHold {
    reason: HeldReason,
    detail: String,
}

impl TargetHold {
    fn new(reason: HeldReason, detail: impl Into<String>) -> Self {
        Self {
            reason,
            detail: detail.into(),
        }
    }
}

struct TargetFile {
    canonical_path: Option<PathBuf>,
    path_sha256: String,
    size_bytes: Option<u64>,
    content_sha256: Option<String>,
    error: Option<String>,
}

/// One target's canonical parse. `request_ids` is every native id it counts
/// whenever the parse established them, even if the target itself is held:
/// a held target's ids still take part in the batch allocation.
struct TargetParse {
    request_ids: Option<BTreeSet<String>>,
    original: Result<OriginalTarget, TargetHold>,
}

struct OriginalTarget {
    item: SnapshotItem,
    request_ids: BTreeSet<String>,
    totals: Dims,
}

/// Why the request sets of the whole batch cannot be trusted. Any entry holds
/// every target without a body.
#[derive(Default)]
struct GlobalCoverage {
    unknown: Vec<String>,
    cap_overflow: Vec<String>,
}

impl GlobalCoverage {
    fn complete(&self) -> bool {
        self.unknown.is_empty() && self.cap_overflow.is_empty()
    }

    fn held_reason(&self) -> Option<HeldReason> {
        if !self.cap_overflow.is_empty() {
            Some(HeldReason::CapOverflow)
        } else if !self.unknown.is_empty() {
            Some(HeldReason::IncompleteCensus)
        } else {
            None
        }
    }
}

#[derive(Debug, Clone)]
struct PeerHit {
    peer_file_index: usize,
    owner_session_sha256: Option<String>,
    line_count: u64,
}

#[derive(Default)]
struct PeerScan {
    roots: Vec<Value>,
    files: Vec<Value>,
    file_count: u64,
    total_bytes: u64,
    ignored_file_count: u64,
    duplicate_path_count: u64,
    covered_symlink_count: u64,
    target_file_occurrences: u64,
    unidentified_usage_line_count: u64,
    /// Per target: request id -> first peer evidence.
    hits: Vec<BTreeMap<String, PeerHit>>,
    /// Per target: lines naming the target's own session (replicas, own forks).
    same_session_line_count: Vec<u64>,
    /// Lines in a replica of one target carrying a request that target counts
    /// and other targets share. That overlap is between targets, so B2
    /// allocates it; the replica is not independent peer evidence.
    shared_target_replica_line_count: u64,
    /// Per target: id-bearing usage lines naming the target's own session whose
    /// id the target does not count.
    replica_divergent_ids: Vec<BTreeSet<String>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Keeper {
    /// Excluded from every holder; the index names a holder whose peer hits
    /// carry the witness.
    Peer(usize),
    Target(usize),
}

struct Allocation {
    /// Per target: excluded request id -> keeper.
    excluded: Vec<BTreeMap<String, Keeper>>,
    /// Per target: kept request id -> other targets that also hold it.
    kept_shared: Vec<BTreeMap<String, Vec<usize>>>,
    entries: Vec<Value>,
    order: Vec<usize>,
    sha256: String,
}

/// Build the artifact, the held operator packet and optional disclosures.
pub(crate) fn produce(
    input: &ProducerInput,
    input_sha256: &str,
    producer: &ProducerBuild,
) -> Result<ProducerOutput, String> {
    if input.contract_version != PRODUCER_INPUT_CONTRACT_VERSION {
        return Err(format!(
            "input contract_version must be {PRODUCER_INPUT_CONTRACT_VERSION}"
        ));
    }
    let scope = OperatorScope {
        operation_id: input.scope.operation_id.clone(),
        user_id: input.scope.user_id.clone(),
        organization_id: input.scope.organization_id.clone(),
        device_id: input.scope.device_id.clone(),
        machine_id: input.scope.machine_id.clone(),
        producer_revision: input.scope.producer_revision.clone(),
    };
    let members = input
        .targets
        .iter()
        .map(|target| ApprovedMember {
            source_session_id: target.source_session_id.clone(),
            session_key_sha256: target.session_key_sha256.clone(),
            prior_refusal_body_witness: target.prior_refusal_body_witness.clone(),
        })
        .collect::<Vec<_>>();
    validate_scope(&scope)?;
    validate_members(&scope, &members)?;
    time::OffsetDateTime::parse(
        &input.collected_at,
        &time::format_description::well_known::Rfc3339,
    )
    .map_err(|_| "collected_at must be RFC 3339".to_string())?;
    validate_bounds(&input.bounds)?;
    if input.peer_roots.is_empty() {
        return Err("at least one peer root is required".to_string());
    }
    for root in &input.peer_roots {
        if !PEER_ROOT_CLASSES.contains(&root.class.as_str()) {
            return Err(format!(
                "peer root class must be one of {PEER_ROOT_CLASSES:?}"
            ));
        }
    }
    if let Some(prices) = &input.catalog_prices {
        validate_prices(prices)?;
    }
    let upload_policy = SnapshotUploadPolicy::from(input.upload_policy);
    let target_count = input.targets.len();
    let mut coverage = GlobalCoverage::default();

    // 1. Targets: exact files and canonical original request sets.
    let mut files = Vec::with_capacity(target_count);
    let mut originals = Vec::with_capacity(target_count);
    for (index, target) in input.targets.iter().enumerate() {
        let file = target_file(&target.transcript_path);
        let parse = match &file.error {
            Some(error) => TargetParse {
                request_ids: None,
                original: Err(TargetHold::new(
                    HeldReason::MissingEvidence,
                    format!("transcript unreadable: {error}"),
                )),
            },
            None => original_target(target, &input.collected_at, upload_policy, input),
        };
        if parse.request_ids.is_none() {
            coverage
                .unknown
                .push(format!("target {index} request set unknown"));
        }
        files.push(file);
        originals.push(parse);
    }
    let mut seen_paths = BTreeSet::new();
    for path in files.iter().filter_map(|file| file.canonical_path.as_ref()) {
        if !seen_paths.insert(path.clone()) {
            return Err("target transcript paths must be distinct".to_string());
        }
    }

    // 2. Peers: one bounded streaming pass, exact native id comparison.
    let peers = scan_peers(input, &files, &originals, &mut coverage);

    // 3. B2 allocation for the whole batch, frozen before bodies and money.
    let allocation = allocate(input, &originals, &peers)?;

    // 4-5. Rebuild, reconcile and serialize each target.
    let mut target_reports = Vec::with_capacity(target_count);
    let mut packet_reasons = Vec::with_capacity(target_count);
    let mut estimates = Vec::with_capacity(target_count);
    for index in 0..target_count {
        let built = build_target(
            index,
            input,
            &scope,
            &members,
            upload_policy,
            producer,
            &files[index],
            &originals[index].original,
            &peers,
            &allocation,
            &coverage,
        );
        packet_reasons.push(built.reason);
        estimates.push(built.estimate);
        target_reports.push(built.report);
    }

    // Held operator packet, each member bound to its content-free report.
    let mut report_shas = Vec::with_capacity(target_count);
    for report in &target_reports {
        let mut content_free = report.clone();
        if let Some(body) = content_free.get_mut("body").and_then(Value::as_object_mut) {
            body.remove("unqualified_batch_request_json");
        }
        let canonical = crate::canonical_json::canonicalize(&content_free)
            .map_err(|error| format!("target report: {error}"))?;
        report_shas.push(sha256_hex(&canonical));
    }
    let packet = Packet {
        contract_version: CANDIDATES_CONTRACT_VERSION,
        operation_id: &scope.operation_id,
        user_id: &scope.user_id,
        organization_id: &scope.organization_id,
        device_id: &scope.device_id,
        machine_id: &scope.machine_id,
        producer_revision: &scope.producer_revision,
        collector_version: &producer.collector_version,
        scope_session_keys: members
            .iter()
            .map(|member| member.session_key_sha256.as_str())
            .collect(),
        members: members
            .iter()
            .zip(&packet_reasons)
            .zip(&report_shas)
            .map(|((member, reason), report_sha)| PacketMember {
                source_session_id: &member.source_session_id,
                session_key_sha256: &member.session_key_sha256,
                prior_refusal_body_witness: &member.prior_refusal_body_witness,
                disposition: "held",
                reason: reason.as_str(),
                qualification_report_sha256: report_sha.clone(),
                cross_session_conservation: Conservation::Unknown.as_str(),
            })
            .collect(),
    };
    let candidate_bundle_json =
        serde_json::to_string(&packet).map_err(|error| format!("packet encoding: {error}"))?;
    let report_bindings = members
        .iter()
        .zip(&report_shas)
        .map(|(member, sha)| {
            json!({
                "session_key_sha256": member.session_key_sha256,
                "qualification_report_sha256": sha,
            })
        })
        .collect::<Vec<_>>();
    let candidate_bundle_sha256 = sha256_hex(candidate_bundle_json.as_bytes());

    let computed_count = target_reports
        .iter()
        .filter(|report| report["candidate_status"] == "computed_unqualified")
        .count();
    let artifact = json!({
        "contract_version": PRODUCER_ARTIFACT_CONTRACT_VERSION,
        "local_only": true,
        "admission_authority": "none",
        "conservation_basis_note": "disclosed residual review input; never strict conservation certification",
        "residual_statement": DISCLOSED_RESIDUAL_STATEMENT,
        "operation_id": scope.operation_id,
        "user_id": scope.user_id,
        "organization_id": scope.organization_id,
        "device_id": scope.device_id,
        "machine_id": scope.machine_id,
        "producer_revision": scope.producer_revision,
        "producer_revision_source": super::PRODUCER_REVISION_SOURCE,
        "producer_binary_sha256": producer.binary_sha256,
        "collector_version": producer.collector_version,
        "input_bundle_sha256": input_sha256,
        "collected_at": input.collected_at,
        "upload_policy": {
            "session_titles_enabled": upload_policy.session_titles_enabled,
            "workspace_labels_enabled": upload_policy.workspace_labels_enabled,
            "session_artifacts_enabled": upload_policy.session_artifacts_enabled,
            "session_attribution_enabled": upload_policy.session_attribution_enabled,
            "session_attribution_labels_enabled": upload_policy.session_attribution_labels_enabled,
        },
        "context_curve_enabled": input.context_curve_enabled,
        "not_reproduced_stages": NOT_REPRODUCED_STAGES,
        "request_witness_scheme": REQUEST_WITNESS_SCHEME,
        "request_set_fingerprint_scheme": "claude_request_id_set:v1",
        "path_witness_scheme": PATH_WITNESS_SCHEME,
        "scope_session_keys": members.iter().map(|member| member.session_key_sha256.as_str()).collect::<Vec<_>>(),
        "input_manifest": {
            "bounds": {
                "max_peer_files": input.bounds.max_peer_files,
                "max_peer_total_bytes": input.bounds.max_peer_total_bytes,
                "max_peer_file_bytes": input.bounds.max_peer_file_bytes,
                "max_line_bytes": input.bounds.max_line_bytes,
            },
            "target_files": files.iter().map(|file| json!({
                "path_sha256": file.path_sha256,
                "size_bytes": file.size_bytes,
                "content_sha256": file.content_sha256,
                "unreadable": file.error,
            })).collect::<Vec<_>>(),
            "peer_roots": peers.roots,
            "peer_files": peers.files,
            "peer_file_count": peers.file_count,
            "cumulative_peer_bytes_read": peers.total_bytes,
            "ignored_non_transcript_file_count": peers.ignored_file_count,
            "duplicate_path_count": peers.duplicate_path_count,
            "covered_symlink_count": peers.covered_symlink_count,
            "target_file_occurrences_under_peer_roots": peers.target_file_occurrences,
            "peer_unidentified_usage_line_count": peers.unidentified_usage_line_count,
            "shared_target_replica_line_count": peers.shared_target_replica_line_count,
            "peer_unidentified_usage_note": "usage lines without a native request id cannot be compared; disclosed, not excluded",
        },
        "global_coverage": {
            "complete": coverage.complete(),
            "unknown": coverage.unknown,
            "cap_overflow": coverage.cap_overflow,
        },
        "b2_allocation": {
            "rule": B2_ALLOCATION_RULE,
            "identity_rule": super::B2_IDENTITY_RULE,
            "frozen_before_money": true,
            "order": allocation.order.iter().map(|index| json!({
                "session_key_sha256": members[*index].session_key_sha256,
                "first_ack_order": input.targets[*index].b2_first_ack_order,
            })).collect::<Vec<_>>(),
            "entries": allocation.entries,
            "sha256": allocation.sha256,
        },
        "qualification_gaps": [
            "source_cost_si_review_of_this_artifact_pending",
            "session_readonly_prepare_pending",
            "approved_conservation_pending",
            "producer_revision_unverified",
        ],
        "qualification_report_scheme": "sha256(rfc8785(target report with the body bytes removed and the body sha256 kept))",
        "qualification_reports": report_bindings,
        "targets": target_reports,
    });
    let artifact_json =
        serde_json::to_string(&artifact).map_err(|error| format!("artifact encoding: {error}"))?;
    let artifact_sha256 = sha256_hex(artifact_json.as_bytes());

    // Disclosures pin the artifact; only targets with an available estimate.
    let disclosures_json = match &input.catalog_prices {
        Some(prices) => {
            let mut records = Vec::new();
            for (index, estimate) in estimates.iter().enumerate() {
                let Some((excluded, dollars)) = estimate else {
                    continue;
                };
                let summary = LocalExclusionSummary {
                    exclusion_artifact_sha256: artifact_sha256.clone(),
                    excluded_request_count: excluded.request_count,
                    excluded_token_counts: excluded.excluded_token_counts(),
                    excluded_catalog_cost_usd: dollars.clone(),
                    copy_screen: CopyScreen::NotRun {
                        reason: COPY_SCREEN_NOT_RUN_REASON.to_string(),
                    },
                };
                let record = local_exclusion_disclosure_json(&scope, &members, &summary)?;
                records.push(json!({
                    "session_key_sha256": members[index].session_key_sha256,
                    "disclosure_sha256": sha256_hex(record.as_bytes()),
                    "disclosure_json": record,
                }));
            }
            let disclosures = json!({
                "contract_version": PRODUCER_DISCLOSURES_CONTRACT_VERSION,
                "exclusion_artifact_sha256": artifact_sha256,
                "estimate_label": ESTIMATE_LABEL,
                "catalog_publication": {
                    "source": prices.publication.source,
                    "revision": prices.publication.revision,
                    "sha256": prices.publication.sha256,
                },
                "records": records,
            });
            Some(
                serde_json::to_string(&disclosures)
                    .map_err(|error| format!("disclosures encoding: {error}"))?,
            )
        }
        None => None,
    };

    let mut reason_counts = BTreeMap::<&str, u64>::new();
    for reason in &packet_reasons {
        *reason_counts.entry(reason.as_str()).or_default() += 1;
    }
    let summary = json!({
        "contract_version": PRODUCER_SUMMARY_CONTRACT_VERSION,
        "artifact_sha256": artifact_sha256,
        "candidate_bundle_sha256": candidate_bundle_sha256,
        "disclosures_sha256": disclosures_json.as_deref().map(|json| sha256_hex(json.as_bytes())),
        "input_bundle_sha256": input_sha256,
        "global_coverage_complete": coverage.complete(),
        "computed_unqualified_candidates": computed_count,
        "held_packet_members": target_count,
        "held_reason_counts": reason_counts,
        "peer_file_count": peers.file_count,
        "cumulative_peer_bytes_read": peers.total_bytes,
        "b2_allocation_sha256": allocation.sha256,
        "admission_authority": "none",
    });
    Ok(ProducerOutput {
        artifact_json,
        artifact_sha256,
        candidate_bundle_json,
        candidate_bundle_sha256,
        disclosures_json,
        summary,
    })
}

fn validate_bounds(bounds: &InputBounds) -> Result<(), String> {
    if bounds.max_peer_files == 0
        || bounds.max_peer_total_bytes == 0
        || bounds.max_peer_file_bytes == 0
        || bounds.max_line_bytes == 0
    {
        return Err("every bound must be positive".to_string());
    }
    if bounds.max_peer_file_bytes > MAX_JSONL_FILE_BYTES
        || bounds.max_line_bytes > MAX_JSONL_LINE_BYTES as u64
    {
        return Err("bounds may not exceed the parser's own file and line caps".to_string());
    }
    Ok(())
}

fn validate_prices(prices: &CatalogPrices) -> Result<(), String> {
    if !super::is_lower_hex(&prices.publication.sha256, 64)
        || prices.publication.source.trim().is_empty()
        || prices.publication.revision.trim().is_empty()
    {
        return Err("catalog publication needs source, revision and a 64-hex sha256".to_string());
    }
    for (key, rates) in &prices.rates_usd_per_mtok {
        if key.split_once('|').is_none() {
            return Err("catalog rate keys are <model>|<context_bucket>".to_string());
        }
        for rate in [
            &rates.input,
            &rates.output,
            &rates.cache_read,
            &rates.cache_creation_5m,
            &rates.cache_creation_1h,
        ] {
            if parse_rate(rate).is_none() {
                return Err(format!(
                    "catalog rates must be exact decimals with at most {RATE_FRACTION_DIGITS} fraction digits"
                ));
            }
        }
    }
    Ok(())
}

fn read_bounded(path: &Path, cap: u64) -> Result<Vec<u8>, String> {
    let file = File::open(path).map_err(|error| error.to_string())?;
    let mut bytes = Vec::new();
    file.take(cap + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if bytes.len() as u64 > cap {
        return Err(format!("larger than {cap} bytes"));
    }
    Ok(bytes)
}

fn path_sha256(path: &Path) -> String {
    sha256_hex(path.to_string_lossy().as_bytes())
}

fn hash_file(path: &Path, cap: u64) -> Result<(u64, String), String> {
    let file = File::open(path).map_err(|error| error.to_string())?;
    let mut reader = file.take(cap + 1);
    let mut digest = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024];
    let mut total = 0_u64;
    loop {
        let read = reader
            .read(&mut buffer)
            .map_err(|error| error.to_string())?;
        if read == 0 {
            break;
        }
        total += read as u64;
        digest.update(&buffer[..read]);
    }
    if total > cap {
        return Err(format!("larger than {cap} bytes"));
    }
    Ok((total, format!("{:x}", digest.finalize())))
}

fn target_file(path: &Path) -> TargetFile {
    let unreadable = |error: String| TargetFile {
        canonical_path: None,
        path_sha256: path_sha256(path),
        size_bytes: None,
        content_sha256: None,
        error: Some(error),
    };
    let canonical_path = match fs::canonicalize(path) {
        Ok(path) if path.is_file() => path,
        Ok(_) => return unreadable("not a regular file".to_string()),
        Err(error) => return unreadable(error.to_string()),
    };
    match hash_file(&canonical_path, MAX_JSONL_FILE_BYTES) {
        Ok((size_bytes, content_sha256)) => TargetFile {
            path_sha256: path_sha256(&canonical_path),
            canonical_path: Some(canonical_path),
            size_bytes: Some(size_bytes),
            content_sha256: Some(content_sha256),
            error: None,
        },
        Err(error) => unreadable(error),
    }
}

/// Canonical parse of one unchanged target and its exact request set.
fn original_target(
    target: &InputTarget,
    collected_at: &str,
    upload_policy: SnapshotUploadPolicy,
    input: &ProducerInput,
) -> TargetParse {
    let unknown = |detail: String| TargetParse {
        request_ids: None,
        original: Err(TargetHold::new(HeldReason::MissingEvidence, detail)),
    };
    let parsed = match parse_target_transcript(
        &target.transcript_path,
        collected_at,
        upload_policy.session_artifacts_enabled,
        input.context_curve_enabled,
        None,
    ) {
        Ok(parsed) => parsed,
        Err(error) => return unknown(error),
    };
    if !parsed.complete {
        return unknown("transcript parse incomplete".to_string());
    }
    let item = match single_item(parsed.snapshots, &target.source_session_id) {
        Ok(item) => item,
        Err(hold) => {
            return TargetParse {
                request_ids: None,
                original: Err(hold),
            }
        }
    };
    let request_ids = item.claude_usage_request_ids.clone();
    let held = |detail: &str| TargetParse {
        request_ids: Some(request_ids.clone()),
        original: Err(TargetHold::new(HeldReason::MissingEvidence, detail)),
    };
    // Every counted request needs a native id for exact comparison.
    if item.claude_usage_occurrences.len() != request_ids.len()
        || item.request_count != request_ids.len() as u64
    {
        return held("counted usage without a native request id");
    }
    if request_ids.is_empty() {
        return held("no counted usage");
    }
    let totals = Dims::of_item(&item);
    let occurrence_sum = sum_dims(
        item.claude_usage_occurrences
            .values()
            .map(|occurrence| &occurrence.usage),
    );
    if occurrence_sum != Some(totals) {
        return held("unsupported grain: item totals differ from per-request usage");
    }
    if let Some(detail) = row_mismatch(&item, totals) {
        return held(detail);
    }
    if has_request_identity_evidence(&item) {
        return held("unsupported: body carries request identity evidence");
    }
    TargetParse {
        request_ids: Some(request_ids.clone()),
        original: Ok(OriginalTarget {
            item,
            request_ids,
            totals,
        }),
    }
}

fn single_item(snapshots: Vec<SnapshotItem>, session_id: &str) -> Result<SnapshotItem, TargetHold> {
    let total = snapshots.len();
    let mut matching = snapshots
        .into_iter()
        .filter(|item| item.source_session_id == session_id)
        .collect::<Vec<_>>();
    match (total, matching.len()) {
        (1, 1) => Ok(matching.remove(0)),
        (_, 0) => Err(TargetHold::new(
            HeldReason::MissingEvidence,
            "transcript has no item for the target session",
        )),
        _ => Err(TargetHold::new(
            HeldReason::UnknownOwner,
            "transcript yields more than one item",
        )),
    }
}

/// Present usage rows must add up to the item totals exactly.
fn row_mismatch(item: &SnapshotItem, totals: Dims) -> Option<&'static str> {
    if !item.model_usage.is_empty() {
        let sum = item
            .model_usage
            .iter()
            .try_fold(Dims::default(), |sum, row| {
                sum.checked_add(Dims::of_row(row))
            });
        if sum != Some(totals) {
            return Some("unsupported grain: model rows differ from item totals");
        }
    }
    if !item.usage_buckets.is_empty() {
        let sum = item
            .usage_buckets
            .iter()
            .flat_map(|bucket| &bucket.model_usage)
            .try_fold(Dims::default(), |sum, row| {
                sum.checked_add(Dims::of_row(row))
            });
        if sum != Some(totals) {
            return Some("unsupported grain: bucket rows differ from item totals");
        }
    }
    None
}

fn has_request_identity_evidence(item: &SnapshotItem) -> bool {
    !item.request_evidence.is_empty()
        || item.request_identity_refusals > 0
        || item
            .usage_buckets
            .iter()
            .flat_map(|bucket| &bucket.model_usage)
            .chain(&item.model_usage)
            .any(|row| row.evidence_ref.is_some() || row.identity_parts.is_some())
}

/// The parser's own session-id rule: the first line naming one fixes it for
/// the whole file.
fn line_session_id(value: &Value) -> Option<String> {
    string_at(value, &["sessionId"])
        .or_else(|| string_at(value, &["session_id"]))
        .or_else(|| string_at(value, &["conversation_id"]))
}

fn transcript_like_compressed(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.contains(".jsonl.")
        && COMPRESSED_EXTENSIONS
            .iter()
            .any(|extension| lower.ends_with(&format!(".{extension}")))
}

fn scan_peers(
    input: &ProducerInput,
    targets: &[TargetFile],
    originals: &[TargetParse],
    coverage: &mut GlobalCoverage,
) -> PeerScan {
    let target_count = targets.len();
    let mut scan = PeerScan {
        hits: vec![BTreeMap::new(); target_count],
        same_session_line_count: vec![0; target_count],
        shared_target_replica_line_count: 0,
        replica_divergent_ids: vec![BTreeSet::new(); target_count],
        ..PeerScan::default()
    };
    // Exact native id -> targets that count it.
    let holders = request_holders(originals);
    let session_index = input
        .targets
        .iter()
        .enumerate()
        .map(|(index, target)| (target.source_session_id.as_str(), index))
        .collect::<BTreeMap<_, _>>();
    let target_paths = targets
        .iter()
        .filter_map(|file| file.canonical_path.clone())
        .collect::<BTreeSet<_>>();
    let mut canonical_roots = Vec::new();
    for root in &input.peer_roots {
        match fs::canonicalize(&root.path) {
            Ok(path) if path.is_dir() => canonical_roots.push((root.class.as_str(), path)),
            _ => coverage
                .unknown
                .push(format!("peer root {} unreadable", path_sha256(&root.path))),
        }
    }
    let mut visited = BTreeSet::new();
    for (class, root) in &canonical_roots {
        let mut root_files = 0_u64;
        let mut root_bytes = 0_u64;
        let mut stack = vec![root.clone()];
        while let Some(directory) = stack.pop() {
            let mut entries = match fs::read_dir(&directory) {
                Ok(entries) => match entries.collect::<Result<Vec<_>, _>>() {
                    Ok(entries) => entries,
                    Err(_) => {
                        coverage.unknown.push(format!(
                            "peer directory {} unreadable",
                            path_sha256(&directory)
                        ));
                        continue;
                    }
                },
                Err(_) => {
                    coverage.unknown.push(format!(
                        "peer directory {} unreadable",
                        path_sha256(&directory)
                    ));
                    continue;
                }
            };
            entries.sort_by_key(|entry| entry.file_name());
            let mut subdirectories = Vec::new();
            for entry in entries {
                let path = entry.path();
                let Ok(metadata) = fs::symlink_metadata(&path) else {
                    coverage
                        .unknown
                        .push(format!("peer entry {} unreadable", path_sha256(&path)));
                    continue;
                };
                if metadata.file_type().is_symlink() {
                    let covered = fs::canonicalize(&path).is_ok_and(|resolved| {
                        canonical_roots
                            .iter()
                            .any(|(_, root)| resolved.starts_with(root))
                    });
                    if covered {
                        scan.covered_symlink_count += 1;
                    } else {
                        coverage
                            .unknown
                            .push(format!("uncovered symlink {}", path_sha256(&path)));
                    }
                    continue;
                }
                if metadata.is_dir() {
                    subdirectories.push(path);
                    continue;
                }
                if !metadata.is_file() {
                    continue;
                }
                let name = entry.file_name().to_string_lossy().to_string();
                if transcript_like_compressed(&name) {
                    coverage.unknown.push(format!(
                        "unsupported compressed transcript {}",
                        path_sha256(&path)
                    ));
                    continue;
                }
                if !name.ends_with(".jsonl") {
                    scan.ignored_file_count += 1;
                    continue;
                }
                if !visited.insert(path.clone()) {
                    scan.duplicate_path_count += 1;
                    continue;
                }
                if target_paths.contains(&path) {
                    scan.target_file_occurrences += 1;
                    continue;
                }
                if !coverage.cap_overflow.is_empty() {
                    continue;
                }
                if scan.file_count >= input.bounds.max_peer_files {
                    coverage
                        .cap_overflow
                        .push("max_peer_files reached".to_string());
                    continue;
                }
                if metadata.len() > input.bounds.max_peer_file_bytes {
                    coverage.cap_overflow.push(format!(
                        "peer file {} over max_peer_file_bytes",
                        path_sha256(&path)
                    ));
                    continue;
                }
                if scan.total_bytes.saturating_add(metadata.len())
                    > input.bounds.max_peer_total_bytes
                {
                    coverage
                        .cap_overflow
                        .push("max_peer_total_bytes reached".to_string());
                    continue;
                }
                let file_index = scan.files.len();
                let bytes_before = scan.total_bytes;
                let outcome = scan_peer_file(
                    &path,
                    file_index,
                    input.bounds,
                    &holders,
                    &session_index,
                    originals,
                    &mut scan,
                );
                scan.file_count += 1;
                root_files += 1;
                root_bytes += scan.total_bytes - bytes_before;
                match outcome {
                    Ok((bytes, content_sha256)) => {
                        scan.files.push(json!({
                            "class": class,
                            "path_sha256": path_sha256(&path),
                            "size_bytes": bytes,
                            "content_sha256": content_sha256,
                        }));
                    }
                    Err(detail) => {
                        scan.files.push(json!({
                            "class": class,
                            "path_sha256": path_sha256(&path),
                            "unknown": detail,
                        }));
                        coverage
                            .unknown
                            .push(format!("peer file {}: {detail}", path_sha256(&path)));
                    }
                }
            }
            // Reversed so the stack visits directory names in ascending order.
            stack.extend(subdirectories.into_iter().rev());
        }
        scan.roots.push(json!({
            "class": class,
            "path_sha256": path_sha256(root),
            "transcript_file_count": root_files,
            "bytes_read": root_bytes,
        }));
    }
    scan
}

/// Stream one peer transcript. Returns its byte count and content hash;
/// an error leaves coverage unknown.
fn scan_peer_file(
    path: &Path,
    file_index: usize,
    bounds: InputBounds,
    holders: &BTreeMap<&str, Vec<usize>>,
    session_index: &BTreeMap<&str, usize>,
    originals: &[TargetParse],
    scan: &mut PeerScan,
) -> Result<(u64, String), String> {
    let before = fs::metadata(path).map_err(|error| format!("stat: {error}"))?;
    let file = File::open(path).map_err(|error| format!("open: {error}"))?;
    let mut reader = BufReader::new(file);
    let mut digest = Sha256::new();
    let mut total = 0_u64;
    let mut line = Vec::new();
    // A subagent transcript is keyed by its path, like the parser does.
    let subagent_session =
        claude_subagent_identity(path).map(|identity| identity.source_session_id());
    let mut file_session = None::<String>;
    loop {
        line.clear();
        let read = (&mut reader)
            .take(bounds.max_line_bytes + 1)
            .read_until(b'\n', &mut line)
            .map_err(|error| format!("read: {error}"))?;
        if read == 0 {
            break;
        }
        total += read as u64;
        // Charged as read, so a failed or growing file still spends the budget.
        scan.total_bytes += read as u64;
        if total > bounds.max_peer_file_bytes || scan.total_bytes > bounds.max_peer_total_bytes {
            return Err("read past the peer byte bounds".to_string());
        }
        digest.update(&line);
        if read as u64 > bounds.max_line_bytes && line.last() != Some(&b'\n') {
            return Err("line over max_line_bytes".to_string());
        }
        let text = line.strip_suffix(b"\n").unwrap_or(&line);
        let has_id_key = contains(text, b"\"requestId\"") || contains(text, b"\"request_id\"");
        let may_name_session = file_session.is_none()
            && [
                &b"\"sessionId\""[..],
                b"\"session_id\"",
                b"\"conversation_id\"",
            ]
            .iter()
            .any(|key| contains(text, key));
        if !has_id_key && !may_name_session && !contains(text, b"usage") {
            continue;
        }
        let Ok(value) = serde_json::from_slice::<Value>(text) else {
            if has_id_key {
                return Err("unparseable line with a request id key".to_string());
            }
            continue;
        };
        if file_session.is_none() {
            file_session = line_session_id(&value);
        }
        let provenance = claude_fork_line_provenance(&value);
        let counted_usage = claude_code_delta_usage(&value).is_some();
        let Some(request_id) = line_request_id(&value) else {
            if counted_usage && provenance == ClaudeForkLineProvenance::None {
                scan.unidentified_usage_line_count += 1;
            }
            continue;
        };
        if !counted_usage {
            continue;
        }
        let owner = match provenance {
            ClaudeForkLineProvenance::Inherited => value
                .get("forkedFrom")
                .and_then(|forked| forked.get("sessionId").or_else(|| forked.get("session_id")))
                .and_then(Value::as_str)
                .map(|session| session.trim().to_string()),
            ClaudeForkLineProvenance::Invalid => {
                return Err("malformed fork marker on a request line".to_string());
            }
            ClaudeForkLineProvenance::None => {
                subagent_session.clone().or_else(|| file_session.clone())
            }
        };
        let owner_target = owner
            .as_deref()
            .and_then(|owner| session_index.get(owner))
            .copied();
        let mut owner_counts_it = false;
        if let Some(own_index) = owner_target {
            owner_counts_it = originals[own_index]
                .request_ids
                .as_ref()
                .is_some_and(|request_ids| request_ids.contains(&request_id));
            if !owner_counts_it {
                scan.replica_divergent_ids[own_index].insert(request_id.clone());
            }
        }
        let Some(target_indexes) = holders.get(request_id.as_str()) else {
            continue;
        };
        if owner_counts_it {
            // A replica of a target that counts this id: its own line for the
            // owner, a target-to-target share for the rest, which B2 allocates.
            for &target in target_indexes {
                if Some(target) == owner_target {
                    scan.same_session_line_count[target] += 1;
                } else {
                    scan.shared_target_replica_line_count += 1;
                }
            }
            continue;
        }
        for &target in target_indexes {
            scan.hits[target]
                .entry(request_id.clone())
                .or_insert_with(|| PeerHit {
                    peer_file_index: file_index,
                    owner_session_sha256: owner
                        .as_deref()
                        .map(|owner| sha256_hex(owner.as_bytes())),
                    line_count: 0,
                })
                .line_count += 1;
        }
    }
    let after = fs::metadata(path).map_err(|error| format!("stat: {error}"))?;
    if before.len() != total
        || after.len() != total
        || before.modified().ok() != after.modified().ok()
    {
        return Err("file changed while read".to_string());
    }
    Ok((total, format!("{:x}", digest.finalize())))
}

/// Exact native id -> every target whose request set counts it.
fn request_holders(originals: &[TargetParse]) -> BTreeMap<&str, Vec<usize>> {
    let mut holders = BTreeMap::<&str, Vec<usize>>::new();
    for (index, parse) in originals.iter().enumerate() {
        for request_id in parse.request_ids.iter().flatten() {
            holders.entry(request_id.as_str()).or_default().push(index);
        }
    }
    holders
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

fn allocate(
    input: &ProducerInput,
    originals: &[TargetParse],
    peers: &PeerScan,
) -> Result<Allocation, String> {
    let target_count = originals.len();
    let mut order = (0..target_count).collect::<Vec<_>>();
    order.sort_by(|left, right| {
        let key = |index: &usize| {
            let target = &input.targets[*index];
            (
                target.b2_first_ack_order.is_none(),
                target.b2_first_ack_order,
                target.session_key_sha256.clone(),
            )
        };
        key(left).cmp(&key(right))
    });
    let mut rank = vec![0_usize; target_count];
    for (position, index) in order.iter().enumerate() {
        rank[*index] = position;
    }
    let holders = request_holders(originals);
    let mut excluded = vec![BTreeMap::new(); target_count];
    let mut kept_shared = vec![BTreeMap::new(); target_count];
    let mut entries = Vec::new();
    for (request_id, holding) in &holders {
        let peer_witness = holding
            .iter()
            .copied()
            .find(|target| peers.hits[*target].contains_key(*request_id));
        if peer_witness.is_none() && holding.len() < 2 {
            continue;
        }
        let keeper = if let Some(witness) = peer_witness {
            Keeper::Peer(witness)
        } else {
            Keeper::Target(
                *holding
                    .iter()
                    .min_by_key(|target| rank[**target])
                    .expect("shared request has holders"),
            )
        };
        for &target in holding {
            if keeper == Keeper::Target(target) {
                kept_shared[target].insert(
                    (*request_id).to_string(),
                    holding
                        .iter()
                        .copied()
                        .filter(|other| *other != target)
                        .collect(),
                );
            } else {
                excluded[target].insert((*request_id).to_string(), keeper.clone());
            }
        }
        let mut holder_keys = holding
            .iter()
            .map(|target| input.targets[*target].session_key_sha256.clone())
            .collect::<Vec<_>>();
        holder_keys.sort();
        entries.push((
            sha256_hex(request_id.as_bytes()),
            json!({
                "request_sha256": sha256_hex(request_id.as_bytes()),
                "holder_session_key_sha256s": holder_keys,
                "kept_by": match keeper {
                    Keeper::Peer(_) => "peer".to_string(),
                    Keeper::Target(target) => input.targets[target].session_key_sha256.clone(),
                },
            }),
        ));
    }
    entries.sort_by(|left, right| left.0.cmp(&right.0));
    let entries = entries
        .into_iter()
        .map(|(_, entry)| entry)
        .collect::<Vec<_>>();
    let digest_body = json!({
        "rule": B2_ALLOCATION_RULE,
        "order": order.iter().map(|index| input.targets[*index].session_key_sha256.as_str()).collect::<Vec<_>>(),
        "entries": entries,
    });
    let sha256 = crate::canonical_json::canonicalize(&digest_body)
        .map(|bytes| sha256_hex(&bytes))
        .map_err(|error| format!("allocation digest: {error}"))?;
    Ok(Allocation {
        excluded,
        kept_shared,
        entries,
        order,
        sha256,
    })
}

struct BuiltTarget {
    reason: HeldReason,
    report: Value,
    /// Excluded dimensions and exact catalog dollars, when available.
    estimate: Option<(Dims, String)>,
}

#[allow(clippy::too_many_arguments)]
fn build_target(
    index: usize,
    input: &ProducerInput,
    scope: &OperatorScope,
    members: &[ApprovedMember],
    upload_policy: SnapshotUploadPolicy,
    producer: &ProducerBuild,
    file: &TargetFile,
    original: &Result<OriginalTarget, TargetHold>,
    peers: &PeerScan,
    allocation: &Allocation,
    coverage: &GlobalCoverage,
) -> BuiltTarget {
    let target = &input.targets[index];
    let member = &members[index];
    let mut report = json!({
        "source_session_id": member.source_session_id,
        "session_key_sha256": member.session_key_sha256,
        "prior_refusal_body_witness": member.prior_refusal_body_witness,
        "transcript_path_sha256": file.path_sha256,
        "transcript_content_sha256": file.content_sha256,
        "b2_first_ack_order": target.b2_first_ack_order,
        "cross_session_conservation": Conservation::Unknown.as_str(),
        "same_session_peer_line_count": peers.same_session_line_count[index],
    });
    let hold = |mut report: Value, hold: TargetHold| {
        report["candidate_status"] = json!("held");
        report["held_reason"] = json!(hold.reason.as_str());
        report["held_detail"] = json!(hold.detail);
        BuiltTarget {
            reason: hold.reason,
            report,
            estimate: None,
        }
    };
    let original = match original {
        Ok(original) => original,
        Err(error) => return hold(report, error.clone()),
    };
    report["original"] = json!({
        "request_count": original.request_ids.len(),
        "request_set_fingerprint": request_set_fingerprint(&original.request_ids),
        "totals": original.totals.json(),
    });
    if let Some(reason) = coverage.held_reason() {
        return hold(
            report,
            TargetHold::new(
                reason,
                "global peer coverage incomplete; no partition or body",
            ),
        );
    }
    if !peers.replica_divergent_ids[index].is_empty() {
        return hold(
            report,
            TargetHold::new(
                HeldReason::UnknownOwner,
                format!(
                    "another local copy of this session counts {} request(s) this transcript does not",
                    peers.replica_divergent_ids[index].len()
                ),
            ),
        );
    }

    // Exact partition fixed by the frozen allocation.
    let excluded_map = &allocation.excluded[index];
    let excluded_ids = excluded_map.keys().cloned().collect::<BTreeSet<_>>();
    let kept_ids = original
        .request_ids
        .difference(&excluded_ids)
        .cloned()
        .collect::<BTreeSet<_>>();
    let usage_of = |ids: &BTreeSet<String>| {
        ids.iter()
            .map(|id| {
                original
                    .item
                    .claude_usage_occurrences
                    .get(id)
                    .map(|occurrence| &occurrence.usage)
            })
            .collect::<Option<Vec<_>>>()
            .and_then(sum_dims)
    };
    let (Some(excluded_dims), Some(kept_dims)) = (usage_of(&excluded_ids), usage_of(&kept_ids))
    else {
        return hold(
            report,
            TargetHold::new(
                HeldReason::MissingEvidence,
                "per-request usage does not reconcile",
            ),
        );
    };
    let mut excluded_witnesses = Vec::with_capacity(excluded_map.len());
    for (request_id, keeper) in excluded_map {
        let mut witness = json!({
            "request_sha256": sha256_hex(request_id.as_bytes()),
        });
        match keeper {
            Keeper::Peer(witness_target) => {
                let Some((hit, peer_path_sha256)) =
                    peers.hits[*witness_target].get(request_id).and_then(|hit| {
                        let path = peers.files.get(hit.peer_file_index)?.get("path_sha256")?;
                        Some((hit, path.clone()))
                    })
                else {
                    return hold(
                        report,
                        TargetHold::new(
                            HeldReason::MissingEvidence,
                            "peer exclusion has no recorded witness",
                        ),
                    );
                };
                witness["cause"] = json!("peer_overlap");
                witness["peer_path_sha256"] = peer_path_sha256;
                witness["peer_owner_session_sha256"] = json!(hit.owner_session_sha256);
                witness["peer_line_count"] = json!(hit.line_count);
            }
            Keeper::Target(keeper) => {
                witness["cause"] = json!("b2_other_target");
                witness["kept_by_session_key_sha256"] = json!(members[*keeper].session_key_sha256);
            }
        }
        excluded_witnesses.push(witness);
    }
    excluded_witnesses.sort_by(|left, right| {
        left["request_sha256"]
            .as_str()
            .cmp(&right["request_sha256"].as_str())
    });
    report["partition"] = json!({
        "excluded": {
            "request_count": excluded_ids.len(),
            "request_set_fingerprint": request_set_fingerprint(&excluded_ids),
            "peer_overlap_count": excluded_map.values().filter(|keeper| matches!(keeper, Keeper::Peer(_))).count(),
            "b2_other_target_count": excluded_map.values().filter(|keeper| matches!(keeper, Keeper::Target(_))).count(),
            "totals": excluded_dims.json(),
            "witnesses": excluded_witnesses,
        },
        "kept": {
            "request_count": kept_ids.len(),
            "request_set_fingerprint": request_set_fingerprint(&kept_ids),
            "totals": kept_dims.json(),
        },
    });
    if kept_ids.is_empty() {
        return hold(
            report,
            TargetHold::new(HeldReason::MissingEvidence, "every request is excluded"),
        );
    }

    // Rebuild through the same parser, then reconcile exactly.
    let mut item = if excluded_ids.is_empty() {
        original.item.clone()
    } else {
        let parsed = match parse_target_transcript(
            &target.transcript_path,
            &input.collected_at,
            upload_policy.session_artifacts_enabled,
            input.context_curve_enabled,
            Some(excluded_ids.clone()),
        ) {
            Ok(parsed) if parsed.complete => parsed,
            Ok(_) => {
                return hold(
                    report,
                    TargetHold::new(HeldReason::MissingEvidence, "rebuild parse incomplete"),
                )
            }
            Err(error) => {
                return hold(
                    report,
                    TargetHold::new(HeldReason::MissingEvidence, format!("rebuild: {error}")),
                )
            }
        };
        match single_item(parsed.snapshots, &target.source_session_id) {
            Ok(item) => item,
            Err(error) => return hold(report, error),
        }
    };
    if let Some(detail) = reconcile(original, &item, &kept_ids, excluded_dims, kept_dims) {
        return hold(report, TargetHold::new(HeldReason::MissingEvidence, detail));
    }
    let identity_changes = allocation_identity_changes(&original.item, &item);
    if identity_changes > 0 {
        return hold(
            report,
            TargetHold::new(
                HeldReason::UnknownOwner,
                "exclusion changed identity-bearing body fields",
            ),
        );
    }

    // Ordinary upload policy and serializer; cache upload stays disabled.
    apply_upload_policy(
        SnapshotSource::ClaudeCode,
        std::slice::from_mut(&mut item),
        upload_policy,
    );
    item.cache_observations = None;
    item.cache_observations_state = None;
    item.cache_base_head_etag = None;
    let body = match ordinary_batch_body(scope, &item, upload_policy, producer) {
        Ok(body) => body,
        Err(error) => return hold(report, TargetHold::new(HeldReason::MissingEvidence, error)),
    };
    let unchanged = file
        .canonical_path
        .as_ref()
        .and_then(|path| hash_file(path, MAX_JSONL_FILE_BYTES).ok())
        .is_some_and(|(size, sha)| {
            Some(size) == file.size_bytes && Some(&sha) == file.content_sha256.as_ref()
        });
    if !unchanged {
        return hold(
            report,
            TargetHold::new(
                HeldReason::MissingEvidence,
                "target transcript changed during the run",
            ),
        );
    }

    // SI: every kept shared request, its keeping root and tag state.
    let receipt_entries = allocation.kept_shared[index]
        .iter()
        .map(|(request_id, others)| {
            let mut other_keys = others
                .iter()
                .map(|other| members[*other].session_key_sha256.clone())
                .collect::<Vec<_>>();
            other_keys.sort();
            (
                sha256_hex(request_id.as_bytes()),
                json!({
                    "request_sha256": sha256_hex(request_id.as_bytes()),
                    "keeping_root_session_key_sha256": member.session_key_sha256,
                    "other_holder_session_key_sha256s": other_keys,
                    "tag_state": "untagged",
                    "evidence_root_session_key_sha256": Value::Null,
                    "evidence_basis": Value::Null,
                }),
            )
        })
        .collect::<BTreeMap<_, _>>()
        .into_values()
        .collect::<Vec<_>>();
    let receipt_group_sha256 = match crate::canonical_json::canonicalize(&json!(receipt_entries)) {
        Ok(bytes) => sha256_hex(&bytes),
        Err(error) => {
            return hold(
                report,
                TargetHold::new(
                    HeldReason::MissingEvidence,
                    format!("receipt digest: {error}"),
                ),
            )
        }
    };
    report["identity_receipt"] = json!({
        "identity_rule": super::B2_IDENTITY_RULE,
        "kept_shared_request_count": receipt_entries.len(),
        "tagged_count": 0,
        "untagged_count": receipt_entries.len(),
        "group_sha256": receipt_group_sha256,
        "entries": receipt_entries,
        "body_request_evidence_count": item.request_evidence.len(),
        "body_rows_with_identity": 0,
        "body_session_account_evidence_present": item.session_account_evidence.is_some(),
        "allocation_identity_changes": identity_changes,
        "note": "no Contract-5 permit in this producer: every kept request is untagged under its starting subscription; an identity-less body cannot authorize replacing an existing name",
    });
    let estimate = estimate_dollars(input.catalog_prices.as_ref(), original, &excluded_ids);
    report["exclusion_estimate"] = match &estimate {
        Ok(dollars) => json!({
            "label": ESTIMATE_LABEL,
            "excluded_catalog_cost_usd": dollars,
        }),
        Err(reason) => json!({
            "label": ESTIMATE_LABEL,
            "excluded_catalog_cost_usd": Value::Null,
            "unavailable_reason": reason,
        }),
    };
    report["body"] = json!({
        "unqualified_batch_request_sha256": sha256_hex(body.as_bytes()),
        "unqualified_batch_request_json": body,
        "item_snapshot_fingerprint": item.snapshot_fingerprint,
        "item_totals": Dims::of_item(&item).json(),
    });
    report["candidate_status"] = json!("computed_unqualified");
    report["held_reason"] = json!(HeldReason::MissingEvidence.as_str());
    report["held_detail"] = json!("awaiting SESSION read-only prepare and SOURCE/COST/SI review");
    BuiltTarget {
        reason: HeldReason::MissingEvidence,
        report,
        estimate: estimate.ok().map(|dollars| (excluded_dims, dollars)),
    }
}

fn request_set_fingerprint(request_ids: &BTreeSet<String>) -> String {
    let hashes = request_ids
        .iter()
        .map(|request_id| sha256_hex(request_id.as_bytes()))
        .collect::<BTreeSet<_>>();
    claude_request_id_set_fingerprint(&hashes)
}

/// Exact reconciliation of the rebuilt item against the original partition.
fn reconcile(
    original: &OriginalTarget,
    rebuilt: &SnapshotItem,
    kept_ids: &BTreeSet<String>,
    excluded_dims: Dims,
    kept_dims: Dims,
) -> Option<&'static str> {
    if &rebuilt.claude_usage_request_ids != kept_ids
        || rebuilt.claude_usage_occurrences.len() != kept_ids.len()
    {
        return Some("rebuilt request set differs from the kept partition");
    }
    for request_id in kept_ids {
        let (Some(before), Some(after)) = (
            original.item.claude_usage_occurrences.get(request_id),
            rebuilt.claude_usage_occurrences.get(request_id),
        ) else {
            return Some("rebuilt request set differs from the kept partition");
        };
        if before.usage != after.usage
            || before.model != after.model
            || before.reasoning_effort != after.reasoning_effort
            || before.timestamp != after.timestamp
            || before.selector != after.selector
            || before.effective_input_context != after.effective_input_context
        {
            return Some("a kept request changed when excluded requests were removed");
        }
    }
    let rebuilt_totals = Dims::of_item(rebuilt);
    if rebuilt_totals != kept_dims
        || original.totals.checked_sub(excluded_dims) != Some(rebuilt_totals)
    {
        return Some("rebuilt totals do not reconcile with kept and excluded requests");
    }
    if let Some(detail) = row_mismatch(rebuilt, rebuilt_totals) {
        return Some(detail);
    }
    if has_request_identity_evidence(rebuilt) {
        return Some("unsupported: rebuilt body carries request identity evidence");
    }
    None
}

/// Identity-bearing fields the counting allocation must leave unchanged.
fn allocation_identity_changes(original: &SnapshotItem, rebuilt: &SnapshotItem) -> u64 {
    let accounts = |item: &SnapshotItem| {
        item.model_usage
            .iter()
            .chain(
                item.usage_buckets
                    .iter()
                    .flat_map(|bucket| &bucket.model_usage),
            )
            .filter_map(|row| row.account_identifier_hash.clone())
            .collect::<BTreeSet<_>>()
    };
    u64::from(original.session_account_evidence != rebuilt.session_account_evidence)
        + u64::from(accounts(original) != accounts(rebuilt))
}

/// Exact decimal catalog estimate over the excluded requests.
fn estimate_dollars(
    prices: Option<&CatalogPrices>,
    original: &OriginalTarget,
    excluded_ids: &BTreeSet<String>,
) -> Result<String, &'static str> {
    let prices = prices.ok_or("catalog_prices_not_supplied")?;
    let mut total = 0_u128;
    for request_id in excluded_ids {
        let occurrence = original
            .item
            .claude_usage_occurrences
            .get(request_id)
            .ok_or("missing_request_occurrence")?;
        let usage = &occurrence.usage;
        if usage.reasoning_output_tokens > 0 || usage.unattributed_total_tokens > 0 {
            return Err("unpriced_dimension");
        }
        let model = occurrence.model.as_deref().ok_or("unpriced_model")?;
        let bucket = occurrence
            .selector
            .context
            .get("context_bucket")
            .ok_or("unpriced_model")?;
        let rates = prices
            .rates_usd_per_mtok
            .get(&format!("{model}|{bucket}"))
            .ok_or("unpriced_model")?;
        for (tokens, rate) in [
            (usage.input_tokens, &rates.input),
            (usage.output_tokens, &rates.output),
            (usage.cache_read_tokens, &rates.cache_read),
            (usage.cache_creation_5m_tokens, &rates.cache_creation_5m),
            (usage.cache_creation_1h_tokens, &rates.cache_creation_1h),
        ] {
            let rate = parse_rate(rate).ok_or("unpriced_model")?;
            total = u128::from(tokens)
                .checked_mul(rate)
                .and_then(|cost| total.checked_add(cost))
                .ok_or("estimate_overflow")?;
        }
    }
    Ok(format_scaled(total, COST_FRACTION_DIGITS))
}

/// Exact nonnegative decimal -> integer scaled by 10^12.
fn parse_rate(value: &str) -> Option<u128> {
    if !super::is_exact_decimal(value) {
        return None;
    }
    let (whole, fraction) = value.split_once('.').unwrap_or((value, ""));
    if fraction.len() > RATE_FRACTION_DIGITS {
        return None;
    }
    let whole = whole.parse::<u128>().ok()?;
    let fraction = format!("{fraction:0<width$}", width = RATE_FRACTION_DIGITS)
        .parse::<u128>()
        .ok()?;
    whole
        .checked_mul(10_u128.pow(RATE_FRACTION_DIGITS as u32))?
        .checked_add(fraction)
}

/// Plain decimal for an integer scaled by 10^digits, trailing zeros trimmed.
fn format_scaled(value: u128, digits: usize) -> String {
    let scale = 10_u128.pow(digits as u32);
    let whole = value / scale;
    let fraction = format!("{:0>digits$}", value % scale);
    let fraction = fraction.trim_end_matches('0');
    if fraction.is_empty() {
        whole.to_string()
    } else {
        format!("{whole}.{fraction}")
    }
}

#[cfg(test)]
mod tests;
