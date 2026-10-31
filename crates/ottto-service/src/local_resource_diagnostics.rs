//! Content-free observations in the existing local service log, never wire data.
//! CPU includes concurrent process work; maximum RSS is a lifetime high-water mark.
use serde::{ser::SerializeMap, Serialize};
use std::collections::BTreeMap;
use std::io::Write;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

pub(crate) mod cache_lifecycle;
pub(crate) mod claude_absence;
pub(crate) mod claude_contract;
pub(crate) mod claude_reread;
pub(crate) mod codex_memo_lifecycle;
pub(crate) mod codex_side_lifecycle;
mod footprint;
pub(crate) mod rearm_cause;

#[cfg(not(test))]
static CLAUDE_IDENTITY_OVER_CAP: [AtomicU64; 6] = [const { AtomicU64::new(0) }; 6];
#[cfg(test)]
thread_local! {
    static CLAUDE_IDENTITY_OVER_CAP: [AtomicU64; 6] = const { [const { AtomicU64::new(0) }; 6] };
}

/// Append-only reason labels, cumulative per process (not distinct sessions).
/// Records each attempted over-cap body before its identities are stripped.
pub(crate) fn claude_identity_over_cap(
    reasons: &std::collections::BTreeSet<crate::snapshots::claude_request_identity::OverCap>,
    item_bytes: usize,
) {
    use crate::snapshots::claude_request_identity::OverCap;
    const LABELS: [&str; 6] = [
        "evidence_entries",
        "authority_keys",
        "parts_per_row",
        "parts_per_item",
        "rows",
        "bytes",
    ];
    let record = |counters: &[AtomicU64; 6]| {
        for reason in reasons {
            let index = match reason {
                OverCap::EvidenceEntries => 0,
                OverCap::AuthorityKeys => 1,
                OverCap::PartsPerRow => 2,
                OverCap::PartsPerItem => 3,
                OverCap::Rows => 4,
                OverCap::Bytes => 5,
            };
            let _ = counters[index].fetch_update(Relaxed, Relaxed, |n| Some(n.saturating_add(1)));
        }
        #[derive(Serialize)]
        struct Counts {
            claude_request_identity_over_cap: BTreeMap<&'static str, u64>,
            claude_request_identity_last_over_cap_item_bytes: usize,
        }
        traversal_point(
            "claude_request_identity_over_cap",
            "claude_code",
            &Counts {
                claude_request_identity_over_cap: LABELS
                    .into_iter()
                    .zip(counters.iter().map(|n| n.load(Relaxed)))
                    .collect(),
                claude_request_identity_last_over_cap_item_bytes: item_bytes,
            },
        );
    };
    #[cfg(test)]
    CLAUDE_IDENTITY_OVER_CAP.with(record);
    #[cfg(not(test))]
    record(&CLAUDE_IDENTITY_OVER_CAP);
}

/// Closed, content-free refusal labels; cumulative process counters on #799.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub(crate) enum CodexZstCause {
    #[serde(rename = "CompressedReplayNotAuthorized")]
    ReplayNotAuthorized,
    #[serde(rename = "CompressedProofParentUnsupported")]
    ProofParentUnsupported,
    #[serde(rename = "CompressedProofChildUnsupported")]
    ProofChildUnsupported,
    #[serde(rename = "CompressedParentSideUnsupported")]
    ParentSideUnsupported,
    #[serde(rename = "CompressedDurableTailUnsupported")]
    DurableTailUnsupported,
    #[serde(rename = "CompressedGroupProbeUnsupported")]
    GroupProbeUnsupported,
    #[serde(rename = "CompressedGroupReadUnsupported")]
    GroupReadUnsupported,
    #[serde(rename = "CompressedParentLedgerUnbound")]
    ParentLedgerUnbound,
    #[serde(rename = "CompressedPhysicalOffsetUnsupported")]
    PhysicalOffsetUnsupported,
    #[serde(rename = "CompressedHeaderUnfunded")]
    HeaderUnfunded,
    #[serde(rename = "CompressedCompatibilityUnfunded")]
    CompatibilityUnfunded,
    #[serde(rename = "CompressedAdmissionRefused")]
    AdmissionRefused,
    // Subset of decoder refusals: the unchanged free-only floor would fit
    // without optional header entries. Attempts, not files or lost usage.
    #[serde(rename = "decoder_refused_header_occupancy")]
    DecoderRefusedHeaderOccupancy,
}
const CODEX_ZST_CAUSES: usize = CodexZstCause::DecoderRefusedHeaderOccupancy as usize + 1;
static CODEX_ZST_REFUSED: [AtomicU64; CODEX_ZST_CAUSES] =
    [const { AtomicU64::new(0) }; CODEX_ZST_CAUSES];

pub(crate) fn codex_zst_refused(cause: CodexZstCause) {
    let counter = &CODEX_ZST_REFUSED[cause as usize];
    let previous = counter
        .fetch_update(Relaxed, Relaxed, |n| Some(n.saturating_add(1)))
        .unwrap_or_else(|n| n);
    traversal_point(
        "codex_zst_refused",
        "codex",
        &BTreeMap::from([(
            "codex_zst_refused",
            BTreeMap::from([(cause, previous.saturating_add(1))]),
        )]),
    );
}

/// Counts per observed usage line, before response deduplication and timestamp
/// drops; rereads count again. Only the lifecycle registry atomics are updated.
pub(crate) fn pi_cost_observations(refused: u64, rounded: u64) {
    if refused == 0 && rounded == 0 {
        return;
    }
    cache_lifecycle::add(cache_lifecycle::Event::PiCostRefusedOverflow, refused);
    cache_lifecycle::add(cache_lifecycle::Event::PiCostPrecisionRounded, rounded);
}

/// Per-pass observations, not distinct entries/files or a lifetime counter.
pub(crate) fn codex_state_only_ambiguous_identity(observations: u64, tokens: u64) {
    if observations > 0 {
        traversal_point(
            "codex_state_only_ambiguous_identity",
            "codex",
            &BTreeMap::from([
                ("codex_state_only_ambiguous_identity", observations),
                ("codex_state_only_ambiguous_identity_tokens", tokens),
            ]),
        );
    }
}

/// One terminal append call, before later policy/no-op suppression; never wire data.
pub(crate) fn codex_state_only(scanned: usize, emitted: usize, noops: usize) {
    if scanned != 0 || emitted != 0 || noops != 0 {
        traversal_point(
            "codex_state_only",
            "codex",
            &BTreeMap::from([(
                "codex_state_only",
                BTreeMap::from([("scanned", scanned), ("emitted", emitted), ("noops", noops)]),
            )]),
        );
    }
}

/// Nonzero-only counters on the existing native_collection_page line.
#[derive(Default, Serialize)]
struct ClaudeRecordCaps {
    #[serde(skip_serializing_if = "is_zero")]
    claude_money_record_cap_half_files: u64,
    #[serde(skip_serializing_if = "is_zero")]
    claude_money_record_cap_hits: u64,
}
fn is_zero(value: &u64) -> bool {
    *value == 0
}
#[cfg(not(test))]
static CLAUDE_CAP_HALF: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
#[cfg(not(test))]
static CLAUDE_CAP_HITS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
#[cfg(test)]
thread_local! {
    static CLAUDE_CAP_HALF: std::sync::atomic::AtomicU64 = const { std::sync::atomic::AtomicU64::new(0) };
    static CLAUDE_CAP_HITS: std::sync::atomic::AtomicU64 = const { std::sync::atomic::AtomicU64::new(0) };
}
fn with_claude_record_caps<T>(
    f: impl FnOnce(&std::sync::atomic::AtomicU64, &std::sync::atomic::AtomicU64) -> T,
) -> T {
    #[cfg(test)]
    {
        CLAUDE_CAP_HALF.with(|half| CLAUDE_CAP_HITS.with(|hits| f(half, hits)))
    }
    #[cfg(not(test))]
    {
        f(&CLAUDE_CAP_HALF, &CLAUDE_CAP_HITS)
    }
}
pub(crate) fn claude_record_cap_half_file() {
    with_claude_record_caps(|half, _| {
        half.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    });
}
pub(crate) fn claude_record_cap_hit() {
    with_claude_record_caps(|_, hits| {
        hits.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    });
}
fn take_claude_record_caps() -> ClaudeRecordCaps {
    with_claude_record_caps(|half, hits| ClaudeRecordCaps {
        claude_money_record_cap_half_files: half.swap(0, std::sync::atomic::Ordering::Relaxed),
        claude_money_record_cap_hits: hits.swap(0, std::sync::atomic::Ordering::Relaxed),
    })
}

#[cfg(test)]
pub(crate) fn take_claude_record_caps_for_test() -> (u64, u64) {
    let c = take_claude_record_caps();
    (
        c.claude_money_record_cap_half_files,
        c.claude_money_record_cap_hits,
    )
}

/// K10 (LD): one line observer's counts for a page; nonzero keys only.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub(crate) struct LineDeliveryCounts {
    #[serde(skip_serializing_if = "is_zero")]
    pub(crate) lines: u64,
    #[serde(skip_serializing_if = "is_zero")]
    pub(crate) bytes: u64,
    #[serde(skip_serializing_if = "is_zero")]
    pub(crate) incomplete: u64,
}

/// K10 (LD): why a discovery gate left a file unselected.
pub(crate) enum UnselectedReason {
    Age,
    Size,
    /// The subset of size skips whose key holds a withheld-account revision.
    WithheldOversized,
    /// F4 kept custody because another same-member path prevents absence proof.
    WithheldAbsenceAmbiguous = 18,
}
/// Three reasons, seven withheld events, growth, deleted tokens and audit retirement.
const UNSELECTED_REASONS: usize = 19;
/// Claude, Codex, Pi x reason, drained by that source's page line.
#[cfg(not(test))]
static LINE_UNSELECTED: [AtomicU64; 3 * UNSELECTED_REASONS] =
    [const { AtomicU64::new(0) }; 3 * UNSELECTED_REASONS];
#[cfg(test)]
thread_local! {
    static LINE_UNSELECTED: [AtomicU64; 3 * UNSELECTED_REASONS] =
        const { [const { AtomicU64::new(0) }; 3 * UNSELECTED_REASONS] };
}
fn source_count(source: &str, reason: usize, f: impl FnOnce(&AtomicU64) -> u64) -> u64 {
    let sources = ["claude_code", "codex", "pi"];
    let Some(slot) = sources.iter().position(|s| *s == source) else {
        return 0;
    };
    #[cfg(test)]
    {
        LINE_UNSELECTED.with(|slots| f(&slots[UNSELECTED_REASONS * slot + reason]))
    }
    #[cfg(not(test))]
    {
        f(&LINE_UNSELECTED[UNSELECTED_REASONS * slot + reason])
    }
}
/// One skip decision, recorded after the gate decided; never a gate input.
pub(crate) fn line_delivery_unselected(source: &str, reason: UnselectedReason) {
    source_count(source, reason as usize, |slot| slot.fetch_add(1, Relaxed));
}
/// One failed parking decision; no logging, resource probes or scan ownership.
pub(crate) fn source_rotation_serial_fallback(source: &str, layout_supported: bool) {
    source_count(source, 16 + usize::from(layout_supported), |slot| {
        slot.fetch_update(Relaxed, Relaxed, |n| Some(n.saturating_add(1)))
            .unwrap_or_else(|n| n)
    });
}

/// E3: Claude withheld-account hold events, in the slots after the reasons.
#[derive(Clone, Copy)]
pub(crate) enum WithheldEvent {
    /// A held key's file was proved absent and its hold released.
    ReleasedDeleted = 3,
    /// A held key re-parsed: first time in this process, after an account
    /// evidence change, or after its transcript stamp changed.
    ReparseStart,
    ReparseEvidence,
    ReparseGrowth,
    /// A parse resolved the account and released the hold.
    ReleasedResolved,
    /// A withheld key past the hold cap left unrecorded, and its withheld tokens.
    UnrecordedEvents,
    UnrecordedTokens,
    ReleasedDeletedTokens = 11,
    BirthClampAccepted = 15,
}
/// Recorded after the decision; never a gate input.
pub(crate) fn withheld_event(event: WithheldEvent, amount: u64) {
    source_count("claude_code", event as usize, |slot| {
        slot.fetch_add(amount, Relaxed)
    });
}
fn drain(source: &str, slots: &[(&'static str, usize)]) -> BTreeMap<&'static str, u64> {
    slots
        .iter()
        .map(|&(key, slot)| (key, source_count(source, slot, |n| n.swap(0, Relaxed))))
        .filter(|(_, count)| *count > 0)
        .collect()
}
pub(crate) fn audit_retired_absent(source: &str) {
    source_count(source, 12, |slot| slot.fetch_add(1, Relaxed));
}
/// One aged gate retained a grown indexed file (not a unique-file count).
pub(crate) fn discovery_retained_grown(source: &str) {
    source_count(source, 10, |slot| slot.fetch_add(1, Relaxed));
}
/// Actual aged, unchanged fragment-only Tail completions; bytes exclude samples.
pub(crate) fn codex_fragment_tail_repeat(bytes: u64) {
    source_count("codex", 13, |slot| slot.fetch_add(1, Relaxed));
    source_count("codex", 14, |slot| slot.fetch_add(bytes, Relaxed));
}
/// Post-save fate and current estimated age of this page's observed growth.
pub(crate) fn discovery_growth_fate(
    source: &str,
    counts: &crate::snapshots::discovery_growth::Counts,
) {
    traversal_point("discovery_growth_fate", source, counts);
}
const WITHHELD_RELEASED: [(&str, usize); 3] =
    [("deleted", 3), ("resolved", 7), ("deleted_tokens", 11)];
const WITHHELD_UNRECORDED: [(&str, usize); 2] = [("events", 8), ("tokens", 9)];
const WITHHELD_REPARSE: [(&str, usize); 3] = [("start", 4), ("evidence", 5), ("growth", 6)];
#[cfg(test)]
pub(crate) mod withheld_support {
    use super::*;
    pub(crate) fn take_withheld() -> [BTreeMap<&'static str, u64>; 3] {
        let claude = "claude_code";
        [
            drain(claude, &WITHHELD_RELEASED),
            drain(claude, &WITHHELD_REPARSE),
            drain(claude, &WITHHELD_UNRECORDED),
        ]
    }
}

const SCHEMA_VERSION: u8 = 2;

pub(crate) fn connection_binding_read<T>(result: anyhow::Result<T>) -> anyhow::Result<T> {
    credential_file_read(result).inspect_err(|_| {
        traversal_point(
            "connection_binding_read",
            "unknown",
            &serde_json::json!({"connection_binding_unreadable": 1}),
        );
    })
}

#[cfg(not(test))]
static CREDENTIAL_FILE_CAP_REFUSED: [AtomicU64; 4] = [const { AtomicU64::new(0) }; 4];
#[cfg(test)]
thread_local! {
    static CREDENTIAL_FILE_CAP_REFUSED: [AtomicU64; 4] = const { [const { AtomicU64::new(0) }; 4] };
}
/// Observe typed cap errors before snapshot callers replace their detail.
/// Ordinary snapshot sync and retained retry use these same authority loads.
pub(crate) fn credential_file_read<T>(result: anyhow::Result<T>) -> anyhow::Result<T> {
    use ottto_core::{CredentialFileCapRefused, TokenStoreError};
    let kind = result.as_ref().err().and_then(|error| {
        error.chain().find_map(|cause| {
            if let Some(TokenStoreError::OversizeRefused) = cause.downcast_ref::<TokenStoreError>()
            {
                return Some(CredentialFileCapRefused::FileSecret);
            }
            cause
                .downcast_ref::<CredentialFileCapRefused>()
                .or_else(|| {
                    cause
                        .downcast_ref::<std::io::Error>()?
                        .get_ref()?
                        .downcast_ref::<CredentialFileCapRefused>()
                })
                .copied()
        })
    });
    if let Some(kind) = kind {
        let (slot, file_kind) = match kind {
            CredentialFileCapRefused::DeviceBinding => (0, "device_binding"),
            CredentialFileCapRefused::FileSecret => (1, "file_secret"),
            CredentialFileCapRefused::ConnectionBinding => (2, "connection_binding"),
            CredentialFileCapRefused::PendingDeviceCredential => (3, "pending_device_credential"),
        };
        let increment = |counts: &[AtomicU64; 4]| {
            counts[slot]
                .fetch_update(Relaxed, Relaxed, |n| Some(n.saturating_add(1)))
                .map_or(u64::MAX, |n| n.saturating_add(1))
        };
        #[cfg(not(test))]
        let total = increment(&CREDENTIAL_FILE_CAP_REFUSED);
        #[cfg(test)]
        let total = CREDENTIAL_FILE_CAP_REFUSED.with(increment);
        traversal_point(
            "credential_file_cap_refusal",
            "unknown",
            &serde_json::json!({
                "file_kind": file_kind,
                "credential_file_cap_refused": 1,
                "credential_file_cap_refused_total": total,
            }),
        );
    }
    result
}

/// Cumulative shared-process totals, NOT events attributed to the finishing
/// page/source. No CPU/RSS probe, lookup, new collection trigger or wire event.
pub(crate) fn cache_lifecycle_totals() {
    traversal_point(
        "process_retained_cache_lifecycle_totals",
        "unknown",
        &cache_lifecycle::snapshot(),
    );
}

/// Cumulative shared-process Codex memo totals (L-2): lifetime counters plus
/// one resident gauge, NOT events attributed to the finishing page/source.
/// Codex scans only.
pub(crate) fn codex_memo_lifecycle_totals(source: &str) {
    if source == "codex" {
        traversal_point(
            "process_codex_memo_lifecycle_totals",
            "codex",
            &codex_memo_lifecycle::snapshot(),
        );
    }
}

/// Local alarm, once per process: a Claude context fold first withheld
/// session scalars for a resource limit (SOURCE Amendment 7). Counts only.
pub(crate) fn claude_context_resource_withhold(counts: &impl Serialize) {
    traversal_point("claude_context_resource_withhold", "claude_code", counts);
}

/// Cumulative shared-process Codex parent side-record totals (U1a-2a):
/// lifetime counters plus last-measured gauges, NOT events attributed to the
/// finishing page/source. Codex scans only.
pub(crate) fn codex_side_lifecycle_totals(source: &str) {
    if source == "codex" {
        traversal_point(
            "process_codex_side_lifecycle_totals",
            "codex",
            &codex_side_lifecycle::snapshot(),
        );
    }
}

/// The two point lines of one side read (`codex_side_lifecycle::SideReadGuard`).
pub(crate) enum SideReadPoint {
    Start { pseq: u64, attempts: u8 },
    End { pseq: u64, abandoned: bool },
}

/// One content-free line per side read start or end, on the existing
/// best-effort stderr carrier. With `process_id`, a start that has no matching
/// end before a new `process_id` is the only crash evidence; nothing is
/// persisted, and no CPU/RSS sample is taken.
pub(crate) fn side_read_point(point: SideReadPoint) {
    #[derive(Serialize)]
    struct Start {
        pseq: u64,
        attempts: u8,
    }
    #[derive(Serialize)]
    struct End {
        pseq: u64,
        #[serde(skip_serializing_if = "std::ops::Not::not")]
        abandoned: bool,
    }
    match point {
        SideReadPoint::Start { pseq, attempts } => {
            traversal_point("side_read_start", "codex", &Start { pseq, attempts })
        }
        SideReadPoint::End { pseq, abandoned } => {
            traversal_point("side_read_end", "codex", &End { pseq, abandoned })
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
enum Source {
    ClaudeCode,
    Codex,
    Pi,
    Unknown,
}
impl Source {
    fn from_slug(slug: &str) -> Self {
        match slug {
            "claude_code" => Self::ClaudeCode,
            "codex" => Self::Codex,
            "pi" => Self::Pi,
            _ => Self::Unknown,
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct ProcessSample {
    cpu_us: u64,
    lifetime_max_rss_bytes: u64,
}

fn process_sample() -> Option<ProcessSample> {
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        let mut usage = std::mem::MaybeUninit::<libc::rusage>::uninit();
        // SAFETY: getrusage initializes the complete struct on success.
        if unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) } != 0 {
            return None;
        }
        let usage = unsafe { usage.assume_init() };
        let micros = |time: libc::timeval| {
            u64::try_from(time.tv_sec)
                .ok()?
                .checked_mul(1_000_000)?
                .checked_add(u64::try_from(time.tv_usec).ok()?)
        };
        let raw_rss = u64::try_from(usage.ru_maxrss).ok()?;
        Some(ProcessSample {
            cpu_us: micros(usage.ru_utime)?.checked_add(micros(usage.ru_stime)?)?,
            lifetime_max_rss_bytes: if cfg!(target_os = "macos") {
                raw_rss
            } else {
                raw_rss.checked_mul(1024)?
            },
        })
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    None
}

#[derive(Debug)]
pub(crate) struct Probe {
    withheld_memo: Option<crate::snapshots::withheld_account::Memo>,
    started: Instant,
    process: Option<ProcessSample>,
    pub(crate) page_events: claude_reread::Counts,
    pub(crate) full_causes: FullCauses,
    pub(crate) line_delivery: Option<(&'static str, LineDeliveryCounts)>,
    pub(crate) discovery_growth: crate::snapshots::discovery_growth::Page,
    #[cfg(feature = "replay-harness")]
    index_reuse_skips: std::cell::Cell<u64>,
}
impl Drop for Probe {
    fn drop(&mut self) {
        rearm_cause::finish_page(self.started);
    }
}
impl Probe {
    pub(crate) fn set_withheld_memo(&mut self, memo: crate::snapshots::withheld_account::Memo) {
        self.withheld_memo = Some(memo);
    }
    pub(crate) fn with_withheld_memo(
        mut self,
        memo: crate::snapshots::withheld_account::Memo,
    ) -> Self {
        self.set_withheld_memo(memo);
        self
    }
    pub(crate) fn rearm_full_selected(
        &self,
        key: &str,
        mode: crate::transcript_acquisition::ReadMode,
    ) {
        rearm_cause::selected(self.started, key, mode);
    }
    pub(crate) fn rearm_full_completed(
        &self,
        key: &str,
        mode: crate::transcript_acquisition::ReadMode,
        bytes: u64,
    ) {
        rearm_cause::completed(self.started, key, mode, bytes);
    }
    pub(crate) fn rearm_fulls(&self) -> rearm_cause::Counts {
        rearm_cause::page(self.started)
    }
    pub(crate) fn start() -> Self {
        Self {
            withheld_memo: None,
            started: Instant::now(),
            process: process_sample(),
            page_events: Default::default(),
            full_causes: Default::default(),
            line_delivery: None,
            discovery_growth: Default::default(),
            #[cfg(feature = "replay-harness")]
            index_reuse_skips: std::cell::Cell::new(0),
        }
    }
    fn stage_observation(&self, footprint: Option<&footprint::Stage>) -> Observation {
        let mut observation = self.observation();
        observation.footprint =
            footprint.map_or_else(footprint::unavailable, footprint::Stage::finish);
        observation
    }
    #[cfg(feature = "replay-harness")]
    pub(crate) fn index_reuse_skip(&self) {
        self.index_reuse_skips
            .set(self.index_reuse_skips.get().saturating_add(1));
    }
    fn observation(&self) -> Observation {
        Observation::between(
            self.started.elapsed().as_micros().min(u128::from(u64::MAX)) as u64,
            self.process,
            process_sample(),
        )
    }
    #[cfg(test)]
    pub(crate) fn collection(&self, source: &str, counts: CollectionCounts) {
        self.collection_with_account_pending(source, counts, None);
    }
    pub(crate) fn collection_with_account_pending(
        &self,
        source: &str,
        counts: CollectionCounts,
        pending: Option<ClaudeAccountRetainedPending>,
    ) {
        #[derive(Serialize)]
        struct Counts {
            #[serde(flatten)]
            collection: CollectionCounts,
            #[cfg(feature = "replay-harness")]
            index_reuse_skips: u64,
            #[serde(flatten)]
            pending: Option<ClaudeAccountRetainedPending>,
            #[serde(flatten)]
            money: crate::snapshots::claude_request_money::e2::Counts,
            #[serde(flatten)]
            caps: ClaudeRecordCaps,
            #[serde(flatten)]
            identity: crate::snapshots::claude_request_identity::IdentityCounts,
            #[serde(flatten)]
            reread: claude_reread::Counts,
            #[serde(skip_serializing_if = "Option::is_none")]
            line_delivery: Option<BTreeMap<&'static str, LineDeliveryCounts>>,
            #[serde(skip_serializing_if = "BTreeMap::is_empty")]
            line_delivery_unselected: BTreeMap<&'static str, u64>,
            #[serde(skip_serializing_if = "BTreeMap::is_empty")]
            audit_retired_absent: BTreeMap<&'static str, u64>,
            #[serde(skip_serializing_if = "BTreeMap::is_empty")]
            discovery_retained: BTreeMap<&'static str, u64>,
            #[serde(skip_serializing_if = "BTreeMap::is_empty")]
            codex_fragment_tail_repeat: BTreeMap<&'static str, u64>,
            #[serde(skip_serializing_if = "BTreeMap::is_empty")]
            withheld_hold_released: BTreeMap<&'static str, u64>,
            #[serde(skip_serializing_if = "BTreeMap::is_empty")]
            withheld_reparse: BTreeMap<&'static str, u64>,
            #[serde(skip_serializing_if = "BTreeMap::is_empty")]
            withheld_birth_clamp_accepted: BTreeMap<&'static str, u64>,
            #[serde(skip_serializing_if = "BTreeMap::is_empty")]
            withheld_hold_unrecorded: BTreeMap<&'static str, u64>,
            #[serde(skip_serializing_if = "Option::is_none")]
            withheld_memo: Option<crate::snapshots::withheld_account::Census>,
            #[serde(flatten)]
            withheld_held: Option<crate::snapshots::withheld_account::HeldGauge>,
            #[serde(skip_serializing_if = "BTreeMap::is_empty")]
            source_rotation_serial_fallback: BTreeMap<&'static str, u64>,
        }
        let claude = source == "claude_code";
        let counts = Counts {
            #[cfg(feature = "replay-harness")]
            index_reuse_skips: self.index_reuse_skips.replace(0),
            line_delivery: self
                .line_delivery
                .filter(|(_, counts)| *counts != LineDeliveryCounts::default())
                .map(|(observer, counts)| BTreeMap::from([(observer, counts)])),
            line_delivery_unselected: drain(
                source,
                &[
                    ("age", 0),
                    ("size", 1),
                    ("withheld_oversized", 2),
                    ("withheld_absence_ambiguous", 18),
                ],
            ),
            audit_retired_absent: drain(source, &[("events", 12)]),
            discovery_retained: drain(source, &[("grown", 10)]),
            codex_fragment_tail_repeat: drain(source, &[("files", 13), ("bytes", 14)]),
            withheld_hold_released: drain(source, &WITHHELD_RELEASED),
            withheld_reparse: drain(source, &WITHHELD_REPARSE),
            withheld_birth_clamp_accepted: drain(source, &[("events", 15)]),
            withheld_hold_unrecorded: drain(source, &WITHHELD_UNRECORDED),
            withheld_memo: claude
                .then(|| self.withheld_memo.as_ref().and_then(|memo| memo.census()))
                .flatten(),
            withheld_held: claude
                .then(|| {
                    self.withheld_memo
                        .as_ref()
                        .and_then(|memo| memo.held_gauge())
                })
                .flatten(),
            source_rotation_serial_fallback: drain(
                source,
                &[("unsupported_layout", 16), ("bound_refused", 17)],
            ),
            reread: if claude {
                self.page_events.with_current().without_terminal_rearm()
            } else {
                Default::default()
            },
            collection: counts,
            pending,
            identity: if claude {
                crate::snapshots::claude_request_identity::take_identity_counts()
            } else {
                Default::default()
            },
            caps: if claude {
                take_claude_record_caps()
            } else {
                Default::default()
            },
            money: if claude {
                crate::snapshots::claude_request_money::e2::take_counts()
            } else {
                Default::default()
            },
        };
        emit(&Record {
            schema_version: SCHEMA_VERSION,
            process_id: std::process::id(),
            stage: "native_collection_page",
            source: Source::from_slug(source),
            observation: self.observation(),
            counts,
        });
    }
}

// Terminal scheduling runs after collection. Same carrier, zero scan counts,
// no process sampling or draining another producer's identity/money counters.
fn rearm_collection(rearm: claude_reread::Counts) {
    #[derive(Serialize)]
    struct Counts {
        #[serde(flatten)]
        collection: CollectionCounts,
        #[serde(flatten)]
        rearm: claude_reread::Counts,
    }
    emit(&Record {
        schema_version: SCHEMA_VERSION,
        process_id: std::process::id(),
        stage: "native_collection_page",
        source: Source::from_slug("claude_code"),
        observation: Observation::between(0, None, None),
        counts: Counts {
            collection: CollectionCounts {
                scanned_files: 0,
                semantic_noops: 0,
                sampled_acquisition: None,
                full_causes: Default::default(),
            },
            rearm,
        },
    });
}

/// All retained account-pending families, including held/incomplete families;
/// a conservative local-only gauge, never an authority or eviction decision.
#[derive(Debug, Serialize)]
pub(crate) struct ClaudeAccountRetainedPending {
    pub(crate) claude_account_retained_pending_families: usize,
    /// Pretty JSON bytes of the retained field, including its field wrapper.
    pub(crate) claude_account_retained_pending_bytes: u64,
    #[serde(flatten)]
    pub(crate) retention: crate::snapshots::account_pending_retention::Counts,
}
impl crate::heap_layout_bound::HeapLayoutBound for Probe {
    fn heap_bound(&self, c: &mut crate::heap_layout_bound::Counter) -> Option<()> {
        crate::heap_layout_bound::HeapLayoutBound::heap_bound(
            &self.full_causes.restore_outcome.miss,
            c,
        )?;
        crate::heap_layout_bound::HeapLayoutBound::heap_bound(&self.discovery_growth, c)
    }
}

#[derive(Debug, Serialize)]
struct Observation {
    observed_unix_ms: Option<u64>,
    wall_elapsed_us: u64,
    shared_process_cpu_delta_us: Option<u64>,
    process_lifetime_max_rss_bytes: Option<u64>,
    process_lifetime_max_rss_before_bytes: Option<u64>,
    #[serde(flatten)]
    footprint: footprint::Observation,
}
impl Observation {
    fn between(wall: u64, before: Option<ProcessSample>, after: Option<ProcessSample>) -> Self {
        Self {
            observed_unix_ms: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .ok()
                .and_then(|elapsed| u64::try_from(elapsed.as_millis()).ok()),
            wall_elapsed_us: wall,
            footprint: Default::default(),
            shared_process_cpu_delta_us: before
                .zip(after)
                .and_then(|(before, after)| after.cpu_us.checked_sub(before.cpu_us)),
            process_lifetime_max_rss_bytes: after.map(|sample| sample.lifetime_max_rss_bytes),
            process_lifetime_max_rss_before_bytes: before.zip(after).and_then(|(before, after)| {
                (before.lifetime_max_rss_bytes <= after.lifetime_max_rss_bytes)
                    .then_some(before.lifetime_max_rss_bytes)
            }),
        }
    }
}

/// Local prepare window, including index load/baseline work before page probes.
/// Return values and errors pass through; unwinding closes sampling silently.
pub(crate) fn source_prepare<T>(source: &str, inner: impl FnOnce() -> T) -> T {
    let probe = Probe::start();
    let footprint = footprint::Stage::begin();
    let result = inner();
    emit(&Record {
        schema_version: SCHEMA_VERSION,
        process_id: std::process::id(),
        stage: "source_prepare",
        source: Source::from_slug(source),
        observation: probe.stage_observation(footprint.as_ref()),
        counts: BTreeMap::<&str, u64>::new(),
    });
    result
}

/// Observe only a normally returned finish; move its value/error through unchanged.
/// A panic drops the probe silently. Outcome reporting remains with the caller.
pub(crate) fn source_finish<T>(
    source: &str,
    inner: impl FnOnce() -> anyhow::Result<T>,
) -> anyhow::Result<T> {
    let probe = Probe::start();
    let footprint = footprint::Stage::begin();
    let result = inner();
    emit(&Record {
        schema_version: SCHEMA_VERSION,
        process_id: std::process::id(),
        stage: "source_finish",
        source: Source::from_slug(source),
        observation: probe.stage_observation(footprint.as_ref()),
        counts: EmptyCounts {},
    });
    result
}
/// Point outcome at an existing Codex authority boundary. Two fixed records at
/// most per completed page, using the existing best-effort stderr carrier.
/// This is not a completion heartbeat, resource window or ingestion verdict.
pub(crate) fn codex_census_fence(
    phase: crate::codex_scan_diagnostics::CensusFencePhase,
    outcome: crate::codex_scan_diagnostics::CensusFenceOutcome,
    invalidation: crate::codex_scan_diagnostics::CensusInvalidation,
) {
    #[derive(Serialize)]
    struct Counts {
        phase: crate::codex_scan_diagnostics::CensusFencePhase,
        outcome: crate::codex_scan_diagnostics::CensusFenceOutcome,
        invalidation: crate::codex_scan_diagnostics::CensusInvalidation,
    }
    emit(&Record {
        schema_version: SCHEMA_VERSION,
        process_id: std::process::id(),
        stage: "codex_census_fence",
        source: Source::Codex,
        // A point observation has no measured resource window. Do not take
        // extra CPU/RSS samples or invent numeric measurements for this event.
        observation: Observation {
            observed_unix_ms: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .ok()
                .and_then(|elapsed| u64::try_from(elapsed.as_millis()).ok()),
            wall_elapsed_us: 0,
            footprint: Default::default(),
            shared_process_cpu_delta_us: None,
            process_lifetime_max_rss_bytes: None,
            process_lifetime_max_rss_before_bytes: None,
        },
        counts: Counts {
            phase,
            outcome,
            invalidation,
        },
    });
}

#[derive(Serialize)]
struct EmptyCounts {}

/// Fixed-schema traversal decisions only; no CPU/RSS sample or wire event.
pub(crate) fn traversal_transition(source: &str, counts: &impl Serialize) {
    traversal_point("bounded_traversal_transition", source, counts);
}
#[derive(Serialize)]
struct ListMissingCause {
    cause: &'static str,
}

/// Local alarm, once per Claude cycle while it lasts: the re-emission list was
/// installed once and its file is now missing, so the one-time history
/// re-read is paused. `cause` names why it reads installed: the seen-marker,
/// Set intent, or intent that could not be read (addendum 3). No path, id or
/// wire event.
pub(crate) fn claude_reemission_list_missing(cause: &'static str) {
    traversal_point(
        "claude_reemission_list_missing_after_install",
        "claude_code",
        &ListMissingCause { cause },
    );
}
/// Local alarm, at most hourly: Claude history owes an upgrade to the active
/// body-witness revision while the protected list was never installed, so
/// the history gate holds it. Counts only; no path, id or wire event.
pub(crate) fn claude_history_upgrade_owed_without_list(counts: &impl Serialize) {
    traversal_point(
        "claude_history_upgrade_owed_without_list",
        "claude_code",
        counts,
    );
}
/// Local alarm, once per park: a held Claude key's progress audit failed its
/// secure open 8 times in a row and is parked, its audit debt still owed.
/// Counts only; no path, id or wire event.
pub(crate) fn claude_held_audit_open_parked(counts: &impl Serialize) {
    traversal_point("claude_held_audit_open_parked", "claude_code", counts);
}
/// Local alarm, at most hourly: a complete Claude terminal kept the retired
/// family tombstone uncertainty fence up, because more absent witnessed roots
/// need a tombstone than fit under the cap. Counts only; no path, id or wire
/// event.
pub(crate) fn claude_absent_family_tombstone_uncertain(counts: &impl Serialize) {
    traversal_point(
        "claude_absent_family_tombstone_uncertain",
        "claude_code",
        counts,
    );
}
/// E7-8a shadow, once per Claude page: per-family census completion counts
/// (`family_census_complete`, `family_census_incomplete{reason}`,
/// `family_complete_deferred{quantum}`), `pending_census_members`, the
/// skipped-set digest and predicate cost. Counts only; never an authority
/// input, no path, id or wire event.
pub(crate) fn claude_family_census_shadow(counts: &impl Serialize) {
    traversal_point("claude_family_census_shadow", "claude_code", counts);
}
static HISTORY_PROOF_CORRECTION_DEFERRED_TOTAL: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

#[derive(Serialize)]
struct HistoryProofCorrectionDeferred {
    history_proof_correction_deferred: u64,
    history_proof_correction_deferred_total: u64,
}

/// Local counter (StateMissing M2, SOURCE h695 N6): proof-correction members
/// the history gate holds, deferred instead of blocking settlement. This
/// settlement's count and a saturating process total. Counts only; no path,
/// id or wire event.
pub(crate) fn claude_history_proof_correction_deferred(members: usize) {
    let members = u64::try_from(members).unwrap_or(u64::MAX);
    let previous = HISTORY_PROOF_CORRECTION_DEFERRED_TOTAL
        .fetch_update(
            std::sync::atomic::Ordering::Relaxed,
            std::sync::atomic::Ordering::Relaxed,
            |total| Some(total.saturating_add(members)),
        )
        .unwrap_or(u64::MAX);
    traversal_point(
        "claude_history_proof_correction_deferred",
        "claude_code",
        &HistoryProofCorrectionDeferred {
            history_proof_correction_deferred: members,
            history_proof_correction_deferred_total: previous.saturating_add(members),
        },
    );
}
/// Local diagnostic, at most hourly: the backfill state's
/// `prior_history_unverified` marker has been read set since the given time
/// (first seen by this process). Counts and times only; no path, id or wire
/// event.
pub(crate) fn claude_prior_history_unverified(counts: &impl Serialize) {
    traversal_point("claude_prior_history_unverified", "claude_code", counts);
}
/// Local alarm, once per refusal: a body-witness revision with no history
/// policy row was not activated, and the previous active revision was kept.
/// Counts only; no path, id or wire event.
pub(crate) fn claude_history_revision_activation_refused(counts: &impl Serialize) {
    traversal_point(
        "claude_history_revision_activation_refused",
        "claude_code",
        counts,
    );
}
static REEMISSION_FAMILY_CLOSURE_ROOT_ABSENT_EXCLUDED_TOTAL: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

#[derive(Serialize)]
struct ReemissionFamilyClosureRootAbsentExcluded {
    claude_reemission_family_closure_root_absent_excluded: u64,
    claude_reemission_family_closure_root_absent_excluded_total: u64,
}

/// Local counter (StateMissing M1, SOURCE d680b524): subagent members the
/// history gate held only through their listed family root while the root
/// file is absent. This page's count and a saturating process total. Counts
/// only; no path, id or wire event.
pub(crate) fn claude_reemission_family_closure_root_absent_excluded(members: u64) {
    let previous = REEMISSION_FAMILY_CLOSURE_ROOT_ABSENT_EXCLUDED_TOTAL
        .fetch_update(
            std::sync::atomic::Ordering::Relaxed,
            std::sync::atomic::Ordering::Relaxed,
            |total| Some(total.saturating_add(members)),
        )
        .unwrap_or(u64::MAX);
    traversal_point(
        "claude_reemission_family_closure_root_absent_excluded",
        "claude_code",
        &ReemissionFamilyClosureRootAbsentExcluded {
            claude_reemission_family_closure_root_absent_excluded: members,
            claude_reemission_family_closure_root_absent_excluded_total: previous
                .saturating_add(members),
        },
    );
}
static CENSUS_RETIRE_KEPT_OVERLAP_TOTAL: [std::sync::atomic::AtomicU64; 6] = [
    std::sync::atomic::AtomicU64::new(0),
    std::sync::atomic::AtomicU64::new(0),
    std::sync::atomic::AtomicU64::new(0),
    std::sync::atomic::AtomicU64::new(0),
    std::sync::atomic::AtomicU64::new(0),
    std::sync::atomic::AtomicU64::new(0),
];

/// One `claude_census_retire_kept_overlap` row (E7 stopgap): a complete
/// terminal's kept records, their hashes and those retired because the
/// census was above 90% occupancy, with the terminal's census-full tombstone
/// count; or the records an insert retired so it fits (admission overflow,
/// no terminal count); or a new key refused at the live record bound.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct CensusRetireKeptOverlapCounts {
    pub(crate) records: u64,
    pub(crate) hashes: u64,
    pub(crate) overflow_occupancy: u64,
    pub(crate) overflow_admission: u64,
    /// New keys refused at the live census record bound.
    pub(crate) record_limit_refused: u64,
    /// The terminal's shadow `missing_over_budget`; None on admission rows.
    pub(crate) missing_over_budget: Option<u64>,
}

#[derive(Serialize)]
struct CensusRetireKeptOverlap {
    census_retire_kept_overlap_records: u64,
    census_retire_kept_overlap_hashes: u64,
    census_retire_kept_overflow: u64,
    census_retire_kept_overflow_occupancy: u64,
    census_retire_kept_overflow_admission: u64,
    census_record_limit_refused: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    census_missing_over_budget: Option<u64>,
    census_retire_kept_overlap_records_total: u64,
    census_retire_kept_overlap_hashes_total: u64,
    census_retire_kept_overflow_total: u64,
    census_retire_kept_overflow_occupancy_total: u64,
    census_retire_kept_overflow_admission_total: u64,
    census_record_limit_refused_total: u64,
}

/// Local counter (E7 stopgap): aged Claude transcript census records kept
/// because they share a request id with another unretired record, and those
/// retired anyway: above 90% census occupancy at a terminal, or so an insert
/// fits. `census_retire_kept_overflow` counts both reasons, `_occupancy`
/// and `_admission` each one. `census_record_limit_refused` counts new keys
/// refused at the live record bound. The row's counts and saturating process totals; a positive
/// overflow or refusal (each loses money proof) also emits
/// `claude_census_retire_kept_overlap_alarm`. Counts only; no path, id or
/// wire event.
pub(crate) fn claude_census_retire_kept_overlap(counts: CensusRetireKeptOverlapCounts) {
    let add = |slot: usize, count: u64| {
        CENSUS_RETIRE_KEPT_OVERLAP_TOTAL[slot]
            .fetch_update(
                std::sync::atomic::Ordering::Relaxed,
                std::sync::atomic::Ordering::Relaxed,
                |total| Some(total.saturating_add(count)),
            )
            .unwrap_or(u64::MAX)
            .saturating_add(count)
    };
    let overflow = counts
        .overflow_occupancy
        .saturating_add(counts.overflow_admission);
    let row = CensusRetireKeptOverlap {
        census_retire_kept_overlap_records: counts.records,
        census_retire_kept_overlap_hashes: counts.hashes,
        census_retire_kept_overflow: overflow,
        census_retire_kept_overflow_occupancy: counts.overflow_occupancy,
        census_retire_kept_overflow_admission: counts.overflow_admission,
        census_record_limit_refused: counts.record_limit_refused,
        census_missing_over_budget: counts.missing_over_budget,
        census_retire_kept_overlap_records_total: add(0, counts.records),
        census_retire_kept_overlap_hashes_total: add(1, counts.hashes),
        census_retire_kept_overflow_total: add(2, overflow),
        census_retire_kept_overflow_occupancy_total: add(3, counts.overflow_occupancy),
        census_retire_kept_overflow_admission_total: add(4, counts.overflow_admission),
        census_record_limit_refused_total: add(5, counts.record_limit_refused),
    };
    traversal_point("claude_census_retire_kept_overlap", "claude_code", &row);
    if overflow > 0 || counts.record_limit_refused > 0 {
        traversal_point(
            "claude_census_retire_kept_overlap_alarm",
            "claude_code",
            &row,
        );
    }
}
/// Local alarm: the one-time Claude history re-read latched its stop until
/// the daemon restarts (SOURCE Amendment 10), once when it sets and at most
/// hourly as a reminder. Counts and hashed root refs only; no wire event.
pub(crate) fn claude_reemission_stop_latched(reminder: bool, counts: &impl Serialize) {
    let stage = if reminder {
        "claude_reemission_stop_latched_reminder"
    } else {
        "claude_reemission_stop_latched"
    };
    traversal_point(stage, "claude_code", counts);
}
/// Local alarm (5a1b): durable-store holds, T14 rebuilds, mode repairs and a
/// disabled store, as [since last, total] counts. No path, id or wire event.
pub(crate) fn durable_tail_alarm(source: &str, counts: &impl Serialize) {
    traversal_point("durable_tail_alarm", source, counts);
}
/// At most once per 24 h while restart Fulls caused by a failed store write persist.
pub(crate) fn durable_tail_restart_full_alarm(source: &str, counts: &impl Serialize) {
    traversal_point("durable_tail_restart_full_alarm", source, counts);
}
pub(crate) fn codex_continuation(held: Option<&'static str>) {
    let counts = serde_json::json!({
        "continuation_pages_run": u8::from(held.is_none()),
        "continuation_held": held.map(|reason| BTreeMap::from([(reason, 1u8)])).unwrap_or_default(),
    });
    traversal_point("codex_continuation", "codex", &counts);
}
pub(crate) fn codex_continuation_mint(outcome: &'static str) {
    let counts = serde_json::json!({"continuation_mint": BTreeMap::from([(outcome, 1u8)])});
    traversal_point("codex_continuation_mint", "codex", &counts);
}
pub(crate) fn traversal_point(stage: &'static str, source: &str, counts: &impl Serialize) {
    emit(&Record {
        schema_version: SCHEMA_VERSION,
        process_id: std::process::id(),
        stage,
        source: Source::from_slug(source),
        observation: Observation {
            observed_unix_ms: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .ok()
                .and_then(|elapsed| u64::try_from(elapsed.as_millis()).ok()),
            wall_elapsed_us: 0,
            footprint: Default::default(),
            shared_process_cpu_delta_us: None,
            process_lifetime_max_rss_bytes: None,
            process_lifetime_max_rss_before_bytes: None,
        },
        counts,
    });
}

/// One preparation/page observation, never a permit or authority input.
/// None means that boundary was not reached, not a known false/zero result.
#[derive(Clone, Copy, Debug, Default, Serialize)]
pub(crate) struct NativeComparisonDecision {
    pub(crate) layout_supported: bool,
    pub(crate) lease_generation: Option<u64>,
    pub(crate) fold_index_generation: Option<u64>,
    pub(crate) allowed_at_bind: Option<bool>,
    pub(crate) controller_created: bool,
    pub(crate) controller_current_at_finish: Option<bool>,
    pub(crate) bootstrap: Option<NativeBootstrap>,
    pub(crate) selected_save: bool,
    pub(crate) upload_fully_settled: Option<bool>,
    pub(crate) clean_at_finish: Option<bool>,
    pub(crate) retained_permit: Option<bool>,
    pub(crate) revoke_calls: usize,
    pub(crate) admission_refusal_calls: usize,
    pub(crate) hit_policy_calls: usize,
    pub(crate) deferred_decisions: usize,
    pub(crate) latched_base_decisions: usize,
    pub(crate) other_base_decisions: usize,
    pub(crate) terminal_rearm: Option<NativeRearm>,
    pub(crate) correction_mint: Option<NativeMint>,
    pub(crate) outcome: NativeDecisionOutcome,
}
#[derive(Clone, Copy, Debug, Default, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum NativeDecisionOutcome {
    #[default]
    Abandoned,
    CadenceWait,
    Finished,
    DisabledBeforeLease,
}
#[derive(Clone, Copy, Debug, Serialize)]
pub(crate) struct NativeBootstrap {
    pub(crate) native_census_complete: bool,
    pub(crate) coverage_complete: bool,
    pub(crate) census_valid: bool,
    pub(crate) fence_open: bool,
    pub(crate) pending_occurrences_present: bool,
    pub(crate) transcript_ownership_complete: bool,
    pub(crate) scan_census_complete: bool,
    pub(crate) not_withheld: bool,
}
#[derive(Clone, Copy, Debug, Default, Serialize)]
pub(crate) struct NativeRearm {
    pub(crate) negative_keys: usize,
    pub(crate) proof_candidates: usize,
    /// Actual no-clear decisions: other rearm disjuncts must also be false.
    pub(crate) suppressed: usize,
    pub(crate) other_rearm_matches: usize,
    pub(crate) clear_calls: usize,
}
#[derive(Clone, Copy, Debug, Default, Serialize)]
pub(crate) struct NativeMint {
    pub(crate) window_available: bool,
    pub(crate) candidates: usize,
    pub(crate) insertions: usize,
    /// This is before later window staging/retirement, not a retained grant.
    pub(crate) receipts_after_mint: usize,
}
/// Inline Cell permits the final read-only negative view to report decisions.
/// It owns no graph and is included in its lease's existing layout charge.
pub(crate) struct NativeDecision(
    pub(crate) std::cell::Cell<NativeComparisonDecision>,
    std::cell::Cell<claude_reread::Counts>,
);
impl NativeDecision {
    pub(crate) fn new() -> Self {
        Self(
            std::cell::Cell::new(NativeComparisonDecision {
                layout_supported: crate::heap_layout_bound::layout_supported(),
                ..Default::default()
            }),
            std::cell::Cell::new(Default::default()),
        )
    }
    pub(crate) fn update(&self, update: impl FnOnce(&mut NativeComparisonDecision)) {
        let mut value = self.0.get();
        update(&mut value);
        self.0.set(value);
    }
    pub(crate) fn add_page_events(&self, counts: claude_reread::Counts) {
        let mut value = self.1.get();
        value.merge(counts);
        self.1.set(value);
    }
    pub(crate) fn emit(&self) {
        #[derive(Serialize)]
        struct Counts {
            #[serde(flatten)]
            decision: NativeComparisonDecision,
            #[serde(flatten)]
            events: claude_reread::Counts,
        }
        traversal_point(
            "native_comparison_decision",
            "claude_code",
            &Counts {
                decision: self.0.get(),
                events: self.1.get().with_current().without_terminal_rearm(),
            },
        );
    }
}
impl crate::heap_layout_bound::HeapLayoutBound for NativeDecision {
    const INLINE_ONLY: bool = true;
    fn heap_bound(&self, c: &mut crate::heap_layout_bound::Counter) -> Option<()> {
        c.add(0)
    }
}

/// Per-page restore attempts. A miss class never authorizes a body read.
#[derive(Debug, Default, Serialize)]
pub(crate) struct FullCauses {
    pub(crate) restore_outcome: RestoreCounts,
}
impl FullCauses {
    fn is_empty(&self) -> bool {
        self.restore_outcome.restored == 0
            && self.restore_outcome.held == 0
            && self.restore_outcome.miss.is_empty()
    }
}
#[derive(Debug, Default, Serialize)]
pub(crate) struct RestoreCounts {
    #[serde(skip_serializing_if = "is_zero")]
    restored: u64,
    #[serde(skip_serializing_if = "is_zero")]
    held: u64,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    miss: BTreeMap<&'static str, u64>,
}
impl RestoreCounts {
    #[cfg(unix)]
    pub(crate) fn record(&mut self, outcome: &crate::snapshots::sampled_scan::RestoreOutcome) {
        use crate::snapshots::sampled_scan::RestoreOutcome;
        let count = match outcome {
            RestoreOutcome::Restored(_) => &mut self.restored,
            RestoreOutcome::Held(_) => &mut self.held,
            RestoreOutcome::Miss(class) => self.miss.entry(class.label()).or_default(),
        };
        *count = count.saturating_add(1);
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct CollectionCounts {
    pub(crate) scanned_files: usize,
    pub(crate) semantic_noops: usize,
    /// Absent without sampled acquisition. Even when present, these are not
    /// total filesystem reads: byte counts exclude failed plans, joins,
    /// discovery and sidecars. Selection counts can include failed/repeated plans.
    pub(crate) sampled_acquisition: Option<ReadCounts>,
    #[serde(skip_serializing_if = "FullCauses::is_empty")]
    pub(crate) full_causes: FullCauses,
}
#[derive(Debug, Serialize)]
pub(crate) struct ReadCounts {
    pub(crate) full_selections: usize,
    pub(crate) tail_selections: usize,
    pub(crate) unchanged_selections: usize,
    pub(crate) completed_native_bytes: u64,
    pub(crate) completed_guard_bytes: u64,
    pub(crate) acquisition_admission: AcquisitionAdmission,
    pub(crate) page_events: PageEvents,
    pub(crate) index_state_at_page_end: IndexState,
    /// Resumable large-file Codex read cursor (#606). `null` when its
    /// snapshot could not be obtained (no Codex cursor page tick in this scan,
    /// or the cursor state was busy at completion): unknown, never zero
    /// activity.
    pub(crate) codex_cursor: Option<Box<CodexCursorCounts>>,
}

/// Content-free, fixed width; each count saturates at `u32::MAX`. Like
/// `FullReasons`, only nonzero keys are serialized (an absent key is zero);
/// the block itself is `null` when unknown.
#[derive(Clone, Copy, Debug, Default, Serialize)]
pub(crate) struct CodexCursorCounts {
    /// Process-global cursor counter deltas while this scan's window was
    /// open (its first cursor page tick to its completion). The cursor is
    /// shared by every namespace in the process and overlapping scans move
    /// these counters too: NOT events caused by this scan.
    pub(crate) during_scan_window: CodexCursorEvents,
    /// Process-wide cursor gauges when this scan completed.
    pub(crate) retained: CodexCursorRetained,
}

/// Process-global cursor events during a scan window (shared process scope,
/// not attributed to one scan or namespace).
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct CodexCursorEvents {
    pub(crate) jobs_started: u32,
    pub(crate) jobs_paused: u32,
    pub(crate) jobs_resumed: u32,
    pub(crate) jobs_certified: u32,
    pub(crate) jobs_uncertified: u32,
    pub(crate) jobs_invalidated: u32,
    pub(crate) jobs_member_changed: u32,
    pub(crate) jobs_state_bound: u32,
    pub(crate) jobs_lost: u32,
    pub(crate) jobs_deferred_inputs: u32,
    pub(crate) jobs_start_unstartable: u32,
    pub(crate) jobs_audit_restarted: u32,
    pub(crate) jobs_finish_failed: u32,
    pub(crate) jobs_frame_returned: u32,
    pub(crate) deferred: u32,
    pub(crate) deferred_rotation: u32,
    pub(crate) deferred_next_generation: u32,
    pub(crate) namespace_busy: u32,
    pub(crate) cursor_disabled_unsupported_layout: u32,
    pub(crate) audit_overdue: u32,
    pub(crate) sealed_fragment_withheld: u32,
    /// A withheld final record applied at a genuine unchanged EOF.
    pub(crate) eof_record_applied: u32,
    /// A paused job ended: its path no longer named its object, or its
    /// evidence stayed unavailable for 3 consecutive resume pages.
    pub(crate) jobs_unavailable_ended: u32,
    pub(crate) memo_hits: u32,
    pub(crate) memo_records: u32,
    pub(crate) parked_hits: u32,
}

/// Process-wide cursor state when the scan completed (gauges, not events).
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct CodexCursorRetained {
    /// A paused job is waiting in the slot.
    pub(crate) paused_job: bool,
    /// Its charged bytes (requested layout, measured at pause).
    pub(crate) paused_job_charged_bytes: u32,
    pub(crate) memo_entries: u32,
    pub(crate) parked_entries: u32,
    pub(crate) invalidation_entries: u32,
    pub(crate) rotation_waiters: u32,
    /// Process-lifetime maximum `now - due` of an overdue certification.
    pub(crate) lifetime_audit_overdue_max_age_seconds: u32,
}
impl Serialize for CodexCursorEvents {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(None)?;
        for (key, count) in [
            ("jobs_started", self.jobs_started),
            ("jobs_paused", self.jobs_paused),
            ("jobs_resumed", self.jobs_resumed),
            ("jobs_certified", self.jobs_certified),
            ("jobs_uncertified", self.jobs_uncertified),
            ("jobs_invalidated", self.jobs_invalidated),
            ("jobs_member_changed", self.jobs_member_changed),
            ("jobs_state_bound", self.jobs_state_bound),
            ("jobs_lost", self.jobs_lost),
            ("jobs_deferred_inputs", self.jobs_deferred_inputs),
            ("jobs_start_unstartable", self.jobs_start_unstartable),
            ("jobs_audit_restarted", self.jobs_audit_restarted),
            ("jobs_finish_failed", self.jobs_finish_failed),
            ("jobs_frame_returned", self.jobs_frame_returned),
            ("deferred", self.deferred),
            ("deferred_rotation", self.deferred_rotation),
            ("deferred_next_generation", self.deferred_next_generation),
            ("namespace_busy", self.namespace_busy),
            (
                "cursor_disabled_unsupported_layout",
                self.cursor_disabled_unsupported_layout,
            ),
            ("audit_overdue", self.audit_overdue),
            ("sealed_fragment_withheld", self.sealed_fragment_withheld),
            ("eof_record_applied", self.eof_record_applied),
            ("jobs_unavailable_ended", self.jobs_unavailable_ended),
            ("memo_hits", self.memo_hits),
            ("memo_records", self.memo_records),
            ("parked_hits", self.parked_hits),
        ] {
            if count != 0 {
                map.serialize_entry(key, &count)?;
            }
        }
        map.end()
    }
}
impl Serialize for CodexCursorRetained {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(None)?;
        if self.paused_job {
            map.serialize_entry("paused_job", &true)?;
        }
        for (key, count) in [
            ("paused_job_charged_bytes", self.paused_job_charged_bytes),
            ("memo_entries", self.memo_entries),
            ("parked_entries", self.parked_entries),
            ("invalidation_entries", self.invalidation_entries),
            ("rotation_waiters", self.rotation_waiters),
            (
                "lifetime_audit_overdue_max_age_seconds",
                self.lifetime_audit_overdue_max_age_seconds,
            ),
        ] {
            if count != 0 {
                map.serialize_entry(key, &count)?;
            }
        }
        map.end()
    }
}

/// Fixed page totals, not per-file history. Unassessed is attempts - assessed;
/// a short-circuited gate is never reported as a known false result.
#[derive(Clone, Copy, Debug, Default, Serialize)]
pub(crate) struct AssessedBool {
    assessed: usize,
    matched: usize,
}
impl AssessedBool {
    pub(crate) fn observe(&mut self, value: bool) {
        self.assessed = self.assessed.saturating_add(1);
        self.matched = self.matched.saturating_add(usize::from(value));
    }
}
#[derive(Clone, Copy, Debug, Default, Serialize)]
pub(crate) struct AcquisitionAdmission {
    pub(crate) attempts: usize,
    pub(crate) cache_lookup_miss_unknown_origin: usize,
    pub(crate) retained_entry: AssessedBool,
    pub(crate) owning_header_current: AssessedBool,
    pub(crate) state_census_complete: AssessedBool,
    pub(crate) sidecar_census_complete: AssessedBool,
    pub(crate) reduction_dependencies_available: AssessedBool,
    pub(crate) index_entry_present: AssessedBool,
    pub(crate) audit_metadata_supported: AssessedBool,
    pub(crate) protected_history: AssessedBool,
    pub(crate) forced_family: AssessedBool,
    pub(crate) comparison_target: AssessedBool,
    pub(crate) parent_proof_required: AssessedBool,
    pub(crate) audit_debt_present: AssessedBool,
    pub(crate) audit_slot_available: AssessedBool,
    pub(crate) sampling_allowed: AssessedBool,
    pub(crate) retained_entry_rejected_by_eligibility: usize,
    pub(crate) prepare_started: usize,
    pub(crate) prepare_failed: usize,
}
impl crate::heap_layout_bound::HeapLayoutBound for AcquisitionAdmission {
    const INLINE_ONLY: bool = true;
    fn heap_bound(&self, c: &mut crate::heap_layout_bound::Counter) -> Option<()> {
        c.add(0)
    }
}

/// Existing audit point, using already computed final/previous fingerprints.
/// Additive aliases retain their meaning; neither comparison is an audit-policy
/// benefit verdict (a suffix or policy change can also change either witness).
pub(crate) fn sampled_audit_comparison(
    source: &str,
    semantic: (Option<&str>, Option<&str>),
    additive: (Option<&str>, Option<&str>),
) {
    #[derive(Serialize)]
    struct Counts {
        body_comparison_available: bool,
        effective_body_changed: bool,
        semantic_comparison_available: bool,
        semantic_changed: bool,
    }
    emit(&Record {
        schema_version: SCHEMA_VERSION,
        process_id: std::process::id(),
        stage: "sampled_audit_comparison",
        source: Source::from_slug(source),
        observation: Observation {
            observed_unix_ms: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .ok()
                .and_then(|elapsed| u64::try_from(elapsed.as_millis()).ok()),
            wall_elapsed_us: 0,
            footprint: Default::default(),
            shared_process_cpu_delta_us: None,
            process_lifetime_max_rss_bytes: None,
            process_lifetime_max_rss_before_bytes: None,
        },
        counts: Counts {
            body_comparison_available: additive.1.is_some(),
            effective_body_changed: additive.0 != additive.1,
            semantic_comparison_available: semantic.1.is_some(),
            semantic_changed: semantic.0 != semantic.1,
        },
    });
}
#[derive(Debug, Serialize)]
pub(crate) struct PageEvents {
    #[serde(skip_serializing_if = "rearm_cause::Counts::is_empty")]
    pub(crate) full_cause: rearm_cause::Counts,
    pub(crate) full_reasons: FullReasons,
    pub(crate) priority_full_replays: usize,
    pub(crate) audits_started: usize,
    pub(crate) audits_completed: usize,
    pub(crate) max_start_overdue_seconds: u64,
    pub(crate) max_completion_overdue_seconds: u64,
}
#[derive(Debug, Serialize)]
pub(crate) struct IndexState {
    pub(crate) audit_quiet_retired: usize,
    pub(crate) audit_cap_full: usize,
    pub(crate) pending_audits: usize,
    pub(crate) overdue_audits: usize,
    pub(crate) oldest_due_age_seconds: u64,
}
/// Reuse the existing counters; serialize only nonzero closed reason keys.
#[derive(Debug)]
pub(crate) struct FullReasons(pub(crate) [usize; 11]);
impl Serialize for FullReasons {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use crate::transcript_acquisition::FullReason::*;
        let mut map = serializer.serialize_map(None)?;
        for (reason, key) in [
            (StateMissing, "state_missing"),
            (AuditDue, "audit_due"),
            (ClockChanged, "clock_changed"),
            (ScopeChanged, "scope_changed"),
            (InvalidCheckpoint, "invalid_checkpoint"),
            (Replaced, "replaced"),
            (Shrunk, "shrunk"),
            (SameSizeEdit, "same_size_edit"),
            (HeadChanged, "head_changed"),
            (BoundaryChanged, "boundary_changed"),
            (UnsupportedIdentity, "unsupported_identity"),
        ] {
            let count = self.0[reason.slot()];
            if count != 0 {
                map.serialize_entry(key, &count)?;
            }
        }
        map.end()
    }
}

#[derive(Debug, Default, Serialize)]
struct UploadCounts {
    serialized_body_bytes: Option<u64>,
    gzip_attempts: u64,
    identity_attempts: u64,
    attempted_encoded_body_bytes: u64,
    attempted_decoded_body_bytes: u64,
}
pub(crate) struct UploadCall {
    probe: Probe,
    source: Source,
    counts: UploadCounts,
}
impl UploadCall {
    pub(crate) fn start(source: &str) -> Self {
        Self {
            probe: Probe::start(),
            source: Source::from_slug(source),
            counts: UploadCounts::default(),
        }
    }
    pub(crate) fn serialized(&mut self, bytes: usize) {
        self.counts.serialized_body_bytes = Some(bytes as u64);
    }
    /// Call after request construction/validation, immediately before send_bytes.
    /// Counts attempted body buffers, not successfully delivered network bytes.
    pub(crate) fn attempt(&mut self, encoded_bytes: usize, gzip: bool) {
        let count = if gzip {
            &mut self.counts.gzip_attempts
        } else {
            &mut self.counts.identity_attempts
        };
        *count = count.saturating_add(1);
        self.counts.attempted_encoded_body_bytes = self
            .counts
            .attempted_encoded_body_bytes
            .saturating_add(encoded_bytes as u64);
        self.counts.attempted_decoded_body_bytes = self
            .counts
            .attempted_decoded_body_bytes
            .saturating_add(self.counts.serialized_body_bytes.unwrap_or(0));
    }
}
impl Drop for UploadCall {
    fn drop(&mut self) {
        emit(&Record {
            schema_version: SCHEMA_VERSION,
            process_id: std::process::id(),
            stage: "snapshot_batch_call",
            source: self.source,
            observation: self.probe.observation(),
            counts: &self.counts,
        });
    }
}

#[derive(Serialize)]
struct Record<T: Serialize> {
    schema_version: u8,
    process_id: u32,
    stage: &'static str,
    source: Source,
    observation: Observation,
    counts: T,
}
fn emit(record: &impl Serialize) {
    if let Ok(json) = serde_json::to_string(record) {
        #[cfg(any(test, feature = "replay-harness"))]
        if TEST_OUTPUT.with(|output| {
            if let Some(output) = output.borrow_mut().as_mut() {
                output.push(json.clone());
                true
            } else {
                false
            }
        }) {
            return;
        }
        // Diagnostic sink failure must not change collection or ACK/recovery.
        write_line(&json, &mut std::io::stderr().lock());
    }
}

fn write_line(json: &str, writer: &mut impl Write) {
    let _ = writeln!(writer, "ottto-service: local_resources {json}");
}

#[cfg(any(test, feature = "replay-harness"))]
thread_local! {
    static TEST_OUTPUT: std::cell::RefCell<Option<Vec<String>>> = const { std::cell::RefCell::new(None) };
}
#[cfg(any(test, feature = "replay-harness"))]
pub(crate) fn capture<T>(f: impl FnOnce() -> T) -> (T, Vec<serde_json::Value>) {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            TEST_OUTPUT.with(|output| *output.borrow_mut() = None);
        }
    }
    TEST_OUTPUT.with(|output| {
        assert!(output.borrow().is_none());
        *output.borrow_mut() = Some(Vec::new());
    });
    let _reset = Reset;
    let result = f();
    let output = TEST_OUTPUT.with(|output| output.borrow_mut().take().unwrap());
    (
        result,
        output
            .iter()
            .map(|text| serde_json::from_str(text).unwrap())
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    #[test]
    fn compressed_causes_have_distinct_pinned_indices() {
        use super::CodexZstCause::*;
        const ALL: [super::CodexZstCause; super::CODEX_ZST_CAUSES] = [
            ReplayNotAuthorized,
            ProofParentUnsupported,
            ProofChildUnsupported,
            ParentSideUnsupported,
            DurableTailUnsupported,
            GroupProbeUnsupported,
            GroupReadUnsupported,
            ParentLedgerUnbound,
            PhysicalOffsetUnsupported,
            HeaderUnfunded,
            CompatibilityUnfunded,
            AdmissionRefused,
            DecoderRefusedHeaderOccupancy,
        ];
        assert_eq!(ALL.len(), super::CODEX_ZST_CAUSES);
        assert_eq!(
            serde_json::to_value(DecoderRefusedHeaderOccupancy).unwrap(),
            "decoder_refused_header_occupancy"
        );
        for (index, cause) in ALL.iter().enumerate() {
            assert_eq!(*cause as usize, index);
        }
    }

    use super::*;

    #[cfg(unix)]
    #[test]
    fn restore_counts_are_sparse_saturating_and_page_scoped() {
        use crate::snapshots::sampled_scan::{MissClass, RestoreOutcome};
        let mut probe = Probe::start();
        let collection = |full_causes| CollectionCounts {
            scanned_files: 0,
            semantic_noops: 0,
            sampled_acquisition: None,
            full_causes,
        };
        let (_, rows) = capture(|| {
            probe.collection("codex", collection(Default::default()));
            probe
                .full_causes
                .restore_outcome
                .record(&RestoreOutcome::Miss(MissClass::Missing));
            probe
                .full_causes
                .restore_outcome
                .record(&RestoreOutcome::Miss(MissClass::Missing));
            probe
                .full_causes
                .restore_outcome
                .record(&RestoreOutcome::Held(
                    crate::durable_tail_store::Refusal::Unknown,
                ));
            let counts = std::mem::take(&mut probe.full_causes);
            probe.collection("codex", collection(counts));
            let counts = std::mem::take(&mut probe.full_causes);
            probe.collection("codex", collection(counts));
        });
        assert!(rows[0]["counts"].get("full_causes").is_none());
        let counts = &rows[1]["counts"]["full_causes"]["restore_outcome"];
        assert_eq!(counts["miss"]["missing"], 2);
        assert_eq!(counts["held"], 1);
        assert!(counts.get("restored").is_none());
        assert_eq!(rows[1]["schema_version"], 2);
        assert!(rows[1]["counts"]["sampled_acquisition"].is_null());
        assert!(rows[2]["counts"].get("full_causes").is_none());
        let counts = &mut probe.full_causes.restore_outcome;
        counts.held = u64::MAX;
        counts.record(&RestoreOutcome::Held(
            crate::durable_tail_store::Refusal::Unknown,
        ));
        assert_eq!(counts.held, u64::MAX);
        counts.restored = 1;
        let json = serde_json::to_value(&probe.full_causes).unwrap();
        assert_eq!(json["restore_outcome"]["restored"], 1);
    }

    #[test]
    fn connection_binding_failures_are_counted_without_sensitive_detail() {
        let (_, lines) = capture(|| {
            assert!(connection_binding_read(Ok::<_, anyhow::Error>(None::<()>))
                .unwrap()
                .is_none());
            assert_eq!(connection_binding_read(Ok(7)).unwrap(), 7);
            for message in [
                "open connection binding /private/synthetic",
                "parse connection binding https://synthetic.invalid",
            ] {
                let error =
                    connection_binding_read::<()>(Err(anyhow::anyhow!(message))).unwrap_err();
                assert_eq!(error.to_string(), message);
            }
            let error = anyhow::Error::new(ottto_core::CredentialFileCapRefused::ConnectionBinding);
            assert!(connection_binding_read::<()>(Err(error)).is_err());
        });
        let unreadable: Vec<_> = lines
            .iter()
            .filter(|r| r["stage"] == "connection_binding_read")
            .collect();
        assert_eq!(unreadable.len(), 3);
        assert_eq!(
            lines
                .iter()
                .filter(|r| r["stage"] == "credential_file_cap_refusal")
                .count(),
            1
        );
        for line in unreadable {
            assert_eq!(line["schema_version"], 2);
            assert_eq!(line["source"], "unknown");
            assert_eq!(
                line["counts"],
                serde_json::json!({"connection_binding_unreadable": 1})
            );
            let text = line.to_string();
            assert!(!text.contains("/private") && !text.contains("synthetic.invalid"));
        }
    }

    #[test]
    fn typed_credential_cap_errors_use_existing_carrier_and_preserve_result() {
        use ottto_core::{CredentialFileCapRefused, FileDeviceStore, TokenStoreError};
        CREDENTIAL_FILE_CAP_REFUSED.with(|counts| counts.iter().for_each(|n| n.store(0, Relaxed)));
        let path = std::env::temp_dir().join(format!("credential-carrier-{}", std::process::id()));
        std::fs::write(&path, vec![b' '; 64 * 1024 + 1]).unwrap();
        let store = FileDeviceStore::new(&path);
        let (_, lines) = capture(|| {
            let error = credential_file_read(store.load()).unwrap_err();
            assert!(format!("{error:#}").contains("exceeds 64 KiB"));
            assert!(credential_file_read(store.load_with_credential_generation()).is_err());
            assert!(
                credential_file_read(ottto_core::FileConnectionStore::new(&path).load()).is_err()
            );
            assert!(credential_file_read(
                ottto_core::FilePendingDeviceCredentialStore::new(&path).load()
            )
            .is_err());
            // The core secret store preserves this typed variant across its API.
            let secret: anyhow::Result<()> = Err(TokenStoreError::OversizeRefused.into());
            assert!(credential_file_read(secret)
                .unwrap_err()
                .is::<TokenStoreError>());
            // Growth refusals carry the same typed inner error through io::Error.
            let growth: anyhow::Result<()> = Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                CredentialFileCapRefused::FileSecret,
            )
            .into());
            assert!(credential_file_read(growth).is_err());
            assert_eq!(credential_file_read(Ok(7)).unwrap(), 7);
            let other: anyhow::Result<()> = Err(anyhow::anyhow!("ordinary read failure"));
            assert!(credential_file_read(other).is_err());
        });
        std::fs::remove_file(path).unwrap();
        assert_eq!(lines.len(), 6);
        for (i, line) in lines.iter().enumerate() {
            assert_eq!(line["schema_version"], 2);
            assert_eq!(line["stage"], "credential_file_cap_refusal");
            assert_eq!(line["source"], "unknown");
            assert_eq!(
                line["counts"]["file_kind"],
                match i {
                    0 | 1 => "device_binding",
                    2 => "connection_binding",
                    3 => "pending_device_credential",
                    _ => "file_secret",
                }
            );
            assert_eq!(line["counts"]["credential_file_cap_refused"], 1);
            assert_eq!(
                line["counts"]["credential_file_cap_refused_total"],
                match i {
                    0 | 2 | 3 | 4 => 1,
                    _ => 2,
                }
            );
            assert_eq!(line["counts"].as_object().unwrap().len(), 3);
        }
    }

    #[test]
    fn history_proof_correction_deferral_is_counted() {
        let ((), lines) = capture(|| {
            claude_history_proof_correction_deferred(2);
            claude_history_proof_correction_deferred(3);
        });
        assert_eq!(lines.len(), 2);
        assert_eq!(
            lines[0]["stage"],
            "claude_history_proof_correction_deferred"
        );
        assert_eq!(lines[1]["counts"]["history_proof_correction_deferred"], 3);
        let first = lines[0]["counts"]["history_proof_correction_deferred_total"]
            .as_u64()
            .unwrap();
        let second = lines[1]["counts"]["history_proof_correction_deferred_total"]
            .as_u64()
            .unwrap();
        assert!(first >= 2 && second >= first + 3, "{first} {second}");
    }
    #[test]
    fn family_closure_root_absent_exclusion_is_counted() {
        let ((), lines) = capture(|| {
            claude_reemission_family_closure_root_absent_excluded(1);
            claude_reemission_family_closure_root_absent_excluded(2);
        });
        assert_eq!(lines.len(), 2);
        assert_eq!(
            lines[0]["stage"],
            "claude_reemission_family_closure_root_absent_excluded"
        );
        assert_eq!(
            lines[1]["counts"]["claude_reemission_family_closure_root_absent_excluded"],
            2
        );
        let first = lines[0]["counts"]
            ["claude_reemission_family_closure_root_absent_excluded_total"]
            .as_u64()
            .unwrap();
        let second = lines[1]["counts"]
            ["claude_reemission_family_closure_root_absent_excluded_total"]
            .as_u64()
            .unwrap();
        assert!(first >= 1 && second >= first + 2, "{first} {second}");
    }
    fn max_read_counts() -> ReadCounts {
        let gate = AssessedBool {
            assessed: usize::MAX,
            matched: usize::MAX,
        };
        ReadCounts {
            full_selections: (usize::MAX / 11) * 11,
            tail_selections: usize::MAX,
            unchanged_selections: usize::MAX,
            completed_native_bytes: u64::MAX,
            completed_guard_bytes: u64::MAX,
            acquisition_admission: AcquisitionAdmission {
                attempts: usize::MAX,
                cache_lookup_miss_unknown_origin: usize::MAX,
                retained_entry: gate,
                owning_header_current: gate,
                state_census_complete: gate,
                sidecar_census_complete: gate,
                reduction_dependencies_available: gate,
                index_entry_present: gate,
                audit_metadata_supported: gate,
                protected_history: gate,
                forced_family: gate,
                comparison_target: gate,
                parent_proof_required: gate,
                audit_debt_present: gate,
                audit_slot_available: gate,
                sampling_allowed: gate,
                retained_entry_rejected_by_eligibility: usize::MAX,
                prepare_started: usize::MAX,
                prepare_failed: usize::MAX,
            },
            page_events: PageEvents {
                full_cause: Default::default(),
                full_reasons: FullReasons([usize::MAX / 11; 11]),
                priority_full_replays: usize::MAX,
                audits_started: usize::MAX,
                audits_completed: usize::MAX,
                max_start_overdue_seconds: u64::MAX,
                max_completion_overdue_seconds: u64::MAX,
            },
            index_state_at_page_end: IndexState {
                audit_quiet_retired: usize::MAX,
                audit_cap_full: usize::MAX,
                pending_audits: usize::MAX,
                overdue_audits: usize::MAX,
                oldest_due_age_seconds: u64::MAX,
            },
            codex_cursor: Some(Box::new(max_codex_cursor_counts())),
        }
    }

    fn max_codex_cursor_counts() -> CodexCursorCounts {
        let m = u32::MAX;
        CodexCursorCounts {
            during_scan_window: CodexCursorEvents {
                jobs_started: m,
                jobs_paused: m,
                jobs_resumed: m,
                jobs_certified: m,
                jobs_uncertified: m,
                jobs_invalidated: m,
                jobs_member_changed: m,
                jobs_state_bound: m,
                jobs_lost: m,
                jobs_deferred_inputs: m,
                jobs_start_unstartable: m,
                jobs_audit_restarted: m,
                jobs_finish_failed: m,
                jobs_frame_returned: m,
                deferred: m,
                deferred_rotation: m,
                deferred_next_generation: m,
                namespace_busy: m,
                cursor_disabled_unsupported_layout: m,
                audit_overdue: m,
                sealed_fragment_withheld: m,
                eof_record_applied: m,
                jobs_unavailable_ended: m,
                memo_hits: m,
                memo_records: m,
                parked_hits: m,
            },
            retained: CodexCursorRetained {
                paused_job: true,
                paused_job_charged_bytes: m,
                memo_entries: m,
                parked_entries: m,
                invalidation_entries: m,
                rotation_waiters: m,
                lifetime_audit_overdue_max_age_seconds: m,
            },
        }
    }

    fn assert_finish_record(record: &serde_json::Value, source: &str) {
        assert_eq!(record["schema_version"], SCHEMA_VERSION);
        assert_eq!(record["stage"], "source_finish");
        assert_eq!(record["source"], source);
        assert_eq!(record["counts"], serde_json::json!({}));
        assert!(record.get("result").is_none());
        println!("RESOURCE_V2_FINISH_FIXTURE {record}");
    }

    #[test]
    fn native_comparison_decision_distinguishes_unreached_saved_and_retained() {
        use crate::snapshots::claude_native_comparison::lifecycle::{Lifecycle, Scope};
        let owner = std::sync::Arc::new(Lifecycle::default());
        let (_, rows) = capture(|| {
            let mut abandoned = owner.begin();
            abandoned.bind_scope(Scope::from_arguments(format_args!(
                "private-synthetic-scope"
            )));
            drop(abandoned);
            // Logical lifecycle fixture: the native conjunction is supplied to
            // the existing settlement seam, not a supported native-path claim.
            let mut saved = owner.begin();
            saved.bind_scope(Scope::from_arguments(format_args!(
                "private-synthetic-scope"
            )));
            saved.note_selected_save(true);
            saved.finish(true);
            let mut retained = owner.begin();
            retained.bind_scope(Scope::from_arguments(format_args!(
                "private-synthetic-scope"
            )));
            assert!(retained.allowed());
            retained.note_selected_save(false);
            retained.finish(true);
        });
        assert_eq!(rows.len(), 3);
        let a = &rows[0]["counts"];
        assert_eq!(a["outcome"], "abandoned");
        assert_eq!(a["allowed_at_bind"], false);
        assert_eq!(a["selected_save"], false);
        assert_eq!(a["retained_permit"], false);
        for unknown in [
            "bootstrap",
            "terminal_rearm",
            "correction_mint",
            "controller_current_at_finish",
            "upload_fully_settled",
        ] {
            assert!(a[unknown].is_null(), "unreached {unknown} is unknown");
        }
        let b = &rows[1]["counts"];
        assert_eq!(b["allowed_at_bind"], false);
        assert_eq!(b["selected_save"], true);
        assert_eq!(b["retained_permit"], true);
        assert_eq!(rows[2]["counts"]["allowed_at_bind"], true);
        for row in rows {
            assert_eq!(row["stage"], "native_comparison_decision");
            assert_eq!(row["counts"]["deferred_decisions"], 0);
            assert_eq!(row["observation"]["wall_elapsed_us"], 0);
            assert!(row["observation"]["shared_process_cpu_delta_us"].is_null());
            let text = serde_json::to_string(&row).unwrap();
            assert!(!text.contains("private-synthetic-scope"));
        }
    }

    #[test]
    fn native_comparison_decision_maximum_width_is_bounded() {
        let diagnostic = NativeDecision::new();
        diagnostic.update(|d| {
            *d = NativeComparisonDecision {
                layout_supported: true,
                lease_generation: Some(u64::MAX),
                fold_index_generation: Some(u64::MAX),
                allowed_at_bind: Some(false),
                controller_created: false,
                controller_current_at_finish: Some(false),
                bootstrap: Some(NativeBootstrap {
                    native_census_complete: false,
                    coverage_complete: false,
                    census_valid: false,
                    fence_open: false,
                    pending_occurrences_present: false,
                    transcript_ownership_complete: false,
                    scan_census_complete: false,
                    not_withheld: false,
                }),
                selected_save: false,
                upload_fully_settled: Some(false),
                clean_at_finish: Some(false),
                retained_permit: Some(false),
                revoke_calls: usize::MAX,
                admission_refusal_calls: usize::MAX,
                hit_policy_calls: usize::MAX,
                deferred_decisions: usize::MAX,
                latched_base_decisions: usize::MAX,
                other_base_decisions: usize::MAX,
                terminal_rearm: Some(NativeRearm {
                    negative_keys: usize::MAX,
                    proof_candidates: usize::MAX,
                    suppressed: usize::MAX,
                    other_rearm_matches: usize::MAX,
                    clear_calls: usize::MAX,
                }),
                correction_mint: Some(NativeMint {
                    window_available: false,
                    candidates: usize::MAX,
                    insertions: usize::MAX,
                    receipts_after_mint: usize::MAX,
                }),
                outcome: NativeDecisionOutcome::DisabledBeforeLease,
            }
        });
        let (_, rows) = capture(|| diagnostic.emit());
        assert_eq!(rows.len(), 1);
        let text = serde_json::to_string(&rows[0]).unwrap();
        assert!(text.len() < 4096);
        println!("NATIVE_COMPARISON_DECISION_MAX_WIDTH bytes={} inline_bytes={} no_resource_samples=true", text.len(), std::mem::size_of::<NativeDecision>());
    }

    #[test]
    fn census_fence_events_have_closed_fields_and_bounded_encoding() {
        use crate::codex_scan_diagnostics::{
            CensusFenceOutcome as O, CensusFencePhase as P, CensusInvalidation as I,
        };
        let (_, rows) = capture(|| {
            for phase in [P::Outer, P::Inner] {
                for outcome in [
                    O::Passed,
                    O::Rejected,
                    O::Published,
                    O::ProjectionUnavailable,
                    O::ClockUnavailable,
                    O::EncodingFailed,
                    O::PrivateWriteFailed,
                ] {
                    for invalidation in [I::NotAttempted, I::Removed, I::AlreadyMissing, I::Failed]
                    {
                        codex_census_fence(phase, outcome, invalidation);
                    }
                }
            }
        });
        assert_eq!(rows.len(), 56);
        for row in rows {
            assert_eq!(row["stage"], "codex_census_fence");
            assert_eq!(row["source"], "codex");
            assert_eq!(row["observation"]["wall_elapsed_us"], 0);
            assert!(row["observation"]["shared_process_cpu_delta_us"].is_null());
            assert!(row["observation"]["process_lifetime_max_rss_bytes"].is_null());
            assert_eq!(row["counts"].as_object().unwrap().len(), 3);
            let text = serde_json::to_string(&row).unwrap();
            assert!(text.len() < 1024);
            for forbidden in [
                "namespace",
                "account",
                "path",
                "digest",
                "credential",
                "error",
            ] {
                assert!(!text.contains(forbidden));
            }
        }
    }

    #[test]
    fn footprint_fields_are_stage_only_for_all_native_sources() {
        for source in ["claude_code", "codex", "pi"] {
            let (result, records) = capture(|| {
                source_prepare(source, || {
                    source_finish(source, || Ok::<_, anyhow::Error>(17))
                })
            });
            assert_eq!(result.unwrap(), 17);
            assert_eq!(records.len(), 2);
            assert_eq!(records[0]["stage"], "source_finish");
            assert_eq!(records[1]["stage"], "source_prepare");
            for record in records {
                assert_eq!(record["source"], source);
                assert!(record["observation"]["footprint_sample_failures"].is_u64());
                let row = &record["observation"];
                if let Some(peak) = row["stage_peak_footprint_bytes"].as_u64() {
                    for endpoint in ["stage_start_footprint_bytes", "stage_end_footprint_bytes"] {
                        if let Some(bytes) = row[endpoint].as_u64() {
                            assert!(peak >= bytes);
                        }
                    }
                    assert!(row["footprint_samples"].as_u64().unwrap() >= 1);
                }
            }
        }
        let (_, records) = capture(|| {
            drop(UploadCall::start("codex"));
            traversal_point("synthetic", "pi", &BTreeMap::<&str, u64>::new());
        });
        let page = serde_json::to_value(Probe::start().observation()).unwrap();
        for row in records.iter().map(|r| &r["observation"]).chain([&page]) {
            for field in [
                "stage_peak_footprint_bytes",
                "stage_start_footprint_bytes",
                "stage_end_footprint_bytes",
                "footprint_samples",
                "footprint_sample_failures",
            ] {
                assert!(row.get(field).is_none());
            }
        }
    }

    #[test]
    fn resource_finish_success_preserves_value_and_contains_batch_window() {
        let value = Box::new(17);
        let original = std::ptr::from_ref(value.as_ref());
        let (result, records) = capture(|| {
            source_finish("claude_code", || {
                let mut upload = UploadCall::start("claude_code");
                upload.serialized(20);
                upload.attempt(20, false);
                Ok(value)
            })
        });
        assert_eq!(std::ptr::from_ref(result.unwrap().as_ref()), original);
        assert_eq!(records.len(), 2);
        assert_eq!(records[0]["stage"], "snapshot_batch_call");
        assert_finish_record(&records[1], "claude_code");
        let batch = &records[0]["observation"];
        let finish = &records[1]["observation"];
        assert!(
            batch["wall_elapsed_us"].as_u64().unwrap()
                <= finish["wall_elapsed_us"].as_u64().unwrap()
        );
        // Unix timestamps are millisecond-granular; the monotonic span comparison
        // above remains valid independently of wall-clock resolution.
        assert!(
            batch["observed_unix_ms"].as_u64().unwrap()
                <= finish["observed_unix_ms"].as_u64().unwrap()
        );
    }

    #[test]
    fn resource_finish_error_preserves_typed_error_and_chain() {
        #[derive(Debug)]
        struct OriginalError(std::sync::Arc<()>);
        impl std::fmt::Display for OriginalError {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("synthetic inner failure")
            }
        }
        impl std::error::Error for OriginalError {}
        let identity = std::sync::Arc::new(());
        let error =
            anyhow::Error::new(OriginalError(identity.clone())).context("synthetic context");
        let original_chain: Vec<_> = error.chain().map(ToString::to_string).collect();
        let (result, records) = capture(|| source_finish::<()>("codex", || Err(error)));
        let returned = result.unwrap_err();
        assert_eq!(
            returned
                .chain()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
            original_chain
        );
        assert!(std::sync::Arc::ptr_eq(
            &returned.downcast_ref::<OriginalError>().unwrap().0,
            &identity
        ));
        assert_eq!(records.len(), 1);
        assert_finish_record(&records[0], "codex");
    }

    #[test]
    fn resource_finish_panic_preserves_payload_without_record() {
        let payload = std::sync::Arc::new("synthetic panic");
        let original = payload.clone();
        let (result, records) = capture(|| {
            std::panic::catch_unwind(|| {
                source_finish::<()>("pi", || std::panic::panic_any(payload))
            })
        });
        let panic = result.unwrap_err();
        assert!(std::sync::Arc::ptr_eq(
            panic.downcast_ref::<std::sync::Arc<&str>>().unwrap(),
            &original
        ));
        assert!(records.is_empty());
    }

    #[test]
    fn claude_page_events_use_existing_carriers_without_source_leakage() {
        let (_, rows) = capture(|| {
            let scope = claude_reread::Scope::begin(true);
            claude_reread::clear(claude_reread::ClearSite::OwnedStart, true);
            cache_lifecycle::record(cache_lifecycle::Event::TakeHit);
            let mut probe = Probe::start();
            probe.page_events.merge(scope.finish());
            probe.collection(
                "claude_code",
                CollectionCounts {
                    scanned_files: 1,
                    semantic_noops: 0,
                    sampled_acquisition: None,
                    full_causes: Default::default(),
                },
            );
            probe.collection(
                "codex",
                CollectionCounts {
                    scanned_files: 0,
                    semantic_noops: 0,
                    sampled_acquisition: None,
                    full_causes: Default::default(),
                },
            );
            let scope = claude_reread::Scope::begin(true);
            claude_reread::restored(true, false, true);
            NativeDecision::new().emit();
            drop(scope);
        });
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0]["source"], "claude_code");
        assert_eq!(rows[0]["counts"]["claude_reread"]["owned_start_cleared"], 1);
        assert_eq!(
            rows[0]["counts"]["retained_cache_page_events"]["take_hit"],
            1
        );
        assert!(rows[1]["counts"].get("claude_reread").is_none());
        assert!(rows[1]["counts"]
            .get("retained_cache_page_events")
            .is_none());
        assert_eq!(rows[2]["stage"], "native_comparison_decision");
        assert_eq!(
            rows[2]["counts"]["claude_reread"]["restored_empty_sibling"],
            1
        );
        for row in rows {
            assert_eq!(row["schema_version"], 2);
            assert!(serde_json::to_string(&row).unwrap().len() < 4096);
        }
    }

    #[test]
    fn terminal_rearm_counts_use_page_carrier_once_and_do_not_drain_other_producers() {
        let (_, rows) = capture(|| {
            let scope = claude_reread::Scope::begin(true);
            claude_record_cap_half_file();
            claude_reread::clear(claude_reread::ClearSite::OwnedStart, true);
            claude_reread::terminal_rearm(
                claude_reread::IgnoredVeto::WithheldAccount.bit(),
                7,
                false,
            );
            claude_reread::terminal_rearm(0, 0, true);
            // Zero deltas never manufacture a scheduling row.
            claude_reread::terminal_rearm(0, 99, false);
            NativeDecision::new().emit();
            let counts = scope.finish();
            assert_eq!(counts.rearm_structural_native_duplicate, 1);
            assert_eq!(counts.rearm_fingerprints_preserved, 7);
            // The ordinary page still owns its cap observation. It must not
            // repeat terminal counters from the parent scope or kept counts.
            let mut probe = Probe::start();
            probe.page_events = counts;
            probe.collection(
                "claude_code",
                CollectionCounts {
                    scanned_files: 1,
                    semantic_noops: 0,
                    sampled_acquisition: None,
                    full_causes: Default::default(),
                },
            );
            // Disabled comparison must omit these fields too.
            claude_reread::emit_without_lease(counts);
        });
        assert_eq!(rows.len(), 5);
        for row in &rows[..2] {
            assert_eq!(row["stage"], "native_collection_page");
            assert_eq!(row["source"], "claude_code");
            assert_eq!(row["schema_version"], 2);
            assert_eq!(row["counts"]["scanned_files"], 0);
            assert_eq!(row["counts"]["semantic_noops"], 0);
            assert!(row["counts"]
                .get("claude_money_record_cap_half_files")
                .is_none());
        }
        assert_eq!(
            rows[0]["counts"]["rearm_veto_ignored"],
            serde_json::json!({"withheld_account": 1})
        );
        assert_eq!(rows[0]["counts"]["rearm_fingerprints_preserved"], 7);
        assert_eq!(rows[1]["counts"]["rearm_structural_native_duplicate"], 1);
        assert_eq!(rows[2]["stage"], "native_comparison_decision");
        assert_eq!(rows[2]["counts"]["claude_reread"]["owned_start_cleared"], 1);
        assert_eq!(rows[3]["counts"]["claude_money_record_cap_half_files"], 1);
        assert_eq!(rows[4]["stage"], "native_comparison_decision");
        for row in &rows[2..] {
            for key in [
                "rearm_veto_ignored",
                "rearm_fingerprints_preserved",
                "rearm_structural_native_duplicate",
            ] {
                assert!(
                    row["counts"].get(key).is_none(),
                    "terminal delta repeated: {row}"
                );
            }
        }
    }

    #[test]
    fn pi_cost_observations_update_registry_without_emitting_records() {
        let (((), counts), rows) = capture(|| {
            cache_lifecycle::observe(|| {
                pi_cost_observations(0, 0);
                pi_cost_observations(2, 3);
            })
        });
        assert_eq!(counts.pi_cost_refused_overflow, 2);
        assert_eq!(counts.pi_cost_precision_rounded, 3);
        assert!(rows.is_empty());
    }

    #[test]
    fn cache_lifecycle_record_is_bounded_and_explicitly_process_global() {
        let (_, records) = capture(|| {
            traversal_point(
                "process_retained_cache_lifecycle_totals",
                "unknown",
                &cache_lifecycle::Counts::maximum(),
            );
        });
        assert_eq!(records.len(), 1);
        let record = &records[0];
        assert_eq!(record["stage"], "process_retained_cache_lifecycle_totals");
        assert_eq!(record["source"], "unknown");
        assert_eq!(record["counts"]["take_poisoned_lock"], u64::MAX);
        assert!(record["observation"]["shared_process_cpu_delta_us"].is_null());
        assert!(record["observation"]["process_lifetime_max_rss_bytes"].is_null());
        // The two Pi observation fields add 97 bytes at u64::MAX.
        assert!(serde_json::to_string(record).unwrap().len() < 2304);
        let (_, actual) = capture(cache_lifecycle_totals);
        assert_eq!(actual.len(), 1);
        assert_eq!(actual[0]["stage"], record["stage"]);
    }

    #[test]
    fn codex_memo_lifecycle_record_is_bounded_and_explicitly_process_global() {
        let (_, records) = capture(|| {
            traversal_point(
                "process_codex_memo_lifecycle_totals",
                "codex",
                &codex_memo_lifecycle::Record::maximum(),
            );
        });
        assert_eq!(records.len(), 1);
        let record = &records[0];
        assert_eq!(record["stage"], "process_codex_memo_lifecycle_totals");
        assert_eq!(record["source"], "codex");
        assert_eq!(
            record["counts"]["memo_hit_estimated_avoided_parser_bytes"],
            u64::MAX
        );
        assert_eq!(record["counts"]["memo_miss_exact_stamp_bytes"], u64::MAX);
        assert_eq!(record["counts"]["memo_resident_bytes"], u64::MAX);
        assert!(record["observation"]["shared_process_cpu_delta_us"].is_null());
        assert!(record["observation"]["process_lifetime_max_rss_bytes"].is_null());
        let width = serde_json::to_string(record).unwrap().len();
        println!("CODEX_MEMO_LIFECYCLE_MAX_WIDTH bytes={width}");
        assert!(width < 2048);
        let (_, actual) = capture(|| codex_memo_lifecycle_totals("codex"));
        assert_eq!(actual.len(), 1);
        assert_eq!(actual[0]["stage"], record["stage"]);
        let (_, none) = capture(|| codex_memo_lifecycle_totals("claude_code"));
        assert!(none.is_empty());
    }

    #[test]
    fn codex_side_lifecycle_record_is_bounded_and_explicitly_process_global() {
        let (_, records) = capture(|| {
            traversal_point(
                "process_codex_side_lifecycle_totals",
                "codex",
                &codex_side_lifecycle::Record::maximum(),
            );
        });
        assert_eq!(records.len(), 1);
        let record = &records[0];
        assert_eq!(record["stage"], "process_codex_side_lifecycle_totals");
        assert_eq!(record["source"], "codex");
        let keys: Vec<_> = record["counts"]
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        // Option B: exactly ten lifetime totals and five last-measured gauges.
        assert_eq!(
            keys,
            [
                "side_ledger_entries",
                "side_ledger_evictions",
                "side_not_due",
                "side_proof_drops",
                "side_proof_release_drops",
                "side_reads_ended",
                "side_reads_started",
                "side_record_bytes",
                "side_records",
                "side_records_written",
                "side_refusals",
                "side_request_bytes",
                "side_requests",
                "side_requests_rearmed",
                "side_requests_tombstoned",
            ]
        );
        assert!(record["counts"]
            .as_object()
            .unwrap()
            .values()
            .all(|value| *value == u64::MAX));
        assert!(record["observation"]["shared_process_cpu_delta_us"].is_null());
        assert!(record["observation"]["process_lifetime_max_rss_bytes"].is_null());
        let width = serde_json::to_string(record).unwrap().len();
        println!("CODEX_SIDE_LIFECYCLE_MAX_WIDTH bytes={width}");
        assert!(width < 2048);
        let (_, actual) = capture(|| codex_side_lifecycle_totals("codex"));
        assert_eq!(actual.len(), 1);
        assert_eq!(actual[0]["stage"], record["stage"]);
        let (_, none) = capture(|| codex_side_lifecycle_totals("claude_code"));
        assert!(none.is_empty());
    }

    #[test]
    fn side_read_lines_are_one_start_and_at_most_one_end_per_read() {
        use codex_side_lifecycle::{observe, SideReadGuard};
        let ((_, lines), counts) = observe(|| {
            capture(|| {
                SideReadGuard::start(3).end();
                drop(SideReadGuard::start(7));
            })
        });
        assert_eq!(counts.side_reads_started, 2);
        assert_eq!(counts.side_reads_ended, 2);
        let stages: Vec<_> = lines.iter().map(|line| line["stage"].clone()).collect();
        assert_eq!(
            stages,
            [
                "side_read_start",
                "side_read_end",
                "side_read_start",
                "side_read_end"
            ]
        );
        assert_eq!(lines[0]["counts"]["attempts"], 3);
        assert_eq!(lines[0]["counts"]["pseq"], lines[1]["counts"]["pseq"]);
        assert!(lines[1]["counts"].get("abandoned").is_none());
        assert_eq!(lines[2]["counts"]["pseq"], lines[3]["counts"]["pseq"]);
        assert_ne!(lines[0]["counts"]["pseq"], lines[2]["counts"]["pseq"]);
        assert_eq!(lines[3]["counts"]["abandoned"], true);
        for line in &lines {
            assert_eq!(line["source"], "codex");
            assert!(line["process_id"].is_u64());
            assert!(serde_json::to_string(line).unwrap().len() < 2048);
        }
    }

    #[test]
    fn resource_log_sink_failure_does_not_escape() {
        struct FailedSink;
        impl Write for FailedSink {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "synthetic",
                ))
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        write_line("{}", &mut FailedSink);
    }

    #[test]
    #[ignore = "bounded native measurement; process allocation scope needs serial isolation"]
    fn measure_local_resource_probe_overhead() {
        const ITERATIONS: u64 = 1000;
        for stage in ["native_collection_page", "source_finish"] {
            let process_before = process_sample();
            let wall = Instant::now();
            let (_, allocation) = crate::retry_allocation_probe::measure_process(|| {
                for _ in 0..ITERATIONS {
                    if stage == "source_finish" {
                        source_finish("claude_code", || Ok(())).unwrap();
                    } else {
                        Probe::start().collection(
                            "claude_code",
                            CollectionCounts {
                                scanned_files: usize::MAX,
                                semantic_noops: usize::MAX,
                                sampled_acquisition: Some(max_read_counts()),
                                full_causes: Default::default(),
                            },
                        );
                    }
                }
            });
            let wall_us = wall.elapsed().as_micros();
            let cpu_us = Observation::between(0, process_before, process_sample())
                .shared_process_cpu_delta_us;
            println!(
                "RESOURCE_PROBE_OVERHEAD {}",
                serde_json::json!({
                    "stage": stage, "iterations": ITERATIONS, "wall_us": wall_us,
                    "wall_us_per_record": wall_us as f64 / ITERATIONS as f64,
                    "shared_process_cpu_us": cpu_us,
                    "shared_process_cpu_us_per_record": cpu_us.map(|cpu| cpu as f64 / ITERATIONS as f64),
                    "probe_inline_bytes": std::mem::size_of::<Probe>(),
                    "upload_call_inline_bytes": std::mem::size_of::<UploadCall>(),
                    "scope_requested_allocation_peak_bytes": allocation.requested_peak,
                    "scope_requested_allocation_live_bytes": allocation.requested_live,
                    "includes_two_os_samples_json_encoding_and_existing_stderr_write": true,
                })
            );
        }
    }

    #[test]
    fn resource_unavailable_or_regressing_cpu_is_unknown_not_zero() {
        let sample = |cpu_us| {
            Some(ProcessSample {
                cpu_us,
                lifetime_max_rss_bytes: 4096,
            })
        };
        for (before, after) in [
            (None, sample(9)),
            (sample(10), None),
            (sample(10), sample(9)),
        ] {
            assert_eq!(
                Observation::between(12, before, after).shared_process_cpu_delta_us,
                None
            );
        }
        let result = Observation::between(12, sample(10), sample(17));
        assert_eq!(result.shared_process_cpu_delta_us, Some(7));
        assert_eq!(result.process_lifetime_max_rss_bytes, Some(4096));
        assert_eq!(result.process_lifetime_max_rss_before_bytes, Some(4096));
        for (before, after) in [
            (None, sample(9)),
            (sample(10), None),
            (
                sample(10),
                Some(ProcessSample {
                    cpu_us: 17,
                    lifetime_max_rss_bytes: 2048,
                }),
            ),
        ] {
            let record = serde_json::to_value(Observation::between(12, before, after)).unwrap();
            assert!(record["process_lifetime_max_rss_before_bytes"].is_null());
        }
        let rising = Observation::between(
            12,
            sample(10),
            Some(ProcessSample {
                cpu_us: 17,
                lifetime_max_rss_bytes: 8192,
            }),
        );
        assert_eq!(rising.process_lifetime_max_rss_before_bytes, Some(4096));
        assert_eq!(rising.process_lifetime_max_rss_bytes, Some(8192));
    }
    #[test]
    fn resource_attempts_count_fallback_and_presend_refusal_without_content() {
        let (_, records) = capture(|| {
            Probe::start().collection(
                "secret/path/provider",
                CollectionCounts {
                    scanned_files: usize::MAX,
                    semantic_noops: usize::MAX,
                    sampled_acquisition: Some(max_read_counts()),
                    full_causes: Default::default(),
                },
            );
            source_finish("secret/path/provider", || Ok(())).unwrap();
            let mut upload = UploadCall::start("secret/path/provider");
            upload.serialized(1000);
            upload.attempt(100, true);
            upload.attempt(1000, false);
            let mut refused = UploadCall::start("codex");
            refused.serialized(500);
        });
        assert_eq!(records[2]["counts"]["identity_attempts"], 0);
        assert_eq!(records[2]["counts"]["attempted_encoded_body_bytes"], 0);
        assert_eq!(records[3]["counts"]["gzip_attempts"], 1);
        assert_eq!(records[3]["counts"]["identity_attempts"], 1);
        assert_eq!(records[3]["counts"]["attempted_encoded_body_bytes"], 1100);
        assert_eq!(records[3]["counts"]["attempted_decoded_body_bytes"], 2000);
        assert_eq!(records[3]["source"], "unknown");
        // The cursor block: a window of shared process deltas plus gauges;
        // an unobtainable snapshot is `null`, never zeros.
        let cursor = &records[0]["counts"]["sampled_acquisition"]["codex_cursor"];
        assert_eq!(cursor["during_scan_window"]["jobs_started"], u32::MAX);
        assert_eq!(
            cursor["retained"]["lifetime_audit_overdue_max_age_seconds"],
            u32::MAX
        );
        let unavailable = ReadCounts {
            codex_cursor: None,
            ..max_read_counts()
        };
        assert!(serde_json::to_value(&unavailable).unwrap()["codex_cursor"].is_null());
        let idle = serde_json::to_value(CodexCursorCounts::default()).unwrap();
        assert_eq!(
            idle,
            serde_json::json!({"during_scan_window": {}, "retained": {}})
        );
        for record in records {
            let text = serde_json::to_string(&record).unwrap();
            // Fixed page gate totals extend this local diagnostic record only;
            // upload/finish records and all runtime resource caps stay unchanged.
            let limit = if record["stage"] == "native_collection_page" {
                4096
            } else {
                2048
            };
            assert!(text.len() < limit);
            assert!(!text.contains("secret/path"));
            assert!(!text.contains("cycle_peak"));
            assert_eq!(record["schema_version"], SCHEMA_VERSION);
        }
    }
}
#[cfg(test)]
mod continuation_tests {
    #[test]
    fn continuation_mint_counts_have_closed_fixed_keys() {
        let outcomes = [
            "minted",
            "inventory_incomplete",
            "groups_completed",
            "no_remaining",
            "over_bound",
        ];
        let (_, rows) = super::capture(|| {
            for outcome in outcomes {
                super::codex_continuation_mint(outcome);
            }
        });
        assert_eq!(rows.len(), outcomes.len());
        for (row, outcome) in rows.iter().zip(outcomes) {
            assert_eq!(row["stage"], "codex_continuation_mint");
            assert_eq!(row["schema_version"], 2);
            assert_eq!(row["source"], "codex");
            assert_eq!(
                row["counts"],
                serde_json::json!({"continuation_mint":{outcome:1}})
            );
        }
    }

    #[test]
    fn continuation_counts_use_fixed_point_schema() {
        let (_, rows) = super::capture(|| {
            super::codex_continuation(None);
            for cause in [
                "roster_changed",
                "context_changed",
                "policy_changed",
                "group_job",
                "other",
            ] {
                super::codex_continuation(Some(cause));
            }
        });
        assert_eq!(rows.len(), 6);
        assert_eq!(rows[0]["counts"]["continuation_pages_run"], 1);
        assert_eq!(
            rows[0]["counts"]["continuation_held"],
            serde_json::json!({})
        );
        for row in rows {
            assert_eq!(row["schema_version"], 2);
            assert_eq!(row["source"], "codex");
            assert_eq!(row["stage"], "codex_continuation");
            assert!(row["observation"]["shared_process_cpu_delta_us"].is_null());
            assert_eq!(row["counts"].as_object().unwrap().len(), 2);
            assert!(
                row["counts"]["continuation_held"]
                    .as_object()
                    .unwrap()
                    .len()
                    <= 1
            );
        }
    }
}

/// Fixed low-cardinality storage observations on the existing #799 envelope.
pub(crate) fn scan_index_storage(
    source: &'static str,
    orphans: u64,
    reserved: u64,
    unavailable: [[u64; 6]; 3],
) {
    #[cfg(test)]
    SCAN_INDEX_STORAGE_OBSERVATIONS.with(|v| v.borrow_mut().push((orphans, unavailable, reserved)));

    static TOTAL_ORPHANS: AtomicU64 = AtomicU64::new(0);
    static ROOT_MISSING_RESERVED_ONLY: AtomicU64 = AtomicU64::new(0);
    static UNAVAILABLE: [[AtomicU64; 6]; 3] = [const { [const { AtomicU64::new(0) }; 6] }; 3];
    let add = |counter: &AtomicU64, n: u64| {
        counter
            .fetch_update(Relaxed, Relaxed, |v| Some(v.saturating_add(n)))
            .unwrap_or_else(|v| v)
            .saturating_add(n)
    };
    let reserved_total = add(&ROOT_MISSING_RESERVED_ONLY, reserved);
    if reserved != 0 {
        traversal_point(
            "scan_index_storage",
            source,
            &BTreeMap::from([("root_missing_reserved_only", reserved_total)]),
        );
    }
    let total = add(&TOTAL_ORPHANS, orphans);
    for (map, counts) in unavailable.into_iter().enumerate() {
        for (cause, n) in counts.into_iter().enumerate() {
            let count = add(&UNAVAILABLE[map][cause], n);
            if n != 0 {
                traversal_point(
                    "scan_index_storage",
                    source,
                    &serde_json::json!({"index_shard_unavailable": {"map": (["account_pending", "usage_pending", "request_census"][map]), "cause": ([crate::snapshots::scan_index_persistence::UnavailableCause::Missing, crate::snapshots::scan_index_persistence::UnavailableCause::Generation, crate::snapshots::scan_index_persistence::UnavailableCause::Digest, crate::snapshots::scan_index_persistence::UnavailableCause::Decode, crate::snapshots::scan_index_persistence::UnavailableCause::Descriptor, crate::snapshots::scan_index_persistence::UnavailableCause::Unsafe][cause].label()), "count": count}}),
                );
            }
        }
    }
    if orphans != 0 {
        traversal_point(
            "scan_index_storage",
            source,
            &BTreeMap::from([("scanindex_orphan_init_discarded", total)]),
        );
    }
}

#[cfg(test)]
thread_local! {
    static SCAN_INDEX_STORAGE_OBSERVATIONS: std::cell::RefCell<Vec<StorageReadObservation>> = const { std::cell::RefCell::new(Vec::new()) };
}
#[cfg(test)]
pub(crate) fn take_scan_index_storage_observations() -> Vec<StorageReadObservation> {
    SCAN_INDEX_STORAGE_OBSERVATIONS.with(|v| std::mem::take(&mut *v.borrow_mut()))
}

#[cfg(test)]
type StorageReadObservation = (u64, [[u64; 6]; 3], u64);

/// One content-free alarm on entry to a shard-unavailable source episode.
pub(crate) fn scan_index_shard_alarm(source: &'static str, unavailable: usize, transitions: u64) {
    traversal_point(
        "scan_index_storage",
        source,
        &serde_json::json!({
            "index_shard_unavailable_alarm": 1,
            "unavailable_maps": unavailable,
            "blocked_sources": 1,
            "transitions": transitions,
        }),
    );
}
pub(crate) fn scan_index_manifest_refused(source: &'static str) {
    static TOTAL: AtomicU64 = AtomicU64::new(0);
    let count = TOTAL
        .fetch_update(Relaxed, Relaxed, |v| Some(v.saturating_add(1)))
        .unwrap_or_else(|v| v)
        .saturating_add(1);
    traversal_point(
        "scan_index_storage",
        source,
        &serde_json::json!({
            "scanindex_manifest_unavailable_refused": count,
        }),
    );
}

/// Per-refused-load counter, independent of the repair blocker's episode alarm.
/// Only fixed causes and numeric counts; never include the originating error.
pub(crate) fn scan_index_repair_required(
    source: &str,
    cause: crate::snapshots::scan_index_health::RepairCause,
) {
    static TOTALS: [AtomicU64; 2] = [const { AtomicU64::new(0) }; 2];
    let count = TOTALS[cause as usize]
        .fetch_update(Relaxed, Relaxed, |v| Some(v.saturating_add(1)))
        .unwrap_or_else(|v| v)
        .saturating_add(1);
    traversal_point(
        "scan_index_storage",
        source,
        &serde_json::json!({
            "scan_index_repair_required": {
                "cause": cause.label(), "delta": 1, "count": count,
            },
        }),
    );
}
