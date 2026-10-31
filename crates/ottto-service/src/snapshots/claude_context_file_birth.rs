//! Claude Code context scalars from the transcript file itself (design E).
//!
//! A ROOT transcript record whose timestamp is more than 60 s before the
//! file's birth was written before the file existed, so it was copied in
//! (Desktop Rewind, `--fork-session` or resume copy, a restored file). Copies
//! keep the original timestamps, so the file proves this alone: no census,
//! no other file and no seen-list. The tag is context-only. A tagged record
//! keeps its usage, cost, request identity and account handling exactly as
//! before; only its context size and compaction boundary leave the session's
//! first/peak/last and compaction count. Subagent transcripts are exempt.
//!
//! Telemetry never fills a number. Where this page loaded API or trace rows,
//! they only veto: a kept request reported under another root, or a tagged
//! request reported under this root, withholds that session's scalars.
//!
//! Everything here is local. Nothing is uploaded except the existing scalar
//! fields and the content-free local counters; the content-free scalars are
//! persisted only in the local durable-tail store (M1).
use super::*;
use std::hash::{Hash, Hasher};

/// A record this much older than its root file's birth was copied in.
const CLAUDE_COPIED_BY_BIRTH_SLACK_NANOS: i128 = 60 * 1_000_000_000;

/// 2020-01-01T00:00:00Z. Claude Code transcripts are younger, so a reported
/// birth at or before this (0, the epoch, a reset clock) is not a birth: the
/// file counts as unknown birth and withholds.
const CLAUDE_BIRTH_FLOOR_UNIX_NANOS: i128 = 1_577_836_800 * 1_000_000_000;

/// At most this many vetoed files are remembered for the process lifetime.
/// Past it every later admission withholds (fail closed) until restart.
const MAX_REMEMBERED_TRIPWIRE_FILES: usize = 4_096;

/// The telemetry owners lookup doubles its partition count at most this many
/// times when hashes are skewed; past it the page fails closed.
const MAX_TELEMETRY_PARTITION_DOUBLINGS: usize = 4;

/// At most this many Claude Code versions get their own counter row, in
/// first-seen order; the rest share `other`. Keeps the local stats line
/// bounded (SOURCE condition 3: 16 plus `other`).
const MAX_CONTEXT_BASIS_VERSION_KEYS: usize = 16;
const MAX_CONTEXT_BASIS_VERSION_KEY_BYTES: usize = 24;

/// Claude Code versions verified to keep every copied record's original
/// timestamp when they write a copy (`/branch`, `/resume` copy, fork). Only
/// such a writer lets the money birth rule skip pre-birth records; any other
/// or mixed writer counts and discloses them.
pub(in crate::snapshots) const KNOWN_COPY_WRITERS: &[&str] = &["2.1.309", "2.1.310"];

/// Sticky response writer certificate. Zero = no responses, 255 = invalid.
/// A missing/unknown version or two different known writers invalidates it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct ClaudeWriterRun(u8);
crate::durable_tail_codec::durable_struct!(ClaudeWriterRun(N x0: u8));
impl ClaudeWriterRun {
    fn observe(&mut self, version: Option<&str>) {
        let id = version
            .and_then(|v| KNOWN_COPY_WRITERS.iter().position(|k| *k == v))
            .map_or(255, |i| i as u8 + 1);
        self.0 = if self.0 == 0 || self.0 == id { id } else { 255 };
    }
    fn certified(self) -> bool {
        self.0 != 0 && self.0 != 255
    }
}
crate::heap_layout_bound::no_heap!(true; ClaudeWriterRun);

/// Money only: the writer certificate of the lines at or after a cutoff that
/// finalize decides (the EFFECTIVE money birth, earlier than the physical
/// birth after a proven move), not only the physical birth. `others[k]` is
/// the latest line (untimed: `i64::MAX`) NOT written by
/// `KNOWN_COPY_WRITERS[k]`, `latest` the latest line of any writer. Lines at
/// or after T are certified by writer k iff `latest >= T && others[k] < T`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ClaudeOwnWriters {
    latest: i64,
    others: [i64; KNOWN_COPY_WRITERS.len()],
}
crate::durable_tail_codec::durable_struct!(ClaudeOwnWriters {
    N latest: i64,
    N others: [i64; KNOWN_COPY_WRITERS.len()],
});
impl Default for ClaudeOwnWriters {
    fn default() -> Self {
        Self {
            latest: i64::MIN,
            others: [i64::MIN; KNOWN_COPY_WRITERS.len()],
        }
    }
}
impl ClaudeOwnWriters {
    fn clamp(at: i128) -> i64 {
        i64::try_from(at).unwrap_or(if at < 0 { i64::MIN } else { i64::MAX })
    }
    fn observe(&mut self, version: Option<&str>, at: Option<i128>) {
        let at = at.map_or(i64::MAX, Self::clamp);
        self.latest = self.latest.max(at);
        for (other, known) in self.others.iter_mut().zip(KNOWN_COPY_WRITERS) {
            if version != Some(*known) {
                *other = (*other).max(at);
            }
        }
    }
    fn certified_from(self, cutoff: i128) -> bool {
        let cutoff = Self::clamp(cutoff);
        self.latest >= cutoff && self.others.iter().any(|other| *other < cutoff)
    }
}
crate::heap_layout_bound::no_heap!(true; ClaudeOwnWriters);

/// Open-descriptor metadata, also used by the page's one metadata probe per twin.
/// A zero inode means unavailable; no timestamp or file identity is invented.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(in crate::snapshots) struct ClaudeOpenedBirth {
    pub(in crate::snapshots) birth: u64,
    pub(in crate::snapshots) device: u64,
    pub(in crate::snapshots) inode: u64,
    pub(in crate::snapshots) size: u64,
}
crate::durable_tail_codec::durable_struct!(ClaudeOpenedBirth {
    N birth: u64,
    N device: u64,
    N inode: u64,
    N size: u64,
});
impl ClaudeOpenedBirth {
    pub(in crate::snapshots) fn from_metadata(metadata: &fs::Metadata) -> Self {
        let birth = metadata
            .created()
            .ok()
            .and_then(system_time_unix_nanos_i128)
            .filter(|b| *b > CLAUDE_BIRTH_FLOOR_UNIX_NANOS)
            .and_then(|b| u64::try_from(b).ok())
            .unwrap_or(0);
        #[cfg(unix)]
        {
            Self {
                birth,
                device: metadata.dev(),
                inode: metadata.ino(),
                size: metadata.len(),
            }
        }
        #[cfg(not(unix))]
        {
            Self {
                birth,
                size: metadata.len(),
                ..Self::default()
            }
        }
    }
}
crate::heap_layout_bound::no_heap!(true; ClaudeOpenedBirth);

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) enum ClaudeBirthScope {
    /// Not read through the Claude transcript parser (synthetic items, other
    /// sources). The birth rule cannot vouch for it, so its scalars stay
    /// withheld.
    #[default]
    NotObserved,
    /// A `subagents/agent-*` transcript: exempt from the birth rule.
    Subagent,
    /// A root transcript whose file system reports no creation time.
    RootUnknownBirth,
    /// A root transcript and its creation time in Unix nanoseconds, read from
    /// the opened file, never from a later path lookup.
    Root(i128),
}
crate::durable_tail_codec::durable_enum!(ClaudeBirthScope {
    0 => NotObserved,
    1 => Subagent,
    2 => RootUnknownBirth,
    3 => Root(N x0: i128),
});

crate::heap_layout_bound::no_heap!(true; ClaudeBirthScope);

/// Per-file birth evidence and the own-only context tally the parser keeps
/// beside today's values. Inline only: no heap, so neither the parser budget
/// nor the retained tail copy grows with the transcript.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct ClaudeFileBirth {
    scope: ClaudeBirthScope,
    /// In-process hash of the file's local index key, used only to notice the
    /// same session id at two paths in one fold. Never persisted.
    path_key_hash: u64,
    /// A tagged record arrived before the session-start opening window closed.
    tagged_in_opening: bool,
    tagged_responses: u64,
    own_responses: u64,
    /// Root records whose usage or boundary timestamp could not be read.
    untimed_records: u64,
    first_own_sequence: Option<u64>,
    own_first_context: Option<u64>,
    own_peak_context: u64,
    own_last_context: Option<u64>,
    /// A tagged response came before the first own response.
    tagged_before_first_own: bool,
    /// Money only: the writer versions of the file's lines by time.
    writer: ClaudeOwnWriters,
    all_response_writers: ClaudeWriterRun,
    opened: ClaudeOpenedBirth,
}
crate::durable_tail_codec::durable_struct!(ClaudeFileBirth {
    N scope: ClaudeBirthScope,
    I path_key_hash: u64,
    N tagged_in_opening: bool,
    N tagged_responses: u64,
    N own_responses: u64,
    N untimed_records: u64,
    N first_own_sequence: Option<u64>,
    N own_first_context: Option<u64>,
    N own_peak_context: u64,
    N own_last_context: Option<u64>,
    N tagged_before_first_own: bool,
    N writer: ClaudeOwnWriters,
    N all_response_writers: ClaudeWriterRun,
    I opened: ClaudeOpenedBirth,
});
// This Copy witness owns no heap. Keep exhaustive coverage so a new
// field cannot silently enter native frame/cache accounting.
crate::heap_layout_bound::no_heap!(true; ClaudeFileBirth {
    scope, path_key_hash, tagged_in_opening, tagged_responses, own_responses, untimed_records,
    first_own_sequence, own_first_context, own_peak_context, own_last_context,
    tagged_before_first_own, writer, all_response_writers, opened,
});

/// A reported birth at or before the floor is no evidence (F5).
fn root_birth_scope(created_unix_nanos: Option<i128>) -> ClaudeBirthScope {
    created_unix_nanos
        .filter(|birth| *birth > CLAUDE_BIRTH_FLOOR_UNIX_NANOS)
        .map_or(ClaudeBirthScope::RootUnknownBirth, ClaudeBirthScope::Root)
}

fn stable_hash(value: &str) -> u64 {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    value.hash(&mut hasher);
    hasher.finish()
}

impl ClaudeFileBirth {
    /// Bind the rule to the opened physical file. `metadata` comes from the
    /// open descriptor; subagent identity uses the same path rule as the
    /// family census, so an alias cannot reach the exemption another way.
    pub(super) fn observe(path: &Path, metadata: Option<&fs::Metadata>) -> Self {
        let scope = match claude_index_path_member_ref(path) {
            None => ClaudeBirthScope::NotObserved,
            Some(member) if member.subagent_stem.is_some() => ClaudeBirthScope::Subagent,
            Some(_) => root_birth_scope(
                metadata
                    .and_then(|metadata| metadata.created().ok())
                    .and_then(system_time_unix_nanos_i128),
            ),
        };
        let birth = Self {
            scope,
            opened: metadata
                .map(ClaudeOpenedBirth::from_metadata)
                .unwrap_or_default(),
            path_key_hash: stable_hash(&local_index_key(path)),
            ..Self::default()
        };
        // A staged synthetic root birth (Linux has no set-creation-time API)
        // stands in for the opened file's, as the parser fixtures set it.
        #[cfg(test)]
        let birth = {
            let mut birth = birth;
            if let Some(staged) =
                super::claude_history_upgrade::staged_birth_for_test(&local_index_key(path))
            {
                if matches!(
                    birth.scope,
                    ClaudeBirthScope::Root(_) | ClaudeBirthScope::RootUnknownBirth
                ) {
                    birth.set_birth_for_test(i128::from(staged));
                }
            }
            birth
        };
        birth
    }

    /// Acquisition proved the retained prefix belongs to this same object.
    /// Refresh its current extent without replacing accumulated birth evidence.
    pub(super) fn refresh_opened(&mut self, current: &Self) {
        self.opened = current.opened;
        // Same path, same key for a RAM copy; a durable-restored copy never
        // carries this path-derived key (M1) and takes it from the live parse.
        self.path_key_hash = current.path_key_hash;
    }

    /// `Some(true)` for a root record more than 60 s older than the file's
    /// birth, `Some(false)` for an owned root record, and `None` when the rule
    /// does not apply or the timestamp is unusable (never "owned" by default).
    fn copied(&self, timestamp: Option<&str>) -> Option<bool> {
        self.copied_with_slack(
            timestamp.and_then(rfc3339_unix_nanos),
            CLAUDE_COPIED_BY_BIRTH_SLACK_NANOS,
        )
    }

    pub(in crate::snapshots) fn copied_with_slack(
        &self,
        at: Option<i128>,
        slack: i128,
    ) -> Option<bool> {
        let ClaudeBirthScope::Root(birth) = self.scope else {
            return None;
        };
        Some(at? < birth.checked_sub(slack)?)
    }

    pub(in crate::snapshots) fn birth_nanos(&self) -> Option<i128> {
        match self.scope {
            ClaudeBirthScope::Root(birth) => Some(birth),
            _ => None,
        }
    }

    pub(in crate::snapshots) fn with_minimum(mut self, minimum: Option<i128>) -> Self {
        if matches!(
            self.scope,
            ClaudeBirthScope::Root(_) | ClaudeBirthScope::RootUnknownBirth
        ) {
            if let Some(minimum) = minimum {
                self.scope = root_birth_scope(Some(
                    self.birth_nanos()
                        .map_or(minimum, |birth| birth.min(minimum)),
                ));
            }
        }
        self
    }

    /// E2-only cutoff for a subagent with a proven earlier path twin.
    /// Context scalars keep their independent subagent exemption.
    pub(in crate::snapshots) fn with_money_birth(mut self, birth: Option<i128>) -> Self {
        self.scope = root_birth_scope(birth);
        self
    }

    pub(in crate::snapshots) fn uncertain_root(&self) -> bool {
        self.scope == ClaudeBirthScope::RootUnknownBirth
    }

    pub(in crate::snapshots) fn opened(&self) -> ClaudeOpenedBirth {
        self.opened
    }

    pub(in crate::snapshots) fn physical_birth_nanos(&self) -> Option<i128> {
        (self.opened.birth != 0)
            .then_some(i128::from(self.opened.birth))
            .or_else(|| self.birth_nanos())
    }

    /// Called only for usage-bearing response records, never headers/tool lines.
    /// Copied prefix versions cannot certify a later response missing its own version.
    pub(in crate::snapshots) fn observe_response_writer(
        &mut self,
        version: Option<&str>,
        timestamp: Option<&str>,
    ) {
        self.all_response_writers.observe(version);
        // An untimed response cannot prove it belongs to the copied prefix;
        // it counts conservatively among the own responses of every cutoff.
        self.writer
            .observe(version, timestamp.and_then(rfc3339_unix_nanos));
    }

    /// Own lines are those at or after THIS birth's money cutoff (minus
    /// slack), the same split `copied_with_slack` makes for money.
    pub(in crate::snapshots) fn writer_certified(&self, first_own_sequence: Option<u64>) -> bool {
        if first_own_sequence.is_some() {
            self.birth_nanos().is_some_and(|birth| {
                self.writer
                    .certified_from(birth - super::claude_request_money::e2::SLACK)
            })
        } else {
            // Restored all-pre-birth files have no own run. Require a known
            // version on EVERY response, never a header or inherited version.
            self.all_response_writers.certified()
        }
    }

    /// Read through the Claude transcript parser.
    pub(super) fn observed(&self) -> bool {
        self.scope != ClaudeBirthScope::NotObserved
    }

    fn root_with_birth(&self) -> bool {
        matches!(self.scope, ClaudeBirthScope::Root(_))
    }

    /// One owned or copied line, before its response is resolved. Only the
    /// opening window is checked, so this costs at most a few timestamp parses
    /// per file.
    pub(super) fn observe_line(&mut self, timestamp: Option<&str>, responses_before: u64) {
        if responses_before < super::session_start::WINDOW_REQUESTS as u64
            && self.copied(timestamp) == Some(true)
        {
            self.tagged_in_opening = true;
        }
    }

    /// One resolved response, in transcript order. Today's naive scalars are
    /// computed beside this and stay untouched; the fold decides which ships.
    pub(super) fn observe_response_at(
        &mut self,
        sequence: u64,
        at: Option<i128>,
        effective_input_context: u64,
    ) {
        let copied = match self.copied_with_slack(at, CLAUDE_COPIED_BY_BIRTH_SLACK_NANOS) {
            Some(copied) => copied,
            None => {
                if self.root_with_birth() {
                    self.untimed_records = self.untimed_records.saturating_add(1);
                }
                false
            }
        };
        if copied {
            self.tagged_responses = self.tagged_responses.saturating_add(1);
            self.tagged_before_first_own |= self.own_responses == 0;
            if sequence < super::session_start::WINDOW_REQUESTS as u64 {
                self.tagged_in_opening = true;
            }
            return;
        }
        self.own_responses = self.own_responses.saturating_add(1);
        self.first_own_sequence.get_or_insert(sequence);
        if effective_input_context > 0 {
            self.own_first_context
                .get_or_insert(effective_input_context);
            self.own_peak_context = self.own_peak_context.max(effective_input_context);
            self.own_last_context = Some(effective_input_context);
        }
    }

    /// Boundaries this session owns: not tagged by timestamp (a second copied
    /// block after new turns is dropped too) and after the first own request.
    fn owned_boundary(&self, observation: &ClaudeCompactionObservation) -> bool {
        if self.copied(observation.timestamp.as_deref()) == Some(true) {
            return false;
        }
        self.first_own_sequence
            .is_some_and(|first| observation.response_count_before > first)
    }

    fn tagged_boundaries(&self, observations: &[ClaudeCompactionObservation]) -> u64 {
        observations
            .iter()
            .filter(|observation| self.copied(observation.timestamp.as_deref()) == Some(true))
            .count() as u64
    }

    /// SOURCE Amendment 5: the earliest kept record follows excluded
    /// pre-birth records (a restore, sync, slot move or Rewind that then
    /// grew). Its numbers cover post-birth activity only.
    fn partially_pre_birth(&self, observations: &[ClaudeCompactionObservation]) -> bool {
        let Some(first_own) = self.first_own_sequence else {
            return false;
        };
        self.tagged_before_first_own
            || observations.iter().any(|observation| {
                observation.response_count_before <= first_own
                    && self.copied(observation.timestamp.as_deref()) == Some(true)
            })
    }

    fn untimed_boundaries(&self, observations: &[ClaudeCompactionObservation]) -> u64 {
        if !self.root_with_birth() {
            return 0;
        }
        observations
            .iter()
            .filter(|observation| self.copied(observation.timestamp.as_deref()).is_none())
            .count() as u64
    }
}

/// Replace the item's first/peak/last and compaction scalars with the own-only
/// values. One source for every branch that ships parser scalars.
pub(super) fn apply_own_context_scalars(
    item: &mut SnapshotItem,
    counts: &mut ClaudeContextFileBirthCounts,
) {
    let birth = item.claude_file_birth;
    item.first_turn_context_tokens = birth.own_first_context;
    item.peak_context_fill_tokens = (birth.own_peak_context > 0).then_some(birth.own_peak_context);
    item.last_turn_context_tokens = birth.own_last_context;
    let owned = item
        .claude_context_curve_boundaries
        .iter()
        .filter(|observation| birth.owned_boundary(observation))
        .cloned()
        .collect::<Vec<_>>();
    // The own requests are the responses `observe_response` counted as own
    // (an untimed one counts as own there too), minus id-less responses,
    // which carry no occurrence. Moved out for the call, never cloned.
    let occurrences = std::mem::take(&mut item.claude_usage_occurrences);
    let (id_less, points_refused) =
        set_claude_compaction_scalars(item, &owned, occurrences.values(), false, |occurrence| {
            birth.copied(occurrence.timestamp.as_deref()) != Some(true)
        });
    item.claude_usage_occurrences = occurrences;
    counts.local_context_points_work_refused_session_count = counts
        .local_context_points_work_refused_session_count
        .saturating_add(u64::from(points_refused));
    counts.id_less_response_before_compaction_count = counts
        .id_less_response_before_compaction_count
        .saturating_add(id_less.before);
    counts.id_less_response_after_compaction_count = counts
        .id_less_response_after_compaction_count
        .saturating_add(id_less.after);
}

/// When the session's first own request ended (SOURCE ruling on
/// `first_own_request_at`): only for a root file whose birth was measured and
/// whose first own request follows no copied record. Read from values the
/// fold already holds; `None` when that request carried no request id (no
/// occurrence), any of its records was unstamped (the kept timestamp may be
/// an earlier partial's, not its end) or its timestamp is not RFC 3339 UTC.
/// Never a guess.
fn measured_first_own_request_at(item: &SnapshotItem) -> Option<String> {
    let birth = &item.claude_file_birth;
    if !birth.root_with_birth() || birth.partially_pre_birth(&item.claude_context_curve_boundaries)
    {
        return None;
    }
    let first_own = birth.first_own_sequence?;
    let timestamp = item
        .claude_usage_occurrences
        .values()
        .find(|occurrence| occurrence.sequence == first_own)
        .filter(|occurrence| occurrence.event_clock_complete)?
        .timestamp
        .as_deref()?;
    let utc = OffsetDateTime::parse(timestamp, &Rfc3339)
        .is_ok_and(|at| at.offset() == time::UtcOffset::UTC);
    (utc && birth.copied(Some(timestamp)) == Some(false)).then(|| timestamp.to_string())
}

/// Why an item without a provider-proven start kept or lost its scalars.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ClaudeFileBirthVerdict {
    Admitted,
    UnknownBirth,
    UntimedRecord,
    AllCopied,
    /// The session id has a second file. Its files are not merged, so the
    /// whole tuple is withheld rather than shipping one file's numbers.
    MultiFile,
    Tripwire,
    EvidenceBound,
}

crate::heap_layout_bound::no_heap!(true; ClaudeFileBirthVerdict);

impl SnapshotItem {
    /// Local design E decision for this fold, independent of strict ownership.
    pub(crate) fn claude_file_birth_verdict(&self) -> Option<ClaudeFileBirthVerdict> {
        self.claude_file_birth_verdict
    }
}

enum TelemetryOwner<'r> {
    One(&'r str),
    Several,
}

/// API rows of roots whose sidecar pair was missing or incomplete this pass.
/// Moved out of the strict read before it is narrowed (never cloned) and used
/// only to veto scalars; usage proof never sees them.
pub(crate) type ClaudeVetoApiRows =
    BTreeMap<String, Vec<crate::claude_local_otel::ClaudeLocalOtelEvidence>>;

/// Loaded API and trace rows' verdict on each judged item, decided once per
/// fold. The evidence bound is per root: a root whose own requests exceed
/// `max_requests` is withheld, never because other roots share the page.
///
/// The owners lookup (request id hash to owning root) is built from the rows
/// already loaded, in request-hash partitions of at most `max_requests` rows
/// each. Rows are counted per partition before the lookup allocates, and one
/// partition map is reused, so the scratch never holds more than
/// `max_requests` keys however large the page is. All rows of one request
/// fall in one partition, so the verdicts equal those of a single page-wide
/// lookup. Partitions that cannot be sized under the bound refuse the page:
/// every judged item withholds (fail closed).
pub(super) struct ClaudeTelemetryTripwire {
    /// Item path hash to its check, sorted by hash: `None` on a
    /// contradiction, otherwise whether telemetry reported every kept request
    /// under its root.
    checks: Vec<(u64, Option<bool>)>,
    over_bound_roots: BTreeSet<String>,
    refused: bool,
}

impl ClaudeTelemetryTripwire {
    pub(super) fn build(
        items: &[SnapshotItem],
        max_requests: usize,
        api_report: &crate::claude_local_otel::ClaudeLocalOtelLoadReport,
        trace_report: &crate::claude_local_otel::ClaudeTraceOwnershipLoadReport,
        veto_api_rows: &ClaudeVetoApiRows,
    ) -> Self {
        let observed = || {
            items
                .iter()
                .filter(|item| item.claude_file_birth.scope != ClaudeBirthScope::NotObserved)
        };
        let mut per_root = BTreeMap::<&str, usize>::new();
        for item in observed() {
            let count = per_root
                .entry(claude_snapshot_family_root_ref(item))
                .or_default();
            *count = count.saturating_add(item.claude_usage_occurrences.len());
        }
        let bound = per_root_evidence_bound(max_requests);
        let over_bound_roots = per_root
            .into_iter()
            .filter(|(_, count)| *count > bound)
            .map(|(root, _)| root.to_string())
            .collect::<BTreeSet<_>>();
        let over_bound = &over_bound_roots;
        let judged = move || {
            observed()
                .filter(move |item| !over_bound.contains(claude_snapshot_family_root_ref(item)))
        };
        let rows = || {
            let api = api_report
                .evidence
                .iter()
                .chain(veto_api_rows)
                .flat_map(|(root, rows)| {
                    rows.iter().map(move |row| {
                        (
                            root.as_str(),
                            row.session_id.as_str(),
                            row.request_id.as_str(),
                        )
                    })
                });
            let trace = trace_report.evidence.iter().flat_map(|(root, rows)| {
                rows.iter().map(move |row| {
                    (
                        root.as_str(),
                        row.session_id.as_str(),
                        row.request_id.as_str(),
                    )
                })
            });
            api.chain(trace)
                .filter(|(_, _, request_id)| !request_id.is_empty())
        };
        let Some(partitions) = telemetry_partitions(
            || rows().map(|(_, _, request_id)| stable_hash(request_id)),
            max_requests,
        ) else {
            return Self {
                checks: Vec::new(),
                over_bound_roots,
                refused: true,
            };
        };
        let mut checks = judged()
            .map(|item| {
                (
                    item.claude_file_birth.path_key_hash,
                    Some(!item.claude_usage_occurrences.is_empty()),
                )
            })
            .collect::<Vec<_>>();
        let mut owners = BTreeMap::<u64, TelemetryOwner<'_>>::new();
        for partition in 0..partitions {
            owners.clear();
            for (root, session_id, request_id) in rows() {
                let request_hash = stable_hash(request_id);
                if request_hash % partitions != partition {
                    continue;
                }
                // SI ruling: an API row without its trace row still names the
                // owner. A row whose session disagrees with its sidecar root
                // has no single owner. Two ids sharing a hash can only merge
                // into `Several`, which withholds.
                let reported = if session_id == root {
                    TelemetryOwner::One(root)
                } else {
                    TelemetryOwner::Several
                };
                match owners.get_mut(&request_hash) {
                    None => {
                        owners.insert(request_hash, reported);
                    }
                    Some(TelemetryOwner::One(first)) if *first == root && session_id == root => {}
                    Some(existing) => *existing = TelemetryOwner::Several,
                }
            }
            for (item, (_, check)) in judged().zip(checks.iter_mut()) {
                let Some(mut confirmed) = *check else {
                    continue;
                };
                let root = claude_snapshot_family_root_ref(item);
                let birth = &item.claude_file_birth;
                let mut contradiction = false;
                for (request_id, occurrence) in &item.claude_usage_occurrences {
                    let request_hash = stable_hash(request_id.as_str());
                    if request_hash % partitions != partition {
                        continue;
                    }
                    let tagged = birth.copied(occurrence.timestamp.as_deref()) == Some(true);
                    // A kept request reported under another root, or a tagged
                    // request reported under this root, contradicts the tags.
                    contradiction = match owners.get(&request_hash) {
                        None => {
                            confirmed &= tagged;
                            false
                        }
                        Some(TelemetryOwner::Several) => true,
                        Some(TelemetryOwner::One(owner)) => (*owner == root) == tagged,
                    };
                    if contradiction {
                        break;
                    }
                }
                *check = (!contradiction).then_some(confirmed);
            }
        }
        drop(owners);
        checks.sort_unstable_by_key(|(path_hash, _)| *path_hash);
        // One file per path; a shared hash merges conservatively.
        checks.dedup_by(|later, kept| {
            if later.0 != kept.0 {
                return false;
            }
            kept.1 = kept.1.zip(later.1).map(|(left, right)| left && right);
            true
        });
        Self {
            checks,
            over_bound_roots,
            refused: false,
        }
    }

    /// Family roots over their own evidence bound this fold. Read-only, for
    /// #677's local stop alarm (hashed there; never logged raw).
    pub(super) fn over_bound_roots(&self) -> &BTreeSet<String> {
        &self.over_bound_roots
    }

    /// `None` when this page could not judge the item (fail closed);
    /// otherwise `None` on a contradiction, else whether telemetry reported
    /// every kept request under its root.
    fn check(&self, item: &SnapshotItem) -> Option<Option<bool>> {
        if self.refused {
            return None;
        }
        let path_hash = item.claude_file_birth.path_key_hash;
        self.checks
            .binary_search_by_key(&path_hash, |(hash, _)| *hash)
            .ok()
            .map(|at| self.checks[at].1)
    }
}

/// The per-root evidence bound: `max_requests`, lowered only by the test seam.
fn per_root_evidence_bound(max_requests: usize) -> usize {
    #[cfg(test)]
    if let Some(bound) = EVIDENCE_BOUND_FOR_TEST.with(std::cell::Cell::get) {
        return bound.min(max_requests);
    }
    max_requests
}

#[cfg(test)]
thread_local! {
    static EVIDENCE_BOUND_FOR_TEST: std::cell::Cell<Option<usize>> =
        const { std::cell::Cell::new(None) };
}

/// SOURCE Amendment 7 seam: run `body` with the per-root evidence bound
/// lowered to `bound` on this thread, whatever bound the fold passes. The
/// owners-lookup slice cap is unchanged.
#[cfg(test)]
pub(crate) fn with_claude_evidence_bound_for_test<T>(bound: usize, body: impl FnOnce() -> T) -> T {
    EVIDENCE_BOUND_FOR_TEST.with(|slot| slot.set(Some(bound)));
    let result = body();
    EVIDENCE_BOUND_FOR_TEST.with(|slot| slot.set(None));
    result
}

/// The slice count `build` uses for these loaded request ids (one entry per
/// loaded row) and the slice of `request_id`, so a test can place a request
/// in a later slice.
#[cfg(test)]
pub(super) fn telemetry_slice_for_test(
    loaded_request_ids: &[&str],
    max_requests: usize,
    request_id: &str,
) -> Option<(u64, u64)> {
    let partitions = telemetry_partitions(
        || loaded_request_ids.iter().map(|id| stable_hash(id)),
        max_requests,
    )?;
    Some((partitions, stable_hash(request_id) % partitions))
}

/// How many request-hash partitions keep every partition at or under
/// `max_rows` loaded rows (so the owners map stays under it), counted before
/// the map allocates. `None` refuses the page.
fn telemetry_partitions<F, I>(hashes: F, max_rows: usize) -> Option<u64>
where
    F: Fn() -> I,
    I: Iterator<Item = u64>,
{
    let max_rows = max_rows.max(1);
    let total = hashes().count();
    if total <= max_rows {
        return Some(1);
    }
    let mut partitions = total.div_ceil(max_rows).checked_mul(2)?;
    for _ in 0..MAX_TELEMETRY_PARTITION_DOUBLINGS {
        let width = u64::try_from(partitions).ok()?;
        let mut rows = vec![0usize; partitions];
        for hash in hashes() {
            let slot = usize::try_from(hash % width).ok()?;
            rows[slot] += 1;
        }
        if rows.iter().all(|count| *count <= max_rows) {
            return Some(width);
        }
        partitions = partitions.checked_mul(2)?;
    }
    None
}

/// Tripwire vetoes remembered for the process lifetime (in memory only, never
/// persisted). Which telemetry rows a fold loads depends on the page, so a
/// veto must not lapse just because a later page did not load the rows: the
/// vetoed (file, fingerprint) keeps withholding until the file changes. A
/// restart forgets; the next fold that loads the rows vetoes again.
pub(crate) struct ClaudeRememberedTripwire {
    /// In-process path hash to the hash of the file fingerprint at the veto.
    vetoed: BTreeMap<u64, u64>,
    capacity: usize,
    overflowed: bool,
}

impl ClaudeRememberedTripwire {
    pub(crate) const fn new(capacity: usize) -> Self {
        Self {
            vetoed: BTreeMap::new(),
            capacity,
            overflowed: false,
        }
    }

    fn key(item: &SnapshotItem) -> (u64, u64) {
        (
            item.claude_file_birth.path_key_hash,
            stable_hash(item.source_file_fingerprint.as_deref().unwrap_or("")),
        )
    }

    /// This exact file version was vetoed earlier, or memory overflowed.
    pub(super) fn holds(&self, item: &SnapshotItem) -> bool {
        let (path, fingerprint) = Self::key(item);
        self.overflowed || self.vetoed.get(&path) == Some(&fingerprint)
    }

    pub(super) fn remember(&mut self, item: &SnapshotItem) {
        let (path, fingerprint) = Self::key(item);
        if self.vetoed.len() >= self.capacity && !self.vetoed.contains_key(&path) {
            // Fail closed: a veto that cannot be remembered withholds every
            // later admission until restart.
            self.overflowed = true;
            return;
        }
        self.vetoed.insert(path, fingerprint);
    }

    /// The file changed since its veto and was admitted: drop the stale row.
    pub(super) fn forget(&mut self, item: &SnapshotItem) {
        self.vetoed.remove(&item.claude_file_birth.path_key_hash);
    }
}

static REMEMBERED_TRIPWIRE: Mutex<ClaudeRememberedTripwire> =
    Mutex::new(ClaudeRememberedTripwire::new(MAX_REMEMBERED_TRIPWIRE_FILES));

/// The process-lifetime veto memory, held for one fold.
pub(super) fn remembered_tripwire() -> std::sync::MutexGuard<'static, ClaudeRememberedTripwire> {
    REMEMBERED_TRIPWIRE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Content-free counters for one fold. Local only: logged on their own line
/// beside the Claude local evidence counts; never uploaded and not part of
/// snapshot-audit.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct ClaudeContextBasisCounts {
    /// Responses and compaction boundaries tagged as copied by file birth.
    pub tagged_record_count: u64,
    /// Scalars from a provider-proven start (the strict rule).
    pub proof_basis_session_count: usize,
    /// Scalars admitted by the file birth rule.
    pub file_birth_rule_session_count: usize,
    /// File-birth admissions whose every kept request telemetry assigned to
    /// this root.
    pub telemetry_confirmed_session_count: usize,
    pub withheld_unknown_birth_session_count: usize,
    pub withheld_untimed_record_session_count: usize,
    /// Every response was copied: a restored or copied file, not measured.
    pub withheld_all_copied_session_count: usize,
    /// The session id has a second file: the whole tuple is withheld.
    pub withheld_multi_file_session_count: usize,
    pub withheld_tripwire_session_count: usize,
    /// Of the tripwire withholds: no contradiction loaded this fold, but this
    /// file version was vetoed earlier in the process (or the memory is full).
    pub withheld_tripwire_remembered_session_count: usize,
    pub withheld_evidence_bound_session_count: usize,
    /// SOURCE Amendment 5: files judged by the birth rule whose earliest kept
    /// record follows excluded pre-birth records. Admitted ones carry
    /// post-birth numbers only.
    pub partially_pre_birth_session_count: usize,
}

impl ClaudeContextBasisCounts {
    fn record(&mut self, outcome: ContextBasisOutcome, tagged_records: u64, partially: bool) {
        self.tagged_record_count = self.tagged_record_count.saturating_add(tagged_records);
        if partially {
            self.partially_pre_birth_session_count += 1;
        }
        let counter = match outcome {
            ContextBasisOutcome::Proof => &mut self.proof_basis_session_count,
            ContextBasisOutcome::FileBirth(verdict, confirmed, remembered) => {
                if confirmed {
                    self.telemetry_confirmed_session_count += 1;
                }
                if remembered {
                    self.withheld_tripwire_remembered_session_count += 1;
                }
                match verdict {
                    ClaudeFileBirthVerdict::Admitted => &mut self.file_birth_rule_session_count,
                    ClaudeFileBirthVerdict::UnknownBirth => {
                        &mut self.withheld_unknown_birth_session_count
                    }
                    ClaudeFileBirthVerdict::UntimedRecord => {
                        &mut self.withheld_untimed_record_session_count
                    }
                    ClaudeFileBirthVerdict::AllCopied => {
                        &mut self.withheld_all_copied_session_count
                    }
                    ClaudeFileBirthVerdict::MultiFile => {
                        &mut self.withheld_multi_file_session_count
                    }
                    ClaudeFileBirthVerdict::Tripwire => &mut self.withheld_tripwire_session_count,
                    ClaudeFileBirthVerdict::EvidenceBound => {
                        &mut self.withheld_evidence_bound_session_count
                    }
                }
            }
        };
        *counter += 1;
    }
}

#[derive(Debug, Clone, Copy)]
enum ContextBasisOutcome {
    Proof,
    /// Verdict, telemetry confirmed, tripwire remembered from an earlier fold.
    FileBirth(ClaudeFileBirthVerdict, bool, bool),
}

/// Fold totals plus the same counters per Claude Code version (bounded).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ClaudeContextFileBirthCounts {
    #[serde(flatten)]
    pub total: ClaudeContextBasisCounts,
    /// Final advertised curve coverage after the ownership fold. Local only;
    /// these bodies may still be held by the existing upload quarantine.
    pub curve_scalars_file_birth_only_session_count: usize,
    pub curve_ownership_unresolved_session_count: usize,
    pub by_claude_code_version: BTreeMap<String, ClaudeContextBasisCounts>,
    /// Sessions the family demotion quarantine held back this fold (R7): the
    /// hold is unchanged, so their scalars wait with the rest of the body.
    pub demotion_quarantined_session_count: usize,
    /// SOURCE condition 6 / R9: Claude bodies without the v1 contract that
    /// carry context scalars, split by the local proven family witness. With
    /// the witness the demotion quarantine holds the body, so no contract-less
    /// scalar change goes out against a proven head. Without it the daemon
    /// cannot know the server head and offers the body once per change
    /// (SOURCE Amendment 2, option (i)).
    pub contractless_scalars_witness_present_session_count: usize,
    pub contractless_scalars_witness_missing_session_count: usize,
    /// The remembered-veto list was full when this fold judged a file-birth
    /// item: every later file-birth admission withholds until restart.
    pub remembered_veto_overflowed: bool,
    /// Shipped compactions whose response just before had no request id, so
    /// their `before` came from an earlier request or is absent. Local only.
    pub id_less_response_before_compaction_count: u64,
    /// Shipped compactions whose response just after had no request id, so
    /// their `after` comes from a later request. Local only.
    pub id_less_response_after_compaction_count: u64,
    /// Recent sessions whose unordered request map exceeded the LOCAL points
    /// work budget. Does not withhold posture or affect upload/backfill.
    pub local_context_points_work_refused_session_count: u64,
}

impl ClaudeContextFileBirthCounts {
    /// SOURCE Amendment 7: this fold withheld scalars for a resource limit,
    /// not for their content: a family over its own evidence bound, or a full
    /// remembered-veto list (review-678c R1). The #677 backfill stops on it.
    pub(crate) fn resource_withheld(&self) -> bool {
        self.total.withheld_evidence_bound_session_count > 0 || self.remembered_veto_overflowed
    }

    fn record(&mut self, item: &SnapshotItem, outcome: ContextBasisOutcome) {
        let birth = &item.claude_file_birth;
        let tagged = birth
            .tagged_responses
            .saturating_add(birth.tagged_boundaries(&item.claude_context_curve_boundaries));
        let partially = matches!(outcome, ContextBasisOutcome::FileBirth(..))
            && birth.partially_pre_birth(&item.claude_context_curve_boundaries);
        self.total.record(outcome, tagged, partially);
        let version = item
            .session_start
            .as_deref()
            .and_then(|start| start.client_version.as_deref())
            .filter(|version| {
                version.len() <= MAX_CONTEXT_BASIS_VERSION_KEY_BYTES
                    && version
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || b".+-_".contains(&byte))
            })
            .unwrap_or("unknown");
        let key = if self.by_claude_code_version.contains_key(version)
            || self.by_claude_code_version.len() < MAX_CONTEXT_BASIS_VERSION_KEYS
        {
            version
        } else {
            "other"
        };
        self.by_claude_code_version
            .entry(key.to_string())
            .or_default()
            .record(outcome, tagged, partially);
    }

    pub(super) fn record_proof(&mut self, item: &SnapshotItem) {
        self.record(item, ContextBasisOutcome::Proof);
    }

    /// Count one body the fold left without the v1 contract (R9).
    pub(super) fn record_contractless(&mut self, item: &SnapshotItem, witness_present: bool) {
        let carries_scalars = item.peak_context_fill_tokens.is_some()
            || item.first_turn_context_tokens.is_some()
            || item.last_turn_context_tokens.is_some()
            || item.compaction_count.is_some();
        if !carries_scalars {
            return;
        }
        if witness_present {
            self.contractless_scalars_witness_present_session_count += 1;
        } else {
            self.contractless_scalars_witness_missing_session_count += 1;
        }
    }
}

#[cfg(not(test))]
static RESOURCE_WITHHOLD_ALARMED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

// Tests share one process, so each test thread keeps its own latch.
#[cfg(test)]
thread_local! {
    static RESOURCE_WITHHOLD_ALARMED: std::cell::Cell<bool> =
        const { std::cell::Cell::new(false) };
}

#[derive(Serialize)]
struct ResourceWithholdAlarm {
    withheld_evidence_bound_session_count: usize,
    remembered_veto_overflowed: bool,
}

/// SOURCE Amendment 7: the first fold of the process that withholds for a
/// resource limit raises one local alarm on the service log. Counts only: no
/// path, id, wire field or UI. Later folds keep counting on the counts line.
pub(super) fn alarm_first_resource_withhold(counts: &ClaudeContextFileBirthCounts) {
    if !counts.resource_withheld() {
        return;
    }
    #[cfg(not(test))]
    let alarmed = RESOURCE_WITHHOLD_ALARMED.swap(true, std::sync::atomic::Ordering::Relaxed);
    #[cfg(test)]
    let alarmed = RESOURCE_WITHHOLD_ALARMED.with(|alarmed| alarmed.replace(true));
    if !alarmed {
        crate::local_resource_diagnostics::claude_context_resource_withhold(
            &ResourceWithholdAlarm {
                withheld_evidence_bound_session_count: counts
                    .total
                    .withheld_evidence_bound_session_count,
                remembered_veto_overflowed: counts.remembered_veto_overflowed,
            },
        );
    }
}

/// Session ids in this fold that have more than one transcript path (an
/// account-slot move or a raw copy keeping the id). Their files are not
/// merged here (a real merge is a later slice), so every file of such an id
/// withholds its whole tuple while the second file exists. Scratch: one
/// borrowed entry per page item and one reused key buffer for the index walk.
pub(super) fn claude_multi_file_members(
    snapshots: &[SnapshotItem],
    index: &ScanIndex,
) -> BTreeSet<String> {
    // Session id -> (first path hash seen, a second path was seen).
    let mut paths = BTreeMap::<&str, (u64, bool)>::new();
    for item in snapshots {
        if item.claude_file_birth.scope != ClaudeBirthScope::NotObserved {
            let path_hash = item.claude_file_birth.path_key_hash;
            let (first, multi) = paths
                .entry(item.source_session_id.as_str())
                .or_insert((path_hash, false));
            *multi |= *first != path_hash;
        }
    }
    if paths.is_empty() {
        return BTreeSet::new();
    }
    let mut member_key = String::new();
    for index_key in index.files.keys() {
        let Some(member) = claude_index_path_member_ref(Path::new(index_key)) else {
            continue;
        };
        member_key.clear();
        member_key.push_str(member.root);
        if let Some(stem) = member.subagent_stem {
            member_key.push('_');
            member_key.push_str(stem);
        }
        if let Some((first, multi)) = paths.get_mut(member_key.as_str()) {
            *multi |= *first != stable_hash(index_key);
        }
    }
    paths
        .into_iter()
        .filter(|(_, (_, multi))| *multi)
        .map(|(member, _)| member.to_string())
        .collect()
}

/// Design E admission for an item the strict rule did not own. Admitted
/// scalars are the parser's own-only values; anything else clears the tuple
/// and session start exactly as before.
pub(super) fn admit_claude_file_birth_posture(
    item: &mut SnapshotItem,
    root_session_id: &str,
    tripwire: &ClaudeTelemetryTripwire,
    remembered: &mut ClaudeRememberedTripwire,
    multi_file: bool,
    counts: &mut ClaudeContextFileBirthCounts,
) -> ClaudeFileBirthVerdict {
    let birth = item.claude_file_birth;
    let mut confirmed = false;
    let mut remembered_veto = false;
    #[cfg(test)]
    if FILE_BIRTH_RULE_DISABLED_FOR_TEST.with(std::cell::Cell::get) {
        // Control arm for byte-identity tests: today's clear.
        clear_claude_context_posture(item);
        return ClaudeFileBirthVerdict::UnknownBirth;
    }
    let verdict = match birth.scope {
        ClaudeBirthScope::NotObserved | ClaudeBirthScope::RootUnknownBirth => {
            ClaudeFileBirthVerdict::UnknownBirth
        }
        // The path alone names a subagent (and keys the item); the records
        // must also mark it a sidechain. The scanner refuses symlinks.
        ClaudeBirthScope::Subagent
            if !item
                .origin
                .as_ref()
                .is_some_and(|origin| origin.is_sidechain == Some(true)) =>
        {
            ClaudeFileBirthVerdict::UnknownBirth
        }
        _ if birth.untimed_records > 0
            || birth.untimed_boundaries(&item.claude_context_curve_boundaries) > 0 =>
        {
            ClaudeFileBirthVerdict::UntimedRecord
        }
        _ if birth.tagged_responses > 0 && birth.own_responses == 0 => {
            ClaudeFileBirthVerdict::AllCopied
        }
        _ if multi_file => ClaudeFileBirthVerdict::MultiFile,
        _ if tripwire.over_bound_roots.contains(root_session_id) => {
            ClaudeFileBirthVerdict::EvidenceBound
        }
        _ => match tripwire.check(item) {
            None => ClaudeFileBirthVerdict::EvidenceBound,
            Some(None) => {
                remembered.remember(item);
                ClaudeFileBirthVerdict::Tripwire
            }
            Some(Some(_)) if remembered.holds(item) => {
                remembered_veto = true;
                ClaudeFileBirthVerdict::Tripwire
            }
            Some(Some(all_reported_own)) => {
                remembered.forget(item);
                confirmed = all_reported_own;
                ClaudeFileBirthVerdict::Admitted
            }
        },
    };
    counts.record(
        item,
        ContextBasisOutcome::FileBirth(verdict, confirmed, remembered_veto),
    );
    counts.remembered_veto_overflowed |= remembered.overflowed;
    match verdict {
        ClaudeFileBirthVerdict::Admitted => {
            apply_own_context_scalars(item, counts);
            item.first_own_request_at = measured_first_own_request_at(item);
            if birth.tagged_in_opening {
                // A copied opening did not start fresh here: keep the
                // version only. A second file for the id withholds above.
                item.session_start = item
                    .session_start
                    .take()
                    .and_then(|start| (*start).inherited())
                    .map(Box::new);
            }
        }
        _ => clear_claude_context_posture(item),
    }
    item.claude_file_birth_verdict = Some(verdict);
    verdict
}

#[cfg(test)]
thread_local! {
    static FILE_BIRTH_RULE_DISABLED_FOR_TEST: std::cell::Cell<bool> =
        const { std::cell::Cell::new(false) };
}

/// Run `body` with the birth rule off on this thread: every item the strict
/// rule does not own is cleared, as before design E.
#[cfg(test)]
pub(crate) fn with_file_birth_rule_disabled_for_test<T>(body: impl FnOnce() -> T) -> T {
    FILE_BIRTH_RULE_DISABLED_FOR_TEST.with(|disabled| disabled.set(true));
    let result = body();
    FILE_BIRTH_RULE_DISABLED_FOR_TEST.with(|disabled| disabled.set(false));
    result
}

#[cfg(test)]
impl ClaudeFileBirth {
    /// A root file system that reports this creation time (Unix nanos),
    /// through the same floor as a real read.
    pub(crate) fn set_birth_for_test(&mut self, created_unix_nanos: i128) {
        self.opened.birth = (created_unix_nanos > CLAUDE_BIRTH_FLOOR_UNIX_NANOS)
            .then(|| u64::try_from(created_unix_nanos).ok())
            .flatten()
            .unwrap_or(0);
        if self.scope != ClaudeBirthScope::Subagent && self.scope != ClaudeBirthScope::NotObserved {
            self.scope = root_birth_scope(Some(created_unix_nanos));
        }
    }

    /// A root file system that reports no creation time.
    pub(crate) fn forget_birth_for_test(&mut self) {
        if self.root_with_birth() {
            self.scope = ClaudeBirthScope::RootUnknownBirth;
            self.opened.birth = 0;
        }
    }

    pub(crate) fn is_root_with_birth_for_test(&self) -> bool {
        self.root_with_birth()
    }

    pub(crate) fn is_subagent_for_test(&self) -> bool {
        self.scope == ClaudeBirthScope::Subagent
    }

    pub(crate) fn tagged_responses_for_test(&self) -> u64 {
        self.tagged_responses
    }
}
