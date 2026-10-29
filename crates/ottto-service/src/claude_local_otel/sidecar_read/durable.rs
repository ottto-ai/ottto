//! v1 at-least-once sidecar acquisition. Compiled in the contract harness until
//! SOURCE approves persistence and the real end-to-end path is proven.
use super::*;
use crate::durable_tail_store::{
    self as store, CodecRow, DurableSource, DurableTailStore, ReadOutcome, SingleWriter,
};
use crate::transcript_acquisition::{
    CertificateRefusal, DurableCertificate, FileStamp, ReadMode, ReadPlan, Scope,
};
use std::io::{self, Seek, SeekFrom};

#[path = "codec.rs"]
mod codec;
#[cfg(test)]
#[path = "durable_tests.rs"]
mod tests;
use codec::{ApiSlot, ApiState, Pair, TraceSlot, TraceState};

pub(super) type Reports = (ClaudeLocalOtelLoadReport, ClaudeTraceOwnershipLoadReport);
type ApiOutput = (Vec<ClaudeLocalOtelEvidence>, ApiReadWitness);
type TraceOutput = (ClaudeTraceOwnershipLoadReport, ClaudeTraceReadGeneration);
// Every admissible file fits a fresh pass. This is a pass byte allowance, not
// permission for a second bootstrap. Production source caps remain unchanged.
const BOOTSTRAP_PASS_BYTES: u64 = MAX_EVIDENCE_FILE_BYTES;
const RETRY_ALARM: u32 = 3;
const GROWTH_PACE_SECONDS: u64 = 6 * 60 * 60;
const PACE_BOUND: usize = store::INVENTORY_BOUND;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RestoreFailure {
    NewerFormat,
    Undecodable,
    Unbindable,
    Unavailable,
}
struct Repair {
    lengths: [Option<u64>; 2],
    reason: RestoreFailure,
}

#[derive(Clone, Copy)]
pub(super) enum Kind {
    Api,
    Trace,
}
impl Kind {
    fn path(self, dir: &Path, session: &str) -> PathBuf {
        match self {
            Self::Api => evidence_path(dir, session),
            Self::Trace => trace_evidence_path(dir, session),
        }
    }
    fn index(self) -> usize {
        match self {
            Self::Api => 0,
            Self::Trace => 1,
        }
    }
}

#[derive(Default, Debug, Clone, Copy)]
pub(super) struct Counts {
    pub(super) selected: u64,
    pub(super) opened: u64,
    pub(super) bytes_read: u64,
    pub(super) guard_bytes: u64,
    pub(super) reuse_hits: u64,
    pub(super) unchanged_reads: u64,
    pub(super) bootstraps: u64,
    pub(super) bootstrap_deferred: u64,
    pub(super) rewrite_rebuilds: u64,
    pub(super) fragments: u64,
    pub(super) fragment_reread_bytes: u64,
    pub(super) failures: u64,
    pub(super) persistent_failures: u64,
}

struct Entry {
    // This cumulative graph may be ahead of disk after a failed v1 post-save
    // write. Keep it in custody: do not evict it and re-bootstrap the source.
    pair: Pair,
    dirty: bool,
    failures: u32,
    write_failures: u32,
    api_generation: Option<ApiFileGeneration>,
    trace_generation: Option<ApiFileGeneration>,
    api_fatal: Option<io::ErrorKind>,
}

pub(crate) struct Reader {
    support: PathBuf,
    store: DurableTailStore,
    context: store::Digest32,
    generation: u64,
    entries: BTreeMap<String, Entry>,
    protected: BTreeMap<String, u32>,
    bootstrap_left: u64,
    write_cursor: Option<String>,
    sync_owed: bool,
    restored_records: u64,
    newer: BTreeSet<String>,
    newer_counted: BTreeSet<String>,
    repairs: BTreeMap<String, Repair>,
    growth_pace: BTreeMap<String, u64>,
    hold_since: BTreeMap<String, u64>,
    now: u64,
    simulated_clock: bool,
    pub(super) counts: [Counts; 2],
}

impl Reader {
    pub(crate) fn new(support: &Path, index_path: &Path, namespace: &str, generation: u64) -> Self {
        // THIN P2 adapter: this row becomes a source-keyed codec-table row.
        // Same directory, source tag, v1 envelope and SingleWriter proof.
        let row = CodecRow {
            source: DurableSource::ClaudeCode,
            allowlist: codec::allowlist(),
            verify: codec::verify,
            newer: codec::newer,
        };
        Self {
            support: support.into(),
            store: DurableTailStore::new(
                store::store_dir_for_index(index_path),
                DurableSource::ClaudeCode,
            )
            .with_codec_row(row),
            context: store::context_digest(namespace, None),
            generation,
            entries: BTreeMap::new(),
            protected: BTreeMap::new(),
            bootstrap_left: BOOTSTRAP_PASS_BYTES,
            write_cursor: None,
            sync_owed: false,
            restored_records: 0,
            simulated_clock: false,
            newer: BTreeSet::new(),
            newer_counted: BTreeSet::new(),
            repairs: BTreeMap::new(),
            growth_pace: BTreeMap::new(),
            hold_since: BTreeMap::new(),
            now: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            counts: [Counts::default(); 2],
        }
    }
    /// Synthetic downgrade: current parser-1 bytes are newer than parser 0.
    /// Re-upgrade uses the unchanged production codec and record, no migration.
    pub(crate) fn into_older_reader(mut self) -> Self {
        assert!(self.entries.is_empty(), "downgrade starts from disk");
        self.store = DurableTailStore::new(self.store.dir().into(), DurableSource::ClaudeCode)
            .with_codec_row(CodecRow {
                source: DurableSource::ClaudeCode,
                allowlist: codec::allowlist(),
                verify: codec::verify_older,
                newer: codec::newer_than_older,
            });
        self
    }
    pub(crate) fn begin_pass(&mut self) {
        if !self.simulated_clock {
            self.now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
        }
        self.bootstrap_left = BOOTSTRAP_PASS_BYTES;
        self.restored_records = 0;
        self.counts = [Counts::default(); 2];
        self.newer_counted.clear();
        self.store.begin_pass();
    }
    pub(crate) fn restored_records(&self) -> u64 {
        self.restored_records
    }
    pub(crate) fn body_bytes(&self) -> [u64; 2] {
        self.counts.map(|counts| counts.bytes_read)
    }
    pub(crate) fn rebuilds(&self) -> [u64; 2] {
        self.counts.map(|counts| counts.rewrite_rebuilds)
    }
    fn binding(&self, session: &str) -> store::Binding {
        // DECISION(19b-§8-SOURCE): explicit kind domain + owning-session id;
        // no source path, provider account UUID, body witness or ACK authority.
        store::Binding {
            source: DurableSource::ClaudeCode,
            key: store::key_digest(
                DurableSource::ClaudeCode,
                &format!("claude-sidecar-pair:v1\0{session}"),
            ),
            context: self.context,
            scope: store::scope_digest(
                "claude-sidecar-decoder:v1",
                &codec::allowlist(),
                "acquisition-only",
                "none",
            ),
            entry: store::entry_digest(session, None),
        }
    }
    fn empty_pair(session: &str) -> Pair {
        Pair {
            parser: codec::PARSER,
            session: session.into(),
            api: ApiSlot::default(),
            trace: TraceSlot::default(),
            pending: false,
        }
    }
    fn restore(&mut self, session: &str) -> Result<Pair, RestoreFailure> {
        use store::Refusal;
        let binding = self.binding(session);
        match self.store.read(&binding.key) {
            ReadOutcome::Missing if self.store.disabled().is_none() => {
                Ok(Self::empty_pair(session))
            }
            ReadOutcome::Found(record) => {
                record
                    .eligible(&store::Expected {
                        binding,
                        committed_generation: self.generation,
                    })
                    .map_err(|_| RestoreFailure::Unbindable)?;
                let pair =
                    codec::decode(&record.record.body).map_err(|_| RestoreFailure::Undecodable)?;
                if pair.session != session {
                    return Err(RestoreFailure::Unbindable);
                }
                self.restored_records += 1;
                Ok(pair)
            }
            ReadOutcome::Refused(Refusal::Unknown | Refusal::NewerFormat) => {
                Err(RestoreFailure::NewerFormat)
            }
            ReadOutcome::Refused(Refusal::Unbindable) => Err(RestoreFailure::Unbindable),
            ReadOutcome::Refused(Refusal::Corrupt | Refusal::Undecodable)
                if self.store.disabled().is_none() =>
            {
                Err(RestoreFailure::Undecodable)
            }
            _ => Err(RestoreFailure::Unavailable),
        }
    }
    pub(crate) fn set_time(&mut self, now: u64) {
        self.now = now;
        self.simulated_clock = true;
    }
    fn lengths(&self, session: &str) -> [Option<u64>; 2] {
        [Kind::Api, Kind::Trace].map(|kind| {
            fs::metadata(kind.path(&self.support, session))
                .ok()
                .map(|m| m.len())
        })
    }
    fn failed_restore(&mut self, session: &str, reason: RestoreFailure) -> io::Error {
        // NewerFormat is UNAVAILABLE. Only stat source paths; no body open,
        // parser fallback, store rewrite, retirement or dependent decision.
        if reason == RestoreFailure::NewerFormat {
            self.newer.insert(session.into());
            if self.newer_counted.insert(session.into()) {
                let _ = self.lengths(session);
                super::counts::extra("sidecar_hold_newer_format", 1);
            }
        }
        let failures = self.protected.entry(session.into()).or_default();
        *failures = failures.saturating_add(1);
        for counts in &mut self.counts {
            counts.selected += 1;
            counts.failures += 1;
            if *failures >= RETRY_ALARM {
                counts.persistent_failures += 1;
            }
        }
        io::Error::new(
            io::ErrorKind::WouldBlock,
            "sidecar unavailable; dependents held",
        )
    }
    fn repair_pair(&mut self, session: &str, reason: RestoreFailure) -> Option<Pair> {
        let lengths = self.lengths(session);
        if lengths.into_iter().flatten().sum::<u64>() > self.bootstrap_left {
            return None;
        }
        if let Some(previous) = self.repairs.get(session) {
            let growth = lengths
                .into_iter()
                .zip(previous.lengths)
                .any(|(now, old)| now.is_some_and(|n| n > old.unwrap_or(0)));
            if !growth {
                return None;
            }
            if self
                .growth_pace
                .get(session)
                .is_some_and(|last| self.now >= *last && self.now - last < GROWTH_PACE_SECONDS)
            {
                return None;
            }
            if self.growth_pace.len() >= PACE_BOUND && !self.growth_pace.contains_key(session) {
                if let Some(oldest) = self
                    .growth_pace
                    .iter()
                    .min_by_key(|(_, time)| **time)
                    .map(|(key, _)| key.clone())
                {
                    self.growth_pace.remove(&oldest);
                    super::counts::extra("sidecar_pace_evicted", 1);
                }
            }
            self.growth_pace.insert(session.into(), self.now);
            let key = match previous.reason {
                RestoreFailure::Unbindable => "sidecar_u_growth_full_unbindable",
                _ => "sidecar_u_growth_full_undecodable",
            };
            super::counts::extra(key, 1);
        } else {
            if !self.store.sidecar_state_fix(&self.binding(session).key) {
                return None;
            }
            super::counts::extra("sidecar_state_fix_rebuilds", 1);
        }
        self.repairs
            .insert(session.into(), Repair { lengths, reason });
        Some(Self::empty_pair(session))
    }
    pub(super) fn load(&mut self, session: &str) -> io::Result<Reports> {
        let before_counts = self.counts;
        if self.newer.contains(session) {
            let error = self.failed_restore(session, RestoreFailure::NewerFormat);
            publish_counts(before_counts, self.counts);
            return Err(error);
        }
        if !self.entries.contains_key(session) {
            let pair = match self.restore(session) {
                Ok(pair) => pair,
                Err(reason) => {
                    let repaired = match reason {
                        RestoreFailure::Undecodable | RestoreFailure::Unbindable => {
                            self.repair_pair(session, reason)
                        }
                        _ => None,
                    };
                    if let Some(pair) = repaired {
                        pair
                    } else {
                        let error = self.failed_restore(session, reason);
                        publish_counts(before_counts, self.counts);
                        return Err(error);
                    }
                }
            };
            self.protected.remove(session);
            self.newer.remove(session);
            self.entries.insert(
                session.into(),
                Entry {
                    pair,
                    dirty: false,
                    failures: 0,
                    write_failures: 0,
                    api_generation: None,
                    trace_generation: None,
                    api_fatal: None,
                },
            );
        }
        let entry = self.entries.get_mut(session).expect("restored entry");
        let was_pending = entry.pair.pending;
        let mut acquire = Acquire {
            support: &self.support,
            session,
            bootstrap_left: &mut self.bootstrap_left,
            counts: &mut self.counts,
            fatal_api: None,
            failure_health: std::array::from_fn(|_| ClaudeLocalOtelLoadHealth::default()),
        };
        let api = acquire.slot(Kind::Api, &mut entry.pair.api);
        let trace = acquire.slot(Kind::Trace, &mut entry.pair.trace);
        let fatal_api = acquire.fatal_api.take();
        let failure_health = acquire.failure_health;
        entry.api_fatal = fatal_api.map(|error| error.kind());
        entry.api_generation = api
            .as_ref()
            .ok()
            .and_then(|acquired| acquired.generation.clone());
        entry.trace_generation = trace
            .as_ref()
            .ok()
            .and_then(|acquired| acquired.generation.clone());
        let failed = api.is_err() || trace.is_err();
        entry.pair.pending = failed || eof_incomplete(&entry.pair);
        entry.dirty |= api.as_ref().is_ok_and(|acquired| acquired.changed)
            || trace.as_ref().is_ok_and(|acquired| acquired.changed)
            || entry.pair.pending
            || was_pending != entry.pair.pending;
        if failed {
            entry.failures = entry.failures.saturating_add(1);
            for kind in [Kind::Api, Kind::Trace] {
                let counts = &mut self.counts[kind.index()];
                counts.failures += 1;
                if entry.failures >= RETRY_ALARM {
                    counts.persistent_failures += 1;
                }
            }
        } else {
            entry.failures = 0;
        }
        // Lead B: cumulative rows are acquisition only. Refusals disclose
        // incomplete; the consumer holds any previously accepted body (S2).
        let mut reports = reports(&entry.pair);
        if api.is_err() {
            reports.0.health = failure_health[0].clone();
            if reports.0.health.is_complete() {
                reports.0.health.unreadable_lines = 1;
            }
            reports.0.evidence.remove(session);
        }
        if trace.is_err() {
            let health = &failure_health[1];
            reports.1 = ClaudeTraceOwnershipLoadReport {
                missing_files: health.missing_files,
                oversized_files: health.oversized_files,
                unreadable_lines: if health.is_complete() {
                    1
                } else {
                    health.unreadable_lines
                },
                ..Default::default()
            };
        }
        if failed
            && self.repairs.contains_key(session)
            && (entry.pair.api.certificate.is_none() || entry.pair.trace.certificate.is_none())
        {
            self.entries.remove(session);
            self.protected.entry(session.into()).or_default();
        }
        publish_counts(before_counts, self.counts);
        Ok(reports)
    }
    /// No mtime/window test: unresolved suffixes stay selectable until a
    /// successful catch-up and post-save write. This is an owning-entry pin,
    /// not a timer or a new discovery scan.
    pub(super) fn pending_sessions(&self) -> BTreeSet<String> {
        self.entries
            .iter()
            .filter(|(_, entry)| entry.dirty || entry.pair.pending)
            .map(|(session, _)| session.clone())
            .chain(self.protected.keys().cloned())
            .collect()
    }
    /// Restore pending selections from the ONE store's bounded inventory.
    /// Other codec kinds and unknown representations remain untouched.
    pub(super) fn restore_pending(&mut self) -> io::Result<()> {
        for key in self.store.inventory()? {
            if let ReadOutcome::Found(record) = self.store.read(&key) {
                if record.index_generation > self.generation
                    || record.record.binding.context != self.context
                {
                    continue;
                }
                let mut pair = codec::decode(&record.record.body).map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "pending sidecar held")
                })?;
                if record.record.binding != self.binding(&pair.session) {
                    continue;
                }
                let growth_or_unavailable = [
                    (Kind::Api, &pair.api.certificate),
                    (Kind::Trace, &pair.trace.certificate),
                ]
                .into_iter()
                .any(|(kind, certificate)| {
                    certificate.as_ref().map_or(true, |cert| {
                        fs::metadata(kind.path(&self.support, &pair.session))
                            .map_or(true, |metadata| metadata.len() != cert.length)
                    })
                });
                if pair.pending || growth_or_unavailable {
                    pair.pending = true;
                    self.entries.entry(pair.session.clone()).or_insert(Entry {
                        pair,
                        dirty: false,
                        failures: 0,
                        write_failures: 0,
                        api_generation: None,
                        trace_generation: None,
                        api_fatal: None,
                    });
                }
            }
        }
        Ok(())
    }
    /// Call ONLY after the owning ScanIndex save succeeded. This is v1
    /// at-least-once post-save persistence, NEVER a write-ahead receipt.
    pub(crate) fn write_after_save<W: SingleWriter>(
        &mut self,
        writer: &W,
        index: &crate::snapshots::ScanIndex,
    ) -> io::Result<()> {
        if index.generation < self.generation {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "sidecar save generation regressed",
            ));
        }
        self.generation = index.generation;
        let before_counts = self.counts;
        let mut successful = Vec::new();
        let mut sessions: Vec<_> = self
            .entries
            .iter()
            .filter(|(_, entry)| entry.dirty)
            .map(|(session, _)| session.clone())
            .collect();
        if let Some(cursor) = &self.write_cursor {
            let pivot = sessions
                .iter()
                .position(|session| session > cursor)
                .unwrap_or(0);
            sessions.rotate_left(pivot);
        }
        // One record at a time bounds codec/atomic-write overlap. Dirty RAM
        // stays owned on error, deferral, budget refusal or disabled store.
        let mut write_left = 8 * 1024 * 1024;
        for session in sessions.into_iter().take(store::MAX_BATCH) {
            self.write_cursor = Some(session.clone());
            let entry = &self.entries[&session];
            let Some(certificate) = entry.pair.api.certificate.as_ref().or(entry
                .pair
                .trace
                .certificate
                .as_ref())
            else {
                continue;
            };
            let body = match codec::encode(&entry.pair) {
                Ok(body) => body,
                Err(_) => {
                    self.note_write_failure(&session);
                    continue;
                }
            };
            if body.len() > write_left {
                continue;
            }
            write_left -= body.len();
            let record = store::PendingRecord {
                binding: self.binding(&session),
                certificate: certificate.clone(),
                body,
                allowlist: codec::allowlist(),
            };
            let mut result = self
                .store
                .write_after_save(writer, index.generation, vec![record]);
            if result.is_err() {
                self.sync_owed = true;
            }
            if result.is_ok() && self.sync_owed {
                match self.store.retry_directory_sync(writer) {
                    Ok(()) => self.sync_owed = false,
                    Err(error) => result = Err(error),
                }
            }
            match result {
                Ok(batch)
                    if batch.written + batch.clean == 1
                        && batch.deferred_keys.is_empty()
                        && batch.budget_refused == 0
                        && self.store.disabled().is_none() =>
                {
                    successful.push(session)
                }
                _ => {
                    self.note_write_failure(&session);
                }
            }
        }
        for session in successful {
            let entry = self.entries.get_mut(&session).expect("saved entry");
            entry.dirty = false;
            entry.write_failures = 0;
        }
        self.generation = index.generation;
        publish_counts(before_counts, self.counts);
        Ok(())
    }
    fn note_write_failure(&mut self, session: &str) {
        let entry = self.entries.get_mut(session).expect("dirty entry retained");
        entry.write_failures = entry.write_failures.saturating_add(1);
        for counts in &mut self.counts {
            counts.failures += 1;
            if entry.write_failures >= RETRY_ALARM {
                counts.persistent_failures += 1;
            }
        }
    }
}

fn eof_incomplete(pair: &Pair) -> bool {
    [&pair.api.certificate, &pair.trace.certificate]
        .into_iter()
        .flatten()
        .any(|cert| cert.sealed_offset < cert.length)
}
// P4b replaces this ONE predicate/view seam with a reversible typed overlay.
fn eof_disclosure(certificate: &Option<DurableCertificate>) -> u64 {
    u64::from(
        certificate
            .as_ref()
            .is_some_and(|cert| cert.sealed_offset < cert.length),
    )
}
fn reports(pair: &Pair) -> Reports {
    let mut health = pair.api.state.health.clone();
    health.unreadable_lines += eof_disclosure(&pair.api.certificate);
    let mut trace = pair.trace.state.health.clone();
    trace.unreadable_lines += eof_disclosure(&pair.trace.certificate);
    if !pair.trace.state.rows.is_empty() {
        trace
            .evidence
            .insert(pair.session.clone(), pair.trace.state.rows.clone());
    }
    let evidence = if pair.api.state.rows.is_empty() {
        BTreeMap::new()
    } else {
        BTreeMap::from([(pair.session.clone(), pair.api.state.rows.clone())])
    };
    (ClaudeLocalOtelLoadReport { evidence, health }, trace)
}

trait Slot: Clone {
    fn certificate(&self) -> &Option<DurableCertificate>;
    fn set_certificate(&mut self, certificate: DurableCertificate);
    fn reset(&mut self);
    fn line(&mut self, session: &str, line: &[u8]);
}
impl Slot for ApiSlot {
    fn certificate(&self) -> &Option<DurableCertificate> {
        &self.certificate
    }
    fn set_certificate(&mut self, certificate: DurableCertificate) {
        self.certificate = Some(certificate);
    }
    fn reset(&mut self) {
        *self = Self::default();
    }
    fn line(&mut self, session: &str, line: &[u8]) {
        let ApiState {
            rows,
            seen,
            requests,
            health,
        } = std::mem::take(&mut self.state);
        let mut decoder = ApiSidecarDecoder {
            session_id: session,
            rows,
            seen_fingerprints: seen,
            request_rows: requests,
            health,
        };
        decoder.push_line(line);
        self.state = ApiState {
            rows: decoder.rows,
            seen: decoder.seen_fingerprints,
            requests: decoder.request_rows,
            health: decoder.health,
        };
    }
}
impl Slot for TraceSlot {
    fn certificate(&self) -> &Option<DurableCertificate> {
        &self.certificate
    }
    fn set_certificate(&mut self, certificate: DurableCertificate) {
        self.certificate = Some(certificate);
    }
    fn reset(&mut self) {
        *self = Self::default();
    }
    fn line(&mut self, session: &str, line: &[u8]) {
        let TraceState {
            rows,
            seen,
            requests,
            health,
        } = std::mem::take(&mut self.state);
        let mut decoder = TraceSidecarDecoder {
            session_id: session,
            rows,
            seen_fingerprints: seen,
            request_fingerprints: requests,
            report: health,
        };
        decoder.push_line(line);
        self.state = TraceState {
            rows: decoder.rows,
            seen: decoder.seen_fingerprints,
            requests: decoder.request_fingerprints,
            health: decoder.report,
        };
    }
}

struct Acquire<'a> {
    support: &'a Path,
    session: &'a str,
    bootstrap_left: &'a mut u64,
    counts: &'a mut [Counts; 2],
    fatal_api: Option<io::Error>,
    failure_health: [ClaudeLocalOtelLoadHealth; 2],
}
struct Acquired {
    changed: bool,
    generation: Option<ApiFileGeneration>,
}
impl Acquire<'_> {
    fn slot<S: Slot>(&mut self, kind: Kind, retained: &mut S) -> io::Result<Acquired> {
        let counts = &mut self.counts[kind.index()];
        counts.selected += 1;
        let path = kind.path(self.support, self.session);
        let metadata = match fs::metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) => {
                if error.kind() == io::ErrorKind::NotFound {
                    self.failure_health[kind.index()].missing_files = 1;
                } else {
                    self.failure_health[kind.index()].unreadable_lines = 1;
                }
                return Err(error);
            }
        };
        if !metadata.is_file() {
            if matches!(kind, Kind::Api) {
                self.fatal_api = Some(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "sidecar API nonregular input",
                ));
            }
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "sidecar nonregular input",
            ));
        }
        if metadata.len() >= MAX_EVIDENCE_FILE_BYTES {
            self.failure_health[kind.index()].oversized_files = 1;
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "sidecar input admission",
            ));
        }
        let before_path = FileStamp::capture(metadata)?;
        if matches!(kind, Kind::Api) {
            API_BEFORE_OPEN.with(|hook| {
                if let Some(hook) = hook.borrow_mut().take() {
                    hook(&path);
                }
            });
        }
        let mut options = OpenOptions::new();
        use std::os::unix::fs::OpenOptionsExt;
        options.read(true).custom_flags(libc::O_NONBLOCK);
        let mut file = match options.open(&path) {
            Ok(file) => file,
            Err(error) => {
                if matches!(kind, Kind::Api) {
                    self.fatal_api = Some(io::Error::new(error.kind(), "open sidecar API"));
                }
                return Err(error);
            }
        };
        counts.opened += 1;
        let before = match file.metadata() {
            Ok(metadata) if metadata.is_file() => metadata,
            result => {
                let error = result.err().unwrap_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "opened sidecar nonregular")
                });
                if matches!(kind, Kind::Api) {
                    self.fatal_api = Some(io::Error::new(error.kind(), "stat opened sidecar API"));
                }
                return Err(error);
            }
        };
        if before.len() >= MAX_EVIDENCE_FILE_BYTES {
            self.failure_health[kind.index()].oversized_files = 1;
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "opened sidecar cap",
            ));
        }
        let stamp = FileStamp::capture(before.clone())?;
        if !before_path.same_content(&stamp) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "sidecar path/open race",
            ));
        }
        let scope = Scope("claude-sidecar-decoder:v1".into());
        let mut previous = None;
        let mut rewrite = false;
        if let Some(certificate) = retained.certificate() {
            // mtime alone is not proof of changed bytes. Shared object/birth
            // and anchor checks still decide; ctime is never a read cause.
            let mut certificate = certificate.clone();
            use std::os::unix::fs::MetadataExt;
            certificate.modified = (before.mtime(), before.mtime_nsec());
            match certificate.restore(&mut file, scope.clone()) {
                Ok((checkpoint, admission)) => {
                    counts.guard_bytes += admission.sample_bytes_read as u64;
                    counts.reuse_hits += 1;
                    if certificate.length == before.len() {
                        if !FileStamp::capture(fs::metadata(&path)?)?.same_content(&stamp)
                            || !FileStamp::capture(file.metadata()?)?.same_content(&stamp)
                        {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "sidecar quiet path race",
                            ));
                        }
                        counts.unchanged_reads += 1;
                        if certificate.sealed_offset < certificate.length {
                            counts.fragments += 1;
                        }
                        let changed = retained.certificate().as_ref() != Some(&certificate);
                        let generation = api_file_generation(&before);
                        retained.set_certificate(certificate);
                        return Ok(Acquired {
                            changed,
                            generation,
                        });
                    }
                    previous = Some(checkpoint);
                }
                Err(CertificateRefusal::Changed(_)) => rewrite = true,
                Err(CertificateRefusal::ReadError) => {
                    return Err(io::Error::other("sidecar anchor I/O"))
                }
            }
        }
        let first = retained.certificate().is_none();
        if first && before.len() > *self.bootstrap_left {
            counts.bootstrap_deferred += 1;
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "sidecar bootstrap paced",
            ));
        }
        // Logical time zero deliberately supplies no clock/audit reread grant.
        // Restored sidecar certificates are written without transcript debt.
        let mut plan = ReadPlan::prepare(&mut file, previous.as_ref(), &scope, None, 0)?;
        counts.guard_bytes += plan.metrics().sample_bytes as u64;
        if previous.is_some() && matches!(plan.mode(), ReadMode::Full(_)) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "sidecar changed during guards",
            ));
        }
        if first {
            *self.bootstrap_left -= before.len();
            counts.bootstraps += 1;
        }
        if rewrite {
            counts.rewrite_rebuilds += 1;
        }
        let mut candidate = retained.clone();
        if rewrite {
            candidate.reset();
        }
        let start = plan.start_offset();
        file.seek(SeekFrom::Start(start))?;
        let mut counted = Counted {
            file: &mut file,
            counts: &mut *counts,
        };
        let mut reader = BufReader::new((&mut counted).take(before.len().saturating_sub(start)));
        let mut line = Vec::new();
        loop {
            line.clear();
            if reader.read_until(b'\n', &mut line)? == 0 {
                break;
            }
            let sealed = line.ends_with(b"\n");
            plan.observe_record_fragment(&line, sealed)?;
            if sealed {
                candidate.line(self.session, &line);
            }
        }
        drop(reader);
        // Count fragment work once per acquisition; never apply finish_eof to
        // the sealed decoder, including valid JSON with no final LF.
        let mut certificate = plan
            .commit_after_native_completion(&file, &scope, 0)?
            .durable_certificate(crate::transcript_acquisition::birth_unix_nanos(&before))
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "sidecar certificate"))?;
        certificate.audit_debt_unix_seconds = None;
        if certificate.sealed_offset < certificate.length {
            counts.fragments += 1;
        }
        if let Some(old) = retained.certificate() {
            counts.fragment_reread_bytes += old.length.saturating_sub(old.sealed_offset);
        }
        if !FileStamp::capture(fs::metadata(&path)?)?.same_content(&stamp) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "sidecar path changed during acquisition",
            ));
        }
        let generation = api_file_generation(&before);
        candidate.set_certificate(certificate);
        *retained = candidate;
        if matches!(kind, Kind::Api) {
            API_AFTER_READ.with(|hook| {
                if let Some(hook) = hook.borrow_mut().take() {
                    hook(&path);
                }
            });
        }
        Ok(Acquired {
            changed: true,
            generation,
        })
    }
}

struct Counted<'a> {
    file: &'a mut File,
    counts: &'a mut Counts,
}
impl Read for Counted<'_> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        let read = self.file.read(bytes)?;
        self.counts.bytes_read += read as u64;
        Ok(read)
    }
}

thread_local! {
    static ACTIVE: std::cell::RefCell<Option<Reader>> = const { std::cell::RefCell::new(None) };
}
// Same real loader seam for ordinary, strict and paid/prepared tests. No
// runtime flag or provider state: activation is scoped to a synthetic fixture.
pub(crate) fn with_reader<T>(reader: Reader, f: impl FnOnce() -> T) -> (Reader, T) {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            ACTIVE.with(|active| {
                active.borrow_mut().take();
            });
        }
    }
    ACTIVE.with(|active| {
        assert!(active.borrow().is_none());
        *active.borrow_mut() = Some(reader);
    });
    let reset = Reset;
    let result = f();
    let reader = ACTIVE.with(|active| active.borrow_mut().take().expect("scoped reader"));
    drop(reset);
    (reader, result)
}
pub(in crate::claude_local_otel) fn active_for(support: &Path) -> bool {
    ACTIVE.with(|active| {
        active
            .borrow()
            .as_ref()
            .is_some_and(|reader| reader.support == support)
    })
}
pub(super) fn active_load(support: &Path, session: &str) -> Option<io::Result<Reports>> {
    ACTIVE.with(|active| {
        let mut active = active.borrow_mut();
        let reader = active.as_mut().filter(|reader| reader.support == support)?;
        Some(reader.load(session))
    })
}
pub(super) fn active_path(path: &Path, session: &str, kind: Kind) -> Option<PathBuf> {
    ACTIVE.with(|active| {
        active
            .borrow()
            .as_ref()
            .filter(|reader| kind.path(&reader.support, session) == path)
            .map(|reader| reader.support.clone())
    })
}
pub(super) fn pay_active(session: &str, paid: &mut PaidReservation, occupied: usize) -> Option<()> {
    if !crate::heap_layout_bound::layout_supported() {
        return None;
    }
    ACTIVE.with(|active| {
        let active = active.borrow();
        let reader = active.as_ref()?;
        let mut source_bytes = 0usize;
        for kind in [Kind::Api, Kind::Trace] {
            let length = fs::metadata(kind.path(&reader.support, session))
                .ok()?
                .len();
            if length >= MAX_EVIDENCE_FILE_BYTES {
                return None;
            }
            source_bytes = source_bytes.checked_add(usize::try_from(length).ok()?)?;
        }
        if let Some(entry) = reader.entries.get(session) {
            for cert in [&entry.pair.api.certificate, &entry.pair.trace.certificate]
                .into_iter()
                .flatten()
            {
                source_bytes =
                    source_bytes.checked_add(usize::try_from(cert.length).ok()?.checked_mul(2)?)?;
            }
        }
        // Conservative temporary harness admission: at most one typed row/map
        // insertion per source byte, four simultaneously owned projections,
        // serde scratch and codec overlap. This deliberately refuses large
        // optional preloads. Native allocation evidence is still required
        // before promoting this adapter into the runtime paid path.
        let peak = occupied
            .checked_add(source_bytes.checked_mul(4096)?)?
            .checked_add(store::RECORD_BYTES.checked_mul(4)?)?;
        paid.grow_for(peak).then_some(())
    })
}

fn publish_counts(before: [Counts; 2], after: [Counts; 2]) {
    fn fields(counts: Counts) -> [u64; 13] {
        [
            counts.selected,
            counts.opened,
            counts.bytes_read,
            counts.guard_bytes,
            counts.reuse_hits,
            counts.unchanged_reads,
            counts.bootstraps,
            counts.bootstrap_deferred,
            counts.rewrite_rebuilds,
            counts.fragments,
            counts.fragment_reread_bytes,
            counts.failures,
            counts.persistent_failures,
        ]
    }
    for (kind, (before, after)) in before.into_iter().zip(after).enumerate() {
        let mut delta = [0; 13];
        for (delta, (before, after)) in delta
            .iter_mut()
            .zip(fields(before).into_iter().zip(fields(after)))
        {
            *delta = after.saturating_sub(before);
        }
        super::counts::record(kind, delta);
    }
}

pub(in crate::claude_local_otel) fn prepared_fixture(check: impl FnOnce(&Path, &Reports)) {
    tests::prepared_fixture(check);
}

pub(in crate::claude_local_otel) fn unavailable_families() -> BTreeSet<String> {
    ACTIVE.with(|active| {
        active
            .borrow()
            .as_ref()
            .map(|r| r.newer.clone())
            .unwrap_or_default()
    })
}
pub(in crate::claude_local_otel) fn record_holds(
    held: &BTreeSet<String>,
    selected: &BTreeSet<String>,
) {
    ACTIVE.with(|active| {
        let mut active = active.borrow_mut();
        let Some(reader) = active.as_mut() else {
            return;
        };
        // A page only resolves the entities it actually reconsidered. An
        // unrelated selected family must not erase an older ongoing hold.
        reader
            .hold_since
            .retain(|id, _| !selected.contains(id) || held.contains(id));
        for id in held {
            reader.hold_since.entry(id.clone()).or_insert(reader.now);
        }
        let age = reader
            .hold_since
            .values()
            .map(|start| reader.now.saturating_sub(*start))
            .max()
            .unwrap_or(0);
        super::counts::record_holds(reader.hold_since.len() as u64, age);
    });
}

pub(super) fn active_api(support: &Path, session: &str) -> Option<io::Result<ApiOutput>> {
    ACTIVE.with(|active| {
        let mut active = active.borrow_mut();
        let reader = active.as_mut().filter(|reader| reader.support == support)?;
        Some(reader.load(session).and_then(|(mut api, _)| {
            if let Some(kind) = reader
                .entries
                .get(session)
                .and_then(|entry| entry.api_fatal)
            {
                return Err(io::Error::new(kind, "fatal sidecar API acquisition"));
            }
            let generation = if api.health.is_complete() {
                reader
                    .entries
                    .get(session)
                    .and_then(|entry| entry.api_generation.clone())
            } else {
                None
            };
            let rows = api.evidence.remove(session).unwrap_or_default();
            Ok((
                rows,
                ApiReadWitness {
                    health: api.health,
                    generation,
                },
            ))
        }))
    })
}
pub(super) fn active_paid_trace(support: &Path, session: &str) -> Option<io::Result<TraceOutput>> {
    ACTIVE.with(|active| {
        let mut active = active.borrow_mut();
        let reader = active.as_mut().filter(|reader| reader.support == support)?;
        Some(reader.load(session).and_then(|(_, report)| {
            let opened = reader
                .entries
                .get(session)
                .and_then(|entry| entry.trace_generation.clone())
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "trace generation unavailable")
                })?;
            Ok((report, ClaudeTraceReadGeneration { opened }))
        }))
    })
}
