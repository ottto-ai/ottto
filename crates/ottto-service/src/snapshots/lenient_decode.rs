// Persistence boundary only. Holds never grant proof, acceptance or retry.
use super::*;
use serde::ser::{SerializeMap, Serializer};
use serde_json::value::RawValue;
use std::io::{BufRead, Read, Seek, SeekFrom};
use std::sync::Arc;

// Source-owner admission: at most 1/8 of input, with these absolute ceilings.
// No parser-copy/census credit is consumed. Check before allocating raw bytes.
const HOLD_BYTES_MAX: u64 = 8 * 1024 * 1024;
const HOLD_COUNT_MAX: usize = 4096;

type HeldSlots = BTreeMap<String, Arc<HeldRaw>>;
#[derive(Debug, Clone, Default)]
pub(super) struct Holds(
    BTreeMap<&'static str, HeldSlots>,
    BTreeMap<&'static str, BTreeSet<String>>,
);
#[derive(Debug)]
struct HeldRaw(Box<RawValue>, Option<String>);
impl HeldRaw {
    fn get(&self) -> &str {
        self.0.get()
    }
}
impl crate::heap_layout_bound::HeapLayoutBound for HeldRaw {
    const STABLE_HEAP: bool = true;
    fn heap_bound(&self, c: &mut crate::heap_layout_bound::Counter) -> Option<()> {
        c.add(self.get().len())?;
        crate::heap_layout_bound::HeapLayoutBound::heap_bound(&self.1, c)
    }
}
impl Holds {
    pub(super) fn contains(&self, field: &str, key: &str) -> bool {
        self.0.get(field).is_some_and(|map| map.contains_key(key))
    }
    pub(super) fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
    pub(super) fn same_as(&self, other: &Self) -> bool {
        self.0.len() == other.0.len()
            && self.0.iter().all(|(field, map)| {
                other.0.get(field).is_some_and(|right| {
                    map.len() == right.len()
                        && map.iter().all(|(key, raw)| {
                            right.get(key).is_some_and(|value| raw.get() == value.get())
                        })
                })
            })
    }
}
impl crate::heap_layout_bound::HeapLayoutBound for Holds {
    fn heap_bound(&self, c: &mut crate::heap_layout_bound::Counter) -> Option<()> {
        crate::heap_layout_bound::HeapLayoutBound::heap_bound(&self.0, c)?;
        crate::heap_layout_bound::HeapLayoutBound::heap_bound(&self.1, c)
    }
    fn completed_heap_bound(&self, c: &mut crate::heap_layout_bound::Counter) -> Option<()> {
        crate::heap_layout_bound::HeapLayoutBound::completed_heap_bound(&self.0, c)?;
        crate::heap_layout_bound::HeapLayoutBound::completed_heap_bound(&self.1, c)
    }
}

struct WireMap<'a, T>(&'a BTreeMap<String, T>, Option<&'a HeldSlots>);
impl<T: Serialize> Serialize for WireMap<'_, T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(None)?;
        for (key, value) in self.0 {
            if !self.1.is_some_and(|held| held.contains_key(key)) {
                map.serialize_entry(key, value)?;
            }
        }
        if let Some(held) = self.1 {
            for (key, raw) in held {
                map.serialize_entry(key, raw.0.as_ref())?;
            }
        }
        map.end()
    }
}

impl Serialize for ScanIndex {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(None)?;
        macro_rules! field {
            ($name:ident) => {
                map.serialize_entry(stringify!($name), &self.$name)?
            };
            ($name:ident, $skip:path) => {
                if !$skip(&self.$name) {
                    field!($name);
                }
            };
            (held $name:ident) => {
                if !self.$name.is_empty() || self.decode_holds.0.contains_key(stringify!($name)) {
                    map.serialize_entry(
                        stringify!($name),
                        &WireMap(&self.$name, self.decode_holds.0.get(stringify!($name))),
                    )?;
                }
            };
        }
        field!(schema_version);
        field!(generation);
        field!(upload_context_fingerprint, Option::is_none);
        map.serialize_entry(
            "files",
            &WireMap(&self.files, self.decode_holds.0.get("files")),
        )?;
        field!(session_account_bindings, BTreeMap::is_empty);
        field!(terminal_jsonl_dispositions, BTreeMap::is_empty);
        field!(known_configured_scan_roots, BTreeSet::is_empty);
        field!(legacy_unresolved_root_file_witnesses, BTreeSet::is_empty);
        field!(codex_state_only_snapshot_fingerprints, BTreeMap::is_empty);
        field!(codex_state_only_blocked_session_ids, BTreeSet::is_empty);
        field!(codex_state_only_blocked_by_file, BTreeMap::is_empty);
        field!(codex_state_only_blocked_unattributed, BTreeSet::is_empty);
        field!(codex_state_only_blocked_legacy, BTreeSet::is_empty);
        field!(codex_state_only_blocked_attributed, std::ops::Not::not);
        field!(codex_parent_ownership_refs, BTreeSet::is_empty);
        field!(codex_parent_ownership_ledgers, BTreeMap::is_empty);
        field!(codex_parent_side_requests, BTreeMap::is_empty);
        field!(codex_parent_side, BTreeMap::is_empty);
        field!(codex_parent_side_generation, is_zero_u64);
        field!(codex_parent_proof_wrap_epoch, is_zero_u64);
        field!(codex_parent_prefix_proofs, BTreeMap::is_empty);
        field!(codex_parent_proof_cursor, Option::is_none);
        field!(codex_parent_side_cursor, Option::is_none);
        field!(codex_parent_proof_seq, is_zero_u64);
        field!(codex_proof_index_incarnation, String::is_empty);
        field!(claude_desktop_title_files, BTreeMap::is_empty);
        field!(held claude_account_family_witnesses);
        field!(held claude_account_family_pending);
        field!(held claude_usage_family_witnesses);
        field!(held claude_usage_family_pending);
        field!(claude_request_census, ClaudeRequestCensus::is_empty);
        field!(
            claude_request_census_shadow,
            ClaudeRequestCensusShadowState::is_empty
        );
        field!(held claude_usage_authority_quarantine);
        field!(claude_duplicate_request_owners, BTreeMap::is_empty);
        field!(claude_duplicate_request_witness_overflowed);
        field!(claude_owned_start_census, BTreeMap::is_empty);
        field!(claude_account_deferred_holds, BTreeMap::is_empty);
        field!(claude_duplicate_fence_rearm_attempt, is_zero_u8);
        field!(
            claude_duplicate_fence_next_full_rearm_unix_seconds,
            Option::is_none
        );
        field!(claude_request_identity_contract, Option::is_none);
        field!(claude_request_identity_contract_changed, std::ops::Not::not);
        field!(claude_desktop_store_cursor, Option::is_none);
        field!(claude_desktop_store_upper_bound, Option::is_none);
        field!(claude_desktop_store_sweep_had_errors);
        field!(claude_desktop_identity_census_complete);
        field!(claude_desktop_lineage_census_complete);
        field!(claude_desktop_census_witness, Option::is_none);
        field!(claude_desktop_store_retry_attempt);
        field!(
            claude_desktop_store_retry_not_before_unix_seconds,
            Option::is_none
        );
        field!(resume_after_path, Option::is_none);
        field!(resume_upper_bound_path, Option::is_none);
        field!(resume_census_window_end, Option::is_none);
        field!(bounded_sweep_had_unsettled_upload);
        field!(bounded_sweep_unsettled_causes, is_zero_u16);
        field!(traversal, Option::is_none);
        field!(claude_stale_family_carry, ClaudeStaleFamilyCarry::is_empty);
        field!(scan_residue_witness, Option::is_none);
        field!(historical_replay_generation, Option::is_none);
        field!(context_curve_capability_enabled, is_false);
        field!(context_curve_replay_epoch, is_zero_u64);
        field!(completed_context_curve_replay_generation, Option::is_none);
        field!(confirmed_empty_files, BTreeSet::is_empty);
        field!(file_snapshot_fingerprints, BTreeMap::is_empty);
        field!(snapshot_activity_at, BTreeMap::is_empty);
        field!(accepted_snapshot_fingerprints, BTreeSet::is_empty);
        field!(accepted_snapshot_fingerprint_ledger_version, is_zero_u8);
        field!(
            legacy_settlement_reconcile_after_fingerprint,
            Option::is_none
        );
        field!(held quarantined_snapshot_fingerprints);
        map.end()
    }
}

pub(super) const FIELDS: &[&str] = &[
    "schema_version",
    "generation",
    "upload_context_fingerprint",
    "files",
    "session_account_bindings",
    "terminal_jsonl_dispositions",
    "known_configured_scan_roots",
    "legacy_unresolved_root_file_witnesses",
    "codex_state_only_snapshot_fingerprints",
    "codex_state_only_blocked_session_ids",
    "codex_state_only_blocked_by_file",
    "codex_state_only_blocked_unattributed",
    "codex_state_only_blocked_legacy",
    "codex_state_only_blocked_attributed",
    "codex_parent_ownership_refs",
    "codex_parent_ownership_ledgers",
    "codex_parent_side_requests",
    "codex_parent_side",
    "codex_parent_side_generation",
    "codex_parent_proof_wrap_epoch",
    "codex_parent_prefix_proofs",
    "codex_parent_proof_cursor",
    "codex_parent_side_cursor",
    "codex_parent_proof_seq",
    "codex_proof_index_incarnation",
    "claude_desktop_title_files",
    "claude_account_family_witnesses",
    "claude_account_family_pending",
    "claude_usage_family_witnesses",
    "claude_usage_family_pending",
    "claude_request_census",
    "claude_request_census_shadow",
    "claude_usage_authority_quarantine",
    "claude_duplicate_request_owners",
    "claude_duplicate_request_witness_overflowed",
    "claude_owned_start_census",
    "claude_account_deferred_holds",
    "claude_duplicate_fence_rearm_attempt",
    "claude_duplicate_fence_next_full_rearm_unix_seconds",
    "claude_request_identity_contract",
    "claude_request_identity_contract_changed",
    "claude_desktop_store_cursor",
    "claude_desktop_store_upper_bound",
    "claude_desktop_store_sweep_had_errors",
    "claude_desktop_identity_census_complete",
    "claude_desktop_lineage_census_complete",
    "claude_desktop_census_witness",
    "claude_desktop_store_retry_attempt",
    "claude_desktop_store_retry_not_before_unix_seconds",
    "resume_after_path",
    "resume_upper_bound_path",
    "resume_census_window_end",
    "bounded_sweep_had_unsettled_upload",
    "bounded_sweep_unsettled_causes",
    "traversal",
    "claude_stale_family_carry",
    "scan_residue_witness",
    "historical_replay_generation",
    "context_curve_capability_enabled",
    "context_curve_replay_epoch",
    "completed_context_curve_replay_generation",
    "confirmed_empty_files",
    "file_snapshot_fingerprints",
    "snapshot_activity_at",
    "accepted_snapshot_fingerprints",
    "accepted_snapshot_fingerprint_ledger_version",
    "legacy_settlement_reconcile_after_fingerprint",
    "quarantined_snapshot_fingerprints",
];

#[derive(Debug, thiserror::Error)]
pub(super) enum Error {
    #[error("scan index JSON syntax: {0}")]
    Syntax(serde_json::Error),
    #[error("scan index I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("scan index refused: {0}")]
    Refused(&'static str),
    #[error("lenient_hold_budget_exceeded")]
    HoldBudget,
}
impl Error {
    pub(super) fn quarantines(&self) -> bool {
        matches!(self, Self::Syntax(_) | Self::HoldBudget)
    }
}
#[derive(Default)]
struct Counts {
    drops: ScanIndexLoadDrops,
    held: usize,
    files: usize,
    families: usize,
    authority_repairs: usize,
}
struct Decoder<R> {
    reader: R,
    input_len: u64,
    held_bytes: u64,
    held_count: usize,
    holds: Holds,
    counts: Counts,
    family_spans: BTreeMap<&'static str, Span>,
}
#[derive(Clone, Copy)]
struct Span {
    start: u64,
    len: u64,
}

// Lexical validation is separate from typed errors, including 1e400. IgnoredAny
// checks grammar without converting numeric tokens or constructing a DOM.
pub(super) fn read<R: BufRead + Seek>(
    mut reader: R,
    stage: &str,
    source: &'static str,
) -> std::result::Result<ScanIndex, Error> {
    take_dropped_codex_side_requests();
    let _side_request_counts = SideRequestCountGuard;
    let input_len = reader.seek(SeekFrom::End(0))?;
    reader.seek(SeekFrom::Start(0))?;
    serde_json::from_reader::<_, serde::de::IgnoredAny>(&mut reader).map_err(|error| {
        if error.is_io() {
            Error::Refused("input read failed")
        } else {
            Error::Syntax(error)
        }
    })?;
    reader.seek(SeekFrom::Start(0))?;
    let mut decoder = Decoder {
        reader,
        input_len,
        held_bytes: 0,
        held_count: 0,
        holds: Holds::default(),
        counts: Counts::default(),
        family_spans: BTreeMap::new(),
    };
    let result = decoder.index();
    if matches!(result, Err(Error::HoldBudget)) {
        emit_scan_index_containment_line(format!(
            "local snapshot scan index {stage}: source={source} lenient_hold_budget_exceeded=1"
        ));
    }
    let mut index = result?;
    controls(&index, source)?;
    index.decode_holds = decoder.holds;
    let semantic = index.drop_invalid_index_records();
    decoder.counts.drops.activity += semantic.activity;
    decoder.counts.drops.accepted += semantic.accepted;
    decoder.counts.drops.cursor += semantic.cursor;
    decoder.counts.drops.quarantine += semantic.quarantine;
    note_scan_index_record_drops_and_decode(
        stage,
        source,
        decoder.counts.drops,
        [
            decoder.counts.held,
            decoder.counts.files,
            decoder.counts.families,
            decoder.counts.authority_repairs,
        ],
    );
    index.retain_decodable_codex_parent_state();
    index.drop_unbound_claude_authority_records(stage);
    Ok(index)
}

pub(super) fn read_file(
    file: File,
    stage: &str,
    source: &'static str,
) -> std::result::Result<ScanIndex, Error> {
    let before = sampled_scan::codex_cursor::OpenStamp::capture(&file)?;
    let mut reader = BufReader::new(file);
    let result = read(&mut reader, stage, source);
    let after = sampled_scan::codex_cursor::OpenStamp::capture(reader.get_ref())?;
    if before != after {
        return Err(Error::Refused("input changed during decode"));
    }
    result
}
struct SideRequestCountGuard;
impl Drop for SideRequestCountGuard {
    fn drop(&mut self) {
        let dropped = take_dropped_codex_side_requests();
        crate::local_resource_diagnostics::codex_side_lifecycle::add(
            crate::local_resource_diagnostics::codex_side_lifecycle::Event::RequestRearmed,
            dropped,
        );
    }
}

pub(super) fn controls(index: &ScanIndex, source: &'static str) -> std::result::Result<(), Error> {
    if index.schema_version != SCAN_INDEX_SCHEMA_VERSION {
        return Err(Error::Refused("schema_version"));
    }
    if index.accepted_snapshot_fingerprint_ledger_version > SNAPSHOT_ACCEPTED_LEDGER_VERSION {
        alarm_future_scan_index_ledger(source, index.accepted_snapshot_fingerprint_ledger_version);
        return Err(Error::Refused("accepted-ledger version"));
    }
    Ok(())
}
impl<R: BufRead + Seek> Decoder<R> {
    fn ws(&mut self) -> std::result::Result<Option<u8>, Error> {
        loop {
            let bytes = self.reader.fill_buf()?;
            let skipped = bytes
                .iter()
                .take_while(|byte| byte.is_ascii_whitespace())
                .count();
            if skipped == 0 {
                return Ok(bytes.first().copied());
            }
            self.reader.consume(skipped);
        }
    }
    fn eat(&mut self, byte: u8) -> std::result::Result<(), Error> {
        if self.ws()? != Some(byte) {
            return Err(Error::Refused("unsupported shape"));
        }
        self.reader.consume(1);
        Ok(())
    }
    fn span(&mut self) -> std::result::Result<Span, Error> {
        self.ws()?;
        let start = self.reader.stream_position()?;
        let mut stream = serde_json::Deserializer::from_reader(&mut self.reader)
            .into_iter::<serde::de::IgnoredAny>();
        stream
            .next()
            .ok_or(Error::Refused("missing value"))?
            .map_err(|_| Error::Refused("changed input"))?;
        let len = stream.byte_offset() as u64;
        self.reader.seek(SeekFrom::Start(start + len))?;
        Ok(Span { start, len })
    }
    fn typed<T: serde::de::DeserializeOwned>(
        &mut self,
        span: Span,
    ) -> std::result::Result<T, Error> {
        self.reader.seek(SeekFrom::Start(span.start))?;
        let result = serde_json::from_reader((&mut self.reader).take(span.len))
            .map_err(|_| Error::Refused("record type"));
        self.reader.seek(SeekFrom::Start(span.start + span.len))?;
        result
    }
    fn raw(&mut self, span: Span) -> std::result::Result<Box<RawValue>, Error> {
        if self.held_count >= HOLD_COUNT_MAX
            || span.len > self.input_len / 8
            || self
                .held_bytes
                .checked_add(span.len)
                .is_none_or(|bytes| bytes > HOLD_BYTES_MAX.min(self.input_len / 8))
        {
            return Err(Error::HoldBudget);
        }
        // The lexical length and running admission are checked before allocation.
        self.reader.seek(SeekFrom::Start(span.start))?;
        let mut bytes = String::with_capacity(span.len as usize);
        (&mut self.reader)
            .take(span.len)
            .read_to_string(&mut bytes)?;
        RawValue::from_string(bytes).map_err(|_| Error::Refused("changed input"))
    }
    fn hold(
        &mut self,
        field: &'static str,
        key: String,
        span: Span,
    ) -> std::result::Result<(), Error> {
        let raw = self.raw(span)?;
        self.held_bytes += span.len;
        self.held_count += 1;
        let owner = (field == "files")
            .then(|| held_file_owner(&raw, &key))
            .flatten();
        self.holds
            .0
            .entry(field)
            .or_default()
            .insert(key, Arc::new(HeldRaw(raw, owner)));
        self.counts.held += 1;
        if field == "files" {
            self.counts.files += 1;
        } else if field != "quarantined_snapshot_fingerprints" {
            self.counts.families += 1;
        }
        Ok(())
    }
    fn records<T: serde::de::DeserializeOwned>(
        &mut self,
        field: &'static str,
        span: Span,
        debt: bool,
    ) -> std::result::Result<BTreeMap<String, T>, Error> {
        self.reader.seek(SeekFrom::Start(span.start))?;
        if self.ws()? != Some(b'{') {
            if debt {
                return Err(Error::Refused("unkeyed negative collection"));
            }
            self.counts.drops.activity += 1;
            return Ok(BTreeMap::new());
        }
        self.eat(b'{')?;
        let mut values = BTreeMap::new();
        while self.ws()? != Some(b'}') {
            let key_span = self.span()?;
            let key: String = self.typed(key_span)?;
            self.eat(b':')?;
            let value = self.span()?;
            if values.contains_key(&key) || self.holds.contains(field, &key) {
                return Err(Error::Refused("duplicate record key"));
            }
            match self.typed(value) {
                Ok(decoded) => {
                    values.insert(key, decoded);
                }
                Err(_) if debt => self.hold(field, key, value)?,
                Err(_) => {
                    self.counts.drops.activity += 1;
                }
            }
            self.reader.seek(SeekFrom::Start(value.start + value.len))?;
            if self.ws()? == Some(b',') {
                self.eat(b',')?;
            } else {
                break;
            }
        }
        self.eat(b'}')?;
        Ok(values)
    }
    fn accepted(&mut self, span: Span) -> std::result::Result<BTreeSet<String>, Error> {
        self.reader.seek(SeekFrom::Start(span.start))?;
        self.eat(b'[')?;
        let mut values = BTreeSet::new();
        while self.ws()? != Some(b']') {
            let value = self.span()?;
            match self.typed::<String>(value) {
                Ok(key) if is_snapshot_fingerprint(&key) => {
                    values.insert(key);
                }
                _ => self.counts.drops.accepted += 1,
            }
            if self.ws()? == Some(b',') {
                self.eat(b',')?;
            } else {
                break;
            }
        }
        self.eat(b']')?;
        Ok(values)
    }
    fn quarantines(
        &mut self,
        span: Span,
    ) -> std::result::Result<BTreeMap<String, SnapshotQuarantineRecord>, Error> {
        let mut values = self.records("quarantined_snapshot_fingerprints", span, true)?;
        self.repair_held(
            "quarantined_snapshot_fingerprints",
            &mut values,
            repaired_quarantine,
        )?;
        for (key, record) in &values {
            if !snapshot_quarantine_deadline_is_bounded(record) {
                self.holds
                    .1
                    .entry("quarantined_snapshot_fingerprints")
                    .or_default()
                    .insert(key.clone());
            }
        }
        Ok(values)
    }
    fn authorities(
        &mut self,
        span: Span,
    ) -> std::result::Result<BTreeMap<String, ClaudeUsageAuthorityQuarantineRecord>, Error> {
        let mut values = self.records("claude_usage_authority_quarantine", span, true)?;
        self.repair_held(
            "claude_usage_authority_quarantine",
            &mut values,
            repaired_authority,
        )?;
        Ok(values)
    }
    fn repair_held<T>(
        &mut self,
        field: &'static str,
        values: &mut BTreeMap<String, T>,
        repair: impl Fn(&RawValue) -> Option<T>,
    ) -> std::result::Result<(), Error> {
        let repairs = &mut self.holds.1;
        if let Some(held) = self.holds.0.get_mut(field) {
            held.retain(|key, raw| {
                if let Some(value) = repair(&raw.0) {
                    values.insert(key.clone(), value);
                    repairs.entry(field).or_default().insert(key.clone());
                    self.held_count -= 1;
                    self.held_bytes -= raw.get().len() as u64;
                    self.counts.held -= 1;
                    if field == "quarantined_snapshot_fingerprints" {
                        self.counts.drops.quarantine += 1;
                    } else {
                        self.counts.families -= 1;
                        self.counts.authority_repairs += 1;
                    }
                    false
                } else {
                    true
                }
            });
            if held.is_empty() {
                self.holds.0.remove(field);
            }
        }
        Ok(())
    }
    fn index(&mut self) -> std::result::Result<ScanIndex, Error> {
        let mut index = ScanIndex {
            accepted_snapshot_fingerprint_ledger_version: 0,
            ..ScanIndex::default()
        }; // legacy serde default
        let array = self.ws()? == Some(b'[');
        self.eat(if array { b'[' } else { b'{' })?;
        let mut seen = BTreeSet::new();
        let mut position = 0;
        while self.ws()? != Some(if array { b']' } else { b'}' }) {
            let name = if array {
                let name = *FIELDS
                    .get(position)
                    .ok_or(Error::Refused("extra positional field"))?;
                position += 1;
                Some(name)
            } else {
                let key = self.span()?;
                // Known field names have bounded escaped spellings. Unknown long
                // keys are ignored without allocating an unbounded String.
                let name = if key.len
                    <= (FIELDS.iter().map(|s| s.len()).max().unwrap_or(0) * 6 + 2) as u64
                {
                    let key: String = self.typed(key)?;
                    FIELDS.iter().copied().find(|name| *name == key)
                } else {
                    None
                };
                self.eat(b':')?;
                name
            };
            let value = self.span()?;
            if let Some(name) = name {
                if matches!(
                    name,
                    "claude_account_family_witnesses"
                        | "claude_account_family_pending"
                        | "claude_usage_family_witnesses"
                        | "claude_usage_family_pending"
                        | "claude_usage_authority_quarantine"
                ) {
                    self.family_spans.insert(name, value);
                }
                if !seen.insert(name) {
                    if name == "claude_request_census" {
                        index.claude_request_census = ClaudeRequestCensus::default();
                    } else if name == "claude_request_census_shadow" {
                        index.claude_request_census_shadow =
                            ClaudeRequestCensusShadowState::default();
                    } else {
                        return Err(Error::Refused("duplicate index field"));
                    }
                } else {
                    match name {
                        "schema_version" => index.schema_version = self.typed(value)?,
                        "generation" => index.generation = self.typed(value)?,
                        "upload_context_fingerprint" => {
                            index.upload_context_fingerprint = self.typed(value)?
                        }
                        "files" => index.files = self.records("files", value, true)?,
                        "session_account_bindings" => {
                            index.session_account_bindings = self.typed(value)?
                        }
                        "terminal_jsonl_dispositions" => {
                            index.terminal_jsonl_dispositions = self.typed(value)?
                        }
                        "known_configured_scan_roots" => {
                            index.known_configured_scan_roots = self.typed(value)?
                        }
                        "legacy_unresolved_root_file_witnesses" => {
                            index.legacy_unresolved_root_file_witnesses = self.typed(value)?
                        }
                        "codex_state_only_snapshot_fingerprints" => {
                            index.codex_state_only_snapshot_fingerprints = self.typed(value)?
                        }
                        "codex_state_only_blocked_session_ids" => {
                            index.codex_state_only_blocked_session_ids = self.typed(value)?
                        }
                        "codex_state_only_blocked_by_file" => {
                            index.codex_state_only_blocked_by_file = self.typed(value)?
                        }
                        "codex_state_only_blocked_unattributed" => {
                            index.codex_state_only_blocked_unattributed = self.typed(value)?
                        }
                        "codex_state_only_blocked_legacy" => {
                            index.codex_state_only_blocked_legacy = self.typed(value)?
                        }
                        "codex_state_only_blocked_attributed" => {
                            index.codex_state_only_blocked_attributed = self.typed(value)?
                        }
                        "codex_parent_ownership_refs" => {
                            index.codex_parent_ownership_refs = self.typed(value)?
                        }
                        "codex_parent_ownership_ledgers" => {
                            index.codex_parent_ownership_ledgers = self.typed(value)?
                        }
                        "codex_parent_side_requests" => {
                            index.codex_parent_side_requests = self
                                .census(value, "codex_parent_side_requests")?
                                .codex_parent_side_requests
                        }
                        "codex_parent_side" => {
                            index.codex_parent_side =
                                self.census(value, "codex_parent_side")?.codex_parent_side
                        }
                        "codex_parent_side_generation" => {
                            index.codex_parent_side_generation = self.typed(value)?
                        }
                        "codex_parent_proof_wrap_epoch" => {
                            index.codex_parent_proof_wrap_epoch = self.typed(value)?
                        }
                        "codex_parent_prefix_proofs" => {
                            index.codex_parent_prefix_proofs = self
                                .census(value, "codex_parent_prefix_proofs")?
                                .codex_parent_prefix_proofs
                        }
                        "codex_parent_proof_cursor" => {
                            index.codex_parent_proof_cursor = self.typed(value)?
                        }
                        "codex_parent_side_cursor" => {
                            index.codex_parent_side_cursor = self.typed(value)?
                        }
                        "codex_parent_proof_seq" => {
                            index.codex_parent_proof_seq = self.typed(value)?
                        }
                        "codex_proof_index_incarnation" => {
                            index.codex_proof_index_incarnation = self.typed(value)?
                        }
                        "claude_desktop_title_files" => {
                            index.claude_desktop_title_files = self.typed(value)?
                        }
                        "claude_account_family_witnesses" => {
                            index.claude_account_family_witnesses =
                                self.records("claude_account_family_witnesses", value, true)?
                        }
                        "claude_account_family_pending" => {
                            index.claude_account_family_pending =
                                self.records("claude_account_family_pending", value, true)?
                        }
                        "claude_usage_family_witnesses" => {
                            index.claude_usage_family_witnesses =
                                self.records("claude_usage_family_witnesses", value, true)?
                        }
                        "claude_usage_family_pending" => {
                            index.claude_usage_family_pending =
                                self.records("claude_usage_family_pending", value, true)?
                        }
                        "claude_request_census" => {
                            index.claude_request_census = self
                                .census(value, "claude_request_census")?
                                .claude_request_census
                        }
                        "claude_request_census_shadow" => {
                            index.claude_request_census_shadow = self
                                .census(value, "claude_request_census_shadow")?
                                .claude_request_census_shadow
                        }
                        "claude_usage_authority_quarantine" => {
                            index.claude_usage_authority_quarantine = self.authorities(value)?
                        }
                        "claude_duplicate_request_owners" => {
                            index.claude_duplicate_request_owners = self.typed(value)?
                        }
                        "claude_duplicate_request_witness_overflowed" => {
                            index.claude_duplicate_request_witness_overflowed = self.typed(value)?
                        }
                        "claude_owned_start_census" => {
                            index.claude_owned_start_census = self.typed(value)?
                        }
                        "claude_account_deferred_holds" => {
                            index.claude_account_deferred_holds = self.typed(value)?
                        }
                        "claude_duplicate_fence_rearm_attempt" => {
                            index.claude_duplicate_fence_rearm_attempt = self.typed(value)?
                        }
                        "claude_duplicate_fence_next_full_rearm_unix_seconds" => {
                            index.claude_duplicate_fence_next_full_rearm_unix_seconds =
                                self.typed(value)?
                        }
                        "claude_request_identity_contract" => {
                            index.claude_request_identity_contract = self.typed(value)?
                        }
                        "claude_request_identity_contract_changed" => {
                            index.claude_request_identity_contract_changed = self.typed(value)?
                        }
                        "claude_desktop_store_cursor" => {
                            index.claude_desktop_store_cursor = self.typed(value)?
                        }
                        "claude_desktop_store_upper_bound" => {
                            index.claude_desktop_store_upper_bound = self.typed(value)?
                        }
                        "claude_desktop_store_sweep_had_errors" => {
                            index.claude_desktop_store_sweep_had_errors = self.typed(value)?
                        }
                        "claude_desktop_identity_census_complete" => {
                            index.claude_desktop_identity_census_complete = self.typed(value)?
                        }
                        "claude_desktop_lineage_census_complete" => {
                            index.claude_desktop_lineage_census_complete = self.typed(value)?
                        }
                        "claude_desktop_census_witness" => {
                            index.claude_desktop_census_witness = self.typed(value)?
                        }
                        "claude_desktop_store_retry_attempt" => {
                            index.claude_desktop_store_retry_attempt = self.typed(value)?
                        }
                        "claude_desktop_store_retry_not_before_unix_seconds" => {
                            index.claude_desktop_store_retry_not_before_unix_seconds =
                                self.typed(value)?
                        }
                        "resume_after_path" => index.resume_after_path = self.typed(value)?,
                        "resume_upper_bound_path" => {
                            index.resume_upper_bound_path = self.typed(value)?
                        }
                        "resume_census_window_end" => {
                            index.resume_census_window_end = self.typed(value)?
                        }
                        "bounded_sweep_had_unsettled_upload" => {
                            index.bounded_sweep_had_unsettled_upload = self.typed(value)?
                        }
                        "bounded_sweep_unsettled_causes" => {
                            index.bounded_sweep_unsettled_causes = self
                                .census(value, "bounded_sweep_unsettled_causes")?
                                .bounded_sweep_unsettled_causes
                        }
                        "traversal" => index.traversal = self.typed(value)?,
                        "claude_stale_family_carry" => {
                            index.claude_stale_family_carry = self.typed(value)?
                        }
                        "scan_residue_witness" => index.scan_residue_witness = self.typed(value)?,
                        "historical_replay_generation" => {
                            index.historical_replay_generation = self.typed(value)?
                        }
                        "context_curve_capability_enabled" => {
                            index.context_curve_capability_enabled = self.typed(value)?
                        }
                        "context_curve_replay_epoch" => {
                            index.context_curve_replay_epoch = self.typed(value)?
                        }
                        "completed_context_curve_replay_generation" => {
                            index.completed_context_curve_replay_generation = self.typed(value)?
                        }
                        "confirmed_empty_files" => {
                            index.confirmed_empty_files = self.typed(value)?
                        }
                        "file_snapshot_fingerprints" => {
                            index.file_snapshot_fingerprints = self.typed(value)?
                        }
                        "snapshot_activity_at" => {
                            index.snapshot_activity_at =
                                self.records("snapshot_activity_at", value, false)?
                        }
                        "accepted_snapshot_fingerprints" => {
                            index.accepted_snapshot_fingerprints = self.accepted(value)?
                        }
                        "accepted_snapshot_fingerprint_ledger_version" => {
                            index.accepted_snapshot_fingerprint_ledger_version =
                                self.typed(value)?
                        }
                        "legacy_settlement_reconcile_after_fingerprint" => {
                            index.legacy_settlement_reconcile_after_fingerprint =
                                match self.typed(value) {
                                    Ok(cursor) => cursor,
                                    Err(_) => {
                                        self.counts.drops.cursor += 1;
                                        Some(lowest_legacy_settlement_cursor())
                                    }
                                }
                        }
                        "quarantined_snapshot_fingerprints" => {
                            index.quarantined_snapshot_fingerprints = self.quarantines(value)?
                        }
                        _ => unreachable!(),
                    }
                }
            }
            self.reader.seek(SeekFrom::Start(value.start + value.len))?;
            if self.ws()? == Some(b',') {
                self.eat(b',')?;
            } else {
                break;
            }
        }
        self.eat(if array { b']' } else { b'}' })?;
        if !seen.contains("files") {
            return Err(Error::Refused("missing files"));
        }

        self.freeze_held_families(&mut index)?;
        Ok(index)
    }
    fn freeze_held_families(&mut self, index: &mut ScanIndex) -> std::result::Result<(), Error> {
        // A held family proof/pending slot also freezes any intact correction
        // and exclusion state for that family. Existing reproof/prune code may
        // not erase its debt just because its typed witness is now absent.
        let roots = self
            .holds
            .0
            .iter()
            .filter(|(field, _)| field.starts_with("claude_"))
            .flat_map(|(_, slots)| slots.keys().cloned())
            .collect::<BTreeSet<_>>();
        if roots.is_empty() {
            return Ok(());
        }
        let fields = std::mem::take(&mut self.family_spans);
        for (field, span) in fields {
            self.reader.seek(SeekFrom::Start(span.start))?;
            self.eat(b'{')?;
            while self.ws()? != Some(b'}') {
                let key_span = self.span()?;
                let key: String = self.typed(key_span)?;
                self.eat(b':')?;
                let value = self.span()?;
                if roots.contains(&key) && !self.holds.contains(field, &key) {
                    self.hold(field, key.clone(), value)?;
                    if self
                        .holds
                        .1
                        .get_mut(field)
                        .is_some_and(|keys| keys.remove(&key))
                    {
                        self.counts.authority_repairs -= 1;
                    }
                    match field {
                        "claude_account_family_witnesses" => {
                            index.claude_account_family_witnesses.remove(&key);
                        }
                        "claude_account_family_pending" => {
                            index.claude_account_family_pending.remove(&key);
                        }
                        "claude_usage_family_witnesses" => {
                            index.claude_usage_family_witnesses.remove(&key);
                        }
                        "claude_usage_family_pending" => {
                            index.claude_usage_family_pending.remove(&key);
                        }
                        "claude_usage_authority_quarantine" => {
                            index.claude_usage_authority_quarantine.remove(&key);
                        }
                        _ => unreachable!(),
                    }
                }
                self.reader.seek(SeekFrom::Start(value.start + value.len))?;
                if self.ws()? == Some(b',') {
                    self.eat(b',')?;
                } else {
                    break;
                }
            }
            self.eat(b'}')?;
        }
        Ok(())
    }
    fn census(&mut self, span: Span, field: &str) -> std::result::Result<ScanIndex, Error> {
        self.reader.seek(SeekFrom::Start(span.start))?;
        let prefix = format!("{{\"files\":{{}},\"{field}\":");
        let reader = std::io::Cursor::new(prefix)
            .chain((&mut self.reader).take(span.len))
            .chain(std::io::Cursor::new(b"}"));
        claude_request_census::decode_index(reader).map_err(|_| Error::Refused("census decode"))
    }
}

impl ScanIndex {
    pub(super) fn decode_repairs_match(&self, working: &Self) -> bool {
        self.decode_holds.1.iter().all(|(field, keys)| {
            keys.iter().all(|key| match *field {
                "quarantined_snapshot_fingerprints" => {
                    match (
                        self.quarantined_snapshot_fingerprints.get(key),
                        working.quarantined_snapshot_fingerprints.get(key),
                    ) {
                        (Some(current), Some(prior)) => {
                            current.witness == prior.witness
                                && current.disposition == prior.disposition
                                && current.failed_reconstruction_count
                                    == prior.failed_reconstruction_count
                                && current.upload_body_witness == prior.upload_body_witness
                                && (current.retry_after_unix_seconds
                                    == prior.retry_after_unix_seconds
                                    || (current.retry_after_unix_seconds
                                        <= sampled_scan::now_seconds()
                                        && prior.retry_after_unix_seconds
                                            <= sampled_scan::now_seconds()))
                        }
                        (None, None) => true,
                        _ => false,
                    }
                }
                "claude_usage_authority_quarantine" => {
                    self.claude_usage_authority_quarantine.get(key)
                        == working.claude_usage_authority_quarantine.get(key)
                }
                _ => false,
            })
        })
    }
    pub(super) fn decode_holds_family(&self, root: &str) -> bool {
        [
            "claude_usage_authority_quarantine",
            "claude_account_family_witnesses",
            "claude_account_family_pending",
            "claude_usage_family_witnesses",
            "claude_usage_family_pending",
        ]
        .iter()
        .any(|field| self.decode_holds.contains(field, root))
    }
    pub(super) fn decode_holds_file(&self, key: &str) -> bool {
        self.decode_holds.contains("files", key)
            || claude_index_path_member_ref(Path::new(key))
                .is_some_and(|member| self.decode_holds_family(member.root))
    }
    pub(super) fn decode_holds_entity(&self, fingerprint: &str) -> bool {
        self.decode_holds
            .contains("quarantined_snapshot_fingerprints", fingerprint)
            || self
                .codex_state_only_snapshot_fingerprints
                .iter()
                .any(|(id, body)| body == fingerprint && self.decode_holds_codex_owner(id))
            || self
                .file_snapshot_fingerprints
                .iter()
                .any(|(key, members)| members.contains(fingerprint) && self.decode_holds_file(key))
            || self.files.iter().any(|(key, entry)| {
                entry.last_snapshot_fingerprint.as_deref() == Some(fingerprint)
                    && self.decode_holds_file(key)
            })
    }
    pub(super) fn decode_held_codex_owners(&self) -> impl Iterator<Item = Option<&str>> {
        self.decode_holds
            .0
            .get("files")
            .into_iter()
            .flat_map(|slots| slots.values())
            .map(|raw| raw.1.as_deref())
    }
    fn decode_holds_codex_owner(&self, id: &str) -> bool {
        let owner = codex_protected_owner(id);
        self.decode_held_codex_owners()
            .any(|held| held.is_none_or(|held| held == owner))
    }
    pub(super) fn decode_holds_snapshot(
        &self,
        source: SnapshotSource,
        item: &SnapshotItem,
    ) -> bool {
        if self.decode_holds_entity(&item.snapshot_fingerprint) {
            return true;
        }
        if source == SnapshotSource::ClaudeCode
            && self.decode_holds_family(claude_snapshot_family_root_ref(item))
        {
            return true;
        }
        if source == SnapshotSource::Codex && item.source_file_fingerprint.is_none() {
            // An opaque file may have lost the only logical-owner disclosure.
            // Preserve the state-only domain fence until protected history is understood.
            return self.decode_holds_codex_owner(&item.source_session_id);
        }
        false
    }
}

// Extension contract for MONEY's independently owned field: its record codec
// must drop/count only the bad selection and leave that file recensus-due.
// Ledger/version/decode errors return Err with the file unchanged. Add the
// field policy here when MONEY composes its codec; never default a failed ledger
// read, quarantine its file, or borrow census/parser-copy credit for it.

pub(super) fn read_bounded(bytes: &[u8]) -> anyhow::Result<ScanIndex> {
    // Preserve the caller byte bound and the existing census normalization and
    // node/depth admission before constructing native state. Original syntax is
    // checked before the optional census normalizer can replace damaged input.
    serde_json::from_slice::<serde::de::IgnoredAny>(bytes)?;
    let (normalized, duplicate_census, duplicate_shadow) =
        claude_request_census::normalized_bounded_bytes(bytes)?;
    bounded_shape(&normalized)?;
    let mut index = read(std::io::Cursor::new(normalized), "cas", "unattributed")?;
    if duplicate_census {
        index.claude_request_census = ClaudeRequestCensus::default();
    }
    if duplicate_shadow {
        index.claude_request_census_shadow = ClaudeRequestCensusShadowState::default();
    }
    Ok(index)
}

fn bounded_shape(bytes: &[u8]) -> anyhow::Result<()> {
    // Same 8,192-node/depth-64 gate as snapshot_retry::state_shape. The lexical
    // pass already proved grammar; count tokens without converting 1e400 to f64.
    let mut nodes = 0;
    let mut depth = 0usize;
    let mut quoted = false;
    let mut escaped = false;
    let mut scalar = false;
    for &byte in bytes {
        if quoted {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                quoted = false;
            }
            continue;
        }
        if byte.is_ascii_whitespace() || matches!(byte, b',' | b':') {
            scalar = false;
            continue;
        }
        if matches!(byte, b'}' | b']') {
            scalar = false;
            depth = depth.saturating_sub(1);
            continue;
        }
        let container = matches!(byte, b'{' | b'[');
        if byte == b'"' || container || !scalar {
            nodes += 1;
            anyhow::ensure!(
                nodes <= crate::snapshot_retry::STATE_NODES && depth <= 64,
                "optional snapshot state shape cap"
            );
        }
        if byte == b'"' {
            quoted = true;
            scalar = false;
        } else if container {
            depth += 1;
            scalar = false;
        } else {
            scalar = true;
        }
    }
    Ok(())
}

// Raw scalars borrow the admitted one-record capture. A malformed-present null
// must stay distinguishable from a missing legacy count.
fn present_raw<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> std::result::Result<Option<&'de RawValue>, D::Error> {
    <&RawValue>::deserialize(d).map(Some)
}
#[derive(Deserialize)]
struct QuarantineRepair<'a> {
    witness: SnapshotQuarantineWitness,
    #[serde(borrow)]
    retry_after_unix_seconds: &'a RawValue,
    #[serde(default)]
    upload_body_witness: Option<String>,
    #[serde(default, borrow, deserialize_with = "present_raw")]
    failed_reconstruction_count: Option<&'a RawValue>,
    #[serde(default)]
    disposition: SnapshotQuarantineDisposition,
}
fn repaired_quarantine(raw: &RawValue) -> Option<SnapshotQuarantineRecord> {
    let wire: QuarantineRepair<'_> = serde_json::from_str(raw.get()).ok()?;
    let terminal = wire.disposition != SnapshotQuarantineDisposition::RetryPending;
    let failed_reconstruction_count = wire.failed_reconstruction_count.map_or(1, |raw| {
        serde_json::from_str(raw.get()).unwrap_or(if terminal {
            MAX_SNAPSHOT_RECONSTRUCTION_FAILURES
        } else {
            MAX_SNAPSHOT_RECONSTRUCTION_FAILURES - 1
        })
    });
    let mut record = SnapshotQuarantineRecord {
        witness: wire.witness,
        retry_after_unix_seconds: serde_json::from_str(wire.retry_after_unix_seconds.get())
            .unwrap_or(0),
        upload_body_witness: wire.upload_body_witness,
        failed_reconstruction_count,
        disposition: wire.disposition,
    };
    normalize_snapshot_quarantine_record(&mut record, sampled_scan::now_seconds());
    Some(record)
}
#[derive(Deserialize)]
struct AuthorityRepair<'a> {
    contract: String,
    proven_witness_fingerprint: String,
    member_source_file_fingerprints: BTreeMap<String, String>,
    #[serde(default, borrow, deserialize_with = "present_raw")]
    failed_reconstruction_count: Option<&'a RawValue>,
    #[serde(default)]
    disposition: ClaudeUsageAuthorityQuarantineDisposition,
    #[serde(borrow)]
    retry_after_unix_seconds: &'a RawValue,
    #[serde(default)]
    proof_correction: Option<ClaudeAuthorityProofCorrection>,
}
fn repaired_authority(raw: &RawValue) -> Option<ClaudeUsageAuthorityQuarantineRecord> {
    let wire: AuthorityRepair<'_> = serde_json::from_str(raw.get()).ok()?;
    let terminal = wire.disposition == ClaudeUsageAuthorityQuarantineDisposition::UnprovenTerminal;
    let count: u8 = wire.failed_reconstruction_count.map_or(1, |raw| {
        serde_json::from_str(raw.get()).unwrap_or(if terminal {
            MAX_CLAUDE_USAGE_AUTHORITY_FAILURES
        } else {
            MAX_CLAUDE_USAGE_AUTHORITY_FAILURES - 1
        })
    });
    let mut record = ClaudeUsageAuthorityQuarantineRecord {
        contract: wire.contract,
        proven_witness_fingerprint: wire.proven_witness_fingerprint,
        member_source_file_fingerprints: wire.member_source_file_fingerprints,
        failed_reconstruction_count: if terminal {
            MAX_CLAUDE_USAGE_AUTHORITY_FAILURES
        } else {
            count.clamp(1, MAX_CLAUDE_USAGE_AUTHORITY_FAILURES - 1)
        },
        disposition: wire.disposition,
        proof_correction: wire.proof_correction,
        retry_after_unix_seconds: if terminal {
            0
        } else {
            serde_json::from_str(wire.retry_after_unix_seconds.get()).unwrap_or(0)
        },
    };
    if record.retry_after_unix_seconds
        > sampled_scan::now_seconds()
            .saturating_add(CLAUDE_USAGE_AUTHORITY_RETRY_SECONDS.saturating_mul(2))
    {
        record.retry_after_unix_seconds = 0;
    }
    claude_authority_record_contract_is_valid(&record).then_some(record)
}

fn held_file_owner(raw: &RawValue, key: &str) -> Option<String> {
    #[derive(Deserialize)]
    struct Owner<'a> {
        #[serde(default, borrow)]
        codex_protected_owner: Option<&'a str>,
    }
    let owner: Owner<'_> = serde_json::from_str(raw.get()).ok()?;
    if let Some(owner) = owner.codex_protected_owner {
        return valid_codex_protected_owner(owner).then(|| owner.to_owned());
    }
    let names = codex_session_id_candidates_from_path(Path::new(key));
    (names.len() == 1).then(|| codex_protected_owner(&names[0]))
}
