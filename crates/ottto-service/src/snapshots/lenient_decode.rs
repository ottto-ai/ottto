// Persistence boundary only. Holds never grant proof, acceptance or retry.
use super::*;
use serde::ser::{SerializeMap, Serializer};
use serde_json::value::RawValue;
use std::io::{BufRead, Read, Seek, SeekFrom};
use std::sync::Arc;

// Source-owner admission: input/8 with a 1 MiB floor and 8 MiB ceiling.
// No parser-copy/census credit is consumed. Check before allocating raw bytes.
const HOLD_BYTES_MAX: u64 = 8 * 1024 * 1024;
const HOLD_BYTES_MIN: u64 = 1024 * 1024;
pub(super) fn hold_bytes_limit(input_len: u64) -> u64 {
    (input_len / 8).clamp(HOLD_BYTES_MIN, HOLD_BYTES_MAX)
}
const HOLD_COUNT_MAX: usize = 4096;
// Inline bookkeeping retained for each slot: key/map entries, shared payload
// and Arc counters, and both fixed-size scope keys. Tree-node slack remains
// O(1) per hold, as in the native typed maps; no corpus-sized metadata credit.
const HOLD_RECORD_OVERHEAD: u64 = (std::mem::size_of::<(String, Arc<HeldRaw>)>()
    + std::mem::size_of::<HeldRaw>()
    + 2 * std::mem::size_of::<usize>()
    + 2 * std::mem::size_of::<[u8; 32]>()
    + std::mem::size_of::<(&str, HeldSlots)>()) as u64;

type HeldSlots = BTreeMap<String, Arc<HeldRaw>>;
#[derive(Debug, Clone, Default)]
pub(super) struct Holds(
    BTreeMap<&'static str, HeldSlots>,
    RepairProvenance,
    BTreeSet<[u8; 32]>, // held file family roots; fixed-size metadata per hold
    BTreeSet<[u8; 32]>, // known protected owners; no reverse file scan
    bool,               // any held file has unknown ownership
);
// Fixed-size multiset commitment to negative records repaired/dropped at the
// persistence boundary. Neither corpus size nor Clone adds retained allocations.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct RepairProvenance {
    sum: u128,
    count: u64,
}
impl RepairProvenance {
    fn entry(field: &str, key: &str, raw_hash: [u8; 32]) -> u128 {
        let mut hash = Sha256::new();
        hash.update((field.len() as u64).to_le_bytes());
        hash.update(field.as_bytes());
        hash.update((key.len() as u64).to_le_bytes());
        hash.update(key.as_bytes());
        hash.update(raw_hash);
        u128::from_le_bytes(hash.finalize()[..16].try_into().expect("digest prefix"))
    }
    fn add(&mut self, field: &str, key: &str, raw_hash: [u8; 32]) {
        self.sum = self.sum.wrapping_add(Self::entry(field, key, raw_hash));
        self.count = self
            .count
            .checked_add(1)
            .expect("input record count fits u64");
    }
    fn remove(&mut self, field: &str, key: &str, raw_hash: [u8; 32]) {
        self.sum = self.sum.wrapping_sub(Self::entry(field, key, raw_hash));
        self.count = self.count.checked_sub(1).expect("record was repaired");
    }
}
#[derive(Debug)]
struct HeldRaw(Box<RawValue>, Option<std::ops::Range<usize>>, u64); // admitted key/value/bookkeeping charge
impl HeldRaw {
    fn get(&self) -> &str {
        self.0.get()
    }
    fn owner(&self) -> Option<&str> {
        self.1
            .as_ref()
            .and_then(|span| self.get().get(span.clone()))
    }
}
impl crate::heap_layout_bound::HeapLayoutBound for HeldRaw {
    const STABLE_HEAP: bool = true;
    fn heap_bound(&self, c: &mut crate::heap_layout_bound::Counter) -> Option<()> {
        // The optional owner is an inline range into this immutable raw slot.
        c.add(self.get().len())
    }
}
impl Holds {
    pub(super) fn contains_field(&self, field: &str) -> bool {
        self.0.get(field).is_some_and(|slots| !slots.is_empty())
    }
    pub(super) fn file_keys(&self) -> impl Iterator<Item = &str> {
        self.0
            .get("files")
            .into_iter()
            .flat_map(|slots| slots.keys())
            .map(String::as_str)
    }

    fn rebuild_scopes(&mut self) {
        if self.0.is_empty() {
            // Removing the final repaired slot can leave an allocated empty
            // BTree root. Published empty Holds must own no container storage;
            // otherwise a repair-only corpus would retain that parser scratch.
            self.0 = BTreeMap::new();
            self.2 = BTreeSet::new();
            self.3 = BTreeSet::new();
            self.4 = false;
            return;
        }
        let files = self.0.get("files");
        self.2 = files
            .into_iter()
            .flat_map(|slots| slots.keys())
            .filter_map(|key| {
                claude_index_path_member_ref(Path::new(key)).map(|member| repair_key(member.root))
            })
            .collect();
        self.3 = files
            .into_iter()
            .flat_map(|slots| slots.values())
            .filter_map(|raw| raw.owner().map(repair_key))
            .collect();
        self.4 = files
            .into_iter()
            .flat_map(|slots| slots.values())
            .any(|raw| raw.owner().is_none());
    }
    #[cfg(test)]
    pub(super) fn provenance_receipt(&self) -> (usize, u64, u128) {
        (
            std::mem::size_of::<RepairProvenance>(),
            self.1.count,
            self.1.sum,
        )
    }
    #[cfg(test)]
    pub(super) fn clone_provenance_for_test(&self) -> impl Sized {
        self.1
    }
    pub(super) fn contains(&self, field: &str, key: &str) -> bool {
        self.0.get(field).is_some_and(|map| map.contains_key(key))
    }
    // Admitted key/value/bookkeeping charge of every held slot.
    pub(super) fn held_bytes(&self) -> u64 {
        self.0
            .values()
            .flat_map(|slots| slots.values())
            .map(|raw| raw.2)
            .sum()
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
    // Both maps and the shared raw payloads are immutable without &mut self.
    const STABLE_HEAP: bool = true;
    fn heap_bound(&self, c: &mut crate::heap_layout_bound::Counter) -> Option<()> {
        // Only Default/Clone or rebuild_scopes-published values escape the
        // decoder. Their empty containers have been replaced with fresh ones;
        // unlike arbitrary empty BTrees they cannot retain allocated roots.
        if self.0.is_empty() && self.2.is_empty() && self.3.is_empty() {
            return Some(());
        }
        crate::heap_layout_bound::HeapLayoutBound::heap_bound(&self.0, c)?;
        crate::heap_layout_bound::HeapLayoutBound::heap_bound(&self.2, c)?;
        crate::heap_layout_bound::HeapLayoutBound::heap_bound(&self.3, c)
    }
    fn completed_heap_bound(&self, c: &mut crate::heap_layout_bound::Counter) -> Option<()> {
        if self.0.is_empty() && self.2.is_empty() && self.3.is_empty() {
            return Some(());
        }
        crate::heap_layout_bound::HeapLayoutBound::completed_heap_bound(&self.0, c)?;
        crate::heap_layout_bound::HeapLayoutBound::completed_heap_bound(&self.2, c)?;
        crate::heap_layout_bound::HeapLayoutBound::completed_heap_bound(&self.3, c)
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
        if !self.persistence_available() {
            return Err(serde::ser::Error::custom("scan_index_map_unavailable"));
        }
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
        field!(claude_retired_family_tombstones);
        field!(claude_retired_family_tombstones_initialized);
        field!(claude_retired_family_tombstones_uncertain, is_false);
        field!(claude_duplicate_request_owners, BTreeMap::is_empty);
        field!(claude_duplicate_request_witness_overflowed);
        field!(claude_owned_start_census, BTreeMap::is_empty);
        field!(claude_account_deferred_holds, BTreeMap::is_empty);
        field!(claude_duplicate_fence_rearm_attempt, is_zero_u8);
        field!(
            claude_duplicate_fence_next_full_rearm_unix_seconds,
            Option::is_none
        );
        field!(
            claude_full_rearm_progress,
            ClaudeFullRearmProgress::is_empty
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
        field!(claude_history_cutoff_unix_seconds, Option::is_none);
        field!(claude_history_gate_loaded, std::ops::Not::not);
        field!(claude_history_move_not_full, std::ops::Not::not);
        field!(claude_history_move_released, std::ops::Not::not);
        field!(accepted_incidence_pending_census, std::ops::Not::not);
        field!(accepted_rebuild_incidence, BTreeMap::is_empty);
        field!(accepted_rebuild_pending_since_unix_seconds, Option::is_none);
        field!(accepted_rebuild_last_alarm_unix_seconds, Option::is_none);
        field!(codex_counting_tombstones, BTreeMap::is_empty);
        field!(
            codex_counting_evicted_legacy,
            codex_counting_version::EvictedLegacyOwners::is_empty
        );
        field!(upload_ack_retirement_handoff, Option::is_none);
        field!(held_audit_progress, Option::is_none);
        field!(
            claude_money_birth_store,
            claude_money_birth_store::BirthStore::is_empty
        );
        field!(
            claude_copy_removals,
            claude_request_money::copy_removals::CopyRemovals::is_unwritten
        );
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
    "claude_retired_family_tombstones",
    "claude_retired_family_tombstones_initialized",
    "claude_retired_family_tombstones_uncertain",
    "claude_duplicate_request_owners",
    "claude_duplicate_request_witness_overflowed",
    "claude_owned_start_census",
    "claude_account_deferred_holds",
    "claude_duplicate_fence_rearm_attempt",
    "claude_duplicate_fence_next_full_rearm_unix_seconds",
    "claude_full_rearm_progress",
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
    "claude_history_cutoff_unix_seconds",
    "claude_history_gate_loaded",
    "claude_history_move_not_full",
    "claude_history_move_released",
    "accepted_incidence_pending_census",
    "accepted_rebuild_incidence",
    "accepted_rebuild_pending_since_unix_seconds",
    "accepted_rebuild_last_alarm_unix_seconds",
    "codex_counting_tombstones",
    "reread_guard", // TOMBSTONE: decode-and-drop; preserve the legacy positional slot.
    "codex_counting_evicted_legacy",
    "upload_ack_retirement_handoff",
    "held_audit_progress",
    "claude_money_birth_store",
    "claude_desktop_store_inventory", // Decoded and ignored; never serialized.
    "claude_copy_removals",
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
    /// Content-free kind for refusal lines.
    pub(super) fn kind(&self) -> &'static str {
        match self {
            Self::Syntax(_) => "syntax",
            Self::Io(_) => "io",
            Self::Refused(_) => "strict_decode",
            Self::HoldBudget => "hold_budget",
        }
    }
}

/// Which fields one `Decoder::index` pass decodes; every other field is
/// skipped by its lexical span, unread.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Pass {
    /// Controls and counters, before any record can spend hold admission.
    Headers,
    /// The headers plus `IDENTITY_CARRY_FIELDS` (`read_identity_carry`).
    IdentityCarry,
    Full,
}
fn header_field(name: &str) -> bool {
    matches!(
        name,
        "schema_version"
            | "generation"
            | "accepted_snapshot_fingerprint_ledger_version"
            | "codex_parent_side_generation"
            | "codex_parent_proof_wrap_epoch"
            | "codex_parent_proof_seq"
            | "codex_proof_index_incarnation"
    )
}
/// SI-718-O1: the session-identity state a user Repair override rebuild
/// carries from the damaged index (`ScanIndex::carry_identity_from`), and the
/// replay generations without which the rebuild would arm a replay the
/// damaged index had completed (that replay clears carried state). Each uses
/// the load's own field decoder; tombstone loss fences without refusing
/// identity carry, and the accepted ledger keeps the load's rule
/// that a malformed fingerprint vouched for nothing.
pub(super) const IDENTITY_CARRY_FIELDS: &[&str] = &[
    // These gate authority re-entry. Carry their own lenient, fail-closed
    // decoding policy, including uncertainty after lost retirement evidence.
    "claude_retired_family_tombstones",
    "claude_retired_family_tombstones_initialized",
    "claude_retired_family_tombstones_uncertain",
    "session_account_bindings",
    "claude_account_deferred_holds",
    "claude_request_identity_contract",
    "claude_request_identity_contract_changed",
    "claude_owned_start_census",
    "claude_stale_family_carry",
    "claude_duplicate_request_owners",
    "claude_duplicate_request_witness_overflowed",
    "accepted_snapshot_fingerprints",
    "file_snapshot_fingerprints",
    "accepted_incidence_pending_census",
    "accepted_rebuild_incidence",
    "accepted_rebuild_pending_since_unix_seconds",
    "accepted_rebuild_last_alarm_unix_seconds",
    "historical_replay_generation",
    "context_curve_capability_enabled",
    "context_curve_replay_epoch",
    "completed_context_curve_replay_generation",
];
#[derive(Default)]
struct Counts {
    drops: ScanIndexLoadDrops,
    held: usize,
    files: usize,
    families: usize,
    authority_repairs: usize,
    // Decode-only provenance, never persisted or copied from an index.
    tombstone_marker_intact: bool,
}
struct Decoder<R> {
    reader: R,
    input_len: u64,
    held_bytes: u64,
    held_count: usize,
    holds: Holds,
    counts: Counts,
    family_spans: BTreeMap<&'static str, Span>,
    census_resources: [bool; 2],
    persistence_map: bool,
}
#[derive(Clone, Copy)]
struct Span {
    start: u64,
    len: u64,
    resource: bool,
}

/// Replace one optional provenance token with null without retaining its
/// bytes. The lexical pass already checked the original grammar and depth.
struct AbsentMarkerReader<'a, R> {
    reader: &'a mut R,
    prefix: u64,
    marker_end: u64,
    suffix: u64,
    replacement: &'static [u8],
    skipped: bool,
}
impl<R: Read + Seek> Read for AbsentMarkerReader<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if self.prefix > 0 {
            let n = self.reader.by_ref().take(self.prefix).read(buf)?;
            self.prefix -= n as u64;
            return Ok(n);
        }
        if !self.skipped {
            self.reader.seek(SeekFrom::Start(self.marker_end))?;
            self.skipped = true;
        }
        if !self.replacement.is_empty() {
            return self.replacement.read(buf);
        }
        let n = self.reader.by_ref().take(self.suffix).read(buf)?;
        self.suffix -= n as u64;
        Ok(n)
    }
}

// Constant-space gate over ORIGINAL bytes. No nesting tags/parent stack are
// retained. Serde grammar checks run only after this gate caps their depth;
// optional resource evidence is drained before it can reach a Serde scanner.
const MAX_JSON_DEPTH: usize = claude_request_census::MAX_EVIDENCE_DEPTH;
fn json_ws(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\r' | b'\n')
}
fn syntax() -> Error {
    Error::Syntax(<serde_json::Error as serde::de::Error>::custom(
        "invalid scan index JSON",
    ))
}
fn peek<R: BufRead>(reader: &mut R) -> std::result::Result<Option<u8>, Error> {
    Ok(reader.fill_buf()?.first().copied())
}
fn whitespace<R: BufRead>(reader: &mut R) -> std::result::Result<Option<u8>, Error> {
    loop {
        let bytes = reader.fill_buf()?;
        let count = bytes.iter().take_while(|&&byte| json_ws(byte)).count();
        if count == 0 {
            return Ok(bytes.first().copied());
        }
        reader.consume(count);
    }
}
#[derive(Clone, Copy, Default)]
enum NumberState {
    #[default]
    None,
    Sign,
    Zero,
    Integer,
    Dot,
    Fraction,
    Exponent,
    ExponentSign,
    ExponentDigits,
}
impl NumberState {
    fn finish(&mut self) -> std::result::Result<(), Error> {
        if matches!(
            self,
            Self::Sign | Self::Dot | Self::Exponent | Self::ExponentSign
        ) {
            return Err(syntax());
        }
        *self = Self::None;
        Ok(())
    }
    fn byte(&mut self, byte: u8) -> std::result::Result<(), Error> {
        if json_ws(byte) || matches!(byte, b'{' | b'[' | b'}' | b']' | b',' | b':') {
            return self.finish();
        }
        *self = match (*self, byte) {
            (Self::None, b'-') => Self::Sign,
            (Self::None | Self::Sign, b'0') => Self::Zero,
            (Self::None | Self::Sign, b'1'..=b'9') => Self::Integer,
            (Self::Integer, b'0'..=b'9') => Self::Integer,
            (Self::Zero | Self::Integer, b'.') => Self::Dot,
            (Self::Dot | Self::Fraction, b'0'..=b'9') => Self::Fraction,
            (Self::Zero | Self::Integer | Self::Fraction, b'e' | b'E') => Self::Exponent,
            (Self::Exponent, b'+' | b'-') => Self::ExponentSign,
            (Self::Exponent | Self::ExponentSign | Self::ExponentDigits, b'0'..=b'9') => {
                Self::ExponentDigits
            }
            (Self::None, _) => Self::None, // strings/literals checked after the gate
            _ => return Err(syntax()),
        };
        Ok(())
    }
}
fn lexical_optional_span<R: BufRead + Seek>(reader: &mut R) -> std::result::Result<Span, Error> {
    // Match CensusRead's complete field drain, including leading/trailing
    // whitespace. Defer grammar until resource classification is final: an
    // early bad token must not quarantine later over-limit optional evidence.
    let start = reader.stream_position()?;
    let mut len = 0u64;
    let mut depth = 0usize;
    let mut quoted = false;
    let mut escaped = false;
    let mut resource = false;
    while let Some(byte) = peek(reader)? {
        if !quoted && depth == 0 && matches!(byte, b',' | b'}' | b']') {
            break;
        }
        reader.consume(1);
        len += 1;
        resource |= len > claude_request_census::MAX_RAW_BYTES as u64;
        if quoted {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                quoted = false;
            }
        } else {
            match byte {
                b'"' => quoted = true,
                b'{' | b'[' => {
                    depth = depth
                        .checked_add(1)
                        .ok_or(Error::Refused("nesting resource cap"))?;
                    resource |= depth > MAX_JSON_DEPTH;
                }
                b'}' | b']' => depth = depth.saturating_sub(1),
                _ => {}
            }
        }
    }
    if quoted || depth != 0 {
        return Err(syntax());
    }
    Ok(Span {
        start,
        len,
        resource,
    })
}
fn lexical_span<R: BufRead + Seek>(
    reader: &mut R,
    optional: bool,
    base_depth: usize,
) -> std::result::Result<Span, Error> {
    if optional {
        return lexical_optional_span(reader);
    }
    let first = whitespace(reader)?.ok_or_else(syntax)?;
    if matches!(first, b',' | b'}' | b']' | b':') {
        return Err(syntax());
    }
    let start = reader.stream_position()?;
    let compound = matches!(first, b'{' | b'[' | b'"');
    let mut len = 0u64;
    let mut depth = 0usize;
    let mut quoted = false;
    let mut escaped = false;
    let mut number = NumberState::None;
    loop {
        let Some(byte) = peek(reader)? else {
            if depth != 0 || quoted {
                return Err(syntax());
            }
            break;
        };
        if len > 0 && depth == 0 && !quoted && (json_ws(byte) || matches!(byte, b',' | b'}' | b']'))
        {
            break;
        }
        reader.consume(1);
        len += 1;
        if quoted {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                quoted = false;
            }
        } else {
            number.byte(byte)?;
            match byte {
                b'"' => {
                    quoted = true;
                    number = NumberState::None;
                }
                b'{' | b'[' => {
                    depth = depth
                        .checked_add(1)
                        .ok_or(Error::Refused("nesting resource cap"))?;
                    if depth.saturating_add(base_depth) > MAX_JSON_DEPTH {
                        return Err(Error::Refused("main document nesting resource cap"));
                    }
                }
                b'}' | b']' => depth = depth.checked_sub(1).ok_or_else(syntax)?,
                _ => {}
            }
        }
        if compound && len > 0 && depth == 0 && !quoted {
            break;
        }
    }
    number.finish()?;
    Ok(Span {
        start,
        len,
        resource: false,
    })
}
fn checked_grammar<R: BufRead + Seek>(
    reader: &mut R,
    span: Span,
) -> std::result::Result<(), Error> {
    // Only admitted depth reaches this library parser. Its scratch is bounded
    // by MAX_JSON_DEPTH, never the depth of discarded original evidence.
    // Pinned serde_json 1.0.149 deserialize_ignored_any calls iterative
    // ignore_value directly; the native 128-level check_recursion is not used.
    reader.seek(SeekFrom::Start(span.start))?;
    serde_json::from_reader::<_, serde::de::IgnoredAny>((&mut *reader).take(span.len)).map_err(
        |error| {
            if error.is_io() {
                Error::Refused("input read failed")
            } else {
                Error::Syntax(error)
            }
        },
    )?;
    reader.seek(SeekFrom::Start(span.start + span.len))?;
    Ok(())
}
fn validate_original<R: BufRead + Seek>(reader: &mut R) -> std::result::Result<[bool; 2], Error> {
    reader.seek(SeekFrom::Start(0))?;
    let first = whitespace(reader)?.ok_or_else(syntax)?;
    let array = first == b'[';
    if !matches!(first, b'{' | b'[') {
        let span = lexical_span(reader, false, 0)?;
        checked_grammar(reader, span)?;
        if whitespace(reader)?.is_some() {
            return Err(syntax());
        }
        return Err(Error::Refused("index shape"));
    }
    reader.consume(1);
    let close = if array { b']' } else { b'}' };
    let mut position = 0;
    let mut resources = [false; 2];
    if whitespace(reader)? != Some(close) {
        loop {
            let name = if array {
                FIELDS.get(position).copied()
            } else {
                if whitespace(reader)? != Some(b'"') {
                    return Err(syntax());
                }
                let key = lexical_span(reader, false, 1)?;
                checked_grammar(reader, key)?;
                let name = if key.len <= 512 {
                    reader.seek(SeekFrom::Start(key.start))?;
                    let name = serde_json::from_reader::<_, String>((&mut *reader).take(key.len))
                        .map_err(Error::Syntax)?;
                    reader.seek(SeekFrom::Start(key.start + key.len))?;
                    FIELDS.iter().copied().find(|field| *field == name)
                } else {
                    None
                };
                if whitespace(reader)? != Some(b':') {
                    return Err(syntax());
                }
                reader.consume(1);
                name
            };
            let optional = optional_census(name) || optional_money_hint(name);
            // CensusRead streams positional-array separator whitespace before
            // capture; object-field evidence starts immediately after ':'.
            if array {
                whitespace(reader)?;
            }
            let value = lexical_span(reader, optional, 1)?;
            if optional {
                if matches!(
                    name,
                    Some("claude_request_census" | "claude_request_census_shadow")
                ) {
                    resources[usize::from(name == Some("claude_request_census_shadow"))] |=
                        value.resource;
                }
                if !value.resource {
                    checked_grammar(reader, value)?;
                }
            }
            position += 1;
            match whitespace(reader)? {
                Some(byte) if byte == close => break,
                Some(b',') => {
                    reader.consume(1);
                }
                _ => return Err(syntax()),
            }
        }
    }
    reader.consume(1);
    if whitespace(reader)?.is_some() {
        return Err(syntax());
    }
    reader.seek(SeekFrom::Start(0))?;
    // CensusRead now drains depth/byte RESOURCE evidence to null. Everything
    // else was depth-gated above. This checks full JSON grammar without a DOM,
    // including delimiter kinds/commas and grammar in admitted optional data.
    claude_request_census::validate_gated_syntax(&mut *reader).map_err(|error| {
        if error.is_io() {
            Error::Refused("input read failed")
        } else {
            Error::Syntax(error)
        }
    })?;
    reader.seek(SeekFrom::Start(0))?;
    Ok(resources)
}
/// Local money hints: damage drops the hint, never the index.
fn optional_money_hint(name: Option<&str>) -> bool {
    matches!(
        name,
        Some("claude_money_birth_store" | "claude_copy_removals")
    )
}

fn optional_census(name: Option<&str>) -> bool {
    matches!(
        name,
        Some("claude_request_census" | "claude_request_census_shadow" | "reread_guard")
    )
}

fn note_refusal(error: &Error, stage: &str, source: &str) {
    let kind = match error {
        // The future-ledger path already has its once-per-source alarm. Keep
        // that existing counter/alarm contract rather than adding repeats.
        Error::Refused("accepted-ledger version") => return,
        Error::Refused("schema_version") => "control",
        Error::Refused("duplicate index field" | "duplicate record key") => "duplicate",
        Error::Refused("main document nesting resource cap" | "nesting resource cap") => "resource",
        Error::Refused("unhandled index field") => "unhandled_field",
        Error::Refused(
            "input changed during decode" | "changed input" | "changed repair input",
        ) => "changed_input",
        Error::Refused(_) => "strict_decode",
        Error::Io(_) => "io",
        Error::Syntax(_) | Error::HoldBudget => return,
    };
    emit_scan_index_containment_line(format!(
        "local snapshot scan index {stage}: source={source} refusal_kind={kind} source_paused=1 index_kept=1; recover with compatible decoding or reviewed repair, never delete the index"
    ));
}

pub(super) fn read<R: BufRead + Seek>(
    reader: R,
    stage: &str,
    source: &'static str,
) -> std::result::Result<ScanIndex, Error> {
    let result = read_inner(reader, stage, source);
    if let Err(error) = &result {
        note_refusal(error, stage, source);
    }
    result
}

fn read_inner<R: BufRead + Seek>(
    reader: R,
    stage: &str,
    source: &'static str,
) -> std::result::Result<ScanIndex, Error> {
    read_persistence_mode(reader, stage, source, false, None)
}
fn read_persistence_mode<R: BufRead + Seek>(
    mut reader: R,
    stage: &str,
    source: &'static str,
    map_only: bool,
    partial: Option<[Option<scan_index_persistence::MapUnavailable>; 3]>,
) -> std::result::Result<ScanIndex, Error> {
    take_dropped_codex_side_requests();
    let _side_request_counts = SideRequestCountGuard;
    let input_len = reader.seek(SeekFrom::End(0))?;
    reader.seek(SeekFrom::Start(0))?;
    let census_resources = validate_original(&mut reader)?;
    // Missing maps cannot defund already-held negative metadata. A Partial
    // index has no publication/acquisition authority. Keep the existing absolute
    // hold/count ceilings, then charge its retained custody in the adapter.
    let input_len = if partial.is_some() {
        input_len.max(HOLD_BYTES_MAX * 8)
    } else {
        input_len
    };
    let mut decoder = Decoder {
        reader,
        input_len,
        held_bytes: 0,
        held_count: 0,
        holds: Holds::default(),
        counts: Counts::default(),
        family_spans: BTreeMap::new(),
        census_resources,
        persistence_map: map_only,
    };
    // Controls are checked before any record can exhaust hold admission.
    // Otherwise a future ledger placed after damaged records could be renamed
    // as corruption before this build learns it cannot interpret the file.
    let mut headers = decoder.index(Pass::Headers)?;
    if partial.is_some() {
        if headers.schema_version != scan_index_persistence::OUTER_SCHEMA {
            return Err(Error::Refused("partial storage schema"));
        }
        headers.schema_version = SCAN_INDEX_SCHEMA_VERSION;
    }
    controls(&headers, source)?;
    drop(headers);
    decoder.reader.seek(SeekFrom::Start(0))?;
    let result = decoder.index(Pass::Full);
    if matches!(result, Err(Error::HoldBudget)) {
        // A load has not decided whether a rebuild is permitted yet. The
        // quarantine boundary emits that token after its shared loop guard.
        let fallback = if stage == "load" {
            "pending_rebuild_guard"
        } else {
            "cas_refusal_without_rewrite"
        };
        emit_scan_index_containment_line(format!(
            "local snapshot scan index {stage}: source={source} lenient_hold_budget_exceeded=1 fallback={fallback}"
        ));
    }
    let mut index = result?;
    if let Some(unavailable) = partial {
        index.persistence_unavailable = unavailable;
    }
    if partial.is_some() {
        index.schema_version = SCAN_INDEX_SCHEMA_VERSION;
    }
    controls(&index, source)?;
    // Normalize on every successful read, including both CAS readers. A bad
    // cutoff clears the loaded marker so prior-history signals re-derive it.
    index.drop_malformed_claude_history_cutoff();
    index.decode_holds = decoder.holds;
    index.decode_holds.rebuild_scopes();
    let semantic = if !map_only && index.persistence_available() {
        index.drop_invalid_index_records()
    } else {
        ScanIndexLoadDrops::default()
    };
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
    if !map_only && index.persistence_available() {
        index.retain_decodable_codex_parent_state();
        index.drop_unbound_claude_authority_records(stage);
        settle_retired_family_decode(&mut index);
    }
    if map_only
        && (!index.decode_holds.is_empty()
            || index.decode_holds.1.count != 0
            || decoder.counts.drops.activity
                + decoder.counts.drops.accepted
                + decoder.counts.drops.cursor
                + decoder.counts.drops.quarantine
                != 0)
    {
        return Err(Error::Refused("incomplete persistence map"));
    }
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
        let error = Error::Refused("input changed during decode");
        note_refusal(&error, stage, source);
        return Err(error);
    }
    result
}
/// SI-718-O1: decode only the headers and `IDENTITY_CARRY_FIELDS` of an
/// index that cannot load whole (syntax, hold budget or a Codex key
/// collision), with the same per-field decoders as a load. File records,
/// holds and every other field are skipped unread, so damaged records spend
/// no admission here. Any error means the identity state is unrecoverable:
/// the override must not rebuild.
pub(super) fn read_identity_carry(
    file: File,
    source: &'static str,
) -> std::result::Result<ScanIndex, Error> {
    let before = sampled_scan::codex_cursor::OpenStamp::capture(&file)?;
    let mut reader = BufReader::new(file);
    let input_len = reader.seek(SeekFrom::End(0))?;
    reader.seek(SeekFrom::Start(0))?;
    let census_resources = validate_original(&mut reader)?;
    let mut decoder = Decoder {
        reader,
        input_len,
        held_bytes: 0,
        held_count: 0,
        holds: Holds::default(),
        counts: Counts::default(),
        family_spans: BTreeMap::new(),
        census_resources,
        persistence_map: false,
    };
    let mut carry = decoder.index(Pass::IdentityCarry)?;
    controls(&carry, source)?;
    // Repair drops the family witnesses, so its later downgrade check cannot
    // recover evidence lost by a pre-bridge or damaged tombstone source.
    // Loss never refuses Repair or withholds unrelated identity bindings.
    let intact = decoder.counts.tombstone_marker_intact
        && carry.claude_retired_family_tombstones.decoded
        && !carry.claude_retired_family_tombstones.damaged;
    carry.claude_retired_family_tombstones_uncertain |= !intact;
    carry.decode_holds = decoder.holds;
    settle_retired_family_decode(&mut carry);
    if sampled_scan::codex_cursor::OpenStamp::capture(decoder.reader.get_ref())? != before {
        return Err(Error::Refused("input changed during decode"));
    }
    Ok(carry)
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
fn settle_retired_family_decode(index: &mut ScanIndex) {
    let initialized = index.claude_retired_family_tombstones_initialized;
    if index.claude_retired_family_tombstones_initialized
        && !index.claude_retired_family_tombstones.decoded
    {
        // Missing evidence under the marker must also make a stale CAS
        // writer reload, just as a damaged-present map does below.
        index
            .decode_holds
            .1
            .add("claude_retired_family_tombstones", "", [0; 32]);
    }
    index.settle_claude_retired_family_tombstone_decode();
    // Preserve a valid legacy marker at the raw codec boundary. Public load
    // settlement and every save own initialization; repair here still raises
    // uncertainty for damaged or missing retirement evidence.
    index.claude_retired_family_tombstones_initialized = initialized;
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
        lexical_span(&mut self.reader, false, 0)
    }
    fn span_optional(&mut self, optional: bool) -> std::result::Result<Span, Error> {
        lexical_span(&mut self.reader, optional, 1)
    }
    /// The carried debt has its own entry/byte fund. Admit each key and ACK
    /// before allocation; charge wire bytes plus conservative retained metadata.
    fn carried_incidence(
        &mut self,
        span: Span,
    ) -> std::result::Result<BTreeMap<String, BTreeSet<String>>, Error> {
        self.reader.seek(SeekFrom::Start(span.start))?;
        if self.ws()? != Some(b'{') {
            return Err(Error::Refused("carried incidence type"));
        }
        self.eat(b'{')?;
        let mut entries = 0usize;
        let mut bytes = 0u64;
        let mut result = BTreeMap::new();
        while self.ws()? != Some(b'}') {
            let key = self.span()?;
            entries = entries.saturating_add(1);
            bytes = bytes.saturating_add(key.len).saturating_add(256);
            if entries > CARRIED_ACK_ENTRIES_MAX || bytes > CARRIED_ACK_BYTES_MAX as u64 {
                return Err(Error::Refused(CARRIED_ACK_BUDGET_REFUSAL));
            }
            let key: String = self.typed(key)?;
            self.eat(b':')?;
            if self.ws()? != Some(b'[') {
                return Err(Error::Refused("carried incidence members type"));
            }
            self.eat(b'[')?;
            let mut members = BTreeSet::new();
            while self.ws()? != Some(b']') {
                let fp = self.span()?;
                entries = entries.saturating_add(1);
                bytes = bytes
                    .saturating_add(fp.len.saturating_mul(2))
                    .saturating_add(256);
                if entries > CARRIED_ACK_ENTRIES_MAX || bytes > CARRIED_ACK_BYTES_MAX as u64 {
                    return Err(Error::Refused(CARRIED_ACK_BUDGET_REFUSAL));
                }
                let fp: String = self.typed(fp)?;
                members.insert(fp);
                if self.ws()? == Some(b',') {
                    self.eat(b',')?;
                } else {
                    break;
                }
            }
            self.eat(b']')?;
            if result.insert(key, members).is_some() {
                return Err(Error::Refused("duplicate carried incidence key"));
            }
            if self.ws()? == Some(b',') {
                self.eat(b',')?;
            } else {
                break;
            }
        }
        self.eat(b'}')?;
        Ok(result)
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
    // A u64 needs at most 20 wire bytes (null needs four). Reject a wider
    // diagnostic scalar before Serde can buffer a malformed JSON string.
    fn diagnostic_timestamp(&mut self, span: Span) -> std::result::Result<Option<u64>, Error> {
        if span.len > 20 {
            return Ok(None);
        }
        self.history_scalar(span, None)
    }

    // History scalars repair only type damage, without allocating a Value for
    // an arbitrarily large malformed record. Seek/I/O errors still propagate.
    fn history_scalar<T: serde::de::DeserializeOwned>(
        &mut self,
        span: Span,
        malformed: T,
    ) -> std::result::Result<T, Error> {
        self.reader.seek(SeekFrom::Start(span.start))?;
        let result = serde_json::from_reader((&mut self.reader).take(span.len));
        self.reader.seek(SeekFrom::Start(span.start + span.len))?;
        match result {
            Ok(value) => Ok(value),
            Err(error) if error.is_io() => Err(Error::Io(std::io::Error::new(
                error.io_error_kind().unwrap_or(std::io::ErrorKind::Other),
                error,
            ))),
            Err(_) => Ok(malformed),
        }
    }
    fn check_hold_bytes(&self, bytes: u64) -> std::result::Result<(), Error> {
        if self
            .held_bytes
            .checked_add(bytes)
            .map_or(true, |total| total > hold_bytes_limit(self.input_len))
        {
            return Err(Error::HoldBudget);
        }
        Ok(())
    }
    fn record_key(&mut self, span: Span) -> std::result::Result<String, Error> {
        // A decoded key cannot exceed its original lexical length. Never let
        // serde allocate an oversized key/unescape buffer. For a damaged record
        // the caller also admits its full key/value charge before this call;
        // healthy native records do not spend the corruption allowance.
        if span.len > HOLD_BYTES_MAX {
            return Err(Error::HoldBudget);
        }
        self.typed(span)
    }
    fn hold_charge(key: Span, value: Span) -> std::result::Result<u64, Error> {
        key.len
            .checked_add(value.len)
            .and_then(|bytes| bytes.checked_add(HOLD_RECORD_OVERHEAD))
            .ok_or(Error::HoldBudget)
    }
    fn raw(&mut self, span: Span, charge: u64) -> std::result::Result<Box<RawValue>, Error> {
        self.check_hold_bytes(charge)?;
        if self.held_count >= HOLD_COUNT_MAX {
            return Err(Error::HoldBudget);
        }
        // Key, value and inline bookkeeping have all been checked
        // before retaining either raw bytes or the already bounded record key.
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
        key_span: Span,
        span: Span,
    ) -> std::result::Result<(), Error> {
        if (field == "quarantined_snapshot_fingerprints" && !is_snapshot_fingerprint(&key))
            || key.is_empty()
        {
            return Err(Error::Refused("unaddressable held identity"));
        }
        // Retain the lexical key charge, including escapes, so canonical output
        // can never require a larger restart admission. An intact file owner
        // is an inline range into the raw slot, never a second payload copy.
        let charge = Self::hold_charge(key_span, span)?;
        let raw = self.raw(span, charge)?;
        self.held_bytes += charge;
        self.held_count += 1;
        let owner = (field == "files").then(|| held_file_owner(&raw)).flatten();
        self.holds
            .0
            .entry(field)
            .or_default()
            .insert(key, Arc::new(HeldRaw(raw, owner, charge)));
        self.counts.held += 1;
        if field == "files" {
            self.counts.files += 1;
        } else if field != "quarantined_snapshot_fingerprints" {
            self.counts.families += 1;
        }
        Ok(())
    }
    // The revision marker has a fixed 32-byte payload. Inspect its lexical
    // span before Serde sees it: from_reader buffers malformed strings and map
    // keys even when a visitor discards them. Damage to this optional field
    // removes only carry eligibility, never the surrounding negative record.
    fn damaged_idless_marker(&mut self, record: Span) -> std::result::Result<Option<Span>, Error> {
        self.reader.seek(SeekFrom::Start(record.start))?;
        let close = match self.ws()? {
            Some(b'{') => b'}',
            Some(b'[') => b']',
            _ => return Ok(None),
        };
        let mut damaged = None;
        self.eat(if close == b'}' { b'{' } else { b'[' })?;
        let mut position = 0usize;
        while self.ws()? != Some(close) {
            let marker = if close == b']' {
                // Derive accepts the struct's positional representation too.
                position == 4
            } else {
                let key = self.span()?;
                let marker = if key.len <= ("idless_revision".len() * 6 + 2) as u64 {
                    self.typed::<String>(key)? == "idless_revision"
                } else {
                    false
                };
                self.eat(b':')?;
                marker
            };
            position = position.saturating_add(1);
            let value = self.span()?;
            // Includes ample space for our pretty-printed fixed array. Wider
            // spellings are damage, never permission to allocate a token.
            if marker
                && (value.len > 4096 || self.typed::<Option<[u8; 32]>>(value).is_err())
                && damaged.replace(value).is_some()
            {
                return Err(Error::Refused("duplicate idless marker"));
            }
            self.reader.seek(SeekFrom::Start(value.start + value.len))?;
            if self.ws()? == Some(b',') {
                self.eat(b',')?;
            } else {
                break;
            }
        }
        self.eat(close)?;
        Ok(damaged)
    }
    fn pending_typed<T: serde::de::DeserializeOwned>(
        &mut self,
        record: Span,
    ) -> std::result::Result<T, Error> {
        let Some(marker) = self.damaged_idless_marker(record)? else {
            return self.typed(record);
        };
        if self.persistence_map {
            return Err(Error::Refused("incomplete persistence marker"));
        }
        self.reader.seek(SeekFrom::Start(record.start))?;
        let masked = AbsentMarkerReader {
            reader: &mut self.reader,
            prefix: marker.start - record.start,
            marker_end: marker.start + marker.len,
            suffix: record.start + record.len - marker.start - marker.len,
            replacement: b"null",
            skipped: false,
        };
        let result = serde_json::from_reader(masked).map_err(|_| Error::Refused("record type"));
        self.reader
            .seek(SeekFrom::Start(record.start + record.len))?;
        result
    }
    fn records<T: serde::de::DeserializeOwned>(
        &mut self,
        field: &'static str,
        span: Span,
        debt: bool,
    ) -> std::result::Result<BTreeMap<String, T>, Error> {
        self.records_checked(field, span, debt, |_| false)
    }
    fn records_checked<T: serde::de::DeserializeOwned>(
        &mut self,
        field: &'static str,
        span: Span,
        debt: bool,
        repaired: impl Fn(&T) -> bool,
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
            self.eat(b':')?;
            let value = self.span()?;
            // Decode the value first: only actual opaque debt spends hold
            // admission. Its full charge is checked before allocating the key.
            let decoded = if field == "claude_usage_family_pending" {
                self.pending_typed(value)
            } else {
                self.typed(value)
            };
            if debt && decoded.is_err() {
                self.check_hold_bytes(Self::hold_charge(key_span, value)?)?;
                if self.held_count >= HOLD_COUNT_MAX {
                    return Err(Error::HoldBudget);
                }
            }
            let key = self.record_key(key_span)?;
            if values.contains_key(&key) || self.holds.contains(field, &key) {
                return Err(Error::Refused("duplicate record key"));
            }
            match decoded {
                Ok(decoded) => {
                    if repaired(&decoded) {
                        let hash = self.hash_span(value)?;
                        self.holds.1.add(field, &key, hash);
                    }
                    values.insert(key, decoded);
                }
                Err(_) if debt => self.hold(field, key, key_span, value)?,
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
    fn accepted(
        &mut self,
        span: Span,
        bounded_carry: bool,
    ) -> std::result::Result<BTreeSet<String>, Error> {
        self.reader.seek(SeekFrom::Start(span.start))?;
        self.eat(b'[')?;
        let mut values = BTreeSet::new();
        let mut charged = 0u64;
        let mut entries = 0usize;
        while self.ws()? != Some(b']') {
            let value = self.span()?;
            charged = charged
                .saturating_add(value.len.saturating_mul(2))
                .saturating_add(256);
            entries = entries.saturating_add(1);
            if bounded_carry
                && (entries >= CARRIED_ACK_ENTRIES_MAX || charged > CARRIED_ACK_BYTES_MAX as u64)
            {
                return Err(Error::Refused(CARRIED_ACK_BUDGET_REFUSAL));
            }
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
        let mut values = self.records_checked(
            "quarantined_snapshot_fingerprints",
            span,
            true,
            |record: &SnapshotQuarantineRecord| !snapshot_quarantine_deadline_is_bounded(record),
        )?;
        self.repair_held(
            "quarantined_snapshot_fingerprints",
            &mut values,
            repaired_quarantine,
        )?;
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
        if let Some(held) = self.holds.0.remove(field) {
            for (key, raw) in held {
                if let Some(value) = repair(&raw.0) {
                    self.holds.1.add(field, &key, repair_key(raw.get()));
                    values.insert(key, value);
                    self.held_count -= 1;
                    self.held_bytes -= raw.2;
                    self.counts.held -= 1;
                    if field == "quarantined_snapshot_fingerprints" {
                        self.counts.drops.quarantine += 1;
                    } else {
                        self.counts.families -= 1;
                        self.counts.authority_repairs += 1;
                    }
                } else {
                    self.holds.0.entry(field).or_default().insert(key, raw);
                }
            }
        }
        Ok(())
    }
    fn hash_span(&mut self, span: Span) -> std::result::Result<[u8; 32], Error> {
        self.reader.seek(SeekFrom::Start(span.start))?;
        let mut remaining = span.len;
        let mut hash = Sha256::new();
        while remaining > 0 {
            let bytes = self.reader.fill_buf()?;
            let count = bytes.len().min(remaining as usize);
            if count == 0 {
                return Err(Error::Refused("changed repair input"));
            }
            hash.update(&bytes[..count]);
            self.reader.consume(count);
            remaining -= count as u64;
        }
        Ok(hash.finalize().into())
    }
    fn index(&mut self, pass: Pass) -> std::result::Result<ScanIndex, Error> {
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
            let value = self.span_optional(optional_census(name) || optional_money_hint(name))?;
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
                    if name == "claude_desktop_store_inventory" && pass == Pass::Full {
                        with_claude_absence_counters(|counts| {
                            counts.tombstone_decode_drops =
                                counts.tombstone_decode_drops.saturating_add(1);
                        });
                    }
                    if name == "claude_request_census" {
                        index.claude_request_census = ClaudeRequestCensus::default();
                    } else if name == "claude_request_census_shadow" {
                        index.claude_request_census_shadow =
                            ClaudeRequestCensusShadowState::default();
                    } else if !matches!(name, "reread_guard" | "claude_desktop_store_inventory") {
                        return Err(Error::Refused("duplicate index field"));
                    }
                } else {
                    match name {
                        _ if match pass {
                            Pass::Full => false,
                            Pass::Headers => !header_field(name),
                            Pass::IdentityCarry => {
                                !header_field(name) && !IDENTITY_CARRY_FIELDS.contains(&name)
                            }
                        } => {}
                        "schema_version" => index.schema_version = self.typed(value)?,
                        "generation" => index.generation = self.typed(value)?,
                        "reread_guard" => {} // TOMBSTONE: decode-and-drop.
                        "claude_desktop_store_inventory" => {
                            // No new refusal: this key was unknown to the last
                            // release. A digest is 64 bytes plus its quotes, so
                            // nothing wider is buffered; a bad value is dropped.
                            let inventory: Option<String> = if value.len > 66 {
                                Some(String::new())
                            } else {
                                self.history_scalar(value, Some(String::new()))?
                            };
                            if inventory.as_ref().is_some_and(|digest| digest.len() != 64) {
                                with_claude_absence_counters(|counts| {
                                    counts.tombstone_decode_drops =
                                        counts.tombstone_decode_drops.saturating_add(1);
                                });
                            } else {
                                index.claude_desktop_store_inventory = inventory;
                            }
                        }
                        "upload_ack_retirement_handoff" => {
                            // Damaged cleanup authority delays retirement; it must
                            // never discard identity custody or pause ingestion.
                            index.upload_ack_retirement_handoff =
                                self.history_scalar(value, None)?
                        }
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
                        "claude_retired_family_tombstones" => {
                            index.claude_retired_family_tombstones = self
                                .history_scalar(value, None::<ClaudeRetiredFamilyTombstones>)?
                                .unwrap_or_else(|| {
                                    with_claude_absence_counters(|counts| {
                                        counts.tombstone_decode_drops =
                                            counts.tombstone_decode_drops.saturating_add(1);
                                    });
                                    ClaudeRetiredFamilyTombstones {
                                        decoded: true,
                                        damaged: true,
                                        ..Default::default()
                                    }
                                });
                            if index.claude_retired_family_tombstones.damaged {
                                let hash = self.hash_span(value)?;
                                self.holds.1.add(name, "", hash);
                            }
                        }
                        "claude_retired_family_tombstones_initialized"
                        | "claude_retired_family_tombstones_uncertain" => {
                            self.reader.seek(SeekFrom::Start(value.start))?;
                            let boolean = matches!(self.ws()?, Some(b't' | b'f'));
                            // Reuse #705's flag codec, including its drop count.
                            #[derive(Deserialize)]
                            #[serde(transparent)]
                            struct Flag(
                                #[serde(deserialize_with = "deserialize_fail_closed_flag")] bool,
                            );
                            let flag = self
                                .history_scalar(value, None::<Flag>)?
                                .map(|flag| flag.0)
                                .unwrap_or_else(|| {
                                    with_claude_absence_counters(|counts| {
                                        counts.tombstone_decode_drops =
                                            counts.tombstone_decode_drops.saturating_add(1);
                                    });
                                    true
                                });
                            if !boolean {
                                let hash = self.hash_span(value)?;
                                self.holds.1.add(name, "", hash);
                            }
                            if name == "claude_retired_family_tombstones_initialized" {
                                self.counts.tombstone_marker_intact = boolean && flag;
                                index.claude_retired_family_tombstones_initialized = flag;
                            } else {
                                index.claude_retired_family_tombstones_uncertain = flag;
                            }
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
                        "claude_full_rearm_progress" => {
                            // #720 scheduling-only memory: malformed progress
                            // costs another re-arm, never opens the fence. Match
                            // the native deserialize_lenient_default policy.
                            index.claude_full_rearm_progress =
                                self.history_scalar(value, ClaudeFullRearmProgress::default())?;
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
                        "held_audit_progress" => {
                            // Scheduling damage cannot erase or verify a census
                            // hold. Bound the single path before allocating it.
                            index.held_audit_progress = if value.len <= 8192 {
                                self.history_scalar(value, None)?
                            } else {
                                None
                            };
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
                        "codex_counting_evicted_legacy" => {
                            index.codex_counting_evicted_legacy =
                                self.history_scalar(value, Default::default())?
                        }
                        "codex_counting_tombstones" => {
                            // Counting-only memory: damage loses it like a
                            // lost index, never refuses the index.
                            index.codex_counting_tombstones =
                                self.history_scalar(value, BTreeMap::new())?
                        }
                        "file_snapshot_fingerprints" => {
                            if pass == Pass::IdentityCarry
                                && value.len > CARRIED_ACK_BYTES_MAX as u64
                            {
                                return Err(Error::Refused(CARRIED_ACK_BUDGET_REFUSAL));
                            }
                            index.file_snapshot_fingerprints = if pass == Pass::IdentityCarry {
                                self.carried_incidence(value)?
                            } else {
                                self.typed(value)?
                            }
                        }
                        "snapshot_activity_at" => {
                            index.snapshot_activity_at =
                                self.records("snapshot_activity_at", value, false)?
                        }
                        "accepted_snapshot_fingerprints" => {
                            if pass == Pass::IdentityCarry
                                && value.len > CARRIED_ACK_BYTES_MAX as u64
                            {
                                return Err(Error::Refused(CARRIED_ACK_BUDGET_REFUSAL));
                            }
                            index.accepted_snapshot_fingerprints =
                                self.accepted(value, pass == Pass::IdentityCarry)?
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
                        "claude_history_cutoff_unix_seconds" => {
                            index.claude_history_cutoff_unix_seconds =
                                self.history_scalar(value, Some(MALFORMED_CLAUDE_HISTORY_CUTOFF))?;
                        }
                        "claude_history_gate_loaded" => {
                            index.claude_history_gate_loaded = self.history_scalar(value, false)?;
                        }
                        "claude_history_move_not_full" => {
                            // A damaged cross-destination hold cannot release history.
                            index.claude_history_move_not_full =
                                self.history_scalar(value, true)?;
                        }
                        "claude_history_move_released" => {
                            index.claude_history_move_released =
                                self.history_scalar(value, false)?;
                        }
                        "accepted_incidence_pending_census" => {
                            // Damage keeps carried acknowledgements, never drops them.
                            index.accepted_incidence_pending_census =
                                self.history_scalar(value, true)?;
                        }
                        "accepted_rebuild_pending_since_unix_seconds" => {
                            index.accepted_rebuild_pending_since_unix_seconds =
                                self.diagnostic_timestamp(value)?;
                        }
                        "accepted_rebuild_last_alarm_unix_seconds" => {
                            index.accepted_rebuild_last_alarm_unix_seconds =
                                self.diagnostic_timestamp(value)?;
                        }
                        "claude_money_birth_store" => {
                            // Optional money hints cannot rebuild or pause an otherwise valid index.
                            // Bound allocation before decoding; do not carry through identity repair.
                            let decoded = if !value.resource && value.len <= 4 * 1024 * 1024 {
                                self.typed::<claude_money_birth_store::BirthStore>(value)
                                    .ok()
                            } else {
                                None
                            };
                            if decoded.is_none() {
                                self.counts.drops.activity += 1;
                            }
                            index.claude_money_birth_store = decoded.unwrap_or_default();
                        }
                        "claude_copy_removals" => {
                            // Like the birth table: a damaged or over-budget
                            // value decodes as none (copies decide afresh).
                            let decoded = if !value.resource
                                && value.len
                                    <= (claude_request_money::copy_removals::MAX_BYTES as u64) / 3
                                        * 4
                                        + 64
                            {
                                self.typed::<claude_request_money::copy_removals::CopyRemovals>(
                                    value,
                                )
                                .ok()
                            } else {
                                None
                            };
                            if decoded.is_none() {
                                self.counts.drops.activity += 1;
                            }
                            index.claude_copy_removals = decoded.unwrap_or_else(
                                claude_request_money::copy_removals::CopyRemovals::missing,
                            );
                        }
                        "accepted_rebuild_incidence" => {
                            if value.len > CARRIED_ACK_BYTES_MAX as u64 {
                                return Err(Error::Refused(CARRIED_ACK_BUDGET_REFUSAL));
                            }
                            index.accepted_rebuild_incidence = self.carried_incidence(value)?;
                            index.admit_carried_ack_debt()?;
                        }
                        _ => return Err(Error::Refused("unhandled index field")),
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
        if !self.persistence_map && !seen.contains("files") {
            return Err(Error::Refused("missing files"));
        }

        if pass == Pass::Full {
            // An empty undamaged store is never written: absence is an empty
            // store, not lost metadata (Lead B F4). Damage is `missing`.
            if !seen.contains("claude_copy_removals") {
                index.claude_copy_removals = Default::default();
            }
            // Migrate the old marker without granting later ACKs blanket retention.
            if index.accepted_incidence_pending_census
                && index.accepted_rebuild_incidence.is_empty()
            {
                index
                    .accepted_rebuild_incidence
                    .insert(String::new(), index.accepted_snapshot_fingerprints.clone());
            }
            index.admit_carried_ack_debt()?;
            let authority_span = self
                .family_spans
                .get("claude_usage_authority_quarantine")
                .copied();
            self.freeze_held_families(&mut index)?;
            self.note_authority_drops(&index, authority_span)?;
        }
        Ok(index)
    }
    fn freeze_unbound_authority_repairs(
        &mut self,
        index: &mut ScanIndex,
    ) -> std::result::Result<(), Error> {
        if self.counts.authority_repairs == 0 {
            return Ok(());
        }
        let field = "claude_usage_authority_quarantine";
        let Some(span) = self.family_spans.get(field).copied() else {
            return Ok(());
        };
        self.reader.seek(SeekFrom::Start(span.start))?;
        self.eat(b'{')?;
        while self.ws()? != Some(b'}') {
            let key_span = self.span()?;
            let key = self.record_key(key_span)?;
            self.eat(b':')?;
            let value = self.span()?;
            let unbound = index
                .claude_usage_authority_quarantine
                .get(&key)
                .is_some_and(|record| {
                    !index
                        .claude_usage_family_witnesses
                        .get(&key)
                        .is_some_and(|witness| {
                            claude_usage_authority_preserves_pending(record, witness)
                        })
                });
            if unbound
                && self
                    .typed::<ClaudeUsageAuthorityQuarantineRecord>(value)
                    .is_err()
            {
                let hash = self.hash_span(value)?;
                self.holds.1.remove(field, &key, hash);
                self.counts.authority_repairs -= 1;
                index.claude_usage_authority_quarantine.remove(&key);
                self.hold(field, key, key_span, value)?;
            }
            self.reader.seek(SeekFrom::Start(value.start + value.len))?;
            if self.ws()? == Some(b',') {
                self.eat(b',')?;
            } else {
                break;
            }
        }
        self.eat(b'}')?;
        Ok(())
    }
    fn freeze_held_families(&mut self, index: &mut ScanIndex) -> std::result::Result<(), Error> {
        // A held family proof/pending slot also freezes any intact correction
        // and exclusion state for that family. Existing reproof/prune code may
        // not erase its debt just because its typed witness is now absent.
        // Admit unbound type repairs as raw holds first, so all sibling maps
        // share their root fence without a corpus-sized temporary key set.
        self.freeze_unbound_authority_repairs(index)?;
        let original = std::mem::take(&mut self.holds.0);
        let roots = original
            .iter()
            .filter(|(field, _)| field.starts_with("claude_"))
            .flat_map(|(_, slots)| slots.keys().map(String::as_str))
            .chain(
                original
                    .get("files")
                    .into_iter()
                    .flat_map(|slots| slots.keys())
                    .filter_map(|key| {
                        claude_index_path_member_ref(Path::new(key)).map(|member| member.root)
                    }),
            )
            .collect::<BTreeSet<_>>();
        let fields = std::mem::take(&mut self.family_spans);
        for (field, span) in fields {
            self.reader.seek(SeekFrom::Start(span.start))?;
            self.eat(b'{')?;
            while self.ws()? != Some(b'}') {
                let key_span = self.span()?;
                let key = self.record_key(key_span)?;
                self.eat(b':')?;
                let value = self.span()?;
                let root_held = roots.contains(key.as_str());
                // Inspect only one original record at a time. No per-repair key
                // set survives this pass (or exists transiently for the corpus).
                let repaired = field == "claude_usage_authority_quarantine"
                    && self.counts.authority_repairs > 0
                    && root_held
                    && index.claude_usage_authority_quarantine.contains_key(&key)
                    && self
                        .typed::<ClaudeUsageAuthorityQuarantineRecord>(value)
                        .is_err();
                if root_held
                    && !original
                        .get(field)
                        .is_some_and(|slots| slots.contains_key(&key))
                    && !self.holds.contains(field, &key)
                {
                    if repaired {
                        let hash = self.hash_span(value)?;
                        self.holds.1.remove(field, &key, hash);
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
                        _ => return Err(Error::Refused("unhandled index field")),
                    }
                    self.hold(field, key, key_span, value)?;
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
        drop(roots);
        for (field, slots) in original {
            self.holds.0.entry(field).or_default().extend(slots);
        }
        Ok(())
    }
    fn note_authority_drops(
        &mut self,
        index: &ScanIndex,
        span: Option<Span>,
    ) -> std::result::Result<(), Error> {
        let Some(span) = span else {
            return Ok(());
        };
        self.reader.seek(SeekFrom::Start(span.start))?;
        self.eat(b'{')?;
        while self.ws()? != Some(b'}') {
            let key_span = self.span()?;
            let key = self.record_key(key_span)?;
            self.eat(b':')?;
            let value = self.span()?;
            if index
                .claude_usage_authority_quarantine
                .get(&key)
                .is_some_and(|record| {
                    !index
                        .claude_usage_family_witnesses
                        .get(&key)
                        .is_some_and(|witness| {
                            claude_usage_authority_preserves_pending(record, witness)
                        })
                })
            {
                let hash = self.hash_span(value)?;
                self.holds
                    .1
                    .add("claude_usage_authority_quarantine", &key, hash);
            }
            self.reader.seek(SeekFrom::Start(value.start + value.len))?;
            if self.ws()? == Some(b',') {
                self.eat(b',')?;
            } else {
                break;
            }
        }
        self.eat(b'}')?;
        Ok(())
    }
    fn census(&mut self, span: Span, field: &str) -> std::result::Result<ScanIndex, Error> {
        if self.persistence_map && field == "claude_request_census" {
            if span.resource || self.census_resources[0] {
                return Err(Error::Refused("census admission"));
            }
            self.reader.seek(SeekFrom::Start(span.start))?;
            let census =
                claude_request_census::decode_persistence_census((&mut self.reader).take(span.len))
                    .map_err(|_| Error::Refused("incomplete persistence census"))?;
            return Ok(ScanIndex {
                claude_request_census: census,
                ..ScanIndex::default()
            });
        }
        if span.resource
            || (optional_census(Some(field))
                && self.census_resources[usize::from(field == "claude_request_census_shadow")])
        {
            return Ok(ScanIndex::default());
        }
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
        // Working domain transitions leave the load-time commitment intact.
        // Thus accepting/removing/advancing a repaired record after load does
        // not mistake our own native edits for new on-disk damage. A canonical
        // save rewrites ALL repaired/dropped records; an empty current digest
        // is safe (the old per-record iteration was vacuously true here too).
        self.decode_holds.1.count == 0 || self.decode_holds.1 == working.decode_holds.1
    }
    pub(super) fn decode_holds_family(&self, root: &str) -> bool {
        #[cfg(test)]
        SCOPE_VISITS.with(|count| count.set(count.get() + 1));
        !self.persistence_available()
            || self.decode_holds.2.contains(&repair_key(root))
            || [
                "claude_usage_authority_quarantine",
                "claude_account_family_witnesses",
                "claude_account_family_pending",
                "claude_usage_family_witnesses",
                "claude_usage_family_pending",
            ]
            .iter()
            .any(|field| self.decode_holds.contains(field, root))
    }
    pub(crate) fn decode_holds_file(&self, key: &str) -> bool {
        #[cfg(test)]
        SCOPE_VISITS.with(|count| count.set(count.get() + 1));
        self.decode_holds.contains("files", key)
            || claude_index_path_member_ref(Path::new(key))
                .is_some_and(|member| self.decode_holds_family(member.root))
    }
    pub(crate) fn decode_held_file_keys(&self) -> impl Iterator<Item = &str> {
        self.decode_holds.file_keys()
    }
    // Missing incidence is UNKNOWN, not an empty set. Keep existing ACKs as
    // possible prior members without inventing membership for emission/manifests.
    pub(super) fn decode_has_opaque_file_incidence(&self) -> bool {
        self.decode_held_file_keys()
            .any(|key| !self.file_snapshot_fingerprints.contains_key(key))
    }
    // Exact entity holds and file/family holds have separate keyed queries.
    // Consumers with a file key must retain that context rather than reverse
    // scanning every incidence set for each fingerprint.
    pub(crate) fn decode_holds_entity(&self, fingerprint: &str) -> bool {
        !self.persistence_available()
            || self
                .decode_holds
                .contains("quarantined_snapshot_fingerprints", fingerprint)
    }
    pub(crate) fn eligible_snapshot_fingerprint_refs(&self) -> impl Iterator<Item = &str> {
        let exact = self
            .file_snapshot_fingerprints
            .iter()
            .filter(|(key, _)| !self.decode_holds_file(key))
            .flat_map(|(_, values)| values.iter().map(String::as_str));
        let legacy = self
            .files
            .iter()
            .filter(|(key, _)| {
                !self.file_snapshot_fingerprints.contains_key(*key) && !self.decode_holds_file(key)
            })
            .filter_map(|(_, entry)| entry.last_snapshot_fingerprint.as_deref());
        let state = self
            .codex_state_only_snapshot_fingerprints
            .iter()
            .filter(|(id, _)| !self.decode_holds_codex_owner(id))
            .map(|(_, fingerprint)| fingerprint.as_str());
        exact.chain(legacy).chain(state)
    }
    pub(super) fn decode_holds_indexed_entity(&self, key: &str, fingerprint: &str) -> bool {
        self.decode_holds_file(key) || self.decode_holds_entity(fingerprint)
    }
    pub(super) fn decode_held_codex_owners(&self) -> impl Iterator<Item = Option<&str>> {
        self.decode_holds
            .0
            .get("files")
            .into_iter()
            .flat_map(|slots| slots.values())
            .map(|raw| raw.owner())
    }
    pub(super) fn decode_holds_codex_owner(&self, id: &str) -> bool {
        self.decode_holds.4
            || self
                .decode_holds
                .3
                .contains(&repair_key(&codex_protected_owner(id)))
    }
    pub(super) fn preserve_decode_held_files(
        &mut self,
        source: SnapshotSource,
        snapshots: &[SnapshotItem],
        pending: &mut [PendingIndexFinalization],
    ) {
        if self.decode_holds.is_empty() {
            return;
        }
        for file in pending {
            if !snapshots.iter().any(|item| {
                item.source_file_fingerprint.as_deref()
                    == Some(file.source_file_fingerprint.as_str())
                    && self.decode_holds_snapshot(source, item)
            }) {
                continue;
            }
            file.parse_complete = false;
            self.confirmed_empty_files.remove(&file.index_key);
            if let Some(entry) = self.files.get_mut(&file.index_key) {
                entry.last_snapshot_fingerprint = file.previous_snapshot_fingerprint.clone();
                entry.last_upload_body_witness = file.previous_upload_body_witness.clone();
            }
            for item in snapshots {
                if item.source_file_fingerprint.as_deref()
                    == Some(file.source_file_fingerprint.as_str())
                    && self.decode_holds_snapshot(source, item)
                {
                    self.file_snapshot_fingerprints
                        .entry(file.index_key.clone())
                        .or_default()
                        .insert(item.snapshot_fingerprint.clone());
                }
            }
            self.mark_bounded_sweep_unsettled();
        }
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
        if source == SnapshotSource::Codex
            && self
                .decode_holds
                .3
                .contains(&repair_key(&codex_protected_owner(&item.source_session_id)))
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
// field policy here when MONEY composes its codec, together with the ScanIndex
// serializer, FIELDS registry and index() dispatch; census sequence_fields()
// asserts their agreement. Never default a failed ledger read, quarantine its
// file, or borrow census/parser-copy credit for it.

pub(super) fn read_bounded(bytes: &[u8]) -> anyhow::Result<ScanIndex> {
    // Preserve the caller byte bound and the existing census normalization and
    // node/depth admission before constructing native state. Original syntax is
    // checked before the optional census normalizer can replace damaged input.
    validate_original(&mut std::io::Cursor::new(bytes)).inspect_err(|error| {
        note_refusal(error, "cas", "unattributed");
    })?;
    let (normalized, duplicate_census, duplicate_shadow) =
        claude_request_census::normalized_bounded_bytes(bytes)?;
    bounded_shape(&normalized).inspect_err(|_| {
        note_refusal(
            &Error::Refused("nesting resource cap"),
            "cas",
            "unattributed",
        );
    })?;
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
    #[serde(
        default = "terminal_contract_retry::legacy_contract",
        deserialize_with = "terminal_contract_retry::decode_contract"
    )]
    reconstruction_contract: u16,
    #[serde(default, deserialize_with = "terminal_contract_retry::decode_claims")]
    contract_retry_claims: Option<u16>,
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
        contract_retry_claims: wire.contract_retry_claims,
        reconstruction_contract: wire.reconstruction_contract,
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

fn held_file_owner(raw: &RawValue) -> Option<std::ops::Range<usize>> {
    #[derive(Deserialize)]
    struct Owner<'a> {
        #[serde(default, borrow)]
        codex_protected_owner: Option<&'a str>,
    }
    let owner: Owner<'_> = serde_json::from_str(raw.get()).ok()?;
    if let Some(owner) = owner.codex_protected_owner {
        if !valid_codex_protected_owner(owner) {
            return None;
        }
        // Serde's borrowed &str is within the immutable raw allocation. Store
        // only its checked byte range; Arc clones keep the backing slot alive.
        let start = (owner.as_ptr() as usize).checked_sub(raw.get().as_ptr() as usize)?;
        let end = start.checked_add(owner.len())?;
        raw.get().get(start..end).filter(|value| *value == owner)?;
        return Some(start..end);
    }
    // Filename hints are not ownership proof for captured/joined history.
    // Without an intact owner disclosure, keep the state-only domain unknown.
    None
}

// The one scan-index file layout, used by the save and by the restart
// admission check below. Compact JSON, except while decode holds exist: then
// the earlier pretty layout stays, so a hold that an older pretty file's
// whitespace funded is still funded by the bytes rewritten on every save.
pub(super) fn write_index<W: std::io::Write>(
    writer: W,
    index: &ScanIndex,
) -> serde_json::Result<()> {
    if index.decode_holds.is_empty() {
        serde_json::to_writer(writer, index)
    } else {
        serde_json::to_writer_pretty(writer, index)
    }
}

// Exactly the bytes write_index emits. This streams to a counter, never
// another encoded byte buffer.
pub(super) fn written_len(index: &ScanIndex) -> serde_json::Result<u64> {
    struct Count(u64);
    impl std::io::Write for Count {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0 = self
                .0
                .checked_add(bytes.len() as u64)
                .ok_or_else(|| std::io::Error::other("scan index output length"))?;
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut output = Count(0);
    write_index(&mut output, index)?;
    Ok(output.0)
}

// Dropped optional/unknown input can make the next wire document much smaller.
// Refuse before writing if that would turn an admitted hold into excess damage
// on restart.
pub(super) fn check_held_output(index: &ScanIndex) -> anyhow::Result<()> {
    if index.decode_holds.is_empty() {
        return Ok(());
    }
    if index.decode_holds.held_bytes() > hold_bytes_limit(written_len(index)?) {
        emit_scan_index_containment_line(
            "local snapshot scan index save: source=unattributed lenient_hold_budget_exceeded=1"
                .into(),
        );
        return Err(Error::HoldBudget.into());
    }
    Ok(())
}

fn repair_key(value: &str) -> [u8; 32] {
    Sha256::digest(value.as_bytes()).into()
}

#[cfg(test)]
thread_local! { static SCOPE_VISITS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) }; }
#[cfg(test)]
pub(super) fn scope_visits_for_test(reset: bool) -> usize {
    SCOPE_VISITS.with(|count| if reset { count.replace(0) } else { count.get() })
}

#[cfg(test)]
#[test]
fn repair_commitment_is_order_independent_and_removes_frozen_records() {
    let mut left = RepairProvenance::default();
    left.add("quarantined_snapshot_fingerprints", "a", [1; 32]);
    left.add("claude_usage_authority_quarantine", "b", [2; 32]);
    let mut right = RepairProvenance::default();
    right.add("claude_usage_authority_quarantine", "b", [2; 32]);
    right.add("quarantined_snapshot_fingerprints", "a", [1; 32]);
    assert_eq!(left, right);
    right.remove("claude_usage_authority_quarantine", "b", [2; 32]);
    let mut only_native = RepairProvenance::default();
    only_native.add("quarantined_snapshot_fingerprints", "a", [1; 32]);
    assert_eq!(right, only_native);
}

pub(super) fn validate_persistence_map(
    field: scan_index_persistence::Field,
    reader: &mut scan_index_persistence::LogicalReader,
) -> anyhow::Result<()> {
    reader.seek(SeekFrom::Start(0))?;
    let index = read_persistence_mode(
        BufReader::new(reader),
        "shard_validation",
        "unattributed",
        true,
        None,
    )?;
    anyhow::ensure!(
        !index.decode_holds.0.contains_key(field.name()),
        "incomplete persistence map"
    );
    Ok(())
}
pub(super) fn read_partial_persistence(
    partial: scan_index_persistence::PartialIndex,
    stage: &str,
    source: &'static str,
    cap: Option<usize>,
) -> anyhow::Result<ScanIndex> {
    let (mut reader, unavailable) = partial.into_reader()?;
    if let Some(cap) = cap {
        anyhow::ensure!(
            reader.seek(SeekFrom::End(0))? <= cap as u64,
            "scan_index_read_limit"
        );
        reader.seek(SeekFrom::Start(0))?;
    }
    let mut index = read_persistence_mode(
        BufReader::new(reader),
        stage,
        source,
        false,
        Some(unavailable),
    )
    .map_err(|error| scan_index_integration::storage_decode_error(error.into()))?;
    index.persistence_unavailable = unavailable;
    Ok(index)
}

/// Immutable semantic custody. Never a receipt and never replaces full CAS decode.
#[derive(Debug, Clone)]
pub(super) struct PersistenceControls {
    holds: Holds,
    claims: BTreeMap<String, SnapshotQuarantineRecord>,
}
crate::heap_layout_bound::fields!(PersistenceControls; holds, claims);
pub(super) fn persistence_controls(
    index: &ScanIndex,
    budget: usize,
) -> anyhow::Result<Arc<PersistenceControls>> {
    use crate::heap_layout_bound::{Counter, HeapLayoutBound};
    let claims = index
        .quarantined_snapshot_fingerprints
        .iter()
        .filter(|(_, r)| r.contract_retry_claims.is_some());
    let mut c = Counter::new(budget);
    let admitted = (|| {
        c.add(
            std::mem::size_of::<PersistenceControls>()
                + std::mem::align_of::<PersistenceControls>()
                + 2 * std::mem::size_of::<usize>(),
        )?;
        index.decode_holds.completed_heap_bound(&mut c)?;
        crate::heap_layout_bound::tree_nodes::<String, SnapshotQuarantineRecord>(
            claims.clone().count(),
            &mut c,
        )?;
        // Completion boundary: each claim gets its ordinary recursive visit
        // budget, while every child spends the SAME diminishing byte budget.
        let mut claim_bytes = 0usize;
        for (key, record) in claims.clone() {
            let remaining = budget.checked_sub(c.bytes)?.checked_sub(claim_bytes)?;
            let mut child = Counter::new(remaining);
            key.completed_heap_bound(&mut child)?;
            record.completed_heap_bound(&mut child)?;
            claim_bytes = claim_bytes.checked_add(child.bytes)?;
        }
        c.add(claim_bytes)?;
        Some(())
    })();
    anyhow::ensure!(admitted.is_some(), "scan_index_storage_admission");
    Ok(Arc::new(PersistenceControls {
        holds: index.decode_holds.clone(),
        claims: claims.map(|(k, r)| (k.clone(), r.clone())).collect(),
    }))
}
pub(super) fn retain_persistence_claims(index: &mut ScanIndex) {
    if let Some(controls) = &index.persistence_controls {
        terminal_contract_retry::merge_maps(
            &mut index.quarantined_snapshot_fingerprints,
            &controls.claims,
        );
    }
}
