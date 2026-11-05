//! The scan index: the persisted `ScanIndex` model and its quarantine
//! records, per-file entries, source fingerprints and the canonical file-set
//! digests it records.

pub(super) mod entry;
pub(super) mod file_set_digest;
pub(super) mod serde_lenient;
pub(super) mod source_fingerprint;

use super::*;
use super::{
    claude_request_money, deserialize_lenient_claude_history_cutoff, deserialize_lenient_move_hold,
    deserialize_lenient_true, terminal_contract_retry,
};
use serde_lenient::{
    deserialize_lenient_default, deserialize_lenient_map, deserialize_unsettled_causes,
};

/// Saved only by the hand-written `impl Serialize` in `lenient_decode.rs`; add
/// each new field's save rule there (serde `skip_serializing*` keys here are inert).
#[derive(Debug, Clone, Deserialize)]
pub struct ScanIndex {
    /// V2-only custody and growth debt; absent on ordinary v1 paths.
    #[serde(skip)]
    pub(super) v2: Option<Box<state_v2::IndexState>>,
    #[serde(skip)]
    pub(super) persistence_root: Option<(
        scan_index_persistence::Binding,
        scan_index_persistence::LoadedRoot,
    )>,
    #[serde(skip)]
    pub(super) persistence_unavailable: [Option<scan_index_persistence::MapUnavailable>; 3],
    #[serde(skip)]
    pub(super) persistence_controls: Option<Arc<lenient_decode::PersistenceControls>>,
    #[serde(skip)]
    pub(super) persistence_legacy_recovery: Option<Arc<scan_index_persistence::LegacyRecovery>>,
    #[serde(skip)]
    pub(super) decode_holds: lenient_decode::Holds,
    /// RAM-only pacing spans ordinary + continuation pages, never durable authority.
    #[serde(skip)]
    pub(super) withheld_memo: withheld_account::Memo,
    #[serde(default = "scan_index_schema_version")]
    pub schema_version: u16,
    #[serde(default)]
    pub generation: u64,
    /// retired_<old>: the source-wide upload context, replaced by per-file
    /// receipts and per-entity stamps. Decode-only; never written.
    #[serde(rename = "upload_context_fingerprint", default, skip_serializing)]
    pub(super) retired_upload_context_fingerprint: serde::de::IgnoredAny,
    pub files: SharedMap<String, ScanIndexEntry>,
    /// Hash-only owner proof keyed by machine and session in this source index.
    /// A later current login can never replace it.
    #[serde(default)]
    pub(super) session_account_bindings: BTreeMap<String, SessionAccountBinding>,
    /// Files whose oversized physical lines were skipped once under a bounded
    /// parser generation. The path key plus exact opened-object-derived source
    /// fingerprint prevents both permanent condemnation after replacement and
    /// repeated work for an unchanged object. Keyed identically to `files` and
    /// retired with it, so this map is a subset of `files`, never its own
    /// independently growing store - see `prune_terminal_jsonl_dispositions`.
    #[serde(default)]
    pub(super) terminal_jsonl_dispositions: BTreeMap<String, TerminalJsonlDisposition>,
    /// Configured roots that have successfully resolved at least once for this
    /// destination/source index. A root that never existed is optional, but a
    /// root that disappears after contributing an authoritative census must
    /// fail the generation red instead of reconciling every entity beneath it
    /// away as if the directory had been observed empty.
    #[serde(default)]
    pub(super) known_configured_scan_roots: BTreeSet<String>,
    /// Pre-root-witness index paths not currently covered by any resolved root.
    /// This is the upgrade-safe witness for a configured symlink whose old
    /// canonical target cannot be reconstructed while the link is missing.
    /// Inference requires a prior traversal with the same root-context proof;
    /// paths clear when a resolved root covers them or the root context changes.
    #[serde(default)]
    pub(super) legacy_unresolved_root_file_witnesses: BTreeSet<String>,
    /// retired_<old>: decode-only placeholders; keep positional slots; never written.
    /// The Codex state-only usage fallback and its blocks, retired with it.
    #[serde(rename = "codex_state_only_snapshot_fingerprints", default)]
    pub(super) retired_codex_state_only_snapshot_fingerprints: serde::de::IgnoredAny,
    #[serde(rename = "codex_state_only_blocked_session_ids", default)]
    pub(super) retired_codex_state_only_blocked_session_ids: serde::de::IgnoredAny,
    #[serde(rename = "codex_state_only_blocked_by_file", default)]
    pub(super) retired_codex_state_only_blocked_by_file: serde::de::IgnoredAny,
    #[serde(rename = "codex_state_only_blocked_unattributed", default)]
    pub(super) retired_codex_state_only_blocked_unattributed: serde::de::IgnoredAny,
    #[serde(rename = "codex_state_only_blocked_legacy", default)]
    pub(super) retired_codex_state_only_blocked_legacy: serde::de::IgnoredAny,
    #[serde(rename = "codex_state_only_blocked_attributed", default)]
    pub(super) retired_codex_state_only_blocked_attributed: serde::de::IgnoredAny,
    // Empty compatibility roots for retired state; never used for runtime decisions.
    #[serde(default)]
    pub(super) codex_parent_ownership_refs: serde::de::IgnoredAny,
    #[serde(default)]
    pub(super) codex_parent_ownership_ledgers: serde::de::IgnoredAny,
    #[serde(default)]
    pub(super) codex_parent_side_requests: serde::de::IgnoredAny,
    #[serde(default)]
    pub(super) codex_parent_side: serde::de::IgnoredAny,
    #[serde(default)]
    pub(super) codex_parent_side_generation: serde::de::IgnoredAny,
    #[serde(default)]
    pub(super) codex_parent_proof_wrap_epoch: serde::de::IgnoredAny,
    #[serde(default)]
    pub(super) codex_parent_prefix_proofs: serde::de::IgnoredAny,
    #[serde(default)]
    pub(super) codex_parent_proof_cursor: serde::de::IgnoredAny,
    #[serde(default)]
    pub(super) codex_parent_side_cursor: serde::de::IgnoredAny,
    #[serde(default)]
    pub(super) codex_parent_proof_seq: serde::de::IgnoredAny,
    #[serde(default)]
    pub(super) codex_proof_index_incarnation: serde::de::IgnoredAny,
    /// Durable, local-only index of Claude Desktop naming sidecars. Paging the
    /// store without retaining these safe extracted fields would make titles
    /// disappear whenever their file was outside the current bounded page.
    #[serde(default)]
    pub(super) claude_desktop_title_files: SharedMap<String, ClaudeDesktopTitleIndexEntry>,
    /// retired_<old>: the family account proof and its account windows.
    /// Decode-only; stored rows are purged by the next save.
    #[serde(rename = "claude_account_family_witnesses", default)]
    pub(super) retired_claude_account_family_witnesses: serde::de::IgnoredAny,
    #[serde(rename = "claude_account_family_pending", default)]
    pub(super) retired_claude_account_family_pending: serde::de::IgnoredAny,
    /// Complete Claude request-ownership witnesses. These are local-only and
    /// persist only content-free request-set fingerprints; raw provider request
    /// ids remain in the transcript/API sidecars that produced them.
    #[serde(default)]
    pub(super) claude_usage_family_witnesses: SharedMap<String, ClaudeUsageFamilyWitness>,
    /// retired_<old>: per-family pending request evidence of the retired
    /// global census. Decode-only; stored rows are purged by the next save.
    #[serde(rename = "claude_usage_family_pending", default)]
    pub(super) retired_claude_usage_family_pending: serde::de::IgnoredAny,
    /// retired_<old>: the census membership count derived from the pending
    /// evidence above. Never a v1 field; stored rows are purged by the next save.
    #[serde(skip)]
    pub(super) retired_family_requests: serde::de::IgnoredAny,
    /// One request-census record per Claude transcript index key,
    /// bound to the candidate fingerprint and census window of the parse that
    /// produced it. Local-only and content-free (8-byte SHA-256 prefixes of
    /// provider request ids); never proof, usage or upload input, and no
    /// decision reads it. Decoded per entry: a malformed record is dropped,
    /// never the index.
    #[serde(default)]
    pub(super) claude_request_census: ClaudeRequestCensus,
    /// Count-only shadow memory between complete terminals.
    #[serde(default)]
    pub(super) claude_request_census_shadow: ClaudeRequestCensusShadowState,
    /// Families whose current transcript revision could not reconstruct a
    /// previously proven session-exclusive usage witness. Unlike backend
    /// poison quarantine, these revisions are not settled and never enter the
    /// upload or manifest set. The prior witness remains durable so a later
    /// family scan can re-prove authority without trusting the older body
    /// itself.
    #[serde(default)]
    pub(super) claude_usage_authority_quarantine:
        BTreeMap<String, ClaudeUsageAuthorityQuarantineRecord>,
    /// retired_<old>: the retired-family tombstones, their marker and their
    /// uncertainty fence. Decode-only placeholders that keep positional
    /// slots; stored rows are purged by the next save.
    #[serde(rename = "claude_retired_family_tombstones", default)]
    pub(super) retired_claude_retired_family_tombstones: serde::de::IgnoredAny,
    #[serde(rename = "claude_retired_family_tombstones_initialized", default)]
    pub(super) retired_claude_retired_family_tombstones_initialized: serde::de::IgnoredAny,
    #[serde(rename = "claude_retired_family_tombstones_uncertain", default)]
    pub(super) retired_claude_retired_family_tombstones_uncertain: serde::de::IgnoredAny,
    /// retired_<old>: the duplicate-request owners, fence and owned-start
    /// witnesses of the retired global census. Decode-only placeholders that
    /// keep positional slots; stored rows are purged by the next save.
    #[serde(rename = "claude_duplicate_request_owners", default)]
    pub(super) retired_claude_duplicate_request_owners: serde::de::IgnoredAny,
    #[serde(rename = "claude_duplicate_request_witness_overflowed", default)]
    pub(super) retired_claude_duplicate_request_witness_overflowed: serde::de::IgnoredAny,
    #[serde(rename = "claude_owned_start_census", default)]
    pub(super) retired_claude_owned_start_census: serde::de::IgnoredAny,
    /// Index keys whose parsed revision is held locally because its session
    /// ownership could not be bound, mapped to that held source fingerprint.
    /// The held body is never uploaded and the key keeps its previously
    /// committed revision. This content-free map keeps the unresolved
    /// ownership disclosed after the page that parsed it. A key leaves only
    /// when a later parse resolves it or rooted no-follow lookup proves it absent;
    /// until then discovery ignores its age (`DiscoveryRetention`), so a
    /// present held file is always observed and only an absent one is pruned.
    #[serde(default)]
    // Correctness hold: recorded ownership debt survives age and growth. Only
    // approved interim withheld_reparse{start,evidence,growth} may Full here.
    pub(super) claude_account_deferred_holds: BTreeMap<String, String>,
    /// retired_<old>: the duplicate fence's full re-arm schedule and memory.
    /// Decode-only placeholders; stored rows are purged by the next save.
    #[serde(rename = "claude_duplicate_fence_rearm_attempt", default)]
    pub(super) retired_claude_duplicate_fence_rearm_attempt: serde::de::IgnoredAny,
    #[serde(
        rename = "claude_duplicate_fence_next_full_rearm_unix_seconds",
        default
    )]
    pub(super) retired_claude_duplicate_fence_next_full_rearm_unix_seconds: serde::de::IgnoredAny,
    #[serde(rename = "claude_full_rearm_progress", default)]
    pub(super) retired_claude_full_rearm_progress: serde::de::IgnoredAny,
    /// Contract-5 identity contract observed when the current traversal
    /// started: the full collector token under a permit, `""` without one, or
    /// a placeholder that matches no contract once it changed mid-traversal.
    /// `None` is unknown (an old index, or one an old decoder rewrote).
    #[serde(default)]
    pub(super) claude_request_identity_contract: Option<String>,
    /// retired_<old>: the identity-contract latch. Decode-only; stored rows
    /// are purged by the next save.
    #[serde(rename = "claude_request_identity_contract_changed", default)]
    pub(super) retired_claude_request_identity_contract_changed: serde::de::IgnoredAny,
    #[serde(default)]
    pub(super) claude_desktop_store_cursor: Option<String>,
    #[serde(default)]
    pub(super) claude_desktop_store_upper_bound: Option<String>,
    #[serde(default)]
    pub(super) claude_desktop_store_sweep_had_errors: bool,
    /// Last completed identity census stays valid during healthy bounded refresh
    /// pages; an actual read/parse/budget failure invalidates it until recovery.
    #[serde(default)]
    pub(super) claude_desktop_identity_census_complete: bool,
    /// Same rule for desktop spawn lineage: links are asserted only from a
    /// complete, error-free store sweep, and an incomplete page that changed a
    /// lineage id invalidates it until the next complete sweep. Kept apart from
    /// the identity census so lineage churn never moves identity evidence.
    #[serde(default)]
    pub(super) claude_desktop_lineage_census_complete: bool,
    /// retired_<old>: decode-only placeholder; keeps positional slots; never written.
    /// The Desktop census completion witness, retired with its only consumer.
    #[serde(rename = "claude_desktop_census_witness", default)]
    pub(super) retired_claude_desktop_census_witness: serde::de::IgnoredAny,
    #[serde(default)]
    pub(super) claude_desktop_store_retry_attempt: u8,
    #[serde(default)]
    pub(super) claude_desktop_store_retry_not_before_unix_seconds: Option<u64>,
    /// Lexicographic path cursor for a bounded sweep when a source has more
    /// eligible transcripts than one cycle may parse. Kept in the v2-only
    /// index so an older daemon can neither clobber nor misread it.
    #[serde(default)]
    pub resume_after_path: Option<String>,
    /// Frozen lexicographic ceiling for the current bounded sweep. Files that
    /// arrive after the sweep starts wait for the next generation instead of
    /// keeping a hot tail full forever and starving older prefix keys.
    #[serde(default)]
    pub resume_upper_bound_path: Option<String>,
    /// Observation boundary paired with `resume_upper_bound_path`. A sweep
    /// that spans cycles may publish only through the time at which its frozen
    /// path generation was captured, never through the later finishing tick.
    #[serde(default)]
    pub resume_census_window_end: Option<String>,
    /// At least one earlier page in this frozen sweep was only partially
    /// settled. The final page may finish discovery, but one clean follow-up
    /// generation is still required before completeness or the policy epoch
    /// can advance.
    #[serde(default)]
    pub(super) bounded_sweep_had_unsettled_upload: bool,
    /// The `UnsettledUploadCause` bits of the paths that set
    /// `bounded_sweep_had_unsettled_upload` in this sweep. Transition lines
    /// name them. Oversized retry scheduling
    /// preserves ordinary recovery for every cause except blocking holds.
    /// Reset with the flag.
    /// Read through `unsettled_cause_bits`, which reports none without the
    /// flag and `Unattributed` for a flag with no recorded cause.
    #[serde(default, deserialize_with = "deserialize_unsettled_causes")]
    pub(super) bounded_sweep_unsettled_causes: u16,
    /// Durable bounded filesystem census. It is intentionally destination-
    /// scoped with the rest of the scan index: missed watcher events, daemon
    /// restarts, deletions, and roots created after startup all converge via
    /// this finite queue without an O(all paths) tick.
    #[serde(default)]
    pub(super) traversal: Option<ScanTraversalCheckpoint>,
    /// retired_<old>: the stale-family carry of a traversal start. Decode-only;
    /// stored rows are purged by the next save.
    #[serde(rename = "claude_stale_family_carry", default)]
    pub(super) retired_claude_stale_family_carry: serde::de::IgnoredAny,
    /// Residue named by the last completed census, see `ScanResidueWitness`.
    /// Absent while the last completed census was clean.
    #[serde(default)]
    pub(super) scan_residue_witness: Option<ScanResidueWitness>,
    /// Destination-scoped historical bootstrap/replay generation currently
    /// being paged. Matching generations resume; a new reviewed revision
    /// clears only derived transcript settlement state once.
    #[serde(default)]
    pub(super) historical_replay_generation: Option<String>,
    /// retired_<old>: decode-only placeholder; keeps positional slots; never written.
    /// The three curve replay slots retired with full context-curve upload.
    #[serde(rename = "context_curve_capability_enabled", default)]
    pub(super) retired_context_curve_capability_enabled: serde::de::IgnoredAny,
    /// retired_<old>: decode-only placeholder; keeps positional slots; never written.
    #[serde(rename = "context_curve_replay_epoch", default)]
    pub(super) retired_context_curve_replay_epoch: serde::de::IgnoredAny,
    /// retired_<old>: decode-only placeholder; keeps positional slots; never written.
    #[serde(rename = "completed_context_curve_replay_generation", default)]
    pub(super) retired_completed_context_curve_replay_generation: serde::de::IgnoredAny,
    /// Files that were fully read and valid but intentionally produced no
    /// snapshot. Separate from `last_snapshot_fingerprint=None`, which legacy
    /// indexes can only treat as unknown/incomplete.
    #[serde(default)]
    pub confirmed_empty_files: BTreeSet<String>,
    /// Scan-local moved-session evidence from the existing bounded header
    /// inventory. Never serialized or used as file/body settlement evidence.
    #[serde(skip)]
    pub(super) codex_counting_moved_evidence: BTreeMap<String, codex_counting_version::AckEvidence>,
    /// Final post-policy entity fingerprints produced by each transcript.
    /// Most files contain one session; the set preserves exact entity grain
    /// for split/provider files instead of hiding all but an arbitrary last.
    #[serde(default)]
    pub file_snapshot_fingerprints: SharedMap<String, BTreeSet<String>>,
    /// Server-reconstructible semantic activity clock for each final entity.
    /// This mirrors the accepted-log `occurred_at` rule and never uses local
    /// file mtime or the collector observation clock.
    #[serde(default)]
    pub snapshot_activity_at: SharedMap<String, Option<String>>,
    /// Exact entity ACK identities known durable at the backend. Older indexes
    /// deserialize this empty. The separate version bit distinguishes that
    /// legacy absence from a current, authoritatively empty ledger.
    #[serde(default)]
    pub(super) accepted_snapshot_fingerprints: Shared<BTreeSet<String>>,
    #[serde(default)]
    pub(super) accepted_snapshot_fingerprint_ledger_version: u8,
    /// Restart-stable lexicographic cursor for bounded re-entry of ambiguous
    /// pre-ledger entities through the existing snapshot entity-ACK contract.
    #[serde(default)]
    pub(super) legacy_settlement_reconcile_after_fingerprint: Option<String>,
    /// Rejected entities are quarantined under the exact daemon/parser/wire
    /// contract that produced the rejection. They are excluded from the
    /// server-agreement manifest while that witness is current, but are
    /// automatically re-derived after a repair changes any witness component.
    /// This isolates poison without turning quarantine into a permanent fence.
    #[serde(default)]
    pub quarantined_snapshot_fingerprints: BTreeMap<String, SnapshotQuarantineRecord>,
    /// Runtime-only witness used to decide whether a persisted quarantine is
    /// stale. It is reconstructed from the current source before every scan.
    #[serde(skip)]
    pub(super) active_quarantine_witness: Option<SnapshotQuarantineWitness>,
    /// Runtime-only desired upload context. It becomes durable only after a
    /// complete census, so a bounded/failed sweep cannot skip untouched files.
    #[serde(skip)]
    pub(super) active_upload_context_fingerprint: Option<String>,
    #[serde(skip)]
    pub(crate) context_read_counts: upload_context_read::LocalCounts,
    /// Runtime-only revision of the effective additive upload projection.
    /// Adoption is recorded per complete, settled file rather than per census.
    #[serde(skip)]
    pub(super) active_effective_upload_body_witness_revision: u64,
    /// Runtime-only, Claude only: adopt a file only when its stored revision
    /// is below the active one. Codex and Pi compare exactly.
    #[serde(skip)]
    pub(super) active_effective_upload_body_witness_revision_monotone: bool,
    /// Local held/mixed groups must not adopt a projection they did not upload.
    #[serde(skip)]
    pub(super) effective_upload_body_witness_revision_excluded_source_files: BTreeSet<String>,
    /// Runtime-only Claude sessions the adoption re-read must not re-emit,
    /// read from the local list each cycle. Empty for other sources.
    #[serde(skip)]
    pub(super) claude_reemission_exclusions: ReemissionExclusions,
    /// Runtime-only exact refusal re-offer leases (fingerprint -> refused body
    /// witness) granted by the upload ledger for this cycle. Never persisted;
    /// scheduling permission only, never acceptance evidence.
    #[serde(skip)]
    pub(super) reason_reoffer_retries: BTreeMap<String, String>,
    /// Runtime file owners for this cycle's quarantine retries. Contract-origin
    /// leases additionally have claims saved in both checkpoints before scanning.
    #[serde(skip)]
    pub(super) terminal_contract_retries: BTreeMap<String, String>,
    /// Runtime-only hashed session keys (`cache_session_key`) with an open
    /// head-CAS challenge, mirrored from the upload ledger when the cycle's
    /// upload context activates. Never persisted. Such a session's answer
    /// rides only a native Full, so its files never continue from Tail state;
    /// removed once the server takes a typed basis for stored reuse.
    #[serde(skip)]
    pub(super) head_conflict_sessions: BTreeSet<String>,
    #[serde(skip)]
    pub(crate) refusal_exposure: crate::local_resource_diagnostics::RefusalExposure,
    /// Runtime-only refusal cooldowns from the upload ledger: ordinary exact
    /// bodies await their reserved re-offer; stale debt permits new input only.
    /// Neither a timer nor a revision grants stale debt a read. Never persisted
    /// or acceptance evidence; uses the existing refusal incidence.
    #[serde(skip)]
    pub(super) reason_reoffer_cooldowns: BTreeMap<String, ReasonReofferCooldown>,
    /// Claude only: the last moment this destination is known to have
    /// received history, recorded when a Mac with prior history loads a fresh
    /// index, a replay drops its entries, or a pre-gate index is first loaded
    /// by the gate. A new file born before it (or at an unknown time) is
    /// history. A malformed value decodes as `MALFORMED_CLAUDE_HISTORY_CUTOFF`
    /// and is dropped on load with the gate marker (lenient decode).
    #[serde(
        default,
        deserialize_with = "deserialize_lenient_claude_history_cutoff"
    )]
    pub(super) claude_history_cutoff_unix_seconds: Option<u64>,
    /// Claude only: a daemon with the history gate has loaded this index
    /// (StateMissing). Without it, an index a pre-gate daemon built, or
    /// rebuilt only partly, gets its cutoff on the first gated load. Any
    /// stored value but `true` reads as `false` (lenient decode, fail closed).
    #[serde(default, deserialize_with = "deserialize_lenient_true")]
    pub(super) claude_history_gate_loaded: bool,
    /// Claude only: this index's cutoff was recorded for history another
    /// destination received, under a claim policy other than an explicit
    /// `full` (cross-org move). Kept, so the hold outlives this
    /// destination's own bootstrap; only an explicit `full` claim clears it.
    #[serde(default, deserialize_with = "deserialize_lenient_move_hold")]
    pub(super) claude_history_move_not_full: bool,
    /// Claude only: an explicit `full` claim was seen for this destination,
    /// which releases its move hold for good, even while the evidence still
    /// reads as a move (its own bootstrap and uploads not yet done).
    #[serde(default, deserialize_with = "deserialize_lenient_true")]
    pub(super) claude_history_move_released: bool,
    /// Legacy carry marker. New carries have bounded per-file incidence below;
    /// old marker-only checkpoints migrate to bounded unknown incidence on read.
    #[serde(default)]
    pub(super) accepted_incidence_pending_census: bool,
    /// Accepted incidence carried by Repair, separate from current membership.
    /// Empty key means an old ACK whose file could not be named. This bounded
    /// debt survives census/held files and retires only at that file's complete,
    /// policy-permitted reconstruction. It never admits newly recorded ACKs.
    #[serde(default)]
    pub(super) accepted_rebuild_incidence: BTreeMap<String, BTreeSet<String>>,
    /// Visibility only: oldest outstanding carried set, including unknown
    /// incidence. Never used for admission, release or eviction.
    #[serde(default, deserialize_with = "deserialize_lenient_default")]
    pub(super) accepted_rebuild_pending_since_unix_seconds: Option<u64>,
    /// Persisted alarm throttle; a future value stays throttled on rollback.
    #[serde(default, deserialize_with = "deserialize_lenient_default")]
    pub(super) accepted_rebuild_last_alarm_unix_seconds: Option<u64>,
    /// Hash-only counting evidence of retired, unprotected Codex entries, by
    /// owner, so a moved session's evidence outlives its old entry being
    /// pruned on an earlier page. Written whatever the cutover, bounded by
    /// `codex_counting_version::MAX_COUNTING_TOMBSTONES`. Never file/body
    /// settlement evidence. Type damage decodes as empty, like a lost index.
    /// Appended serialized slot, so older positional indexes keep their slots.
    #[serde(default, deserialize_with = "deserialize_lenient_map")]
    pub(super) codex_counting_tombstones:
        BTreeMap<String, codex_counting_version::CountingTombstone>,
    /// Retired replay slot: drain old values without retaining authority.
    #[serde(rename = "reread_guard", default, skip_serializing)]
    pub(super) retired_reread_guard: serde::de::IgnoredAny,
    /// Diagnostic-only bounded FIFO of evicted Legacy tombstones. Appended
    /// serialized slot; old indexes default empty, damaged values are dropped.
    #[serde(default, deserialize_with = "deserialize_lenient_default")]
    pub(super) codex_counting_evicted_legacy: codex_counting_version::EvictedLegacyOwners,
    /// Scan-local cap eviction events by safety class; drained into receipts.
    #[serde(skip)]
    pub(super) codex_counting_evictions: [u64; 3],
    /// Appended persisted field: preserve every older positional index slot.
    #[serde(default)]
    pub(crate) upload_ack_retirement_handoff: Option<UploadAckRetirementHandoff>,
    /// retired_<old>: the paced held-audit slot. Decode-only; stored rows are
    /// purged by the next save.
    #[serde(rename = "held_audit_progress", default)]
    pub(super) retired_held_audit_progress: serde::de::IgnoredAny,
    /// Runtime-only, Claude only: what owed history does this cycle where no
    /// list is intended, set with the cutoff before scanning.
    #[serde(skip)]
    pub(super) claude_no_list_policy: NoListPolicy,
    /// Runtime-only history-gate decisions of this cycle, by source file.
    #[serde(skip)]
    pub(super) claude_history_emission: HistoryEmission,
    // Append persisted fields last: positional serde indexes must stay stable.
    #[serde(default, deserialize_with = "deserialize_lenient_default")]
    pub(crate) claude_money_birth_store: claude_money_birth_store::BirthStore,
    /// Inventory fence for the Desktop pagination cursor, never identity proof.
    /// The version prefix rejects #851's legacy digest; an absent/mismatched
    /// fence restarts discovery before any census can certify completeness.
    /// Reuses the existing appended positional slot.
    #[serde(
        default,
        skip_serializing_if = "claude_desktop_store_inventory_is_legacy",
        deserialize_with = "deserialize_lenient_default"
    )]
    pub(super) claude_desktop_store_inventory: Option<String>,
    /// `e2` stored copy removals (copy-family fix): what each Claude file once
    /// removed on an earlier holder's current proof stays removed after that
    /// proof retires. Bounded and local. Appended slot; older daemons ignore
    /// it. Only an empty undamaged store is never written, so an absent field
    /// is an empty store; damaged metadata stays uncertain until
    /// the current proof decides.
    #[serde(
        default,
        deserialize_with = "claude_request_money::copy_removals::CopyRemovals::deserialize_lenient"
    )]
    pub(crate) claude_copy_removals: claude_request_money::copy_removals::CopyRemovals,
    /// Per-item upload-context proof. Appended for old readers, which drop it;
    /// missing means owed. Gates no decision yet.
    #[serde(
        default,
        skip_serializing_if = "upload_context_receipt::ProofState::is_empty"
    )]
    pub(crate) upload_context_proof: upload_context_receipt::ProofState,
    // Inert accepted fields preserve the catalogue and old positional slots.
    #[serde(rename = "archives", default)]
    pub(super) retired_archives: serde::de::IgnoredAny,
    #[serde(rename = "archive_deferred_alarm_count", default)]
    pub(super) retired_archive_deferred_alarm_count: serde::de::IgnoredAny,
    /// Runtime capability only: never persisted, absent hint defaults OFF.
    #[serde(skip)]
    pub(crate) copy_unproven_enabled: bool,
    /// Runtime base delivery context; local copy-mode retry isolation is
    /// source-wide, while reacquisition is restricted to requested files.
    #[serde(skip)]
    pub(crate) copy_prefix_base_upload_context: Option<String>,
    /// Local destination-scoped publication authority, saved with re-owed marks.
    #[serde(default)]
    pub(crate) copy_prefix_last_accepted_nonce: Option<String>,
    /// retired_<old>: decode-only placeholder; keeps positional slots; never written.
    /// The per-folder login ledger, retired with its only consumer.
    #[serde(rename = "claude_folder_login_ledger", default)]
    pub(super) retired_claude_folder_login_ledger: serde::de::IgnoredAny,
    /// Durable debt facts that outlive any one traversal (state layout 5).
    #[serde(default)]
    pub(crate) tail_discovery: TailDiscovery,
}

/// The production paths that set `bounded_sweep_had_unsettled_upload`.
/// Transition diagnostics, the held-family terminal unchanged-proof skip,
/// and oversized retry scheduling read these bits. The proof skip scopes
/// `CompletedBlockingHolds` alone to its held families; oversized retries
/// preserve ordinary recovery for every other cause. Other settlement and
/// completeness readers continue to use the authoritative flag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UnsettledUploadCause {
    /// A 429/503 shed left a partial checkpoint.
    Shed,
    /// Any other upload error left a partial checkpoint.
    UploadError,
    /// A 200 deferred conflicted entities.
    DeferredConflict,
    /// Permanent refusals settled beside a local hold.
    RejectedWithHolds,
    /// A completed upload kept progress-blocking local holds.
    CompletedBlockingHolds,
    /// Uploading would have demoted a proven Claude usage authority. No
    /// longer produced: the path-(a) bridge removed the authority-only census
    /// stamp (the debt is a census reason, not an unsettled upload). Kept so
    /// a bit recorded by an earlier daemon still decodes by name.
    AuthorityCensusWithheld,
    /// Legacy settlement reconciliation armed revisions.
    LegacyReconcile,
    /// An admission-limit re-offer armed revisions.
    AdmissionReoffer,
    /// A path that does not name itself, a flag saved before causes were
    /// recorded, or a malformed recorded value.
    Unattributed,
}

impl UnsettledUploadCause {
    pub(super) const ALL: [Self; 9] = [
        Self::Shed,
        Self::UploadError,
        Self::DeferredConflict,
        Self::RejectedWithHolds,
        Self::CompletedBlockingHolds,
        Self::AuthorityCensusWithheld,
        Self::LegacyReconcile,
        Self::AdmissionReoffer,
        Self::Unattributed,
    ];

    pub(super) fn bit(self) -> u16 {
        1 << self as u16
    }

    pub(super) fn name(self) -> &'static str {
        match self {
            Self::Shed => "shed",
            Self::UploadError => "upload_error",
            Self::DeferredConflict => "deferred_conflict",
            Self::RejectedWithHolds => "rejected_with_holds",
            Self::CompletedBlockingHolds => "completed_blocking_holds",
            Self::AuthorityCensusWithheld => "authority_census_withheld",
            Self::LegacyReconcile => "legacy_reconcile",
            Self::AdmissionReoffer => "admission_reoffer",
            Self::Unattributed => "unattributed",
        }
    }

    /// Fixed names of the set bits, in declaration order. Bits a newer daemon
    /// set are kept and named `unknown` once, never read as a known set.
    pub(super) fn names(causes: u16) -> Vec<&'static str> {
        let known = Self::ALL
            .into_iter()
            .fold(0, |bits, cause| bits | cause.bit());
        let mut names: Vec<_> = Self::ALL
            .into_iter()
            .filter(|cause| causes & cause.bit() != 0)
            .map(Self::name)
            .collect();
        if causes & !known != 0 {
            names.push("unknown");
        }
        names
    }
}

impl Default for ScanIndex {
    fn default() -> Self {
        Self {
            v2: None,
            claude_money_birth_store: Default::default(),
            persistence_root: None,
            persistence_unavailable: [None; 3],
            persistence_controls: None,
            persistence_legacy_recovery: None,
            decode_holds: lenient_decode::Holds::default(),
            withheld_memo: Default::default(),
            schema_version: SCAN_INDEX_SCHEMA_VERSION,
            generation: 0,
            upload_ack_retirement_handoff: None,
            retired_upload_context_fingerprint: serde::de::IgnoredAny,
            retired_archives: serde::de::IgnoredAny,
            retired_archive_deferred_alarm_count: serde::de::IgnoredAny,
            files: SharedMap::default(),
            retired_reread_guard: serde::de::IgnoredAny,
            session_account_bindings: BTreeMap::new(),
            terminal_jsonl_dispositions: BTreeMap::new(),
            known_configured_scan_roots: BTreeSet::new(),
            legacy_unresolved_root_file_witnesses: BTreeSet::new(),
            retired_codex_state_only_snapshot_fingerprints: serde::de::IgnoredAny,
            retired_codex_state_only_blocked_session_ids: serde::de::IgnoredAny,
            retired_codex_state_only_blocked_by_file: serde::de::IgnoredAny,
            retired_codex_state_only_blocked_unattributed: serde::de::IgnoredAny,
            retired_codex_state_only_blocked_legacy: serde::de::IgnoredAny,
            retired_codex_state_only_blocked_attributed: serde::de::IgnoredAny,
            codex_parent_ownership_refs: Default::default(),
            codex_parent_ownership_ledgers: Default::default(),
            codex_parent_side_requests: Default::default(),
            codex_parent_side: Default::default(),
            codex_parent_side_generation: Default::default(),
            codex_parent_proof_wrap_epoch: Default::default(),
            codex_parent_prefix_proofs: Default::default(),
            codex_parent_proof_cursor: Default::default(),
            codex_parent_side_cursor: Default::default(),
            codex_parent_proof_seq: Default::default(),
            codex_proof_index_incarnation: Default::default(),
            claude_desktop_title_files: SharedMap::default(),
            retired_claude_account_family_witnesses: serde::de::IgnoredAny,
            retired_claude_account_family_pending: serde::de::IgnoredAny,
            claude_usage_family_witnesses: SharedMap::default(),
            retired_claude_usage_family_pending: serde::de::IgnoredAny,
            retired_family_requests: serde::de::IgnoredAny,
            claude_request_census: ClaudeRequestCensus::default(),
            claude_request_census_shadow: ClaudeRequestCensusShadowState::default(),
            claude_usage_authority_quarantine: BTreeMap::new(),
            retired_claude_retired_family_tombstones: serde::de::IgnoredAny,
            retired_claude_retired_family_tombstones_initialized: serde::de::IgnoredAny,
            retired_claude_retired_family_tombstones_uncertain: serde::de::IgnoredAny,
            retired_claude_duplicate_request_owners: serde::de::IgnoredAny,
            retired_claude_duplicate_request_witness_overflowed: serde::de::IgnoredAny,
            retired_claude_owned_start_census: serde::de::IgnoredAny,
            claude_account_deferred_holds: BTreeMap::new(),
            retired_claude_duplicate_fence_rearm_attempt: serde::de::IgnoredAny,
            retired_claude_duplicate_fence_next_full_rearm_unix_seconds: serde::de::IgnoredAny,
            retired_claude_full_rearm_progress: serde::de::IgnoredAny,
            claude_request_identity_contract: None,
            retired_claude_request_identity_contract_changed: serde::de::IgnoredAny,
            claude_desktop_store_inventory: None,
            claude_copy_removals: Default::default(),
            upload_context_proof: Default::default(),
            copy_unproven_enabled: false,
            copy_prefix_base_upload_context: None,
            copy_prefix_last_accepted_nonce: None,
            retired_claude_folder_login_ledger: serde::de::IgnoredAny,
            tail_discovery: TailDiscovery::default(),
            claude_desktop_store_cursor: None,
            claude_desktop_store_upper_bound: None,
            claude_desktop_store_sweep_had_errors: false,
            claude_desktop_identity_census_complete: false,
            claude_desktop_lineage_census_complete: false,
            retired_claude_desktop_census_witness: serde::de::IgnoredAny,
            claude_desktop_store_retry_attempt: 0,
            claude_desktop_store_retry_not_before_unix_seconds: None,
            resume_after_path: None,
            resume_upper_bound_path: None,
            resume_census_window_end: None,
            retired_held_audit_progress: serde::de::IgnoredAny,
            bounded_sweep_had_unsettled_upload: false,
            bounded_sweep_unsettled_causes: 0,
            traversal: None,
            retired_claude_stale_family_carry: serde::de::IgnoredAny,
            scan_residue_witness: None,
            historical_replay_generation: None,
            retired_context_curve_capability_enabled: serde::de::IgnoredAny,
            retired_context_curve_replay_epoch: serde::de::IgnoredAny,
            retired_completed_context_curve_replay_generation: serde::de::IgnoredAny,
            confirmed_empty_files: BTreeSet::new(),
            codex_counting_moved_evidence: BTreeMap::new(),
            codex_counting_tombstones: BTreeMap::new(),
            codex_counting_evicted_legacy: Default::default(),
            codex_counting_evictions: [0; 3],
            file_snapshot_fingerprints: SharedMap::default(),
            snapshot_activity_at: SharedMap::default(),
            accepted_snapshot_fingerprints: Default::default(),
            accepted_snapshot_fingerprint_ledger_version: SNAPSHOT_ACCEPTED_LEDGER_VERSION,
            legacy_settlement_reconcile_after_fingerprint: None,
            quarantined_snapshot_fingerprints: BTreeMap::new(),
            active_quarantine_witness: None,
            active_upload_context_fingerprint: None,
            context_read_counts: Default::default(),
            active_effective_upload_body_witness_revision: 0,
            active_effective_upload_body_witness_revision_monotone: false,
            effective_upload_body_witness_revision_excluded_source_files: BTreeSet::new(),
            claude_reemission_exclusions: ReemissionExclusions::default(),
            reason_reoffer_retries: BTreeMap::new(),
            terminal_contract_retries: BTreeMap::new(),
            head_conflict_sessions: BTreeSet::new(),
            refusal_exposure: Default::default(),
            reason_reoffer_cooldowns: BTreeMap::new(),
            claude_history_cutoff_unix_seconds: None,
            claude_history_gate_loaded: false,
            claude_history_move_not_full: false,
            claude_history_move_released: false,
            accepted_incidence_pending_census: false,
            accepted_rebuild_incidence: BTreeMap::new(),
            accepted_rebuild_pending_since_unix_seconds: None,
            accepted_rebuild_last_alarm_unix_seconds: None,
            claude_no_list_policy: NoListPolicy::Pace,
            claude_history_emission: HistoryEmission::default(),
        }
    }
}

/// Content-free proof of the code and wire contract that rejected an entity.
/// A semantic fingerprint alone is insufficient: a parser or validator fix
/// can make the same entity acceptable without changing that fingerprint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotQuarantineWitness {
    pub contract: String,
    pub collector_version: String,
    pub parser_version: String,
    pub scan_identity_version: String,
    pub snapshot_schema_version: u16,
    pub entity_ack_contract: String,
    /// Local admission policy, not part of wire or semantic identity. Legacy
    /// records predate the backend-first 640 KiB admission repair.
    #[serde(default = "legacy_snapshot_item_wire_byte_limit")]
    pub item_wire_byte_limit: usize,
}

impl SnapshotQuarantineWitness {
    /// Build/parser labels alone neither correct a body nor change its retry contract.
    pub(crate) fn same_retry_contract(&self, other: &Self) -> bool {
        self.contract == other.contract
            && self.scan_identity_version == other.scan_identity_version
            && self.snapshot_schema_version == other.snapshot_schema_version
            && self.entity_ack_contract == other.entity_ack_contract
            && self.item_wire_byte_limit == other.item_wire_byte_limit
    }

    /// The same retry contract, whatever upload context assessed the body: a
    /// context-only change reassesses at the record's own deadline, not early.
    pub(crate) fn same_retry_contract_any_context(&self, other: &Self) -> bool {
        self.same_retry_contract(other) || quarantine_context_only_changed(self, other)
    }
}

pub(super) const fn legacy_snapshot_item_wire_byte_limit() -> usize {
    128 * 1024
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotQuarantineRecord {
    /// Reconstruction semantics last assessed; legacy records were assessed under v1.
    #[serde(
        default = "terminal_contract_retry::legacy_contract",
        deserialize_with = "terminal_contract_retry::decode_contract"
    )]
    pub reconstruction_contract: u16,
    /// Claimed source acquisitions for a contract-origin retry at this version.
    /// None is an ordinary retry; Some(0) is a newly owed contract attempt.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "terminal_contract_retry::decode_claims"
    )]
    pub contract_retry_claims: Option<u16>,
    pub witness: SnapshotQuarantineWitness,
    pub retry_after_unix_seconds: u64,
    /// Optional exact hash-neutral body rejected under this contract. A body
    /// correction with the same semantic fingerprint bypasses quarantine.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upload_body_witness: Option<String>,
    #[serde(default = "initial_snapshot_reconstruction_failure_count")]
    pub failed_reconstruction_count: u8,
    #[serde(default)]
    pub disposition: SnapshotQuarantineDisposition,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotQuarantineDisposition {
    #[default]
    RetryPending,
    UnprovenTerminal,
    SupersededTerminal,
}

pub(super) const fn initial_snapshot_reconstruction_failure_count() -> u8 {
    1
}

pub fn snapshot_quarantine_witness(source: SnapshotSource) -> SnapshotQuarantineWitness {
    SnapshotQuarantineWitness {
        contract: SNAPSHOT_QUARANTINE_CONTRACT_VERSION.to_string(),
        collector_version: collector_version(),
        parser_version: source.parser_version().to_string(),
        scan_identity_version: source.scan_identity_version().to_string(),
        snapshot_schema_version: SNAPSHOT_SCHEMA_VERSION,
        entity_ack_contract: SNAPSHOT_ENTITY_ACK_CONTRACT.to_string(),
        item_wire_byte_limit: MAX_SNAPSHOT_ITEM_WIRE_BYTES,
    }
}

/// Reuse the existing refusal witness to distinguish an assessed body under
/// a changed upload policy. This is refusal/backoff evidence, never acceptance.
pub(crate) fn snapshot_quarantine_witness_for_context(
    source: SnapshotSource,
    context: &str,
) -> SnapshotQuarantineWitness {
    let mut witness = snapshot_quarantine_witness(source);
    if matches!(source, SnapshotSource::ClaudeCode | SnapshotSource::Codex) {
        witness.contract.push_str(":upload_context:");
        witness.contract.push_str(context);
    }
    witness
}

/// A policy-only reassessment must not spend an ordinary retry or move its deadline.
pub(crate) fn quarantine_context_only_changed(
    previous: &SnapshotQuarantineWitness,
    active: &SnapshotQuarantineWitness,
) -> bool {
    if previous.contract == active.contract
        || previous.contract.split(":upload_context:").next()
            != active.contract.split(":upload_context:").next()
    {
        return false;
    }
    let mut normalized = previous.clone();
    normalized.contract.clone_from(&active.contract);
    normalized.same_retry_contract(active)
}

#[cfg(test)]
pub fn snapshot_quarantine_record(source: SnapshotSource) -> SnapshotQuarantineRecord {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default();
    SnapshotQuarantineRecord {
        contract_retry_claims: None,
        reconstruction_contract: crate::snapshots::terminal_contract_retry::current_contract(),
        witness: snapshot_quarantine_witness(source),
        retry_after_unix_seconds: now.saturating_add(SNAPSHOT_QUARANTINE_RETRY_SECONDS),
        upload_body_witness: None,
        failed_reconstruction_count: initial_snapshot_reconstruction_failure_count(),
        disposition: SnapshotQuarantineDisposition::RetryPending,
    }
}

pub(crate) fn snapshot_quarantine_deadline_is_bounded(record: &SnapshotQuarantineRecord) -> bool {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default();
    snapshot_quarantine_deadline_is_bounded_at(record, now)
}

pub(super) fn snapshot_quarantine_deadline_is_bounded_at(
    record: &SnapshotQuarantineRecord,
    now: u64,
) -> bool {
    // Fresh quarantine is deterministically staggered across [6h, 12h).
    // Anything further out is corrupt state or evidence the wall clock moved
    // backwards. In either case local state must never become a permanent
    // authority that fences a repaired backend forever.
    match record.disposition {
        SnapshotQuarantineDisposition::RetryPending => {
            record.failed_reconstruction_count < MAX_SNAPSHOT_RECONSTRUCTION_FAILURES
                && record.retry_after_unix_seconds
                    <= now.saturating_add(SNAPSHOT_QUARANTINE_RETRY_SECONDS.saturating_mul(2))
        }
        SnapshotQuarantineDisposition::UnprovenTerminal => {
            record.failed_reconstruction_count == MAX_SNAPSHOT_RECONSTRUCTION_FAILURES
                && record.retry_after_unix_seconds == 0
        }
        SnapshotQuarantineDisposition::SupersededTerminal => {
            record.failed_reconstruction_count <= MAX_SNAPSHOT_RECONSTRUCTION_FAILURES
                && record.retry_after_unix_seconds == 0
        }
    }
}

pub(super) fn scan_index_schema_version() -> u16 {
    SCAN_INDEX_SCHEMA_VERSION
}
pub(super) use crate::hex::is_sha256_lower as valid_codex_protected_owner;
pub(super) fn codex_protected_owner(session: &str) -> String {
    sha256_hex(&["codex_protected_owner:v1", &resolve_codex_identity(session)])
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct SessionAccountBinding {
    pub(super) account_identifier_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) workspace_identifier_hash: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct ClaudeUsageFamilyWitness {
    pub(super) evidence_fingerprint: String,
    pub(super) member_request_id_fingerprints: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub(super) member_occurrence_fingerprints: BTreeMap<String, String>,
    pub(super) assigned_request_id_fingerprints: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub(super) legacy_excluded_request_id_hashes: BTreeMap<String, BTreeSet<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) legacy_exclusion_evidence_fingerprint: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub(super) legacy_owner_roots: BTreeSet<String>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum ClaudeUsageAuthorityQuarantineDisposition {
    #[default]
    RetryPending,
    UnprovenTerminal,
}

pub(super) fn initial_claude_usage_authority_failure_count() -> u8 {
    1
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct ClaudeUsageAuthorityQuarantineRecord {
    pub(super) contract: String,
    /// Exact content-free digest of the last proven family witness. The
    /// witness itself remains in `claude_usage_family_witnesses`; this binding
    /// prevents a stale quarantine from being paired with a different proof.
    pub(super) proven_witness_fingerprint: String,
    /// Exact scan fingerprints for every currently known family member. These
    /// contain no transcript content and let a changed revision bypass the
    /// timer while unchanged failures observe bounded retry cadence.
    pub(super) member_source_file_fingerprints: BTreeMap<String, String>,
    /// Consecutive complete-family reconstruction failures for this retained
    /// witness. Older v1 records predate the field but already represent the
    /// initial failure, so deserialize them as one rather than granting an
    /// unbounded fresh budget after upgrade.
    #[serde(default = "initial_claude_usage_authority_failure_count")]
    pub(super) failed_reconstruction_count: u8,
    #[serde(default)]
    pub(super) disposition: ClaudeUsageAuthorityQuarantineDisposition,
    pub(super) retry_after_unix_seconds: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) proof_correction: Option<ClaudeAuthorityProofCorrection>,
}

// Terminal verdicts before `e2` get one retry; delete when the count of matching records reaches 0.
pub(super) const PRE_E2_TERMINAL_DEADLINE_CUTOFF: u64 = 1_793_167_200; // 2026-10-28T06:00Z
pub(super) fn claude_terminal_predates_e2(record: &ClaudeUsageAuthorityQuarantineRecord) -> bool {
    record.disposition == ClaudeUsageAuthorityQuarantineDisposition::UnprovenTerminal
        && (1..=PRE_E2_TERMINAL_DEADLINE_CUTOFF).contains(&record.retry_after_unix_seconds)
}

crate::heap_layout_bound::fields!(ClaudeUsageAuthorityQuarantineRecord; contract, proven_witness_fingerprint, member_source_file_fingerprints, failed_reconstruction_count, disposition, retry_after_unix_seconds, proof_correction);
crate::heap_layout_bound::fields!(ClaudeUsageFamilyWitness; evidence_fingerprint, member_request_id_fingerprints, member_occurrence_fingerprints, assigned_request_id_fingerprints, legacy_excluded_request_id_hashes, legacy_exclusion_evidence_fingerprint, legacy_owner_roots);
crate::heap_layout_bound::fields!(SessionAccountBinding; account_identifier_hash, workspace_identifier_hash);
crate::heap_layout_bound::fields!(SnapshotQuarantineRecord; reconstruction_contract, contract_retry_claims, witness, retry_after_unix_seconds, upload_body_witness, failed_reconstruction_count, disposition);
crate::heap_layout_bound::fields!(SnapshotQuarantineWitness; contract, collector_version, parser_version, scan_identity_version, snapshot_schema_version, entity_ack_contract, item_wire_byte_limit);
