//! Upload progress of a routed source as keyed rows of its custody store: the
//! two keyed cache maps and the ledger (every other durable field). A
//! route's first load moves its JSON ledger in once under the import marker;
//! from then on the rows are the only progress the source reads or writes.
//!
//! A page COMMIT is the receipt: a crash before it re-offers the exact body,
//! and once it is durable the graph may settle against it.
use super::*;
use crate::snapshots::claude_request_identity::{AcceptedSession, IdentityScope};
use crate::snapshots::{ProgressMarker, ProgressPage, ProgressPoint, ProgressRead};

/// Fields the ledger never holds: the keyed maps and the generation.
const KEYED: [&str; 3] = [
    "accepted_cache_states",
    "accepted_cache_heads",
    "generation",
];

/// A legacy ACK receipt: the exact progress bytes one save was about to
/// rename over the bytes `previous_digest` names.
#[derive(Deserialize)]
struct LegacyReceipt {
    previous_digest: Option<Vec<u8>>,
    digest: Vec<u8>,
    progress: String,
}

fn legacy_digest(bytes: &[u8]) -> Vec<u8> {
    let mut hash = Sha256::new();
    hash.update(b"ottto.state-v2.ack-progress.v1\0");
    hash.update(bytes);
    hash.finalize().to_vec()
}

fn index_sibling(index_path: &Path, suffix: &str) -> PathBuf {
    let mut name = index_path.as_os_str().to_owned();
    name.push(suffix);
    name.into()
}

const LEGACY_RECEIPT: &str = ".v2-ack-receipt";
const LEGACY_FAILED_IMPORT: &str = ".v2-ack-receipt.failed-import-";

pub(super) fn valid_cache_state(key: &str, state: &serde_json::Value) -> bool {
    is_snapshot_fingerprint(key)
        && state
            .get("observations")
            .and_then(serde_json::Value::as_array)
            .is_some_and(|rows| rows.len() <= crate::snapshots::cache_observations::MAX_ROWS)
        && serde_json::to_vec(state)
            .is_ok_and(|bytes| bytes.len() <= crate::snapshots::cache_observations::MAX_STATE_BYTES)
}

pub(super) fn valid_cache_head(key: &str, head: &str) -> bool {
    is_snapshot_fingerprint(key) && is_snapshot_fingerprint(head)
}

impl SnapshotUploadProgress {
    /// A pass's progress for its loaded index: the route's rows when the
    /// source has native custody. Legacy JSON is read only by import_rows.
    pub(super) fn load_for_index(
        index: &ScanIndex,
        index_path: &Path,
        path: &Path,
        namespace: &str,
        witness: SnapshotQuarantineWitness,
    ) -> Result<Self> {
        if !crate::snapshots::state_v2_growth_retention_active(index) {
            return Err(crate::snapshots::state_v2::Hold::ReloadRequired.into());
        }
        let owner = SnapshotProgressLock::acquire(path)?.for_v2(path);
        let read = crate::snapshots::read_progress_rows(index_path, &owner)?;
        let mut progress = if read.ledger.is_none() && read.marker.is_none() {
            Self::import_rows(index, index_path, path, &owner, namespace, &witness)?
        } else {
            purge_legacy_progress(index_path, path)?;
            Self::from_rows(read, namespace, &witness)?
        };
        progress.finish_load(witness);
        Ok(progress)
    }

    /// The ledger of this progress. Identity hints are rows of their own
    /// (`accepted_identity_scope` holds their barriers).
    pub(super) fn ledger_row(&mut self) -> Result<serde_json::Value> {
        let states = std::mem::take(&mut self.accepted_cache_states);
        let heads = std::mem::take(&mut self.accepted_cache_heads);
        let hints = std::mem::take(&mut self.accepted_identity_buckets);
        let ledger = serde_json::to_value(&*self);
        self.accepted_cache_states = states;
        self.accepted_cache_heads = heads;
        self.accepted_identity_buckets = hints;
        let mut ledger = ledger.context("encode snapshot upload progress ledger")?;
        let fields = ledger
            .as_object_mut()
            .context("snapshot upload progress ledger is an object")?;
        for field in KEYED {
            fields.remove(field);
        }
        Ok(ledger)
    }

    /// Rebuild from hydrated rows. Invalid keyed rows are set aside, counted
    /// and stay stored; an invalid ledger holds the whole source.
    fn from_rows(
        read: ProgressRead,
        namespace: &str,
        witness: &SnapshotQuarantineWitness,
    ) -> Result<Self> {
        let ProgressRead {
            cache_state,
            cache_head,
            ledger,
            mut rows,
            ..
        } = read;
        let mut ledger = ledger.context("state_v2 upload progress rows lack their ledger")?;
        let (mut states, mut heads) = (BTreeMap::new(), BTreeMap::new());
        let (mut bad_states, mut bad_heads) = (Vec::new(), Vec::new());
        for (key, state) in cache_state {
            if valid_cache_state(&key, &state) {
                states.insert(key, state);
            } else {
                bad_states.push(key);
            }
        }
        for (key, head) in cache_head {
            match head.as_str() {
                Some(head) if valid_cache_head(&key, head) => {
                    heads.insert(key, head.to_owned());
                }
                _ => bad_heads.push(key),
            }
        }
        rows.set_aside(&bad_states, &bad_heads)?;
        ledger
            .as_object_mut()
            .context("state_v2 upload progress ledger is an object")?
            .insert("generation".into(), rows.generation().into());
        let mut progress: Self =
            serde_json::from_value(ledger).context("parse state_v2 upload progress ledger")?;
        progress.accepted_cache_states = states;
        progress.accepted_cache_heads = heads;
        if progress.destination_namespace_hash != namespace {
            // Another destination's progress, as the JSON load clears it.
            progress = Self::new(namespace.to_owned(), witness.clone());
            progress.generation = rows.generation();
        } else {
            anyhow::ensure!(
                progress.valid(namespace),
                "state_v2 upload progress ledger is invalid"
            );
        }
        progress.rows = Some(Box::new(rows));
        Ok(progress)
    }

    /// The one-time import: the JSON ledger (or the exact progress a legacy
    /// ACK receipt holds ahead of it) becomes the route's first rows with the
    /// import marker at P = 1, its identity hints one row per session.
    /// Unparseable input or an invalid ledger holds the source and stays on
    /// disk; an invalid keyed entry imports as its row and is set aside, as
    /// the row loader treats it. A failed COMMIT holds this pass, and the next
    /// load imports again. Once the marker commits the legacy files are
    /// purged.
    fn import_rows(
        index: &ScanIndex,
        index_path: &Path,
        path: &Path,
        owner: &SnapshotProgressLock,
        namespace: &str,
        witness: &SnapshotQuarantineWitness,
    ) -> Result<Self> {
        let json = match std::fs::read(path) {
            Ok(bytes) => Some(bytes),
            Err(error) if error.kind() == ErrorKind::NotFound => None,
            Err(error) => return Err(error).context("read snapshot upload progress for import"),
        };
        let input = match legacy_receipt_ahead(index_path, json.as_deref())? {
            Some(next) => next,
            None => json.unwrap_or_default(),
        };
        let mut progress = if input.is_empty() {
            Self::new(namespace.to_owned(), witness.clone())
        } else {
            serde_json::from_slice::<Self>(&input)
                .context("parse snapshot upload progress for import")?
        };
        let marker = ProgressMarker {
            sha256: crate::hex::encode(&Sha256::digest(&input)),
            generation: progress.generation,
        };
        if progress.destination_namespace_hash != namespace {
            progress = Self::new(namespace.to_owned(), witness.clone());
        }
        anyhow::ensure!(
            progress.valid(namespace),
            "snapshot upload progress for import is invalid"
        );
        progress.accepted_identity_scope = IdentityScope {
            key_epoch: progress.accepted_identity_buckets.resident_epoch(),
            ..IdentityScope::default()
        };
        let states = &progress.accepted_cache_states;
        let bad_states: Vec<String> = states
            .iter()
            .filter(|(key, state)| !valid_cache_state(key, state))
            .map(|(key, _)| key.clone())
            .collect();
        let heads = &progress.accepted_cache_heads;
        let bad_heads: Vec<String> = heads
            .iter()
            .filter(|(key, head)| !valid_cache_head(key, head))
            .map(|(key, _)| key.clone())
            .collect();
        let ledger = progress.ledger_row()?;
        let points = progress.accepted_identity_buckets.dirty();
        let page = (
            &progress.accepted_cache_states,
            &progress.accepted_cache_heads,
            &ledger,
        );
        let rows = crate::snapshots::import_progress_rows(
            index, index_path, owner, page, &points, &marker,
        )?;
        let progress = match rows {
            Some(mut rows) => {
                // Stored and counted, never accepted evidence: the next body
                // for that session is fuller, never smaller.
                rows.set_aside(&bad_states, &bad_heads)?;
                for key in &bad_states {
                    progress.accepted_cache_states.remove(key);
                }
                for key in &bad_heads {
                    progress.accepted_cache_heads.remove(key);
                }
                progress.generation = rows.generation();
                progress.rows = Some(Box::new(rows));
                progress.accepted_identity_buckets.release();
                progress
            }
            // Another writer's import committed first: its rows win.
            None => Self::from_rows(
                crate::snapshots::read_progress_rows(index_path, owner)?,
                namespace,
                witness,
            )?,
        };
        purge_legacy_progress(index_path, path)?;
        Ok(progress)
    }

    /// Write one progress page: the changed keyed rows and the ledger, at
    /// this pass's progress generation. Nothing durable on NotPublished: RAM
    /// keeps every change and the next save writes it again.
    /// Identity hints whose encoded value changed ride the same commit as
    /// rows; once durable every resident hint is released.
    pub(super) fn save_rows(&mut self, path: &Path) -> Result<()> {
        let owner = SnapshotProgressLock::acquire(path)?.for_v2(path);
        let ledger = self.ledger_row()?;
        let points = self.accepted_identity_buckets.dirty();
        let rows = self
            .rows
            .as_mut()
            .context("snapshot upload progress rows are not loaded")?;
        if rows.generation() != self.generation {
            return Err(anyhow!("snapshot upload progress changed concurrently"));
        }
        let page = (
            &self.accepted_cache_states,
            &self.accepted_cache_heads,
            &ledger,
        );
        match rows.commit(&owner, page, &points)? {
            ProgressPage::Committed(generation) => self.generation = generation,
            ProgressPage::Unchanged => {}
            ProgressPage::NotPublished => {
                return Err(anyhow!("snapshot upload progress page was not published"))
            }
        }
        self.accepted_identity_buckets.release();
        Ok(())
    }

    /// Before a consumer reads identity hints: load the stored rows of
    /// `sessions` not resident, under the stored scope. A row from before a
    /// key epoch change or under another epoch stays unloaded; one from
    /// before a replay change loads without retained proof. The JSON ledger
    /// keeps every hint resident.
    pub(super) fn load_identity<'s>(
        &mut self,
        sessions: impl IntoIterator<Item = &'s str>,
    ) -> Result<()> {
        let Some(rows) = self.rows.as_deref() else {
            return Ok(());
        };
        let hints = &mut self.accepted_identity_buckets;
        let scope = &mut self.accepted_identity_scope;
        let epoch = hints.epoch();
        if scope.key_epoch != epoch {
            hints.discard_resident(scope.key_epoch.is_some());
            scope.key_epoch = epoch;
            scope.discard_before = self.generation.saturating_add(1);
        }
        let keys = (sessions.into_iter())
            .filter_map(|session| hints.row_name(session))
            .filter(|name| !hints.holds_row(name))
            .collect::<BTreeSet<_>>();
        let discard_before = scope.discard_before;
        let points = rows.read_points::<ProgressPoint<AcceptedSession>>(&keys, |_, point| {
            point.progress_generation >= discard_before && hints.admissible(&point.accepted)
        })?;
        for (name, point) in points {
            hints.admit(name, point.accepted);
        }
        Ok(())
    }

    /// The committed ledger, as a durable-state read (partial checkpoint).
    pub(super) fn durable_rows(
        &self,
        index_path: &Path,
        owner: &SnapshotProgressLock,
    ) -> Result<Self> {
        let (ledger, generation) = crate::snapshots::read_progress_ledger(index_path, owner)?;
        let mut ledger = ledger.context("state_v2 upload progress rows lack their ledger")?;
        ledger
            .as_object_mut()
            .context("state_v2 upload progress ledger is an object")?
            .insert("generation".into(), generation.into());
        serde_json::from_value(ledger).context("parse state_v2 upload progress ledger")
    }
}

/// The exact progress a legacy receipt holds ahead of `json`: a crash came
/// between the receipt and the JSON rename. A receipt that does not parse
/// holds the source; one that is not ahead is ignored.
fn legacy_receipt_ahead(index_path: &Path, json: Option<&[u8]>) -> Result<Option<Vec<u8>>> {
    let bytes = match std::fs::read(index_sibling(index_path, LEGACY_RECEIPT)) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).context("read legacy upload progress receipt"),
    };
    let receipt: LegacyReceipt =
        serde_json::from_slice(&bytes).context("parse legacy upload progress receipt")?;
    let next = receipt.progress.into_bytes();
    anyhow::ensure!(
        legacy_digest(&next) == receipt.digest,
        "legacy upload progress receipt digest"
    );
    let ahead = receipt.previous_digest == json.map(legacy_digest);
    Ok(ahead.then_some(next))
}

/// Remove the JSON ledger and legacy receipt files unread, once the rows own
/// the route's progress.
fn purge_legacy_progress(index_path: &Path, path: &Path) -> Result<()> {
    let mut removed = false;
    let mut remove = |file: &Path| -> Result<()> {
        match std::fs::remove_file(file) {
            Ok(()) => removed = true,
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(error) => return Err(error).context("purge legacy upload progress"),
        }
        Ok(())
    };
    remove(path)?;
    remove(&index_sibling(index_path, LEGACY_RECEIPT))?;
    if let (Some(parent), Some(name)) = (index_path.parent(), index_path.file_name()) {
        let mut prefix = name.to_owned();
        prefix.push(LEGACY_FAILED_IMPORT);
        let prefix = prefix.to_string_lossy().into_owned();
        let entries = match std::fs::read_dir(parent) {
            Ok(entries) => entries,
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error).context("list legacy upload progress"),
        };
        for entry in entries {
            let entry = entry.context("list legacy upload progress")?;
            if entry.file_name().to_string_lossy().starts_with(&prefix) {
                remove(&entry.path())?;
            }
        }
    }
    if removed {
        sync_progress_parent(path)?;
    }
    Ok(())
}

pub(super) const SNAPSHOT_UPLOAD_PROGRESS_SCHEMA_VERSION: u16 = 3;

/// Durable, privacy-minimal progress for one policy-scoped scan index.
///
/// The scanner cannot commit its final `ScanIndex` until every changed
/// snapshot is accepted: committing it earlier would silently drop the files
/// represented by a later failed batch. Persisting only the stable semantic
/// snapshot fingerprints lets a restart skip already-accepted pages without
/// retaining titles, paths, or prompts. Numeric cache evidence and opaque accepted
/// head tokens survive cycle cleanup for later corrections; session keys are hashes.
/// A subset of the current file/entity incidence table, containing only cache
/// evidence actually deferred for missing accepted predecessor authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct PendingCacheHeadFile {
    pub(super) source_file_fingerprint: String,
    pub(super) group_fingerprint: String,
    /// Semantic entity -> hashed session key; no source body or authority.
    pub(super) entities: BTreeMap<String, String>,
    /// Sessions whose head arrival already reached a saved current file group.
    /// Failed bodies remain owed, but normal quarantine drives their retry.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub(super) reselected_heads: BTreeMap<String, String>,
    /// Exact cache-bearing settlements recorded only after the index save.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub(super) settled_entities: BTreeSet<String>,
}

/// A server head-CAS challenge this session still owes an answer. The
/// challenge binds the server's current head to the exact refused revision v2
/// hash, so the next upload can replace the stale base through the backend's
/// existing rescan handshake instead of conflicting on it forever.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct HeadConflictChallenge {
    pub(super) challenge: String,
    pub(super) stale_revision_v2_hash: String,
    /// Answers the server refused again. Counted and logged; never terminal,
    /// so an unrecovered session keeps today's retryable conflict hold.
    #[serde(default)]
    pub(super) answer_attempts: u32,
    /// When an answer to THIS challenge and revision was last refused; 0 when
    /// none was. A re-send of the same held body waits its conflict probe
    /// after it; a new challenge or revision resets it.
    #[serde(default)]
    pub(super) last_answer_unix: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct PermanentSnapshotRejection {
    pub(super) body_witness: String,
    /// Old enum vocabulary only: `original_pair_candidate_unproved` is
    /// written as `other`, so an older daemon keeps reading and suppressing it.
    pub(super) reason: crate::upload_receipts::RejectedUsageReason,
    /// Optional daily/one-time re-offer schedule for this exact body. Older
    /// daemons ignore it; a malformed value disables only this record's retry.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        serialize_with = "reason_reoffer::serialize",
        deserialize_with = "reason_reoffer::deserialize"
    )]
    pub(super) reoffer: Option<reason_reoffer::RefusalReoffer>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "stale_owed::decode_exposure"
    )]
    pub(super) exposure: Option<stale_owed::Exposure>,
    /// Exact older revisions remain with their existing refusal owner.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub(super) revisions: BTreeMap<String, PermanentSnapshotRejection>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct SnapshotUploadProgress {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) telemetry_only: Option<Box<telemetry_only::Ledger>>,
    pub(super) schema_version: u16,
    /// A routed source's progress rows; never serialized into the ledger.
    #[serde(skip)]
    pub(super) rows: Option<Box<crate::snapshots::ProgressRows>>,
    #[serde(default)]
    pub(super) generation: u64,
    pub(super) destination_namespace_hash: String,
    /// Full replay generation whose ACKs populate this ledger. A new reviewed
    /// replay must not inherit ACKs for identical entities from an older
    /// generation, while a restart of the same generation must still resume.
    #[serde(default)]
    pub(super) historical_replay_generation: Option<String>,
    #[serde(default)]
    pub(super) accepted_fingerprints: BTreeSet<String>,
    /// Exact local body witness accepted for each semantic entity. Schema v3
    /// prevents a crash-resume ledger for curve A from suppressing corrected
    /// curve B, while the backend continues to ACK the stable semantic
    /// fingerprint.
    #[serde(default)]
    pub(super) accepted_body_witnesses: BTreeMap<String, String>,
    /// Exact context of each durable stored-body ACK; absent means unknown.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub(super) accepted_body_contexts: BTreeMap<String, String>,
    #[serde(skip)]
    pub(super) context_resend: upload_context_resend::Cycle,
    /// Admission only: current live incidence plus bounded unsettled ACK debt.
    #[serde(skip, default = "ack_retention::default_ack_capacity")]
    pub(super) ack_capacity: usize,
    /// ACKs outside known live incidence; includes valid unindexed debt.
    #[serde(skip)]
    pub(super) retained_stale_ack_count: usize,
    #[serde(default)]
    pub(super) accepted_cache_states: BTreeMap<String, serde_json::Value>,
    /// Class L bucket/share fingerprints, written only for stored-body ACKs.
    #[serde(
        default,
        skip_serializing_if = "crate::snapshots::claude_request_identity::AcceptedBuckets::is_empty"
    )]
    pub(super) accepted_identity_buckets:
        crate::snapshots::claude_request_identity::AcceptedBuckets,
    /// Routed progress: the stored identity rows' barriers. The hints
    /// themselves are rows of their own, loaded per page.
    #[serde(
        default,
        skip_serializing_if = "crate::snapshots::claude_request_identity::IdentityScope::is_unset"
    )]
    pub(super) accepted_identity_scope: crate::snapshots::claude_request_identity::IdentityScope,
    #[serde(default)]
    pub(super) accepted_cache_heads: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub(super) pending_cache_heads: BTreeMap<String, PendingCacheHeadFile>,
    /// Head-CAS conflict challenges keyed like `accepted_cache_heads`. Any
    /// accepted or unchanged ACK for the session clears its entry.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub(super) head_conflict_challenges: BTreeMap<String, HeadConflictChallenge>,
    #[serde(default)]
    pub(super) quarantined_fingerprints: BTreeMap<String, SnapshotQuarantineRecord>,
    /// Exact server-permanent refusals. Same destination, entity and body only;
    /// parser/replay epochs and premature retry timers cannot erase this fact.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub(super) permanent_rejections: BTreeMap<String, PermanentSnapshotRejection>,
    #[serde(skip)]
    pub(super) active_quarantine_witness: Option<SnapshotQuarantineWitness>,
    /// Runtime leases for quarantine entries selected this cycle. The durable
    /// record stays armed with its next future deadline until an exact ACK
    /// clears it; this set only bypasses suppression for the current request.
    #[serde(skip)]
    pub(super) active_quarantine_retries: BTreeSet<String>,
    /// Runtime leases for refusals re-offered this cycle: fingerprint -> the
    /// exact refused body witness. Only that body passes permanent
    /// suppression, once per logical offer; the refusal stays durable.
    #[serde(skip)]
    pub(super) active_reason_reoffers: BTreeMap<String, String>,
    #[serde(skip)]
    pub(super) attempted_reason_reoffers: BTreeSet<String>,
    #[serde(skip)]
    pub(super) reason_reoffer_counts: reason_reoffer::ReofferCounts,
    #[serde(skip)]
    pub(super) terminal_contract_retry_pending_save: bool,
    /// Only exact entity ACKs observed in this cycle; never restored from disk.
    #[serde(skip)]
    pub(super) fresh_context_body_acks: BTreeMap<String, String>,
    #[serde(skip)]
    pub(super) context_receipt_candidates: Vec<crate::snapshots::UploadContextReceiptCandidate>,
    #[serde(skip)]
    pub(super) request_contributions:
        BTreeMap<String, (String, crate::snapshots::upload_context_receipt::SlotRows)>,
    /// Sessions whose identity-503 deferral still owes a later main-upload
    /// ACK (`cache_session_key`). Absent is unknown or nothing owed; only an
    /// empty set clears the walk's `Isolated503` cause.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "decode_identity_503_pending"
    )]
    pub(super) identity_503_pending: Option<BTreeSet<String>>,
    /// Main page upload only: this pass's identity-503 inserts. `None`
    /// elsewhere (bootstrap probes, retries), which neither record nor drain.
    #[serde(skip)]
    pub(super) identity_503_pass: Option<BTreeSet<String>>,
}

/// Malformed custody decodes as absent (unknown), never as an empty set.
fn decode_identity_503_pending<'de, D: serde::Deserializer<'de>>(
    decoder: D,
) -> Result<Option<BTreeSet<String>>, D::Error> {
    let value = serde_json::Value::deserialize(decoder)?;
    Ok(serde_json::from_value::<BTreeSet<String>>(value)
        .ok()
        .filter(|keys| keys.iter().all(|key| is_snapshot_fingerprint(key))))
}

/// What a save's compare-and-swap reads from the on-disk progress: the writer
/// stamp and the quarantine claims to merge. Other fields are skipped, not kept.
#[cfg(test)]
#[derive(Deserialize)]
pub(super) struct SnapshotUploadProgressCas {
    pub(super) schema_version: u16,
    #[serde(default)]
    pub(super) generation: u64,
    pub(super) destination_namespace_hash: String,
    #[serde(default)]
    pub(super) quarantined_fingerprints: BTreeMap<String, SnapshotQuarantineRecord>,
}

impl SnapshotUploadProgress {
    /// A server-attested record of an earlier upload to this destination: an
    /// accepted, quarantined or refused body, or accepted cache evidence
    /// (prior history). A saved generation, a replay claim or a
    /// pending cache head is this daemon's own claim, saved before any upload,
    /// so it is not evidence.
    pub(super) fn records_server_attested_upload(&self) -> bool {
        !self.accepted_fingerprints.is_empty()
            || !self.accepted_body_witnesses.is_empty()
            || !self.accepted_cache_states.is_empty()
            || !self.accepted_cache_heads.is_empty()
            || !self.quarantined_fingerprints.is_empty()
            || !self.permanent_rejections.is_empty()
    }

    pub(super) fn new(
        destination_namespace_hash: String,
        active_quarantine_witness: SnapshotQuarantineWitness,
    ) -> Self {
        Self {
            schema_version: SNAPSHOT_UPLOAD_PROGRESS_SCHEMA_VERSION,
            telemetry_only: None,
            rows: None,
            generation: 0,
            destination_namespace_hash,
            historical_replay_generation: None,
            accepted_fingerprints: BTreeSet::new(),
            accepted_body_witnesses: BTreeMap::new(),
            accepted_body_contexts: BTreeMap::new(),
            context_resend: upload_context_resend::Cycle::default(),
            ack_capacity: ack_retention::default_ack_capacity(),
            retained_stale_ack_count: 0,
            accepted_cache_states: BTreeMap::new(),
            accepted_identity_buckets: Default::default(),
            accepted_identity_scope: Default::default(),
            accepted_cache_heads: BTreeMap::new(),
            pending_cache_heads: BTreeMap::new(),
            head_conflict_challenges: BTreeMap::new(),
            quarantined_fingerprints: BTreeMap::new(),
            permanent_rejections: BTreeMap::new(),
            active_quarantine_witness: Some(active_quarantine_witness),
            active_quarantine_retries: BTreeSet::new(),
            active_reason_reoffers: BTreeMap::new(),
            attempted_reason_reoffers: BTreeSet::new(),
            reason_reoffer_counts: reason_reoffer::ReofferCounts::default(),
            terminal_contract_retry_pending_save: false,
            fresh_context_body_acks: BTreeMap::new(),
            context_receipt_candidates: Vec::new(),
            request_contributions: BTreeMap::new(),
            identity_503_pending: None,
            identity_503_pass: None,
        }
    }

    #[cfg(test)]
    pub(super) fn load(
        path: &Path,
        expected_destination_namespace_hash: &str,
        active_quarantine_witness: SnapshotQuarantineWitness,
    ) -> Result<Self> {
        let _lock = SnapshotProgressLock::acquire(path)?;
        if !path.exists() {
            return Ok(Self::new(
                expected_destination_namespace_hash.to_string(),
                active_quarantine_witness,
            ));
        }
        let parsed = std::fs::read(path)
            .context("read snapshot upload progress")
            .and_then(|bytes| {
                serde_json::from_slice::<Self>(&bytes)
                    .context("parse v3 local snapshot upload progress")
            });
        let mut progress = match parsed {
            Ok(progress)
                if progress.valid(expected_destination_namespace_hash)
                    && progress
                        .accepted_cache_states
                        .iter()
                        .all(|(key, state)| progress_rows::valid_cache_state(key, state))
                    && progress
                        .accepted_cache_heads
                        .iter()
                        .all(|(key, head)| progress_rows::valid_cache_head(key, head)) =>
            {
                progress
            }
            Ok(_) | Err(_) => {
                quarantine_invalid_progress(path)?;
                return Ok(Self::new(
                    expected_destination_namespace_hash.to_string(),
                    active_quarantine_witness,
                ));
            }
        };
        progress.finish_load(active_quarantine_witness);
        Ok(progress)
    }

    /// Every durable field but the keyed cache maps is admissible for this
    /// destination.
    pub(super) fn valid(&self, namespace: &str) -> bool {
        self.schema_version == SNAPSHOT_UPLOAD_PROGRESS_SCHEMA_VERSION
            && self.destination_namespace_hash == namespace
            && is_snapshot_fingerprint(&self.destination_namespace_hash)
            && self
                .accepted_fingerprints
                .iter()
                .all(|value| is_snapshot_fingerprint(value))
            && self.accepted_body_witnesses.len() == self.accepted_fingerprints.len()
            && self.accepted_body_witnesses.keys().all(|value| {
                is_snapshot_fingerprint(value) && self.accepted_fingerprints.contains(value)
            })
            && self
                .accepted_body_witnesses
                .values()
                .all(|value| is_snapshot_fingerprint(value))
            && self.accepted_body_contexts.iter().all(|(key, context)| {
                self.accepted_body_witnesses.contains_key(key) && is_snapshot_fingerprint(context)
            })
            && self.pending_cache_heads.iter().all(|(file, pending)| {
                let sessions = pending.entities.values().collect::<BTreeSet<_>>();
                is_snapshot_fingerprint(file)
                    && is_snapshot_fingerprint(&pending.source_file_fingerprint)
                    && is_snapshot_fingerprint(&pending.group_fingerprint)
                    && !pending.entities.is_empty()
                    && pending.reselected_heads.iter().all(|(key, witness)| {
                        is_snapshot_fingerprint(witness) && sessions.contains(key)
                    })
                    && pending
                        .settled_entities
                        .iter()
                        .all(|entity| pending.entities.contains_key(entity))
                    && pending.entities.iter().all(|(entity, session)| {
                        is_snapshot_fingerprint(entity) && is_snapshot_fingerprint(session)
                    })
            })
            && self
                .quarantined_fingerprints
                .keys()
                .all(|value| is_snapshot_fingerprint(value))
            && self
                .permanent_rejections
                .iter()
                .all(|(fingerprint, record)| {
                    is_snapshot_fingerprint(fingerprint)
                        && is_snapshot_fingerprint(&record.body_witness)
                })
            && self.quarantined_fingerprints.values().all(|record| {
                snapshot_quarantine_deadline_is_bounded(record)
                    && record
                        .upload_body_witness
                        .as_deref()
                        .map_or(true, is_snapshot_fingerprint)
            })
    }

    /// Runtime state a loaded ledger starts every pass with.
    pub(super) fn finish_load(&mut self, active_quarantine_witness: SnapshotQuarantineWitness) {
        let permanent = &self.permanent_rejections;
        self.terminal_contract_retry_pending_save = crate::snapshots::terminal_contract_retry::rearm(
            self.quarantined_fingerprints
                .iter_mut()
                .filter(|(fingerprint, record)| {
                    !permanent.get(*fingerprint).is_some_and(|refusal| {
                        record.upload_body_witness.as_deref() == Some(refusal.body_witness.as_str())
                    })
                }),
            Some(&active_quarantine_witness),
        ) > 0;
        self.active_quarantine_witness = Some(active_quarantine_witness);
        self.active_quarantine_retries.clear();
        self.active_reason_reoffers.clear();
    }

    /// Rearm every current entity exactly once for a new historical replay.
    ///
    /// The scan index independently clears its file checkpoints, but stable
    /// semantic fingerprints mean an older accepted/quarantined progress entry
    /// could otherwise suppress the re-derived upload. Keep same-generation
    /// progress intact so page ACKs and conflict retries remain resumable.
    pub(super) fn prepare_historical_replay(&mut self, generation: &str) -> bool {
        if self.historical_replay_generation.as_deref() == Some(generation) {
            return false;
        }
        self.historical_replay_generation = Some(generation.to_string());
        // The removed retained-identity barrier: still written so the stored
        // scope keeps its bytes; nothing reads it.
        if self.rows.is_some() && !self.accepted_identity_scope.is_unset() {
            self.accepted_identity_scope.retained_before = self.generation.saturating_add(1);
        }
        self.accepted_fingerprints.clear();
        self.accepted_body_witnesses.clear();
        self.accepted_body_contexts.clear();
        self.quarantined_fingerprints.clear();
        for pending in self.pending_cache_heads.values_mut() {
            pending.settled_entities.clear();
            pending.reselected_heads.clear();
        }
        true
    }

    pub(super) fn save(&mut self, path: &Path) -> Result<()> {
        if self.rows.is_none() {
            return Err(crate::snapshots::state_v2::Hold::ReloadRequired.into());
        }
        self.accepted_body_contexts
            .retain(|fp, _| self.accepted_body_witnesses.contains_key(fp));
        self.save_rows(path)
    }

    /// The concurrent-writer stamp of every progress write: the on-disk stamp
    /// is this owner's last save and nobody has saved since.
    pub(super) fn same_writer(
        &self,
        (schema_version, generation, namespace): (u16, u64, &str),
    ) -> bool {
        schema_version == SNAPSHOT_UPLOAD_PROGRESS_SCHEMA_VERSION
            && generation == self.generation
            && namespace == self.destination_namespace_hash
    }

    pub(super) fn stamp(&self) -> (u16, u64, &str) {
        let namespace = self.destination_namespace_hash.as_str();
        (self.schema_version, self.generation, namespace)
    }

    /// Fixture persistence is explicit; native owners still use the real saver.
    #[cfg(test)]
    pub(super) fn save_fixture(&mut self, path: &Path) -> Result<()> {
        self.save_legacy_fixture(path)
    }

    #[cfg(test)]
    pub(super) fn finish_cycle_fixture(&mut self, path: &Path) -> Result<()> {
        match self.finish_cycle(path) {
            Err(error)
                if self.rows.is_none()
                    && error.downcast_ref::<crate::snapshots::state_v2::Hold>()
                        == Some(&crate::snapshots::state_v2::Hold::ReloadRequired) =>
            {
                self.save_fixture(path)
            }
            result => result,
        }
    }

    /// Explicit old-release input export for decoder and ACK-import fixtures.
    #[cfg(test)]
    pub(super) fn save_legacy_fixture(&mut self, path: &Path) -> Result<()> {
        self.accepted_body_contexts
            .retain(|fp, _| self.accepted_body_witnesses.contains_key(fp));
        if self.rows.is_some() {
            return self.save_rows(path);
        }
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).context("create snapshot upload progress directory")?;
        }
        let _lock = SnapshotProgressLock::acquire(path)?;
        let mut unchanged = false;
        if path.exists() {
            let bytes = std::fs::read(path).context("read current snapshot upload progress")?;
            let current: SnapshotUploadProgressCas = serde_json::from_slice(&bytes)
                .map_err(anyhow::Error::from)
                .context("parse current snapshot upload progress for compare-and-swap")?;
            let namespace = current.destination_namespace_hash.as_str();
            if !self.same_writer((current.schema_version, current.generation, namespace)) {
                return Err(anyhow!("snapshot upload progress changed concurrently"));
            }
            crate::snapshots::terminal_contract_retry::merge_maps(
                &mut self.quarantined_fingerprints,
                &current.quarantined_fingerprints,
            );
            unchanged = serializes_to(&*self, &bytes);
        } else if self.generation != 0 {
            return Err(anyhow!("snapshot upload progress disappeared concurrently"));
        }
        if unchanged {
            // The durable ledger already holds these exact bytes at this
            // generation: write nothing and claim no generation, so the next
            // writer's compare-and-swap still matches. Retry only the
            // durability barrier: an earlier rename may be visible but not
            // yet synced.
            return sync_progress_parent(path);
        }
        let previous_generation = self.generation;
        self.generation = self
            .generation
            .checked_add(1)
            .ok_or_else(|| anyhow!("snapshot upload progress generation overflow"))?;
        let temp_path = path.with_extension(format!("json.{}.tmp", std::process::id()));
        let mut file =
            std::fs::File::create(&temp_path).context("create snapshot upload progress temp")?;
        let result = (|| -> Result<()> {
            serde_json::to_writer(&mut file, &*self)
                .context("write snapshot upload progress temp")?;
            file.sync_all()
                .context("sync snapshot upload progress temp")?;
            std::fs::rename(&temp_path, path).context("replace snapshot upload progress")?;
            sync_progress_parent(path)
        })();
        if result.is_err() {
            self.generation = previous_generation;
            let _ = std::fs::remove_file(&temp_path);
        }
        result
    }

    /// A retired walk's custody ends with it, except this pass's own
    /// deferrals (its page was sent after the walk's terminal verdict, so
    /// they hold the walk that follows). An owed or unknown cause becomes
    /// explicit custody, so the next reconcile settles it; one blocked walk
    /// bounds a session that is never ACKed.
    pub(super) fn retire_identity_503_custody(&mut self, this_pass: BTreeSet<String>, owed: bool) {
        let pending = self.identity_503_pending.take();
        self.identity_503_pending = pending
            .or_else(|| owed.then(BTreeSet::new))
            .map(|pending| &pending & &this_pass);
    }

    pub(super) fn finish_cycle(&mut self, path: &Path) -> Result<()> {
        if self.rows.is_none()
            && self.accepted_fingerprints.is_empty()
            && self.permanent_rejections.is_empty()
            && self.accepted_cache_states.is_empty()
            && self.accepted_cache_heads.is_empty()
            && self.pending_cache_heads.is_empty()
            && self.head_conflict_challenges.is_empty()
            && self.accepted_identity_buckets.is_empty()
            && self.identity_503_pending.is_none()
        {
            return self.clear(path);
        }
        // Unadopted ACKs survive until a successful index save transfers them.
        // A later conflict on the refused bytes is the stronger settlement
        // fact, even while the retained refusal gates its next daily offer.
        // Keep it in the same atomic ledger so an older index-only timer can
        // still be distinguished from this newer server answer on restart.
        self.quarantined_fingerprints.retain(|fingerprint, record| {
            record.disposition == SnapshotQuarantineDisposition::RetryPending
                && self
                    .permanent_rejections
                    .get(fingerprint)
                    .is_some_and(|refusal| {
                        record.upload_body_witness.as_deref() == Some(refusal.body_witness.as_str())
                    })
        });
        self.active_quarantine_retries.clear();
        self.active_reason_reoffers.clear();
        self.save(path)
    }

    pub(super) fn clear(&self, path: &Path) -> Result<()> {
        let _lock = SnapshotProgressLock::acquire(path)?;
        let current = match std::fs::read(path) {
            Ok(bytes) => serde_json::from_slice::<Self>(&bytes)
                .context("parse snapshot upload progress before clear")?,
            Err(error) if error.kind() == ErrorKind::NotFound && self.generation == 0 => {
                return Ok(())
            }
            Err(error) if error.kind() == ErrorKind::NotFound => {
                return Err(anyhow!("snapshot upload progress disappeared concurrently"))
            }
            Err(error) => return Err(error).context("read snapshot upload progress before clear"),
        };
        if !self.same_writer(current.stamp()) {
            return Err(anyhow!("snapshot upload progress changed concurrently"));
        }
        let tombstone = unique_progress_sibling(path, "cleared");
        std::fs::rename(path, &tombstone).context("atomically clear snapshot upload progress")?;
        sync_progress_parent(path)?;
        std::fs::remove_file(&tombstone).context("remove cleared snapshot upload progress")?;
        sync_progress_parent(path)
    }
}

pub(crate) struct SnapshotProgressLock {
    pub(super) file: std::fs::File,
    pub(super) path: Option<Box<Path>>,
}

impl SnapshotProgressLock {
    pub(super) fn acquire(path: &Path) -> Result<Self> {
        let lock_path = path.with_extension("lock");
        if let Some(parent) = lock_path.parent() {
            std::fs::create_dir_all(parent).context("create snapshot upload progress directory")?;
        }
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(lock_path)
            .context("open snapshot upload progress lock")?;
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
                return Err(std::io::Error::last_os_error())
                    .context("snapshot upload progress is owned by another daemon");
            }
        }
        Ok(Self { file, path: None })
    }

    pub(super) fn for_v2(mut self, path: &Path) -> Self {
        self.path = Some(path.into());
        self
    }
}

impl Drop for SnapshotProgressLock {
    fn drop(&mut self) {
        #[cfg(unix)]
        unsafe {
            use std::os::fd::AsRawFd;
            libc::flock(self.file.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

pub(super) fn unique_progress_sibling(path: &Path, kind: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    path.with_extension(format!("{kind}.{}.{nanos}.json", std::process::id()))
}

/// Whether `value` serializes to exactly `bytes` (compact JSON). Streams into
/// the comparison and stops at the first differing byte; nothing is buffered.
#[cfg(test)]
pub(super) fn serializes_to(value: &impl Serialize, bytes: &[u8]) -> bool {
    struct Same<'a>(&'a [u8]);
    impl Write for Same<'_> {
        fn write(&mut self, chunk: &[u8]) -> std::io::Result<usize> {
            self.0 = self.0.strip_prefix(chunk).ok_or(ErrorKind::InvalidData)?;
            Ok(chunk.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut same = Same(bytes);
    serde_json::to_writer(&mut same, value).is_ok() && same.0.is_empty()
}

pub(super) fn sync_progress_parent(path: &Path) -> Result<()> {
    let Some(parent) = path.parent() else {
        return Ok(());
    };
    std::fs::File::open(parent)
        .and_then(|directory| directory.sync_all())
        .context("sync snapshot upload progress directory")
}

#[cfg(test)]
pub(super) fn quarantine_invalid_progress(path: &Path) -> Result<()> {
    let quarantine_path = unique_progress_sibling(path, "corrupt");
    std::fs::rename(path, quarantine_path)
        .context("quarantine invalid local snapshot upload progress")?;
    sync_progress_parent(path)
}

crate::heap_layout_bound::fields!(SnapshotUploadProgress; telemetry_only, schema_version, rows, generation, destination_namespace_hash, historical_replay_generation, accepted_fingerprints, accepted_body_witnesses, accepted_body_contexts, context_resend, ack_capacity, retained_stale_ack_count, accepted_cache_states, accepted_identity_buckets, accepted_identity_scope, accepted_cache_heads, pending_cache_heads, head_conflict_challenges, quarantined_fingerprints, permanent_rejections, active_quarantine_witness, active_quarantine_retries, active_reason_reoffers, attempted_reason_reoffers, reason_reoffer_counts, terminal_contract_retry_pending_save, fresh_context_body_acks, context_receipt_candidates, identity_503_pending, identity_503_pass, request_contributions);

crate::heap_layout_bound::fields!(PendingCacheHeadFile; source_file_fingerprint, group_fingerprint, entities, reselected_heads, settled_entities);

crate::heap_layout_bound::fields!(PermanentSnapshotRejection; body_witness, reason, reoffer, exposure, revisions);

crate::heap_layout_bound::fields!(HeadConflictChallenge; challenge, stale_revision_v2_hash, answer_attempts, last_answer_unix);
