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
    /// source is routed, else the JSON ledger.
    pub(super) fn load_for_index(
        index: &ScanIndex,
        index_path: &Path,
        path: &Path,
        namespace: &str,
        witness: SnapshotQuarantineWitness,
    ) -> Result<Self> {
        if !crate::snapshots::state_v2_growth_retention_active(index) {
            return Self::load(path, namespace, witness);
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
            progress
                .accepted_identity_buckets
                .count_retained_cleared_if_any();
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
            progress
                .accepted_identity_buckets
                .count_retained_cleared_if_any();
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
            let retained_reset = point.progress_generation < scope.retained_before;
            hints.admit(name, point.accepted, retained_reset);
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
        }
    }

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
        // Option (ii) proof is scoped to the namespace that ACKed it.
        if let Ok(progress) = &parsed {
            if progress.destination_namespace_hash != expected_destination_namespace_hash {
                progress
                    .accepted_identity_buckets
                    .count_retained_cleared_if_any();
            }
        }
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
        self.accepted_identity_buckets.clear_retained();
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
        self.save_with_read_limit(path, None)
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

    pub(super) fn save_with_read_limit(
        &mut self,
        path: &Path,
        read_limit: Option<usize>,
    ) -> Result<()> {
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
            let bytes = match read_limit {
                Some(cap) => crate::snapshot_retry::read_state(path, cap),
                None => std::fs::read(path),
            }
            .context("read current snapshot upload progress")?;
            let current: SnapshotUploadProgressCas = if read_limit.is_some() {
                crate::snapshot_retry::decode_state(&bytes)
            } else {
                serde_json::from_slice(&bytes).map_err(anyhow::Error::from)
            }
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

    pub(super) fn finish_cycle(&mut self, path: &Path) -> Result<()> {
        if self.rows.is_none()
            && self.accepted_fingerprints.is_empty()
            && self.permanent_rejections.is_empty()
            && self.accepted_cache_states.is_empty()
            && self.accepted_cache_heads.is_empty()
            && self.pending_cache_heads.is_empty()
            && self.head_conflict_challenges.is_empty()
            && self.accepted_identity_buckets.is_empty()
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
