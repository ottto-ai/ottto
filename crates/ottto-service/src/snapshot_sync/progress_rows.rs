//! Upload progress of a routed source as keyed rows of its custody store: the
//! two keyed cache maps and one ledger row (every other durable field). A
//! route's first load moves its JSON ledger in once under the import marker;
//! from then on the rows are the only progress the source reads or writes.
//!
//! A page COMMIT is the receipt: a crash before it re-offers the exact body,
//! and once it is durable the graph may settle against it.
use super::*;
use crate::snapshots::{ProgressMarker, ProgressPage, ProgressRead};

/// Fields the ledger row never holds: the keyed maps and the generation.
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

    /// The ledger row of this progress.
    pub(super) fn ledger_row(&mut self) -> Result<serde_json::Value> {
        let states = std::mem::take(&mut self.accepted_cache_states);
        let heads = std::mem::take(&mut self.accepted_cache_heads);
        let ledger = serde_json::to_value(&*self);
        self.accepted_cache_states = states;
        self.accepted_cache_heads = heads;
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
    /// import marker at P = 1. Unparseable or invalid input holds the source
    /// and stays on disk; a failed COMMIT holds this pass, and the next load
    /// imports again. Once the marker commits the legacy files are purged.
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
            progress.valid(namespace)
                && progress
                    .accepted_cache_states
                    .iter()
                    .all(|(key, state)| valid_cache_state(key, state))
                && progress
                    .accepted_cache_heads
                    .iter()
                    .all(|(key, head)| valid_cache_head(key, head)),
            "snapshot upload progress for import is invalid"
        );
        let ledger = progress.ledger_row()?;
        let page = (
            &progress.accepted_cache_states,
            &progress.accepted_cache_heads,
            &ledger,
        );
        let rows = crate::snapshots::import_progress_rows(index, index_path, owner, page, &marker)?;
        let progress = match rows {
            Some(rows) => {
                progress.generation = rows.generation();
                progress.rows = Some(Box::new(rows));
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
    pub(super) fn save_rows(&mut self, path: &Path) -> Result<()> {
        let owner = SnapshotProgressLock::acquire(path)?.for_v2(path);
        let ledger = self.ledger_row()?;
        let rows = self
            .rows
            .as_mut()
            .context("snapshot upload progress rows are not loaded")?;
        if rows.generation() != self.generation {
            return Err(anyhow!("snapshot upload progress changed concurrently"));
        }
        match rows.commit(
            &owner,
            &self.accepted_cache_states,
            &self.accepted_cache_heads,
            &ledger,
        )? {
            ProgressPage::Committed(generation) => self.generation = generation,
            ProgressPage::Unchanged => {}
            ProgressPage::NotPublished => {
                return Err(anyhow!("snapshot upload progress page was not published"))
            }
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
