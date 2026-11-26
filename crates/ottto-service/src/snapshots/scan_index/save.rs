//! Saving a `ScanIndex`: the compare-and-swap save paths, the snapshot
//! source manifest, upload-progress ACK incidence and the current
//! snapshot fingerprints.

use crate::snapshots::*;

impl ScanIndex {
    pub fn save(&mut self, path: &Path) -> Result<()> {
        self.save_internal(path, false)
    }
    /// A save while the caller holds the source's progress owner, which a
    /// routed save never takes itself: owner, then CheckpointLock.
    pub(crate) fn save_with_progress_owner(
        &mut self,
        path: &Path,
        _owner: &crate::snapshot_sync::SnapshotProgressLock,
    ) -> Result<()> {
        self.save(path)
    }
    /// Test-only since growth claims commit their rows directly.
    #[cfg(test)]
    pub(in crate::snapshots) fn save_growth_claim(&mut self, path: &Path) -> Result<()> {
        self.save_internal(path, true)
    }
    fn save_internal(&mut self, path: &Path, claim_only: bool) -> Result<()> {
        let _save_window = state_v2::state_v2_growth_retention_active(self)
            .then(|| state_v2::telemetry::Window::begin("save"))
            .flatten();
        self.require_persistence_available()?;
        lenient_decode::retain_persistence_claims(self);
        if !claim_only {
            self.prune_claude_money_births(sampled_scan::now_seconds());
        }
        lenient_decode::controls(self, scan_index_source_label(None))?;
        if !claim_only {
            self.drop_unbound_claude_authority_records("save");
            let drops = self.drop_invalid_index_records();
            note_scan_index_record_drops("save", scan_index_source_label(None), drops);
        }
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("create scan index directory {}", parent.display()))?;
        }
        let _lock = CheckpointLock::acquire(path)?;
        #[cfg(test)]
        pause_scan_index_cas_if_requested_for_test();
        state_v2::save_locked(path, self, claim_only)
    }

    /// The scan-index manifest for `source`: how many entities this machine
    /// believes the server holds, and one hash that summarises which.
    ///
    /// This is the only independent witness the server has that its own entity
    /// set matches the machine's before the multiplexed sync cycle exists: it
    /// can recompute the same fold over the fingerprints it stored for this
    /// (user, machine, source) and compare. It is also the denominator a
    /// backfill-progress reading needs, because "how many entities exist
    /// locally" is not derivable from anything the server already receives.
    ///
    /// Grain, stated precisely because a consumer cannot infer it: one entity
    /// per final snapshot fingerprint, including every entity when one indexed
    /// transcript produces several snapshots, plus each Codex state-only
    /// entity. The separate per-file group fingerprint is only an incremental
    /// no-op witness and never substitutes for this exact entity set.
    ///
    /// Scope is the exact half-open semantic activity window `[start, end)`.
    /// Membership uses the same producer-side activity clock as accepted-log
    /// `occurred_at`, never local path or file mtime.
    ///
    /// No local path, session id, title, or byte offset participates: the fold
    /// is over semantic fingerprints only, which are already on the wire.
    #[cfg(test)]
    pub fn manifest(&self, source: SnapshotSource, _window_days: u64) -> SnapshotSourceManifest {
        let mut index = self.clone();
        let fingerprints = index
            .file_snapshot_fingerprints
            .values()
            .flat_map(BTreeSet::iter)
            .chain(
                index
                    .files
                    .values()
                    .filter_map(|entry| entry.last_snapshot_fingerprint.as_ref()),
            )
            .cloned()
            .collect::<BTreeSet<_>>();
        for fingerprint in fingerprints {
            index
                .snapshot_activity_at
                .insert_if_absent(fingerprint, || Some("2050-01-01T00:00:00Z".to_string()));
        }
        index
            .manifest_for_window(source, "2000-01-01T00:00:00Z", "2100-01-01T00:00:00Z")
            .expect("static test manifest window is valid")
    }

    pub fn manifest_for_window(
        &self,
        source: SnapshotSource,
        window_start: &str,
        window_end: &str,
    ) -> Result<SnapshotSourceManifest> {
        if !self.persistence_available() {
            crate::local_resource_diagnostics::scan_index_manifest_refused(source.api_slug());
            return Err(anyhow::anyhow!("scan_index_map_unavailable"));
        }
        let window_start_at = OffsetDateTime::parse(window_start, &Rfc3339)
            .context("parse snapshot manifest window start")?;
        let window_end_at = OffsetDateTime::parse(window_end, &Rfc3339)
            .context("parse snapshot manifest window end")?;
        if window_start_at >= window_end_at {
            return Err(anyhow::anyhow!(
                "snapshot manifest window must be non-empty and increasing"
            ));
        }
        let all_fingerprints = self
            .eligible_snapshot_fingerprint_refs()
            .map(str::to_owned)
            .collect::<BTreeSet<_>>();
        let fingerprints = all_fingerprints
            .iter()
            .map(String::as_str)
            .filter(|fingerprint| {
                !self.decode_holds_entity(fingerprint)
                    && !self
                        .quarantined_snapshot_fingerprints
                        .contains_key(*fingerprint)
            })
            .filter(|fingerprint| {
                self.snapshot_activity_at
                    .get(*fingerprint)
                    .and_then(|activity| activity.as_deref())
                    .and_then(|activity| OffsetDateTime::parse(activity, &Rfc3339).ok())
                    .is_some_and(|activity| window_start_at <= activity && activity < window_end_at)
            })
            .collect::<BTreeSet<_>>();
        let mut digest = Sha256::new();
        update_length_prefixed(&mut digest, SNAPSHOT_MANIFEST_CONTRACT_VERSION.as_bytes());
        update_length_prefixed(&mut digest, SNAPSHOT_MANIFEST_SCOPE.as_bytes());
        update_length_prefixed(&mut digest, source.api_slug().as_bytes());
        for fingerprint in &fingerprints {
            update_length_prefixed(&mut digest, fingerprint.as_bytes());
        }
        if !all_fingerprints
            .iter()
            .filter(|fingerprint| {
                !self.decode_holds_entity(fingerprint)
                    && !self
                        .quarantined_snapshot_fingerprints
                        .contains_key(*fingerprint)
            })
            .all(|fingerprint| {
                self.snapshot_activity_at
                    .get(fingerprint)
                    .is_some_and(valid_snapshot_activity)
            })
        {
            return Err(anyhow::anyhow!(
                "snapshot manifest semantic activity witness is incomplete"
            ));
        }
        Ok(SnapshotSourceManifest {
            contract_version: SNAPSHOT_MANIFEST_CONTRACT_VERSION.to_string(),
            scope: SNAPSHOT_MANIFEST_SCOPE.to_string(),
            source: source.api_slug().to_string(),
            window_start: window_start.to_string(),
            window_end: window_end.to_string(),
            entity_count: fingerprints.len() as u64,
            rolling_hash: format!("{:x}", digest.finalize()),
        })
    }

    /// Upload-progress retention uses committed and carried incidence, never
    /// the subset emitted by a scan. This borrowed view allocates no census.
    pub(crate) fn upload_progress_ack_incidence(&self) -> impl Iterator<Item = &str> {
        self.current_snapshot_fingerprint_refs().chain(
            self.accepted_rebuild_incidence
                .values()
                .flat_map(|members| members.iter().map(String::as_str)),
        )
    }

    /// Transfer an exact progress ACK only when a saved file body-set witness
    /// adopts it. Semantic acceptance alone may still describe an older curve
    /// under the same fingerprint. Incomplete/legacy groups remain resume debt.
    pub(crate) fn adopted_upload_progress_acks(
        &self,
        bodies: &BTreeMap<String, String>,
    ) -> BTreeSet<String> {
        let mut adopted = BTreeSet::new();
        for (key, members) in &self.file_snapshot_fingerprints {
            if members.is_empty() || self.decode_holds_file(key) {
                continue;
            }
            let Some(expected) = self
                .files
                .get(key)
                .and_then(|entry| entry.last_upload_body_witness.as_deref())
            else {
                continue;
            };
            if !members.iter().all(|fp| {
                bodies.contains_key(fp) && self.accepted_snapshot_fingerprint_recorded(fp)
            }) {
                continue;
            }
            // All members are in the admitted progress map. Price scratch at
            // one borrowed string slice (two words) per member; no body clone.
            let mut witnesses = Vec::with_capacity(members.len());
            witnesses.extend(members.iter().map(|fp| bodies[fp].as_str()));
            witnesses.sort_unstable();
            witnesses.dedup();
            // Only the exact lowercase 64-hex rendering decodes, so this
            // matches the recorded String without formatting one.
            if codex_digest_from_hex(expected)
                == Some(snapshot_file_upload_body_set_digest(witnesses))
            {
                adopted.extend(members.iter().cloned());
            }
        }
        adopted
    }

    pub(crate) fn upload_progress_ack_incidence_unknown(&self) -> bool {
        self.decode_has_opaque_file_incidence()
    }

    pub(crate) fn current_snapshot_fingerprints(&self) -> BTreeSet<String> {
        self.current_snapshot_fingerprint_refs()
            .map(str::to_owned)
            .collect()
    }

    /// Exact per-file sets (including empty) override legacy last fingerprints.
    /// Selected rollback visits this canonical universe once and removes live
    /// references from its small affected set, instead of cloning every body
    /// fingerprint or scanning the full index once per affected body.
    pub(crate) fn current_snapshot_fingerprint_refs(&self) -> impl Iterator<Item = &str> {
        let exact = self
            .file_snapshot_fingerprints
            .values()
            .flat_map(|values| values.iter().map(String::as_str));
        let legacy = self
            .files
            .iter()
            .filter(|(key, _)| !self.file_snapshot_fingerprints.contains_key(*key))
            .filter_map(|(_, entry)| entry.last_snapshot_fingerprint.as_deref());
        exact.chain(legacy)
    }
}

#[cfg(test)]
type ScanIndexCasPauseForTest = (std::sync::mpsc::Sender<()>, std::sync::mpsc::Receiver<()>);
#[cfg(test)]
thread_local! {
    static SCAN_INDEX_CAS_PAUSE: std::cell::RefCell<Option<ScanIndexCasPauseForTest>> = const { std::cell::RefCell::new(None) };
}
#[cfg(test)]
pub(crate) fn pause_next_scan_index_cas_for_test(
    entered: std::sync::mpsc::Sender<()>,
    resume: std::sync::mpsc::Receiver<()>,
) {
    SCAN_INDEX_CAS_PAUSE.with(|pause| *pause.borrow_mut() = Some((entered, resume)));
}
#[cfg(test)]
fn pause_scan_index_cas_if_requested_for_test() {
    if let Some((entered, resume)) = SCAN_INDEX_CAS_PAUSE.with(|pause| pause.borrow_mut().take()) {
        entered.send(()).expect("CAS observer");
        resume.recv().expect("CAS release");
    }
}

impl ScanIndex {
    pub(crate) fn retain_persistence_baseline_from(&mut self, committed: &Self) {
        if let Some(state) = &committed.v2 {
            let own = self.v2_mut();
            own.persistence_v2 = state.persistence_v2.clone();
            own.growth_claim_context = state.growth_claim_context.clone();
        } else {
            self.v2 = None;
        }
        self.persistence_root = committed.persistence_root.clone();
        self.persistence_controls = committed.persistence_controls.clone();
        self.persistence_unavailable = std::array::from_fn(|i| {
            self.persistence_unavailable[i].or(committed.persistence_unavailable[i])
        });
        if !self.persistence_available() {
            if let Some((_, root)) = &mut self.persistence_root {
                *root = root.unavailable();
            }
        }
    }
}
