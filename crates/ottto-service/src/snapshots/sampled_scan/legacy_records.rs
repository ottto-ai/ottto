//! Existing record cleanup and pass lifecycle; unlink barriers own erasure counts.
use super::*;

impl SharedCache {
    /// Allocate the existing store owner only inside an approved OFF action.
    /// Registration never probes disk. Missing directories need no owner.
    pub(super) fn off_exception(&self, source: SnapshotSource) -> Result<bool, ()> {
        if restart_restore::enabled() {
            return Ok(true);
        }
        let Some(ds) = durable_source(source) else {
            return Ok(false);
        };
        let mut root = self.durable.lock().map_err(|_| ())?;
        let Some(pass) = root.passes[ds.slot()].clone() else {
            return Ok(false);
        };
        let dir = store::store_dir_for_index(&pass.index_path);
        if let Some(state) = root.state.as_mut() {
            if let Some(old) = state.slot(ds).as_mut().filter(|slot| slot.dir != dir) {
                // Keep the old owner and its age evidence until its own unlink
                // is durable. This never holds native OFF publication.
                let writer = crate::locked_state_dir::held_for(&old.dir)
                    .map(|writer| writer as &dyn SingleWriter);
                old.store.retry_off_v1_unlink(writer).map_err(|_| ())?;
            }
        }
        if matches!(std::fs::symlink_metadata(&dir), Err(e) if e.kind() == std::io::ErrorKind::NotFound)
        {
            return Ok(false);
        }
        let state = root.state.get_or_insert_with(Default::default);
        let slot = state.slot(ds);
        if slot.as_ref().map_or(true, |slot| slot.dir != dir) {
            let mut replacement =
                Slot::new(ds, pass.index_path, pass.namespace, pass.identity_capture);
            if let Some(previous) = slot.as_ref() {
                replacement.store.inherit_off_v1_counts(&previous.store);
            }
            *slot = Some(replacement);
            for debt in state.key_debt.values_mut() {
                if debt
                    .off_v1_failed_since
                    .is_some_and(|(source, _)| source == ds)
                {
                    debt.off_v1_failed_since = None;
                }
            }
            state.key_debt.retain(|_, debt| !debt.is_empty());
        }
        state
            .slot(ds)
            .as_mut()
            .expect("exception slot")
            .skill_labels_enabled = pass.skill_labels_enabled;
        self.durable_bytes.store(
            size_of::<Stores>() + std::mem::align_of::<Stores>(),
            Ordering::Relaxed,
        );
        Ok(true)
    }
    /// Selects `source`'s store for this pass, the sibling of `index_path`,
    /// under the pass's sampled scope (`namespace`) and identity-capture
    /// mode. An index at another path (a destination or account switch) gets
    /// a fresh store; the old directory is left to its own index's GC.
    pub(in crate::snapshots) fn durable_skill_label_permission(
        &self,
        source: SnapshotSource,
        enabled: bool,
    ) {
        if !restart_restore::enabled() {
            if let (Some(ds), Ok(mut root)) = (durable_source(source), self.durable.lock()) {
                if let Some(pass) = root.passes[ds.slot()].as_mut() {
                    pass.skill_labels_enabled = enabled;
                }
            }
            return;
        }
        if let (Some(ds), Some(mut stores)) = (durable_source(source), self.durable()) {
            if let Some(slot) = stores.slot(ds).as_mut() {
                slot.skill_labels_enabled = enabled;
                if enabled {
                    slot.skill_label_purge_complete = false;
                }
            }
        }
    }
    pub(crate) fn durable_begin_pass(
        &self,
        source: SnapshotSource,
        index_path: &Path,
        namespace: &Scope,
        identity_capture: bool,
    ) {
        if !restart_restore::enabled() {
            let Some(ds) = durable_source(source) else {
                return;
            };
            if let Ok(mut root) = self.durable.lock() {
                if root.passes[ds.slot()].as_ref().is_some_and(|pass| {
                    pass.index_path != index_path
                        || pass.namespace != *namespace
                        || pass.identity_capture != identity_capture
                }) {
                    for pending in &mut root.retiring {
                        if pending.is_some_and(|p| p.source == source) {
                            *pending = None;
                        }
                    }
                }
                root.passes[ds.slot()] = Some(OffPass {
                    index_path: index_path.to_owned(),
                    namespace: namespace.clone(),
                    identity_capture,
                    skill_labels_enabled: false,
                });
            }
            return;
        }
        let (Some(source), Some(mut stores)) = (durable_source(source), self.durable()) else {
            return;
        };
        let dir = store::store_dir_for_index(index_path);
        if restart_restore::enabled() {
            // P2 head budget is per pass; authorityless custody nodes are freed.
            stores.rederive_spent[source.slot()] = 0;
            // A native error may discard staging without a publication. Its empty
            // reservation carries no authority and cannot pin next-pass capacity.
            stores.key_debt.retain(|_, debt| !debt.is_empty());
            stores
                .retail_spent
                .retain(|_, custody| custody.has_authority());
        }
        let changed = stores.slot(source).as_ref().map_or(true, |slot| {
            slot.dir != dir
                || slot.namespace != *namespace
                || slot.identity_capture != identity_capture
        });
        if changed {
            for pending in &mut stores.retiring {
                if pending.is_some_and(|pending| durable_source(pending.source) == Some(source)) {
                    *pending = None;
                }
            }
        }
        if stores
            .slot(source)
            .as_ref()
            .is_some_and(|slot| slot.dir != dir)
        {
            for debt in stores.key_debt.values_mut() {
                if debt.off_v1_failed_since.is_some_and(|(s, _)| s == source) {
                    debt.off_v1_failed_since = None;
                }
            }
            stores.key_debt.retain(|_, debt| !debt.is_empty());
        }
        let slot = stores.slot(source);
        if let Some(current) = slot.as_mut().filter(|current| current.dir == dir) {
            current.decided.clear();
            current.index_path = index_path.to_owned();
            current.namespace = namespace.clone();
            current.identity_capture = identity_capture;
            current.skill_labels_enabled = false;
        } else {
            if let Some(old) = slot
                .as_mut()
                .filter(|s| restart_restore::enabled() && s.store.has_pending())
            {
                old.store.disable("namespace_pending");
                return;
            }
            *slot = Some(Slot::new(
                source,
                index_path.to_owned(),
                namespace.clone(),
                identity_capture,
            ));
        }
        if let Some(slot) = slot.as_mut() {
            if restart_restore::enabled() {
                slot.store.begin_pass();
            }
            // At most one resource probe per pass; the store owns its back-off.
            // Held keys retry through their own next native write.
            if restart_restore::enabled() && slot.store.resource_paused() {
                if let Some(writer) = crate::locked_state_dir::held_for(&slot.dir) {
                    let index_len = std::fs::metadata(index_path).map_or(0, |m| m.len());
                    // This pass-start probe only refreshes an existing pause.
                    // An I/O error keeps it held; the write path reports errors.
                    let _ = slot.store.check_resources(writer, index_len);
                }
            }
        }
    }
    /// The sole OFF publication exception: discard this key's outgrown v1
    /// restart record. No inventory, body read, new store or publication hold.
    pub(crate) fn durable_off_published(
        &self,
        source: SnapshotSource,
        key: &str,
        published_end: u64,
    ) {
        if restart_restore::enabled() {
            return;
        }
        if self.off_exception(source) != Ok(true) {
            return;
        }
        let (Some(source), Some(mut stores)) = (durable_source(source), self.durable()) else {
            return;
        };
        let digest = store::key_digest(source, key);
        let Some(slot) = stores.slot(source).as_mut() else {
            return;
        };
        let outcome = if let Some(writer) = crate::locked_state_dir::held_for(&slot.dir) {
            slot.store
                .invalidate_outgrown_v1(writer, &digest, published_end)
        } else if !slot.dir.try_exists().unwrap_or(true) && slot.store.record_missing(&digest) {
            Ok(true) // No record or outstanding unlink barrier remains.
        } else {
            return;
        };
        match outcome {
            Err(_) => {
                // The diagnostic shares the prepaid, bounded key owner; it
                // never grants discovery/receipt custody or blocks a publish.
                if let Some(debt) = stores.fund_debt(digest) {
                    debt.off_v1_failed_since
                        .get_or_insert((source, std::time::Instant::now()));
                } else if let Some(slot) = stores.slot(source).as_mut() {
                    slot.off_v1_failed_age_untracked = true;
                }
            }
            Ok(true) => {
                if let Some(debt) = stores.key_debt.get_mut(&digest) {
                    debt.off_v1_failed_since = None;
                }
                stores.release_idle_debt(&digest);
            }
            Ok(false) => {} // Inconclusive or unchanged: keep the first failure.
        }
    }
    pub(super) fn erase_private_labels<W: SingleWriter>(
        &self,
        writer: &W,
        snapshot_source: SnapshotSource,
        reason: store::PrivateLabelEraseReason,
        keep: std::io::Result<Option<&BTreeSet<store::Digest32>>>,
    ) {
        let (keep, candidate_error) = match keep {
            Ok(keep) => (keep, None),
            Err(error) => (None, Some(error)),
        };
        let owner = self.off_exception(snapshot_source);
        if owner == Ok(false) {
            return;
        }
        let owner_blocked = owner.is_err();
        let Some(source) = durable_source(snapshot_source) else {
            return;
        };
        let needed = owner_blocked
            || candidate_error.is_some()
            || self.durable().is_some_and(|mut stores| {
                stores.slot(source).as_ref().is_some_and(|slot| {
                    (keep.is_some()
                        || (!slot.skill_labels_enabled && !slot.skill_label_purge_complete))
                        && slot.store.private_label_purge_needed(keep)
                })
            });
        if !needed {
            return;
        }
        let store::LeaseWait::Granted(lease) =
            self.acquire_active(snapshot_source, store::RESTORE_INPUT_BYTES)
        else {
            return;
        };
        if let Some(mut stores) = self.durable() {
            if let Some(slot) = stores.slot(source).as_mut() {
                let result = if let Some(error) = candidate_error {
                    Err(error)
                } else if owner_blocked {
                    Err(std::io::Error::other("prior OFF unlink barrier"))
                } else {
                    match keep {
                        Some(keep) => {
                            slot.store
                                .purge_private_labels_kept(writer, keep, reason, |body| {
                                    codec::body_has_skill_labels(snapshot_source, body)
                                        .unwrap_or(true)
                                })
                        }
                        None => slot.store.purge_private_labels(writer, |body| {
                            codec::body_has_skill_labels(snapshot_source, body).unwrap_or(true)
                        }),
                    }
                };
                let (visited, scanned, verified, erased, failed) = result
                    .map_or((0, 0, 0, 0, 1), |r| {
                        (r.visited, r.scanned, r.verified, r.erased, r.refused)
                    });
                slot.skill_label_purge_complete =
                    failed == 0 && !slot.store.private_label_purge_needed(None);
                slot.skill_label_purge_failures = if failed > 0 {
                    slot.skill_label_purge_failures.saturating_add(1)
                } else if slot.skill_label_purge_complete {
                    0
                } else {
                    // A bounded partial page is progress, not a verified
                    // successful traversal that can clear earlier failures.
                    slot.skill_label_purge_failures
                };
                let alarm = slot.skill_label_purge_failures > 3;
                for (class, count) in [
                    ("skill_label_entries_visited", visited),
                    ("skill_label_scanned", scanned),
                    ("skill_label_verified", verified),
                    ("skill_label_purged", erased),
                    ("skill_label_purge_failed", failed),
                ] {
                    *stores.counters.not_persisted.entry(class).or_default() += count;
                }
                if visited + scanned + erased + failed > 0 {
                    crate::local_resource_diagnostics::durable_tail_alarm(
                        snapshot_source.api_slug(),
                        &serde_json::json!({"skill_label_entries_visited":visited,
                            "skill_label_scanned":scanned, "skill_label_verified":verified,
                            "skill_label_purged":erased, "skill_label_purge_failed":failed}),
                    );
                }
                if alarm {
                    crate::local_resource_diagnostics::durable_tail_alarm(
                        snapshot_source.api_slug(),
                        &serde_json::json!({"skill_label_purge_failed_consecutive":4}),
                    );
                }
            }
        }
        lease.release();
    }
    /// Collects records the committed `index` no longer keeps, from another
    /// context, scope or allowlist, and torn temps. Runs after a save.
    pub(crate) fn durable_gc<W: SingleWriter>(
        &self,
        writer: &W,
        snapshot_source: SnapshotSource,
        index: &ScanIndex,
    ) -> std::io::Result<()> {
        match self.off_exception(snapshot_source) {
            Ok(true) => {}
            Ok(false) => return Ok(()),
            Err(()) => {
                // Count refusal without touching the old slot under new context.
                self.erase_private_labels(
                    writer,
                    snapshot_source,
                    store::PrivateLabelEraseReason::ConsentOrSource,
                    Ok(None),
                );
                return Ok(());
            }
        }
        if let Some(ds) = durable_source(snapshot_source) {
            let possible = self.durable().and_then(|mut stores| {
                let slot = stores.slot(ds).as_mut()?;
                if !slot.store.private_label_purge_needed(None) {
                    return None;
                }
                Some(slot.store.private_label_candidates())
            });
            match possible {
                Some(Ok(possible)) => {
                    // Retention intersects a bounded marker/inventory, never a
                    // second unbounded copy of the committed index.
                    let keep = index
                        .files
                        .keys()
                        .map(|key| store::key_digest(ds, key))
                        .filter(|key| possible.contains(key))
                        .collect();
                    self.erase_private_labels(
                        writer,
                        snapshot_source,
                        store::PrivateLabelEraseReason::CommittedKeyAbsent,
                        Ok(Some(&keep)),
                    );
                }
                Some(Err(error)) => {
                    self.erase_private_labels(
                        writer,
                        snapshot_source,
                        store::PrivateLabelEraseReason::CommittedKeyAbsent,
                        Err(error),
                    );
                }
                None => {}
            }
        }
        if !restart_restore::enabled() {
            return Ok(());
        }
        let Some(source) = durable_source(snapshot_source) else {
            return Ok(());
        };
        let Some(mut stores) = self.durable() else {
            return Ok(());
        };
        stores.note_indexed(source, index);
        let Some(slot) = stores.slot(source).as_mut() else {
            return Ok(());
        };
        let (namespace, identity_capture) = (&slot.namespace, slot.identity_capture);
        let context = store::context_digest(
            &namespace.0,
            index.active_upload_context_fingerprint.as_deref(),
        );
        // Only keys with a record on disk (at most `INVENTORY_BOUND`) are
        // looked up; the index is streamed, never copied.
        let inventory = slot.store.inventory()?;
        if source == DurableSource::ClaudeCode {
            slot.store.revoke_all();
        }
        let mut keep = BTreeMap::new();
        let mut mapping_holds = BTreeMap::new();
        if !inventory.is_empty() {
            for key in index.files.keys() {
                let digest = store::key_digest(source, key);
                if !inventory.contains(&digest) {
                    continue;
                }
                if let Some(ScopeDecision::LayoutUnavailable { settled, verified }) =
                    slot.decided.get(key)
                {
                    keep.insert(
                        digest,
                        if *settled {
                            store::GcKeep::LayoutUnavailable {
                                audit_debt: index.files[key].unverified_deadline(),
                                verified: *verified,
                            }
                        } else {
                            store::GcKeep::Unknown
                        },
                    );
                    continue;
                }
                if matches!(slot.decided.get(key), Some(ScopeDecision::Excluded))
                    || source == DurableSource::Codex
                        && index.files[key].codex_history_is_protected()
                {
                    keep.insert(
                        digest,
                        store::GcKeep::Excluded {
                            audit_debt: index.files[key].unverified_deadline(),
                        },
                    );
                    continue;
                }
                let scope = slot
                    .decided
                    .get(key)
                    .and_then(ScopeDecision::scope)
                    .and_then(|scope| {
                        if index.files[key].has_unverified_source() {
                            return None; // Keep the predecessor until a verified Full replaces it.
                        }
                        let interpretation = Interpretation::of(
                            snapshot_source,
                            key,
                            index,
                            identity_capture,
                            namespace,
                        );
                        if source == DurableSource::ClaudeCode {
                            let ReadOutcome::Found(record) = slot.store.read(&digest) else {
                                return None;
                            };
                            let (original, _) = match claude_expected(
                                key,
                                scope,
                                index,
                                &interpretation,
                                &record,
                            ) {
                                Ok(proof) => proof,
                                Err(reason) => {
                                    Counters::bump(&mut mapping_holds, reason);
                                    slot.held += 1;
                                    return None;
                                }
                            };
                            slot.store.authorize(&record, &original);
                            return Some(original.binding.scope);
                        }
                        None
                    });
                keep.insert(
                    digest,
                    scope.map_or(store::GcKeep::Unknown, store::GcKeep::Scope),
                );
            }
        }
        for (reason, n) in mapping_holds {
            *stores.counters.ineligible.entry(reason).or_default() += n;
        }
        stores.counters.gc_keep_peak = stores.counters.gc_keep_peak.max(keep.len() as u64);
        let Some(slot) = stores.slot(source).as_mut() else {
            return Ok(());
        };
        slot.store.gc_classified(writer, &context, &keep)
    }
    /// Fresh-index cleanup uses the same verified, bounded GC; U/T14 survive.
    pub(crate) fn durable_remove<W: SingleWriter>(
        &self,
        writer: &W,
        snapshot_source: SnapshotSource,
    ) -> std::io::Result<()> {
        self.erase_private_labels(
            writer,
            snapshot_source,
            store::PrivateLabelEraseReason::ConsentOrSource,
            Ok(Some(&BTreeSet::new())),
        );
        // OFF fresh-index cleanup only erases private labels. It cannot
        // settle v1 failures, especially when an old unlink barrier deferred
        // that erasure; only verified absence/invalidation clears those ages.
        if !restart_restore::enabled() {
            return Ok(());
        }
        if let (Some(source), Some(mut stores)) = (durable_source(snapshot_source), self.durable())
        {
            for debt in stores.key_debt.values_mut() {
                if debt.off_v1_failed_since.is_some_and(|(s, _)| s == source) {
                    debt.off_v1_failed_since = None;
                }
            }
            stores.key_debt.retain(|_, debt| !debt.is_empty());
            if let Some(slot) = stores.slot(source).as_mut() {
                slot.off_v1_failed_age_untracked = false;
            }
        }
        let Some(source) = durable_source(snapshot_source) else {
            return Ok(());
        };
        let Some(mut stores) = self.durable() else {
            return Ok(());
        };
        for pending in &mut stores.retiring {
            if pending.is_some_and(|pending| pending.source == snapshot_source) {
                *pending = None;
            }
        }
        match stores.slot(source).as_mut() {
            Some(slot) => {
                if source == DurableSource::ClaudeCode {
                    slot.store.revoke_all();
                }
                slot.store.gc(writer, &[0; 32], &BTreeMap::new())
            }
            None => Ok(()),
        }
    }
    /// After a source's local copy is erased. With restart restore on, the next
    /// `durable_begin_pass` sees no slot and drops this source's retirements. Key
    /// custody and pacing stay: they are source+key state, never cleared here.
    pub(crate) fn durable_forget_source(&self, source: SnapshotSource) {
        if let (Some(source), Some(mut stores)) = (durable_source(source), self.durable()) {
            *stores.slot(source) = None;
        }
    }
    /// A post-save pass in a process that does not hold the state-directory
    /// lock: nothing is written or collected, and the admitted keys are
    /// dropped (they would never be written).
    pub(crate) fn durable_note_unlocked(&self, snapshot_source: SnapshotSource) {
        if durable_source(snapshot_source).is_none() {
            return;
        }
        if let Some(mut stores) = self.durable() {
            stores.touched.clear();
            stores.selected.clear();
            stores.retiring.fill(None);
            stores.counters.write_unlocked += 1;
        }
    }
    pub(super) fn legacy_alarm_at(&self, snapshot_source: SnapshotSource, at: std::time::Instant) {
        let Some(source) = durable_source(snapshot_source) else {
            return;
        };
        let Some(mut stores) = self.durable() else {
            return;
        };
        let (keys, age, untracked) = stores.off_v1_failure_age(source, at);
        let Some(slot) = stores.slot(source).as_ref() else {
            return;
        };
        let counts = slot.store.counters();
        if counts.off_v1_invalidated > 0 || counts.off_v1_invalidate_failed > 0 {
            crate::local_resource_diagnostics::durable_tail_alarm(
                snapshot_source.api_slug(),
                &serde_json::json!({
                    "off_v1_invalidated": counts.off_v1_invalidated,
                    "off_v1_invalidate_failed": counts.off_v1_invalidate_failed,
                    "off_v1_invalidate_failed_age": {"keys": keys, "oldest_age": age.as_secs()},
                    "off_v1_invalidate_failed_alarm": age > RESTART_FULL_ALARM_WINDOW || untracked,
                    "off_v1_failed_age_untracked": untracked,
                }),
            );
        }
    }
}
