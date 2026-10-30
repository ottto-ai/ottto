//! Lazy, exact retired-pin recovery. No new persisted ledger or source pin.
use super::*;

const FILES: u64 = 64;
const BYTES: u64 = 64 * 1024 * 1024;

#[derive(Clone, Copy, Default)]
pub(super) struct Pass {
    files: u64,
    bytes: u64,
    carried: u64,
    oldest: u64,
    pub(super) seen: bool,
}
#[derive(Clone, Copy)]
pub(super) struct State {
    source: DurableSource,
    started: bool,
    completed: bool,
    limit: u64,
    since: SystemTime,
}
impl State {
    pub(super) fn begin_pass(&mut self, source: DurableSource) {
        // A failed or unpersisted attempt may retry only through the shared
        // six-hour pace. Never hold a growing file without that retry exit.
        if self.source == source {
            self.started = false;
        }
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub(in crate::snapshots) enum RepinPlan {
    Ordinary,
    Quiet,
    Ready,
    Carry,
}

impl Stores {
    pub(super) fn repin_pending(&self, source: DurableSource, key: &str) -> bool {
        self.key_debt
            .get(&store::key_digest(source, key))
            .is_some_and(|d| d.repin.is_some())
    }
}
impl SharedCache {
    pub(in crate::snapshots) fn repin_growth(
        &self,
        source: SnapshotSource,
        key: &str,
        files: &BTreeMap<String, ScanIndexEntry>,
        length: u64,
    ) -> bool {
        if !files.get(key).is_some_and(|e| length > e.size_bytes) {
            return false;
        }
        let Some(ds) = durable_source(source) else {
            return false;
        };
        self.durable().is_some_and(|mut stores| {
            stores
                .slot(ds)
                .as_mut()
                .is_some_and(|slot| slot.store.has_retired_pin(&store::key_digest(ds, key)))
        })
    }
    #[cfg(test)]
    pub(super) fn repin_fill_pass_for_test(&self, source: SnapshotSource) {
        self.durable().unwrap().repin_pass[durable_source(source).unwrap().slot()].bytes = BYTES;
    }
    pub(in crate::snapshots) fn repin_started(&self, source: SnapshotSource, key: &str) -> bool {
        durable_source(source).is_some_and(|ds| {
            self.durable().is_some_and(|stores| {
                stores
                    .key_debt
                    .get(&store::key_digest(ds, key))
                    .and_then(|d| d.repin)
                    .is_some_and(|r| r.started)
            })
        })
    }
    pub(in crate::snapshots) fn repin_limit(
        &self,
        source: SnapshotSource,
        key: &str,
    ) -> Option<u64> {
        let ds = durable_source(source)?;
        self.durable()?
            .key_debt
            .get(&store::key_digest(ds, key))?
            .repin
            .filter(|r| r.started)
            .map(|r| r.limit)
    }

    /// The whole native group is the Full unit. Prepay replay, boot probes,
    /// and header rechecks conservatively before its first content read.
    pub(in crate::snapshots) fn repin_group_start(
        &self,
        source: SnapshotSource,
        members: &[CandidateFile],
    ) -> bool {
        if !members
            .iter()
            .any(|m| self.repin_pending(source, &local_index_key(&m.path)))
        {
            return true;
        }
        let store::LeaseWait::Granted(lease) =
            self.acquire_active(source, store::RESTORE_INPUT_BYTES)
        else {
            return false;
        };
        let result = self.repin_group_start_funded(source, members);
        lease.release();
        result
    }
    fn repin_group_start_funded(&self, source: SnapshotSource, members: &[CandidateFile]) -> bool {
        let old: Vec<_> = members
            .iter()
            .filter(|m| self.repin_pending(source, &local_index_key(&m.path)))
            .collect();
        if old.is_empty()
            || old
                .iter()
                .all(|m| self.repin_started(source, &local_index_key(&m.path)))
        {
            return true;
        }
        let Some(ds) = durable_source(source) else {
            return false;
        };
        let bytes = members.iter().try_fold(0u64, |n, m| {
            n.checked_add(std::fs::metadata(&m.path).ok()?.len().checked_mul(3)?)
        });
        let Some(bytes) = bytes else {
            return false;
        };
        let room = self.durable().is_some_and(|stores| {
            let pass = stores.repin_pass[ds.slot()];
            members.len() as u64 <= FILES.saturating_sub(pass.files)
                && bytes <= BYTES.saturating_sub(pass.bytes)
        });
        if !room
            || !old.iter().all(|m| {
                self.paced_admission(
                    source,
                    &local_index_key(&m.path),
                    SystemTime::now(),
                    false,
                    false,
                    false,
                )
            })
        {
            for m in old {
                if let Ok(file) = File::open(&m.path) {
                    self.repin_carry(source, &local_index_key(&m.path), &file);
                }
            }
            return false;
        }
        let before = self
            .durable()
            .map(|s| s.repin_pass[ds.slot()])
            .unwrap_or_default();
        for m in old {
            let Ok(file) = File::open(&m.path) else {
                return false;
            };
            if !self.repin_start_funded(source, &local_index_key(&m.path), &file) {
                return false;
            }
        }
        if let Some(mut stores) = self.durable() {
            stores.repin_pass[ds.slot()].files = before.files + members.len() as u64;
            stores.repin_pass[ds.slot()].bytes = before.bytes + bytes;
        }
        true
    }
    pub(super) fn repin_completed(&self, source: SnapshotSource, key: &str) -> bool {
        durable_source(source).is_some_and(|ds| {
            self.durable().is_some_and(|stores| {
                stores
                    .key_debt
                    .get(&store::key_digest(ds, key))
                    .and_then(|d| d.repin)
                    .is_some_and(|r| r.completed)
            })
        })
    }
    pub(super) fn repin_source_pending(&self, source: SnapshotSource) -> bool {
        durable_source(source).is_some_and(|ds| {
            self.durable().is_some_and(|stores| {
                stores
                    .key_debt
                    .values()
                    .any(|d| d.repin.is_some_and(|r| r.source == ds))
            })
        })
    }
    pub(in crate::snapshots) fn repin_report(&self, source: SnapshotSource) {
        let Some(ds) = durable_source(source) else {
            return;
        };
        let Some(stores) = self.durable() else {
            return;
        };
        let p = stores.repin_pass[ds.slot()];
        if !p.seen {
            return;
        }
        let pending = stores
            .key_debt
            .values()
            .filter(|d| d.repin.is_some_and(|r| r.source == ds))
            .count();
        drop(stores);
        crate::local_resource_diagnostics::durable_tail_alarm(
            source.api_slug(),
            &serde_json::json!({
            "repin_pending":pending,"repin_carried_files":p.carried,"repin_oldest_carried_age_seconds":p.oldest,
            "repin_carry_over_24h":u64::from(p.oldest > 86400)}),
        );
    }
    pub(in crate::snapshots) fn repin_pending(&self, source: SnapshotSource, key: &str) -> bool {
        durable_source(source).is_some_and(|ds| {
            self.durable()
                .is_some_and(|stores| stores.repin_pending(ds, key))
        })
    }

    /// Header classification is distinct from funded envelope verification.
    /// Quiet retired records return before any source sample or body input.
    pub(in crate::snapshots) fn repin_plan(
        &self,
        source: SnapshotSource,
        key: &str,
        file: &File,
        index: &ScanIndex,
    ) -> RepinPlan {
        let Some(ds) = durable_source(source) else {
            return RepinPlan::Ordinary;
        };
        let digest = store::key_digest(ds, key);
        let retired = self.durable().is_some_and(|mut stores| {
            stores
                .slot(ds)
                .as_mut()
                .is_some_and(|slot| slot.store.has_retired_pin(&digest))
        });
        if !retired {
            return RepinPlan::Ordinary;
        }
        if let Some(mut stores) = self.durable() {
            stores.repin_pass[ds.slot()].seen = true;
        }
        let Some(entry) = index.files.get(key) else {
            self.repin_carry(source, key, file);
            return RepinPlan::Carry;
        };
        let Ok(metadata) = file.metadata() else {
            self.repin_carry(source, key, file);
            return RepinPlan::Carry;
        };
        if metadata.len() <= entry.size_bytes {
            return RepinPlan::Quiet;
        }
        let store::LeaseWait::Granted(lease) =
            self.acquire_active(source, store::RESTORE_INPUT_BYTES)
        else {
            self.repin_carry(source, key, file);
            return RepinPlan::Carry;
        };
        let result = (|| {
            let mut stores = self.durable()?;
            let slot = stores.slot(ds).as_mut()?;
            let context = store::context_digest(
                &slot.namespace.0,
                index.active_upload_context_fingerprint.as_deref(),
            );
            let (proof, certificate) =
                slot.store
                    .repin_witness(&digest, &context, index.generation)?;
            if (metadata.dev(), metadata.ino()) != (certificate.device, certificate.inode)
                || (certificate.birth_nanos != 0
                    && birth_unix_nanos(&metadata) != certificate.birth_nanos)
                || metadata.len() <= certificate.length
            {
                return None;
            }
            if !stores.fund_key(digest) {
                return None;
            }
            if stores.fund_debt(digest).is_none() {
                stores.release_idle_custody(&digest);
                return None;
            }
            let debt = stores.key_debt.get_mut(&digest)?;
            debt.repin.get_or_insert(State {
                source: ds,
                started: false,
                completed: false,
                limit: 0,
                since: metadata.modified().unwrap_or_else(|_| SystemTime::now()),
            });
            let custody = stores.retail_spent.get_mut(&digest)?;
            if custody
                .original
                .as_ref()
                .is_some_and(|old| !old.same_predecessor(&proof))
            {
                return None;
            }
            custody.original = Some(proof);
            Some(())
        })();
        lease.release();
        if result.is_some() {
            RepinPlan::Ready
        } else {
            self.repin_carry(source, key, file);
            RepinPlan::Carry
        }
    }

    pub(in crate::snapshots) fn repin_carry(&self, source: SnapshotSource, key: &str, file: &File) {
        let now = SystemTime::now();
        let mut age = file
            .metadata()
            .ok()
            .and_then(|m| m.modified().ok())
            .and_then(|mtime| now.duration_since(mtime).ok())
            .map_or(0, |d| d.as_secs());
        if let Some(mut stores) = self.durable() {
            if let Some(ds) = durable_source(source) {
                if let Some(state) = stores
                    .key_debt
                    .get(&store::key_digest(ds, key))
                    .and_then(|d| d.repin)
                {
                    age = age.max(now.duration_since(state.since).map_or(0, |d| d.as_secs()));
                }
                let pass = &mut stores.repin_pass[ds.slot()];
                pass.carried += 1;
                pass.oldest = pass.oldest.max(age);
            }
        }
        crate::local_resource_diagnostics::durable_tail_alarm(
            source.api_slug(),
            &serde_json::json!({"repin_carried":1,"repin_oldest_carried_age_seconds":age,"repin_carry_over_24h":u64::from(age > 86400)}),
        );
    }

    /// Last pre-input boundary, after all ordinary preparation/holds. No first
    /// file escape. This also supplies Claude's aggregate Full-byte cap.
    pub(in crate::snapshots) fn repin_start(
        &self,
        source: SnapshotSource,
        key: &str,
        file: &File,
    ) -> bool {
        let store::LeaseWait::Granted(lease) =
            self.acquire_active(source, store::RESTORE_INPUT_BYTES)
        else {
            self.repin_carry(source, key, file);
            return false;
        };
        let result = self.repin_start_funded(source, key, file);
        lease.release();
        result
    }
    // The process-wide active owner serializes verification, the shared pace
    // spend and pass reservation together, without holding Stores across I/O.
    fn repin_start_funded(&self, source: SnapshotSource, key: &str, file: &File) -> bool {
        let Some(ds) = durable_source(source) else {
            return false;
        };
        let Ok(metadata) = file.metadata() else {
            return false;
        };
        let bytes = metadata.len();
        let digest = store::key_digest(ds, key);
        let reserved = self.durable().is_some_and(|stores| {
            let pass = &stores.repin_pass[ds.slot()];
            pass.files < FILES
                && bytes <= BYTES.saturating_sub(pass.bytes)
                && stores
                    .key_debt
                    .get(&digest)
                    .and_then(|d| d.repin)
                    .is_some_and(|r| !r.started)
        });
        if !reserved {
            self.repin_carry(source, key, file);
            return false;
        }
        let verified = self.durable().is_some_and(|mut guard| {
            let stores = &mut *guard;
            let Some(proof) = stores
                .retail_spent
                .get(&digest)
                .and_then(|c| c.original.as_ref())
            else {
                return false;
            };
            stores.slots[ds.slot()]
                .as_mut()
                .is_some_and(|slot| slot.store.authorize_repin(proof))
        });
        if !verified {
            self.repin_carry(source, key, file);
            return false;
        }
        // Shared cross-cause allowance is spent only at actual native start.
        if !self.paced_admission(source, key, SystemTime::now(), false, false, true) {
            self.repin_carry(source, key, file);
            return false;
        }
        let Some(mut stores) = self.durable() else {
            return false;
        };
        let pass = &mut stores.repin_pass[ds.slot()];
        pass.files += 1;
        pass.bytes += bytes;
        let state = stores
            .key_debt
            .get_mut(&digest)
            .and_then(|d| d.repin.as_mut())
            .expect("reserved repin");
        state.started = true;
        state.completed = false;
        state.limit = bytes;
        Counters::bump(&mut stores.counters.resource_full, "repin");
        drop(stores);
        crate::local_resource_diagnostics::durable_tail_alarm(
            source.api_slug(),
            &serde_json::json!({"repin_full_files":1}),
        );
        true
    }

    /// Actual consumed bytes, on every step including partial/error steps.
    pub(in crate::snapshots) fn repin_input(
        &self,
        source: SnapshotSource,
        key: &str,
        bytes: u64,
        complete: bool,
    ) {
        let Some(ds) = durable_source(source) else {
            return;
        };
        let mut completed = false;
        let active = self.durable().is_some_and(|mut stores| {
            let Some(state) = stores
                .key_debt
                .get_mut(&store::key_digest(ds, key))
                .and_then(|d| d.repin.as_mut())
            else {
                return false;
            };
            if !state.started {
                return false;
            }
            if complete && !state.completed {
                state.completed = true;
                completed = true;
            }
            true
        });
        if active {
            crate::local_resource_diagnostics::durable_tail_alarm(
                source.api_slug(),
                &serde_json::json!({"repin_full_bytes":bytes,"repin_completed":u64::from(completed)}),
            );
        }
    }

    pub(in crate::snapshots) fn repin_retire<W: SingleWriter>(
        &self,
        writer: &W,
        source: SnapshotSource,
    ) {
        let Some(ds) = durable_source(source) else {
            return;
        };
        let Some(mut guard) = self.durable() else {
            return;
        };
        let stores = &mut *guard;
        let Some(slot) = stores.slots[ds.slot()].as_mut() else {
            return;
        };
        for (digest, debt) in &mut stores.key_debt {
            let Some(_state) = debt.repin.filter(|r| r.source == ds && r.completed) else {
                continue;
            };
            let Some(custody) = stores.retail_spent.get_mut(digest) else {
                continue;
            };
            let Some(proof) = custody.original.as_ref() else {
                continue;
            };
            // Never retire an old survivor just because parsing finished. Only
            // a fully verified current-pin canonical record permits settlement.
            if slot
                .store
                .representation(digest)
                .map_or(true, |(format, pin)| store::retired_pin(ds, format, &pin))
            {
                continue;
            }
            debt.retire_sync = true;
            if matches!(
                slot.store
                    .retire_exact(writer, proof, &mut debt.retire_sync),
                store::RetireOutcome::Superseded
            ) {
                custody.original = None;
                debt.settle_repin();
                crate::local_resource_diagnostics::durable_tail_alarm(
                    source.api_slug(),
                    &serde_json::json!({"repin_retired":1}),
                );
            }
        }
        stores.retail_spent.retain(|_, c| c.has_authority());
    }
}
