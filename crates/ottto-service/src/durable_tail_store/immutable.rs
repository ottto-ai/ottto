//! Immutable publications in the existing store. SQLite owns reference authority.
use super::*;

pub(crate) struct ImmutableRecord {
    pub(crate) name: String,
    pub(crate) record: PendingRecord,
    pub(crate) generation: u64,
    bytes: Vec<u8>,
}
impl ImmutableRecord {
    /// Pure: reuse the envelope encoder, retaining the exact planned bytes.
    pub(crate) fn plan(record: PendingRecord, generation: u64, attempt: &str) -> Self {
        let durable = DurableRecord {
            format: record.format(),
            record,
            index_generation: generation,
            envelope_audit_debt: None,
            wire: None,
        };
        let bytes = encode(&durable);
        let mut record = durable.record;
        record.body = Vec::new();
        Self {
            name: format!("{}.{}.{attempt}.rec", hex(&record.binding.key), generation),
            record,
            generation,
            bytes,
        }
    }
    pub(crate) fn len(&self) -> u64 {
        self.bytes.len() as u64
    }
    pub(crate) fn trailer(&self) -> Digest32 {
        self.bytes[self.bytes.len() - TRAILER_BYTES..]
            .try_into()
            .expect("encoded trailer")
    }
}

/// Shared by reference lookup, generation GC and owned-temp cleanup.
pub(super) fn name_key(name: &str) -> Option<(Digest32, u64)> {
    let (key, rest) = name.strip_suffix(".rec")?.split_once('.')?;
    let key = parse_hex_digest(key)?;
    let (generation, attempt) = rest.split_once('.')?;
    let generation = generation.parse::<u64>().ok().filter(|g| *g > 0)?;
    (!attempt.is_empty()
        && attempt.len() <= 128
        && attempt
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'))
    .then_some((key, generation))
}
pub(super) fn temp_key(name: &str) -> Option<Digest32> {
    let (record, _) = name
        .strip_prefix('.')?
        .strip_suffix(TEMP_SUFFIX)?
        .split_once(".rec.")?;
    name_key(&format!("{record}.rec")).map(|(key, _)| key)
}

pub(super) type LabelNamePage = (BTreeMap<Digest32, Vec<String>>, BTreeSet<Digest32>);

impl DurableTailStore {
    pub(super) fn immutable_path(&self, name: &str, key: &Digest32) -> io::Result<PathBuf> {
        if self.source != DurableSource::ClaudeCode
            || name_key(name).map(|(named, _)| named) != Some(*key)
        {
            return Err(io::Error::other("immutable record name/source"));
        }
        Ok(self.dir.join(name))
    }

    /// Admission reads only metadata. Referenced records are never eviction candidates.
    pub(crate) fn admit_immutable(
        &self,
        writer: &dyn SingleWriter,
        bytes: u64,
        current: impl Iterator<Item = (Digest32, String, bool)>,
    ) -> io::Result<()> {
        self.check_writer(writer)?;
        if self.disabled.is_some() {
            return Err(io::Error::other("immutable store disabled"));
        }
        let mut steady = bytes;
        for (key, name, replaced) in current {
            let path = self.immutable_path(&name, &key)?;
            let metadata = inspect_path(&path)?;
            if !metadata.is_file()
                || metadata.uid() != our_uid()
                || metadata.mode() & 0o777 != 0o600
            {
                return Err(io::Error::other("immutable reference metadata"));
            }
            if !replaced {
                steady = steady
                    .checked_add(metadata.len())
                    .ok_or_else(|| io::Error::other("immutable quota"))?;
            }
        }
        if steady > 512 * 1024 * 1024 {
            return Err(io::Error::other("immutable admission capacity"));
        }
        let dir = match inspect_path(&self.dir) {
            Ok(metadata) => {
                if !metadata.is_dir()
                    || metadata.uid() != our_uid()
                    || metadata.mode() & 0o777 != 0o700
                {
                    return Err(io::Error::other("immutable directory metadata"));
                }
                self.dir.as_path()
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => self
                .dir
                .parent()
                .ok_or_else(|| io::Error::other("immutable parent"))?,
            Err(error) => return Err(error),
        };
        // statvfs already accounts for retained predecessors and orphan allocations.
        if !above_floor(dir, bytes.saturating_add((MAX_BATCH * 4096) as u64), 0)? {
            return Err(io::Error::other("immutable physical headroom"));
        }
        Ok(())
    }

    pub(crate) fn stage_immutable<W: SingleWriter>(
        &mut self,
        writer: &W,
        record: &ImmutableRecord,
    ) -> io::Result<()> {
        self.check_writer(writer)?;
        let path = self.immutable_path(&record.name, &record.record.binding.key)?;
        ensure_private_dir(&self.dir)?;
        let metadata = inspect_path(&self.dir)?;
        if !metadata.is_dir() || metadata.uid() != our_uid() || metadata.mode() & 0o777 != 0o700 {
            return Err(io::Error::other("immutable directory metadata"));
        }
        // No overwrite, even when a caller retries the same plan.
        if stamp_at(&path)?.is_some() {
            return Err(io::Error::other("immutable name occupied"));
        }
        // Fail-closed inventory precedes any possible PL-bearing bytes.
        self.mark_private_labels(writer, record.record.binding.key)?;
        let mut temp = OwnedTemp::prepare(&self.dir, &path, self.cleanup.clone())?;
        temp.write_all(&record.bytes)?;
        #[cfg(test)]
        test_hooks::write_failure("immutable_file_sync")?;
        temp.sync()?;
        temp.commit(&path, None)?;
        #[cfg(test)]
        test_hooks::write_failure("immutable_directory_sync")?;
        self.sync_store()
    }

    /// Select an exact committed name for one operation; reuse the classifier,
    /// verifier and codec. Never let its memo authorize the canonical scratch file.
    pub(crate) fn read_immutable(
        &mut self,
        name: &str,
        key: &Digest32,
    ) -> Result<(Box<DurableRecord>, MutationWitness), Refusal> {
        let path = self
            .immutable_path(name, key)
            .map_err(|_| Refusal::Unbindable)?;
        self.durable.remove(key);
        self.immutable_target = Some((*key, path));
        let result = (|| {
            let verified = self
                .read_known(key, None, false)?
                .ok_or(Refusal::Unbindable)?;
            let expected = Expected {
                binding: verified.record.record.binding.clone(),
                committed_generation: verified.record.index_generation,
            };
            let proof = self
                .mutation_witness(&verified.record, &expected)
                .ok_or(Refusal::Unbindable)?;
            Ok((verified.record, proof))
        })();
        self.immutable_target = None;
        self.durable.remove(key);
        result
    }

    /// The exact-retire implementation owns unlink -> directory-sync custody.
    pub(crate) fn retire_immutable(
        &mut self,
        writer: &dyn SingleWriter,
        name: &str,
        proof: &MutationWitness,
        sync_due: &mut bool,
    ) -> RetireOutcome {
        let Ok(path) = self.immutable_path(name, &proof.key) else {
            return RetireOutcome::Retry;
        };
        self.durable.remove(&proof.key);
        self.immutable_target = Some((proof.key, path));
        *sync_due |= self.immutable_sync_due;
        let outcome = self.retire_exact(writer, proof, sync_due);
        self.immutable_sync_due = *sync_due;
        self.immutable_target = None;
        self.durable.remove(&proof.key);
        outcome
    }

    /// Consent erasure visits all generations of the same key, including
    /// committed records. Refusal retains the existing fail-closed PL marker.
    pub(super) fn immutable_label_names(
        &mut self,
        keys: &BTreeSet<Digest32>,
    ) -> io::Result<LabelNamePage> {
        let entries = match fs::read_dir(&self.dir) {
            Ok(entries) => entries,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                return Ok((BTreeMap::new(), BTreeSet::new()))
            }
            Err(e) => return Err(e),
        };
        let mut names = BTreeMap::<_, Vec<_>>::new();
        let mut overflow = BTreeSet::new();
        let mut count = 0;
        for entry in entries {
            let entry = entry?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            if let Some(key) = temp_key(name).filter(|key| keys.contains(key)) {
                if count == GC_RECORDS_PER_PASS || !dead_temp(name) {
                    overflow.insert(key);
                    continue;
                }
                let metadata = inspect_path(&entry.path())?;
                if !metadata.is_file()
                    || metadata.uid() != our_uid()
                    || metadata.mode() & 0o777 != 0o600
                {
                    overflow.insert(key);
                    continue;
                }
                remove_if_present(&entry.path())?;
                self.immutable_sync_due = true;
                self.counters.gc_temps_deleted += 1;
                count += 1;
                continue;
            }
            let Some(key) = name
                .split_once('.')
                .and_then(|(key, _)| parse_hex_digest(key))
            else {
                continue;
            };
            if keys.contains(&key) && self.immutable_path(name, &key).is_ok() {
                if count == GC_RECORDS_PER_PASS {
                    overflow.insert(key);
                    continue;
                }
                names.entry(key).or_default().push(name.to_owned());
                count += 1;
            }
        }
        Ok((names, overflow))
    }

    /// Only known verified generations absent from the complete committed
    /// root may retire. Future names, unknown codecs and canonical v1 backup
    /// records remain held. This cursor shares the existing bounded GC quantum.
    pub(crate) fn gc_immutable(
        &mut self,
        writer: &dyn SingleWriter,
        generation: u64,
        keep: &BTreeSet<&str>,
    ) -> io::Result<()> {
        self.check_writer(writer)?;
        let entries = match fs::read_dir(&self.dir) {
            Ok(entries) => entries,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e),
        };
        let mut page = BTreeSet::new();
        for entry in entries {
            let name = entry?.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            let Some((key, rest)) = name.split_once('.') else {
                continue;
            };
            let Some(key) = parse_hex_digest(key) else {
                continue;
            };
            if self.gc_after.is_some_and(|after| key < after) {
                continue;
            }
            if self.immutable_path(name, &key).is_err() {
                continue;
            }
            let Some(record_generation) =
                rest.split('.').next().and_then(|g| g.parse::<u64>().ok())
            else {
                continue;
            };
            if record_generation > generation || keep.contains(name) {
                continue;
            }
            page.insert(name.to_owned());
            if page.len() > GC_RECORDS_PER_PASS {
                page.pop_last();
            }
        }
        let full = page.len() == GC_RECORDS_PER_PASS;
        for name in &page {
            let (key, rest) = name.split_once('.').expect("admitted name");
            let key = parse_hex_digest(key).expect("admitted key");
            let named_generation = rest
                .split('.')
                .next()
                .and_then(|g| g.parse::<u64>().ok())
                .expect("admitted generation");
            let Ok((record, proof)) = self.read_immutable(name, &key) else {
                if self.disabled.is_some() {
                    return Err(io::Error::other("immutable GC store fault"));
                }
                continue;
            };
            if record.index_generation != named_generation {
                continue;
            }
            let mut sync_due = false;
            if !matches!(
                self.retire_immutable(writer, name, &proof, &mut sync_due),
                RetireOutcome::Retired
            ) {
                return Err(io::Error::other("immutable GC retry"));
            }
        }
        self.gc_after = if full {
            page.last()
                .and_then(|name| name.split('.').next())
                .and_then(parse_hex_digest)
        } else {
            None
        };
        self.flush_immutable(writer)
    }

    pub(crate) fn flush_immutable(&mut self, writer: &dyn SingleWriter) -> io::Result<()> {
        self.check_writer(writer)?;
        if self.immutable_sync_due || self.dir.exists() {
            self.sync_store()?;
            self.immutable_sync_due = false;
        }
        Ok(())
    }
}

impl DurableRecord {
    pub(crate) fn trailer_digest(&self) -> Option<Digest32> {
        self.wire.map(|wire| wire.trailer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::durable_tail_store::tests::{binding, certificate, pending, Scratch};

    /// [format] crash boundaries preserve the exact SQLite-selected generation.
    #[test]
    fn immutable_crash_boundaries_preserve_selected_reference() {
        for edge in [
            "before_file_sync",
            "before_directory_sync",
            "before_commit",
            "ambiguous_old",
            "ambiguous_new",
            "before_gc",
            "unlink_before_sync",
        ] {
            let scratch = Scratch::new();
            let writer = crate::locked_state_dir::test_locks::hold(&scratch.root);
            let transcript = scratch.transcript("source.jsonl", b"{}\n");
            let mut store = scratch.store();
            let mut record = pending(
                binding("account", "scope", ("fp", None)),
                certificate(&transcript),
                1,
            );
            record.binding.entry = [0; 32];
            record.acquisition = Some(AcquisitionFields {
                acquired_revision: 1,
                protocol: crate::snapshots::AcquisitionProtocol::WriteAhead,
            });
            let key = record.binding.key;
            let prior = ImmutableRecord::plan(record.clone(), 1, "first");
            store.stage_immutable(writer, &prior).unwrap();
            // Planning is permitted while every filesystem access is refused.
            test_hooks::set_before_access(Some(Box::new(|_, _| {
                Err(io::Error::other("no planning IO"))
            })));
            let next = ImmutableRecord::plan(record, 2, "second");
            test_hooks::set_before_access(None);
            let fault = match edge {
                "before_file_sync" => Some("immutable_file_sync"),
                "before_directory_sync" => Some("immutable_directory_sync"),
                _ => None,
            };
            test_hooks::set_write_failure(fault);
            let stage = store.stage_immutable(writer, &next);
            test_hooks::set_write_failure(None);
            assert_eq!(stage.is_err(), fault.is_some(), "{edge}");
            assert_eq!(
                fs::read(store.dir.join(&prior.name)).unwrap(),
                prior.bytes,
                "{edge}"
            );
            let selected = if matches!(edge, "ambiguous_new" | "before_gc" | "unlink_before_sync") {
                &next
            } else {
                &prior
            };
            // A fresh store receives the recovered exact ref. A newer filename
            // cannot replace it; ambiguity has no deletion callback.
            let mut reopened = scratch.store();
            let (restored, _) = reopened.read_immutable(&selected.name, &key).unwrap();
            assert_eq!(restored.index_generation, selected.generation, "{edge}");
            assert_eq!(
                restored.trailer_digest(),
                Some(selected.trailer()),
                "{edge}"
            );
            if matches!(edge, "ambiguous_old" | "ambiguous_new" | "before_gc") {
                assert!(store.dir.join(&prior.name).exists());
                assert!(store.dir.join(&next.name).exists());
            }
            if edge == "unlink_before_sync" {
                let (_, proof) = reopened.read_immutable(&prior.name, &key).unwrap();
                test_hooks::set_before_dir_sync(Some(Box::new(|_| {
                    Err(io::Error::other("lost deletion barrier"))
                })));
                let mut due = false;
                assert!(matches!(
                    reopened.retire_immutable(writer, &prior.name, &proof, &mut due),
                    RetireOutcome::Retry
                ));
                test_hooks::set_before_dir_sync(None);
                assert!(due);
                assert!(!store.dir.join(&prior.name).exists());
                assert!(matches!(
                    reopened.retire_immutable(writer, &prior.name, &proof, &mut due),
                    RetireOutcome::Retired
                ));
                assert!(!due);
                assert!(reopened.read_immutable(&next.name, &key).is_ok());
            }
        }
    }

    /// [format] consent erasure discovers immutable generations on a cold OFF owner.
    #[test]
    fn immutable_consent_sweep_discovers_generations_after_reopen() {
        let _off = crate::snapshots::RestartRestoreForTest::disabled();
        let scratch = Scratch::new();
        let writer = crate::locked_state_dir::test_locks::hold(&scratch.root);
        let transcript = scratch.transcript("source.jsonl", b"{}\n");
        let pending = pending(
            binding("account", "scope", ("fp", None)),
            certificate(&transcript),
            1,
        );
        let mut store = scratch.store();
        let first = ImmutableRecord::plan(pending.clone(), 1, "first");
        let second = ImmutableRecord::plan(pending, 2, "second");
        store.stage_immutable(writer, &first).unwrap();
        store.stage_immutable(writer, &second).unwrap();
        let orphan = store.dir.join(format!(".{}.2147483647.1.tmp", second.name));
        fs::write(&orphan, b"interrupted private-label staging").unwrap();
        fs::set_permissions(&orphan, fs::Permissions::from_mode(0o600)).unwrap();
        let mut reopened = scratch.store();
        // The existing caller owns the label predicate; the store still
        // verifies each envelope and retains unknown/corrupt generations.
        // Expected holds remain eligible across repeated passes and never
        // count as erasure failures, even with unknown inventory after reopen.
        fs::write(reopened.dir.with_extension("private-labels"), b"PL??").unwrap();
        for pass in 0..5 {
            let report = reopened
                .purge_private_labels(writer, |name| name == first.name, |_| true)
                .unwrap();
            assert_eq!(report.erased, u64::from(pass == 0));
            assert_eq!(report.held_committed, 1);
            assert_eq!(report.refused, 0);
            assert!(reopened.dir.join(&first.name).exists());
            assert!(reopened.private_label_purge_needed(None));
        }
        assert!(!reopened.dir.join(&second.name).exists());
        let report = reopened
            .purge_private_labels(writer, |_| false, |_| true)
            .unwrap();
        assert_eq!(report.erased, 1);
        assert_eq!(report.refused, 0);
        assert!(!orphan.exists());
        assert!(!reopened.dir.join(first.name).exists());
        assert!(!reopened.dir.join(second.name).exists());
        assert_eq!(
            reopened.private_label_keys().unwrap(),
            Some(BTreeSet::new())
        );
    }

    /// [format] capacity refusal keeps committed references and stages nothing.
    #[test]
    fn immutable_capacity_refusal_keeps_committed_reference() {
        let scratch = Scratch::new();
        let writer = crate::locked_state_dir::test_locks::hold(&scratch.root);
        let transcript = scratch.transcript("source.jsonl", b"{}\n");
        let record = ImmutableRecord::plan(
            pending(
                binding("account", "scope", ("fp", None)),
                certificate(&transcript),
                1,
            ),
            1,
            "retained",
        );
        let key = record.record.binding.key;
        let mut store = scratch.store();
        store.stage_immutable(writer, &record).unwrap();
        assert!(store
            .admit_immutable(
                writer,
                512 * 1024 * 1024,
                [(key, record.name.clone(), false)].into_iter()
            )
            .is_err());
        assert!(store.read_immutable(&record.name, &key).is_ok());
        assert_eq!(fs::read_dir(&store.dir).unwrap().count(), 1);
    }
}
