//! Default-OFF M1 warm restore. Kept in main's order: entry/carrier/binding,
//! native bounded rederivation, then ordinary RAM admission. No M3 custody.
use super::*;

impl SharedCache {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn m1_restore(
        &self,
        source: SnapshotSource,
        key: &str,
        path: &Path,
        scope: &Scope,
        held: &mut File,
        index: &ScanIndex,
        interpretation: &Interpretation<'_>,
    ) -> RestoreOutcome {
        if source == SnapshotSource::Codex
            && refuse_compressed_codex(Some(path), None, CodexZstCause::DurableTailUnsupported)
                .is_err()
        {
            return RestoreOutcome::Miss(MissClass::Failure(Failure::NotRederived(
                Refuse::NotRederivable("compressed"),
            )));
        }
        match self.m1_restore_known(source, key, path, scope, held, index, interpretation) {
            Ok(taken) => RestoreOutcome::M1Restored(Box::new(taken)),
            Err(class @ MissClass::AuditCarrier) => RestoreOutcome::Miss(class),
            Err(class) => self
                .durable_guard(source, key, true, index, &mut None)
                .map_or(RestoreOutcome::Miss(class), RestoreOutcome::Held),
        }
    }
    #[allow(clippy::too_many_arguments)]
    fn m1_restore_known(
        &self,
        snapshot_source: SnapshotSource,
        key: &str,
        path: &Path,
        scope: &Scope,
        held: &mut File,
        index: &ScanIndex,
        interpretation: &Interpretation<'_>,
    ) -> Result<Taken<CachedJsonlReduction>, MissClass> {
        let source = durable_source(snapshot_source).ok_or(MissClass::Unavailable)?;
        let store_key = store::key_digest(source, key);
        let record = {
            let mut stores = self.durable().ok_or(MissClass::Unavailable)?;
            if !index.files.contains_key(key) && stores.slot(source).is_none() {
                return Err(MissClass::NoEntry);
            }
            stores.counters.restore_attempts += 1;
            // A cleared fingerprint is reparse debt (a held or reverted
            // selection): it always reads Full.
            if index
                .files
                .get(key)
                .is_some_and(|entry| entry.source_file_fingerprint.is_empty())
            {
                Counters::bump(&mut stores.counters.ineligible, "selection_cleared");
                return Err(MissClass::SelectionCleared);
            }
            // Revision adoption and money-rule replay both use this debt.
            // Check before disk I/O: an owed raw replay may never be served
            // by an otherwise valid pre-replay reduction plus Tail.
            if index.effective_upload_body_witness_revision_requires_adoption(key) {
                Counters::bump(&mut stores.counters.ineligible, "history_owed");
                return Err(MissClass::HistoryOwed);
            }
            let (outcome, disabled) = match stores.slot(source).as_mut() {
                Some(slot) => (slot.store.read(&store_key), slot.store.disabled().is_some()),
                None => {
                    return Err(if index.files.contains_key(key) {
                        MissClass::Unavailable
                    } else {
                        MissClass::NoEntry
                    })
                }
            };
            match outcome {
                ReadOutcome::Found(record) => record,
                ReadOutcome::Missing => {
                    stores.counters.missing += 1;
                    return Err(if disabled {
                        MissClass::Unavailable
                    } else if !index.files.contains_key(key) {
                        MissClass::NoEntry
                    } else {
                        MissClass::Missing
                    });
                }
                ReadOutcome::Refused(reason) => {
                    stores.counters.refused_record += 1;
                    return Err(MissClass::Record(reason));
                }
            }
        };
        if record.format != store::FORMAT_V1 {
            return Err(MissClass::Record(store::Refusal::Unknown));
        }
        if record.record.binding.context
            == store::context_digest(
                &interpretation.namespace.0,
                index.active_upload_context_fingerprint.as_deref(),
            )
            && !audit_carrier_matches(
                &record,
                index,
                key,
                unix_seconds(SystemTime::now()).unwrap_or(0),
            )
        {
            Counters::bump(
                &mut self
                    .durable()
                    .ok_or(MissClass::Unavailable)?
                    .counters
                    .ineligible,
                "audit_carrier",
            );
            return Err(MissClass::AuditCarrier);
        }
        index.files.get(key).ok_or(MissClass::NoEntry)?;
        let expected = expected(
            source,
            snapshot_source,
            key,
            scope,
            index,
            interpretation,
            Some((
                record.format,
                record.record.allowlist,
                effective_revision(snapshot_source),
            )),
        )
        .ok_or(MissClass::NoEntry)?;
        let restored =
            self.m1_restore_record(snapshot_source, &record, &expected, path, scope, held);
        // Registry probes include allowlist hashing; keep them outside Stores.
        let owed = if matches!(restored, Err(Failure::Ineligible(store::Ineligible::Scope))) {
            unregistered_scope(
                snapshot_source,
                scope,
                index,
                interpretation,
                record.record.binding.scope,
            )
        } else {
            None
        };
        let mut stores = self.durable().ok_or(MissClass::Unavailable)?;
        let (checkpoint, reduction, receipt) = match restored {
            Ok(restored) => restored,
            Err(class) => {
                let counters = &mut stores.counters;
                match class {
                    Failure::Ineligible(reason) => {
                        Counters::bump(&mut counters.ineligible, ineligible_class(reason))
                    }
                    Failure::Certificate(reason) => Counters::bump(
                        &mut counters.certificate_refused,
                        match reason {
                            CertificateRefusal::Changed(reason) => full_reason_class(reason),
                            CertificateRefusal::ReadError => "read_error",
                        },
                    ),
                    Failure::Corrupt => counters.corrupt_body += 1,
                    Failure::Resource(_) => unreachable!("M1 has no M3 resource admission"),
                    Failure::NotRederived(refuse) => {
                        Counters::bump(&mut counters.not_rederived, refuse_class(refuse))
                    }
                }
                if let Some(owed) = owed {
                    return Err(MissClass::Unregistered(owed));
                }
                return Err(MissClass::Failure(class));
            }
        };
        stores.counters.rederive_head_bytes += receipt.head_bytes;
        REDERIVE_HEAD_BYTES[source as usize].fetch_add(receipt.head_bytes, Ordering::Relaxed);
        stores.counters.rederive_named_lines += receipt.named_lines;
        stores.counters.rederive_line_bytes += receipt.line_bytes;
        drop(stores);
        // The restored copy is charged to the RAM cache exactly as a retained
        // copy is admitted; a refused charge leaves the read Full.
        let admitted = self.insert_admitted(
            key.to_string(),
            sampled_jsonl::CompletedNativeAcquisition {
                checkpoint,
                reduction: Some(reduction),
                released: None,
                unsealed: false,
                durable: Default::default(),
            },
            0,
        );
        let mut stores = self.durable().ok_or(MissClass::Unavailable)?;
        if !admitted {
            stores.counters.budget_refused += 1;
            return Err(MissClass::BudgetRefused);
        }
        stores.counters.restored += 1;
        drop(stores);
        self.take(key).ok_or(MissClass::TakeLost)
    }

    fn m1_restore_record(
        &self,
        source: SnapshotSource,
        record: &store::DurableRecord,
        expected: &Expected,
        path: &Path,
        scope: &Scope,
        held: &mut File,
    ) -> Result<(Checkpoint, CachedJsonlReduction, codec::RederiveReceipt), Failure> {
        if source == SnapshotSource::Codex {
            refuse_compressed_codex(Some(path), None, CodexZstCause::DurableTailUnsupported)
                .map_err(|_| Failure::NotRederived(Refuse::NotRederivable("compressed")))?;
        }
        record.eligible(expected).map_err(Failure::Ineligible)?;
        // M3 relaxes Claude v1 binding through its accepted-floor adapter.
        // OFF retains main's strict generation and committed-entry checks.
        if record.index_generation > expected.committed_generation {
            return Err(Failure::Ineligible(store::Ineligible::GenerationAhead));
        }
        if record.record.binding.entry != expected.binding.entry {
            return Err(Failure::Ineligible(store::Ineligible::EntryChanged));
        }
        let decoded = codec::decode(&record.record.body, source).map_err(|_| Failure::Corrupt)?;
        if !decoded.permits_skill_labels(false) {
            return Err(Failure::NotRederived(Refuse::NonEmpty(
                "skill_label_consent_off",
            )));
        }
        if decoded
            .cutover()
            .is_some_and(|stored| stored != codex_counting_version::cutover_unix_ms())
        {
            return Err(Failure::Ineligible(store::Ineligible::Scope));
        }
        let (checkpoint, _) = record
            .record
            .certificate
            .restore(held, scope.clone())
            .map_err(Failure::Certificate)?;
        let mut rederive = held
            .try_clone()
            .map_err(|_| Failure::NotRederived(Refuse::NotRederivable("descriptor")))?;
        let parser = codec::rederive_parser(
            rederive
                .try_clone()
                .map_err(|_| Failure::NotRederived(Refuse::NotRederivable("descriptor")))?,
            path,
            &decoded,
        )
        .map_err(|_| Failure::NotRederived(Refuse::NotRederivable("parser")))?;
        let (reduction, receipt) = decoded
            .rederive(parser, &mut rederive, jsonl_line_cap() as u64)
            .map_err(Failure::NotRederived)?;
        Ok((checkpoint, reduction, receipt))
    }
}
