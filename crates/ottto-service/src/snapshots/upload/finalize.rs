//! Scan finalization after the upload policy: binds the index state to the
//! exact bytes and semantics that go on the wire, samples Codex recovery
//! lineage and observes parentless Claude Desktop lineage.

use crate::snapshots::*;

#[derive(Debug, Clone)]
pub(in crate::snapshots) struct PendingIndexFinalization {
    pub(in crate::snapshots) refold_unchanged: bool,
    pub(in crate::snapshots) withheld_content: Option<withheld_account::Seen>,
    pub(in crate::snapshots) sampled_audit_verified: bool,
    pub(in crate::snapshots) codex_pending_recovery: bool,
    pub(in crate::snapshots) index_key: String,
    pub(in crate::snapshots) source_file_fingerprint: String,
    pub(in crate::snapshots) previous_snapshot_fingerprint: Option<String>,
    pub(in crate::snapshots) previous_upload_body_witness: Option<String>,
    pub(in crate::snapshots) parse_complete: bool,
    pub(in crate::snapshots) diagnostic_reason: FileReason,
    pub(in crate::snapshots) parsed_snapshot_count: usize,
    pub(in crate::snapshots) effective_upload_body_witness_revision: u64,
}

pub(crate) fn snapshot_source_from_api_slug(value: &str) -> Option<SnapshotSource> {
    match value {
        "codex" => Some(SnapshotSource::Codex),
        "claude_code" => Some(SnapshotSource::ClaudeCode),
        "pi" => Some(SnapshotSource::Pi),
        _ => None,
    }
}

#[cfg(test)]
pub(crate) fn snapshot_item_wire_size(
    source: SnapshotSource,
    item: &SnapshotItem,
    policy: SnapshotUploadPolicy,
) -> usize {
    serde_json::to_vec(&SnapshotItemWire {
        snapshot: item,
        semantic_envelope: snapshot_semantic_envelope(source, item, policy),
    })
    .map(|encoded| encoded.len())
    .unwrap_or(usize::MAX)
}

/// Bind incremental state to the exact bytes/semantics that will go on the
/// wire. This MUST run after every enrichment, privacy policy, and account
/// cutoff. Parser-time fingerprints are provisional only: committing them
/// earlier can suppress a later policy/enrichment correction forever.
pub fn finalize_scan_after_policy(
    source: SnapshotSource,
    result: &mut SourceScanResult,
    index: &mut ScanIndex,
) {
    finalize_scan_after_policy_with_body_witness(
        source,
        result,
        index,
        snapshot_upload_body_witness,
    );
}

/// Sample existing quarantine metadata only. These are working-index witnesses
/// at finalization, not a claim about later partial-checkpoint persistence.
pub(crate) fn prepare_codex_recovery_diagnostics(
    result: &mut SourceScanResult,
    index: &ScanIndex,
    quarantines: &BTreeMap<String, SnapshotQuarantineRecord>,
) {
    let Some(diagnostic) = result.local_codex_diagnostics.as_mut() else {
        return;
    };
    diagnostic.lineage = [None; LINEAGE_SAMPLES];
    diagnostic.sample_offset = 0;
    diagnostic.quarantine_count = quarantines.len() as u64;
    if quarantines.is_empty() {
        return;
    }
    let offset = (diagnostic.generation % quarantines.len() as u64) as usize;
    diagnostic.sample_offset = offset as u64;
    for (slot, (fingerprint, quarantine)) in quarantines
        .iter()
        .cycle()
        .skip(offset)
        .take(quarantines.len().min(LINEAGE_SAMPLES))
        .enumerate()
    {
        let mut sample = RecoveryLineage::new(fingerprint, quarantine.disposition);
        for (key, fingerprints) in &index.file_snapshot_fingerprints {
            if fingerprints.contains(fingerprint) {
                sample.before_current = true;
                sample.associated_file_count = sample.associated_file_count.saturating_add(1);
                if sample.file_key_digest.is_none() {
                    sample.file_key_digest = Some(codex_scan_diagnostics::digest(key));
                    sample.previous_body_digest = result
                        .pending_finalization
                        .iter()
                        .find(|pending| &pending.index_key == key)
                        .and_then(|pending| pending.previous_upload_body_witness.as_deref())
                        .or_else(|| {
                            index
                                .files
                                .get(key)
                                .and_then(|entry| entry.last_upload_body_witness.as_deref())
                        })
                        .map(codex_scan_diagnostics::digest);
                }
            }
        }
        // Preserve the canonical current-set fallback for pre-entity-map indexes.
        for (key, entry) in &index.files {
            if !index.file_snapshot_fingerprints.contains_key(key)
                && entry.last_snapshot_fingerprint.as_ref() == Some(fingerprint)
            {
                sample.before_current = true;
                sample.associated_file_count = sample.associated_file_count.saturating_add(1);
                if sample.file_key_digest.is_none() {
                    sample.file_key_digest = Some(codex_scan_diagnostics::digest(key));
                    sample.legacy_file_association = true;
                    sample.previous_body_digest = entry
                        .last_upload_body_witness
                        .as_deref()
                        .map(codex_scan_diagnostics::digest);
                }
            }
        }
        diagnostic.lineage[slot] = Some(sample);
    }
}

/// Finalize using the additive body witness of the effective upload projection.
/// The witness function sees recomputed semantic fingerprints and must return
/// a stable witness for both file no-op suppression and quarantine retries.
/// It does not modify the local snapshot items or semantic entity identity.
pub fn finalize_scan_after_policy_with_body_witness(
    source: SnapshotSource,
    result: &mut SourceScanResult,
    index: &mut ScanIndex,
    mut body_witness: impl FnMut(&SnapshotItem) -> String,
) {
    if !index.persistence_available() {
        result.snapshots.clear();
        result.census_complete = false;
        return;
    }

    // Backstop of the one emission seam: no held history body is finalized.
    index.veto_claude_history_emission(source, &mut result.snapshots);
    let mut refold_components = tail_source::refold_moved::Page::new();
    for snapshot in &mut result.snapshots {
        let components = snapshot_semantic_component_hashes(source, snapshot);
        snapshot.snapshot_fingerprint = snapshot_fingerprint_from_component_hashes(
            source,
            &snapshot.source_session_id,
            &components,
        );
        tail_source::refold_moved::capture(source, snapshot, &components, &mut refold_components);
        index.snapshot_activity_at.insert(
            snapshot.snapshot_fingerprint.clone(),
            snapshot_semantic_activity_at(snapshot),
        );
    }

    index.preserve_decode_held_files(source, &result.snapshots, &mut result.pending_finalization);
    result
        .snapshots
        .retain(|snapshot| !index.decode_holds_snapshot(source, snapshot));
    if !index.decode_holds.is_empty() {
        result.census_complete = false;
        index.mark_bounded_sweep_unsettled();
    }
    let mut by_source_file: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut by_source_file_body_witness: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for snapshot in &result.snapshots {
        if let Some(source_file_fingerprint) = snapshot.source_file_fingerprint.as_ref() {
            by_source_file
                .entry(source_file_fingerprint.clone())
                .or_default()
                .insert(snapshot.snapshot_fingerprint.clone());
            by_source_file_body_witness
                .entry(source_file_fingerprint.clone())
                .or_default()
                .insert(body_witness(snapshot));
        }
    }

    if source == SnapshotSource::Codex {
        codex_file_join::fan_out_body_witnesses(
            index,
            &mut by_source_file,
            &mut by_source_file_body_witness,
        );
    }

    let mut noop_source_files = BTreeSet::new();
    let mut carried_noop_entities = BTreeSet::new();
    for pending in &result.pending_finalization {
        if let Some(diagnostic) = result.local_codex_diagnostics.as_mut() {
            let key_digest = codex_scan_diagnostics::digest(&pending.index_key);
            for sample in diagnostic.lineage.iter_mut().flatten() {
                if sample.file_key_digest == Some(key_digest) {
                    sample.file_reason = pending.diagnostic_reason;
                    sample.parsed_count = pending.parsed_snapshot_count as u64;
                }
            }
        }
        if !pending.parse_complete {
            continue;
        }
        if index.finalize_claude_held_history(&pending.index_key, &pending.source_file_fingerprint)
        {
            continue;
        }
        let final_fingerprints = by_source_file
            .get(&pending.source_file_fingerprint)
            .cloned()
            .unwrap_or_default();
        let final_group_fingerprint = (!final_fingerprints.is_empty())
            .then(|| snapshot_file_entity_set_hex(&final_fingerprints));
        tail_source::refold_moved::observe(
            source,
            pending,
            final_group_fingerprint.as_deref(),
            &mut refold_components,
        );
        let final_upload_body_witness = by_source_file_body_witness
            .get(&pending.source_file_fingerprint)
            .filter(|witnesses| !witnesses.is_empty())
            .map(snapshot_file_upload_body_set_hex);
        if pending.sampled_audit_verified {
            crate::local_resource_diagnostics::sampled_audit_comparison(
                source.api_slug(),
                (
                    final_group_fingerprint.as_deref(),
                    pending.previous_snapshot_fingerprint.as_deref(),
                ),
                (
                    final_upload_body_witness.as_deref(),
                    pending.previous_upload_body_witness.as_deref(),
                ),
            );
        }
        let quarantine_retry_required = result.snapshots.iter().any(|snapshot| {
            snapshot.source_file_fingerprint.as_deref()
                == Some(pending.source_file_fingerprint.as_str())
                && index.quarantine_requires_retry_body(
                    &snapshot.snapshot_fingerprint,
                    &body_witness(snapshot),
                )
        });
        if let Some(entry) = index.files.get_mut(&pending.index_key) {
            entry.last_snapshot_fingerprint = final_group_fingerprint.clone();
            entry.last_upload_body_witness = final_upload_body_witness.clone();
        }
        let stamped = index.stamp_effective_upload_body_witness_revision(
            &pending.index_key,
            &pending.source_file_fingerprint,
            pending.effective_upload_body_witness_revision,
        );
        if stamped && source == SnapshotSource::ClaudeCode {
            // The settled body's money-rule marks (design item 8), with its stamp.
            let mut items = result
                .snapshots
                .iter()
                .filter(|item| {
                    item.source_file_fingerprint.as_deref()
                        == Some(pending.source_file_fingerprint.as_str())
                })
                .peekable();
            if items.peek().is_some() {
                // The retired permit bit stays as stored.
                let retired = index
                    .claude_money_birth_store
                    .money_marks(claude_money_birth_store::location_key(&pending.index_key))
                    & (claude_request_money::e2::money_mark::RETIRED_PERMIT
                        | claude_copy_prefix_reread::REOWED);
                let marks = items.fold(retired, |marks, item| {
                    marks | claude_request_money::e2::money_marks(item)
                });
                index
                    .claude_money_birth_store
                    .set_money_marks(&pending.index_key, marks);
            }
        }
        if let Some(diagnostic) = result.local_codex_diagnostics.as_mut() {
            let key_digest = codex_scan_diagnostics::digest(&pending.index_key);
            for sample in diagnostic.lineage.iter_mut().flatten() {
                if sample.file_key_digest == Some(key_digest) {
                    sample.finalized = true;
                    sample.finalized_entity_count = final_fingerprints.len() as u64;
                    for (slot, fingerprint) in
                        final_fingerprints.iter().take(LINEAGE_SAMPLES).enumerate()
                    {
                        sample.successor_digests[slot] =
                            codex_scan_diagnostics::digest(fingerprint);
                    }
                    sample.final_body_digest = final_upload_body_witness
                        .as_deref()
                        .map(codex_scan_diagnostics::digest);
                    sample.final_body_revision = index
                        .files
                        .get(&pending.index_key)
                        .map(|entry| entry.effective_upload_body_witness_revision)
                        .unwrap_or_default();
                }
            }
        }
        // A complete, permitted reconstruction replaces only THIS file's
        // carried incidence. Its already accepted entities must not be offered
        // again when a history hold is released, even without an old body tuple.
        // Legacy/unknown incidence stays funded and protects only its original
        // ACKs even when no file association can be recovered.
        // A semantic no-op at a moved revision carries its receipt (A1-A4):
        // complete parse, identical entity and body sets, no quarantine retry,
        // no hold. A correction-owed member is not carried: its own no-op rule
        // drains it, so its unchanged bodies are not re-sent either, and a
        // later read carries or sends once the correction settled.
        let semantic_noop = final_group_fingerprint.is_some()
            && final_group_fingerprint == pending.previous_snapshot_fingerprint
            && final_upload_body_witness == pending.previous_upload_body_witness
            && !pending.codex_pending_recovery
            && !quarantine_retry_required;
        let correction_named = source == SnapshotSource::ClaudeCode
            && index.claude_authority_correction_owed(Path::new(&pending.index_key));
        let correction_owed = semantic_noop && correction_named;
        // The A1-A3 exclusions shared by the carry and a rebuilt receipt.
        let receipt_eligible = !correction_named
            && !pending.codex_pending_recovery
            && !quarantine_retry_required
            && !index.decode_holds_file(&pending.index_key)
            && !index
                .claude_account_deferred_holds
                .contains_key(&pending.index_key)
            && !final_fingerprints
                .iter()
                .any(|fp| index.quarantined_snapshot_fingerprints.contains_key(fp));
        let carried_incidence = index.accepted_rebuild_incidence.remove(&pending.index_key);
        let entity_bodies = if (semantic_noop && receipt_eligible)
            || carried_incidence.is_some()
            || index.accepted_rebuild_incidence.contains_key("")
        {
            result
                .snapshots
                .iter()
                .filter(|item| {
                    item.source_file_fingerprint.as_deref()
                        == Some(pending.source_file_fingerprint.as_str())
                })
                .map(|item| (item.snapshot_fingerprint.clone(), body_witness(item)))
                .collect::<BTreeMap<_, _>>()
        } else {
            BTreeMap::new()
        };
        // A carried accepted entity whose durable stamp proves this body
        // under the file's context is not re-sent, even while its file owes
        // a receipt (a manual-override rebuild keeps stamps, not receipts).
        let stamp_proven = entity_bodies
            .iter()
            .filter(|(fp, body)| index.file_entity_stamp_proves(&pending.index_key, fp, body))
            .map(|(fp, _)| fp.clone())
            .collect::<BTreeSet<_>>();
        if semantic_noop
            && receipt_eligible
            && !entity_bodies.is_empty()
            && stamp_proven.len() == entity_bodies.len()
        {
            index
                .carry_upload_context_receipt(&pending.index_key, &pending.source_file_fingerprint);
        }
        // P2: the file receipt only from this complete parse of the current
        // revision that found exactly the carried accepted set, every entity
        // stamp-proven with its body, under the A1-A3 exclusions.
        if receipt_eligible
            && !final_fingerprints.is_empty()
            && carried_incidence.as_ref() == Some(&final_fingerprints)
            && stamp_proven == final_fingerprints
            && index.file_upload_context_requires_adoption(&pending.index_key)
        {
            if let Some(body) = final_upload_body_witness.as_deref() {
                index.receipt_from_stamps(
                    &pending.index_key,
                    &pending.source_file_fingerprint,
                    body,
                );
            }
        }
        let context_rearm_required =
            !correction_owed && index.file_upload_context_requires_adoption(&pending.index_key);
        let carried_noop = |fp: &String| {
            index.accepted_snapshot_fingerprints.contains(fp)
                && (!context_rearm_required || stamp_proven.contains(fp))
        };
        if let Some(unknown) = index.accepted_rebuild_incidence.get("") {
            carried_noop_entities.extend(
                unknown
                    .intersection(&final_fingerprints)
                    .filter(|fp| carried_noop(fp))
                    .cloned(),
            );
        }
        if let Some(carried) = carried_incidence {
            carried_noop_entities.extend(
                carried
                    .intersection(&final_fingerprints)
                    .filter(|fp| carried_noop(fp))
                    .cloned(),
            );
        }
        index.accepted_incidence_pending_census = !index.accepted_rebuild_incidence.is_empty();
        if final_fingerprints.is_empty() {
            index.file_snapshot_fingerprints.remove(&pending.index_key);
            index
                .confirmed_empty_files
                .insert(pending.index_key.clone());
            index.note_empty_file_upload_context(&pending.index_key);
        } else {
            index
                .file_snapshot_fingerprints
                .insert(pending.index_key.clone(), final_fingerprints);
            index.confirmed_empty_files.remove(&pending.index_key);
        }
        // An unresolved POST may have replaced that older accepted body.
        // Use the pre-replay fact: record() writes provisional new entries.
        if semantic_noop && !context_rearm_required {
            noop_source_files.insert(pending.source_file_fingerprint.clone());
            result.semantic_noop_count = result
                .semantic_noop_count
                .saturating_add(pending.parsed_snapshot_count);
        }
    }
    if source == SnapshotSource::ClaudeCode {
        index.note_claude_history_not_stamped();
    }
    result.snapshots.retain(|snapshot| {
        !carried_noop_entities.contains(&snapshot.snapshot_fingerprint)
            && snapshot
                .source_file_fingerprint
                .as_ref()
                .map(|source_file| !noop_source_files.contains(source_file))
                .unwrap_or(true)
    });

    if result.census_complete {
        index.bounded_sweep_had_unsettled_upload = false;
        index.bounded_sweep_unsettled_causes = 0;
    }
    index.note_carried_ack_census(source, result.census_complete, SystemTime::now());
    let current_fingerprints = index
        .file_snapshot_fingerprints
        .values()
        .flat_map(BTreeSet::iter)
        .collect::<BTreeSet<_>>();
    index
        .snapshot_activity_at
        .retain(|fingerprint, _| current_fingerprints.contains(fingerprint));
    #[cfg(unix)]
    tail_source::counters::emit(source);
}

/// Observe only offers that survived policy, holds and semantic no-op removal.
/// Cached Desktop child metadata is already resident; no source reads or durable
/// state are needed. Scratch is bounded by this page's emitted items.
pub(crate) fn record_lineage_parentless_while_incomplete(
    source: SnapshotSource,
    snapshots: &[SnapshotItem],
    index: &ScanIndex,
) {
    if source != SnapshotSource::ClaudeCode
        || index.claude_desktop_lineage_census_complete
        || snapshots.is_empty()
    {
        return;
    }
    let mut parentless: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    for snapshot in snapshots {
        if snapshot
            .origin
            .as_ref()
            .and_then(|origin| origin.parent_session_ref.as_deref())
            .is_none()
            && !snapshot
                .attribution_facts
                .iter()
                .any(|fact| fact.field == "parent_session_ref")
        {
            if let Some(file) = snapshot.source_file_fingerprint.as_deref() {
                parentless
                    .entry(&snapshot.source_session_id)
                    .or_default()
                    .insert(file);
            }
        }
    }
    if parentless.is_empty() {
        return;
    }
    let mut files = BTreeSet::new();
    for entry in index.claude_desktop_title_files.values() {
        if entry.spawned_from_desktop_session_id.is_some() || entry.spawned_from_unresolved {
            if let Some(emitted) = parentless.remove(entry.cli_session_id.as_str()) {
                files.extend(emitted);
            }
        }
    }
    crate::local_resource_diagnostics::claude_reread::lineage_parentless_while_incomplete(
        files.len() as u64,
    );
}

/// The producer-side event clock mirrored by the accepted-log append path.
/// The maximum activity clock is stable across retries and reconstructible on
/// both sides. `collected_at` is deliberately excluded because it is an
/// observation clock; metadata-only entities without semantic activity do not
/// participate in a v2 manifest.
pub(in crate::snapshots) fn snapshot_semantic_activity_at(item: &SnapshotItem) -> Option<String> {
    item.usage_buckets
        .iter()
        .flat_map(|bucket| {
            [
                Some(bucket.bucket_start.as_str()),
                bucket.first_activity_at.as_deref(),
                bucket.last_activity_at.as_deref(),
            ]
        })
        .chain([
            item.source_started_at.as_deref(),
            item.source_ended_at.as_deref(),
            item.source_last_activity_at.as_deref(),
        ])
        .flatten()
        .filter_map(|value| {
            OffsetDateTime::parse(value, &Rfc3339)
                .ok()
                .map(|parsed| (parsed, value))
        })
        .max_by_key(|(parsed, _)| *parsed)
        .map(|(_, value)| value.to_string())
}

crate::heap_layout_bound::fields!(PendingIndexFinalization; withheld_content, sampled_audit_verified, codex_pending_recovery, index_key, source_file_fingerprint, previous_snapshot_fingerprint, previous_upload_body_witness, parse_complete, diagnostic_reason, parsed_snapshot_count, effective_upload_body_witness_revision);
