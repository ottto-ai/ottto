//! Claude reported usage: the transcript reasoning-effort reader and its
//! evidence pass, the reported-usage entry points over the index and the
//! local API rows, and the family-root helpers they key by.

use crate::snapshots::*;

/// The applied reasoning-effort tier recorded on this transcript record.
///
/// Claude Code writes it as a top-level `effort` field on assistant records.
/// Unknown or malformed values degrade to `None` (effort-unknown) rather than
/// inventing a tier, and the vocabulary check keeps a future Claude tier from
/// silently widening the column the backend stores this in.
pub(in crate::snapshots) fn claude_transcript_effort(value: &Value) -> Option<String> {
    let effort = string_at(value, &["effort"])?.trim().to_ascii_lowercase();
    CLAUDE_EFFORT_TIERS
        .contains(&effort.as_str())
        .then_some(effort)
}

/// Apply privacy-safe account identity reduced from Claude Code's local OTLP.
///
/// Reasoning effort comes only from each assistant transcript record. Local
/// OTLP evidence may stamp an exactly covered session from its own requests,
/// but it must never supply or split reasoning-effort tiers.
pub fn apply_claude_effort_evidence(
    snapshots: &mut [SnapshotItem],
    evidence_by_session: &BTreeMap<String, Vec<crate::claude_local_otel::ClaudeLocalOtelEvidence>>,
) {
    for item in snapshots.iter_mut() {
        let Some(evidence) = evidence_by_session.get(&item.source_session_id) else {
            continue;
        };
        let identity_changed = veto_claude_original_identity(item, evidence);
        let account_applied = apply_claude_account_evidence(item, evidence);
        if account_applied {
            crate::local_resource_diagnostics::change_reason::claude_account_evidence_applied(
                &item.source_session_id,
            );
        }
        if account_applied || identity_changed {
            rebuild_retagged_model_usage(item);
            item.snapshot_fingerprint = snapshot_fingerprint(SnapshotSource::ClaudeCode, item);
        }
    }
}

pub fn apply_claude_effort_evidence_with_index(
    snapshots: &mut [SnapshotItem],
    evidence_by_session: &BTreeMap<String, Vec<crate::claude_local_otel::ClaudeLocalOtelEvidence>>,
    index: &ScanIndex,
) {
    if index.persistence_available() {
        apply_claude_effort_evidence(snapshots, evidence_by_session);
    }
}

/// The telemetry rows the file birth tripwire may hold per root.
const MAX_CLAUDE_TRIPWIRE_REQUESTS: usize = 250_000;

/// Replace transcript-only Claude usage of a witnessed family with the exact
/// union of transcript responses and locally reported API-request
/// occurrences, rebuilt from its durable witness.
///
/// This mutates usage, cost, and context-posture fields only. Provider graph
/// facts remain the transcript/filesystem truth and are never inferred from
/// telemetry spans.
#[cfg(test)]
pub fn apply_claude_reported_usage_with_index(
    snapshots: &mut [SnapshotItem],
    api_report: &crate::claude_local_otel::ClaudeLocalOtelLoadReport,
    trace_report: &crate::claude_local_otel::ClaudeTraceOwnershipLoadReport,
    index: &mut ScanIndex,
) -> ClaudeUsageAuthorityDisposition {
    apply_claude_reported_usage_with_identity(snapshots, api_report, trace_report, index, None)
}

/// As above; with contract-5 evidence, each rebuilt item's requests are also
/// classified and grouped as the rebuild places them.
#[cfg(test)]
pub(crate) fn apply_claude_reported_usage_with_identity(
    snapshots: &mut [SnapshotItem],
    api_report: &crate::claude_local_otel::ClaudeLocalOtelLoadReport,
    trace_report: &crate::claude_local_otel::ClaudeTraceOwnershipLoadReport,
    index: &mut ScanIndex,
    identity: Option<&claude_request_identity::ScanEvidence<'_>>,
) -> ClaudeUsageAuthorityDisposition {
    apply_claude_reported_usage_with_index_and_rows(
        snapshots,
        api_report,
        trace_report,
        index,
        identity,
        ClaudeEvidenceRows::Whole(&BTreeMap::new()),
    )
}

#[cfg(test)]
pub(crate) fn apply_claude_reported_usage_to_scan_with_identity(
    scan: &mut SourceScanResult,
    api_report: &crate::claude_local_otel::ClaudeLocalOtelLoadReport,
    trace_report: &crate::claude_local_otel::ClaudeTraceOwnershipLoadReport,
    index: &mut ScanIndex,
    identity: Option<&claude_request_identity::ScanEvidence<'_>>,
) -> ClaudeUsageAuthorityDisposition {
    apply_claude_reported_usage_to_scan_with_rows(
        scan,
        api_report,
        trace_report,
        index,
        identity,
        ClaudeEvidenceRows::Whole(&BTreeMap::new()),
    )
}

/// Where the Claude fold finds the evidence of roots outside its reports.
#[derive(Clone, Copy)]
pub(crate) enum ClaudeEvidenceRows<'a> {
    /// The reports hold every healthy root; these are the API rows of roots
    /// whose pair was missing or unhealthy, which only veto the file birth rule.
    Whole(&'a ClaudeVetoApiRows),
    /// The reports hold the page roots; every root's cross-root answers were
    /// gathered while the pass read it, and other pairs are reread on demand.
    Streamed(&'a claude_cross_root_evidence::CrossRootEvidence),
}

pub(crate) fn apply_claude_reported_usage_to_scan_with_rows(
    scan: &mut SourceScanResult,
    api_report: &crate::claude_local_otel::ClaudeLocalOtelLoadReport,
    trace_report: &crate::claude_local_otel::ClaudeTraceOwnershipLoadReport,
    index: &mut ScanIndex,
    identity: Option<&claude_request_identity::ScanEvidence<'_>>,
    evidence_rows: ClaudeEvidenceRows<'_>,
) -> ClaudeUsageAuthorityDisposition {
    apply_claude_reported_usage_with_index_and_rows(
        &mut scan.snapshots,
        api_report,
        trace_report,
        index,
        identity,
        evidence_rows,
    )
}

/// The whole page quarantined, as a fold refuses a page it cannot read
/// (persistence unavailable).
fn claude_page_refused(snapshots: &[SnapshotItem]) -> ClaudeUsageAuthorityDisposition {
    ClaudeUsageAuthorityDisposition {
        quarantined_source_session_ids: snapshots
            .iter()
            .map(|s| s.source_session_id.clone())
            .collect(),
        ..Default::default()
    }
}

fn apply_claude_reported_usage_with_index_and_rows(
    snapshots: &mut [SnapshotItem],
    api_report: &crate::claude_local_otel::ClaudeLocalOtelLoadReport,
    trace_report: &crate::claude_local_otel::ClaudeTraceOwnershipLoadReport,
    index: &mut ScanIndex,
    identity: Option<&claude_request_identity::ScanEvidence<'_>>,
    evidence_rows: ClaudeEvidenceRows<'_>,
) -> ClaudeUsageAuthorityDisposition {
    if !index.persistence_available() {
        return claude_page_refused(snapshots);
    }
    let reports_healthy = api_report.health.is_complete() && trace_report.is_complete();
    // The canonical ownership reducer validates semantic evidence too (row
    // fingerprints/revisions/clocks and paired clients), beyond file health.
    // No evidence is healthy: the reducer returns Some(empty), not a refusal.
    let whole_ownership;
    let ownership = match evidence_rows {
        _ if !reports_healthy => None,
        ClaudeEvidenceRows::Whole(_) => {
            whole_ownership = classify_claude_legacy_request_owners(
                api_report.evidence.iter(),
                &trace_report.evidence,
            );
            Some(whole_ownership.as_ref().map_err(|refusal| *refusal))
        }
        ClaudeEvidenceRows::Streamed(cross) => Some(cross.legacy_request_owners.verdict()),
    };
    let legacy_request_owners = ownership.and_then(Result::ok);

    // Only FE-published sealed prefixes are excluded. Ordinary
    // EOF-recomposed Tail/Unchanged bodies keep positive proof/posture behavior
    // while still owing their Full audit. Request-census tail records used directly, without
    // a complete current native body, remain observation-only evidence.
    // Bind prefix provenance by exact revision as well as physical path: a
    // logical family can differ from its index key, and the census record can be missing.
    let uncertified_revisions = index
        .files
        .values()
        .filter(|entry| entry.has_prefix_provenance())
        .map(|entry| entry.source_file_fingerprint.as_str())
        .filter(|revision| !revision.is_empty())
        .collect::<BTreeSet<_>>();
    let mut uncertified_roots = index
        .claude_request_census
        .records()
        .filter(|(_, record)| {
            record.unverified_or_twin()
                && !(record.can_bind_recomposed_body()
                    && snapshots.iter().any(|item| {
                        item.source_file_fingerprint
                            .as_deref()
                            .is_some_and(|revision| {
                                !uncertified_revisions.contains(revision)
                                    && claude_request_census::fingerprint_matches(record, revision)
                            })
                    }))
        })
        .map(|(key, _)| key)
        .chain(
            index
                .files
                .iter()
                .filter(|(_, entry)| entry.has_prefix_provenance())
                .map(|(key, _)| key),
        )
        .filter_map(|key| claude_index_path_family_member(Path::new(key)))
        .map(|(root, _)| root)
        .collect::<BTreeSet<_>>();
    let mut prefix_excluded_bodies = 0u64;
    uncertified_roots.extend(
        snapshots
            .iter()
            .filter(|item| {
                let prefix = item
                    .source_file_fingerprint
                    .as_deref()
                    .is_some_and(|revision| uncertified_revisions.contains(revision));
                prefix_excluded_bodies = prefix_excluded_bodies.saturating_add(u64::from(prefix));
                prefix
            })
            .map(claude_snapshot_family_root),
    );
    crate::local_resource_diagnostics::cache_lifecycle::add(
        crate::local_resource_diagnostics::cache_lifecycle::Event::PrefixExcludedBody,
        prefix_excluded_bodies,
    );
    drop(uncertified_revisions);
    // A reconstructed family is read only for this call's items (rebuild and
    // posture below); the witness retain already keeps every earlier root.
    let item_roots = snapshots
        .iter()
        .map(claude_snapshot_family_root)
        .collect::<BTreeSet<_>>();
    let witness_roots_before = index
        .claude_usage_family_witnesses
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    let witness_fingerprints_before = index
        .claude_usage_family_witnesses
        .iter()
        .map(|(root_session_id, witness)| {
            (
                root_session_id.clone(),
                claude_usage_family_witness_fingerprint(witness),
            )
        })
        .collect::<BTreeMap<_, _>>();
    // A witnessed family is rebuilt from the reports; nothing new is proven.
    let reconstructed = if reports_healthy {
        index
            .claude_usage_family_witnesses
            .iter()
            .filter(|(root_session_id, _)| {
                item_roots.contains(*root_session_id)
                    && !uncertified_roots.contains(*root_session_id)
            })
            .filter_map(|(root_session_id, witness)| {
                reconstruct_claude_usage_family(
                    root_session_id,
                    witness,
                    api_report,
                    trace_report,
                    legacy_request_owners,
                )
                .map(|family| (root_session_id.clone(), family))
            })
            .collect::<BTreeMap<_, _>>()
    } else {
        BTreeMap::new()
    };

    let mut request_groupings = BTreeMap::new();
    for item in snapshots.iter_mut() {
        // "None owners" for v1 bodies: an `e2` body never
        // reaches the legacy fork-prefix exclusion. Its copies are removed
        // once, by the `e2` copy rule.
        if item.claude_money.is_some() {
            continue;
        }
        item.usage_accounting_contract = None;
        let root_session_id = claude_snapshot_family_root(item);
        let Some(family) = reconstructed.get(&root_session_id) else {
            continue;
        };
        let Some((rows, excluded_request_hashes)) = claude_reported_usage_inputs(item, family)
        else {
            continue;
        };
        // The rebuild mirrors each of its rows into the grouping, so groups
        // are bounded by the rows it builds, never by the request count.
        let mut sink = identity.and_then(|evidence| {
            claude_request_identity::RequestSink::for_item(evidence, item, usize::MAX)
                .map(|sink| sink.excluding(item, &excluded_request_hashes))
        });
        if rebuild_claude_reported_usage(item, rows, &excluded_request_hashes, sink.as_mut()) {
            if let Some(sink) = sink {
                request_groupings.insert(item.source_session_id.clone(), sink.finish());
            }
            item.usage_accounting_contract =
                Some("session_exclusive_reported_usage:v1".to_string());
            item.snapshot_fingerprint = snapshot_fingerprint(SnapshotSource::ClaudeCode, item);
        }
    }
    // The rebuild above was the only reader of the cloned family rows.
    drop(reconstructed);

    // Every certified item keeps its own-only scalars by the file birth rule.
    // Loaded telemetry only vetoes them.
    let file_birth_tripwire = match evidence_rows {
        ClaudeEvidenceRows::Whole(veto_api_rows) => {
            claude_context_file_birth::ClaudeTelemetryTripwire::build(
                snapshots,
                MAX_CLAUDE_TRIPWIRE_REQUESTS,
                api_report,
                trace_report,
                veto_api_rows,
            )
        }
        ClaudeEvidenceRows::Streamed(cross) => {
            cross.tripwire(snapshots, MAX_CLAUDE_TRIPWIRE_REQUESTS)
        }
    };

    let multi_file_members = claude_context_file_birth::claude_multi_file_members(snapshots, index);
    let mut context_file_birth = ClaudeContextFileBirthCounts::default();
    #[cfg(test)]
    let mut posture_admissions = BTreeMap::new();
    let cache_births = claude_context_file_birth::cache_content_births(snapshots);
    for (item, cache_birth) in snapshots.iter_mut().zip(cache_births) {
        let root_session_id = claude_snapshot_family_root(item);
        if uncertified_roots.contains(&root_session_id) {
            clear_claude_context_posture(item);
            item.claude_file_birth_verdict = Some(ClaudeFileBirthVerdict::UnknownBirth);
        } else {
            let multi_file = multi_file_members.contains(&item.source_session_id);
            let verdict = claude_context_file_birth::admit_claude_file_birth_posture(
                item,
                &root_session_id,
                &file_birth_tripwire,
                &mut claude_context_file_birth::remembered_tripwire(),
                multi_file,
                &mut context_file_birth,
            );
            #[cfg(test)]
            posture_admissions.insert(
                item.source_session_id.clone(),
                ClaudePostureAdmission::FileBirth(verdict),
            );
            #[cfg(not(test))]
            let _ = verdict;
        }
        // Cache rows ship only for an owned file (an Admitted file birth),
        // and only its own requests: those not more than the copy slack
        // before its content birth. No content birth (no timed own response)
        // ships nothing.
        item.cache_observations = cache_birth
            .filter(|_| item.claude_file_birth_verdict == Some(ClaudeFileBirthVerdict::Admitted))
            .map(|birth| {
                cache_wire(
                    &item.source_session_id,
                    item.cache_requests.iter().filter(|request| {
                        claude_context_file_birth::cache_owns(birth, &request.slot.occurred_at)
                    }),
                    item.cache_requests_complete,
                )
            });
        // Context posture participates in semantic identity. Recompute after
        // the ownership fold.
        item.snapshot_fingerprint = snapshot_fingerprint(SnapshotSource::ClaudeCode, item);
    }
    claude_context_file_birth::alarm_first_resource_withhold(&context_file_birth);
    note_claude_reemission_stop(&context_file_birth, file_birth_tripwire.over_bound_roots());

    let mut disposition = ClaudeUsageAuthorityDisposition {
        request_groupings,
        #[cfg(test)]
        posture_admissions,
        context_file_birth,
        ..ClaudeUsageAuthorityDisposition::default()
    };
    let mut demoting_members_by_root = BTreeMap::<String, BTreeSet<String>>::new();
    for item in snapshots.iter() {
        let root_session_id = claude_snapshot_family_root(item);
        let contractless = item.usage_accounting_contract.as_deref()
            != Some("session_exclusive_reported_usage:v1");
        if contractless {
            disposition
                .context_file_birth
                .record_contractless(item, witness_roots_before.contains(&root_session_id));
        }
        // `e2` (gate on): a request-owned body replaces the family's exclusive
        // reported body as a contract of its own (its literal is installed by
        // `e2::finish_page` after this fold), so it is not a demotion. Account,
        // security and `e2` twin holds are separate and still apply.
        let request_owned = item.claude_money.is_some();
        if witness_roots_before.contains(&root_session_id) && contractless && !request_owned {
            demoting_members_by_root
                .entry(root_session_id)
                .or_default()
                .insert(item.source_session_id.clone());
            if disposition
                .quarantined_source_session_ids
                .insert(item.source_session_id.clone())
            {
                // R7: the demotion hold stays; its sessions upload no
                // scalars this pass whatever their basis. Counted locally.
                disposition
                    .context_file_birth
                    .demotion_quarantined_session_count += 1;
            }
        }
    }

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default();
    for root_session_id in demoting_members_by_root.keys() {
        let correction_failed = index
            .claude_usage_authority_quarantine
            .get(root_session_id)
            .is_some_and(|record| record.proof_correction.is_some());
        let current_witness = index.claude_usage_family_witnesses.get(root_session_id);
        let proven_witness_fingerprint = current_witness
            .map(claude_usage_family_witness_fingerprint)
            .or_else(|| witness_fingerprints_before.get(root_session_id).cloned());
        let Some(proven_witness_fingerprint) = proven_witness_fingerprint.as_ref() else {
            continue;
        };
        // A prior digest cannot bind a new record without its witness. Count
        // it and keep the page's demotion hold; the family stays unproven
        // residue.
        if current_witness.is_none() {
            count_claude_authority_unwitnessed_demotion();
            continue;
        }
        let mut member_source_file_fingerprints = index
            .files
            .iter()
            .filter_map(|(index_key, entry)| {
                let (root, member) = claude_index_path_family_member(Path::new(index_key))?;
                (root == *root_session_id && !entry.source_file_fingerprint.is_empty())
                    .then(|| (member, entry.source_file_fingerprint.clone()))
            })
            .collect::<BTreeMap<_, _>>();
        for item in snapshots
            .iter()
            .filter(|item| claude_snapshot_family_root(item) == *root_session_id)
        {
            // File-backed Claude snapshots always have a source fingerprint.
            // The body fingerprint is a fail-closed fallback for a malformed
            // legacy entry: it deliberately cannot match the next file
            // candidate, which makes that family reparse every pass instead
            // of silently settling a held revision without durable retry
            // state.
            let revision_fingerprint = item
                .source_file_fingerprint
                .as_ref()
                .unwrap_or(&item.snapshot_fingerprint);
            member_source_file_fingerprints
                .insert(item.source_session_id.clone(), revision_fingerprint.clone());
        }
        let existing = index.claude_usage_authority_quarantine.get(root_session_id);
        let same_binding = existing.is_some_and(|existing| {
            claude_usage_authority_deadline_is_bounded(existing)
                && existing.proven_witness_fingerprint == *proven_witness_fingerprint
                && existing.member_source_file_fingerprints == member_source_file_fingerprints
        });
        let retain_existing = existing.is_some_and(|existing| {
            !correction_failed
                && same_binding
                && (existing.disposition
                    == ClaudeUsageAuthorityQuarantineDisposition::UnprovenTerminal
                    && !claude_terminal_predates_e2(existing)
                    || existing.retry_after_unix_seconds > now)
        });
        if !retain_existing {
            let failed_reconstruction_count = existing
                .map(|existing| existing.failed_reconstruction_count.saturating_add(1))
                .unwrap_or_else(initial_claude_usage_authority_failure_count)
                .min(MAX_CLAUDE_USAGE_AUTHORITY_FAILURES);
            let disposition = if failed_reconstruction_count == MAX_CLAUDE_USAGE_AUTHORITY_FAILURES
            {
                ClaudeUsageAuthorityQuarantineDisposition::UnprovenTerminal
            } else {
                ClaudeUsageAuthorityQuarantineDisposition::RetryPending
            };
            let retry_after_unix_seconds = if correction_failed {
                existing
                    .expect("correction record exists")
                    .retry_after_unix_seconds
            } else {
                claude_usage_authority_retry_deadline(root_session_id, proven_witness_fingerprint)
            };
            index.claude_usage_authority_quarantine.insert(
                root_session_id.clone(),
                ClaudeUsageAuthorityQuarantineRecord {
                    proof_correction: None,
                    contract: CLAUDE_USAGE_AUTHORITY_QUARANTINE_CONTRACT_VERSION.to_string(),
                    proven_witness_fingerprint: proven_witness_fingerprint.clone(),
                    member_source_file_fingerprints,
                    failed_reconstruction_count,
                    disposition,
                    retry_after_unix_seconds,
                },
            );
        }
    }

    // `e2` (gate on): a request-owned body settles its family's authority like
    // a reported one (it is not a demotion, above), so a legacy record
    // clears on the family's first `e2` page, never staying red.
    let current_authority_by_root = snapshots.iter().fold(
        BTreeMap::<String, BTreeMap<String, bool>>::new(),
        |mut by_root, item| {
            by_root
                .entry(claude_snapshot_family_root(item))
                .or_default()
                .insert(
                    item.source_session_id.clone(),
                    item.usage_accounting_contract.as_deref()
                        == Some("session_exclusive_reported_usage:v1")
                        || item.claude_money.is_some(),
                );
            by_root
        },
    );
    let resolved_quarantines = index
        .claude_usage_authority_quarantine
        .iter()
        .filter(|(root_session_id, record)| {
            if demoting_members_by_root.contains_key(*root_session_id)
                // Only exact durable body settlement may drain a correction grant.
                || record.proof_correction.is_some()
            {
                return false;
            }
            let Some(witness) = index.claude_usage_family_witnesses.get(*root_session_id) else {
                return false;
            };
            let empty_members = confirmed_empty_claude_family_members(index, root_session_id);
            let current = current_authority_by_root
                .get(*root_session_id)
                .cloned()
                .unwrap_or_default();
            witness.member_request_id_fingerprints.keys().all(|member| {
                empty_members.contains(member) || current.get(member).copied() == Some(true)
            })
        })
        .map(|(root_session_id, _)| root_session_id.clone())
        .collect::<BTreeSet<_>>();
    for root_session_id in resolved_quarantines {
        index
            .claude_usage_authority_quarantine
            .remove(&root_session_id);
    }
    disposition
}

fn confirmed_empty_claude_family_members(
    index: &ScanIndex,
    root_session_id: &str,
) -> BTreeSet<String> {
    index
        .confirmed_empty_files
        .iter()
        .filter_map(|index_key| {
            let (root, member) = claude_index_path_family_member(Path::new(index_key))?;
            (root == root_session_id).then_some(member)
        })
        .collect()
}

pub(in crate::snapshots) fn claude_snapshot_family_root(item: &SnapshotItem) -> String {
    claude_snapshot_family_root_ref(item).to_owned()
}

pub(in crate::snapshots) fn claude_snapshot_family_root_ref(item: &SnapshotItem) -> &str {
    item.attribution_facts
        .iter()
        .find(|fact| fact.field == "root_session_ref")
        .map(|fact| fact.value.as_str())
        .or_else(|| {
            item.source_session_id
                .split_once("_agent-")
                .map(|(root, _)| root)
        })
        .unwrap_or(&item.source_session_id)
}
