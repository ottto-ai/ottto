//! Claude account evidence and session placement checks.

use std::collections::BTreeSet;

use crate::snapshots::{
    claude_api_cache_creation, claude_api_reasoning_matches, claude_request_identity,
    claude_snapshot_request_id_hashes, SnapshotItem,
    CLAUDE_ACCOUNT_WITHHELD_INCOMPLETE_REQUEST_EVIDENCE, CLAUDE_ACCOUNT_WITHHELD_MULTIPLE_ACCOUNTS,
};

/// Request observations can veto an original Desktop identity, never create it.
/// Only exact transcript-owned request IDs belong to this entity; the sidecar's
/// root session ID also includes children and auxiliary calls.
pub(in crate::snapshots) fn veto_claude_original_identity(
    item: &mut SnapshotItem,
    rows: &[crate::claude_local_otel::ClaudeLocalOtelEvidence],
) -> bool {
    use crate::claude_local_otel::ClaudeIdentityDisposition::{Conflict, Invalid};
    let Some(original) = item.session_account_evidence.as_mut() else {
        return false;
    };
    if original.provider != "anthropic" {
        return false;
    }
    let previous = original.identity_disposition;
    for row in rows
        .iter()
        .filter(|row| item.claude_usage_request_ids.contains(&row.request_id))
    {
        let Some(observed) = &row.request_identity else {
            continue;
        };
        let different = [
            (&original.account_identifier_hash, &observed.account),
            (&original.provider_workspace_hash, &observed.organization),
        ]
        .iter()
        .any(|(expected, attribute)| {
            expected.as_ref().is_some_and(|expected| {
                attribute
                    .resource_hash
                    .iter()
                    .chain(attribute.log_record_hash.iter())
                    .any(|actual| actual != expected)
            })
        });
        if different || observed.disposition == Conflict {
            original.identity_disposition = Some("conflict");
        } else if observed.disposition == Invalid
            && original.identity_disposition != Some("conflict")
        {
            original.identity_disposition = Some("missing");
        }
    }
    previous != original.identity_disposition
}

fn strict_claude_account_hash(
    evidence: &[crate::claude_local_otel::ClaudeLocalOtelEvidence],
) -> Option<&str> {
    if evidence.is_empty()
        || evidence
            .iter()
            .any(|row| !row.account_identity_checked || row.account_identifier_hash.is_none())
    {
        return None;
    }
    let hashes = evidence
        .iter()
        .filter_map(|row| row.account_identifier_hash.as_deref())
        .collect::<BTreeSet<_>>();
    (hashes.len() == 1).then(|| *hashes.first().expect("one account hash"))
}

pub(in crate::snapshots) fn apply_claude_account_evidence(
    item: &mut SnapshotItem,
    evidence: &[crate::claude_local_otel::ClaudeLocalOtelEvidence],
) -> bool {
    let checked_evidence = evidence
        .iter()
        .filter(|row| row.account_identity_checked)
        .collect::<Vec<_>>();
    if checked_evidence.is_empty() {
        return false;
    }
    let evidence_hashes = checked_evidence
        .iter()
        .filter_map(|row| row.account_identifier_hash.as_deref())
        .collect::<BTreeSet<_>>();
    let has_unidentified_request = checked_evidence
        .iter()
        .any(|row| row.account_identifier_hash.is_none());
    let has_legacy_unchecked_request = evidence.iter().any(|row| !row.account_identity_checked);
    let existing_hashes = item
        .model_usage
        .iter()
        .chain(
            item.usage_buckets
                .iter()
                .flat_map(|bucket| bucket.model_usage.iter()),
        )
        .filter_map(|row| row.account_identifier_hash.as_deref())
        .collect::<BTreeSet<_>>();
    let existing_identity_matches =
        !existing_hashes.is_empty() && existing_hashes == evidence_hashes;
    let evidence_covers_snapshot = claude_account_evidence_covers_snapshot(item, &checked_evidence);
    let request_ids_cover_snapshot = strict_claude_account_hash(evidence).is_some()
        && claude_account_evidence_covers_request_ids(item, evidence);
    let target = (!has_unidentified_request
        && evidence_hashes.len() == 1
        && (existing_identity_matches
            || (existing_hashes.is_empty()
                && !has_legacy_unchecked_request
                && (evidence_covers_snapshot || request_ids_cover_snapshot))))
        .then(|| evidence_hashes.first().map(|value| (*value).to_string()))
        .flatten();
    // Explanation only: the account decision above is final and unchanged.
    item.claude_account_withheld_reason = if target.is_some() {
        None
    } else if evidence_hashes.len() > 1 {
        // The sidecar's root session id also carries auxiliary and child
        // requests, so a second account counts only when it appears on this
        // entity's own billed request ids. Reached only for multi-account
        // evidence; stops at the second owned account.
        let mut owned_hash = None;
        checked_evidence
            .iter()
            .filter(|row| item.claude_usage_request_ids.contains(&row.request_id))
            .filter_map(|row| row.account_identifier_hash.as_deref())
            .any(|hash| *owned_hash.get_or_insert(hash) != hash)
            .then_some(CLAUDE_ACCOUNT_WITHHELD_MULTIPLE_ACCOUNTS)
    } else {
        (evidence_hashes.len() == 1
            && !has_unidentified_request
            && !has_legacy_unchecked_request
            && existing_hashes.is_empty())
        .then_some(CLAUDE_ACCOUNT_WITHHELD_INCOMPLETE_REQUEST_EVIDENCE)
    };
    set_claude_account_hash(item, target)
}

pub(in crate::snapshots) fn set_claude_account_hash(
    item: &mut SnapshotItem,
    target: Option<String>,
) -> bool {
    let mut changed = false;
    for row in item.model_usage.iter_mut().chain(
        item.usage_buckets
            .iter_mut()
            .flat_map(|bucket| bucket.model_usage.iter_mut()),
    ) {
        if row.account_identifier_hash != target {
            row.account_identifier_hash = target.clone();
            changed = true;
        }
    }
    changed
}

pub(in crate::snapshots) fn exact_session_account_hash(item: &SnapshotItem) -> Option<String> {
    // A carried or recorded-login account is placement, never a session-wide
    // login proof.
    if item.request_evidence.iter().any(|entry| {
        entry.account_source.is_some()
            || entry.identity_basis == claude_request_identity::TRANSCRIPT_RECORDED_LOGIN
    }) {
        return None;
    }
    uniform_session_account_hash(item)
}

/// Uniform placement only, including carried rows. Never use for creator,
/// retained, sole-login or own-request proof.
fn uniform_session_account_hash(item: &SnapshotItem) -> Option<String> {
    let rows = item.model_usage.iter().chain(
        item.usage_buckets
            .iter()
            .flat_map(|bucket| bucket.model_usage.iter()),
    );
    // Only the new provenance split admits same-login identity parts here.
    // With no carried evidence preserve the old row-only comparison exactly.
    let carried = item
        .request_evidence
        .iter()
        .any(|entry| entry.account_source.is_some());
    let mut accounts = rows.flat_map(|row| {
        let parts = row.identity_parts.as_deref().filter(|_| carried);
        std::iter::once(row.account_identifier_hash.as_deref())
            .take(usize::from(parts.is_none()))
            .chain(
                parts
                    .into_iter()
                    .flatten()
                    .map(|part| part.account_identifier_hash.as_deref()),
            )
    });
    let first = accounts.next()??;
    accounts
        .all(|account| account == Some(first))
        .then(|| first.to_string())
}

pub(in crate::snapshots) fn set_session_account_hash(
    item: &mut SnapshotItem,
    account_hash: Option<&str>,
) {
    for row in item.model_usage.iter_mut().chain(
        item.usage_buckets
            .iter_mut()
            .flat_map(|bucket| bucket.model_usage.iter_mut()),
    ) {
        row.account_identifier_hash = account_hash.map(str::to_string);
    }
}

pub(in crate::snapshots) fn claude_account_evidence_covers_snapshot(
    item: &SnapshotItem,
    evidence: &[&crate::claude_local_otel::ClaudeLocalOtelEvidence],
) -> bool {
    let sum = |value: fn(&crate::claude_local_otel::ClaudeLocalOtelEvidence) -> u64| {
        evidence
            .iter()
            .map(|row| u128::from(value(row)))
            .sum::<u128>()
    };
    let Some(cache_creation) = evidence.iter().try_fold(0_u128, |total, row| {
        let (five_m, one_h, unattributed) = claude_api_cache_creation(row)?;
        total
            .checked_add(u128::from(five_m))?
            .checked_add(u128::from(one_h))?
            .checked_add(u128::from(unattributed))
    }) else {
        return false;
    };
    item.unattributed_total_tokens == 0
        && sum(|row| row.input_tokens) == u128::from(item.input_tokens)
        && sum(|row| row.output_tokens) == u128::from(item.output_tokens)
        && sum(|row| row.cache_read_tokens) == u128::from(item.cache_read_tokens)
        && cache_creation
            == u128::from(item.cache_creation_5m_tokens) + u128::from(item.cache_creation_1h_tokens)
        && claude_api_reasoning_matches(
            sum(|row| row.reasoning_output_tokens),
            item.reasoning_output_tokens,
        )
        && sum(|row| row.request_count) == u128::from(item.request_count)
}

fn claude_account_evidence_covers_request_ids(
    item: &SnapshotItem,
    evidence: &[crate::claude_local_otel::ClaudeLocalOtelEvidence],
) -> bool {
    if item.unattributed_total_tokens != 0 || claude_snapshot_request_id_hashes(item).is_none() {
        return false;
    }
    let mut covered = BTreeSet::new();
    for row in evidence {
        if item.claude_usage_request_ids.contains(&row.request_id)
            && (row.request_count != 1 || !covered.insert(row.request_id.as_str()))
        {
            return false;
        }
    }
    covered.len() == item.claude_usage_request_ids.len()
}
