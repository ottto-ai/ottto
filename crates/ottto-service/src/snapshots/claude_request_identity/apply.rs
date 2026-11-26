//! Applying contract 5 to one item's grouping: the identity cap, the
//! account display read from the final grouping, shedding display leaves,
//! and untagging rows whose unpriced parts or evidence cannot reconcile.

use super::{
    accepted, budget, count_cause, install, max_parts_per_item, protect_accepted_shares,
    record_refusal_causes, reproduces, row_costs, row_identity, strip, wire_grouping, Amounts,
    AuthorityKey, Grouping, Ineligible, OverCap, RowIdentity, Tagged, COLLECTOR,
    COST_MISSING_COLLAPSE, MAX_AUTHORITY_KEYS, MAX_EVIDENCE_ENTRIES, MAX_ITEM_BYTES,
    MAX_PARTS_PER_ROW, MAX_ROWS, OVER_CAP_STRIP, REFUSAL_CAUSES,
};
#[cfg(test)]
use super::{bucket_row_count, cycle_contract, effective_item_cap, Contribution};
#[cfg(test)]
use crate::snapshots::claude_request_identity::accepted::AcceptedBuckets;
use crate::snapshots::claude_request_identity::budget::Measurement as CapMeasurement;
use crate::snapshots::{
    row_key_from_model_usage, snapshot_fingerprint, RowKey, SnapshotItem, SnapshotModelUsage,
    SnapshotSource,
};
use ottto_protocol::{ActiveSessionAccountUse, ActiveSessionCurrentAccount};
use sha2::Digest;
use std::collections::{BTreeMap, BTreeSet};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

/// Tag `item` from materialized requests: the W0 builder oracle (tests only).
#[cfg(test)]
pub(crate) fn apply(
    item: &mut SnapshotItem,
    contributions: &[Contribution],
) -> Result<Tagged, Ineligible> {
    let mut grouping = Grouping::new(bucket_row_count(item));
    for contribution in contributions {
        grouping.add(
            &contribution.bucket_start,
            &contribution.row_key,
            &contribution.usage,
            contribution.identity.as_ref(),
        );
    }
    apply_grouped(item, grouping)
}

#[cfg(test)]
pub(crate) fn apply_with_accepted_for_test(
    item: &mut SnapshotItem,
    contributions: &[Contribution],
    accepted: &AcceptedBuckets,
) -> Result<Tagged, Ineligible> {
    apply_with_reserved_bytes_for_test(item, contributions, accepted, 0, None)
}

#[cfg(test)]
pub(crate) fn apply_with_reserved_bytes_for_test(
    item: &mut SnapshotItem,
    contributions: &[Contribution],
    accepted: &AcceptedBuckets,
    extra_wire_bytes: usize,
    advertised_item_bytes: Option<u64>,
) -> Result<Tagged, Ineligible> {
    let mut grouping = Grouping::new(bucket_row_count(item));
    grouping.extra_wire_bytes = extra_wire_bytes;
    for c in contributions {
        grouping.add_at(
            &c.bucket_start,
            &c.row_key,
            &c.usage,
            c.identity.as_ref(),
            Some(&c.bucket_start),
        );
    }
    let known = accepted.get(&item.source_session_id);
    grouping.accepted_miss = accepted.miss_cause();
    apply_grouped_with_accepted(
        item,
        grouping,
        known,
        effective_item_cap(advertised_item_bytes),
    )
}

/// `apply` with each request's own transcript time (`None`: auxiliary),
/// withdrawing transcript tags first exactly as `tag_item` does.
#[cfg(test)]
pub(crate) fn apply_timed(
    item: &mut SnapshotItem,
    requests: &[(Contribution, Option<&str>)],
) -> Result<Tagged, Ineligible> {
    let mut grouping = Grouping::new(bucket_row_count(item));
    for (contribution, at) in requests {
        grouping.add_at(
            &contribution.bucket_start,
            &contribution.row_key,
            &contribution.usage,
            contribution.identity.as_ref(),
            *at,
        );
    }
    grouping.withdraw_transcript_tags();
    apply_grouped(item, grouping)
}

/// Tag `item` from its aggregated requests. Returns `Err` when the item must
/// stay on today's path (it is left unchanged). On success the item carries the
/// new collector, the tagged or fallback shape, and a fresh fingerprint.
#[cfg(test)]
pub(crate) fn apply_grouped(
    item: &mut SnapshotItem,
    grouping: Grouping,
) -> Result<Tagged, Ineligible> {
    apply_grouped_with_accepted(item, grouping, None, MAX_ITEM_BYTES)
}

/// The accepted ledger is the share-protection priority.
pub(super) fn apply_grouped_with_accepted(
    item: &mut SnapshotItem,
    mut grouping: Grouping,
    known: Option<&accepted::AcceptedSession>,
    max_item_bytes: usize,
) -> Result<Tagged, Ineligible> {
    let accepted = known;
    if let Some(ineligible) = grouping.failed {
        return Err(ineligible);
    }
    // Every bucket row must be reproduced exactly, and nothing may be left over.
    let mut matched = 0_usize;
    for bucket in &item.usage_buckets {
        for row in &bucket.model_usage {
            let key = row_key_from_model_usage(row);
            let group = grouping
                .get(&bucket.bucket_start, &key)
                .ok_or(Ineligible::RowsNotReproduced)?;
            reproduces(row, &group.total)?;
            matched += 1;
        }
    }
    if matched != grouping.group_count {
        return Err(Ineligible::RowsNotReproduced);
    }
    let keys_over_cap = grouping.keys_over_cap;
    // Top-level rows must equal the per-key sum of their bucket rows.
    let mut top_groups: BTreeMap<&RowKey, Amounts> = BTreeMap::new();
    for (row_key, group) in grouping.rows() {
        top_groups
            .entry(row_key)
            .or_default()
            .merge_wire(&group.total)
            .ok_or(Ineligible::RowsNotReproduced)?;
    }
    if item.model_usage.len() != top_groups.len() {
        return Err(Ineligible::RowsNotReproduced);
    }
    for row in &item.model_usage {
        let key = row_key_from_model_usage(row);
        reproduces(
            row,
            top_groups.get(&key).ok_or(Ineligible::RowsNotReproduced)?,
        )?;
    }

    protect_accepted_shares(&mut grouping, accepted);
    crate::local_resource_diagnostics::change_reason::claude_placement(
        &item.source_session_id,
        accepted.filter(|known| !known.incomplete).map(|_| {
            !grouping.accepted_share_changed.is_empty() || grouping.accepted_rows_vanished > 0
        }),
    );
    let prior_refusals = item.request_identity_refusals;
    let mut refusals = prior_refusals;
    let mut over_cap = BTreeSet::new();
    if keys_over_cap {
        over_cap.insert(OverCap::AuthorityKeys);
    }

    // A row whose app-reported money cannot be split per request stays untagged.
    let mut causes = grouping.refusal_causes;
    for group in grouping.groups.values_mut().flat_map(BTreeMap::values_mut) {
        let unsplittable =
            (0..5).any(|index| group.total.wire(index).is_some()) && group.total.cost_missing;
        if unsplittable && group.by_key.keys().any(Option::is_some) {
            let total = group.total.clone();
            group.by_key = BTreeMap::from([(None, total)]);
            group.refused = true;
            count_cause(&mut causes, COST_MISSING_COLLAPSE);
        }
    }

    let evidence = grouping
        .rows()
        .flat_map(|(_, group)| group.by_key.keys().flatten())
        .map(AuthorityKey::evidence)
        .collect::<BTreeSet<_>>();
    if evidence.len() > MAX_EVIDENCE_ENTRIES {
        over_cap.insert(OverCap::EvidenceEntries);
    }
    let used_keys = grouping
        .rows()
        .flat_map(|(_, group)| group.by_key.keys().flatten())
        .collect::<BTreeSet<_>>();
    if used_keys.len() > MAX_AUTHORITY_KEYS {
        over_cap.insert(OverCap::AuthorityKeys);
    }
    let evidence_index = evidence
        .iter()
        .enumerate()
        .map(|(index, entry)| (entry.clone(), index as u16))
        .collect::<BTreeMap<_, _>>();

    let mut total_parts = 0_usize;
    let mut bucket_identities = Vec::with_capacity(item.usage_buckets.len());
    for bucket in &item.usage_buckets {
        let mut rows = Vec::with_capacity(bucket.model_usage.len());
        for row in &bucket.model_usage {
            let key = row_key_from_model_usage(row);
            let group = grouping
                .get(&bucket.bucket_start, &key)
                .expect("every bucket row was matched");
            if group.refused {
                refusals = refusals.saturating_add(1);
            }
            let identity = row_identity(row, &group.by_key, &evidence_index)?;
            if let RowIdentity::Parts(parts) = &identity {
                if parts.len() > MAX_PARTS_PER_ROW {
                    over_cap.insert(OverCap::PartsPerRow);
                }
                total_parts += parts.len();
            }
            rows.push(identity);
        }
        bucket_identities.push(rows);
    }
    let mut top_identities = Vec::with_capacity(item.model_usage.len());
    for row in &item.model_usage {
        let key = row_key_from_model_usage(row);
        let mut by_key: BTreeMap<Option<AuthorityKey>, Amounts> = BTreeMap::new();
        for (row_key, group) in grouping.rows() {
            if *row_key == key {
                for (authority, amounts) in &group.by_key {
                    let mut wire_amount = amounts.clone();
                    for field in 0..5 {
                        if group.total.wire(field).is_none() {
                            wire_amount.poisoned[field] = true;
                        }
                    }
                    by_key
                        .entry(authority.clone())
                        .or_default()
                        .merge_wire(&wire_amount)
                        .ok_or(Ineligible::RowsNotReproduced)?;
                }
            }
        }
        let identity = row_identity(row, &by_key, &evidence_index)?;
        if let RowIdentity::Parts(parts) = &identity {
            if parts.len() > MAX_PARTS_PER_ROW {
                over_cap.insert(OverCap::PartsPerRow);
            }
            total_parts += parts.len();
        }
        top_identities.push(identity);
    }
    // Every early `Ineligible` exit is behind us. Per tagging attempt: a held
    // or retried body counts again.
    record_refusal_causes(&causes);
    if total_parts > max_parts_per_item(max_item_bytes) {
        over_cap.insert(OverCap::PartsPerItem);
    }
    if item.model_usage.len() > MAX_ROWS
        || item
            .usage_buckets
            .iter()
            .any(|bucket| bucket.model_usage.len() > MAX_ROWS)
    {
        over_cap.insert(OverCap::Rows);
    }

    let lost = item
        .usage_buckets
        .iter()
        .zip(&bucket_identities)
        .map(|(bucket, identities)| {
            bucket
                .model_usage
                .iter()
                .zip(identities)
                .filter(|(row, identity)| {
                    !matches!(identity, RowIdentity::Untagged)
                        || grouping
                            .get(&bucket.bucket_start, &row_key_from_model_usage(row))
                            .is_some_and(|group| group.refused)
                })
                .count() as u64
        })
        .sum::<u64>();
    // Measure the attempted tagged body even when another cap failed. Only
    // byte counts and closed reason labels enter local diagnostics. Recovery
    // below must satisfy the same wire bounds and reconciliation rules.
    install(item, &evidence, top_identities, bucket_identities, refusals);
    let attempted_bytes = grouping.item_bytes(item);
    if max_item_bytes > MAX_ITEM_BYTES && attempted_bytes > max_item_bytes / 2 {
        crate::local_resource_diagnostics::claude_identity_over_cap(
            &BTreeSet::from([OverCap::NearCap]),
            attempted_bytes,
            None,
        );
    }
    let components = (attempted_bytes > max_item_bytes)
        .then(|| shed_display_leaves(item, &grouping, attempted_bytes, max_item_bytes));
    if let Some(bytes) = &components {
        if bytes.after_shed > max_item_bytes {
            over_cap.insert(OverCap::Bytes);
        } else if over_cap.is_empty() {
            crate::local_resource_diagnostics::claude_identity_over_cap(
                &over_cap,
                attempted_bytes,
                Some(bytes),
            );
        }
    }
    if max_item_bytes > MAX_ITEM_BYTES && over_cap.is_empty() {
        let new_shares = grouping
            .groups
            .values()
            .flat_map(BTreeMap::values)
            .filter(|group| group.by_key.keys().any(Option::is_some))
            .map(|group| group.by_key.len())
            .sum::<usize>();
        if item.usage_buckets.len() > accepted::MAX_BUCKETS
            || known.map_or(new_shares > accepted::max_shares(max_item_bytes), |state| {
                state.exceeds_share_bound(item, max_item_bytes, new_shares)
            })
        {
            over_cap.insert(OverCap::PartsPerItem);
            budget::record(&budget::Counts {
                accepted_state_unknown: 1,
                accepted_state_unknown_cause: budget::UnknownCauses::one(
                    accepted::UnknownCause::Incomplete,
                ),
                ..Default::default()
            });
        }
    }
    let unpriced = over_cap
        .is_empty()
        .then(|| untag_unpriced_parts(item, &grouping, accepted))
        .flatten();
    if let Some(unpriced) = unpriced {
        // Stripping only removes tags; the wire bound is still re-checked.
        if grouping.item_bytes(item) <= max_item_bytes {
            let mut counts = cap_counts(item, &grouping, accepted, None);
            unpriced.count(&mut counts);
            budget::record(&counts);
            untag_groups(&mut grouping, &unpriced.keys);
            item.snapshot_fingerprint = snapshot_fingerprint(SnapshotSource::ClaudeCode, item);
            item.claude_account_display = Some(Box::new(account_display(
                &grouping,
                grouping.unowned_request,
            )));
            return Ok(Tagged::Sent {
                refusals: item.request_identity_refusals,
            });
        }
        over_cap.insert(OverCap::Bytes);
    }
    // All cap reasons share one exit after display shedding: bytes, authority
    // keys, parts, rows and evidence entries preserve the same owed custody.
    if (max_item_bytes > MAX_ITEM_BYTES || grouping.hold_over_cap) && !over_cap.is_empty() {
        over_cap.insert(OverCap::IdentityHeld);
        crate::local_resource_diagnostics::claude_identity_over_cap(
            &over_cap,
            attempted_bytes,
            components.as_ref(),
        );
        // Local explanation only: an account-limit hold never uploads, so the
        // app can say why. Other holds (rows, bytes) keep their reason.
        if over_cap.contains(&OverCap::AuthorityKeys)
            || over_cap.contains(&OverCap::EvidenceEntries)
        {
            item.claude_account_withheld_reason =
                Some(crate::snapshots::CLAUDE_ACCOUNT_WITHHELD_TOO_MANY_ACCOUNTS);
        }
        item.snapshot_fingerprint = snapshot_fingerprint(SnapshotSource::ClaudeCode, item);
        return Ok(Tagged::Held);
    }
    crate::local_resource_diagnostics::claude_identity_over_cap(
        &over_cap,
        attempted_bytes,
        components.as_ref(),
    );
    let attempted_counts = cap_counts(item, &grouping, accepted, None);
    let accepted_tagged_attempted = item
        .usage_buckets
        .iter()
        .filter(|bucket| {
            accepted::bucket_key(&bucket.bucket_start)
                .is_some_and(|key| accepted.is_some_and(|known| known.binary_search(&key).is_ok()))
                && bucket.model_usage.iter().any(|row| {
                    row.evidence_ref.is_some()
                        || row.identity_parts.as_ref().is_some_and(|parts| {
                            parts.iter().any(|part| part.evidence_ref.is_some())
                        })
                })
        })
        .count() as u64;
    let selected = (!grouping.upstream_proof_lost)
        .then(|| budget::select(item, &grouping, prior_refusals, accepted, max_item_bytes))
        .flatten()
        .and_then(|(kept, mut measurement)| {
            let unpriced = untag_unpriced_parts(item, &grouping, accepted)?;
            if !unpriced.keys.is_empty() {
                // Kept buckets left without any tag are no longer retained.
                measurement.accepted_retained =
                    cap_counts(item, &grouping, accepted, None).retained_buckets;
            }
            (grouping.item_bytes(item) <= max_item_bytes).then_some((kept, measurement, unpriced))
        });
    if let Some((kept, measurement, unpriced)) = selected {
        let mut counts = cap_counts(item, &grouping, accepted, Some(&measurement));
        unpriced.count(&mut counts);
        budget::record(&counts);
        let mut visible = grouping;
        untag_groups(&mut visible, &unpriced.keys);
        for (bucket, keep) in item.usage_buckets.iter().zip(&kept) {
            if !keep {
                for group in visible
                    .groups
                    .get_mut(&bucket.bucket_start)
                    .into_iter()
                    .flat_map(BTreeMap::values_mut)
                {
                    group.by_key = BTreeMap::from([(None, group.total.clone())]);
                }
            }
        }
        item.snapshot_fingerprint = snapshot_fingerprint(SnapshotSource::ClaudeCode, item);
        // account_display checks the newest request against the filtered rows.
        // Withholding only that request must not anonymize retained history.
        item.claude_account_display =
            Some(Box::new(account_display(&visible, visible.unowned_request)));
        return Ok(Tagged::Sent {
            refusals: item.request_identity_refusals,
        });
    }
    let mut counts = attempted_counts;
    counts.accepted_overflow.differs = accepted_tagged_attempted;
    counts.retained_buckets = 0;
    counts.refused_new_buckets = grouping
        .groups
        .iter()
        .filter(|(bucket, rows)| {
            !accepted::bucket_key(bucket)
                .is_some_and(|key| accepted.is_some_and(|known| known.binary_search(&key).is_ok()))
                && rows
                    .values()
                    .any(|group| group.by_key.keys().any(Option::is_some))
        })
        .count() as u64;
    let refusals = lost.max(1).saturating_add(prior_refusals);
    let mut stripped = [0; REFUSAL_CAUSES.len()];
    count_cause(&mut stripped, OVER_CAP_STRIP);
    record_refusal_causes(&stripped);
    strip(item);
    item.provenance.collector = COLLECTOR.to_string();
    #[cfg(test)]
    {
        item.provenance.collector = cycle_contract(true).to_owned();
    }
    budget::record(&counts);
    item.request_identity_refusals = refusals;
    item.snapshot_fingerprint = snapshot_fingerprint(SnapshotSource::ClaudeCode, item);
    // The rows carry no identity, so neither may the display.
    item.claude_account_display = Some(Box::new(account_display(&grouping, true)));
    Ok(Tagged::Fallback {
        over_cap: over_cap.into_iter().collect(),
        refusals,
    })
}

fn cap_counts(
    item: &SnapshotItem,
    grouping: &Grouping,
    accepted: Option<&accepted::AcceptedSession>,
    measurement: Option<&CapMeasurement>,
) -> budget::Counts {
    let unknown = match accepted {
        None => Some(grouping.accepted_miss),
        Some(known) => known
            .incomplete
            .then_some(accepted::UnknownCause::Incomplete),
    };
    let retained = item
        .usage_buckets
        .iter()
        .filter(|bucket| {
            accepted::bucket_key(&bucket.bucket_start)
                .is_some_and(|key| accepted.is_some_and(|known| known.binary_search(&key).is_ok()))
                && !grouping
                    .accepted_share_changed
                    .contains(&bucket.bucket_start)
                && bucket.model_usage.iter().any(|row| {
                    row.evidence_ref.is_some()
                        || row.identity_parts.as_ref().is_some_and(|parts| {
                            parts.iter().any(|part| part.evidence_ref.is_some())
                        })
                })
        })
        .count() as u64;
    budget::Counts {
        retained_buckets: measurement.map_or(retained, |m| m.accepted_retained),
        refused_new_buckets: measurement.map_or(0, |m| m.refused_recent_buckets),
        accepted_state_unknown: u64::from(unknown.is_some()),
        accepted_share_changed: grouping.accepted_share_changed.len() as u64,
        accepted_overflow: measurement
            .map_or_else(Default::default, |m| m.accepted_overflow.clone()),
        unpriced_part_untagged: 0,
        accepted_row_vanished: grouping.accepted_rows_vanished,
        accepted_state_unknown_cause: unknown.map(budget::UnknownCauses::one).unwrap_or_default(),
        ..Default::default()
    }
}

/// Local display evidence of a tagged item's accounts, read from the same
/// final grouping its wire rows are: usage per (account, workspace,
/// subscription) and the account of its newest own transcript request. Never
/// serialized or uploaded, and never account evidence for anything else.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AccountDisplay {
    pub(crate) current: ActiveSessionCurrentAccount,
    pub(crate) history: Vec<ActiveSessionAccountUse>,
}

pub(crate) const CURRENT_KNOWN: &str = "known";
pub(crate) const CURRENT_UNKNOWN: &str = "unknown";
const LATEST_UNIDENTIFIED: &str = "latest_request_unidentified";
const LATEST_CONFLICTING: &str = "conflicting_latest_requests";
const ORDER_UNAVAILABLE: &str = "request_order_unavailable";
pub(crate) const IDENTITY_WITHHELD: &str = "identity_withheld";

/// (account, workspace, subscription), compared whole.
type AccountTriple = (Option<String>, Option<String>, Option<String>);

fn account_triple(key: Option<&AuthorityKey>, row_key: &RowKey) -> AccountTriple {
    (
        key.and_then(|key| key.login.clone()),
        key.and_then(|key| key.org.clone()),
        row_key.subscription_product.clone(),
    )
}

fn display_time(at: Option<OffsetDateTime>) -> Option<String> {
    at?.to_offset(time::UtcOffset::UTC).format(&Rfc3339).ok()
}

/// `withheld`: the rows carry no identity, so every use is unnamed and the
/// current account is unknown.
fn account_display(grouping: &Grouping, withheld: bool) -> AccountDisplay {
    let mut uses: BTreeMap<AccountTriple, ([u64; 8], Option<OffsetDateTime>)> = BTreeMap::new();
    for (row_key, group) in grouping.rows() {
        let named = (!withheld).then_some(&group.by_key);
        let entries = named
            .into_iter()
            .flatten()
            .map(|(key, amounts)| (key.as_ref(), amounts));
        let unnamed = withheld.then_some((None, &group.total));
        for (key, amounts) in entries.chain(unnamed) {
            if amounts.counts == [0; 8] {
                continue;
            }
            let (counts, last_at) = uses.entry(account_triple(key, row_key)).or_default();
            for (total, value) in counts.iter_mut().zip(amounts.counts) {
                *total = total.saturating_add(value);
            }
            *last_at = (*last_at).max(amounts.last_at);
        }
    }

    let latest = &grouping.latest;
    let current = if withheld {
        Err(IDENTITY_WITHHELD)
    } else if latest.unordered || latest.at.is_none() {
        Err(ORDER_UNAVAILABLE)
    } else if latest.ties_overflowed {
        Err(LATEST_CONFLICTING)
    } else {
        // Ignore empty entries just as history does, including unnamed ones.
        // A removed key follows its row's unnamed entry after an untag.
        let mut triples = latest
            .ties
            .iter()
            .filter_map(|(bucket_start, row_key, key)| {
                let group = grouping.get(bucket_start, row_key)?;
                let (carried, amounts) = match group.by_key.get(key) {
                    Some(amounts) => (key.as_ref(), amounts),
                    None => (None, group.by_key.get(&None)?),
                };
                (amounts.counts != [0; 8]).then(|| account_triple(carried, row_key))
            })
            .collect::<BTreeSet<_>>();
        if triples.is_empty() {
            // Recover only uses at that same instant, never an older account.
            triples.extend(
                uses.iter()
                    .filter(|(_, (_, last_at))| *last_at == latest.at)
                    .map(|(triple, _)| triple.clone()),
            );
        }
        if triples.is_empty() || triples.iter().any(|(account, _, _)| account.is_none()) {
            Err(LATEST_UNIDENTIFIED)
        } else if triples.len() != 1 {
            Err(LATEST_CONFLICTING)
        } else {
            Ok(triples.into_iter().next().expect("one triple"))
        }
    };

    let mut history = uses
        .into_iter()
        .map(|(triple, (counts, last_at))| {
            let current = current.as_ref().is_ok_and(|current| *current == triple);
            let (account, organization, subscription) = triple;
            (
                last_at,
                ActiveSessionAccountUse {
                    account_identifier_hash: account,
                    organization_identifier_hash: organization,
                    subscription_product: subscription,
                    input_tokens: counts[0],
                    output_tokens: counts[1],
                    cache_read_tokens: counts[2],
                    cache_creation_5m_tokens: counts[3],
                    cache_creation_1h_tokens: counts[4],
                    request_count: counts[7],
                    last_used_at: display_time(last_at),
                    current,
                },
            )
        })
        .collect::<Vec<_>>();
    // Newest use first, uses without a provable time last; ties keep triple order.
    history.sort_by(|(left, _), (right, _)| match (left, right) {
        (Some(left), Some(right)) => right.cmp(left),
        (Some(_), None) => std::cmp::Ordering::Less,
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (None, None) => std::cmp::Ordering::Equal,
    });
    let latest_request_at = display_time(latest.at);
    let current = match current {
        Ok((account, organization, subscription)) => ActiveSessionCurrentAccount {
            status: CURRENT_KNOWN.to_string(),
            account_identifier_hash: account,
            organization_identifier_hash: organization,
            subscription_product: subscription,
            latest_request_at,
            unknown_reason: None,
        },
        Err(reason) => ActiveSessionCurrentAccount {
            status: CURRENT_UNKNOWN.to_string(),
            account_identifier_hash: None,
            organization_identifier_hash: None,
            subscription_product: None,
            latest_request_at,
            unknown_reason: Some(reason.to_string()),
        },
    };
    AccountDisplay {
        current,
        history: history.into_iter().map(|(_, entry)| entry).collect(),
    }
}

/// Money identity outranks display data: an over-cap tagged body first
/// drops its counted request positions, then sheds cache observations from
/// the end of the patch, and only then may the selector strip tags. A body
/// that fits without the positions keeps every other byte. Returns the
/// pre-shed component bytes (counts only; the positions count with the
/// curve) and the bytes after shedding.
fn shed_display_leaves(
    item: &mut SnapshotItem,
    grouping: &Grouping,
    attempted: usize,
    max_item_bytes: usize,
) -> crate::local_resource_diagnostics::ClaudeIdentityOverCapBytes {
    crate::snapshots::clear_counted_request_positions(item);
    let mut probe = item.clone();
    probe.context_curve = None;
    let without_curve = grouping.item_bytes(&probe);
    probe.cache_observations = None;
    let without_cache = grouping.item_bytes(&probe);
    strip(&mut probe);
    let untagged = grouping.item_bytes(&probe);
    probe.usage_buckets.clear();
    let rest = grouping.item_bytes(&probe);
    drop(probe);
    let fits = |item: &SnapshotItem| grouping.item_bytes(item) <= max_item_bytes;
    // Twin tool rows merged at emission are display data: fall back to the
    // carrier's own rows before any cache evidence goes, so the merge never
    // holds a body that fit without it.
    if !fits(item) {
        let own = item
            .claude_money
            .as_deref_mut()
            .and_then(|fold| fold.take_own_tools());
        if let Some((rows, truncated)) = own {
            (item.tool_usage, item.tool_usage_truncated) = (rows, truncated);
        }
    }
    while !fits(item) {
        let Some(cache) = item.cache_observations.as_mut() else {
            break;
        };
        if cache.operations.pop().is_none() {
            break;
        }
        // The receiver keeps accepted rows on a partial patch. The omitted
        // count is unknown: an exact one could become null against an ACKed
        // predecessor at upload and grow past the measured bytes.
        cache.coverage = "partial".into();
        cache.omitted_observation_count = None;
    }
    crate::local_resource_diagnostics::ClaudeIdentityOverCapBytes {
        // SHA-256(session id)[:8], the investigation reports' entity digest.
        entity: format!(
            "{:x}",
            sha2::Sha256::digest(item.source_session_id.as_bytes())
        )[..8]
            .to_owned(),
        item: attempted,
        context_curve: attempted.saturating_sub(without_curve),
        cache_observations: without_curve.saturating_sub(without_cache),
        identity: without_cache.saturating_sub(untagged),
        usage_buckets: untagged.saturating_sub(rest),
        rest,
        after_shed: grouping.item_bytes(item),
    }
}

fn row_tagged(row: &SnapshotModelUsage) -> bool {
    row.evidence_ref.is_some()
        || row
            .identity_parts
            .iter()
            .flatten()
            .any(|part| part.evidence_ref.is_some())
}

/// The receiver's identity-part validation checks each cost field. A
/// row carrying it needs it on every part and a row without it allows none.
fn parts_presence_holds(row: &SnapshotModelUsage) -> bool {
    let row_present = row_costs(row).map(Option::is_some);
    row.identity_parts.iter().flatten().all(|part| {
        [
            &part.cost_usd,
            &part.input_cost_usd,
            &part.output_cost_usd,
            &part.cache_read_cost_usd,
            &part.cache_creation_cost_usd,
        ]
        .map(Option::is_some)
            == row_present
    })
}

/// Model rows the final body stripped because a share had no value for a cost
/// field its priced row carries.
#[derive(Default)]
struct UnpricedStrip {
    keys: BTreeSet<RowKey>,
    /// Stripped rows with a frozen tagged share set in an accepted bucket.
    accepted_rows: u64,
}

impl UnpricedStrip {
    fn count(&self, counts: &mut budget::Counts) {
        counts.unpriced_part_untagged = self.keys.len() as u64;
        // Losing accepted tags can move dollars to the starting binding.
        counts.accepted_overflow.differs = counts
            .accepted_overflow
            .differs
            .saturating_add(self.accepted_rows);
    }
}

/// Fail closed on the final derived rows: a share whose contributing buckets
/// all lack a cost its priced parent carries has no exact value, and neither a
/// zero nor a guessed identity may stand in. The whole model row (top and
/// every bucket row) goes out untagged with its unchanged money, one refusal
/// per newly untagged bucket row; orphaned evidence is pruned and remapped.
/// `None` when the stripped body no longer reconciles (never expected).
fn untag_unpriced_parts(
    item: &mut SnapshotItem,
    grouping: &Grouping,
    accepted: Option<&accepted::AcceptedSession>,
) -> Option<UnpricedStrip> {
    if item.evidence_basis == Some("otel_only") {
        return Some(UnpricedStrip::default());
    }
    let keys = item
        .model_usage
        .iter()
        .chain(
            item.usage_buckets
                .iter()
                .flat_map(|bucket| &bucket.model_usage),
        )
        .filter(|row| !parts_presence_holds(row))
        .map(row_key_from_model_usage)
        .collect::<BTreeSet<_>>();
    let mut stripped = UnpricedStrip::default();
    if keys.is_empty() {
        return Some(stripped);
    }
    let mut refusals = 0_u64;
    let mut accepted_keys = BTreeSet::new();
    for bucket in &mut item.usage_buckets {
        let start = accepted::bucket_key(&bucket.bucket_start)
            .filter(|key| accepted.is_some_and(|known| known.binary_search(key).is_ok()));
        for row in &mut bucket.model_usage {
            let key = row_key_from_model_usage(row);
            if !keys.contains(&key) || !row_tagged(row) {
                continue;
            }
            let group = grouping.get(&bucket.bucket_start, &key)?;
            refusals += u64::from(!group.refused);
            if let (Some(start), Some(known)) = (start, accepted) {
                if known.row_shares(start, &key).iter().any(Option::is_some) {
                    accepted_keys.insert(key);
                }
            }
            row.account_identifier_hash = None;
            row.evidence_ref = None;
            row.identity_parts = None;
        }
    }
    for row in &mut item.model_usage {
        if keys.contains(&row_key_from_model_usage(row)) {
            row.account_identifier_hash = None;
            row.evidence_ref = None;
            row.identity_parts = None;
        }
    }
    item.request_identity_refusals = item.request_identity_refusals.saturating_add(refusals);
    prune_evidence(item);
    if !wire_reconciles(item) {
        return None;
    }
    stripped.accepted_rows = accepted_keys.len() as u64;
    stripped.keys = keys;
    Some(stripped)
}

/// Drop evidence no row references and remap references, preserving order.
fn prune_evidence(item: &mut SnapshotItem) {
    let mut used = vec![false; item.request_evidence.len()];
    let rows = || {
        item.model_usage.iter().chain(
            item.usage_buckets
                .iter()
                .flat_map(|bucket| &bucket.model_usage),
        )
    };
    for row in rows() {
        let references = row.evidence_ref.into_iter().chain(
            row.identity_parts
                .iter()
                .flatten()
                .filter_map(|part| part.evidence_ref),
        );
        for reference in references {
            if let Some(slot) = used.get_mut(usize::from(reference)) {
                *slot = true;
            }
        }
    }
    if used.iter().all(|used| *used) {
        return;
    }
    let mut next = 0_u16;
    let positions = used
        .iter()
        .map(|used| {
            let index = next;
            next += u16::from(*used);
            used.then_some(index)
        })
        .collect::<Vec<_>>();
    item.request_evidence = std::mem::take(&mut item.request_evidence)
        .into_iter()
        .zip(&used)
        .filter_map(|(entry, used)| used.then_some(entry))
        .collect();
    let remap = |reference: &mut Option<u16>| {
        *reference = reference.and_then(|old| positions.get(usize::from(old)).copied().flatten());
    };
    for row in item.model_usage.iter_mut().chain(
        item.usage_buckets
            .iter_mut()
            .flat_map(|bucket| bucket.model_usage.iter_mut()),
    ) {
        remap(&mut row.evidence_ref);
        for part in row.identity_parts.iter_mut().flatten() {
            remap(&mut part.evidence_ref);
        }
    }
}

/// Re-run the bucket and top-row reconciliation on the emitted wire alone:
/// money presence on every part, bucket rows reproduced by their shares, and
/// top rows equal to the receiver-arithmetic sum of their bucket rows.
fn wire_reconciles(item: &SnapshotItem) -> bool {
    let rows = || {
        item.model_usage.iter().chain(
            item.usage_buckets
                .iter()
                .flat_map(|bucket| &bucket.model_usage),
        )
    };
    if !rows().all(parts_presence_holds) {
        return false;
    }
    let Some(grouping) = wire_grouping(item).filter(|grouping| grouping.failed.is_none()) else {
        return false;
    };
    let mut top: BTreeMap<RowKey, Amounts> = BTreeMap::new();
    for bucket in &item.usage_buckets {
        for row in &bucket.model_usage {
            let key = row_key_from_model_usage(row);
            let Some(group) = grouping.get(&bucket.bucket_start, &key) else {
                return false;
            };
            if reproduces(row, &group.total).is_err()
                || top
                    .entry(key)
                    .or_default()
                    .merge_wire(&group.total)
                    .is_none()
            {
                return false;
            }
        }
    }
    top.len() == item.model_usage.len()
        && item.model_usage.iter().all(|row| {
            top.get(&row_key_from_model_usage(row))
                .is_some_and(|amounts| reproduces(row, amounts).is_ok())
        })
}

/// Display follows the emitted rows: stripped model rows name no account.
fn untag_groups(grouping: &mut Grouping, keys: &BTreeSet<RowKey>) {
    for (key, group) in grouping.groups.values_mut().flat_map(BTreeMap::iter_mut) {
        if keys.contains(key) {
            group.by_key = BTreeMap::from([(None, group.total.clone())]);
        }
    }
}
