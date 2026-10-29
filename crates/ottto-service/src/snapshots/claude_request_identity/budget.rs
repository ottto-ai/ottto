//! Deterministic sticky priority, with linear row encoding and exact size deltas.
use super::*;
use accepted::bucket_key;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub(crate) struct OverflowCounts {
    pub(crate) same_as_parent: u64,
    pub(crate) differs: u64,
}
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub(crate) struct Counts {
    pub(crate) retained_buckets: u64,
    pub(crate) refused_new_buckets: u64,
    pub(crate) accepted_state_unknown: u64,
    pub(crate) accepted_overflow: OverflowCounts,
}
impl Counts {
    pub(super) fn is_empty(&self) -> bool {
        self == &Self::default()
    }
}
#[cfg(not(test))]
static COUNTERS: [AtomicU64; 5] = [const { AtomicU64::new(0) }; 5];
#[cfg(test)]
thread_local! { static COUNTERS: [AtomicU64; 5] = const { [const { AtomicU64::new(0) }; 5] }; }
fn counters<T>(f: impl FnOnce(&[AtomicU64; 5]) -> T) -> T {
    #[cfg(test)]
    {
        COUNTERS.with(f)
    }
    #[cfg(not(test))]
    {
        f(&COUNTERS)
    }
}
pub(super) fn record(counts: &Counts) {
    counters(|counters| {
        for (counter, value) in counters.iter().zip([
            counts.retained_buckets,
            counts.refused_new_buckets,
            counts.accepted_state_unknown,
            counts.accepted_overflow.same_as_parent,
            counts.accepted_overflow.differs,
        ]) {
            let _ = counter.fetch_update(Relaxed, Relaxed, |n| Some(n.saturating_add(value)));
        }
    });
}
pub(super) fn take_counts() -> Counts {
    let [retained_buckets, refused_new_buckets, accepted_state_unknown, same_as_parent, differs] =
        counters(|counters| counters.each_ref().map(|counter| counter.swap(0, Relaxed)));
    Counts {
        retained_buckets,
        refused_new_buckets,
        accepted_state_unknown,
        accepted_overflow: OverflowCounts {
            same_as_parent,
            differs,
        },
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub(crate) struct Measurement {
    pub(crate) tagged_recent_buckets: u64,
    pub(crate) refused_recent_buckets: u64,
    pub(crate) accepted_retained: u64,
    pub(crate) accepted_overflow: OverflowCounts,
    pub(crate) item_bytes: usize,
}
/// The daemon cannot prove the server's parent binding. Unknown = differs,
/// even when a local creator, starting login or display happens to match.
fn same_as_parent(_item: &SnapshotItem, _bucket: usize) -> bool {
    false
}

#[derive(Clone, Default)]
struct Metrics {
    bytes: usize,
    parts: usize,
    references: BTreeMap<EvidenceKey, usize>,
}
impl Metrics {
    fn add(&mut self, other: &Self) {
        self.bytes += other.bytes;
        self.parts += other.parts;
        for (key, count) in &other.references {
            *self.references.entry(key.clone()).or_default() += count;
        }
    }
    fn subtract(&mut self, other: &Self) {
        self.bytes -= other.bytes;
        self.parts -= other.parts;
        for (key, count) in &other.references {
            *self.references.get_mut(key).expect("charged reference") -= count;
        }
        self.references.retain(|_, count| *count > 0);
    }
}
fn metrics(row: &SnapshotModelUsage, identity: &RowIdentity) -> Option<Metrics> {
    let mut references = BTreeMap::new();
    let parts = match identity {
        RowIdentity::Untagged => 0,
        RowIdentity::Single(key) => {
            references.insert(key.evidence(), 1);
            0
        }
        RowIdentity::Parts(parts) => {
            if parts.len() > MAX_PARTS_PER_ROW {
                return None;
            }
            for (key, _) in parts {
                if let Some(key) = key {
                    *references.entry(key.evidence()).or_default() += 1;
                }
            }
            parts.len()
        }
    };
    // Encode each changed row with one-digit references. The only adjustment
    // after evidence pruning/remapping is the exact decimal index width.
    let index = references.keys().map(|key| (key.clone(), 0)).collect();
    let mut encoded = row.clone();
    set_row(&mut encoded, RowIdentity::Untagged, &index);
    let before = serde_json::to_vec(&encoded).ok()?.len();
    set_row(&mut encoded, identity.clone(), &index);
    let after = serde_json::to_vec(&encoded).ok()?.len();
    Some(Metrics {
        bytes: after.checked_sub(before)?,
        parts,
        references,
    })
}
fn evidence_bytes(evidence: &BTreeSet<EvidenceKey>, refusals: u64) -> Option<usize> {
    let mut fields = serde_json::Map::new();
    if !evidence.is_empty() {
        fields.insert(
            "request_evidence".into(),
            serde_json::to_value(
                evidence
                    .iter()
                    .map(|key| SnapshotRequestEvidence {
                        identity_basis: key.basis.into(),
                        provider_workspace_hash: key.org.clone(),
                    })
                    .collect::<Vec<_>>(),
            )
            .ok()?,
        );
    }
    if refusals > 0 {
        fields.insert("request_identity_refusals".into(), json!(refusals));
    }
    // Remove the braces; every nonempty metadata object also adds the comma
    // between its first field and the item's pre-existing fields.
    let comma = usize::from(!fields.is_empty());
    Some(serde_json::to_vec(&fields).ok()?.len() - 2 + comma)
}
fn subtract_amounts(total: &mut Amounts, part: &Amounts) -> Option<()> {
    for (total, value) in total.counts.iter_mut().zip(part.counts) {
        *total = total.checked_sub(value)?;
    }
    for (total, part) in total.costs.iter_mut().zip(part.costs) {
        if let (Some(total), Some(part)) = (total, part) {
            *total = total.checked_sub(part)?;
        }
    }
    Some(())
}

#[derive(Clone)]
struct Selection {
    top: Vec<BTreeMap<Option<AuthorityKey>, Amounts>>,
    top_metrics: Vec<Metrics>,
    residual_missing: Vec<[usize; 5]>,
    metrics: Metrics,
    keys: BTreeSet<AuthorityKey>,
    refused_rows: u64,
}

/// Pure allocation over current proof; mutates only the supplied output body.
/// Full-item serialization happens once for the untagged baseline and once
/// for the finished body. Each bucket changes at most MAX_ROWS top rows; no
/// per-bucket serialization traverses the growing session.
pub(super) fn select(
    item: &mut SnapshotItem,
    grouping: &Grouping,
    prior_refusals: u64,
    accepted: Option<&[i64]>,
) -> Option<(Vec<bool>, Measurement)> {
    let is_accepted = item
        .usage_buckets
        .iter()
        .map(|bucket| {
            bucket_key(&bucket.bucket_start)
                .is_some_and(|key| accepted.is_some_and(|set| set.binary_search(&key).is_ok()))
        })
        .collect::<Vec<_>>();
    let tagged = item
        .usage_buckets
        .iter()
        .map(|bucket| {
            bucket.model_usage.iter().any(|row| {
                grouping
                    .get(&bucket.bucket_start, &row_key_from_model_usage(row))
                    .is_some_and(|group| {
                        group
                            .by_key
                            .iter()
                            .any(|(key, amounts)| key.is_some() && amounts.counts != [0; 8])
                    })
            })
        })
        .collect::<Vec<_>>();
    let mut order = (0..item.usage_buckets.len())
        .filter(|&index| tagged[index])
        .collect::<Vec<_>>();
    let current_hour = bucket_key(&item.collected_at).map(|at| at.div_euclid(3600));
    order.sort_by_key(|&index| {
        let at = bucket_key(&item.usage_buckets[index].bucket_start);
        let open = at.map(|at| at.div_euclid(3600)) == current_hour && current_hour.is_some();
        (
            !is_accepted[index],
            !(open && is_accepted[index]),
            same_as_parent(item, index),
            std::cmp::Reverse(at),
            index,
        )
    });
    let row_index = item
        .model_usage
        .iter()
        .enumerate()
        .map(|(index, row)| (row_key_from_model_usage(row), index))
        .collect::<BTreeMap<_, _>>();
    let mut selection = Selection {
        top: vec![BTreeMap::new(); item.model_usage.len()],
        top_metrics: vec![Metrics::default(); item.model_usage.len()],
        residual_missing: vec![[0; 5]; item.model_usage.len()],
        metrics: Metrics::default(),
        keys: BTreeSet::new(),
        refused_rows: 0,
    };
    for (row, group) in grouping.rows() {
        selection.top[*row_index.get(row)?]
            .entry(None)
            .or_default()
            .merge(&group.total)?;
    }
    for bucket in &item.usage_buckets {
        for row in &bucket.model_usage {
            let group = grouping.get(&bucket.bucket_start, &row_key_from_model_usage(row))?;
            let has_tag = group
                .by_key
                .iter()
                .any(|(key, amount)| key.is_some() && amount.counts != [0; 8]);
            selection.refused_rows += u64::from(group.refused || has_tag);
            let top = row_index[&row_key_from_model_usage(row)];
            for (count, cost) in selection.residual_missing[top]
                .iter_mut()
                .zip(row_costs(row))
            {
                *count += usize::from(cost.is_none());
            }
        }
    }
    strip(item);
    item.provenance.collector = COLLECTOR.to_owned();
    #[cfg(test)]
    {
        item.provenance.collector = cycle_contract(true).to_owned();
    }
    let base_bytes = item_bytes(item);
    if item.model_usage.len() > MAX_ROWS
        || item
            .usage_buckets
            .iter()
            .any(|bucket| bucket.model_usage.len() > MAX_ROWS)
    {
        return None;
    }
    let mut kept = vec![false; item.usage_buckets.len()];
    let mut bucket_identities = item
        .usage_buckets
        .iter()
        .map(|bucket| vec![RowIdentity::Untagged; bucket.model_usage.len()])
        .collect::<Vec<_>>();
    for index in order {
        let bucket = &item.usage_buckets[index];
        let mut next = selection.clone();
        let mut identities = Vec::new();
        let mut changed = BTreeSet::new();
        let mut valid = true;
        for row in &bucket.model_usage {
            let key = row_key_from_model_usage(row);
            let group = grouping.get(&bucket.bucket_start, &key)?;
            if group.truncated {
                valid = false;
                break;
            }
            let top_index = row_index[&key];
            let untagged = group
                .by_key
                .get(&None)
                .is_some_and(|amount| amount.counts != [0; 8]);
            let absent = row_costs(row).map(Option::is_none);
            for (count, absent) in next.residual_missing[top_index].iter_mut().zip(absent) {
                if absent && !untagged {
                    *count -= 1;
                }
            }
            let top = &mut next.top[top_index];
            let residual = top.get_mut(&None)?;
            subtract_amounts(residual, &group.total)?;
            for (poisoned, count) in residual
                .poisoned
                .iter_mut()
                .zip(next.residual_missing[top_index])
            {
                *poisoned = count > 0;
            }
            for (key, amount) in &group.by_key {
                let mut wire_amount = amount.clone();
                // Missing bucket money is missing on every emitted part,
                // even when the request regrouping held a partial amount.
                for (field, absent) in absent.into_iter().enumerate() {
                    if absent {
                        wire_amount.costs[field] = None;
                        wire_amount.poisoned[field] = true;
                    }
                }
                top.entry(key.clone()).or_default().merge(&wire_amount)?;
            }
            next.keys.extend(
                group
                    .by_key
                    .iter()
                    .filter(|(_, amount)| amount.counts != [0; 8])
                    .filter_map(|(key, _)| key.clone()),
            );
            let zero_index = group
                .by_key
                .keys()
                .flatten()
                .map(|key| (key.evidence(), 0))
                .collect();
            let identity = row_identity(row, &group.by_key, &zero_index).ok()?;
            let Some(measured) = metrics(row, &identity) else {
                valid = false;
                break;
            };
            next.metrics.add(&measured);
            let has_tag = !matches!(identity, RowIdentity::Untagged);
            if has_tag && !group.refused {
                next.refused_rows -= 1;
            }
            identities.push(identity);
            changed.insert(row_index[&key]);
        }
        if !valid {
            break;
        }
        let evidence = next
            .keys
            .iter()
            .map(AuthorityKey::evidence)
            .collect::<BTreeSet<_>>();
        if next.keys.len() > MAX_AUTHORITY_KEYS || evidence.len() > MAX_EVIDENCE_ENTRIES {
            break;
        }
        let zero_index = evidence.iter().map(|key| (key.clone(), 0)).collect();
        for top in changed {
            // A parent row with absent money cannot carry a known amount on
            // just one part. Refuse an unrepresentable partial body rather
            // than violate receiver per-authority money reconciliation.
            if next.top[top]
                .values()
                .filter(|amount| amount.counts != [0; 8])
                .any(|amount| {
                    row_costs(&item.model_usage[top])
                        .iter()
                        .enumerate()
                        .any(|(field, cost)| cost.is_none() && amount.wire(field).is_some())
                })
            {
                valid = false;
                break;
            }
            next.metrics.subtract(&next.top_metrics[top]);
            let identity =
                row_identity(&item.model_usage[top], &next.top[top], &zero_index).ok()?;
            let Some(measured) = metrics(&item.model_usage[top], &identity) else {
                valid = false;
                break;
            };
            next.metrics.add(&measured);
            next.top_metrics[top] = measured;
        }
        if !valid || next.metrics.parts > MAX_PARTS_PER_ITEM {
            break;
        }
        let index_bytes = evidence
            .iter()
            .enumerate()
            .map(|(index, key)| {
                next.metrics.references.get(key).copied().unwrap_or(0)
                    * (index.to_string().len() - 1)
            })
            .sum::<usize>();
        let bytes = base_bytes
            .checked_add(next.metrics.bytes)?
            .checked_add(index_bytes)?
            .checked_add(evidence_bytes(
                &evidence,
                prior_refusals.saturating_add(next.refused_rows),
            )?)?;
        if bytes > MAX_ITEM_BYTES {
            break;
        }
        selection = next;
        kept[index] = true;
        bucket_identities[index] = identities;
    }
    if !kept.iter().any(|keep| *keep) {
        return None;
    }
    let evidence = selection
        .keys
        .iter()
        .map(AuthorityKey::evidence)
        .collect::<BTreeSet<_>>();
    let zero_index = evidence.iter().map(|key| (key.clone(), 0)).collect();
    let top = item
        .model_usage
        .iter()
        .zip(&selection.top)
        .map(|(row, by_key)| row_identity(row, by_key, &zero_index))
        .collect::<Result<Vec<_>, _>>()
        .ok()?;
    install(
        item,
        &evidence,
        top,
        bucket_identities,
        prior_refusals.saturating_add(selection.refused_rows),
    );
    let mut measurement = Measurement {
        item_bytes: item_bytes(item),
        ..Default::default()
    };
    if measurement.item_bytes > MAX_ITEM_BYTES {
        return None;
    }
    for (index, keep) in kept.iter().enumerate() {
        match (is_accepted[index], *keep, tagged[index]) {
            (true, true, _) => measurement.accepted_retained += 1,
            (true, false, true) => {
                if same_as_parent(item, index) {
                    measurement.accepted_overflow.same_as_parent += 1;
                } else {
                    measurement.accepted_overflow.differs += 1;
                }
            }
            (false, true, _) => measurement.tagged_recent_buckets += 1,
            (false, false, true) => measurement.refused_recent_buckets += 1,
            _ => {}
        }
    }
    Some((kept, measurement))
}
