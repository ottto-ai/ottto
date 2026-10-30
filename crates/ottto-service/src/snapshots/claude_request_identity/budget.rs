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
    pub(crate) accepted_share_changed: u64,
    pub(crate) accepted_overflow: OverflowCounts,
}
impl Counts {
    pub(super) fn is_empty(&self) -> bool {
        self == &Self::default()
    }
}
#[cfg(not(test))]
static COUNTERS: [AtomicU64; 6] = [const { AtomicU64::new(0) }; 6];
#[cfg(test)]
thread_local! { static COUNTERS: [AtomicU64; 6] = const { [const { AtomicU64::new(0) }; 6] }; }
fn counters<T>(f: impl FnOnce(&[AtomicU64; 6]) -> T) -> T {
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
            counts.accepted_share_changed,
            counts.accepted_overflow.same_as_parent,
            counts.accepted_overflow.differs,
        ]) {
            let _ = counter.fetch_update(Relaxed, Relaxed, |n| Some(n.saturating_add(value)));
        }
    });
}
pub(super) fn take_counts() -> Counts {
    let [retained_buckets, refused_new_buckets, accepted_state_unknown, accepted_share_changed, same_as_parent, differs] =
        counters(|counters| counters.each_ref().map(|counter| counter.swap(0, Relaxed)));
    Counts {
        retained_buckets,
        refused_new_buckets,
        accepted_state_unknown,
        accepted_share_changed,
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
// Receiver arithmetic: add present values, ignoring absent contributions.
// The sum is absent only when no contribution supplied that cost field.
#[derive(Clone, Default)]
struct Aggregate {
    amount: Amounts,
    present: [usize; 5],
    missing: [usize; 5],
}
impl Aggregate {
    fn change(&mut self, amount: &Amounts, remove: bool) -> Option<()> {
        for (total, value) in self.amount.counts.iter_mut().zip(amount.counts) {
            *total = if remove {
                total.checked_sub(value)?
            } else {
                total.checked_add(value)?
            };
        }
        self.amount.observed = true;
        for field in 0..5 {
            let value = amount.wire(field);
            let count = if value.is_some() {
                &mut self.present[field]
            } else {
                &mut self.missing[field]
            };
            *count = if remove {
                count.checked_sub(1)?
            } else {
                count.checked_add(1)?
            };
            let total = self.amount.costs[field].unwrap_or(0);
            let value = value.unwrap_or(0);
            let total = if remove {
                total.checked_sub(value)?
            } else {
                total.checked_add(value)?
            };
            self.amount.costs[field] = (self.present[field] > 0).then_some(total);
            self.amount.poisoned[field] = false;
        }
        Some(())
    }
}

fn bucket_amount(row: &SnapshotModelUsage, group: &RowGroup) -> Amounts {
    let mut amount = group.total.clone();
    amount.observed = true;
    for (field, cost) in row_costs(row).into_iter().enumerate() {
        amount.poisoned[field] = cost.is_none();
    }
    amount
}

fn share_amount(row: &SnapshotModelUsage, amount: &Amounts) -> Amounts {
    let mut amount = amount.clone();
    for (field, cost) in row_costs(row).into_iter().enumerate() {
        if cost.is_none() {
            amount.poisoned[field] = true;
        }
    }
    amount
}

#[derive(Clone)]
struct Selection {
    top: Vec<BTreeMap<Option<AuthorityKey>, Aggregate>>,
    top_metrics: Vec<Metrics>,
    metrics: Metrics,
    keys: BTreeSet<AuthorityKey>,
    refused_rows: u64,
}

// A lower bound, not a standalone fit check. Other buckets can collapse a
// temporary top Parts row to Single or poison its money. Charge only the
// unavoidable top representation: Single for one key, key-only parts with no
// money for multiple keys. Excluding a bucket on this bound cannot exclude a
// collectively fitting set, including the otherwise protected open bucket.
fn intrinsically_fits(
    item: &SnapshotItem,
    grouping: &Grouping,
    index: usize,
    base: usize,
    additional_refusal_rows: usize,
    mandatory_refusals: u64,
) -> bool {
    let minimum = || -> Option<Metrics> {
        let mut total = Metrics::default();
        let mut keys = BTreeSet::new();
        let mut own_additional_refusals = 0usize;
        for row in &item.usage_buckets[index].model_usage {
            let group = grouping.get(
                &item.usage_buckets[index].bucket_start,
                &row_key_from_model_usage(row),
            )?;
            if group.truncated {
                return None;
            }
            let tagged = group
                .by_key
                .iter()
                .filter_map(|(key, amount)| {
                    (amount.counts != [0; 8]).then_some((key.as_ref()?, amount))
                })
                .collect::<Vec<_>>();
            own_additional_refusals += usize::from(!tagged.is_empty() && !group.refused);
            keys.extend(tagged.iter().map(|(key, _)| (*key).clone()));
            let zero_index = keys
                .iter()
                .map(|key: &AuthorityKey| (key.evidence(), 0))
                .collect();
            total.add(&metrics(
                row,
                &row_identity(row, &group.by_key, &zero_index).ok()?,
            )?);
            let identity = match tagged.as_slice() {
                [] => RowIdentity::Untagged,
                [(key, _)] => RowIdentity::Single((*key).clone()),
                _ => RowIdentity::Parts(
                    tagged
                        .into_iter()
                        .map(|(key, amount)| {
                            let mut amount = amount.clone();
                            amount.costs = [None; 5];
                            (Some(key.clone()), amount)
                        })
                        .collect(),
                ),
            };
            total.add(&metrics(row, &identity)?);
        }
        let evidence = keys
            .iter()
            .map(AuthorityKey::evidence)
            .collect::<BTreeSet<_>>();
        let metadata = evidence_bytes(&evidence, mandatory_refusals)?;
        total.bytes += metadata;
        // Either every other not-yet-refused tagged row stays (each adds at
        // least a row evidence_ref), or stripping one adds a refusal. Rows
        // already counted in mandatory_refusals cannot add another refusal.
        // Charge the smaller cost, so a refused older pair cannot make an
        // independently impossible open bucket appear feasible by a few bytes.
        let other_tags =
            (additional_refusal_rows - own_additional_refusals) * ",\"evidence_ref\":0".len();
        let extra_refusal =
            evidence_bytes(&evidence, mandatory_refusals.saturating_add(1))? - metadata;
        total.bytes += other_tags.min(extra_refusal);
        total.bytes += evidence
            .iter()
            .enumerate()
            .map(|(index, key)| {
                total.references.get(key).copied().unwrap_or(0) * (index.to_string().len() - 1)
            })
            .sum::<usize>();
        (keys.len() <= MAX_AUTHORITY_KEYS && evidence.len() <= MAX_EVIDENCE_ENTRIES)
            .then_some(total)
    };
    minimum().is_some_and(|minimum| {
        minimum.parts <= MAX_PARTS_PER_ITEM
            && base
                .checked_add(minimum.bytes)
                .is_some_and(|bytes| bytes <= MAX_ITEM_BYTES)
    })
}

fn change_bucket(
    item: &SnapshotItem,
    grouping: &Grouping,
    selection: &Selection,
    row_index: &BTreeMap<RowKey, usize>,
    index: usize,
    remove: bool,
) -> Option<(Selection, Vec<RowIdentity>)> {
    let bucket = &item.usage_buckets[index];
    let mut next = selection.clone();
    let mut identities = Vec::new();
    let mut changed = BTreeSet::new();
    for row in &bucket.model_usage {
        let key = row_key_from_model_usage(row);
        let group = grouping.get(&bucket.bucket_start, &key)?;
        if group.truncated {
            return None;
        }
        let top_index = row_index[&key];
        let top = &mut next.top[top_index];
        if !remove {
            top.entry(None)
                .or_default()
                .change(&bucket_amount(row, group), true)?;
        }
        for (key, amount) in &group.by_key {
            if amount.counts != [0; 8] {
                top.entry(key.clone())
                    .or_default()
                    .change(&share_amount(row, amount), remove)?;
            }
        }
        if remove {
            top.entry(None)
                .or_default()
                .change(&bucket_amount(row, group), false)?;
        }
        top.retain(|key, aggregate| key.is_none() || aggregate.amount.counts != [0; 8]);
        let zero_index = group
            .by_key
            .keys()
            .flatten()
            .map(|key| (key.evidence(), 0))
            .collect();
        let identity = row_identity(row, &group.by_key, &zero_index).ok()?;
        let measured = metrics(row, &identity)?;
        if remove {
            next.metrics.subtract(&measured);
        } else {
            next.metrics.add(&measured);
        }
        let has_tag = !matches!(identity, RowIdentity::Untagged);
        if has_tag && !group.refused {
            if remove {
                next.refused_rows += 1;
            } else {
                next.refused_rows -= 1;
            }
        }
        identities.push(identity);
        changed.insert(top_index);
    }
    next.keys = next
        .top
        .iter()
        .flat_map(BTreeMap::keys)
        .flatten()
        .cloned()
        .collect();
    let evidence = next
        .keys
        .iter()
        .map(AuthorityKey::evidence)
        .collect::<BTreeSet<_>>();
    if next.keys.len() > MAX_AUTHORITY_KEYS || evidence.len() > MAX_EVIDENCE_ENTRIES {
        return None;
    }
    let zero_index = evidence.iter().map(|key| (key.clone(), 0)).collect();
    for top in changed {
        next.metrics.subtract(&next.top_metrics[top]);
        let by_key = next.top[top]
            .iter()
            .map(|(key, aggregate)| (key.clone(), aggregate.amount.clone()))
            .collect();
        let identity = row_identity(&item.model_usage[top], &by_key, &zero_index).ok()?;
        let measured = metrics(&item.model_usage[top], &identity)?;
        next.metrics.add(&measured);
        next.top_metrics[top] = measured;
    }
    Some((next, identities))
}

fn fits(
    item: &SnapshotItem,
    selection: &Selection,
    base_bytes: usize,
    prior_refusals: u64,
) -> Option<usize> {
    for (row, groups) in item.model_usage.iter().zip(&selection.top) {
        if groups
            .values()
            .filter(|amount| amount.amount.counts != [0; 8])
            .any(|amount| {
                row_costs(row)
                    .iter()
                    .enumerate()
                    .any(|(field, cost)| cost.is_none() && amount.amount.wire(field).is_some())
            })
        {
            return None;
        }
    }
    fits_caps(selection, base_bytes, prior_refusals)
}

fn fits_caps(selection: &Selection, base_bytes: usize, prior_refusals: u64) -> Option<usize> {
    if selection.metrics.parts > MAX_PARTS_PER_ITEM {
        return None;
    }
    let evidence = selection
        .keys
        .iter()
        .map(AuthorityKey::evidence)
        .collect::<BTreeSet<_>>();
    let index_bytes = evidence
        .iter()
        .enumerate()
        .map(|(index, key)| {
            selection.metrics.references.get(key).copied().unwrap_or(0)
                * (index.to_string().len() - 1)
        })
        .sum::<usize>();
    let bytes = base_bytes
        .checked_add(selection.metrics.bytes)?
        .checked_add(index_bytes)?
        .checked_add(evidence_bytes(
            &evidence,
            prior_refusals.saturating_add(selection.refused_rows),
        )?)?;
    (bytes <= MAX_ITEM_BYTES).then_some(bytes)
}

/// Pure allocation over current proof; mutates only the supplied output body.
/// Full-item serialization happens once for the untagged baseline and once
/// for the finished body. Each bucket changes at most MAX_ROWS top rows; no
/// per-bucket serialization traverses the growing session.
pub(super) fn select(
    item: &mut SnapshotItem,
    grouping: &Grouping,
    prior_refusals: u64,
    accepted: Option<&accepted::AcceptedSession>,
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
        metrics: Metrics::default(),
        keys: BTreeSet::new(),
        refused_rows: 0,
    };
    let mut additional_refusal_rows = 0;
    let mut mandatory_refusals = prior_refusals;
    for bucket in &item.usage_buckets {
        for row in &bucket.model_usage {
            let group = grouping.get(&bucket.bucket_start, &row_key_from_model_usage(row))?;
            let has_tag = group
                .by_key
                .iter()
                .any(|(key, amount)| key.is_some() && amount.counts != [0; 8]);
            additional_refusal_rows += usize::from(has_tag && !group.refused);
            mandatory_refusals = mandatory_refusals.saturating_add(u64::from(group.refused));
            selection.refused_rows += u64::from(group.refused || has_tag);
            let top = *row_index.get(&row_key_from_model_usage(row))?;
            selection.top[top]
                .entry(None)
                .or_default()
                .change(&bucket_amount(row, group), false)?;
        }
    }
    strip(item);
    item.provenance.collector = COLLECTOR.to_owned();
    #[cfg(test)]
    {
        item.provenance.collector = cycle_contract(true).to_owned();
    }
    let base_bytes = grouping.item_bytes(item);
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
    // Build accepted proof collectively. Intermediate bytes and parts
    // can fail even when the complete set fits (a top Parts row may collapse
    // to Single). If it overflows, remove in the prescribed drop order; never
    // use standalone fit as a prerequisite for collectively fitting proof.
    let accepted_order = order
        .iter()
        .copied()
        .filter(|&index| is_accepted[index])
        .collect::<Vec<_>>();
    let mut rank = vec![usize::MAX; item.usage_buckets.len()];
    for (priority, &index) in order.iter().enumerate() {
        rank[index] = priority;
    }
    let possible = (0..item.usage_buckets.len())
        .map(|index| {
            tagged[index]
                && intrinsically_fits(
                    item,
                    grouping,
                    index,
                    base_bytes,
                    additional_refusal_rows,
                    mandatory_refusals,
                )
        })
        .collect::<Vec<_>>();
    for &index in &accepted_order {
        if !possible[index] {
            continue;
        }
        let Some((next, rows)) =
            change_bucket(item, grouping, &selection, &row_index, index, false)
        else {
            continue;
        };
        selection = next;
        kept[index] = true;
        bucket_identities[index] = rows;
    }
    for &index in accepted_order.iter().rev() {
        if fits(item, &selection, base_bytes, prior_refusals).is_some() {
            break;
        }
        if !kept[index] {
            continue;
        }
        let (next, _) = change_bucket(item, grouping, &selection, &row_index, index, true)?;
        selection = next;
        kept[index] = false;
        bucket_identities[index].fill(RowIdentity::Untagged);
    }
    let mut row_buckets = vec![Vec::new(); item.model_usage.len()];
    for &index in &order {
        if possible[index] {
            for row in &item.usage_buckets[index].model_usage {
                row_buckets[row_index[&row_key_from_model_usage(row)]].push(index);
            }
        }
    }
    // Re-admit buckets or shared-row completions atomically. A completion can
    // also collapse Parts to Single; cache failed completions until selection
    // changes, so one shared long row is not retried for every bucket.
    let mut failed_completions = BTreeSet::new();
    for &index in &order {
        if kept[index] || !possible[index] {
            continue;
        }
        let mut own_rows = item.usage_buckets[index]
            .model_usage
            .iter()
            .map(|row| row_index[&row_key_from_model_usage(row)])
            .collect::<Vec<_>>();
        own_rows.sort_unstable();
        own_rows.dedup();
        let choices = vec![vec![index]];
        let completion_of = |rows: &[usize]| {
            rows.iter()
                .flat_map(|&row| row_buckets[row].iter().copied())
                .filter(|&member| !kept[member])
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect::<Vec<_>>()
        };
        let completion = (!failed_completions.contains(&own_rows))
            .then(|| completion_of(&own_rows))
            .filter(|members| members.len() > 1);
        let individual_completions = own_rows
            .iter()
            .filter(|&&row| !failed_completions.contains(&vec![row]))
            .map(|&row| completion_of(&[row]))
            .filter(|members| members.len() > 1);
        let mut admitted = None;
        for mut members in choices
            .into_iter()
            .chain(individual_completions)
            .chain(completion)
        {
            members.sort_by_key(|&member| rank[member]);
            let mut trial = selection.clone();
            let mut added = Vec::new();
            let mut valid = true;
            for member in members {
                let Some((next, identities)) =
                    change_bucket(item, grouping, &trial, &row_index, member, false)
                else {
                    valid = false;
                    break;
                };
                trial = next;
                added.push((member, identities));
            }
            if !valid || fits(item, &trial, base_bytes, prior_refusals).is_none() {
                continue;
            }
            admitted = Some((trial, added));
            break;
        }
        if let Some((trial, added)) = admitted {
            selection = trial;
            for (member, identities) in added {
                kept[member] = true;
                bucket_identities[member] = identities;
            }
            failed_completions.clear();
        } else {
            failed_completions.extend(own_rows.iter().map(|&row| vec![row]));
            failed_completions.insert(own_rows);
        }
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
        .map(|(row, aggregates)| {
            let by_key = aggregates
                .iter()
                .map(|(key, aggregate)| (key.clone(), aggregate.amount.clone()))
                .collect();
            row_identity(row, &by_key, &zero_index)
        })
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
        item_bytes: grouping.item_bytes(item),
        ..Default::default()
    };
    if measurement.item_bytes > MAX_ITEM_BYTES {
        return None;
    }
    for (index, keep) in kept.iter().enumerate() {
        match (is_accepted[index], *keep, tagged[index]) {
            (true, true, _)
                if !grouping
                    .accepted_share_changed
                    .contains(&item.usage_buckets[index].bucket_start) =>
            {
                measurement.accepted_retained += 1
            }
            (true, true, _) => {}
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
