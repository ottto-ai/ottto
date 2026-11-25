//! Copy decisions for e2: which copied requests a page counts, the stored
//! copy ownership a scan carries forward, the shared proof that a holder
//! owns a copy, the family rule, subagent and same-session twins, and the
//! twin holds that finish reads.

#[cfg(test)]
use super::pipeline_test_observer;
use super::telemetry::place_request_identity;
use super::{
    diag, hold_copies, money_mark, record_counts, CertificateFailure, CopyProof, Counts, FileFold,
    IdentityCaller, Located, PageSpent, PrefixTally, SLACK,
};
use crate::snapshots::claude_history_upgrade::{
    claude_path_twin_groups, path_twins, probe_opened_birth, ClaudeTwinGroups,
};
use crate::snapshots::claude_money_birth_store::{location_key, LocationKey};
use crate::snapshots::claude_request_census::claude_request_hash;
use crate::snapshots::claude_request_identity::{AcceptedBuckets, LentSlot};
use crate::snapshots::upload_context_receipt::receipt_binds_bytes;
use crate::snapshots::{
    claude_index_path_family_member, claude_index_path_member_ref, claude_snapshot_family_root_ref,
    rfc3339_unix_nanos, ClaudeTranscriptUsageOccurrence, ScanIndex, SnapshotItem,
};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::Arc;

/// The request ids of `item` whose response is held as a copy.
pub(super) fn skipped_ids(item: &SnapshotItem) -> impl Iterator<Item = &String> + '_ {
    let fold = item.claude_money.as_deref();
    item.claude_usage_occurrences
        .iter()
        .filter(move |(_, occurrence)| {
            fold.is_some_and(|fold| fold.is_skipped(occurrence.sequence))
        })
        .map(|(id, _)| id)
}

/// Never count twice, never drop. Decide every held copy
/// skip of the page once, before telemetry attach, so a copy that counts
/// after all is matched like any counted request. A request stays removed
/// only if its proof file's CURRENT revision holds that request id: that
/// file's parse on this page, else its census record bound to its index
/// entry's fingerprint. Requests no current revision holds count and are
/// disclosed. Unresolved prefixes count immediately. All the page's cross-session
/// checks share one completing census walk per folder. Runs in both gate modes;
/// dark only counts. Returns the removals to store (gate on only): the caller
/// applies them to the index
/// (`CopyRemovalUpdates::apply`). Removals precede ordinary accepted-share
/// reconciliation. Single-page callers (tests) plan the content-twin holds
/// over `items`.
#[cfg(test)]
pub(crate) fn decide_page_copies(
    items: &mut [SnapshotItem],
    index: &ScanIndex,
    accepted: Option<&AcceptedBuckets>,
) -> CopyRemovalUpdates {
    let content_held = page_content_holds(items, index);
    decide_page_copies_planned(items, index, accepted, &content_held)
}

/// Sessions the page withholds for an absent content twin, decided once over
/// the whole acquisition page: copy decisions and every evidence chunk's
/// finish share it, so a twin read in another chunk is present.
pub(crate) fn page_content_holds(items: &[SnapshotItem], index: &ScanIndex) -> BTreeSet<String> {
    let mut sessions = BTreeMap::<&str, Vec<LocationKey>>::new();
    for item in items {
        if let Some(fold) = item.claude_money.as_deref() {
            let here = sessions.entry(item.source_session_id.as_str()).or_default();
            here.extend(fold.location.map(|located| located.0));
        }
    }
    let sessions = sessions
        .iter()
        .map(|(s, l)| (*s, l.as_slice()))
        .collect::<Vec<_>>();
    content_twin_holds(&sessions, items, index)
}

pub(crate) fn decide_page_copies_planned(
    items: &mut [SnapshotItem],
    index: &ScanIndex,
    _accepted: Option<&AcceptedBuckets>,
    content_held: &BTreeSet<String>,
) -> CopyRemovalUpdates {
    let _spent = PageSpent::start("page.copies");
    let mut holders = Vec::new();
    let mut resolved_holds = Vec::new();
    let mut uncopied = BTreeMap::<&str, usize>::new();
    for item in items.iter() {
        if item.claude_money.as_deref().is_some_and(|fold| {
            !fold.native_copied && fold.proof.is_none() && fold.copy_order().is_some()
        }) {
            *uncopied.entry(&item.source_session_id).or_default() += 1;
        }
    }
    let uncopied = uncopied
        .into_iter()
        .filter(|(_, count)| *count > 1)
        .map(|(session, _)| session.to_owned())
        .collect::<BTreeSet<_>>();
    for at in 0..items.len() {
        let page_twin = uncopied.contains(&items[at].source_session_id);
        let Some(fold) = items[at].claude_money.as_deref_mut() else {
            continue;
        };
        // A page decides afresh (a test re-deciding a larger page included).
        fold.entity.held = false;
        fold.prefix = PrefixTally {
            unproven_idless: fold.prefix.unproven_idless,
            ..PrefixTally::default()
        };
        let twin_pending = std::mem::take(&mut fold.twin_pending);
        let proof = fold.proof.clone();
        if !matches!(proof, Some(CopyProof::Holders { .. })) {
            if let Some(Located(file)) = fold.location {
                if index.claude_copy_removals.pending(file) {
                    resolved_holds.push(file);
                }
            }
        }
        match proof {
            Some(CopyProof::Holders { .. }) => holders.push(at),
            Some(CopyProof::Family(root)) => {
                if twin_pending {
                    decide_subagent_twins(items, at);
                    items[at].claude_money.as_deref_mut().unwrap().proof =
                        Some(CopyProof::Family(root.clone()));
                }
                decide_family(items, at, &root, index);
            }
            None if page_twin && !fold.native_copied && fold.copy_order().is_some() => {
                decide_subagent_twins(items, at)
            }
            None => {}
        }
    }
    let mut updates = if holders.is_empty() {
        CopyRemovalUpdates::default()
    } else {
        decide_holders(items, &holders, index, content_held)
    };
    if !resolved_holds.is_empty() {
        let state = updates
            .state
            .get_or_insert_with(|| index.claude_copy_removals.clone());
        for file in resolved_holds {
            state.clear_hold(file);
        }
    }

    for at in holders {
        finish_holder_identity(&mut items[at]);
    }
    for item in items.iter_mut() {
        tally_unproven_prefix(item, index.claude_copy_removals.metadata_lost());
    }

    updates
}

/// Apply the money decision to the existing native account policy before
/// telemetry attachment. Only the decided skipped marker positions disappear.
fn finish_holder_identity(item: &mut SnapshotItem) {
    let SnapshotItem {
        claude_money: Some(fold),
        claude_org_markers,
        claude_usage_occurrences,
        ..
    } = item
    else {
        return;
    };
    let Some(mut accounts) = fold.accounts.take() else {
        return;
    };
    let first_retained = claude_usage_occurrences
        .values()
        .filter(|o| !fold.is_skipped(o.sequence) && !o.usage.is_zero())
        .map(|o| o.sequence)
        .chain(fold.first_idless)
        .min();
    let mut rebuilt =
        accounts.after_copy_decision(claude_org_markers.as_deref(), &fold.skipped, first_retained);
    // Identity a copied marker lent to a
    // counted request is invalidated where a stored body froze it, so the
    // identity pass learns which (bucket, account) this re-derivation moved.
    if let Some(own) = rebuilt.as_mut() {
        let lent = claude_usage_occurrences
            .values()
            .filter(|o| !fold.is_skipped(o.sequence) && !o.usage.is_zero())
            .filter_map(|o| {
                let lent = accounts.account(o.sequence)?;
                if own.account(o.sequence).as_ref() == Some(&lent) {
                    return None;
                }
                let slot = LentSlot {
                    key: fold.occurrence_key(o)?,
                    origin: None,
                    lent,
                    read: false,
                };
                Some((o.sequence, slot))
            })
            .collect();
        own.copied_marker_lent = lent;
    }
    if let Some(own) = rebuilt.as_ref() {
        // Restored identified prefix grains and unstaged own requests were
        // placed with the original native policy; an own marker accepted only
        // after a copied one can flip here. Marker-dependent grains are still
        // staged, and a request whose account held still returns early.
        for occurrence in claude_usage_occurrences.values() {
            let unstaged_own = !fold.is_skipped(occurrence.sequence)
                && !occurrence.usage.is_zero()
                && accounts
                    .copied_marker_position(occurrence.sequence)
                    .is_none();
            if !unstaged_own && !fold.unproven_copy(occurrence) {
                continue;
            }
            place_request_identity(
                fold,
                occurrence,
                None,
                accounts.account(occurrence.sequence),
                own.account(occurrence.sequence),
                IdentityCaller::UnprovenCopy,
            );
        }
    }
    let changed = rebuilt.is_some();
    if let Some(own) = rebuilt {
        *accounts = own;
    }
    fold.accounts = Some(accounts);
    fold.absorb_prefix_inherited(changed);
}

/// The flagged range of a decided fold: its copied-prefix requests that
/// count because their proof failed. A held fold emits
/// nothing on this page, so it flags nothing.
fn tally_unproven_prefix(item: &mut SnapshotItem, metadata_lost: bool) {
    let SnapshotItem {
        claude_money: Some(fold),
        claude_usage_occurrences,
        ..
    } = item
    else {
        return;
    };
    // Every counted copy was disclosed when its proof failed.
    if fold.entity.held || fold.disclosed == 0 {
        return;
    }
    fold.prefix.unproven_requests = claude_usage_occurrences
        .values()
        .filter(|occurrence| fold.unproven_copy(occurrence))
        .map(|occurrence| occurrence.usage.request_count)
        .sum();
    if metadata_lost {
        fold.prefix.metadata_lost = fold.prefix.unproven_requests + fold.prefix.unproven_idless;
    }
}

/// Removal decisions of one page for the index's stored copy removals.
#[derive(Debug, Default)]
pub(crate) struct CopyRemovalUpdates {
    state: Option<crate::snapshots::claude_request_money::copy_removals::CopyRemovals>,
    added: u64,
}
impl CopyRemovalUpdates {
    /// The replacement carries stored decisions and retry debt in the same
    /// index save.
    pub(crate) fn apply(self, index: &mut ScanIndex) {
        if let Some(state) = self.state {
            index.claude_copy_removals = state;
        }
        diag("copy_removal_stored", self.added);
        record_counts(Counts::removal_store(self.added));
    }
}

/// The committed ownership facts retained with the save baseline. Census clones
/// share their hash buffers; no upload, account-window or usage graph is copied.
#[derive(Default)]
pub(in crate::snapshots) struct CopyOwnership(
    Owners,
    pub(in crate::snapshots) Carriers,
    AcceptedRows,
);
type Owners = BTreeMap<String, CopyOwner>;
struct CopyOwner {
    owned: bool,
    group_owned: bool,
    carrier: bool,
    order: Option<(i128, LocationKey)>,
    census: Option<crate::snapshots::claude_request_census::ClaudeRequestCensusRecord>,
    groups: Vec<(LocationKey, Box<[u64]>)>,
}
pub(in crate::snapshots) type Links = BTreeMap<String, String>;
#[derive(Default)]
pub(in crate::snapshots) struct Carriers {
    pub(in crate::snapshots) links: Links,
    pub(in crate::snapshots) unknown: BTreeSet<String>,
    // Baseline only. These roots still need a definitive loss comparison.
    pending_loss: BTreeSet<String>,
}
impl Carriers {
    pub(in crate::snapshots) fn remember(&mut self, before: &Self) {
        let unknown = !self.unknown.is_empty();
        if !unknown && before.pending_loss.is_empty() {
            return;
        }
        let lost = before
            .pending_loss
            .iter()
            .chain(before.links.values().filter(|_| unknown));
        let carried = self.links.values().collect::<BTreeSet<_>>();
        self.pending_loss
            .extend(lost.filter(|root| !carried.contains(root)).cloned());
    }
}
type HeadReader<'a> = dyn FnMut(&[&str]) -> Carriers + 'a;
impl CopyOwnership {
    pub(in crate::snapshots) fn capture(index: &ScanIndex) -> Self {
        let live = main_files_with(index, |_| Carriers::default(), None);
        Self(
            index
                .files
                .keys()
                .filter_map(|key| {
                    let member = claude_index_path_member_ref(Path::new(key))
                        .filter(|m| m.subagent_stem.is_none())?;
                    Some((
                        key.clone(),
                        CopyOwner {
                            owned: local_owned(index, &[], key, true),
                            group_owned: index_group_owned(index, &live, key) == Some(true),
                            carrier: committed_twin_carrier(index, key),
                            order: committed_holder_order(
                                &index.claude_money_birth_store,
                                member.root,
                                key,
                            ),
                            census: index.claude_request_census.get(key).cloned(),
                            groups: index.claude_copy_removals.get(location_key(key)).to_vec(),
                        },
                    ))
                })
                .collect(),
            Carriers::default(),
            live.accepted,
        )
    }

    pub(in crate::snapshots) fn seed(&mut self, read: &mut HeadReader) {
        let keys = self
            .0
            .iter()
            .filter_map(|(k, o)| o.carrier.then_some(k.as_str()))
            .collect::<Vec<_>>();
        self.1 = read(&keys);
    }
    pub(in crate::snapshots) fn sessions(&self, index: &ScanIndex, keys: &[&str]) -> Carriers {
        let mut sessions = Carriers::default();
        for &key in keys {
            if self.1.unknown.contains(key) {
                sessions.unknown.insert(key.to_owned());
            } else if let Some(session) = self.1.links.get(key).filter(|_| {
                self.0
                    .get(key)
                    .and_then(|old| old.census.as_ref())
                    .zip(index.files.get(key))
                    .is_some_and(|(old, entry)| {
                        old.current_twin_for(&entry.source_file_fingerprint)
                    })
            }) {
                sessions.links.insert(key.to_owned(), session.clone());
            }
        }
        sessions
    }
    /// Publish marks with the facts that invalidate them. Progress may already
    /// be ahead after a crash; only the two committed index images matter here.
    pub(in crate::snapshots) fn reconcile(
        &self,
        next: &mut ScanIndex,
        read: &mut HeadReader,
    ) -> Carriers {
        let before = &self.0;
        let old_carried = self
            .1
            .links
            .values()
            .chain(&self.1.pending_loss)
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        let mut live = main_files_with(next, &mut *read, None);
        record_counts(Counts::one(23, live.sessions.unknown.len() as u64));
        let mut invalid = next
            .claude_copy_removals
            .relied_on
            .iter()
            .filter(|holder| {
                live.get(holder)
                    .is_none_or(|key| index_group_owned(next, &live, key) == Some(false))
            })
            .copied()
            .collect::<BTreeSet<_>>();
        let lost = before.keys().filter(|key| !next.files.contains_key(*key));
        invalid.extend(lost.map(|key| location_key(key)));
        invalid.extend(self.2.iter().filter_map(|(loc, rows)| {
            (!live.contains_key(loc) && Some(rows) != live.accepted.get(loc)).then_some(*loc)
        }));
        let mut keep = next.claude_copy_removals.referenced_hashes();
        keep.retain(|loc, _| invalid.contains(loc));
        for (loc, hashes) in &mut keep {
            hashes.retain(|&hash| {
                holder_proof(next, &live, *loc, hash, HolderUse::Stored) != Some(false)
            });
        }
        let accepted = std::mem::take(&mut live.accepted);
        let sessions = std::mem::take(&mut live.sessions);
        drop(live);
        let mut marks = next.claude_copy_removals.drop_holder_hashes(&keep);
        let invalidated = marks.iter().copied().collect::<BTreeSet<_>>();
        let live = main_files_with(next, |_| sessions, Some(accepted));
        marks.extend(live.iter().filter_map(|(&location, &key)| {
            let member = claude_index_path_member_ref(Path::new(key))?;
            (old_carried.contains(member.root) && live.carrier(member.root) == Some(false))
                .then_some(location)
        }));
        let mut carrier_lost = marks[invalidated.len()..].to_vec();
        // A carrier transfer leaves dependents settled if the main still owns its group.
        carrier_lost.retain(|h| index_group_owned(next, &live, live[h]) == Some(false));
        let keys = before
            .keys()
            .map(String::as_str)
            .chain(live.values().copied())
            .collect::<BTreeSet<_>>();
        let mut folders = BTreeMap::<String, BTreeMap<u64, (i128, LocationKey)>>::new();
        for key in keys {
            let location = location_key(key);
            let old = before.get(key);
            let census = next.claude_request_census.get(key);
            let groups = next.claude_copy_removals.get(location);
            let accepted_delta = accepted_hashes(&self.2, location)
                .symmetric_difference(&accepted_hashes(&live.accepted, location))
                .copied()
                .collect::<BTreeSet<_>>();
            let changed = !accepted_delta.is_empty()
                || old.is_some_and(|o| o.owned) != local_owned(next, &[], key, true)
                || index_group_owned(next, &live, key).is_some_and(|owned| {
                    owned
                        != (old.is_some_and(|o| o.group_owned)
                            || claude_index_path_member_ref(Path::new(key))
                                .is_some_and(|m| old_carried.contains(m.root)))
                })
                || old.map_or(&[][..], |o| o.groups.as_slice()) != groups
                || old
                    .and_then(|o| o.census.as_ref())
                    .map_or(&[][..], |record| record.request_hashes())
                    != census.map_or(&[][..], |record| record.request_hashes());
            if !changed {
                continue;
            }
            let member = claude_index_path_member_ref(Path::new(key)).unwrap();
            let Some(order) =
                committed_holder_order(&next.claude_money_birth_store, member.root, key)
                    .or_else(|| old.and_then(|o| o.order))
            else {
                continue;
            };
            let hashes = old
                .and_then(|o| o.census.as_ref())
                .into_iter()
                .chain(census)
                .flat_map(|r| r.request_hashes().iter().copied())
                .chain(accepted_delta)
                .chain(
                    old.into_iter()
                        .flat_map(|o| o.groups.iter().flat_map(|(_, h)| h.iter().copied())),
                )
                .collect::<BTreeSet<_>>();
            let mut destinations = BTreeSet::from([Path::new(key)
                .parent()
                .unwrap()
                .to_string_lossy()
                .into_owned()]);
            // Rule A reaches the same session's other locations across folders.
            for (other, _) in next.claude_money_birth_store.observations(member.root) {
                if let Some(parent) = live.get(&other).and_then(|key| Path::new(key).parent()) {
                    destinations.insert(parent.to_string_lossy().into_owned());
                }
            }
            for folder in destinations {
                let union = folders.entry(folder).or_default();
                for &hash in &hashes {
                    union
                        .entry(hash)
                        .and_modify(|earliest| *earliest = (*earliest).min(order))
                        .or_insert(order);
                }
            }
        }
        // One complete walk per folder. A changed fact is a reason to compare
        // decisions, not permission to reread every later overlapping file.
        for (folder, changed) in folders {
            let mut candidates = BTreeMap::<LocationKey, Vec<u64>>::new();
            let mut union = BTreeSet::new();
            let prefix = format!("{folder}{}", std::path::MAIN_SEPARATOR);
            // Direct indexed lookups identify the affected copies. Include all
            // their ids in the one census walk: a different id can be the
            // in-folder bridge to a holder session (Rule B).
            for (key, _) in next
                .files
                .range(prefix.clone()..)
                .take_while(|(key, _)| key.starts_with(&prefix))
            {
                if Path::new(key).parent() != Some(Path::new(&folder)) || copy_held(next, key) {
                    continue;
                }
                let Some(member) = claude_index_path_member_ref(Path::new(key))
                    .filter(|member| member.subagent_stem.is_none())
                else {
                    continue;
                };
                let Some(order) =
                    committed_holder_order(&next.claude_money_birth_store, member.root, key)
                else {
                    continue;
                };
                let Some(record) = next.claude_request_census.get(key) else {
                    continue;
                };
                let hits = record
                    .request_hashes()
                    .iter()
                    .copied()
                    .filter(|hash| changed.get(hash).is_some_and(|before| order > *before))
                    .collect::<Vec<_>>();
                if !hits.is_empty() {
                    candidates.insert(order.1, hits);
                    union.extend(record.request_hashes().iter().copied());
                }
            }
            let union = union.into_iter().collect::<Vec<_>>();
            marks.extend(changed_copy_decisions(
                next,
                &live,
                &folder,
                &union,
                candidates,
                &carrier_lost,
            ));
        }
        let lost_copy_marks = invalidated
            .iter()
            .filter(|&&file| next.claude_copy_removals.get(file).is_empty())
            .filter_map(|file| {
                live.get(file).map(|key| {
                    (
                        (*key).to_owned(),
                        next.claude_money_birth_store.money_marks(*file) & !money_mark::COPY,
                    )
                })
            })
            .collect::<Vec<_>>();
        marks.retain(|file| live.get(file).is_some_and(|key| !copy_held(next, key)));
        let mut sessions = live.sessions;
        // Compare a deferred loss again after the unreadable heads recover.
        if !sessions.unknown.is_empty() {
            sessions.remember(&self.1);
        }
        for (key, money_marks) in lost_copy_marks {
            next.claude_money_birth_store
                .set_money_marks(&key, money_marks);
        }
        for file in marks {
            next.claude_copy_removals.mark(file);
        }
        next.claude_copy_removals.relied_on.clear();
        sessions
    }
}

/// Compare the saved decision with current holder proof in one complete folder walk.
fn changed_copy_decisions(
    index: &ScanIndex,
    live: &Live<'_>,
    folder: &str,
    union: &[u64],
    candidates: BTreeMap<LocationKey, Vec<u64>>,
    carrier_lost: &[LocationKey],
) -> Vec<LocationKey> {
    let mut marks = Vec::new();
    let mut holders = BTreeMap::<u64, (i128, LocationKey)>::new();
    let mut holder_sessions = BTreeMap::<&str, BTreeSet<u64>>::new();
    let _ = index.claude_request_census.main_transcript_holders(
        Some(folder),
        union,
        None,
        |key, root, record, hits| {
            let Some(order) = committed_holder_order(&index.claude_money_birth_store, root, key)
            else {
                return;
            };
            let owned = local_owned(index, &[], key, true);
            for &hash in hits {
                let removed = saved_removal_proof(index, live, key, hash);
                let proven = holder_proof(
                    index,
                    live,
                    location_key(key),
                    hash,
                    HolderUse::New(Some(owned)),
                );
                if proven == Some(false) || !record.proves_scan() || removed == Some(true) {
                    holder_sessions.entry(root).or_default().insert(hash);
                }
                if proven == Some(true) {
                    holders
                        .entry(hash)
                        .and_modify(|earliest| *earliest = (*earliest).min(order))
                        .or_insert(order);
                }
            }
        },
    );
    for (location, hashes) in candidates {
        let Some(&key) = live.get(&location) else {
            continue;
        };
        let member = claude_index_path_member_ref(Path::new(key)).unwrap();
        let order =
            committed_holder_order(&index.claude_money_birth_store, member.root, key).unwrap();
        let groups = index.claude_copy_removals.get(location);
        let record = index.claude_request_census.get(key).unwrap();
        let sessions = std::iter::once(member.root)
            .chain(
                holder_sessions
                    .iter()
                    .filter(|(_, bridge)| bridge.iter().any(|hash| record.holds_hash(*hash)))
                    .map(|(&session, _)| session),
            )
            .collect::<BTreeSet<_>>();
        let copy = index.claude_money_birth_store.money_marks(location)
            & (money_mark::COPY | money_mark::DISCLOSED)
            != 0;
        // A path twin's own location can count a request without any mark of its own.
        let twin = index
            .claude_money_birth_store
            .observations(member.root)
            .any(|(other, _)| other != location && live.contains_key(&other));
        let locations = live;
        let contributions = &index.upload_context_proof.request_contributions;
        let bodies = index.file_snapshot_fingerprints.get(key);
        let rows = contributions
            .values()
            .filter(|slot| bodies.is_some_and(|b| b.contains(&slot.fingerprint)))
            .flat_map(|slot| slot.rows.iter())
            .collect::<Vec<_>>();
        if hashes.into_iter().any(|hash| {
            let removed = groups
                .iter()
                .any(|(_, hashes)| hashes.binary_search(&hash).is_ok());
            let keep = saved_removal_proof(index, live, key, hash) != Some(false)
                && !groups.iter().any(|(h, _)| carrier_lost.contains(h));
            let twin_counted = twin && live.accepts(location, hash);
            // Skip a family duplicate already removed inside this accepted sum.
            let covered = holders
                .get(&hash)
                .copied()
                .into_iter()
                .chain(earliest_accepted_holder(
                    index,
                    live,
                    hash,
                    order,
                    sessions.iter().flat_map(move |&session| {
                        index
                            .claude_money_birth_store
                            .observations(session)
                            .filter_map(move |(location, _)| {
                                let &key = locations.get(&location)?;
                                Some((key, session, local_owned(index, &[], key, true)))
                            })
                    }),
                ))
                .min()
                .is_some_and(|holder| {
                    holder < order
                        && (twin_counted
                            || !rows
                                .iter()
                                .any(|(loc, h)| *loc == holder.1 && h.binary_search(&hash).is_ok()))
                });
            // An invalid old holder must be replaced in the saved
            // groups even if another holder proves the same removal.
            (removed && !keep) || (!removed && (copy || twin_counted) && covered)
        }) {
            marks.push(location);
        }
    }
    marks
}

/// Rule 5 selects only settled DISCLOSED mains whose counted hashes now have
/// positive earlier-holder proof. Each selected location owes one ordinary
/// correction; holders never become seeds and no read revision is changed.
pub(super) fn mark_settled_counted_copies(index: &mut ScanIndex) {
    let live = indexed_main_files(index);
    let mut folders = BTreeMap::<_, (BTreeMap<_, _>, BTreeSet<_>)>::new();
    for (&location, &key) in live.iter() {
        if index.claude_money_birth_store.money_marks(location) & money_mark::DISCLOSED == 0
            || !index.file_has_accepted_body_unheld(key)
            || copy_held(index, key)
            || index.claude_family_listed(key)
        {
            continue;
        }
        let member = claude_index_path_member_ref(Path::new(key)).unwrap();
        if committed_holder_order(&index.claude_money_birth_store, member.root, key).is_none() {
            continue;
        }
        let Some(record) = index.claude_request_census.get(key) else {
            continue;
        };
        let groups = index.claude_copy_removals.get(location);
        let counted = record
            .request_hashes()
            .iter()
            .copied()
            .filter(|hash| {
                !groups
                    .iter()
                    .any(|(_, removed)| removed.binary_search(hash).is_ok())
            })
            .collect::<Vec<_>>();
        if !counted.is_empty() {
            let (candidates, union) = folders.entry(Path::new(key).parent().unwrap()).or_default();
            candidates.insert(location, counted);
            union.extend(record.request_hashes().iter().copied());
        }
    }
    let mut marks = Vec::new();
    for (folder, (candidates, union)) in folders {
        marks.extend(changed_copy_decisions(
            index,
            &live,
            &folder.to_string_lossy(),
            &union.into_iter().collect::<Vec<_>>(),
            candidates,
            &[],
        ));
    }
    drop(live);
    for location in marks {
        index.claude_copy_removals.mark(location);
    }
}

#[cfg(test)]
pub(in crate::snapshots) fn reconcile_copy_ownership(previous: &ScanIndex, next: &mut ScanIndex) {
    CopyOwnership::capture(previous).reconcile(next, &mut |_| Carriers::default());
}

fn committed_holder_order(
    store: &crate::snapshots::claude_money_birth_store::BirthStore,
    root: &str,
    key: &str,
) -> Option<(i128, LocationKey)> {
    store
        .effective_cutoff(root, key)
        .map(|birth| (birth, location_key(key)))
}

/// An unknown carrier keeps the group's ownership undecided.
fn index_group_owned(index: &ScanIndex, live: &Live<'_>, key: &str) -> Option<bool> {
    index
        .claude_family_listed(key)
        .then_some(true)
        .or_else(|| local_owned(index, &[], key, true).then_some(true))
        // A summed session body can be carried by another physical location.
        // Its earlier counting location still owns the stored removal.
        .or_else(|| {
            let Some(member) = claude_index_path_member_ref(Path::new(key)) else {
                return Some(false);
            };
            if index
                .claude_money_birth_store
                .observations(member.root)
                .any(|(location, _)| {
                    live.get(&location)
                        .is_some_and(|other| local_owned(index, &[], other, true))
                })
            {
                return Some(true);
            }
            live.carrier(member.root)
        })
}

fn saved_removal_proof(index: &ScanIndex, live: &Live<'_>, key: &str, hash: u64) -> Option<bool> {
    any_proof(
        index
            .claude_copy_removals
            .get(location_key(key))
            .iter()
            .filter(|(_, hashes)| hashes.binary_search(&hash).is_ok())
            .map(|(holder, _)| holder_proof(index, live, *holder, hash, HolderUse::Stored)),
    )
}

#[cfg(test)]
pub(super) fn saved_removal_applies(
    index: &ScanIndex,
    live: &Live<'_>,
    key: &str,
    hash: u64,
) -> bool {
    saved_removal_proof(index, live, key, hash) == Some(true)
}

/// Any positive proof settles the question, otherwise an unknown proof keeps it open.
fn any_proof(proofs: impl Iterator<Item = Option<bool>>) -> Option<bool> {
    let mut answer = Some(false);
    for proof in proofs {
        match proof {
            Some(true) => return Some(true),
            Some(false) => {}
            None => answer = None,
        }
    }
    answer
}

type AcceptedRows = BTreeMap<LocationKey, Vec<Arc<[u64]>>>;
fn accepted_rows(index: &ScanIndex) -> AcceptedRows {
    let mut view = AcceptedRows::new();
    for slot in index.upload_context_proof.request_contributions.values() {
        for (loc, hashes) in &slot.rows {
            view.entry(*loc).or_default().push(Arc::clone(hashes));
        }
    }
    view
}
fn accepted_hashes(view: &AcceptedRows, loc: LocationKey) -> BTreeSet<u64> {
    view.get(&loc)
        .into_iter()
        .flatten()
        .flat_map(|h| h.iter().copied())
        .collect()
}
enum HolderUse {
    New(Option<bool>),
    Stored,
}
fn holder_proof(
    index: &ScanIndex,
    live: &Live<'_>,
    loc: LocationKey,
    hash: u64,
    usage: HolderUse,
) -> Option<bool> {
    if live.accepts(loc, hash) {
        return Some(true);
    }
    let Some(&key) = live.get(&loc) else {
        return Some(false);
    };
    match usage {
        HolderUse::Stored => index_group_owned(index, live, key)
            .map(|owned| owned && stored_holder_answer(index, Some(key), hash) != Some(false)),
        HolderUse::New(local) => {
            if local == Some(false)
                || !index
                    .claude_request_census
                    .get(key)
                    .is_some_and(|r| r.proves_scan() && r.holds_hash(hash))
            {
                return Some(false);
            }
            match saved_removal_proof(index, live, key, hash) {
                Some(true) => Some(false),
                Some(false) => local,
                None => None,
            }
        }
    }
}

pub(super) struct Live<'a> {
    files: BTreeMap<LocationKey, &'a str>,
    accepted: AcceptedRows,
    carried: BTreeSet<String>,
    sessions: Carriers,
}
impl Live<'_> {
    fn carrier(&self, root: &str) -> Option<bool> {
        if self.carried.contains(root) {
            Some(true)
        } else {
            // An unreadable head does not identify its session. The path name
            // can differ from the session carried by the head.
            self.sessions.unknown.is_empty().then_some(false)
        }
    }

    fn accepts(&self, loc: LocationKey, hash: u64) -> bool {
        self.accepted
            .get(&loc)
            .is_some_and(|rows| rows.iter().any(|h| h.binary_search(&hash).is_ok()))
    }
}
impl<'a> std::ops::Deref for Live<'a> {
    type Target = BTreeMap<LocationKey, &'a str>;
    fn deref(&self) -> &Self::Target {
        &self.files
    }
}
fn main_files_with(
    index: &ScanIndex,
    read: impl FnOnce(&[&str]) -> Carriers,
    accepted: Option<AcceptedRows>,
) -> Live<'_> {
    let files = index
        .files
        .keys()
        .filter(|key| {
            claude_index_path_member_ref(Path::new(key.as_str()))
                .is_some_and(|member| member.subagent_stem.is_none())
        })
        .map(|key| (location_key(key), key.as_str()))
        .collect::<BTreeMap<_, _>>();
    let keys = files
        .values()
        .copied()
        .filter(|key| twin_carrier(index, key))
        .collect::<Vec<_>>();
    let sessions = read(&keys);
    Live {
        accepted: accepted.unwrap_or_else(|| accepted_rows(index)),
        files,
        carried: sessions.links.values().cloned().collect(),
        sessions,
    }
}
pub(super) fn indexed_main_files(index: &ScanIndex) -> Live<'_> {
    main_files_with(
        index,
        |keys| {
            if keys.is_empty() {
                return Carriers::default();
            }
            crate::snapshots::state_v2::carried_sessions(index, keys).unwrap_or_else(|| Carriers {
                unknown: keys.iter().map(|&key| key.to_owned()).collect(),
                ..Default::default()
            })
        },
        None,
    )
}

/// Earliest positive holder before this file. Rule A supplies session-level
/// Local proof; exact accepted contributions are always checked per hash.
fn earliest_accepted_holder<'a>(
    index: &ScanIndex,
    live: &Live<'_>,
    hash: u64,
    before: (i128, LocationKey),
    candidates: impl Iterator<Item = (&'a str, &'a str, bool)>,
) -> Option<(i128, LocationKey)> {
    candidates
        .filter_map(|(key, root, local)| {
            let (holder, proven) = census_holder(index, live, key, root, hash, Some(local))?;
            (holder < before && proven == Some(true)).then_some(holder)
        })
        .min()
}

/// Positive census discovery and order, with per-hash accepted contribution
/// proof or the caller's Local proof.
fn census_holder(
    index: &ScanIndex,
    live: &Live<'_>,
    key: &str,
    root: &str,
    hash: u64,
    local: Option<bool>,
) -> Option<((i128, LocationKey), Option<bool>)> {
    let record = index.claude_request_census.get(key)?;
    if !record.proves_scan() || !record.holds_hash(hash) {
        return None;
    }
    let holder = holder_order(&index.claude_money_birth_store, root, key)?;
    Some((
        holder,
        holder_proof(index, live, holder.1, hash, HolderUse::New(local)),
    ))
}

#[cfg(test)]
pub(crate) fn copied_file_holders_for_test<'a>(
    index: &ScanIndex,
    keys: impl Iterator<Item = &'a str>,
) -> BTreeMap<String, String> {
    copied_file_holders(index, keys)
}

/// One census-only walk for a fixed seed set. Each seed pulls at most its
/// earliest accepted main holder; returned holders never become new seeds.
/// All census hashes participate, so an own turn cannot hide a copied prefix.
pub(in crate::snapshots) fn copied_file_holders<'a>(
    index: &ScanIndex,
    keys: impl Iterator<Item = &'a str>,
) -> BTreeMap<String, String> {
    let mut wanted = BTreeMap::<u64, Vec<(&str, (i128, LocationKey))>>::new();
    for key in keys {
        let Some(member) =
            claude_index_path_member_ref(Path::new(key)).filter(|m| m.subagent_stem.is_none())
        else {
            continue;
        };
        let Some(order) = holder_order(&index.claude_money_birth_store, member.root, key) else {
            continue;
        };
        let Some(record) = index.claude_request_census.get(key) else {
            continue;
        };
        for &hash in record.request_hashes() {
            wanted.entry(hash).or_default().push((key, order));
        }
    }
    let union = wanted.keys().copied().collect::<Vec<_>>();
    let live = indexed_main_files(index);
    let mut found = BTreeMap::<String, ((i128, LocationKey), String)>::new();
    let _ = index.claude_request_census.main_transcript_holders(
        None,
        &union,
        None,
        |key, root, _, hits| {
            let accepted = local_owned(index, &[], key, true);
            for &hash in hits {
                for &(copy, order) in &wanted[&hash] {
                    if let Some(holder) = earliest_accepted_holder(
                        index,
                        &live,
                        hash,
                        order,
                        std::iter::once((key, root, accepted)),
                    ) {
                        let entry = found
                            .entry(copy.to_owned())
                            .or_insert_with(|| (holder, key.to_owned()));
                        if holder < entry.0 {
                            *entry = (holder, key.to_owned());
                        }
                    }
                }
            }
        },
    );
    found
        .into_iter()
        .map(|(copy, (_, holder))| (copy, holder))
        .collect()
}

/// A stored removal of `hash` under `holder` (index key): `None` when the
/// holder is no longer indexed or its census can no longer
/// answer (retired, over budget or no record), so the stored decision
/// stands; else whether its record holds the hash (a record that lacks it
/// disproves the stored ownership).
fn stored_holder_answer(index: &ScanIndex, holder: Option<&str>, hash: u64) -> Option<bool> {
    index
        .claude_request_census
        .get(holder?)
        .filter(|record| record.proves_scan())
        .and_then(|record| {
            if record.holds_hash(hash) {
                Some(true)
            } else if record.is_lossy() {
                None
            }
            // Absence is unknown.
            else {
                Some(false)
            }
        })
}

/// A file's request ids at its current revision: its parse on this page
/// (current by construction), else its census record while that still
/// proves the file.
enum Witness<'a> {
    Page(&'a BTreeSet<String>),
    Census(&'a crate::snapshots::claude_request_census::ClaudeRequestCensusRecord),
}
impl Witness<'_> {
    fn holds(&self, request_id: &str) -> bool {
        match self {
            Self::Page(ids) => ids.contains(request_id),
            Self::Census(record) => record.holds_hash(claude_request_hash(request_id)),
        }
    }
}

/// `key`'s current witness: `session`'s parse at that path on this page,
/// else its census record. None: the file is not read at its current
/// revision (or has no scan state).
fn current_witness<'a>(
    items: &'a [SnapshotItem],
    session: &str,
    key: &str,
    index: &'a ScanIndex,
) -> Option<Witness<'a>> {
    let location = Some(Located(location_key(key)));
    let on_page = items.iter().find(|item| {
        item.source_session_id == session
            && item
                .claude_money
                .as_deref()
                .is_some_and(|fold| fold.location == location)
    });
    match on_page {
        Some(item) => Some(Witness::Page(&item.claude_usage_request_ids)),
        None => index
            .claude_request_census
            .get(key)
            .filter(|record| scan_evidence(index, key, record) == Evidence::Current)
            .map(Witness::Census),
    }
}

/// Activation boundary: 2026-11-05T00:00:00Z, the ship date (UTC ns).
pub(super) const SUBAGENT_TWIN_FROM: i128 = 1_793_836_800_000_000_000;

/// Each shared request before the later home's first own turn counts once,
/// at the earliest home that holds it (`copy_order`: effective birth, then
/// `LocationKey` for equal births). One pass over a later home's responses:
/// a held native skip stays removed, an unheld one counts again, and a held
/// response it would count (a copy within the slack before its birth) is
/// dropped. A zero-usage or untimed response is never dropped.
/// Main path twins with no copies at parse time instead use usage dominance,
/// with equal native accounts and copy-order ties, drop-only and without a
/// birth/cutoff gate.
fn decide_subagent_twins(items: &mut [SnapshotItem], at: usize) {
    let item = &items[at];
    let Some(fold) = item.claude_money.as_deref() else {
        return;
    };
    let uncopied = !fold.native_copied && fold.proof.is_none();
    let group = items
        .iter()
        .enumerate()
        .filter(|(_, other)| other.source_session_id == item.source_session_id)
        .filter(|(_, other)| {
            !uncopied
                || other.claude_money.as_deref().is_some_and(|other| {
                    !other.native_copied && other.proof.is_none() && other.copy_order().is_some()
                })
        })
        .map(|(other, _)| other)
        .collect::<Vec<_>>();
    let earlier = fold
        .copy_order()
        .map(|order| {
            earlier_holders(items, &group, &order, |other| {
                items[other].claude_money.as_deref()?.copy_order()
            })
        })
        .unwrap_or_default();
    let first_own = first_own_turn(item, 0, &earlier).map(|o| o.sequence);
    let (mut kept, mut uncovered, mut drops) = (0, Vec::new(), Vec::new());
    let mut overcount = 0;
    for (id, occurrence) in &item.claude_usage_occurrences {
        let beaten = if uncopied {
            let peers = group
                .iter()
                .filter_map(|other| {
                    let peer = &items[*other];
                    Some((
                        *other,
                        peer.claude_money.as_deref()?,
                        peer.claude_usage_occurrences.get(id)?,
                    ))
                })
                .collect::<Vec<_>>();
            let account = |fold: &FileFold, sequence| {
                fold.accounts
                    .as_ref()
                    .and_then(|accounts| accounts.account(sequence))
            };
            let conflict = peers.iter().any(|(_, a, x)| {
                peers.iter().any(|(_, b, y)| {
                    account(a, x.sequence) != account(b, y.sequence)
                        || (!x.usage.is_monotonic_after(&y.usage)
                            && !y.usage.is_monotonic_after(&x.usage))
                })
            });
            // Disclose once per request id, on its first page fold. A
            // disagreement anywhere in the group prevents every drop of it.
            if conflict && peers.first().is_some_and(|(other, _, _)| *other == at) {
                overcount += 1;
            }
            !conflict
                && peers.iter().any(|(other, keeper, candidate)| {
                    *other != at
                        && !keeper.is_skipped(candidate.sequence)
                        && !candidate.usage.is_zero()
                        && !keeper.is_ambiguous(id)
                        && candidate.usage.is_monotonic_after(&occurrence.usage)
                        && (candidate.usage != occurrence.usage
                            || keeper.copy_order() < fold.copy_order())
                })
        } else {
            false
        };
        let held = || earlier.iter().any(|ids| ids.contains(id));
        let before_own = first_own.is_none_or(|own| occurrence.sequence < own);
        if fold.is_skipped(occurrence.sequence) {
            if uncopied {
                continue;
            }
            let eligible = before_own
                || occurrence
                    .timestamp
                    .as_deref()
                    .and_then(rfc3339_unix_nanos)
                    .expect("native skips have usable provider timestamps")
                    >= SUBAGENT_TWIN_FROM;
            if eligible && held() {
                kept += 1;
            } else {
                uncovered.push(id.clone());
            }
        } else if !occurrence.usage.is_zero()
            && (if uncopied { beaten } else { held() && before_own })
            && !fold.is_ambiguous(id)
            // An unknown time is never newly dropped: it stays counted.
            && occurrence
                .timestamp
                .as_deref()
                .and_then(rfc3339_unix_nanos)
                .is_some()
        {
            drops.push(id.clone());
        }
    }
    if !uncopied {
        restore_uncovered(&mut items[at], &uncovered);
    }
    if let SnapshotItem {
        claude_money: Some(fold),
        claude_usage_occurrences,
        ..
    } = &mut items[at]
    {
        fold.disclose("twin_overcount_kept", overcount);
        for id in &drops {
            let occurrence = &claude_usage_occurrences[id];
            let time = occurrence.timestamp.as_deref().and_then(rfc3339_unix_nanos);
            let own = fold.money_birth.copied_with_slack(time, SLACK) == Some(false);
            if fold.drop_family_duplicate(occurrence) {
                kept += 1;
                if own {
                    fold.own_requests = fold
                        .own_requests
                        .saturating_sub(occurrence.usage.request_count);
                }
            } else {
                // It stays counted, disclosed.
                fold.disclose("twin_drop_missed", 1);
            }
        }
    }
    record_counts(Counts::one(21, kept));
    diag("copy_prefix_twin_page_removed", kept);
}

/// A forked subagent's first line repeats the parent's last response: the
/// subagent's first response counts once, at the root, when the root's
/// page or valid persisted census holds its request id, regardless of
/// freshness. Without either witness the copy counts (no hold, counted as
/// deferred); the subagent's next page decides again.
fn decide_family(items: &mut [SnapshotItem], at: usize, root_key: &str, index: &ScanIndex) {
    let item = &items[at];
    let first = item
        .claude_usage_occurrences
        .iter()
        .min_by_key(|(_, occurrence)| occurrence.sequence);
    let Some((id, sequence)) = first.map(|(id, occurrence)| (id.clone(), occurrence.sequence))
    else {
        return;
    };
    let root = claude_snapshot_family_root_ref(item);
    let witness = current_witness(items, root, root_key, index);
    let census = index
        .claude_request_census
        .get(root_key)
        .filter(|record| record.proves_scan());
    let copied = witness.as_ref().is_some_and(|witness| witness.holds(&id))
        || census.is_some_and(|record| record.holds_hash(claude_request_hash(&id)));
    let deferred = u64::from(witness.is_none() && census.is_none());
    record_counts(Counts::one(20, deferred));
    diag("family_copy_deferred", deferred);
    // The proof is this fold's, so the fold is present.
    let SnapshotItem {
        claude_money: Some(fold),
        claude_usage_occurrences,
        ..
    } = &mut items[at]
    else {
        return;
    };
    if copied && !fold.is_skipped(sequence) {
        fold.drop_family_duplicate(&claude_usage_occurrences[&id]);
    }
}

/// What a census record proves about its file now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Evidence {
    /// It lists the requests the file holds.
    Current,
    /// The file changed since that scan and this traversal still queues it:
    /// the decision waits for the re-read (a stale holder never decides).
    Queued,
    /// The live mtime changed since the census read, whether queued or not.
    Stale,
    /// Nothing: retired, over budget, twin, older derivation, or a held
    /// scan whose file is gone.
    None,
}

/// What `key`'s census record proves about the file now (owner rule:
/// holding a session withholds its UPLOAD only; its scan state stays
/// evidence). The record of the settled revision (its index entry, same
/// fingerprint) proves it; so does the record of a scan whose upload is held
/// (entry absent or not advanced), while the file is still there. A file
/// modified since its recorded read is Stale until read again.
/// A queued size change also waits, including changes within one mtime
/// second (PR C). Unchanged held scans remain evidence, never upload proof.
pub(super) fn scan_evidence(
    index: &ScanIndex,
    key: &str,
    record: &crate::snapshots::claude_request_census::ClaudeRequestCensusRecord,
) -> Evidence {
    if !record.proves_scan() {
        return Evidence::None;
    }
    let settled = index
        .files
        .get(key)
        .filter(|entry| record.proves_current(entry.source_file_fingerprint.as_str()));
    let metadata = std::fs::metadata(key).ok().filter(|m| m.is_file());
    if let Some(metadata) = &metadata {
        let now = metadata
            .modified()
            .ok()
            .and_then(crate::snapshots::unix_seconds);
        if matches!((record.modified(), now), (Some(read), Some(now)) if read != now) {
            return Evidence::Stale;
        }
    }
    let changed = match (settled, &metadata) {
        (Some(entry), Some(metadata)) => metadata.len() != entry.size_bytes,
        (Some(_), None) => false,
        (None, Some(metadata)) => record.modified().is_some_and(|at| {
            metadata
                .modified()
                .ok()
                .and_then(crate::snapshots::unix_seconds)
                != Some(at)
        }),
        (None, None) => return Evidence::None,
    };
    if changed && queued(index, key) {
        Evidence::Queued
    } else {
        Evidence::Current
    }
}

/// This traversal still queues `key` for a page.
fn queued(index: &ScanIndex, key: &str) -> bool {
    index.traversal.as_ref().is_some_and(|traversal| {
        traversal
            .pending_candidates
            .iter()
            .any(|candidate| candidate.path == Path::new(key))
    })
}

/// A holder's place in the total copy order: (effective birth, location).
/// A holder without a stored birth is probed once.
fn holder_order(
    store: &crate::snapshots::claude_money_birth_store::BirthStore,
    root: &str,
    key: &str,
) -> Option<(i128, LocationKey)> {
    let birth = store.effective_cutoff(root, key).or_else(|| {
        probe_opened_birth(key)
            .filter(|opened| opened.birth != 0)
            .map(|opened| i128::from(opened.birth))
    })?;
    Some((birth, location_key(key)))
}

/// Accepted bodies remain on the server through a later local hold or refusal.
fn accepted_origin(index: &ScanIndex, key: &str) -> bool {
    index.file_has_accepted_body_unheld(key)
}

/// Destination-local ownership needs no server round trip. Before acceptance,
/// only a counted, identity-complete body on this page or committed here proves it.
#[cfg(test)]
pub(super) fn origin_owned(
    index: &ScanIndex,
    page: &[SnapshotItem],
    key: &str,
    need_census: bool,
) -> bool {
    if !need_census && index.claude_family_listed(key) {
        return false;
    }
    accepted_origin(index, key) || local_owned(index, page, key, need_census)
}
fn local_owned(index: &ScanIndex, page: &[SnapshotItem], key: &str, need_census: bool) -> bool {
    let Some(entry) = index.files.get(key) else {
        return false;
    };
    if copy_held(index, key) || index.claude_family_listed(key) {
        return false;
    }
    let page_body = page.iter().find(|item| {
        item.claude_money
            .as_deref()
            .is_some_and(|fold| fold.location_key() == Some(location_key(key)))
    });
    let bodies = index.file_snapshot_fingerprints.get(key);
    let cutoff = index.backfill_cutoff_nanos;
    let nonempty = match page_body {
        Some(item) => {
            !item.snapshot_fingerprint.is_empty()
                && item.request_count > 0
                && item
                    .claude_money
                    .as_deref()
                    .is_some_and(|fold| !fold.entity.held)
                // A body the claim cutoff will drop owns only as its emptied
                // file would, so every placement agrees from the first body.
                && cutoff.is_none_or(|cutoff| {
                    !crate::backfill::ended_before_backfill_cutoff(item, cutoff)
                        || cutoff_owner(index, key, cutoff)
                })
        }
        None => {
            (!index.confirmed_empty_files.contains(key)
                && bodies.is_some_and(|fps| !fps.is_empty()))
                || (need_census
                    && index.confirmed_empty_files.contains(key)
                    && cutoff.is_some_and(|cutoff| cutoff_owner(index, key, cutoff)))
        }
    };
    let refused = page_body.map_or_else(
        || {
            bodies
                .into_iter()
                .flatten()
                .any(|fp| index.quarantined_snapshot_fingerprints.contains_key(fp))
        },
        |item| {
            index
                .quarantined_snapshot_fingerprints
                .contains_key(&item.snapshot_fingerprint)
        },
    );
    nonempty
        && !refused
        && (!need_census
            || index
                .claude_request_census
                .get(key)
                .is_some_and(|record| record.current_for(&entry.source_file_fingerprint)))
}
/// Under the claim cutoff (UTC ns), a main whose body finish drops is the
/// previous owner's history: never uploaded here, it still owns the requests
/// its copies hold, so they count nowhere at this destination. Only while its
/// file was last written before the cutoff (census mtime) and the birth store
/// records this location as its session's only one (another's body may carry
/// them). A local proof only (with a current census holding the hash): server
/// acceptance never reads it.
fn cutoff_owner(index: &ScanIndex, key: &str, cutoff: i128) -> bool {
    let here = location_key(key);
    index
        .claude_request_census
        .get(key)
        .and_then(|record| record.modified())
        .is_some_and(|modified| (i128::from(modified) + 1) * 1_000_000_000 <= cutoff)
        && claude_index_path_member_ref(Path::new(key)).is_some_and(|member| {
            let mut locations = index
                .claude_money_birth_store
                .observations(member.root)
                .map(|(location, _)| location);
            locations.next() == Some(here) && locations.all(|location| location == here)
        })
}
fn twin_carrier(index: &ScanIndex, key: &str) -> bool {
    index.file_upload_context_enabled()
        && !index.file_upload_context_requires_adoption(key)
        && accepted_origin(index, key)
        && committed_twin_carrier(index, key)
}
fn committed_twin_carrier(index: &ScanIndex, key: &str) -> bool {
    let Some(entry) = index.files.get(key) else {
        return false;
    };
    index
        .claude_request_census
        .get(key)
        .is_some_and(|r| r.current_twin_for(&entry.source_file_fingerprint))
        && !index.confirmed_empty_files.contains(key)
        && entry
            .upload_context_receipt
            .as_ref()
            .is_some_and(|r| !r.body_witness.is_empty() && receipt_binds_bytes(entry, r, false))
        && local_owned(index, &[], key, false)
}

fn copy_held(index: &ScanIndex, key: &str) -> bool {
    let Some(entry) = index.files.get(key) else {
        return false;
    };
    index.decode_holds_file(key)
        || claude_index_path_member_ref(Path::new(key))
            .is_some_and(|m| index.claude_usage_authority_quarantine.contains_key(m.root))
        || index.claude_account_deferred_holds.contains_key(key)
        || index
            .effective_upload_body_witness_revision_excluded_source_files
            .contains(&entry.source_file_fingerprint)
        || index
            .claude_history_emission_held(&entry.source_file_fingerprint)
            .is_some()
        || index
            .claude_history_emission
            .literal_denied(&entry.source_file_fingerprint)
}

/// Owner direction (PR C (a)): a /branch names its original in a
/// `fork-context-ref` line. When that original is still indexed but its
/// census cannot answer (retired after 35 idle days, over budget, older
/// derivation, none), the named earlier original is the copy proof for the
/// requests no current record covers. A current record that lacks a request
/// proves the original does not hold it: no proof then.
pub(super) fn parent_proves(
    index: &ScanIndex,
    parent: &str,
    session: &str,
    order: (i128, LocationKey),
    live: &Live<'_>,
    hash: u64,
) -> bool {
    let Some(member) = claude_index_path_member_ref(Path::new(parent)) else {
        return false;
    };
    member.subagent_stem.is_none()
        && member.root != session
        && (live.accepts(location_key(parent), hash)
            || (local_owned(index, &[], parent, false)
                && !index
                    .claude_request_census
                    .get(parent)
                    .is_some_and(|record| record.proves_scan())))
        && holder_order(&index.claude_money_birth_store, member.root, parent)
            .is_some_and(|holder| holder < order)
}

/// 2026-11-04T00:00:00Z (UTC ms). A copy whose own turns start at or after
/// it also takes the same-session page proof.
pub(super) const COPY_PROOF_FROM: i64 = 1_793_750_400_000;

/// A provider time (UTC ns) at or after `COPY_PROOF_FROM`.
pub(super) fn from_copy_proof_cutoff(at: i128) -> bool {
    at >= i128::from(COPY_PROOF_FROM) * 1_000_000
}

/// The held copies of `items[at]` that an EARLIER fold of the same session
/// on this page holds, by that fold's parse (the `Witness::Page` evidence):
/// that fold already counts them. Transient: never stored, so a page
/// without that fold decides as before.
fn twin_page_held(
    items: &[SnapshotItem],
    page_folds: &BTreeMap<&str, Vec<usize>>,
    at: usize,
    order: (i128, LocationKey),
) -> BTreeSet<u64> {
    let item = &items[at];
    let earlier = earlier_holders(
        items,
        page_folds
            .get(item.source_session_id.as_str())
            .map_or(&[][..], Vec::as_slice),
        &order,
        |other| {
            items[other]
                .claude_money
                .as_deref()
                .and_then(FileFold::copy_order)
        },
    );
    if earlier.is_empty() || !twin_copy_born_from_cutoff(item, &earlier) {
        return BTreeSet::new();
    }
    skipped_ids(item)
        .filter(|id| earlier.iter().any(|ids| ids.contains(*id)))
        .map(|id| claude_request_hash(id))
        .collect()
}

/// The request ids of the files in `group` that come before `at` in the
/// caller's `order`; a file without a place in that order holds nothing.
pub(in crate::snapshots) fn earlier_holders<'a, K: Ord>(
    items: &'a [SnapshotItem],
    group: &[usize],
    at: &K,
    order: impl Fn(usize) -> Option<K>,
) -> Vec<&'a BTreeSet<String>> {
    group
        .iter()
        .filter(|&&other| order(other).is_some_and(|key| key < *at))
        .map(|&other| &items[other].claude_usage_request_ids)
        .collect()
}

/// An unknown time keeps today's decision.
fn twin_copy_born_from_cutoff(item: &SnapshotItem, earlier: &[&BTreeSet<String>]) -> bool {
    first_own_turn_at(item, 0, earlier).is_some_and(from_copy_proof_cutoff)
}

/// The copy's birth from its lines alone: the time of its first response at
/// or after sequence `from` that no earlier twin holds (its first own turn).
/// Never a file system birth, which a copy, rewrite or restore resets, so
/// cold and stored reads agree.
pub(in crate::snapshots) fn first_own_turn_at(
    item: &SnapshotItem,
    from: u64,
    earlier: &[&BTreeSet<String>],
) -> Option<i128> {
    first_own_turn(item, from, earlier)
        .and_then(|occurrence| occurrence.timestamp.as_deref())
        .and_then(rfc3339_unix_nanos)
}

fn first_own_turn<'a>(
    item: &'a SnapshotItem,
    from: u64,
    earlier: &[&BTreeSet<String>],
) -> Option<&'a ClaudeTranscriptUsageOccurrence> {
    item.claude_usage_occurrences
        .iter()
        .filter(|(id, occurrence)| {
            occurrence.sequence >= from && !earlier.iter().any(|ids| ids.contains(*id))
        })
        .min_by_key(|(_, occurrence)| occurrence.sequence)
        .map(|(_, occurrence)| occurrence)
}

/// One completing census walk per folder for every copied main file of the page.
/// Locally owned earlier main files prove copies through positive census ids,
/// including the copy's own session and the in-folder holder's session
/// across folders. A copy's own stored removals prove nothing. The in-folder
/// walk has no deadline.
fn decide_holders(
    items: &mut [SnapshotItem],
    folds: &[usize],
    index: &ScanIndex,
    late_held: &BTreeSet<String>,
) -> CopyRemovalUpdates {
    if !index.persistence_available() {
        for at in folds {
            hold_copies(&mut items[*at], "index_unavailable");
        }
        return CopyRemovalUpdates::default();
    }

    struct Wanted {
        at: usize,
        session: String,
        order: (i128, LocationKey),
        hashes: Vec<u64>,
        /// Hash -> the earliest holder whose current scan state proves it.
        covered: BTreeMap<u64, (i128, LocationKey)>,
        /// Hashes a stored removal keeps removed: not disproven by its
        /// still-indexed holder, or kept while that holder is not indexed.
        stored: BTreeSet<u64>,
        /// Of `stored`, those whose recorded holder is no longer indexed.
        absent: BTreeSet<u64>,
        /// Own turns follow the copied prefix.
        resumed: bool,
        /// The original its `fork-context-ref` line names.
        parent: Option<String>,
        /// The copy's folder: only holders there prove its requests.
        folder: String,
        /// Hashes an earlier same-session fold on this page counts
        /// (`twin_page_held`): removed, never stored.
        twin_held: BTreeSet<u64>,
        holder_sessions: BTreeSet<String>,
        carrier_unknown: bool,
    }
    // One accepted-row view for the whole acquisition page, before evidence chunks.
    let live = std::cell::OnceCell::<Live<'_>>::new();
    // The page's folds by session, for the same-session page proof. By
    // session id alone: path twins live under different folders and roots.
    let page: &[SnapshotItem] = items;
    // A page body the page will withhold proves nothing yet.
    let held_here = page
        .iter()
        .filter(|item| late_held.contains(&item.source_session_id))
        .filter_map(|item| {
            item.claude_money
                .as_deref()
                .and_then(FileFold::location_key)
        })
        .collect::<BTreeSet<_>>();
    // An empty-proof main whose current-context empty proof binds its exact
    // bytes, while a current twin carries its session's summed body: the
    // twin's ACK accepted that body, which counts this main's requests, so
    // the main holds them off the page as well.
    let carried = |key: &str| {
        if !(index.file_upload_context_enabled()
            && index.confirmed_empty_files.contains(key)
            && !index.file_upload_context_requires_adoption(key)
            && !copy_held(index, key)
            && !index.claude_family_listed(key)
            && index.files.get(key).is_some_and(|entry| {
                index
                    .claude_request_census
                    .get(key)
                    .is_some_and(|record| record.current_for(&entry.source_file_fingerprint))
            }))
        {
            return Some(false);
        }
        let Some(member) = claude_index_path_member_ref(Path::new(key)) else {
            return Some(false);
        };
        live.get_or_init(|| indexed_main_files(index))
            .carrier(member.root)
    };
    let owned = |key: &str| {
        if held_here.contains(&location_key(key)) {
            Some(false)
        } else if local_owned(index, page, key, true) {
            Some(true)
        } else {
            carried(key)
        }
    };
    let mut page_folds = BTreeMap::<&str, Vec<usize>>::new();
    for (at, item) in page.iter().enumerate() {
        if item.claude_money.is_some() {
            page_folds
                .entry(item.source_session_id.as_str())
                .or_default()
                .push(at);
        }
    }
    let mut wanted = folds
        .iter()
        .filter_map(|&at| {
            let item = &items[at];
            let fold = item.claude_money.as_deref()?;
            let order = fold.copy_order()?;
            let resumed = fold.first_own.is_some();
            let Some(CopyProof::Holders { parent, folder }) = fold.proof.clone() else {
                return None;
            };
            let mut hashes = skipped_ids(item)
                .map(|id| claude_request_hash(id))
                .collect::<Vec<_>>();
            hashes.sort_unstable();
            hashes.dedup();
            // A stored removal stays removed after its holder's
            // id list retires. Only a holder whose census disproves it
            // invalidates that saved decision; a holder family on the
            // re-emission list keeps it (listing pauses new removals only).
            // A holder no longer indexed (its transcript deleted)
            // cannot disprove anything; its recorded removals stand only
            // for hashes its accepted request rows still prove.
            let mut stored = BTreeSet::new();
            let mut absent = BTreeSet::new();
            let mut carrier_unknown = false;
            for (holder, held) in index.claude_copy_removals.get(order.1) {
                let live = live.get_or_init(|| indexed_main_files(index));
                for &hash in held.iter() {
                    match holder_proof(index, live, *holder, hash, HolderUse::Stored) {
                        Some(true) if hashes.binary_search(&hash).is_ok() => {
                            stored.insert(hash);
                            if !live.contains_key(holder) {
                                absent.insert(hash);
                            }
                        }
                        None => carrier_unknown = true,
                        Some(_) => {}
                    }
                }
            }

            Some(Wanted {
                at,
                session: item.source_session_id.clone(),
                order,
                twin_held: twin_page_held(page, &page_folds, at, order),
                hashes,
                covered: BTreeMap::new(),
                stored,
                absent,
                resumed,
                parent,
                folder,
                holder_sessions: BTreeSet::new(),
                carrier_unknown,
            })
        })
        .collect::<Vec<_>>();
    // Per folder, (hash, wanted file), sorted: each holder hit finds the
    // files that want it directly, never a pass over every wanted file per
    // holder record.
    let mut by_folder = BTreeMap::<String, Vec<(u64, usize)>>::new();
    for (at, file) in wanted.iter().enumerate() {
        by_folder
            .entry(file.folder.clone())
            .or_default()
            .extend(file.hashes.iter().map(|&hash| (hash, at)));
    }
    let store = &index.claude_money_birth_store;
    for (folder, mut wanting) in by_folder {
        wanting.sort_unstable();
        let mut union = wanting.iter().map(|&(hash, _)| hash).collect::<Vec<_>>();
        union.dedup();
        let _ = index.claude_request_census.main_transcript_holders(
            Some(folder.as_str()),
            &union,
            None,
            |key, root, record, hits| {
                // Per holder record, each at most once and only when another
                // session wants one of its ids: evidence, then (birth, location).
                let evidence = if record.proves_scan() {
                    Evidence::Current
                } else {
                    Evidence::None
                };
                let holder = holder_order(store, root, key);
                for &hash in hits {
                    let proven = holder_proof(
                        index,
                        live.get_or_init(|| indexed_main_files(index)),
                        location_key(key),
                        hash,
                        HolderUse::New(owned(key)),
                    );
                    let from = wanting.partition_point(|&(wanted, _)| wanted < hash);
                    for &(_, at) in wanting[from..].iter().take_while(|&&(h, _)| h == hash) {
                        let file = &mut wanted[at];
                        if file.session == root {
                            continue;
                        }
                        if proven.is_none() {
                            file.carrier_unknown = true;
                        }
                        if proven == Some(false) || evidence == Evidence::None {
                            // Another location of this session may count the request.
                            file.holder_sessions.insert(root.to_owned());
                        }
                        if let Some(holder) =
                            holder.filter(|h| proven == Some(true) && *h < file.order)
                        {
                            let earliest = file.covered.entry(hash).or_insert(holder);
                            *earliest = (*earliest).min(holder);
                        }
                    }
                }
            },
        );
    }
    let on_page = page
        .iter()
        .filter_map(|item| item.claude_money.as_deref()?.location_key())
        .collect::<BTreeSet<_>>();
    // (A) The copy's own session, then (B) the in-folder holder's
    // session in every folder. These indexed lookups need no census walk.
    for file in &mut wanted {
        // The first discovered path carries a summed session's ACK. Rule A
        // uses that session acceptance regardless of the carrier's location.
        let session_accepted = any_proof(store.observations(&file.session).filter_map(
            |(location, _)| {
                live.get_or_init(|| indexed_main_files(index))
                    .get(&location)
                    .map(|key| owned(key))
            },
        ));
        for session in std::iter::once(&file.session).chain(file.holder_sessions.iter()) {
            for (location, _) in store.observations(session) {
                let Some(&key) = live
                    .get_or_init(|| indexed_main_files(index))
                    .get(&location)
                else {
                    continue;
                };
                for &hash in &file.hashes {
                    if file.stored.contains(&hash) {
                        continue;
                    }
                    let accepted = if session == &file.session {
                        session_accepted
                    } else {
                        owned(key)
                    };
                    if let Some((holder, proven)) = census_holder(
                        index,
                        live.get_or_init(|| indexed_main_files(index)),
                        key,
                        session,
                        hash,
                        accepted,
                    )
                    .filter(|(h, _)| {
                        *h < file.order
                            && (session != &file.session || !file.resumed || on_page.contains(&h.1))
                    }) {
                        match proven {
                            Some(true) => {
                                let earliest = file.covered.entry(hash).or_insert(holder);
                                *earliest = (*earliest).min(holder);
                            }
                            None => file.carrier_unknown = true,
                            Some(false) => {}
                        }
                    }
                }
            }
        }
    }
    let mut held_sessions = wanted
        .iter()
        .filter(|file| file.carrier_unknown)
        .map(|file| file.session.clone())
        .collect::<BTreeSet<_>>();
    if !held_sessions.is_empty()
        && let Some(live) = live.get()
    {
        // A withheld page body cannot supply Local proof to another session.
        let page_sessions = page
            .iter()
            .filter_map(|item| {
                let location = item.claude_money.as_deref()?.location_key()?;
                Some((location, item.source_session_id.as_str()))
            })
            .collect::<BTreeMap<_, _>>();
        let mut dependents = BTreeMap::<&str, BTreeSet<&str>>::new();
        for file in &wanted {
            for (&hash, &(_, location)) in &file.covered {
                let Some(&session) = page_sessions.get(&location) else {
                    continue;
                };
                if session == file.session.as_str()
                    || file.stored.contains(&hash)
                    || live.accepts(location, hash)
                {
                    continue;
                }
                let independent = live.get(&location).is_some_and(|key| {
                    local_owned(index, &[], key, true) || carried(key) == Some(true)
                });
                if holder_proof(
                    index,
                    live,
                    location,
                    hash,
                    HolderUse::New(Some(independent)),
                ) != Some(true)
                {
                    dependents
                        .entry(session)
                        .or_default()
                        .insert(file.session.as_str());
                }
            }
        }
        let mut pending = held_sessions.iter().cloned().collect::<Vec<_>>();
        while let Some(session) = pending.pop() {
            if let Some(copies) = dependents.remove(session.as_str()) {
                for copy in copies {
                    if held_sessions.insert(copy.to_owned()) {
                        pending.push(copy.to_owned());
                    }
                }
            }
        }
    }
    let mut updates = CopyRemovalUpdates {
        // Stored removals leave only with their file
        // (`ScanIndex::drop_file_entry`); no page sweeps them.
        state: Some(index.claude_copy_removals.clone()),
        ..Default::default()
    };

    for wanted in wanted {
        if held_sessions.contains(&wanted.session) {
            hold_copies(&mut items[wanted.at], "request_owned_held");
            continue;
        }
        #[cfg(test)]
        pipeline_test_observer::record_holder(wanted.order.1, wanted.covered.values().min());
        let decided =
            |hash: &u64| wanted.covered.contains_key(hash) || wanted.stored.contains(hash);
        let uncovered = wanted
            .hashes
            .iter()
            .copied()
            .filter(|hash| !decided(hash) && !wanted.twin_held.contains(hash))
            .collect::<Vec<_>>();
        let twin_removed = wanted.twin_held.iter().filter(|&h| !decided(h)).count() as u64;
        diag("copy_prefix_twin_page_removed", twin_removed);
        record_counts(Counts::one(21, twin_removed));
        let reused = wanted
            .stored
            .iter()
            .filter(|hash| !wanted.covered.contains_key(hash))
            .count() as u64;
        let absent_kept = wanted
            .absent
            .iter()
            .filter(|hash| !wanted.covered.contains_key(hash))
            .count() as u64;
        if absent_kept > 0 {
            diag("copy_removal_holder_absent_kept", absent_kept);
            record_counts(Counts::one(19, absent_kept));
        }
        if let Some(state) = updates.state.as_mut() {
            let groups = stored_groups(index, &live, wanted.covered, wanted.order.1);
            state.relied_on.extend(
                groups
                    .iter()
                    .filter(|(holder, hashes)| {
                        let live = live.get_or_init(|| indexed_main_files(index));
                        hashes.iter().any(|hash| !live.accepts(**holder, *hash))
                    })
                    .map(|(&holder, _)| holder),
            );
            updates.added += state.store(wanted.order.1, groups);
        }
        note_reused(&mut items[wanted.at], reused);
        updates.state.as_mut().unwrap().clear_hold(wanted.order.1);
        // The pre-existing all-copy /branch lineage rule is not request-id
        // proof for a resumed prefix. Missing/retired ids there must emit
        // flagged, even when the transcript names an earlier parent.
        let mut uncovered = uncovered;
        if !wanted.resumed {
            if let Some(parent) = wanted.parent.as_deref() {
                let live = live.get_or_init(|| indexed_main_files(index));
                let proved = uncovered
                    .iter()
                    .copied()
                    .filter(|&hash| {
                        parent_proves(index, parent, &wanted.session, wanted.order, live, hash)
                    })
                    .collect::<BTreeSet<_>>();
                let state = updates.state.as_mut().unwrap();
                let mut groups = state
                    .get(wanted.order.1)
                    .iter()
                    .map(|(h, ids)| (*h, ids.iter().copied().collect::<BTreeSet<_>>()))
                    .collect::<BTreeMap<_, _>>();
                groups.entry(location_key(parent)).or_default().extend(
                    proved
                        .iter()
                        .copied()
                        .filter(|hash| live.accepts(location_key(parent), *hash)),
                );
                updates.added += state.store(wanted.order.1, groups);
                diag("copy_parent_ref", proved.len() as u64);
                uncovered.retain(|h| !proved.contains(h));
            }
        }
        // What no holder proves now (its id list retired, over budget or
        // missing, an origin deleted or in another folder, no stored
        // removal) counts, flagged.
        let ids = skipped_ids(&items[wanted.at])
            .filter(|id| uncovered.binary_search(&claude_request_hash(id)).is_ok())
            .cloned()
            .collect::<Vec<_>>();
        restore_uncovered(&mut items[wanted.at], &ids);
    }
    if let Some(live) = live.get() {
        record_counts(Counts::one(23, live.sessions.unknown.len() as u64));
    }
    updates
}

/// The file's removals to store: its stored hashes not disproven by their
/// still-indexed holder's record (a holder no longer indexed disproves
/// nothing), plus each newly proven hash under its earliest
/// current holder.
fn stored_groups<'a>(
    index: &'a ScanIndex,
    live: &std::cell::OnceCell<Live<'a>>,
    mut covered: BTreeMap<u64, (i128, LocationKey)>,
    file: LocationKey,
) -> BTreeMap<LocationKey, BTreeSet<u64>> {
    let mut groups = BTreeMap::<LocationKey, BTreeSet<u64>>::new();
    let old = index.claude_copy_removals.get(file);
    for (holder, hashes) in old {
        let kept = hashes.iter().filter(|&&hash| {
            holder_proof(
                index,
                live.get_or_init(|| indexed_main_files(index)),
                *holder,
                hash,
                HolderUse::Stored,
            ) == Some(true)
        });
        let into = groups.entry(*holder).or_default();
        for &hash in kept {
            // Consume covered entries once; never search every holder group
            // again for every currently proven request.
            covered.remove(&hash);
            into.insert(hash);
        }
    }
    groups.retain(|_, hashes| !hashes.is_empty());
    for (hash, (_, holder)) in covered {
        groups.entry(holder).or_default().insert(hash);
    }
    groups
}

/// Stored removals this decision kept without a current holder's proof.
fn note_reused(item: &mut SnapshotItem, reused: u64) {
    if let Some(fold) = item.claude_money.as_deref_mut() {
        fold.prefix.reused = reused;
        diag("copy_removal_reused", reused);
    }
}

/// Decided: `uncovered` (and every id-less copy) counts, disclosed.
pub(super) fn restore_uncovered(item: &mut SnapshotItem, uncovered: &[String]) {
    let SnapshotItem {
        claude_money: Some(fold),
        claude_usage_occurrences,
        ..
    } = item
    else {
        return;
    };
    let holder_proof = matches!(fold.proof, Some(CopyProof::Holders { .. }));
    for id in uncovered {
        if fold.is_ambiguous(id) {
            // Two responses claim it: no single grain to give back.
            fold.entity
                .fail_certificate(CertificateFailure::AmbiguousDuplicate);
        } else if let Some(occurrence) = claude_usage_occurrences.get(id) {
            fold.restore_one(occurrence);
        }
    }
    fold.restore_idless();
    fold.proof = None;
    if !holder_proof {
        fold.absorb_prefix_inherited(false);
    }
}

/// Prove dominance from the current request census, else bounded member bytes.
/// No path, account or birth-time preference grants redundancy.
fn redundant_twin(key: &str, other: &str, folded: &SnapshotItem, index: &ScanIndex) -> bool {
    use std::io::{BufRead, BufReader, Read};
    let proof = || -> Option<bool> {
        let metadata = std::fs::metadata(key).ok()?;
        if let Some(record) = index.claude_request_census.get(key).filter(|record| {
            !record.request_hashes().is_empty()
                && index.files.get(key).is_some_and(|entry| {
                    record.current_for(entry.source_file_fingerprint.as_str())
                        && entry.same_listing_stamp_as(&metadata)
                })
        }) {
            let hashes = folded
                .claude_usage_request_ids
                .iter()
                .map(|id| claude_request_hash(id))
                .collect::<BTreeSet<_>>();
            if record
                .request_hashes()
                .iter()
                .all(|hash| hashes.contains(hash))
            {
                return Some(true);
            }
        }
        let bound = std::fs::metadata(other).ok()?.len();
        if metadata.len() > bound {
            return Some(false);
        }
        let mut p = BufReader::new(std::fs::File::open(key).ok()?.take(bound.saturating_add(1)));
        let mut q = BufReader::new(std::fs::File::open(other).ok()?.take(bound));
        let (mut a, mut b) = (Vec::new(), Vec::new());
        let (mut prefix, mut read) = (true, 0u64);
        loop {
            a.clear();
            let n = p.read_until(b'\n', &mut a).ok()?;
            if n == 0 {
                return Some(read == metadata.len());
            }
            read = read.saturating_add(n as u64);
            if prefix {
                b.clear();
                q.read_until(b'\n', &mut b).ok()?;
                if a == b {
                    continue;
                }
                prefix = false;
            }
            let line: serde_json::Value = serde_json::from_slice(&a).ok()?;
            if crate::snapshots::claude_code_usage_dedup_key(&line).is_some()
                || crate::snapshots::claude_code_usage_root(&line).is_some()
            {
                return Some(false);
            }
        }
    };
    proof() == Some(true)
}

/// Missing overlapping contributors hold the replacement. Deleted files
/// and retired/missing census hashes release the content dependency.
fn content_twin_holds(
    sessions: &[(&str, &[LocationKey])],
    items: &[SnapshotItem],
    index: &ScanIndex,
) -> BTreeSet<String> {
    if sessions.is_empty() {
        return BTreeSet::new();
    }
    let mut twin_locations = BTreeSet::new();
    let mut twins_by_hash = BTreeMap::<u64, BTreeSet<&str>>::new();
    for (key, twin) in index
        .claude_request_census
        .records()
        .filter(|(_, r)| r.is_twin())
    {
        twin_locations.insert(location_key(key));
        for &hash in twin.request_hashes() {
            twins_by_hash.entry(hash).or_default().insert(key);
        }
    }
    let mut page_locations = BTreeSet::new();
    let mut session_hashes = BTreeMap::<&str, BTreeSet<u64>>::new();
    for item in items {
        page_locations.extend(
            item.claude_money
                .as_deref()
                .and_then(FileFold::location_key),
        );
        session_hashes
            .entry(&item.source_session_id)
            .or_default()
            .extend(
                item.claude_usage_request_ids
                    .iter()
                    .map(|id| claude_request_hash(id)),
            );
    }
    // Build filename groups once for the same twin-only sessions, including
    // empty location lists (all() was vacuously true for those too).
    let only_twins = sessions
        .iter()
        .filter(|(_, here)| here.iter().all(|key| twin_locations.contains(key)))
        .map(|(session, _)| (*session).to_owned())
        .collect::<BTreeSet<_>>();
    let groups = (!only_twins.is_empty()).then(|| claude_path_twin_groups(index, &only_twins));
    sessions
        .iter()
        .filter(|(session, here)| {
            // Filename absence still takes precedence over content overlap.
            if only_twins.contains(*session)
                && groups
                    .as_ref()
                    .and_then(|groups| groups.get(*session))
                    .is_some_and(|keys| {
                        keys.iter().any(|(key, _)| {
                            Path::new(key).is_file() && !here.contains(&location_key(key))
                        })
                    })
            {
                return true;
            }
            let hashes = &session_hashes[*session];
            // Keep census key order and check each overlapping twin only once.
            let overlapping = hashes
                .iter()
                .filter_map(|hash| twins_by_hash.get(hash))
                .flatten()
                .copied()
                .collect::<BTreeSet<_>>();
            overlapping.into_iter().any(|key| {
                let twin = index.claude_request_census.get(key).unwrap();
                !(twin.is_exact()
                    && twin
                        .request_hashes()
                        .iter()
                        .all(|hash| hashes.contains(hash)))
                    && !page_locations.contains(&location_key(key))
                    && Path::new(key).is_file()
            })
        })
        .map(|(session, _)| (*session).to_owned())
        .collect()
}

/// Sessions (roots and subagent members) with a live indexed path that is
/// not on this page: never publish one path over complete twin history. Only
/// sessions whose birth table knows more paths than the page holds build the
/// shared twin groups (after the scan, so not the page's own copy).
pub(super) fn absent_twins(
    sessions: &[(&str, &[LocationKey])],
    items: &[SnapshotItem],
    index: &ScanIndex,
    queued_family_deferred_paths: &BTreeSet<LocationKey>,
    hold_reasons: &mut BTreeMap<&'static str, u64>,
) -> BTreeSet<String> {
    let store = &index.claude_money_birth_store;
    let suspects = sessions
        .iter()
        .filter(|(session, here)| {
            store
                .observations(session)
                .any(|(location, _)| !here.contains(&location))
        })
        .collect::<Vec<_>>();
    let mut held = BTreeSet::new();
    if suspects.is_empty() {
        return held;
    }
    let groups = claude_path_twin_groups(index, &BTreeSet::new());
    for (session, here) in suspects {
        let absent = path_twins(&groups, session).is_some_and(|keys| {
            keys.iter().any(|(key, size)| {
                if size.is_none() || here.contains(&location_key(key)) || !Path::new(key).is_file()
                {
                    return false;
                }
                let redundant = keys.iter().any(|(other, _)| {
                    items.iter().any(|item| {
                        item.source_session_id == *session
                            && item.claude_money.as_deref().is_some_and(|fold| {
                                fold.location == Some(Located(location_key(other)))
                                    // A folded copy that still excludes requests cannot replace its witness.
                                    && fold.copied == 0
                            })
                            && redundant_twin(key, other, item, index)
                    })
                });
                if redundant {
                    diag("twin_redundant", 1);
                }
                !redundant
            })
        });
        if absent {
            held.insert((*session).to_owned());
        }
    }
    if !held.is_empty() {
        // Count the known twin groups of each held FAMILY once, including
        // sibling members. Staged means a native fold on this page, not a
        // metadata birth probe (which may also stage an absent twin).
        let families = held
            .iter()
            .filter_map(|member| groups.get(member)?.first())
            .filter_map(|(key, _)| claude_index_path_member_ref(Path::new(key)))
            .map(|member| member.root)
            .collect::<BTreeSet<_>>();
        let mut known = 0;
        let mut staged = 0;
        let mut deferred_families = BTreeSet::new();
        for (member, keys) in &groups {
            let Some(twins) = path_twins(&groups, member) else {
                continue;
            };
            let Some(family) = keys
                .first()
                .and_then(|(key, _)| claude_index_path_member_ref(Path::new(key)))
            else {
                continue;
            };
            if !families.contains(family.root) {
                continue;
            }
            let here = sessions
                .iter()
                .find(|(session, _)| *session == member)
                .map(|(_, here)| *here)
                .unwrap_or_default();
            for (key, _) in twins {
                let location = location_key(key);
                known += 1;
                staged += u64::from(here.contains(&location));
                if queued_family_deferred_paths.contains(&location) {
                    deferred_families.insert(family.root);
                }
            }
        }
        for (label, count) in [
            ("known_twin_paths", known),
            ("staged_twin_paths", staged),
            (
                "queued_family_deferred_families",
                deferred_families.len() as u64,
            ),
        ] {
            *hold_reasons.entry(label).or_default() += count;
        }
    }
    held
}

/// A selected path twin pulls its complete family into this existing native
/// page's forced-family path. No parser/scope/identity bump is involved.
pub(in crate::snapshots) fn selected_twin_roots<'a>(
    paths: impl Iterator<Item = &'a Path>,
    twins: &ClaudeTwinGroups,
) -> BTreeSet<String> {
    paths
        .filter_map(claude_index_path_family_member)
        .filter(|(_, member)| path_twins(twins, member).is_some())
        .map(|(root, _)| root)
        .collect()
}

#[cfg(test)]
pub(crate) fn carrier_group_owned_for_test(index: &ScanIndex, key: &str) -> bool {
    index_group_owned(index, &indexed_main_files(index), key) == Some(true)
}

#[cfg(test)]
pub(crate) fn reconcile_carrier_images_for_test(
    previous: &ScanIndex,
    next: &mut ScanIndex,
    mut heads: impl FnMut(&[&str], bool) -> BTreeMap<String, String>,
) {
    let mut previous = CopyOwnership::capture(previous);
    previous.seed(&mut |keys| Carriers {
        links: heads(keys, true),
        ..Default::default()
    });
    previous.reconcile(next, &mut |keys| Carriers {
        links: heads(keys, false),
        ..Default::default()
    });
}
