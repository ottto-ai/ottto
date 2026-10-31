//! Released holder decisions, retained verbatim for the default-OFF path.
use super::*;

pub(super) fn decide_holders(items: &mut [SnapshotItem], folds: &[usize], index: &ScanIndex) {
    if !index.persistence_available() {
        for at in folds {
            hold_copies(&mut items[*at], "index_unavailable");
        }
        return;
    }

    struct Wanted {
        at: usize,
        session: String,
        order: (i128, LocationKey),
        hashes: Vec<u64>,
        covered: BTreeSet<u64>,
        /// A holder that would cover it changed and is still queued.
        waiting: bool,
        /// Hashes held only by an earlier file modified since its census read.
        stale: BTreeSet<u64>,
        /// The original its `fork-context-ref` line names.
        parent: Option<String>,
    }
    let mut wanted = folds
        .iter()
        .filter_map(|&at| {
            let item = &items[at];
            let fold = item.claude_money.as_deref()?;
            let order = fold.copy_order()?;
            let parent = match &fold.proof {
                Some(CopyProof::Holders(parent)) => parent.clone(),
                _ => None,
            };
            let mut hashes = skipped_ids(item)
                .map(|id| claude_request_hash(id))
                .collect::<Vec<_>>();
            hashes.sort_unstable();
            hashes.dedup();
            Some(Wanted {
                at,
                session: item.source_session_id.clone(),
                order,
                hashes,
                covered: BTreeSet::new(),
                waiting: false,
                stale: BTreeSet::new(),
                parent,
            })
        })
        .collect::<Vec<_>>();
    // (hash, wanted file), sorted: each holder hit finds the files that want
    // it directly, never a pass over every wanted file per holder record.
    let mut wanting = wanted
        .iter()
        .enumerate()
        .flat_map(|(at, wanted)| wanted.hashes.iter().map(move |&hash| (hash, at)))
        .collect::<Vec<_>>();
    wanting.sort_unstable();
    let mut union = wanting.iter().map(|&(hash, _)| hash).collect::<Vec<_>>();
    union.dedup();
    let store = &index.claude_money_birth_store;
    let walked = index.claude_request_census.main_transcript_holders(
        &union,
        Instant::now() + SIDE_CALL_DEADLINE,
        |key, root, record, hits| {
            // Per holder record, each at most once and only when another
            // session wants one of its ids: evidence, then (birth, location).
            let mut holder = None::<Option<(Evidence, (i128, LocationKey))>>;
            for &hash in hits {
                let from = wanting.partition_point(|&(wanted, _)| wanted < hash);
                for &(_, at) in wanting[from..].iter().take_while(|&&(h, _)| h == hash) {
                    let file = &mut wanted[at];
                    if file.session == root {
                        continue;
                    }
                    let holder = *holder.get_or_insert_with(|| {
                        let evidence = scan_evidence(index, key, record);
                        if evidence == Evidence::None {
                            return None;
                        }
                        Some((evidence, holder_order(store, root, key)?))
                    });
                    match holder {
                        Some((evidence, holder)) if holder < file.order => match evidence {
                            Evidence::Queued => file.waiting = true,
                            Evidence::Stale => {
                                file.stale.insert(hash);
                            }
                            Evidence::Current => {
                                file.covered.insert(hash);
                            }
                            Evidence::None => {}
                        },
                        _ => {}
                    }
                }
            }
        },
    );
    let pending = std::cell::OnceCell::<BTreeSet<String>>::new();
    for wanted in wanted {
        let uncovered = wanted
            .hashes
            .iter()
            .copied()
            .filter(|hash| !wanted.covered.contains(hash))
            .collect::<Vec<_>>();
        if walked.is_none() {
            hold_copies(&mut items[wanted.at], "held_copy_deadline");
            continue;
        }
        if wanted.waiting || uncovered.iter().any(|hash| wanted.stale.contains(hash)) {
            hold_copies(&mut items[wanted.at], "held_copy_stale_holder");
            continue;
        }
        if !uncovered.is_empty()
            && wanted
                .parent
                .as_deref()
                .is_some_and(|parent| parent_proves(index, parent, &wanted.session, wanted.order))
        {
            diag("copy_parent_ref", uncovered.len() as u64);
            restore_uncovered(&mut items[wanted.at], &[]);
            continue;
        }
        if !uncovered.is_empty()
            && pending
                .get_or_init(|| unscanned_main_roots(index))
                .iter()
                .any(|root| *root != wanted.session)
        {
            hold_copies(&mut items[wanted.at], "held_copy_unscanned");
            continue;
        }
        let ids = skipped_ids(&items[wanted.at])
            .filter(|id| uncovered.binary_search(&claude_request_hash(id)).is_ok())
            .cloned()
            .collect::<Vec<_>>();
        restore_uncovered(&mut items[wanted.at], &ids);
    }
}
