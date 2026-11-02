//! The ordered, sliced usage-pending visitor over a real cold session: any
//! slicing visits exactly one whole visit's families, each slice decodes at
//! most what its budget admits and installs nothing, and a patched head is
//! rewritten alone at save.
use super::*;
use crate::snapshots::state_v2::money_test_support as v2;
use crate::snapshots::ClaudeUsageFamilyPending;
use std::collections::{BTreeMap, BTreeSet};

const WINDOW: &str = "2026-11-01T00:00:00Z";

fn hash(n: u64) -> String {
    format!("{n:064x}")
}

/// A one-member family (its root is its only member) whose requests occur
/// in the given order.
fn family(window: &str, root: &str, requests: &[u64]) -> ClaudeUsageFamilyPending {
    let occurrences: serde_json::Map<String, serde_json::Value> = requests
        .iter()
        .enumerate()
        .map(|(sequence, n)| {
            let witness = serde_json::json!({
                "sequence": sequence, "input_tokens": 1, "output_tokens": 2,
                "cache_read_tokens": 0, "cache_creation_5m_tokens": 0,
                "cache_creation_1h_tokens": 0, "reasoning_output_tokens": 0,
                "model": null, "speed_mode": null, "reasoning_effort": null
            });
            (hash(*n), witness)
        })
        .collect();
    let hashes: Vec<String> = requests.iter().map(|n| hash(*n)).collect();
    serde_json::from_value(serde_json::json!({
        "census_window_end": window,
        "member_request_id_hashes": { root: hashes },
        "member_occurrences": { root: occurrences },
        "invalid": false,
    }))
    .unwrap()
}

/// root-b shares request 3 with root-a; root-d's ordered requests are a
/// strict prefix of root-c's (a legacy divergent-prefix pair).
fn fixture() -> ScanIndex {
    let mut index = ScanIndex::default();
    for (root, window, requests) in [
        ("root-a", WINDOW, &[1, 2, 3][..]),
        ("root-b", WINDOW, &[3, 4][..]),
        ("root-c", WINDOW, &[10, 11, 12][..]),
        ("root-d", WINDOW, &[10, 11][..]),
        ("root-e", WINDOW, &[20][..]),
        ("root-f", "2026-10-01T00:00:00Z", &[30][..]),
    ] {
        index
            .claude_usage_family_pending
            .add(root.to_owned(), family(window, root, requests));
    }
    index
}

type Seen = Vec<(String, ClaudeUsageFamilyPending)>;

/// Every slice of one ordered visit: what it emitted, in order, and how each
/// slice ended.
fn visit(
    index: &ScanIndex,
    roots: Option<&BTreeSet<String>>,
    budget: SliceBudget,
) -> Result<(Seen, Vec<SliceEnd>)> {
    let mut seen = Vec::new();
    let mut slices = Vec::new();
    let mut after: Option<String> = None;
    loop {
        let end = visit_usage_ordered(index, roots, after.as_deref(), budget, &mut |root, f| {
            seen.push((root.to_owned(), f.clone()))
        })?;
        after = end.last_root.clone();
        slices.push(end);
        if after.is_none() {
            return Ok((seen, slices));
        }
    }
}

/// The cross-family facts a terminal joins from visitor outputs: each
/// request owned by more than one root, and each (prefix root, longer root)
/// pair whose root member's ordered occurrences are a strict prefix.
fn joins(
    seen: &Seen,
) -> (
    BTreeMap<String, BTreeSet<String>>,
    BTreeSet<(String, String)>,
) {
    let mut owners = BTreeMap::<String, BTreeSet<String>>::new();
    let mut sequences = BTreeMap::<String, Vec<String>>::new();
    for (root, family) in seen {
        for request in family
            .member_request_id_hashes
            .values()
            .flatten()
            .chain(family.member_occurrences.values().flat_map(BTreeMap::keys))
        {
            owners
                .entry(request.clone())
                .or_default()
                .insert(root.clone());
        }
        if let Some(occurrences) = family.member_occurrences.get(root) {
            let mut ordered: Vec<_> = occurrences.iter().map(|(h, w)| (w.sequence, h)).collect();
            ordered.sort();
            sequences.insert(
                root.clone(),
                ordered.into_iter().map(|(_, h)| h.clone()).collect(),
            );
        }
    }
    owners.retain(|_, roots| roots.len() > 1);
    let mut prefixes = BTreeSet::new();
    for (short, s) in &sequences {
        for (long, l) in &sequences {
            if !s.is_empty() && s.len() < l.len() && l.starts_with(s) {
                prefixes.insert((short.clone(), long.clone()));
            }
        }
    }
    (owners, prefixes)
}

fn roots_of(seen: &Seen) -> Vec<&str> {
    seen.iter().map(|(root, _)| root.as_str()).collect()
}

/// [money] Slicing changes no visitor output. A one-family budget visits
/// exactly what one whole visit does, in root order, with a shared request
/// and a legacy divergent-prefix pair split across slices, so the joins
/// built from either are equal. A loaded, changed family is emitted at its
/// root position, a patched head with its flag, and every slice carries the
/// same token whose family count the slices cover once.
#[test]
fn sliced_usage_visit_equals_one_whole_visit() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let dir = crate::test_scratch::canonical_private_dir("usage-ordered-parity");
    let (custody, mut cold) = v2::ColdSession::publish(&fixture(), &dir);
    load_usage(&mut cold, Some(&BTreeSet::from(["root-e".to_owned()]))).unwrap();
    let usage = &mut cold.claude_usage_family_pending;
    usage
        .page_mut(["root-e"])
        .unwrap()
        .get_mut("root-e")
        .unwrap()
        .invalid = true;
    usage.mark_unproven("root-f");

    let one = SliceBudget {
        families: 1,
        bytes: usize::MAX,
    };
    let (whole, whole_slices) = visit(&cold, None, SliceBudget::WHOLE).unwrap();
    let (sliced, slices) = visit(&cold, None, one).unwrap();
    assert_eq!(whole_slices.len(), 1);
    assert_eq!(slices.len(), 6, "one family per slice");
    assert_eq!(sliced, whole);
    assert_eq!(
        roots_of(&whole),
        ["root-a", "root-b", "root-c", "root-d", "root-e", "root-f"]
    );
    assert!(whole[4].1.invalid, "the loaded value, at its root position");
    assert!(whole[5].1.contract_unproven, "the patch, applied on read");
    assert!(!whole[0].1.contract_unproven);

    let (owners, prefixes) = joins(&sliced);
    assert_eq!(joins(&whole), (owners.clone(), prefixes.clone()));
    let pair = |a: &str, b: &str| BTreeSet::from([a.to_owned(), b.to_owned()]);
    assert_eq!(
        owners,
        BTreeMap::from([
            (hash(3), pair("root-a", "root-b")),
            (hash(10), pair("root-c", "root-d")),
            (hash(11), pair("root-c", "root-d")),
        ])
    );
    assert_eq!(
        prefixes,
        BTreeSet::from([("root-d".to_owned(), "root-c".to_owned())])
    );

    // The targeted visit of J2/J1 candidates, sliced, equals its whole visit;
    // a name with no family is no callback.
    let candidates = BTreeSet::from(["root-c", "root-d", "root-z"].map(str::to_owned));
    let (targeted, _) = visit(&cold, Some(&candidates), one).unwrap();
    let (targeted_whole, _) = visit(&cold, Some(&candidates), SliceBudget::WHOLE).unwrap();
    assert_eq!(targeted, targeted_whole);
    assert_eq!(roots_of(&targeted), ["root-c", "root-d"]);

    let token = whole_slices[0].token;
    assert!(token.stamp.is_some());
    assert!(slices.iter().all(|end| end.token == token));
    assert_eq!(
        token.families,
        slices.iter().map(|end| end.visited).sum::<usize>()
    );
    drop(custody);
    let _ = std::fs::remove_dir_all(dir);
}

/// [regress] The ordered visit holds at most one decoded family and installs
/// none, where `load_usage(None)` installs every family: under a one-byte
/// budget each slice decodes exactly one stored row. A patched head is
/// rewritten alone at save with nothing loaded, and the stored row carries
/// the flag. A row gone mid-sweep refuses the next slice, counted.
#[test]
fn ordered_usage_visit_decodes_one_family_and_installs_none() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let dir = crate::test_scratch::canonical_private_dir("usage-ordered-bounded");
    let (custody, cold) = v2::ColdSession::publish(&fixture(), &dir);
    let loaded = |index: &ScanIndex| {
        index
            .claude_usage_family_pending
            .cold()
            .unwrap()
            .loaded()
            .len()
    };
    let byte = SliceBudget {
        families: usize::MAX,
        bytes: 1,
    };
    let mut after: Option<String> = None;
    let mut slices = 0;
    loop {
        let end = visit_usage_ordered(&cold, None, after.as_deref(), byte, &mut |_, _| {}).unwrap();
        assert_eq!(end.visited, 1, "a decoded family ends its slice");
        assert!(end.decoded_bytes > 0);
        assert_eq!(end.decoded_bytes, end.peak_family_bytes);
        assert_eq!(loaded(&cold), 0, "nothing installed");
        slices += 1;
        after = end.last_root;
        if after.is_none() {
            break;
        }
    }
    assert_eq!(slices, 6);
    let mut whole = cold.clone();
    load_usage(&mut whole, None).unwrap();
    assert_eq!(loaded(&whole), 6, "the whole-kind load this replaces");

    // Patch at save: two heads flip, no family loads, only their rows change.
    let mut expected = v2::resident(&cold);
    let mut page = cold.clone();
    page.claude_usage_family_pending.mark_unproven("root-a");
    page.claude_usage_family_pending.mark_unproven("root-f");
    assert_eq!(loaded(&page), 0);
    let (reloaded, view) = custody.save_reload(&mut page);
    assert_eq!(loaded(&page), 0, "the save installed nothing");
    let saved = page.claude_usage_family_pending.cold().unwrap();
    assert!(!saved.patched("root-a") && !saved.patched("root-f"));
    for root in ["root-a", "root-f"] {
        expected.claude_usage_family_pending.mark_unproven(root);
    }
    assert_eq!(
        serde_json::to_value(&view.claude_usage_family_pending).unwrap(),
        serde_json::to_value(&expected.claude_usage_family_pending).unwrap()
    );

    // A row gone between slices: the next slice is Unknown, counted.
    let one = SliceBudget {
        families: 1,
        bytes: usize::MAX,
    };
    let first = visit_usage_ordered(&reloaded, None, None, one, &mut |_, _| {}).unwrap();
    assert_eq!(first.last_root.as_deref(), Some("root-a"));
    delete_usage_row_in_session(&reloaded, "root-b");
    let before = usage_unknown_count();
    let next = first.last_root.as_deref();
    assert!(visit_usage_ordered(&reloaded, None, next, one, &mut |_, _| {}).is_err());
    assert!(usage_unknown_count() > before, "counted");
    assert_eq!(loaded(&reloaded), 0);
    drop(custody);
    let _ = std::fs::remove_dir_all(dir);
}
