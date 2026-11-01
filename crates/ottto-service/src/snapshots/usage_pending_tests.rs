use super::*;
use std::collections::BTreeSet;

fn witness(sequence: u64) -> super::super::ClaudeTranscriptUsageOccurrenceWitness {
    serde_json::from_value(serde_json::json!({
        "sequence": sequence, "input_tokens": 1, "output_tokens": 2, "cache_read_tokens": 0,
        "cache_creation_5m_tokens": 0, "cache_creation_1h_tokens": 0,
        "reasoning_output_tokens": 0, "model": null, "speed_mode": null, "reasoning_effort": null
    }))
    .unwrap()
}
/// A family with `n` members; member `m` holds `m + 1` requests, all with
/// occurrences except the last member's (hashes only).
pub(in crate::snapshots) fn family(
    window: &str,
    n: u64,
    invalid: bool,
) -> ClaudeUsageFamilyPending {
    let mut family: ClaudeUsageFamilyPending = serde_json::from_value(serde_json::json!({
        "census_window_end": window, "member_request_id_hashes": {}, "invalid": invalid
    }))
    .unwrap();
    for m in 0..n {
        let member = format!("member-{m}");
        let hashes: BTreeSet<String> = (0..=m).map(|r| format!("{:064x}", m * 16 + r)).collect();
        if m + 1 < n {
            family.member_occurrences.insert(
                member.clone(),
                hashes.iter().map(|h| (h.clone(), witness(m))).collect(),
            );
        }
        family.member_request_id_hashes.insert(member, hashes);
    }
    family
}
fn resident() -> Families {
    Families::from([
        ("a".to_owned(), family("w1", 3, false)),
        ("b".to_owned(), family("w0", 1, true)),
        ("c".to_owned(), family("w1", 0, false)),
        ("d".to_owned(), family("w1", 4, false)),
    ])
}
fn digest(family: &ClaudeUsageFamilyPending) -> [u8; 32] {
    use sha2::Digest;
    sha2::Sha256::digest(serde_json::to_vec(family).unwrap()).into()
}
/// Rows folded in the given order, as a complete hydrate does.
fn cold(order: &[&str]) -> UsagePending {
    let rows = resident();
    let mut cold = ColdUsage::default();
    for root in order {
        cold.fold(root, &rows[*root], digest(&rows[*root]));
    }
    UsagePending::Cold(Box::new(cold))
}
fn summary(usage: &UsagePending) -> Vec<String> {
    usage
        .views()
        .map(|(root, v)| {
            format!(
                "{root} {} {} {:?} {:?} {:?} {:?} {} {} {} {}",
                v.window(),
                v.invalid(),
                v.idless_revision(),
                v.identity_contract(),
                v.hash_members().collect::<Vec<_>>(),
                v.occurrence_members().collect::<Vec<_>>(),
                v.hash_member_count(),
                v.request_hash_count(),
                v.occurrences(),
                v.evidence_free(),
            )
        })
        .collect()
}

/// [money] heads are the fold of their rows in any order: every summary
/// reader and the cap's running total see what the resident families say,
/// and evidence of a family that was not loaded is Unknown, never absent.
#[test]
fn cold_heads_equal_the_fold_of_their_rows_in_any_order() {
    let resident = UsagePending::from(resident());
    let mut usage = cold(&["d", "b", "a", "c"]);
    assert_eq!(summary(&usage), summary(&cold(&["a", "b", "c", "d"])));
    assert_eq!(summary(&usage), summary(&resident));
    assert_eq!(usage.total_occurrences(), resident.total_occurrences());
    // a: 1 + 2, b and c: none, d: 1 + 2 + 3.
    assert_eq!(usage.total_occurrences(), 3 + 6);
    assert_eq!(usage.len(), 4);
    assert_eq!(usage.family("a"), Err(Unknown));
    assert_eq!(usage.family("z"), Ok(None));
    assert!(usage.all().is_err());
    assert!(usage.page_mut(["a"]).is_err());

    // Load every family: the join sees exactly the resident families.
    let cold_usage = usage.cold_mut().unwrap();
    for (root, family) in resident.resident().unwrap() {
        cold_usage
            .install(root.clone(), family.clone(), digest(family))
            .unwrap();
    }
    cold_usage.complete().unwrap();
    assert_eq!(usage.all().unwrap(), resident.resident().unwrap());
    assert_eq!(usage.total_occurrences(), resident.total_occurrences());

    // The join removes one family and changes another; settling returns the
    // unchanged ones to heads and keeps the changed one loaded.
    usage.discard("c");
    usage.all_mut().unwrap().get_mut("a").unwrap().invalid = true;
    usage
        .cold_mut()
        .unwrap()
        .settle(&BTreeSet::new(), |f| Some(digest(f)));
    assert_eq!(
        usage.cold().unwrap().loaded().keys().collect::<Vec<_>>(),
        ["a"]
    );
    assert!(!usage.contains_key("c"));
    assert_eq!(usage.family("b"), Err(Unknown));
    assert!(usage.family("a").unwrap().unwrap().invalid);
    let mut expected = resident.resident().unwrap().clone();
    expected.remove("c");
    expected.get_mut("a").unwrap().invalid = true;
    assert_eq!(
        summary(&usage),
        summary(&UsagePending::from(expected.clone()))
    );
    assert_eq!(
        usage.total_occurrences(),
        UsagePending::from(expected).total_occurrences()
    );
}

/// [money] a page accumulates only into loaded families: an unloaded stored
/// family refuses, a removed family stays removed, a row whose digest is not
/// the head's is Unknown, and a new family joins the loaded set.
#[test]
fn cold_pages_accumulate_only_into_loaded_families() {
    let rows = resident();
    let mut usage = cold(&["a", "b", "c", "d"]);
    assert_eq!(usage.unloaded(["a", "z"]), BTreeSet::from(["a".to_owned()]));
    let cold_usage = usage.cold_mut().unwrap();
    assert_eq!(
        cold_usage.install("a".into(), rows["a"].clone(), [0; 32]),
        Err(Unknown)
    );
    cold_usage
        .install("a".into(), rows["a"].clone(), digest(&rows["a"]))
        .unwrap();
    usage.discard("b");
    usage
        .cold_mut()
        .unwrap()
        .install("b".into(), rows["b"].clone(), digest(&rows["b"]))
        .unwrap();
    assert!(!usage.contains_key("b"));
    let page = usage.page_mut(["a", "new"]).unwrap();
    page.insert("new".into(), family("w1", 2, false));
    assert_eq!(usage.len(), 4);
    assert_eq!(usage.total_occurrences(), 3 + 6 + 1);
    assert!(usage.unloaded(["a", "new"]).is_empty());
    // A committed save refreshes the loaded heads from the stored digests.
    let committed = |root: &str| (root != "new").then(|| digest(&rows[root]));
    usage.cold_mut().unwrap().saved(committed);
    assert_eq!(
        usage.cold().unwrap().head("a").unwrap().digest,
        digest(&rows["a"])
    );
    assert!(usage.cold().unwrap().head("new").is_none());
}

/// [behaviour] a cold family's retained heap does not grow with its stored
/// evidence: one family or two hundred history families plus the same page
/// family keep equal heap per head once only the page family is loaded.
#[test]
fn cold_usage_heap_does_not_grow_with_stored_evidence() {
    use crate::heap_layout_bound::HeapLayoutBound;
    let heap = |usage: &UsagePending| {
        let mut counter = crate::heap_layout_bound::Counter::new(usize::MAX);
        usage.heap_bound(&mut counter).map(|()| counter.bytes)
    };
    let page = family("w1", 3, false);
    let with = |members: u64| {
        let history = family("w0", members, false);
        let mut cold = ColdUsage::default();
        cold.fold("history", &history, digest(&history));
        cold.fold("page", &page, digest(&page));
        cold.install("page".into(), page.clone(), digest(&page))
            .unwrap();
        UsagePending::Cold(Box::new(cold))
    };
    let small = with(1);
    let large = with(200);
    // Heads keep member names and counts only: no request hash or
    // occurrence of the history family is resident.
    if crate::heap_layout_bound::layout_supported() {
        let (small, large) = (heap(&small).unwrap(), heap(&large).unwrap());
        let resident = heap(&UsagePending::from(Families::from([(
            "history".to_owned(),
            family("w0", 200, false),
        )])))
        .unwrap();
        assert!(large - small < resident / 4, "{small} {large} {resident}");
    }
    assert_eq!(small.cold().unwrap().loaded().len(), 1);
    assert_eq!(large.cold().unwrap().loaded().len(), 1);
}
