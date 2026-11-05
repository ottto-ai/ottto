//! Native skip eligibility and fallback controls.
use super::*;

fn pair() -> (PathBuf, PathBuf, ScanIndex) {
    let dir = scratch("subagent-twin-proof");
    let paths = ["a", "z"].map(|home| dir.join(home).join(ROOT).join("subagents/agent-a1.jsonl"));
    let mut index = ScanIndex::default();
    let member = format!("{ROOT}_agent-a1");
    for (n, path) in paths.iter().enumerate() {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, b"fixture\n").unwrap();
        let key = local_index_key(path);
        index.files.insert(key.clone(), entry());
        index.claude_money_birth_store.record_observation(
            &member,
            &key,
            t0() + n as i128 * 100_000_000_000,
        );
    }
    (paths[0].clone(), paths[1].clone(), index)
}

/// [money] A settled, grandfathered child retains its exact accepted body
/// on a new native read; the new twin decision never restores its prefix.
#[test]
fn grandfathered_twin_keeps_accepted_body_on_reread() {
    let (a, z, mut index) = pair();
    let key = local_index_key(&z);
    index
        .claude_money_birth_store
        .set_money_marks(&key, money_mark::COPY);
    crate::snapshots::e2_pipeline_scan_fixture::origin_accepted_for_test(&mut index, &key);
    let copied = line("shared", &at(10), 10);
    let lines = [copied.clone(), line("own", &at(130), 20)];
    let read = |index: &ScanIndex| {
        let original = parse_undecided(&a, Some(t0()), index, std::slice::from_ref(&copied));
        let copy = parse_undecided(&z, Some(t0() + 100_000_000_000), index, &lines);
        assert!(fold(&copy).grandfathered);
        assert!(!fold(&copy).twin_pending);
        publish(vec![original, copy], None, TelemetryRead::NotRead, index)
    };
    let accepted = read(&index);
    assert_eq!(
        (accepted[0].request_count, accepted[0].removed_request_count),
        (2, Some(1))
    );
    let acks = crate::snapshots::e2_pipeline_scan_fixture::exact_acks_for_test(&accepted);
    index.activate_upload_context("twin-proof-context".into());
    crate::snapshots::e2_pipeline_scan_fixture::accept_upload_context_acks_for_test(
        &mut index, &accepted, &acks,
    );
    let reread = read(&index);
    assert_eq!(
        serde_json::to_value(&reread).unwrap(),
        serde_json::to_value(&accepted).unwrap()
    );
    assert_eq!(
        crate::snapshots::e2_pipeline_scan_fixture::exact_acks_for_test(&reread),
        acks
    );
    fs::remove_dir_all(a.ancestors().nth(4).unwrap()).unwrap();
}

/// [money] A duplicated copied id, including an own response with that id,
/// restores all native grains exactly like a lone child's old counted path.
#[test]
fn ambiguous_copy_uses_restore_all() {
    for own in [false, true] {
        let (a, z, index) = pair();
        let first = line("shared", &at(10), 10);
        let mut second = line("shared", &at(if own { 130 } else { 20 }), 20);
        second["message"]["id"] = json!("another-response");
        let lines = [first, second];
        let control = parse_undecided(
            &z,
            Some(t0() + 100_000_000_000),
            &ScanIndex::default(),
            &lines,
        );
        let mut actual = vec![parse_undecided(
            &z,
            Some(t0() + 100_000_000_000),
            &index,
            &lines,
        )];
        assert!(!fold(&actual[0]).ambiguous.is_empty());
        assert!(!fold(&actual[0]).twin_pending);
        decide_page_copies(&mut actual, &index, None);
        let decided = fold(&actual[0]);
        assert_eq!(decided.entity.totals(), fold(&control).entity.totals());
        assert_eq!(decided.entity.removed_requests, 0);
        assert!(decided.entity.certificate_ok && !decided.entity.held);
        fs::remove_dir_all(a.ancestors().nth(4).unwrap()).unwrap();
    }
}

/// [money] Timestamp eligibility alone is insufficient: a present earlier
/// fold must hold the id. Missing/unreadable paths prove no removal either.
#[test]
fn eligible_copy_without_a_holder_counts() {
    for state in ["lacks", "absent", "unreadable"] {
        let (a, z, mut index) = pair();
        let born = SUBAGENT_TWIN_FROM + 600_000_000_000;
        let member = format!("{ROOT}_agent-a1");
        index.claude_money_birth_store = Default::default();
        for (path, birth) in [(&a, SUBAGENT_TWIN_FROM - 1), (&z, born)] {
            index.claude_money_birth_store.record_observation(
                &member,
                &local_index_key(path),
                birth,
            );
        }
        let request = line("eligible", "2026-11-05T00:01:00Z", 10);
        let mut items = Vec::new();
        if state == "lacks" {
            items.push(parse_undecided(
                &a,
                Some(SUBAGENT_TWIN_FROM - 1),
                &index,
                &[line("other", "2026-11-05T00:01:00Z", 5)],
            ));
        } else {
            fs::remove_file(&a).unwrap();
            if state == "unreadable" {
                fs::create_dir(&a).unwrap();
                assert!(fs::read_to_string(&a).is_err());
            }
        }
        items.push(parse_undecided(&z, Some(born), &index, &[request]));
        assert!(fold(items.last().unwrap()).twin_pending);
        decide_page_copies(&mut items, &index, None);
        let copy = fold(items.last().unwrap());
        assert_eq!(
            (
                copy.entity.totals().1,
                copy.entity.removed_requests,
                copy.copied
            ),
            (1, 0, 0)
        );
        let body = publish(items, None, TelemetryRead::NotRead, &index);
        assert_eq!(body[0].request_count, if state == "lacks" { 2 } else { 1 });
        fs::remove_dir_all(a.ancestors().nth(4).unwrap()).unwrap();
    }
}
