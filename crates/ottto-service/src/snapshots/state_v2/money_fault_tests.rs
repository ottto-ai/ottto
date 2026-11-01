//! Cross-kind custody faults use the composed mapper, never a partial graph.
use super::super::scan_index_persistence::Source;
use super::*;
use serde_json::json;
use std::collections::BTreeMap;

fn fixture() -> ScanIndex {
    let shaped: serde_json::Value = serde_json::from_str(include_str!(
        "../../../tests/fixtures/scan_index/real-shaped-v1.json"
    ))
    .unwrap();
    let mut raw = shaped["logical"].clone();
    raw["generation"] = json!(0);
    raw["claude_request_census"]["same-census"] =
        raw["claude_request_census"]["synthetic-file"].clone();
    raw["claude_usage_family_pending"]["synthetic-family"]["member_request_id_hashes"]
        ["same-member"] = raw["claude_usage_family_pending"]["synthetic-family"]
        ["member_request_id_hashes"]["synthetic-file"]
        .clone();
    raw["claude_account_family_pending"]["synthetic-family"]["v"] =
        json!("claude_account_request_set:v2");
    raw["claude_account_family_pending"]["synthetic-family"]["r"] =
        json!({"synthetic-file":format!(":{}:{}", "b".repeat(64), "c".repeat(64))});
    raw["claude_retired_family_tombstones"] = json!({"a".repeat(64):u64::MAX});
    raw["claude_retired_family_tombstones_initialized"] = json!(true);
    // MISC multi-segment scalar alongside FILES, ACCOUNTS and CENSUS owners.
    raw["upload_context_fingerprint"] = json!("x".repeat(3 * 64 * 1024 + 17));
    serde_json::from_value(raw).unwrap()
}

struct Bytes(Vec<u8>);
impl Value for Bytes {
    fn write(&self, out: &mut dyn Write) -> Result<()> {
        out.write_all(&self.0)?;
        Ok(())
    }
}
pub(super) fn headers(tx: &mut impl Transaction, table: Table) -> Vec<Header> {
    let mut all = Vec::new();
    let mut after = None;
    loop {
        let page = tx
            .scan_prefix(RowPrefix { table }, after.as_ref(), 32)
            .unwrap();
        if page.is_empty() {
            break;
        }
        after = page.last().map(|h| h.key.clone());
        all.extend(page);
    }
    all
}
fn assert_refs(db: &mut sqlite::Sqlite) -> BTreeMap<RowKey, u64> {
    let mut tx = db.begin(TxnMode::Read).unwrap();
    let mut expected = BTreeMap::<RowKey, u64>::new();
    for h in headers(&mut tx, Table::Records) {
        let mut bytes = Vec::new();
        tx.read_value(&h, &mut bytes).unwrap();
        kinds::references(&h, &Bytes(bytes), &mut |key| {
            *expected.entry(key.clone()).or_default() += 1;
            Ok(())
        })
        .unwrap();
    }
    let actual = headers(&mut tx, Table::RequestSets)
        .into_iter()
        .map(|h| {
            let Fixed::RequestSet { refs, .. } = h.fixed else {
                panic!("shared header")
            };
            (h.key, refs)
        })
        .collect::<BTreeMap<_, _>>();
    assert_eq!(
        actual, expected,
        "all cross-kind edges, repeated refs, and zero-ref reclamation"
    );
    actual
}

/// [money] money presence empty null zero and tombstones survive all kind hydration.
#[test]
fn money_presence_empty_null_zero_and_tombstones_survive_all_kind_hydration() {
    let scratch = crate::test_scratch::ScratchDir::canonical("money-presence");
    for (n, value) in [None, Some(serde_json::Value::Null), Some(json!(0))]
        .into_iter()
        .enumerate()
    {
        let mut raw = serde_json::to_value(fixture()).unwrap();
        raw["accepted_snapshot_fingerprints"] = json!([]);
        raw["confirmed_empty_files"] = json!([]);
        raw["claude_usage_family_pending"]["empty-family"] =
            json!({"census_window_end":"", "member_request_id_hashes":{}, "invalid":false});
        raw["snapshot_activity_at"] = json!({"absent-time":null,"empty-time":""});
        if let Some(value) = &value {
            raw["claude_history_cutoff_unix_seconds"] = value.clone();
        } else {
            raw.as_object_mut()
                .unwrap()
                .remove("claude_history_cutoff_unix_seconds");
        }
        let index: ScanIndex = serde_json::from_value(raw).unwrap();
        let presence = BTreeMap::from([
            ("claude_history_cutoff_unix_seconds".into(), value.is_some()),
            ("accepted_snapshot_fingerprints".into(), true),
        ]);
        let mut db = money_test_support::populate(
            &scratch.join(format!("presence-{n}.v2.sqlite.import")),
            &index,
            presence.clone(),
        );
        let (restored, cx) =
            kinds::hydrate(&mut db, money_test_support::binding(Source::Claude)).unwrap();
        let mut expected = index;
        expected.generation = 1;
        assert_eq!(
            serde_json::to_vec(&restored).unwrap(),
            serde_json::to_vec(&expected).unwrap()
        );
        for (field, present) in presence {
            assert_eq!(cx.presence.get(&field), Some(&present), "{field}");
        }
        assert_refs(&mut db);
    }
}

/// [money] money missing owner tombstone or segment refuses complete hydration.
#[test]
fn money_missing_owner_tombstone_or_segment_refuses_complete_hydration() {
    for kind in [
        "v1_field.census_shadow",
        "tombstone.claude_retired_family_tombstones",
        "account.current",
        "usage.pending",
        "family.requests",
        "file.entities",
        "setting.upload_context_fingerprint",
        "accepted.entity",
    ] {
        let scratch = crate::test_scratch::ScratchDir::canonical("money-missing-owner");
        let mut db = money_test_support::populate(
            &scratch.join("missing.v2.sqlite.import"),
            &fixture(),
            BTreeMap::new(),
        );
        assert!(import::hydrate_context(&mut db).is_ok());
        let mut tx = db.begin(TxnMode::Write).unwrap();
        let mut rows = tx
            .scan_kind(&RecordKind::parse(kind).unwrap(), None, 64)
            .unwrap();
        assert!(!rows.is_empty(), "fixture must exercise {kind}");
        // Remove a middle scalar segment; for membership kinds remove an
        // owner/member that the manifest still commits to.
        let h = rows.remove(rows.len() / 2);
        assert!(tx.delete(&h.key).unwrap());
        assert_eq!(tx.commit(1, 2), DurableCommitOutcome::Committed(2));
        assert!(
            import::hydrate_context(&mut db).is_err(),
            "missing {kind} must not look like empty custody"
        );
    }
}

/// [money] money ref diffs rollback and commit across accounts census and family membership.
#[test]
fn money_ref_diffs_rollback_and_commit_across_accounts_census_and_family_membership() {
    let scratch = crate::test_scratch::ScratchDir::canonical("money-ref-diff");
    let mut db = money_test_support::populate(
        &scratch.join("refs.v2.sqlite.import"),
        &fixture(),
        BTreeMap::new(),
    );
    let before = assert_refs(&mut db);
    assert!(
        before.values().any(|refs| *refs >= 2),
        "real deduplicated evidence"
    );
    let (prev, _) = kinds::hydrate(&mut db, money_test_support::binding(Source::Claude)).unwrap();
    let mut raw = serde_json::to_value(&prev).unwrap();
    raw["claude_request_census"]
        .as_object_mut()
        .unwrap()
        .remove("same-census");
    raw["claude_usage_family_pending"]["synthetic-family"]["member_request_id_hashes"]
        .as_object_mut()
        .unwrap()
        .remove("same-member");
    raw["claude_account_family_pending"] = json!({});
    let mut next: ScanIndex = serde_json::from_value(raw).unwrap();
    next.generation = 2;
    for commit in [false, true] {
        let (_, mut cx) =
            kinds::hydrate(&mut db, money_test_support::binding(Source::Claude)).unwrap();
        let baseline = kinds::baseline(&prev, &mut cx).unwrap();
        let mut tx = db.begin(TxnMode::Write).unwrap();
        kinds::delta(baseline, &next, &mut tx, &mut cx).unwrap();
        if commit {
            let outcome = tx.commit(1, 2);
            assert_eq!(outcome, DurableCommitOutcome::Committed(2));
        } else {
            drop(tx);
        }
        let counts = assert_refs(&mut db);
        let restored = money_test_support::hydrate_resident(&mut db);
        assert_eq!(
            serde_json::to_vec(&restored).unwrap(),
            serde_json::to_vec(if commit { &next } else { &prev }).unwrap()
        );
        if commit {
            assert!(counts.values().sum::<u64>() < before.values().sum::<u64>());
        } else {
            assert_eq!(counts, before);
        }
    }
}

/// [money] money missing shared value refuses instead of losing request membership.
#[test]
fn money_missing_shared_value_refuses_instead_of_losing_request_membership() {
    let scratch = crate::test_scratch::ScratchDir::canonical("money-missing-ref");
    let mut db = money_test_support::populate(
        &scratch.join("missing-ref.v2.sqlite.import"),
        &fixture(),
        BTreeMap::new(),
    );
    let all = assert_refs(&mut db);
    assert!(
        all.len() >= 3,
        "independent account, census-prefix and full-hash domains"
    );
    for key in all.keys() {
        let mut tx = db.begin(TxnMode::Write).unwrap();
        assert!(tx.delete(key).unwrap());
        assert!(
            kinds::hydrate_txn(&mut tx, money_test_support::binding(Source::Claude)).is_err(),
            "{key:?}"
        );
        drop(tx); // Preserve evidence for the next domain's fault.
    }
    assert_eq!(assert_refs(&mut db), all);
}

/// [money] money 915 lost saturated and unknown copy classes pause before any baseline.
#[test]
fn money_915_lost_saturated_and_unknown_copy_classes_pause_before_any_baseline() {
    let scratch = crate::test_scratch::ScratchDir::canonical("money-unmapped");
    let path = scratch.join("claude_code-scan-index.json");
    std::fs::write(&path, br#"{"schema_version":2,"files":{}}"#).unwrap();
    assert!(
        import::inventory_context(&path).is_ok(),
        "valid original must reach inventory"
    );
    // #915 has no mapper on this main: every prospective representation is
    // refused by original inventory, while its v1 bytes stay available. The
    // mapped #938 copy removals pause only when malformed; checked CCR2 passes.
    for (field, value, expected, case) in [
        (
            "claude_request_census",
            json!({"~lost":["synthetic-file"]}),
            Err(import::Pause::UnknownClass),
            "unmapped",
        ),
        (
            "claude_request_census",
            json!({"~saturated":true}),
            Err(import::Pause::UnknownClass),
            "unmapped",
        ),
        (
            "claude_census_money_marks",
            json!({"lost":["synthetic-file"],"saturated":true}),
            Err(import::Pause::UnknownClass),
            "unmapped",
        ),
        (
            "claude_copy_removals",
            json!({"synthetic-file":1}),
            Err(import::Pause::UnknownClass),
            "malformed mapped",
        ),
        (
            "claude_copy_removals",
            json!(money_test_support::CCR2_DEFINITE),
            Ok(()),
            "checked mapped",
        ),
    ] {
        let mut raw = json!({"schema_version":2,"files":{}});
        raw[field] = value;
        let bytes = serde_json::to_vec(&raw).unwrap();
        std::fs::write(&path, &bytes).unwrap();
        assert_eq!(
            import::inventory_context(&path).map(|_| ()),
            expected,
            "{case} {field}"
        );
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
        for suffix in [".v1-readonly", ".v2.sqlite.import", ".v2.sqlite"] {
            assert!(!fence::sibling(&path, suffix).exists());
        }
    }
}

/// [money] money unknown registered marks refuse even with zero length payload.
#[test]
fn money_unknown_registered_marks_refuse_even_with_zero_length_payload() {
    let scratch = crate::test_scratch::ScratchDir::canonical("money-unknown-kind");
    let mut db = money_test_support::populate(
        &scratch.join("unknown.v2.sqlite.import"),
        &fixture(),
        BTreeMap::new(),
    );
    let mut tx = db.begin(TxnMode::Write).unwrap();
    tx.put(RowInput {
        key: &RowKey::record("v1_field.census_money_marks", Vec::new(), 0).unwrap(),
        fixed: &Fixed::None,
        value_version: 1,
        value: &[],
    })
    .unwrap();
    assert_eq!(tx.commit(1, 2), DurableCommitOutcome::Committed(2));
    assert!(import::hydrate_context(&mut db).is_err());
}

/// [money] money large memberships segment and preserve exact shared domains.
#[test]
fn money_large_memberships_segment_and_preserve_exact_shared_domains() {
    use sha2::Digest;
    let scratch = crate::test_scratch::ScratchDir::canonical("money-segmented");
    let mut raw = serde_json::to_value(fixture()).unwrap();
    let mut members = serde_json::Map::new();
    let hashes = (0_u64..12_000)
        .map(|n| {
            let hash = format!("{:x}", sha2::Sha256::digest(n.to_be_bytes()));
            members.insert(hash.clone(), json!(1));
            hash
        })
        .collect::<Vec<_>>();
    raw["claude_account_family_pending"]["synthetic-family"]["members"] = members.into();
    raw["claude_usage_family_pending"]["synthetic-family"]["member_request_id_hashes"]
        ["synthetic-file"] = json!(hashes);
    raw["file_snapshot_fingerprints"]["synthetic-file"] = json!(hashes);
    raw["upload_context_fingerprint"] = json!(hashes.join(""));
    let index: ScanIndex = serde_json::from_value(raw).unwrap();
    let mut db = money_test_support::populate(
        &scratch.join("segments.v2.sqlite.import"),
        &index,
        BTreeMap::new(),
    );
    let restored = money_test_support::hydrate_resident(&mut db);
    let mut expected = index;
    expected.generation = 1;
    assert_eq!(
        serde_json::to_vec(&restored).unwrap(),
        serde_json::to_vec(&expected).unwrap()
    );
    assert_refs(&mut db);
    // Remove a physical chunk from each independent money domain inside a
    // rolled-back transaction, then prove the complete original still opens.
    for kind in [
        "account_window",
        "file.entities",
        "setting.upload_context_fingerprint",
    ] {
        let mut tx = db.begin(TxnMode::Write).unwrap();
        let rows = tx
            .scan_kind(&RecordKind::parse(kind).unwrap(), None, 128)
            .unwrap();
        let row = rows
            .iter()
            .find(|row| row.parts > 1)
            .unwrap_or_else(|| panic!("{kind} fixture must span physical chunks"));
        sqlite::remove_value_chunk(&tx, row);
        assert!(
            kinds::hydrate_txn(&mut tx, money_test_support::binding(Source::Claude)).is_err(),
            "missing {kind} segment"
        );
        drop(tx);
    }
    assert_eq!(
        serde_json::to_vec(&money_test_support::hydrate_resident(&mut db)).unwrap(),
        serde_json::to_vec(&expected).unwrap()
    );
}
