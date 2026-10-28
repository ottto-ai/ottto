//! E3 (B17 path A): a late identity permit re-owes no history. The
//! `STAMPED_WITHOUT_PERMIT` bit records which revision-3 bodies were stamped
//! without the permit; it is seeded once by money-rule version 2, follows the
//! entry a partial save keeps, and is disclosed by counts only.

use super::claude_history_upgrade::{GatedHistory, HistoryHold};
use super::claude_money_birth_store::location_key;
use super::claude_request_money::e2::{apply_money_rules, money_mark};
use super::*;
use crate::local_resource_diagnostics::claude_reread;

const PERMIT: u8 = money_mark::STAMPED_WITHOUT_PERMIT;

fn entry(revision: u64, fingerprint: &str) -> ScanIndexEntry {
    let mut entry: ScanIndexEntry = serde_json::from_value(serde_json::json!({
        "size_bytes": 1,
        "modified_unix_seconds": 1,
        "source_file_fingerprint": fingerprint,
    }))
    .unwrap();
    entry.effective_upload_body_witness_revision = revision;
    entry
}

fn at_revision_three() -> ScanIndex {
    ScanIndex {
        active_effective_upload_body_witness_revision: 3,
        ..ScanIndex::default()
    }
}

fn marks(index: &ScanIndex, key: &str) -> u8 {
    index
        .claude_money_birth_store
        .money_marks(location_key(key))
}

fn temp(name: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!("permit-mark-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).unwrap();
    path
}

/// Lead B's migration ruling: an adopted record (E2 or adoption pending)
/// marks nothing; every other record counts as "" and marks every revision-3
/// Claude file once, keeping its other marks. The version is durable, so a
/// later load never re-initializes, whatever its record.
#[test]
fn version_two_seeds_the_permit_mark_once_from_the_loaded_record() {
    let (three, two) = ("/p/three.jsonl", "/p/two.jsonl");
    let root = temp("migration");
    let file = root.join("index.json");
    for (record, seeded) in [
        (Some(claude_request_identity::E2_GROUPING), false),
        (Some(CLAUDE_E2_IDENTITY_ADOPTION_PENDING), false),
        (Some(""), true),
        (
            Some(CLAUDE_REQUEST_IDENTITY_CONTRACT_CHANGED_MID_TRAVERSAL),
            true,
        ),
        (None, true),
        (Some(claude_request_identity::COLLECTOR), true),
        (Some("unknown-contract"), true),
    ] {
        let mut index = at_revision_three();
        index.files.insert(three.into(), entry(3, "three"));
        index.files.insert(two.into(), entry(2, "two"));
        let store = &mut index.claude_money_birth_store;
        store.set_money_rule_version(1);
        store.set_money_marks(three, money_mark::ESTIMATED);
        index.claude_request_identity_contract = record.map(str::to_owned);
        let reowed = history_local_count(HistoryLocalCount::Reowed);
        apply_money_rules(&mut index);
        assert_eq!(
            history_local_count(HistoryLocalCount::Reowed),
            reowed,
            "{record:?}: a zero-mask row re-owes nothing"
        );
        assert_eq!(index.files[three].effective_upload_body_witness_revision, 3);
        let seeded_mark = if seeded { PERMIT } else { 0 };
        assert_eq!(
            marks(&index, three),
            money_mark::ESTIMATED | seeded_mark,
            "{record:?}"
        );
        assert_eq!(marks(&index, two), 0, "{record:?}: only revision 3");
        assert_eq!(index.claude_money_birth_store.money_rule_version(), 2);

        index.save(&file).unwrap();
        for reload_record in [None, Some(""), Some("unknown-contract")] {
            let mut loaded = ScanIndex::load(&file).unwrap();
            assert_eq!(marks(&loaded, three), money_mark::ESTIMATED | seeded_mark);
            // A restart while the permit is off must not re-mark clean history.
            loaded
                .claude_money_birth_store
                .set_money_mark(three, PERMIT, false);
            loaded.claude_request_identity_contract = reload_record.map(str::to_owned);
            apply_money_rules(&mut loaded);
            assert_eq!(marks(&loaded, three), money_mark::ESTIMATED, "{record:?}");
        }
    }
    std::fs::remove_dir_all(root).unwrap();
}

/// The bit describes the stamped body of the entry a save keeps. A partial
/// save never revives a bit this page consumed (BS `preserve_missing_from`),
/// a restored entry takes its committed bit back, and other marks keep their
/// existing preservation.
#[test]
fn the_permit_mark_follows_the_entry_a_partial_save_keeps() {
    // accepted: committed with the bit, restamped under the permit, settled.
    // rejected: committed with the bit, restamped under the permit, unsettled.
    // fresh: committed without it, restamped without the permit, unsettled.
    let (accepted, rejected, fresh) = ("/p/accepted.jsonl", "/p/rejected.jsonl", "/p/fresh.jsonl");
    let mut previous = at_revision_three();
    for key in [accepted, rejected, fresh] {
        previous.files.insert(key.into(), entry(2, key));
    }
    let store = &mut previous.claude_money_birth_store;
    store.set_money_marks(accepted, PERMIT | money_mark::ESTIMATED);
    store.set_money_marks(rejected, PERMIT);
    let mut working = previous.clone();
    for key in [accepted, rejected, fresh] {
        working
            .files
            .get_mut(key)
            .unwrap()
            .effective_upload_body_witness_revision = 3;
    }
    let store = &mut working.claude_money_birth_store;
    store.set_money_marks(accepted, 0);
    store.set_money_marks(rejected, 0);
    store.set_money_mark(fresh, PERMIT, true);
    for (key, body) in [(rejected, "rejected-body"), (fresh, "fresh-body")] {
        working
            .file_snapshot_fingerprints
            .insert(key.into(), BTreeSet::from([body.to_owned()]));
    }
    let held = BTreeSet::from(["rejected-body".to_owned(), "fresh-body".to_owned()]);
    let subset = working.committable_subset(&previous, &BTreeSet::new(), &BTreeMap::new());
    let oracle = working.with_locally_held_keys_reverted(&previous, &held, &BTreeSet::new());
    let reverted =
        working
            .clone()
            .into_locally_held_keys_reverted(&previous, &held, &BTreeSet::new());
    for saved in [&subset, &oracle, &reverted] {
        assert_eq!(
            marks(saved, accepted),
            money_mark::ESTIMATED,
            "a consumed bit stays consumed; other marks are preserved"
        );
        assert_eq!(
            marks(saved, rejected),
            PERMIT,
            "restored entry, restored bit"
        );
        assert_eq!(marks(saved, fresh), 0, "restored entry, committed bit");
        assert_eq!(
            saved.files[accepted].effective_upload_body_witness_revision,
            3
        );
        assert_eq!(
            saved.files[rejected].effective_upload_body_witness_revision,
            2
        );
    }
    // The settled save keeps the working bits unchanged.
    let settled = working.committable_subset(&previous, &held, &BTreeMap::new());
    assert_eq!(marks(&settled, accepted), money_mark::ESTIMATED);
    assert_eq!(marks(&settled, rejected), 0);
    assert_eq!(marks(&settled, fresh), PERMIT);
}

/// A late permit (also observed twice, as prepare and scan start do) lowers
/// no revision and keeps every mark; the contract record and its latch are
/// unchanged from before. Off/on/off/on stays the same.
#[test]
fn a_late_identity_permit_lowers_no_revision() {
    claude_request_identity::with_cycle_contract_for_test(
        claude_request_identity::E2_GROUPING,
        || {
            let key = "/p/session.jsonl";
            let mut index = at_revision_three();
            index.files.insert(key.into(), entry(3, "session"));
            index
                .claude_money_birth_store
                .set_money_marks(key, PERMIT | money_mark::DISCLOSED);
            index.claude_request_identity_contract = Some(String::new());
            let reowed = history_local_count(HistoryLocalCount::Reowed);
            for permitted in [true, true, false, true, false, true, true] {
                index.observe_claude_request_identity_contract(permitted);
                assert_eq!(index.files[key].effective_upload_body_witness_revision, 3);
                assert_eq!(marks(&index, key), PERMIT | money_mark::DISCLOSED);
            }
            assert_eq!(history_local_count(HistoryLocalCount::Reowed), reowed);
            assert_eq!(
                index.claude_request_identity_contract_for_test(),
                (Some(claude_request_identity::E2_GROUPING), true)
            );
        },
    );
}

/// Counts only: the gauge, and each upgrade the gate permitted that did not
/// stamp, by hold. A decide-time hold and a literal-only denial were never
/// permitted; a stamped upgrade a partial save does not commit is
/// `not_accepted`.
#[test]
fn permit_debt_counts_classify_permitted_upgrades() {
    let mut index = at_revision_three();
    let gated = |key: &str, held, permitted, literal_denied| GatedHistory {
        index_key: key.into(),
        held,
        permitted,
        literal_denied,
        ..GatedHistory::default()
    };
    for (key, revision, gate) in [
        (
            "/p/stamped.jsonl",
            3,
            gated("/p/stamped.jsonl", None, true, false),
        ),
        (
            "/p/telemetry.jsonl",
            2,
            gated(
                "/p/telemetry.jsonl",
                Some(HistoryHold::TelemetryUnread),
                true,
                false,
            ),
        ),
        (
            "/p/latched.jsonl",
            2,
            gated("/p/latched.jsonl", Some(HistoryHold::Latched), true, false),
        ),
        (
            "/p/other.jsonl",
            2,
            gated("/p/other.jsonl", None, true, false),
        ),
        (
            "/p/budget.jsonl",
            2,
            gated("/p/budget.jsonl", Some(HistoryHold::Budget), false, false),
        ),
        (
            "/p/literal.jsonl",
            2,
            gated("/p/literal.jsonl", None, false, true),
        ),
    ] {
        index.files.insert(key.into(), entry(revision, key));
        index.claude_history_emission.files.insert(key.into(), gate);
    }
    index
        .claude_money_birth_store
        .set_money_mark("/p/stamped.jsonl", PERMIT, true);
    index
        .claude_money_birth_store
        .set_money_mark("/p/other.jsonl", PERMIT, true);
    let scope = claude_reread::Scope::begin(true);
    index.note_claude_permit_debt();
    index.note_claude_permit_debt();
    let counts = scope.finish().claude_reread;
    assert_eq!(counts.stamped_without_permit, 2, "a gauge, not a sum");
    assert_eq!(counts.history_permitted_not_stamped_telemetry_unread, 2);
    assert_eq!(counts.history_permitted_not_stamped_held, 2);
    assert_eq!(counts.history_permitted_not_stamped_other, 2);
    assert_eq!(counts.history_permitted_not_stamped_not_accepted, 0);

    let mut previous = index.clone();
    previous
        .files
        .get_mut("/p/stamped.jsonl")
        .unwrap()
        .effective_upload_body_witness_revision = 2;
    index.file_snapshot_fingerprints.insert(
        "/p/stamped.jsonl".into(),
        BTreeSet::from(["unsent".to_owned()]),
    );
    let scope = claude_reread::Scope::begin(true);
    let saved = index.committable_subset(&previous, &BTreeSet::new(), &BTreeMap::new());
    let counts = scope.finish().claude_reread;
    assert_eq!(counts.history_permitted_not_stamped_not_accepted, 1);
    assert_eq!(
        saved.files["/p/stamped.jsonl"].effective_upload_body_witness_revision,
        2
    );
    let value = serde_json::to_value(counts).unwrap();
    assert_eq!(value["history_permitted_not_stamped_not_accepted"], 1);
    assert!(value.get("stamped_without_permit").is_none(), "sparse");
}
