//! Contract-5 cutover (SOURCE §B): contract 5 is always on for Claude Code.
//! The identity permit and #825's `STAMPED_WITHOUT_PERMIT` machinery are
//! retired. Old stores keep decoding the retired bit (64), which is never
//! set, cleared or replayed; money-rule version 2 keeps its meaning; a
//! contract change re-owes nothing; caps are unchanged.

use super::claude_history_upgrade::{GatedHistory, HistoryHold};
use super::claude_money_birth_store::location_key;
use super::claude_request_money::e2::{apply_money_rules, money_mark};
use super::*;
use crate::local_resource_diagnostics::claude_reread;

/// #825's `STAMPED_WITHOUT_PERMIT`, retired: decoded, never acted on.
const RETIRED_PERMIT_MARK: u8 = 64;

// Lead B / SOURCE: the contract-5 caps stay exactly as they were.
const _: () = assert!(
    claude_request_identity::MAX_AUTHORITY_KEYS == 16
        && claude_request_identity::MAX_PARTS_PER_ROW == 17
        && claude_request_identity::MAX_PARTS_PER_ITEM == 2_048
        && claude_request_identity::MAX_ITEM_BYTES == 640 * 1024
);

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
    let path =
        std::env::temp_dir().join(format!("contract5-cutover-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).unwrap();
    path
}

/// Money-rule version 2 stays a zero-mask row: from version 1 it re-owes
/// nothing and, whatever the loaded contract record, sets no mark. Was
/// `version_two_seeds_the_permit_mark_once_from_the_loaded_record`, whose
/// non-adopted records seeded `STAMPED_WITHOUT_PERMIT` on every revision-3
/// file.
#[test]
fn version_two_reowes_nothing_and_seeds_no_mark() {
    let (three, two) = ("/p/three.jsonl", "/p/two.jsonl");
    for record in [
        Some(claude_request_identity::E2_GROUPING),
        Some(CLAUDE_E2_IDENTITY_ADOPTION_PENDING),
        Some(""),
        Some(CLAUDE_REQUEST_IDENTITY_CONTRACT_CHANGED_MID_TRAVERSAL),
        None,
        Some(claude_request_identity::COLLECTOR),
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
            "{record:?}"
        );
        assert_eq!(index.files[three].effective_upload_body_witness_revision, 3);
        assert_eq!(marks(&index, three), money_mark::ESTIMATED, "{record:?}");
        assert_eq!(marks(&index, two), 0, "{record:?}");
        assert_eq!(index.claude_money_birth_store.money_rule_version(), 2);
    }
}

/// A store written by a #825 build may carry the retired bit. It decodes
/// unchanged through a save and load, a money-rule pass re-owes nothing for
/// it, and the contract latch neither clears nor replays it.
#[test]
fn a_retired_permit_bit_is_decoded_and_never_replayed() {
    let root = temp("retired-bit");
    let (marked, plain) = ("/p/marked.jsonl", "/p/plain.jsonl");
    for stored_version in [1, 2] {
        let file = root.join(format!("index-v{stored_version}.json"));
        let mut index = at_revision_three();
        index.files.insert(marked.into(), entry(3, "marked"));
        index.files.insert(plain.into(), entry(3, "plain"));
        let store = &mut index.claude_money_birth_store;
        store.set_money_rule_version(stored_version);
        store.set_money_marks(marked, RETIRED_PERMIT_MARK | money_mark::DISCLOSED);
        index.claude_request_identity_contract = Some(String::new());
        index.save(&file).unwrap();
        let mut loaded = ScanIndex::load(&file).unwrap();
        assert_eq!(
            marks(&loaded, marked),
            RETIRED_PERMIT_MARK | money_mark::DISCLOSED,
            "v{stored_version}: decoded as stored"
        );
        let reowed = history_local_count(HistoryLocalCount::Reowed);
        apply_money_rules(&mut loaded);
        loaded.observe_claude_request_identity_contract(true);
        loaded.observe_claude_request_identity_contract(true);
        assert_eq!(history_local_count(HistoryLocalCount::Reowed), reowed);
        for key in [marked, plain] {
            assert_eq!(loaded.files[key].effective_upload_body_witness_revision, 3);
        }
        assert_eq!(
            marks(&loaded, marked),
            RETIRED_PERMIT_MARK | money_mark::DISCLOSED,
            "v{stored_version}: never cleared or replayed"
        );
        assert_eq!(marks(&loaded, plain), 0, "never set");
        assert_eq!(loaded.claude_money_birth_store.money_rule_version(), 2);
    }
    std::fs::remove_dir_all(root).unwrap();
}

/// The always-on contract meets a permit-era record (`""`, none, or the
/// other collector): it lowers no revision and keeps every mark, and the
/// latch is set exactly as for any contract change. Was
/// `a_late_identity_permit_lowers_no_revision`.
#[test]
fn the_always_on_contract_lowers_no_revision() {
    claude_request_identity::with_cycle_contract_for_test(
        claude_request_identity::E2_GROUPING,
        || {
            for record in [Some(""), None, Some(claude_request_identity::COLLECTOR)] {
                let key = "/p/session.jsonl";
                let mut index = at_revision_three();
                index.files.insert(key.into(), entry(3, "session"));
                index
                    .claude_money_birth_store
                    .set_money_marks(key, money_mark::DISCLOSED);
                index.claude_request_identity_contract = record.map(str::to_owned);
                let reowed = history_local_count(HistoryLocalCount::Reowed);
                for _ in 0..3 {
                    index.observe_claude_request_identity_contract(true);
                    assert_eq!(index.files[key].effective_upload_body_witness_revision, 3);
                    assert_eq!(marks(&index, key), money_mark::DISCLOSED);
                }
                assert_eq!(history_local_count(HistoryLocalCount::Reowed), reowed);
                assert_eq!(
                    index.claude_request_identity_contract_for_test(),
                    (Some(claude_request_identity::E2_GROUPING), true),
                    "{record:?}"
                );
            }
        },
    );
}

/// History-gate counts (kept: they concern the history-upgrade gate, not
/// request identity): each upgrade the gate permitted that did not stamp, by
/// hold. A decide-time hold and a literal-only denial were never permitted;
/// a stamped upgrade a partial save does not commit is `not_accepted`. Was
/// `permit_debt_counts_classify_permitted_upgrades`, without its retired
/// gauge.
#[test]
fn history_not_stamped_counts_classify_permitted_upgrades() {
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
    let scope = claude_reread::Scope::begin(true);
    index.note_claude_history_not_stamped();
    index.note_claude_history_not_stamped();
    let counts = scope.finish().claude_reread;
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
    assert!(value.get("stamped_without_permit").is_none(), "retired");
}
