//! Codex-ON: one source row table drives import, hydrate and save.
//! A source the store serves adds a row here, never a second test body.
use super::*;
use crate::snapshots::scan_index_persistence::Source;
use crate::snapshots::{LoadOrigin, SnapshotSource};
use serde_json::json;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

type FixtureRow = (Source, fn() -> ScanIndex);
fn fixtures() -> [FixtureRow; 3] {
    [
        (Source::Claude, kinds::tests::fixture),
        (Source::Codex, codex_fixture),
        (Source::Pi, pi_fixture),
    ]
}
const PI_ACTIVE: &str =
    "/synthetic/.pi/agent/sessions/--synthetic-work--/2026-10-27T06-00-00-000Z_a.jsonl";
const PI_OWED: &str =
    "/synthetic/.pi/agent/sessions/--synthetic-work--/2026-10-27T07-00-00-000Z_b.jsonl";
const PI_EMPTY: &str =
    "/synthetic/.pi/agent/sessions/--synthetic-work--/2026-10-27T08-00-00-000Z_c.jsonl";

/// Pi has no Pi-only kind (its fork ledger lives in the durable tail record):
/// every shared file-owned and accepted kind non-default, with each optional
/// entry field present once, one file not yet fingerprinted and one
/// confirmed-empty file.
fn pi_fixture() -> ScanIndex {
    let receipt = json!({
        "context_fingerprint": "1".repeat(64),
        "replay_generation": 3,
        "source_witness": "2".repeat(64),
        "body_witness": "3".repeat(64),
    });
    serde_json::from_value(json!({
        "schema_version": crate::snapshots::SCAN_INDEX_SCHEMA_VERSION,
        "generation": 0,
        "files": {
            PI_ACTIVE: {
                "size_bytes": 4096,
                "modified_unix_seconds": 1_793_084_400_u64,
                "modified_unix_nanos": 1_793_084_400_123_456_789_u64,
                "source_file_fingerprint": "a".repeat(64),
                "last_snapshot_fingerprint": "b".repeat(64),
                "last_upload_body_witness": "c".repeat(64),
                "effective_upload_body_witness_revision": 2,
                "scan_identity_version": crate::snapshots::LOCAL_SCAN_INDEX_IDENTITY_VERSION,
                "opened_changed_nanos": 1_793_084_401_000_000_000_u64,
                "opened_birth_nanos": 1_793_080_800_000_000_000_u64,
                "upload_context_receipt": receipt,
            },
            PI_OWED: {
                "size_bytes": 512,
                "modified_unix_seconds": 1_793_088_000_u64,
                "source_file_fingerprint": "",
                "last_snapshot_fingerprint": null,
            },
        },
        "terminal_jsonl_dispositions": {
            PI_ACTIVE: {
                "source_file_fingerprint": "a".repeat(64),
                "parser_generation": "pi:1",
                "loss": {"over_line_cap_count": 1, "recognized_usage_drop_count": 0,
                    "dropped_usage_record_count": 0},
            },
        },
        "confirmed_empty_files": [PI_EMPTY],
        "file_snapshot_fingerprints": {PI_ACTIVE: ["pi-accepted"], PI_OWED: []},
        // Missing activity is not empty: keep one known and one unknown.
        "snapshot_activity_at": {PI_ACTIVE: "2026-10-27T06:00:01Z", PI_OWED: null},
        "accepted_snapshot_fingerprints": ["pi-accepted"],
    }))
    .unwrap()
}

/// Every persisted Codex field non-default, beside a Codex-bearing file.
fn codex_fixture() -> ScanIndex {
    let mut index = ScanIndex::default();
    let (fingerprint, key) = ("c".repeat(64), "/synthetic/sessions/rollout.jsonl");
    let entry = crate::snapshots::tests::manifest_index_entry(Some(&fingerprint));
    index.files.insert(key.into(), entry);
    index
        .file_snapshot_fingerprints
        .insert(key.into(), BTreeSet::from([fingerprint.clone()]));
    index.accepted_snapshot_fingerprints.insert(fingerprint);
    let mut value = serde_json::to_value(&index).unwrap();
    for (field, replacement) in [
        (
            "codex_state_only_snapshot_fingerprints",
            json!({"session":"value"}),
        ),
        ("codex_state_only_blocked_session_ids", json!(["member"])),
        (
            "codex_state_only_blocked_by_file",
            json!({"file":["session"]}),
        ),
        ("codex_state_only_blocked_unattributed", json!(["member"])),
        ("codex_state_only_blocked_legacy", json!(["member"])),
        ("codex_state_only_blocked_attributed", json!(true)),
        (
            "codex_counting_tombstones",
            json!({"a".repeat(64):{"evidence":"legacy_acked","retired_in":"2026-10-22T00:00:00Z"}}),
        ),
        (
            "codex_counting_evicted_legacy",
            json!([{"owner":"b".repeat(64),"selected_v2":false}]),
        ),
    ] {
        value[field] = replacement;
    }
    serde_json::from_value(value).unwrap()
}

/// A bound index path in its own support dir and namespace (live keys are
/// binding-scoped); dropping it erases the custody.
struct Route {
    support: PathBuf,
    path: PathBuf,
}
impl Route {
    fn new(source: Source) -> Self {
        use sha2::Digest;
        let support = crate::test_scratch::canonical_private_dir("ottto-codex-on");
        let namespace = format!(
            "{:x}",
            sha2::Sha256::digest(support.to_string_lossy().as_bytes())
        );
        let parent = support.join("snapshots/destinations").join(namespace);
        std::fs::create_dir_all(&parent).unwrap();
        let path = parent.join(money_test_support::synthetic_file(source, ".json"));
        Self { support, path }
    }
}
impl Drop for Route {
    fn drop(&mut self) {
        money_test_support::erase_published(&self.path);
        let _ = std::fs::remove_dir_all(&self.support);
    }
}

/// Serialized graph with cold rows read back from the session store.
fn view(index: &ScanIndex) -> serde_json::Value {
    let cold = money_test_support::has_cold_archive(index);
    serde_json::to_value(if cold {
        money_test_support::resident(index)
    } else {
        index.clone()
    })
    .unwrap()
}
fn assert_same(expected: &ScanIndex, actual: &ScanIndex) {
    assert_eq!(view(actual), view(expected));
    assert!(actual.decode_holds.same_as(&expected.decode_holds));
    assert_eq!(
        actual.decode_holds.v2_provenance(),
        expected.decode_holds.v2_provenance()
    );
}
fn page(mut index: ScanIndex) -> ScanIndex {
    index.accepted_snapshot_fingerprints.insert("f".repeat(64));
    index
}

/// [format] Each row fills every persisted field of its source at the current
/// layout, imports through the production route, hydrates equal to its
/// normalized v1 load, and a selected page saves and reopens equal. Live keys
/// per source: runtime_tests' f6 table.
#[test]
fn source_rows_import_hydrate_and_save_like_v1() {
    let empty = serde_json::to_value(ScanIndex::default()).unwrap();
    let filled = serde_json::to_value(codex_fixture()).unwrap();
    let codex = catalogue::LAYOUTS
        .iter()
        .filter(|(kind, field, _)| field.starts_with("codex_") && !catalogue::retired(kind))
        .collect::<Vec<_>>();
    assert_eq!(codex.len(), 8, "persisted Codex kinds");
    for (kind, field, introduced) in codex {
        assert_eq!(*introduced, 1, "{kind}: no layout bump for Codex-ON");
        assert_ne!(
            filled[field], empty[field],
            "{field}: the Codex row fills it"
        );
    }
    for (source, build) in fixtures() {
        let snapshot_source = source.snapshot();
        let route = Route::new(source);
        std::fs::write(&route.path, serde_json::to_vec(&build()).unwrap()).unwrap();
        let load = |support: Option<&Path>| {
            let now = SystemTime::now();
            ScanIndex::load_inner_with_support(&route.path, Some(snapshot_source), support, now)
                .unwrap()
                .0
        };
        // The normalized v1 load that the support dir lets import.
        let imported = load(Some(route.support.as_path()));
        assert!(
            state_v2_growth_retention_active(&imported),
            "{source:?}: imported and published"
        );
        let reopened = load(None);
        assert!(state_v2_growth_retention_active(&reopened));
        assert_same(&imported, &reopened);
        let mut saved = page(reopened);
        saved.save(&route.path).unwrap();
        assert_same(&saved, &load(None));
        money_test_support::assert_selected_saves(source, &build(), &[page(build())]);
    }
}

/// [behaviour] The per-path first-load marker survives v2 reloads without
/// retaining a proof incarnation or sequence high-water.
#[test]
fn v2_reload_keeps_per_path_first_load_membership() {
    let scratch = crate::test_scratch::ScratchDir::canonical("codex-first-load");
    let (custody, published) = money_test_support::ColdSession::publish(
        Source::Codex,
        &ScanIndex::default(),
        &scratch.join("store"),
    );
    let path = custody.path();
    assert!(state_v2_growth_retention_active(&published));
    ScanIndex::default().note_first_index_load(path);
    for _ in 0..2 {
        let (index, origin) = ScanIndex::load_inner_with_support(
            path,
            Some(SnapshotSource::Codex),
            None,
            SystemTime::now(),
        )
        .unwrap();
        assert!(matches!(origin, LoadOrigin::Loaded));
        assert!(state_v2_growth_retention_active(&index));
        assert!(
            !index.note_first_index_load(path),
            "not the path's first load"
        );
    }
}

/// [format] A previous release's store holds rows of every retired kind:
/// Claude's with usage members (a request set shared with a live row, a value
/// stored in chunks) and a raw usage hold, Codex's and Pi's manifest-only.
/// One hydrate and save removes them all, releases their request sets and
/// chunks, and leaves every live row as it was; a reopen finds none.
#[test]
fn previous_release_store_retired_rows_absent_after_save_and_reopen() {
    use kinds::tests::{referenced_sets, set_refs};
    const LIVE: [&str; 4] = [
        "accepted.entity",
        "refusal.authority",
        "proof.usage",
        "file.census",
    ];
    let live = |db: &mut sqlite::Sqlite| {
        let mut tx = db.begin(TxnMode::Read).unwrap();
        let mut headers = Vec::new();
        for kind in LIVE {
            mapper::rows(&mut tx, kind, |_, h| {
                headers.push(h);
                Ok(())
            })
            .unwrap();
        }
        headers
    };
    for (source, build) in fixtures() {
        let claude = source == Source::Claude;
        let scratch = crate::test_scratch::ScratchDir::canonical("retired-purge");
        let path = scratch.join("state.v2.sqlite.import");
        let index = if claude {
            kinds::tests::with_co_owned_witness(build())
        } else {
            build()
        };
        let mut db = money_test_support::populate(source, &path, &index, BTreeMap::new());
        let identity = db.read_control::<Identity>("identity").unwrap().unwrap();
        let retired = kinds::tests::seed_retired_rows(&mut db, claude);
        let before = live(&mut db);
        assert!(
            !claude || before.len() > LIVE.len(),
            "Claude holds live members"
        );
        // Each usage row's request sets, with their counts before the purge.
        let mut sets = Vec::new();
        {
            let mut tx = db.begin(TxnMode::Read).unwrap();
            for key in retired.iter().filter(|key| {
                matches!(key, RowKey::Record { kind, position: 1, .. } if kind.name() == "usage.pending")
            }) {
                let h = tx.get(key).unwrap().unwrap();
                if key == &mapper::key("usage.pending", kinds::tests::CHUNKED, 1).unwrap() {
                    assert!(h.parts > 0, "{source:?}: stored in chunks");
                }
                for set in referenced_sets(&mut tx, key) {
                    let refs = set_refs(&mut tx, &set).unwrap();
                    sets.push((set, refs));
                }
            }
        }
        assert_eq!(sets.len(), if claude { 2 } else { 0 }, "{source:?}");
        kinds::tests::purge(&mut db, money_test_support::binding(source)).unwrap();
        drop(db);
        let mut db = sqlite::Sqlite::open(&path, &identity).unwrap();
        let (_, cx) = kinds::hydrate(&mut db, money_test_support::binding(source)).unwrap();
        assert!(cx.retired.is_empty(), "{source:?}");
        {
            let mut tx = db.begin(TxnMode::Read).unwrap();
            for key in &retired {
                assert!(tx.get(key).unwrap().is_none(), "{source:?}: {key:?}");
            }
            for (set, refs) in &sets {
                // One reference less: a set only the retired row held is released.
                let after = set_refs(&mut tx, set);
                assert_eq!(after, refs.checked_sub(1).filter(|n| *n > 0), "{source:?}");
            }
        }
        assert!(
            sets.iter().any(|(_, refs)| *refs == 2) == claude,
            "{source:?}"
        );
        assert_eq!(live(&mut db), before, "{source:?}: live rows untouched");
        db.audit_headers().unwrap();
        db.validate_references().unwrap();
    }
}
