//! Codex-ON: one source row table drives import, hydrate, save and live keys.
//! A source the store serves adds a row here, never a second test body.
use super::*;
use crate::durable_tail_store::{key_digest, DurableSource};
use crate::snapshots::scan_index_persistence::Source;
use crate::snapshots::{
    CodexParentProofOwed, CodexParentProofState, LoadOrigin, OwedOrigin, SnapshotSource,
};
use serde_json::json;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

type FixtureRow = (Source, fn() -> ScanIndex);
fn fixtures() -> [FixtureRow; 2] {
    [
        (Source::Claude, kinds::tests::fixture),
        (Source::Codex, codex_fixture),
    ]
}
fn sources(source: Source) -> (SnapshotSource, DurableSource) {
    match source {
        Source::Claude => (SnapshotSource::ClaudeCode, DurableSource::ClaudeCode),
        Source::Codex => (SnapshotSource::Codex, DurableSource::Codex),
        Source::Pi => unreachable!("Pi is not served by the store yet"),
    }
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
    let owed = CodexParentProofOwed::new(
        "parent".into(),
        1,
        crate::snapshots::CAUSE_NO_EVIDENCE,
        OwedOrigin::Lineage,
    );
    index
        .codex_parent_prefix_proofs
        .insert("child".into(), CodexParentProofState::Owed(owed));
    let stamp = json!({"length":1,"device":1,"inode":2,"modified":[1,0],"changed":[1,0]});
    let seal = json!({"stamp":stamp,"scope":crate::snapshots::codex_parent_side_scope().0,
        "sample_len":1,"head_sha256":"a".repeat(64),"boundary_sha256":"b".repeat(64),
        "verified_unix_seconds":1,"sealed_unix_seconds":1});
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
        ("codex_parent_ownership_refs", json!(["member"])),
        (
            "codex_parent_ownership_ledgers",
            json!({"parent":{"signatures":["signature"],"scan_complete":true}}),
        ),
        (
            "codex_parent_side_requests",
            json!({"parent":{"dev_ino":[1,2],"needed_extent":1,"state":{"kind":"live"},
                "state_extent":1,"state_ctime":[1,0],"attempt_extent":1,"attempt_ctime":[1,0],
                "attempts":1,"not_before_unix_seconds":1}}),
        ),
        (
            "codex_parent_side",
            json!({"parent":{"verdict":{"kind":"settled"},"generation":1,"referenced_epoch":1,
                "parsed":{"dev":1,"ino":2,"extent":1,"modified":[1,0],"changed":[1,0]},
                "seal":seal}}),
        ),
        ("codex_parent_side_generation", json!(1)),
        ("codex_parent_proof_wrap_epoch", json!(1)),
        ("codex_parent_proof_cursor", json!("child")),
        ("codex_parent_side_cursor", json!("parent")),
        ("codex_parent_proof_seq", json!(1)),
        (
            "codex_proof_index_incarnation",
            json!("0123456789abcdef0123456789abcdef"),
        ),
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
    let cold = index.claude_usage_family_pending.cold().is_some();
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
    index.codex_parent_side_generation += 1;
    index
}

/// [format] Each row fills every persisted field of its source at the current
/// layout, imports through the production route, hydrates equal to its
/// normalized v1 load, and a selected page saves and reopens equal. [money]
/// Committed live keys are exactly the row source's digests of its file keys.
#[test]
fn source_rows_import_hydrate_save_and_key_like_v1() {
    let empty = serde_json::to_value(ScanIndex::default()).unwrap();
    let filled = serde_json::to_value(codex_fixture()).unwrap();
    let codex = catalogue::LAYOUTS
        .iter()
        .filter(|(_, field, _)| field.starts_with("codex_"))
        .collect::<Vec<_>>();
    assert_eq!(codex.len(), 19, "persisted Codex kinds");
    for (kind, field, introduced) in codex {
        assert_eq!(*introduced, 1, "{kind}: no layout bump for Codex-ON");
        assert_ne!(
            filled[field], empty[field],
            "{field}: the Codex row fills it"
        );
    }
    for (source, build) in fixtures() {
        let (snapshot_source, durable) = sources(source);
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
        let live = {
            let _owner = crate::snapshots::CheckpointLock::acquire(&route.path).unwrap();
            live_key_digests(&route.path).unwrap()
        };
        assert!(live.complete && !live.digests.is_empty(), "{source:?}");
        assert_eq!(live.generation, saved.generation);
        let keys = saved.files.keys().map(|key| key_digest(durable, key));
        assert_eq!(live.digests, keys.collect::<BTreeSet<_>>());
        money_test_support::assert_selected_saves(source, &build(), &[page(build())]);
    }
}

/// [money] Codex-ON: the existing 24b Codex transition row with its index
/// published to state v2. Cold Full, restored Tail and restarted arms emit
/// equal money and placement.
#[cfg(unix)]
#[test]
fn codex_transition_on_published_state_v2_emits_equal_money_and_placement() {
    crate::snapshot_sync::codex_24b_on_published_state_v2();
}

/// [regress] D62: a state v2 reload whose store holds no incarnation mints a
/// fresh RAM nonce each time, though its fence is unchanged; the path's
/// first-load flag and seq high-water still come from the memo.
#[test]
fn v2_reload_without_a_persisted_incarnation_mints_fresh_and_keeps_high_water() {
    let scratch = crate::test_scratch::ScratchDir::canonical("codex-on-d62");
    let (custody, published) = money_test_support::ColdSession::publish(
        Source::Codex,
        &ScanIndex::default(),
        &scratch.join("store"),
    );
    let path = custody.path();
    assert!(state_v2_growth_retention_active(&published));
    assert!(published.codex_proof_index_incarnation.is_empty());
    crate::snapshots::raise_codex_proof_seq_high_water(&published.codex_proof_index_minted, 7);
    let mut nonces = BTreeSet::from([published.codex_proof_index_minted.clone()]);
    for _ in 0..2 {
        let (mut index, origin) = ScanIndex::load_inner_with_support(
            path,
            Some(SnapshotSource::Codex),
            None,
            SystemTime::now(),
        )
        .unwrap();
        assert!(matches!(origin, LoadOrigin::Loaded(_)));
        assert!(state_v2_growth_retention_active(&index));
        assert!(
            !index.mint_or_reuse_codex_proof_incarnation(path, origin),
            "not the path's first load"
        );
        assert_eq!(index.codex_parent_proof_seq, 7, "the path's high-water");
        assert!(index.codex_proof_index_incarnation.is_empty());
        assert!(
            nonces.insert(index.codex_proof_index_minted.clone()),
            "a fresh RAM nonce"
        );
    }
}
