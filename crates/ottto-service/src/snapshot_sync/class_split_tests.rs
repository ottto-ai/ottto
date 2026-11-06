// Upload requests split by cache-patch class. The client declares head CAS for
// a whole request when one body carries a cache patch, so an unpatched body
// sent beside a patched one used to travel under CAS with no base, conflict
// with its server head, and owe a challenge it could never answer.
// Included into `snapshot_sync::tests`; uses its helpers and the head-conflict
// and e2 upload fixtures.

use super::e2_upload_tests::{accept_all, family, plain_item, upload_families, FamilyItem};
use crate::snapshot_client::{SnapshotBatchResponse, SnapshotEntityRef};
use crate::snapshot_sync::head_conflict_answer_tests::{
    challenge, cycle_with_transport, empty_ack, envelope, item, mirrored, reference, request,
    revision_v2, stale_head, SCOPE,
};
use crate::snapshots::cache_observations::CacheObservations;
use serde_json::Value;

fn fresh_progress() -> SnapshotUploadProgress {
    SnapshotUploadProgress::new(
        "a".repeat(64),
        snapshot_quarantine_witness(SnapshotSource::Codex),
    )
}

fn complete_empty() -> CacheObservations {
    CacheObservations {
        schema_version: 1,
        operations: Vec::new(),
        coverage: "complete".into(),
        omitted_observation_count: None,
        full_replacement: false,
    }
}

/// The fixture body as session `name`, carrying `patch` (None: unpatched,
/// as a birth- or cap-withheld body or an unproven Codex body is).
fn body(name: &str, patch: Option<CacheObservations>) -> SnapshotItem {
    let mut item = item();
    item.source_session_id = name.into();
    if patch.is_none() {
        item.cache_observations_state = None;
    }
    item.cache_observations = patch;
    item.snapshot_fingerprint =
        crate::snapshots::snapshot_fingerprint(SnapshotSource::Codex, &item);
    item
}

/// A changed revision of `item` (new usage), same session and patch class.
fn revised(item: &SnapshotItem, step: u64) -> SnapshotItem {
    let mut item = item.clone();
    item.avg_duration_ms = Some(item.avg_duration_ms.unwrap_or_default() + step);
    item.snapshot_fingerprint =
        crate::snapshots::snapshot_fingerprint(SnapshotSource::Codex, &item);
    item
}

/// The observed seed: an owed challenge, no saved base or cache state, and
/// no answer attempt.
fn owe(progress: &mut SnapshotUploadProgress, item: &SnapshotItem, challenge: String) {
    progress.head_conflict_challenges.insert(
        cache_session_key(&item.source_session_id),
        HeadConflictChallenge {
            challenge,
            stale_revision_v2_hash: revision_v2(item),
            answer_attempts: 0,
            last_answer_unix: 0,
        },
    );
}

fn sessions(wire: &Value) -> Vec<String> {
    wire["snapshots"]
        .as_array()
        .unwrap()
        .iter()
        .map(|body| body["source_session_id"].as_str().unwrap().to_owned())
        .collect()
}

/// A backend-shaped head store for the daemon rows; real HTTP and Postgres
/// admission is the backend's own receiver test. An ordinary request skips
/// CAS. Under the head-CAS contract a changed body whose base is not the
/// current head conflicts with a fresh challenge unless it answers the
/// current one. An exact repeat is unchanged; a conflict stores nothing.
#[derive(Clone, Default)]
struct HeadStore {
    /// session -> (head etag, stored body content identity)
    heads: BTreeMap<String, (String, String)>,
    challenges: BTreeMap<String, String>,
    minted: u64,
    stored: Vec<String>,
}

impl HeadStore {
    fn mint(&mut self) -> String {
        self.minted += 1;
        format!("{:064x}", 0x1000 + self.minted)
    }

    /// The server already holds an older body of `session`.
    fn seed(&mut self, session: &str) -> String {
        let head = self.mint();
        self.heads
            .insert(session.into(), (head.clone(), "older".into()));
        head
    }

    fn post(&mut self, request: &SnapshotBatchRequest, wire: &Value) -> SnapshotBatchResponse {
        let cas = wire["head_cas_contract"].is_string();
        let mut ack = empty_ack();
        for (item, sent) in request
            .snapshots
            .iter()
            .zip(wire["snapshots"].as_array().unwrap())
        {
            let envelope = &sent["semantic_envelope"];
            let witness = snapshot_upload_body_witness(item);
            let version = crate::snapshot_client::snapshot_ack_body_witness_version(item).unwrap();
            let echo = SnapshotEntityRef {
                body_witness_version: version,
                body_witness_digest: version.map(|_| witness.clone()),
                ..reference(item)
            };
            let session = item.source_session_id.clone();
            if let Some((head, held)) = self.heads.get(&session).cloned() {
                if held == item.snapshot_fingerprint {
                    ack.accepted += 1;
                    ack.unchanged_entities.push(SnapshotEntityRef {
                        head_etag: cas.then_some(head),
                        ..echo
                    });
                    continue;
                }
                let answer = envelope["conflict_head_challenge"].as_str();
                let answered =
                    answer.is_some() && answer == self.challenges.get(&session).map(String::as_str);
                if cas && envelope["base_head_etag"].as_str() != Some(head.as_str()) && !answered {
                    let challenge = self.mint();
                    self.challenges.insert(session, challenge.clone());
                    ack.conflict_entities.push(SnapshotEntityRef {
                        head_challenge: Some(challenge),
                        ..reference(item)
                    });
                    continue;
                }
            }
            let head = self.mint();
            self.heads.insert(
                session.clone(),
                (head.clone(), item.snapshot_fingerprint.clone()),
            );
            self.challenges.remove(&session);
            self.stored.push(session);
            ack.accepted += 1;
            ack.accepted_entities.push(SnapshotEntityRef {
                head_etag: cas.then_some(head),
                ..echo
            });
        }
        ack
    }
}

/// One production-shaped main-upload page (see `cycle_with_transport`)
/// under the production class; only a legacy reconciliation declares head
/// CAS for its whole request.
fn page(
    progress: &mut SnapshotUploadProgress,
    items: &[SnapshotItem],
    legacy: &BTreeSet<String>,
    server: impl FnMut(&SnapshotBatchRequest, &Value) -> Result<SnapshotBatchResponse>,
) -> (Result<ResumableUploadResult>, Vec<Value>) {
    cycle_with_transport(
        progress,
        items,
        current_unix_seconds(),
        |item| snapshot_upload_batch_class(item, legacy.contains(&item.snapshot_fingerprint)),
        |batch| {
            batch
                .iter()
                .all(|item| legacy.contains(&item.snapshot_fingerprint))
        },
        server,
    )
}

/// The previous packing: every body in one class, no route-wide CAS.
fn single_class_page(
    progress: &mut SnapshotUploadProgress,
    items: &[SnapshotItem],
    server: impl FnMut(&SnapshotBatchRequest, &Value) -> Result<SnapshotBatchResponse>,
) -> (Result<ResumableUploadResult>, Vec<Value>) {
    cycle_with_transport(
        progress,
        items,
        current_unix_seconds(),
        |_| 0,
        |_| false,
        server,
    )
}

/// [money] [regress] A mixed page (patched, admitted-empty and
/// partial-empty patches; birth- and cap-withheld unpatched bodies; saved and
/// missing bases; existing, missing and exact-repeat server heads). Only the
/// patched request declares head CAS; the ordinary one carries no contract
/// and no borrowed token, and each entity settles by its own ACK.
#[test]
fn mixed_page_sends_each_patch_class_in_its_own_request() {
    let none = BTreeSet::new();
    let mut store = HeadStore::default();
    let mut progress = fresh_progress();
    let patched = body("patched", Some(item().cache_observations.unwrap()));
    let empty = body("admitted-empty", Some(complete_empty()));
    let partial = body("partial-empty", Some(CacheObservations::partial(Some(2))));
    let birth = body("birth-withheld", None);
    let cap = body("cap-withheld", None);
    let repeat = body("exact-repeat", None);
    // Saved bases equal the server heads. The birth-withheld session has a
    // server head and no base (the observed population); the partial-empty
    // session is new to the server; the repeat is already stored exactly.
    for item in [&patched, &empty, &cap] {
        let head = store.seed(&item.source_session_id);
        progress
            .accepted_cache_heads
            .insert(cache_session_key(&item.source_session_id), head);
    }
    store.seed(&birth.source_session_id);
    let head = store.mint();
    store.heads.insert(
        repeat.source_session_id.clone(),
        (head, repeat.snapshot_fingerprint.clone()),
    );
    let items = [
        patched.clone(),
        birth.clone(),
        empty.clone(),
        cap.clone(),
        partial.clone(),
        repeat.clone(),
    ];
    let bases = items
        .iter()
        .map(|item| {
            (
                item.source_session_id.clone(),
                progress
                    .accepted_cache_heads
                    .get(&cache_session_key(&item.source_session_id))
                    .cloned(),
            )
        })
        .collect::<BTreeMap<_, _>>();

    // Before the split: one patched sibling made the whole request CAS and
    // the base-less unpatched body conflicted with a challenge.
    let mut before = progress.clone();
    let mut old_store = store.clone();
    let (result, wires) = single_class_page(&mut before, &items, |request, wire| {
        Ok(old_store.post(request, wire))
    });
    assert_eq!(wires.len(), 1);
    assert!(wires[0]["head_cas_contract"].is_string());
    assert_eq!(
        result.unwrap(),
        ResumableUploadResult::Deferred {
            count: 1,
            isolated: 1
        }
    );
    assert!(before
        .head_conflict_challenges
        .contains_key(&cache_session_key("birth-withheld")));

    let (result, wires) = page(&mut progress, &items, &none, |request, wire| {
        Ok(store.post(request, wire))
    });
    assert_eq!(result.unwrap(), ResumableUploadResult::Completed);
    assert_eq!(wires.len(), 2, "one request per class");
    assert!(wires[0].get("head_cas_contract").is_none());
    assert!(wires[1]["head_cas_contract"].is_string());
    let mut ordinary = sessions(&wires[0]);
    ordinary.sort();
    assert_eq!(ordinary, ["birth-withheld", "cap-withheld", "exact-repeat"]);
    let mut cas = sessions(&wires[1]);
    cas.sort();
    assert_eq!(cas, ["admitted-empty", "partial-empty", "patched"]);
    for (index, wire) in wires.iter().enumerate() {
        for sent in wire["snapshots"].as_array().unwrap() {
            let session = sent["source_session_id"].as_str().unwrap();
            let item = items
                .iter()
                .find(|item| item.source_session_id == session)
                .unwrap();
            let envelope = &sent["semantic_envelope"];
            assert!(envelope.get("conflict_head_challenge").is_none());
            // Only the entity's own saved base, never a borrowed token.
            assert_eq!(
                envelope.get("base_head_etag").and_then(Value::as_str),
                bases[session].as_deref(),
                "{session}"
            );
            // [money] Exact cache event sets: the patch whole, or none.
            assert_eq!(
                sent.get("cache_observations")
                    .filter(|value| !value.is_null()),
                item.cache_observations
                    .as_ref()
                    .map(|patch| serde_json::to_value(patch).unwrap())
                    .as_ref(),
                "{session}"
            );
            assert_eq!(item.cache_observations.is_some(), index == 1, "{session}");
        }
    }
    assert!(progress.head_conflict_challenges.is_empty(), "no conflict");
    for item in &items {
        assert_eq!(
            progress
                .accepted_body_witnesses
                .get(&item.snapshot_fingerprint),
            Some(&snapshot_upload_body_witness(item)),
            "{}",
            item.source_session_id
        );
    }
    let mut stored = store.stored.clone();
    stored.sort();
    assert_eq!(
        stored,
        [
            "admitted-empty",
            "birth-withheld",
            "cap-withheld",
            "partial-empty",
            "patched"
        ],
        "the exact repeat is not stored again"
    );
    for item in [&patched, &empty, &partial] {
        assert_eq!(
            progress.accepted_cache_heads[&cache_session_key(&item.source_session_id)],
            store.heads[&item.source_session_id].0
        );
    }
    // The ordinary ACK has no etag, so the cap-withheld session's saved
    // token is dropped; a later patch for it re-bootstraps through a probe.
    for item in [&birth, &cap, &repeat] {
        assert!(!progress
            .accepted_cache_heads
            .contains_key(&cache_session_key(&item.source_session_id)));
    }

    // A single-class page sends the same bytes as before the split.
    let single = [
        body("single-patched", Some(item().cache_observations.unwrap())),
        body("single-admitted-empty", Some(complete_empty())),
    ];
    let (result, now) = page(&mut fresh_progress(), &single, &none, |request, wire| {
        Ok(HeadStore::default().post(request, wire))
    });
    assert_eq!(result.unwrap(), ResumableUploadResult::Completed);
    let (result, previous) = single_class_page(&mut fresh_progress(), &single, |request, wire| {
        Ok(HeadStore::default().post(request, wire))
    });
    assert_eq!(result.unwrap(), ResumableUploadResult::Completed);
    assert_eq!(now, previous);
}

/// [money] The observed seed (challenge, no base or state, no attempt)
/// with a no-patch offer beside a patched sibling. With no saved base the
/// owed session can carry no answer, so it is not mirrored and its files may
/// re-fold. It goes out in an ordinary request, is accepted, and its exact
/// ACK clears the challenge without an answer. A restart keeps it clear.
#[test]
fn observed_unanswered_challenge_clears_through_an_ordinary_accept() {
    let none = BTreeSet::new();
    let mut store = HeadStore::default();
    let mut progress = fresh_progress();
    let owed = body("owed", None);
    let sibling = body("patched-sibling", Some(item().cache_observations.unwrap()));
    store.seed("owed");
    let head = store.seed("patched-sibling");
    progress
        .accepted_cache_heads
        .insert(cache_session_key("patched-sibling"), head);
    let key = cache_session_key("owed");
    owe(&mut progress, &owed, challenge(0xc));
    assert!(
        !mirrored(&progress, &key),
        "no saved base: no answer can ride, so it may re-fold"
    );

    let (result, wires) = page(
        &mut progress,
        &[owed.clone(), sibling.clone()],
        &none,
        |request, wire| Ok(store.post(request, wire)),
    );
    assert_eq!(result.unwrap(), ResumableUploadResult::Completed);
    assert_eq!(wires.len(), 2);
    assert!(wires[0].get("head_cas_contract").is_none());
    assert_eq!(sessions(&wires[0]), ["owed"]);
    let envelope = envelope(&wires[0]);
    for field in [
        "base_head_etag",
        "conflict_head_challenge",
        "rescan_from_revision_hash",
        "forced_full_rescan",
    ] {
        assert!(envelope.get(field).is_none(), "{field}");
    }
    assert!(
        progress.head_conflict_challenges.is_empty(),
        "cleared by the accept, never answered"
    );
    assert_eq!(
        progress.accepted_body_witnesses[&owed.snapshot_fingerprint],
        snapshot_upload_body_witness(&owed),
        "exact receipt"
    );
    assert!(!progress.accepted_cache_heads.contains_key(&key));
    assert_eq!(store.stored, ["owed", "patched-sibling"]);
    assert!(!mirrored(&progress, &key));

    let root = crate::test_scratch::ScratchDir::new("class-split-restart");
    let path = root.join("upload-progress.json");
    progress.generation = 0;
    progress.save(&path).unwrap();
    let restarted = SnapshotUploadProgress::load(
        &path,
        &"a".repeat(64),
        snapshot_quarantine_witness(SnapshotSource::Codex),
    )
    .unwrap();
    assert!(restarted.head_conflict_challenges.is_empty());
    assert_eq!(
        restarted.accepted_body_witnesses,
        progress.accepted_body_witnesses
    );
    assert!(!mirrored(&restarted, &key));
}

/// [money] The observed seed when the session regains a patch, including a
/// partial-empty one. The existing ordinary bootstrap probe's ACK clears the
/// challenge, its exact CAS repeat saves the head, and the patched main offer
/// declares CAS with that base and carries its whole patch. With no saved
/// base the session is never mirrored, and no POST carries the rescan claim.
#[test]
fn a_session_that_regains_a_patch_clears_through_the_ordinary_bootstrap() {
    let none = BTreeSet::new();
    for regained in [
        item().cache_observations.unwrap(),
        CacheObservations::partial(Some(2)),
    ] {
        let mut store = HeadStore::default();
        let mut progress = fresh_progress();
        let item = body("owed", Some(regained.clone()));
        let key = cache_session_key("owed");
        store.seed("owed");
        owe(&mut progress, &item, challenge(0xc));
        assert!(!mirrored(&progress, &key), "no saved base");

        let probes = vec![cache_head_probe(&item)];
        let mut probe_wires = Vec::new();
        let deferred = bootstrap_cache_heads(
            &probes,
            SCOPE,
            &mut progress,
            true,
            |batch, enforce_head_cas| {
                let request = request(batch);
                let wire = if enforce_head_cas {
                    serde_json::to_value(request.wire_with_head_cas())?
                } else {
                    serde_json::to_value(&request)?
                };
                probe_wires.push(wire.clone());
                let mut response = store.post(&request, &wire);
                response.validate_entity_ack_with_head_cas(&request, enforce_head_cas)?;
                response.bind_conflict_rescans(&request);
                Ok(response)
            },
            |_| Ok(()),
        )
        .unwrap();
        assert_eq!(deferred, 0);
        assert_eq!(probe_wires.len(), 2, "ordinary probe, then its CAS repeat");
        assert!(probe_wires[0].get("head_cas_contract").is_none());
        assert!(probe_wires[1]["head_cas_contract"].is_string());
        assert!(progress.head_conflict_challenges.is_empty());
        let head = progress.accepted_cache_heads[&key].clone();
        assert_eq!(head, store.heads["owed"].0);

        let mut items = vec![item.clone()];
        assert_eq!(
            apply_bootstrapped_cache_heads("codex", &mut items, &progress).unwrap(),
            0
        );
        assert_eq!(
            items[0].cache_base_head_etag.as_deref(),
            Some(head.as_str())
        );
        let (result, wires) = page(&mut progress, &items, &none, |request, wire| {
            Ok(store.post(request, wire))
        });
        assert_eq!(result.unwrap(), ResumableUploadResult::Completed);
        assert_eq!(wires.len(), 1);
        assert!(wires[0]["head_cas_contract"].is_string());
        let sent = &wires[0]["snapshots"][0];
        assert_eq!(sent["semantic_envelope"]["base_head_etag"], head);
        assert!(sent["semantic_envelope"]
            .get("conflict_head_challenge")
            .is_none());
        assert_eq!(
            sent["cache_observations"],
            serde_json::to_value(&regained).unwrap(),
            "no accepted cache rows lost"
        );
        assert_eq!(progress.accepted_cache_heads[&key], store.heads["owed"].0);
        assert!(progress.head_conflict_challenges.is_empty());
        assert!(!mirrored(&progress, &key));
        for wire in probe_wires.iter().chain(&wires) {
            for body in wire["snapshots"].as_array().unwrap() {
                assert!(body.get("forced_full_rescan").is_none());
                assert!(body["semantic_envelope"]
                    .get("forced_full_rescan")
                    .is_none());
            }
        }
    }
}

/// [money] A mixed owed page beside the class split: a base-holding patched
/// owed body, a base-less unpatched owed body and a healthy patched sibling.
/// Requests are class-pure. Only the base-holding session is mirrored (its
/// body is a native Full) and only its body carries the answer and the
/// rescan claim. The base-less session is not mirrored, travels alone in a
/// class-0 request with no claim, and its ordinary accept clears its
/// challenge. Every body settles by its exact ACK, stored once.
#[test]
fn a_mixed_owed_page_answers_only_the_base_holding_patched_body() {
    let none = BTreeSet::new();
    let mut store = HeadStore::default();
    let mut progress = fresh_progress();
    let based = body("owed-based", Some(item().cache_observations.unwrap()));
    let baseless = body("owed-baseless", None);
    let sibling = body("patched-sibling", Some(item().cache_observations.unwrap()));
    let (based_key, baseless_key, sibling_key) = (
        cache_session_key("owed-based"),
        cache_session_key("owed-baseless"),
        cache_session_key("patched-sibling"),
    );
    // The saved base is stale: the server head moved on and challenged it.
    let stale = store.seed("owed-based");
    store.seed("owed-based");
    store.challenges.insert("owed-based".into(), challenge(0xa));
    progress
        .accepted_cache_heads
        .insert(based_key.clone(), stale);
    owe(&mut progress, &based, challenge(0xa));
    store.seed("owed-baseless");
    owe(&mut progress, &baseless, challenge(0xb));
    let head = store.seed("patched-sibling");
    progress
        .accepted_cache_heads
        .insert(sibling_key.clone(), head);
    assert!(mirrored(&progress, &based_key), "a saved base: native Full");
    assert!(!mirrored(&progress, &baseless_key), "no base: may re-fold");
    assert!(!mirrored(&progress, &sibling_key), "healthy");
    assert_eq!(snapshot_upload_batch_class(&baseless, false), 0);
    assert_eq!(snapshot_upload_batch_class(&based, false), 1);
    assert_eq!(snapshot_upload_batch_class(&sibling, false), 1);

    let (result, wires) = page(
        &mut progress,
        &[based.clone(), baseless.clone(), sibling.clone()],
        &none,
        |request, wire| Ok(store.post(request, wire)),
    );
    assert_eq!(result.unwrap(), ResumableUploadResult::Completed);
    let mut answered = Vec::new();
    for wire in &wires {
        let cas = wire["head_cas_contract"].is_string();
        for sent in wire["snapshots"].as_array().unwrap() {
            assert_eq!(
                !sent["cache_observations"].is_null(),
                cas,
                "a request mixes cache-patch classes"
            );
            let envelope = &sent["semantic_envelope"];
            assert_eq!(
                envelope.get("forced_full_rescan").is_some(),
                envelope.get("conflict_head_challenge").is_some()
            );
            if envelope.get("conflict_head_challenge").is_some() {
                assert_eq!(envelope["forced_full_rescan"], true);
                assert_eq!(envelope["conflict_head_challenge"], challenge(0xa));
                assert_eq!(envelope["rescan_from_revision_hash"], revision_v2(&based));
                answered.push(sent["source_session_id"].as_str().unwrap().to_owned());
            }
        }
    }
    assert_eq!(
        answered,
        ["owed-based"],
        "only the base-holding body answers"
    );
    let ordinary = wires
        .iter()
        .filter(|wire| sessions(wire).contains(&"owed-baseless".to_owned()))
        .collect::<Vec<_>>();
    assert_eq!(ordinary.len(), 1);
    assert_eq!(sessions(ordinary[0]), ["owed-baseless"], "class 0 alone");
    assert!(ordinary[0].get("head_cas_contract").is_none(), "class 0");
    let envelope = envelope(ordinary[0]);
    for field in [
        "base_head_etag",
        "conflict_head_challenge",
        "rescan_from_revision_hash",
        "forced_full_rescan",
    ] {
        assert!(envelope.get(field).is_none(), "{field}");
    }

    assert!(
        progress.head_conflict_challenges.is_empty(),
        "the answer and the ordinary accept clear both"
    );
    for item in [&based, &baseless, &sibling] {
        assert_eq!(
            progress.accepted_body_witnesses[&item.snapshot_fingerprint],
            snapshot_upload_body_witness(item),
            "exact receipt"
        );
    }
    let mut stored = store.stored.clone();
    stored.sort();
    assert_eq!(stored, ["owed-based", "owed-baseless", "patched-sibling"]);
    assert!(!progress.accepted_cache_heads.contains_key(&baseless_key));
    for key in [&based_key, &baseless_key, &sibling_key] {
        assert!(!mirrored(&progress, key), "nothing owed: may re-fold");
    }
}

/// [money] A lost ACK keeps the debt; the replay is an exact repeat
/// (unchanged, no second store); a repeat pass sends no POST; a fresh
/// challenge from a later CAS conflict is recorded and cleared again by the
/// next ordinary accept.
#[test]
fn lost_ack_replays_unchanged_and_a_fresh_challenge_clears_again() {
    let none = BTreeSet::new();
    let mut store = HeadStore::default();
    let mut progress = fresh_progress();
    let owed = body("owed", None);
    let key = cache_session_key("owed");
    store.seed("owed");
    owe(&mut progress, &owed, challenge(0xc));

    let (lost, _) = page(
        &mut progress,
        std::slice::from_ref(&owed),
        &none,
        |request, wire| {
            store.post(request, wire);
            Err(anyhow!("synthetic lost reply"))
        },
    );
    assert!(lost.is_err());
    assert!(progress.head_conflict_challenges.contains_key(&key));
    assert!(!progress
        .accepted_body_witnesses
        .contains_key(&owed.snapshot_fingerprint));

    let (result, _) = page(
        &mut progress,
        std::slice::from_ref(&owed),
        &none,
        |request, wire| Ok(store.post(request, wire)),
    );
    assert_eq!(result.unwrap(), ResumableUploadResult::Completed);
    assert!(progress.head_conflict_challenges.is_empty());
    assert_eq!(store.stored, ["owed"], "no double credit");

    // A repeat pass sends no POST: the packer skips an exact settled body.
    // (`page` forces a retry of every item, so ask the packer's predicate.)
    assert!(progress.contains_body(
        &owed.snapshot_fingerprint,
        &snapshot_upload_body_witness(&owed)
    ));

    // A later patched revision under a stale saved base conflicts under CAS.
    let mut patched = revised(&owed, 1);
    patched.cache_observations = item().cache_observations;
    patched.cache_observations_state = item().cache_observations_state;
    patched.snapshot_fingerprint =
        crate::snapshots::snapshot_fingerprint(SnapshotSource::Codex, &patched);
    progress
        .accepted_cache_heads
        .insert(key.clone(), stale_head());
    let (result, wires) = page(&mut progress, &[patched], &none, |request, wire| {
        Ok(store.post(request, wire))
    });
    assert_eq!(
        result.unwrap(),
        ResumableUploadResult::Deferred {
            count: 1,
            isolated: 1
        }
    );
    assert!(wires[0]["head_cas_contract"].is_string());
    assert_eq!(
        progress.head_conflict_challenges[&key].challenge,
        store.challenges["owed"]
    );
    // The next unpatched revision goes ordinary, is accepted, and clears it.
    let next = revised(&owed, 2);
    let (result, wires) = page(&mut progress, &[next], &none, |request, wire| {
        Ok(store.post(request, wire))
    });
    assert_eq!(result.unwrap(), ResumableUploadResult::Completed);
    assert!(wires[0].get("head_cas_contract").is_none());
    assert!(progress.head_conflict_challenges.is_empty());
    assert!(!progress.accepted_cache_heads.contains_key(&key));
    assert_eq!(store.stored, ["owed", "owed"]);
}

/// [money] Fence outcomes for the owed session's ordinary body. A covered
/// older or other authority downgrade is a permanent rejection: the
/// challenge clears and the body is held with no receipt. Mixed usage is
/// retryable: the challenge stays and the page is Deferred. A dominated
/// re-offer is unchanged with a basis: the challenge clears, the body is
/// held, no receipt. No saved head is created or lowered.
#[test]
fn ordinary_fence_outcomes_settle_the_owed_challenge_by_their_own_rules() {
    let none = BTreeSet::new();
    for (outcome, permanent) in [
        ("accepted_log_stale_older_upload", Some(true)),
        ("usage_accounting_authority_downgrade", Some(true)),
        ("accepted_log_stale_older_mixed", Some(false)),
        ("dominated_by_head", None),
    ] {
        let mut progress = fresh_progress();
        let owed = body("owed", None);
        let key = cache_session_key("owed");
        owe(&mut progress, &owed, challenge(0xc));
        let (result, wires) = page(
            &mut progress,
            std::slice::from_ref(&owed),
            &none,
            |request, _| {
                let item = &request.snapshots[0];
                let mut ack = empty_ack();
                match permanent {
                    Some(permanent) => {
                        ack.rejected_entities.push(
                            crate::snapshot_client::SnapshotEntityRejection {
                                source_session_id: item.source_session_id.clone(),
                                snapshot_fingerprint: item.snapshot_fingerprint.clone(),
                                occurrence_count: 1,
                                permanent,
                                reason: outcome.into(),
                                detail: String::new(),
                            },
                        );
                    }
                    None => {
                        let version =
                            crate::snapshot_client::snapshot_ack_body_witness_version(item)
                                .unwrap();
                        ack.accepted = 1;
                        ack.unchanged_entities.push(SnapshotEntityRef {
                            body_witness_version: version,
                            body_witness_digest: version
                                .map(|_| snapshot_upload_body_witness(item)),
                            unchanged_basis: Some(outcome.into()),
                            ..reference(item)
                        });
                    }
                }
                Ok(ack)
            },
        );
        assert!(wires[0].get("head_cas_contract").is_none(), "{outcome}");
        let result = result.unwrap();
        let retryable = permanent == Some(false);
        assert_eq!(
            progress.head_conflict_challenges.contains_key(&key),
            retryable,
            "{outcome}"
        );
        if retryable {
            assert_eq!(
                result,
                ResumableUploadResult::Deferred {
                    count: 1,
                    isolated: 1
                },
                "{outcome}"
            );
            assert_eq!(progress.head_conflict_challenges[&key].answer_attempts, 0);
        }
        assert!(
            progress.accepted_body_witnesses.is_empty(),
            "{outcome}: no receipt"
        );
        assert!(
            progress
                .quarantined_fingerprints
                .contains_key(&owed.snapshot_fingerprint),
            "{outcome}: held"
        );
        assert!(progress.accepted_cache_heads.is_empty(), "{outcome}");
    }
}

/// [money] Negative control: a legacy reconciliation stays CAS and alone in
/// its request, after the ordinary and patched requests.
#[test]
fn a_legacy_reconciliation_stays_cas_and_alone_in_its_request() {
    let mut store = HeadStore::default();
    let mut progress = fresh_progress();
    let legacy_item = body("legacy", None);
    let ordinary = body("ordinary", None);
    let patched = body("patched", Some(item().cache_observations.unwrap()));
    for item in [&legacy_item, &patched] {
        let head = store.seed(&item.source_session_id);
        progress
            .accepted_cache_heads
            .insert(cache_session_key(&item.source_session_id), head);
    }
    let legacy = BTreeSet::from([legacy_item.snapshot_fingerprint.clone()]);
    let (result, wires) = page(
        &mut progress,
        &[legacy_item, ordinary, patched],
        &legacy,
        |request, wire| Ok(store.post(request, wire)),
    );
    assert_eq!(result.unwrap(), ResumableUploadResult::Completed);
    let shape = wires
        .iter()
        .map(|wire| (wire["head_cas_contract"].is_string(), sessions(wire)))
        .collect::<Vec<_>>();
    assert_eq!(
        shape,
        [
            (false, vec!["ordinary".to_owned()]),
            (true, vec!["patched".to_owned()]),
            (true, vec!["legacy".to_owned()]),
        ]
    );
}

fn with_class(mut item: FamilyItem, class: u8) -> FamilyItem {
    item.class = class;
    item
}

/// [money] A literal family whose root and members differ in patch class
/// (patched root with unpatched members, and the reverse) is cut into
/// class-pure requests, so no unpatched member is sent under CAS. Its groups
/// stay contiguous and root first, and each settles by its own ACKs.
#[test]
fn mixed_class_family_is_class_pure_root_first_in_both_directions() {
    for root_class in [1u8, 0] {
        let member_class = 1 - root_class;
        let mut family = family("root-m", 4, 0);
        family[0].class = root_class;
        family[2].class = member_class;
        family[3].class = member_class;
        let mut items = vec![
            with_class(plain_item(1), 1),
            with_class(plain_item(2), 0),
            with_class(plain_item(3), 1),
        ];
        items.extend(family.iter().cloned());
        let mut seen = Vec::new();
        let mut progress = test_upload_progress();
        let (result, batches) = upload_families(&items, &mut progress, |batch| {
            let class = batch[0].class;
            assert!(
                batch.iter().all(|item| item.class == class),
                "a request is class-pure"
            );
            seen.push(class);
            accept_all(batch)
        });
        assert_eq!(
            result.unwrap(),
            ResumableUploadResult::Completed,
            "root class {root_class}"
        );
        for item in &items {
            assert!(
                progress.accepted_fingerprints.contains(&item.fingerprint),
                "{}",
                item.session
            );
        }
        // Family groups: contiguous, root first, members in session order.
        let flat = batches.concat();
        let first = flat.iter().position(|s| s == "root-m").unwrap();
        assert_eq!(
            flat[first..first + 4],
            family
                .iter()
                .map(|item| item.session.clone())
                .collect::<Vec<_>>()[..],
            "family contiguous and root first"
        );
        // The family's own groups follow its root's class run; singles are
        // grouped by class, ordinary first.
        let expected = if root_class == 1 {
            vec![0, 1, 0]
        } else {
            vec![0, 1]
        };
        assert_eq!(seen, expected, "root class {root_class}");
        let single_runs = batches
            .iter()
            .filter(|sessions| sessions.iter().any(|s| s.starts_with("plain-")))
            .count();
        assert_eq!(single_runs, 2, "one run per class for single bodies");
    }
}

/// [money] A single-class page (Pi, an all-patched page, or all ordinary) is
/// packed exactly as before the class split: same requests, same order.
#[test]
fn single_class_pages_keep_the_previous_batches() {
    for class in [0u8, 1, 2] {
        let mut items = (0..60).rev().map(plain_item).collect::<Vec<_>>();
        items.extend(family("root-s", 5, 0));
        items.extend(family("root-t", 3, 0));
        for item in &mut items {
            item.class = class;
        }
        let (result, batches) = upload_families(&items, &mut test_upload_progress(), accept_all);
        assert_eq!(result.unwrap(), ResumableUploadResult::Completed);
        let mut previous = Vec::new();
        let mut accepted = 0;
        upload_resumable_batches_with_literal_families(
            &items,
            &unique_poison_scope(),
            &mut test_upload_progress(),
            &mut accepted,
            |item| item.fingerprint.as_str(),
            |item| item.fingerprint.clone(),
            |item| Some(item.session.as_str()),
            |_| 0,
            |item| item.root.as_deref(),
            &mut InplaceRetryBudget::default(),
            |batch| {
                previous.push(
                    batch
                        .iter()
                        .map(|item| item.session.clone())
                        .collect::<Vec<_>>(),
                );
                Ok(accepted_batch(batch.len()))
            },
            |_| Ok(()),
        )
        .unwrap();
        assert_eq!(batches, previous, "class {class}");
    }
}

/// [money] The first class request checkpoints; the second is unsent,
/// loses its ACK after the server stored it, or its checkpoint save fails.
/// After a restart from the saved ledger only unsettled bodies are re-sent;
/// a replay of a stored body is an exact repeat (unchanged), so nothing is
/// stored or credited twice. Every class order: ordinary before patched, patched
/// before legacy, and a mixed literal family whose patched root is sent
/// before its ordinary members.
#[test]
fn class_request_lost_after_a_checkpoint_resends_only_unsettled_bodies() {
    for (first, second) in [(0u8, 1u8), (1, 2)] {
        let items = vec![
            with_class(plain_item(1), second),
            with_class(plain_item(2), first),
            with_class(plain_item(3), second),
            with_class(plain_item(4), first),
        ];
        assert_lost_class_request_resends_only_unsettled(&items, first, second);
    }
    // Patched before ordinary: a literal family's patched root group, then
    // its ordinary members' group.
    let mut items = family("root-pm", 3, 0);
    items[0].class = 1;
    assert_lost_class_request_resends_only_unsettled(&items, 1, 0);
}

/// Sends `items` (two classes, `first` sent before `second`) with each loss:
/// the second request's reply lost, the first request's reply lost, and the
/// second request's checkpoint save failing; then restarts from the saved
/// ledger and checks only unsettled bodies are re-sent, once.
fn assert_lost_class_request_resends_only_unsettled(items: &[FamilyItem], first: u8, second: u8) {
    for (lost, save_fails) in [(second, false), (first, false), (second, true)] {
        let root = crate::test_scratch::ScratchDir::new("e2-class-lost");
        let path = root.join("progress.json");
        let mut progress = test_upload_progress();
        progress.save(&path).unwrap();
        // The server stores each new body once; a stored body is unchanged.
        let stored = std::cell::RefCell::new(BTreeMap::<String, usize>::new());
        let serve = |batch: &[FamilyItem]| {
            let mut stored = stored.borrow_mut();
            let (mut accepted, mut unchanged) = (Vec::new(), Vec::new());
            for item in batch {
                if stored.contains_key(&item.fingerprint) {
                    unchanged.push(item.fingerprint.clone());
                } else {
                    stored.insert(item.fingerprint.clone(), 1);
                    accepted.push(item.fingerprint.clone());
                }
            }
            entity_ack_batch(&accepted, &unchanged, &[])
        };
        let mut accepted = 0;
        let mut sent = Vec::new();
        let result = upload_resumable_batches_with_literal_families(
            items,
            &unique_poison_scope(),
            &mut progress,
            &mut accepted,
            |item| item.fingerprint.as_str(),
            |item| item.fingerprint.clone(),
            |item| Some(item.session.as_str()),
            |item| item.class,
            |item| item.root.as_deref(),
            &mut InplaceRetryBudget::default(),
            |batch| {
                sent.push(batch[0].class);
                let response = serve(&batch);
                if batch[0].class == lost && !save_fails {
                    return Err(anyhow!("synthetic lost reply"));
                }
                Ok(response)
            },
            |state| {
                let saving_lost = items
                    .iter()
                    .filter(|item| item.class == lost)
                    .all(|item| state.accepted_fingerprints.contains(&item.fingerprint));
                if save_fails && saving_lost {
                    return Err(anyhow!("synthetic save failure"));
                }
                state.save(&path)
            },
        );
        let case = format!("{first}->{second} lost {lost} save_fails {save_fails}");
        assert!(result.is_err(), "{case}");
        let expected_sent = if lost == first {
            vec![first]
        } else {
            vec![first, second]
        };
        assert_eq!(sent, expected_sent, "{case}: first class first");
        let mut restarted = SnapshotUploadProgress::load(
            &path,
            &format!("{:064x}", 99),
            snapshot_quarantine_witness(SnapshotSource::Codex),
        )
        .unwrap();
        for item in items {
            assert_eq!(
                restarted.accepted_fingerprints.contains(&item.fingerprint),
                lost == second && item.class == first,
                "{case}: {}",
                item.session
            );
        }
        let mut resent = Vec::new();
        let (result, _) = upload_families(items, &mut restarted, |batch| {
            resent.extend(batch.iter().map(|item| item.session.clone()));
            Ok(serve(batch))
        });
        assert_eq!(result.unwrap(), ResumableUploadResult::Completed, "{case}");
        let mut expected = items
            .iter()
            .filter(|item| lost == first || item.class == second)
            .map(|item| item.session.clone())
            .collect::<Vec<_>>();
        expected.sort();
        resent.sort();
        assert_eq!(resent, expected, "{case}: only unsettled bodies, once");
        assert!(
            stored.borrow().values().all(|count| *count == 1),
            "{case}: no body stored twice"
        );
        assert_eq!(stored.borrow().len(), items.len(), "{case}");
        for item in items {
            assert!(restarted.accepted_fingerprints.contains(&item.fingerprint));
        }
        // A repeat pass sends no POST.
        let (result, batches) = upload_families(items, &mut restarted, |_| {
            panic!("a settled page sends no POST")
        });
        assert_eq!(result.unwrap(), ResumableUploadResult::Completed);
        assert!(batches.is_empty());
    }
}
