//! U1a-2a `s` row 1: the persisted parent-prefix proof object (types,
//! ordinals, chain, install checks, backoff). No fixture content comes from a
//! provider account.
use super::*;

fn stamp(ino: u64, extent: u64) -> WakeStamp {
    serde_json::from_value(serde_json::json!({
        "dev": 1,
        "ino": ino,
        "extent": extent,
        "modified": [1_792_540_800, 0],
        "changed": [1_792_540_800, 0],
    }))
    .unwrap()
}

fn seal(scope: &str) -> crate::transcript_acquisition::PrefixSeal {
    serde_json::from_value(serde_json::json!({
        "stamp": {
            "length": 4096,
            "device": 1,
            "inode": 7,
            "modified": [1_792_540_800, 0],
            "changed": [1_792_540_800, 0],
        },
        "scope": scope,
        "sample_len": 4096,
        "head_sha256": sha256_hex(&["head"]),
        "boundary_sha256": sha256_hex(&["boundary"]),
        "verified_unix_seconds": 1_792_540_800,
        "sealed_unix_seconds": 1_792_540_800,
    }))
    .unwrap()
}

fn proof(scope: &str, matched: u64, owned: bool) -> CodexParentPrefixProof {
    let mut digest = codex_parent_prefix_seed();
    for signature in ["s0", "s1"] {
        digest = codex_parent_prefix_chain(&digest, signature);
    }
    CodexParentPrefixProof {
        parent: "019a0000-0000-7000-8000-000000000001".into(),
        parent_seal: seal(scope),
        matched,
        child_digest: codex_digest_hex(&digest),
        owned,
        published: false,
    }
}

/// U-T10(d): ordinals are frozen and invertible; only the cap and deferred
/// classes are proof-owed.
#[test]
fn unresolvable_ordinals_round_trip_and_proof_owed_is_cap_or_deferred() {
    for (at, cause) in CodexParentUnresolvable::ALL.iter().enumerate() {
        assert_eq!(cause.index(), at);
        assert_eq!(CodexParentUnresolvable::from_index(at as u8), Some(*cause));
        assert_eq!(cause.proof_owed(), cause.cap() || cause.deferred());
    }
    assert_eq!(
        CodexParentUnresolvable::from_index(CodexParentUnresolvable::COUNT as u8),
        None
    );
    assert_eq!(CodexParentUnresolvable::from_index(CAUSE_NO_EVIDENCE), None);
    let owed = CodexParentUnresolvable::ALL
        .into_iter()
        .filter(|cause| cause.proof_owed())
        .collect::<Vec<_>>();
    assert_eq!(
        owed,
        [
            CodexParentUnresolvable::Oversize,
            CodexParentUnresolvable::LedgerCapped,
            CodexParentUnresolvable::DeferredRef,
            CodexParentUnresolvable::DeferredRestart,
        ]
    );
}

#[test]
fn prefix_chain_is_seeded_length_prefixed_and_hex_is_strict() {
    let seed = codex_parent_prefix_seed();
    let expected: PrefixDigest = Sha256::digest(CODEX_PARENT_PROOF_FORMAT.as_bytes()).into();
    assert_eq!(seed, expected);
    // The length prefix separates field splits.
    let split =
        |a: &str, b: &str| codex_parent_prefix_chain(&codex_parent_prefix_chain(&seed, a), b);
    assert_ne!(split("ab", "c"), split("a", "bc"));
    assert_eq!(split("a", "bc"), split("a", "bc"));

    let digest = split("a", "bc");
    let hex = codex_digest_hex(&digest);
    assert_eq!(hex.len(), 64);
    assert_eq!(codex_digest_from_hex(&hex), Some(digest));
    assert_eq!(codex_digest_from_hex(&hex.to_uppercase()), None);
    assert_eq!(codex_digest_from_hex(&hex[..63]), None);
    assert_eq!(codex_digest_from_hex(&format!("{}g", &hex[..63])), None);
}

#[test]
fn installable_checks_the_label_the_scope_and_the_digest_only() {
    let scope = crate::transcript_acquisition::Scope(sha256_hex(&["proof-scope"]));
    let owned = proof(&scope.0, 2, true);
    assert_eq!(
        owned.installable(&scope),
        codex_digest_from_hex(&owned.child_digest)
    );
    assert!(proof(&scope.0, 0, false).installable(&scope).is_some());
    // Mislabelled: owned without a match, or a match marked held.
    assert_eq!(proof(&scope.0, 0, true).installable(&scope), None);
    assert_eq!(proof(&scope.0, 2, false).installable(&scope), None);
    // Another scope (a parser, identity or format bump).
    let other = crate::transcript_acquisition::Scope(sha256_hex(&["other"]));
    assert_eq!(owned.installable(&other), None);
    // An undecodable digest.
    let mut bad = owned;
    bad.child_digest = "z".repeat(64);
    assert_eq!(bad.installable(&scope), None);
}

#[test]
fn proof_outcome_ordinals_are_frozen() {
    assert_eq!(ProofOutcome::Owned as u8, 1);
    assert_eq!(ProofOutcome::MemoryRefused as u8, 14);
    assert_eq!(ProofOutcome::SideStale as u8, 15);
    assert_eq!(ProofOutcome::FileCapHeld as u8, 16);
    assert_eq!(ProofOutcome::StepRefusedMemory as u8, 17);
    assert_eq!(ProofOutcome::SideUnreadable as u8, 18);
    assert_eq!(ProofOutcome::LAST, 18);
}

/// Backoff keys on the outcome kind only: 112 s doubling to the audit
/// interval; a new kind starts over; a regressed clock is never parked.
#[test]
fn owed_backoff_keys_on_the_outcome_kind() {
    let now = 1_792_540_800;
    let mut owed = CodexParentProofOwed::new("p".into(), 1, 3, OwedOrigin::Child);
    assert_eq!(owed.wake, ProofWake::Due);
    assert!(!owed.backed_off(now));
    let mut gaps = Vec::new();
    for _ in 0..7 {
        owed.after_attempt(ProofOutcome::ParentExhausted, ProofWake::Backoff, now);
        gaps.push(owed.not_before_unix_seconds - now);
    }
    assert_eq!(gaps, [112, 225, 450, 900, 1800, 3600, 3600]);
    assert_eq!(owed.outcome, ProofOutcome::ParentExhausted as u8);
    assert!(owed.backed_off(now));
    assert!(!owed.backed_off(now + 3600));
    // A clock that went back past the cap is due, not parked.
    assert!(!owed.backed_off(now - 3601));

    owed.after_attempt(ProofOutcome::ChildExhausted, ProofWake::Backoff, now);
    assert_eq!(owed.attempts, 1);
    assert_eq!(owed.not_before_unix_seconds - now, 112);
}

#[test]
fn proof_state_serde_is_tagged_and_round_trips_every_wake() {
    let scope = sha256_hex(&["proof-scope"]);
    let wakes = [
        ProofWake::Due,
        ProofWake::ParentChanged {
            parent: stamp(1, 10),
            child: stamp(2, 20),
        },
        ProofWake::ChildChanged {
            parent: stamp(1, 10),
            child: stamp(2, 20),
        },
        ProofWake::Rewritten {
            parent: None,
            child: stamp(2, 20),
        },
        ProofWake::Census {
            matches: sha256_hex(&["census"]),
            child: stamp(2, 20),
        },
        ProofWake::ParentHeld {
            parent_key: "/p.jsonl".into(),
            generation: 4,
            parent_entry: "none".into(),
            parent: stamp(1, 10),
            lineage: true,
            needed_extent: 4096,
        },
        ProofWake::Backoff,
    ];
    let kinds = [
        "due",
        "parent_changed",
        "child_changed",
        "rewritten",
        "census",
        "parent_held",
        "backoff",
    ];
    for (wake, kind) in wakes.into_iter().zip(kinds) {
        let mut owed =
            CodexParentProofOwed::new("p".into(), 9, CAUSE_NO_EVIDENCE, OwedOrigin::Lineage);
        owed.after_attempt(ProofOutcome::LineageHeld, wake, 1_792_540_800);
        owed.kept = Some(Box::new(proof(&scope, 2, true)));
        let state = CodexParentProofState::Owed(owed);
        let value = serde_json::to_value(&state).unwrap();
        assert_eq!(value["state"], "owed");
        assert_eq!(value["wake"]["kind"], kind);
        assert_eq!(value["origin"], "lineage");
        assert_eq!(
            serde_json::from_value::<CodexParentProofState>(value).unwrap(),
            state
        );
        assert_eq!(
            crate::heap_layout_bound::bound(&state, usize::MAX).is_some(),
            crate::heap_layout_bound::layout_supported()
        );
    }

    let proven = CodexParentProofState::Proven(proof(&scope, 2, true));
    let value = serde_json::to_value(&proven).unwrap();
    assert_eq!(value["state"], "proven");
    assert_eq!(
        serde_json::from_value::<CodexParentProofState>(value).unwrap(),
        proven
    );

    // Older or minimal shapes: `seq`, `origin`, `outcome` default; `kept` is
    // omitted when absent.
    let owed = CodexParentProofOwed::new("p".into(), 0, 3, OwedOrigin::Child);
    let mut value = serde_json::to_value(CodexParentProofState::Owed(owed.clone())).unwrap();
    assert!(value.get("kept").is_none());
    for key in ["seq", "origin", "outcome"] {
        value.as_object_mut().unwrap().remove(key);
    }
    assert_eq!(
        serde_json::from_value::<CodexParentProofState>(value).unwrap(),
        CodexParentProofState::Owed(owed)
    );
}

fn owed(parent: &str, cause: u8, origin: OwedOrigin) -> CodexParentProofState {
    CodexParentProofState::Owed(CodexParentProofOwed::new(parent.into(), 4, cause, origin))
}

fn held_side_record(cause: u8) -> serde_json::Value {
    serde_json::json!({
        "verdict": { "kind": "held", "lineage": true, "cause": cause },
        "seal": serde_json::to_value(seal(&"f".repeat(64))).unwrap(),
        "parsed": serde_json::to_value(stamp(7, 4096)).unwrap(),
        "generation": 1,
        "referenced_epoch": 0,
    })
}

fn temp_index_path(name: &str) -> std::path::PathBuf {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("time")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "ottto-u1a2a-{name}-{}-{unique}",
        std::process::id()
    ));
    fs::create_dir_all(&dir).expect("create temp dir");
    dir.join("index.json")
}

/// Row 34 (rev 2 R1-M5, rev 3 §1.7, rev 4, rev 10 §2.3, rev 11/12): the
/// proof map, both cursors, `seq` and the incarnation persist; the map
/// decodes per entry and then semantically (digest; cause ordinal, or
/// `CAUSE_NO_EVIDENCE` only for lineage; side `Held` causes); the RAM
/// parent fold is rebuilt at load and in the subset; the subset takes the
/// larger `seq`; replay clears the map, cursors and fold but never `seq` or
/// the incarnation. A pre-2a file has none of the keys.
#[test]
fn proof_map_cursors_and_seq_follow_the_index_lifecycle() {
    const P1: &str = "019a0000-0000-7000-8000-000000000001";
    const P2: &str = "019a0000-0000-7000-8000-000000000002";
    let empty = serde_json::to_value(ScanIndex::default()).unwrap();
    for key in [
        "codex_parent_prefix_proofs",
        "codex_parent_proof_cursor",
        "codex_parent_side_cursor",
        "codex_parent_proof_seq",
        "codex_proof_index_incarnation",
        "codex_parent_proof_parents_live",
    ] {
        assert!(empty.get(key).is_none(), "{key}");
    }

    let cause = CodexParentUnresolvable::LedgerCapped.index() as u8;
    let mut index = ScanIndex::default();
    let proofs = [
        (
            "/c/proven.jsonl",
            CodexParentProofState::Proven(proof(&"f".repeat(64), 2, true)),
        ),
        ("/c/owed.jsonl", owed(P1, cause, OwedOrigin::Child)),
        ("/c/owed-2.jsonl", owed(P1, cause, OwedOrigin::Child)),
        (
            "/c/lineage.jsonl",
            owed(P2, CAUSE_NO_EVIDENCE, OwedOrigin::Lineage),
        ),
    ];
    for (key, state) in &proofs {
        index
            .codex_parent_prefix_proofs
            .insert((*key).into(), state.clone());
    }
    index.codex_parent_proof_cursor = Some("/c/owed.jsonl".into());
    index.codex_parent_side_cursor = Some("/p.jsonl".into());
    index.codex_parent_proof_seq = 7;
    index.codex_proof_index_incarnation = "0123456789abcdef0123456789abcdef".into();
    let path = temp_index_path("proof-map");
    index.save(&path).unwrap();
    let loaded = ScanIndex::load(&path).unwrap();
    assert_eq!(
        loaded.codex_parent_prefix_proofs,
        index.codex_parent_prefix_proofs
    );
    assert_eq!(
        loaded.codex_parent_proof_cursor,
        index.codex_parent_proof_cursor
    );
    assert_eq!(
        loaded.codex_parent_side_cursor,
        index.codex_parent_side_cursor
    );
    assert_eq!(loaded.codex_parent_proof_seq, 7);
    assert_eq!(
        loaded.codex_proof_index_incarnation,
        index.codex_proof_index_incarnation
    );
    let live = BTreeMap::from([(P1.to_owned(), 2), (P2.to_owned(), 1)]);
    assert_eq!(loaded.codex_parent_proof_parents_live, live);
    assert!(serde_json::to_value(&loaded)
        .unwrap()
        .get("codex_parent_proof_parents_live")
        .is_none());

    // Per entry, then semantically: each bad entry alone is dropped; the
    // rest of the map, the side records and the index load.
    let mut value = serde_json::to_value(&loaded).unwrap();
    let proofs_value = &mut value["codex_parent_prefix_proofs"];
    proofs_value["/c/bad-digest.jsonl"] = proofs_value["/c/proven.jsonl"].clone();
    proofs_value["/c/bad-digest.jsonl"]["child_digest"] = serde_json::json!("not-hex");
    proofs_value["/c/bad-cause.jsonl"] = proofs_value["/c/owed.jsonl"].clone();
    proofs_value["/c/bad-cause.jsonl"]["cause"] = serde_json::json!(200);
    proofs_value["/c/child-no-evidence.jsonl"] = proofs_value["/c/owed.jsonl"].clone();
    proofs_value["/c/child-no-evidence.jsonl"]["cause"] = serde_json::json!(CAUSE_NO_EVIDENCE);
    proofs_value["/c/malformed.jsonl"] = serde_json::json!({ "state": "owed" });
    value["codex_parent_side"] = serde_json::json!({
        "/p/held-valid.jsonl": held_side_record(cause),
        "/p/held-no-evidence.jsonl": held_side_record(CAUSE_NO_EVIDENCE),
        "/p/held-bad.jsonl": held_side_record(200),
    });
    fs::write(&path, serde_json::to_vec_pretty(&value).unwrap()).unwrap();
    let lenient = ScanIndex::load(&path).unwrap();
    assert!(path.exists(), "never quarantined");
    assert_eq!(
        lenient.codex_parent_prefix_proofs,
        index.codex_parent_prefix_proofs
    );
    assert_eq!(
        lenient.codex_parent_side.keys().collect::<Vec<_>>(),
        ["/p/held-no-evidence.jsonl", "/p/held-valid.jsonl"]
    );
    assert_eq!(lenient.codex_parent_proof_parents_live, live);
    assert_eq!(lenient.codex_parent_proof_seq, 7);

    // A partial checkpoint carries the map, cursors and incarnation, takes
    // the larger `seq`, and folds the parents again.
    let previous = ScanIndex {
        codex_parent_proof_seq: 9,
        ..ScanIndex::default()
    };
    let subset = loaded.committable_subset(&previous, &BTreeSet::new(), &BTreeMap::new());
    assert_eq!(
        subset.codex_parent_prefix_proofs,
        loaded.codex_parent_prefix_proofs
    );
    assert_eq!(
        subset.codex_parent_proof_cursor,
        loaded.codex_parent_proof_cursor
    );
    assert_eq!(
        subset.codex_parent_side_cursor,
        loaded.codex_parent_side_cursor
    );
    assert_eq!(
        subset.codex_proof_index_incarnation,
        loaded.codex_proof_index_incarnation
    );
    assert_eq!(subset.codex_parent_proof_seq, 9);
    assert_eq!(subset.codex_parent_proof_parents_live, live);
    let subset =
        loaded.committable_subset(&ScanIndex::default(), &BTreeSet::new(), &BTreeMap::new());
    assert_eq!(subset.codex_parent_proof_seq, 7);
    if crate::heap_layout_bound::layout_supported() {
        assert!(
            crate::heap_layout_bound::bound(&loaded, usize::MAX).unwrap()
                > crate::heap_layout_bound::bound(&ScanIndex::default(), usize::MAX).unwrap()
        );
    }

    // Replay clears the map, the cursors and the fold, never `seq` or the
    // incarnation.
    let mut replayed = loaded.clone();
    replayed.prepare_historical_replay("replay-1".into());
    assert!(replayed.codex_parent_prefix_proofs.is_empty());
    assert_eq!(replayed.codex_parent_proof_cursor, None);
    assert_eq!(replayed.codex_parent_side_cursor, None);
    assert!(replayed.codex_parent_proof_parents_live.is_empty());
    assert_eq!(replayed.codex_parent_proof_seq, 7);
    assert_eq!(
        replayed.codex_proof_index_incarnation,
        loaded.codex_proof_index_incarnation
    );
}

/// Row 4 (U-T54(e) unit): liveness by any of P's ids in the ownership refs
/// or the owed-parent fold, or by P's key in the side requests; the fold
/// comes back after save, load and the subset, and goes with replay.
#[test]
fn side_liveness_reads_refs_and_the_owed_fold_by_id_and_requests_by_key() {
    const P: &str = "019a0000-0000-7000-8000-00000000000a";
    const PATH_ID: &str = "019a0000-0000-7000-8000-00000000000b";
    let p_key = "/s/rollout-p.jsonl";
    let ids = [P.to_owned(), PATH_ID.to_owned()];
    let mut index = ScanIndex::default();
    assert!(!codex_parent_side_live(&index, p_key, &ids));
    // A path-only id in the refs (an N1 parent with no header).
    index.codex_parent_ownership_refs.insert(PATH_ID.into());
    assert!(codex_parent_side_live(&index, p_key, &ids));
    assert!(!codex_parent_side_live(&index, p_key, &ids[..1]));
    index.codex_parent_ownership_refs.clear();
    // A side request, by P's key only.
    let request: SideRequest = serde_json::from_value(serde_json::json!({
        "dev_ino": [1, 7],
        "needed_extent": 4096,
        "state": { "kind": "live" },
        "state_extent": 4096,
        "state_ctime": [1_792_540_800, 0],
        "attempt_extent": 4096,
        "attempt_ctime": [1_792_540_800, 0],
        "attempts": 0,
        "not_before_unix_seconds": 0,
    }))
    .unwrap();
    index
        .codex_parent_side_requests
        .insert(p_key.into(), request);
    assert!(codex_parent_side_live(&index, p_key, &[]));
    assert!(!codex_parent_side_live(&index, "/s/other.jsonl", &ids));
    index.codex_parent_side_requests.clear();
    // An owed entry naming P, through the fold rebuilt at load and in the
    // subset; a proven entry alone is not liveness.
    let cause = CodexParentUnresolvable::DeferredRef.index() as u8;
    index
        .codex_parent_prefix_proofs
        .insert("/s/child.jsonl".into(), owed(P, cause, OwedOrigin::Child));
    index.codex_parent_prefix_proofs.insert(
        "/s/proven.jsonl".into(),
        CodexParentProofState::Proven(CodexParentPrefixProof {
            parent: PATH_ID.into(),
            ..proof(&"f".repeat(64), 1, true)
        }),
    );
    assert!(
        !codex_parent_side_live(&index, p_key, &ids),
        "not folded yet"
    );
    let path = temp_index_path("side-live");
    index.save(&path).unwrap();
    let loaded = ScanIndex::load(&path).unwrap();
    assert!(codex_parent_side_live(&loaded, p_key, &ids));
    assert!(!codex_parent_side_live(&loaded, p_key, &ids[1..]));
    let subset =
        index.committable_subset(&ScanIndex::default(), &BTreeSet::new(), &BTreeMap::new());
    assert!(codex_parent_side_live(&subset, p_key, &ids));
    let mut replayed = loaded;
    replayed.prepare_historical_replay("replay-1".into());
    assert!(!codex_parent_side_live(&replayed, p_key, &ids));
}
