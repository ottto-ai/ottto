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
        "codex_proof_index_minted",
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

const OWE_P: &str = "019a0000-0000-7000-8000-000000000001";
const OWE_Q: &str = "019a0000-0000-7000-8000-000000000002";

fn owed_at(index: &ScanIndex, key: &str) -> CodexParentProofOwed {
    match &index.codex_parent_prefix_proofs[key] {
        CodexParentProofState::Owed(owed) => owed.clone(),
        CodexParentProofState::Proven(_) => panic!("{key} is proven"),
    }
}

fn fold(pairs: &[(&str, u32)]) -> BTreeMap<String, u32> {
    pairs
        .iter()
        .map(|(parent, count)| ((*parent).to_owned(), *count))
        .collect()
}

/// Row 2 (rev 3 §3.1, rev 5 R2-M6, rev 11 R1-M1): the owe is idempotent
/// for the same parent (progress kept, no new `seq`), an unused `Proven`
/// is a no-op, a refused `Proven` or another parent takes a fresh `seq`;
/// the owed-parent fold follows every insert and remove and equals a
/// rebuild; a pinned count never decrements; what load would drop, and a
/// `seq` overflow, are refused.
#[test]
fn owe_is_idempotent_takes_a_fresh_seq_and_folds_by_parent() {
    let cause = CodexParentUnresolvable::DeferredRef.index() as u8;
    let capped = CodexParentUnresolvable::LedgerCapped.index() as u8;
    let now = 1_792_540_800;
    let mut index = ScanIndex::default();
    assert!(!index.owe_codex_parent_proof(
        "/c/x",
        OWE_P,
        CAUSE_NO_EVIDENCE,
        OwedOrigin::Child,
        false
    ));
    assert!(!index.owe_codex_parent_proof("/c/x", OWE_P, 200, OwedOrigin::Lineage, false));
    assert!(index.codex_parent_prefix_proofs.is_empty());
    assert_eq!(index.codex_parent_proof_seq, 0);

    assert!(index.owe_codex_parent_proof("/c/a", OWE_P, cause, OwedOrigin::Child, false));
    assert_eq!(owed_at(&index, "/c/a").seq, 1);
    assert_eq!(index.codex_parent_proof_parents_live, fold(&[(OWE_P, 1)]));

    // Same parent: progress kept, the cause follows, no new `seq`.
    if let Some(CodexParentProofState::Owed(owed)) =
        index.codex_parent_prefix_proofs.get_mut("/c/a")
    {
        owed.after_attempt(ProofOutcome::ParentExhausted, ProofWake::Backoff, now);
    }
    assert!(index.owe_codex_parent_proof("/c/a", OWE_P, capped, OwedOrigin::Child, false));
    let kept = owed_at(&index, "/c/a");
    assert_eq!(
        (kept.seq, kept.cause, kept.attempts, kept.wake),
        (1, capped, 1, ProofWake::Backoff)
    );
    assert_eq!(index.codex_parent_proof_seq, 1);
    assert_eq!(index.codex_parent_proof_parents_live, fold(&[(OWE_P, 1)]));

    // Another parent replaces: fresh `seq`, fresh progress, the fold moves.
    assert!(index.owe_codex_parent_proof("/c/a", OWE_Q, cause, OwedOrigin::Child, false));
    let moved = owed_at(&index, "/c/a");
    assert_eq!(
        (moved.seq, moved.attempts, moved.parent.as_str()),
        (2, 0, OWE_Q)
    );
    assert_eq!(index.codex_parent_proof_parents_live, fold(&[(OWE_Q, 1)]));
    assert!(index.owe_codex_parent_proof(
        "/c/b",
        OWE_Q,
        CAUSE_NO_EVIDENCE,
        OwedOrigin::Lineage,
        false
    ));
    assert_eq!(index.codex_parent_proof_parents_live, fold(&[(OWE_Q, 2)]));

    // An unused `Proven` is a no-op; a used and refused one is re-owed.
    let proven = CodexParentProofState::Proven(proof(&"f".repeat(64), 2, true));
    index
        .codex_parent_prefix_proofs
        .insert("/c/p".into(), proven.clone());
    assert!(!index.owe_codex_parent_proof("/c/p", OWE_P, cause, OwedOrigin::Child, false));
    assert_eq!(index.codex_parent_prefix_proofs["/c/p"], proven);
    assert_eq!(index.codex_parent_proof_seq, 3);
    assert!(index.owe_codex_parent_proof("/c/p", OWE_P, cause, OwedOrigin::Child, true));
    assert_eq!(owed_at(&index, "/c/p").seq, 4);
    assert_eq!(
        index.codex_parent_proof_parents_live,
        fold(&[(OWE_P, 1), (OWE_Q, 2)])
    );

    // Remove keeps the fold equal to a rebuild.
    assert!(index.remove_codex_parent_proof("/c/b").is_some());
    assert!(index.remove_codex_parent_proof("/c/b").is_none());
    assert_eq!(
        index.codex_parent_proof_parents_live,
        codex_parent_proof_parents_live(&index.codex_parent_prefix_proofs)
    );
    assert_eq!(
        index.codex_parent_proof_parents_live,
        fold(&[(OWE_P, 1), (OWE_Q, 1)])
    );
    // A pinned count is never decremented (live until the next rebuild).
    index
        .codex_parent_proof_parents_live
        .insert(OWE_P.into(), u32::MAX);
    index.remove_codex_parent_proof("/c/p");
    assert_eq!(index.codex_parent_proof_parents_live[OWE_P], u32::MAX);

    // `seq` overflow refuses; nothing changes.
    index.codex_parent_proof_seq = u64::MAX;
    assert!(!index.owe_codex_parent_proof("/c/z", OWE_P, cause, OwedOrigin::Child, false));
    assert!(!index.codex_parent_prefix_proofs.contains_key("/c/z"));
    assert_eq!(index.codex_parent_proof_seq, u64::MAX);
}

/// Row 2 (rev 3 §3.2, rev 10/11 finish deltas, U-T59(b) unit leg): the
/// record-site transitions, and a finish that applies only with the job's
/// `seq` in the index's own minted incarnation.
#[test]
fn settle_and_finish_move_one_entry_and_the_finish_needs_the_jobs_seq_and_incarnation() {
    let cause = CodexParentUnresolvable::DeferredRef.index() as u8;
    let now = 1_792_540_800;
    let incarnation = "0123456789abcdef0123456789abcdef".to_owned();
    let mut index = ScanIndex {
        codex_proof_index_incarnation: incarnation.clone(),
        ..ScanIndex::default()
    };
    let proven = proof(&"f".repeat(64), 2, true);
    index
        .codex_parent_prefix_proofs
        .insert("/c/p".into(), CodexParentProofState::Proven(proven.clone()));

    // A debt-free use publishes nothing; the first use of a debt publishes once.
    let admitted = || ProofSettle::Admitted { debt: true };
    assert_eq!(
        index.settle_codex_parent_proof_entry("/c/p", ProofSettle::Admitted { debt: false }),
        Some(false)
    );
    assert_eq!(
        index.settle_codex_parent_proof_entry("/c/p", admitted()),
        Some(true)
    );
    assert_eq!(
        index.settle_codex_parent_proof_entry("/c/p", admitted()),
        Some(false)
    );
    assert_eq!(
        index.settle_codex_parent_proof_entry("/c/none", admitted()),
        None
    );
    let published = CodexParentPrefixProof {
        published: true,
        ..proven.clone()
    };

    // A not-proof-owed hold keeps a `Proven` entry.
    assert_eq!(
        index.settle_codex_parent_proof_entry("/c/p", ProofSettle::RemoveOwed),
        None
    );
    assert_eq!(
        index.codex_parent_prefix_proofs["/c/p"],
        CodexParentProofState::Proven(published.clone())
    );

    // P's side held: owed under the child's cause, keeping the proof.
    index.settle_codex_parent_proof_entry(
        "/c/p",
        ProofSettle::ParentHeld {
            cause,
            wake: ProofWake::Backoff,
        },
    );
    let held = owed_at(&index, "/c/p");
    assert_eq!(held.seq, 1);
    assert_eq!(held.origin, OwedOrigin::Child);
    assert_eq!(held.wake, ProofWake::Backoff);
    assert_eq!(held.kept.as_deref(), Some(&published));
    assert_eq!(index.codex_parent_proof_parents_live, fold(&[(OWE_P, 1)]));
    // ...and then a not-proof-owed hold removes the `Owed` entry.
    index.settle_codex_parent_proof_entry("/c/p", ProofSettle::RemoveOwed);
    assert!(index.codex_parent_prefix_proofs.is_empty());
    assert!(index.codex_parent_proof_parents_live.is_empty());

    // Finish: only the job's `seq`, in this minted incarnation.
    assert!(index.owe_codex_parent_proof("/c/c", OWE_P, cause, OwedOrigin::Child, false));
    let seq = owed_at(&index, "/c/c").seq;
    let attempt = || ProofFinish::Attempt {
        outcome: ProofOutcome::ParentExhausted,
        wake: ProofWake::Backoff,
    };
    assert!(!index.finish_codex_parent_proof_entry("/c/c", seq - 1, &incarnation, attempt(), now));
    assert!(!index.finish_codex_parent_proof_entry(
        "/c/c",
        seq,
        "fedcba9876543210fedcba9876543210",
        attempt(),
        now
    ));
    assert!(!index.finish_codex_parent_proof_entry("/c/none", seq, &incarnation, attempt(), now));
    let mut unminted = index.clone();
    unminted.codex_proof_index_incarnation.clear();
    assert!(!unminted.finish_codex_parent_proof_entry("/c/c", seq, "", attempt(), now));
    assert_eq!(owed_at(&index, "/c/c").attempts, 0);
    assert!(index.finish_codex_parent_proof_entry("/c/c", seq, &incarnation, attempt(), now));
    let attempted = owed_at(&index, "/c/c");
    assert_eq!(
        (attempted.attempts, attempted.outcome),
        (1, ProofOutcome::ParentExhausted as u8)
    );

    // Replay, then a re-owe: a new `seq`, so the old job's delta is dropped.
    let mut replayed = index.clone();
    replayed.prepare_historical_replay("replay-1".into());
    assert!(replayed.owe_codex_parent_proof("/c/c", OWE_P, cause, OwedOrigin::Child, false));
    assert!(owed_at(&replayed, "/c/c").seq > seq);
    assert!(!replayed.finish_codex_parent_proof_entry(
        "/c/c",
        seq,
        &incarnation,
        ProofFinish::Proven(proven.clone()),
        now
    ));

    // A proof replaces the entry and leaves the fold.
    assert!(index.finish_codex_parent_proof_entry(
        "/c/c",
        seq,
        &incarnation,
        ProofFinish::Proven(proven.clone()),
        now
    ));
    assert_eq!(
        index.codex_parent_prefix_proofs["/c/c"],
        CodexParentProofState::Proven(proven)
    );
    assert!(index.codex_parent_proof_parents_live.is_empty());
    assert!(!index.finish_codex_parent_proof_entry("/c/c", seq, &incarnation, attempt(), now));
    index.settle_codex_parent_proof_entry("/c/c", ProofSettle::Remove);
    assert!(index.codex_parent_prefix_proofs.is_empty());
}

/// Row 35 (rev 12 §5.3 table, rev 13 R1-L4; U-T59(a)/(c) unit legs): a
/// missing index mints once and reuses while missing; an unsaved reload
/// starts above the owe's high-water, so `seq` never repeats; a saved nonce
/// is kept; a file without one reuses only while it is the same object; a
/// quarantine mints fresh, and the then-missing path reuses it. Nothing is
/// persisted until a use binds the nonce, so an index with no proof work
/// keeps its bytes.
#[test]
fn load_keeps_reuses_or_mints_the_incarnation_and_seq_never_repeats() {
    let cause = CodexParentUnresolvable::DeferredRef.index() as u8;
    let is_nonce = |nonce: &str| {
        nonce.len() == 32
            && nonce
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    };
    let path = temp_index_path("mint");
    let mut missing = ScanIndex::load(&path).unwrap();
    assert!(
        missing.codex_proof_index_incarnation.is_empty(),
        "not before a use"
    );
    let nonce = missing.codex_proof_incarnation_in_use().to_owned();
    assert!(is_nonce(&nonce));
    assert!(missing.owe_codex_parent_proof("/c/a", OWE_P, cause, OwedOrigin::Child, false));
    assert_eq!(missing.codex_parent_proof_seq, 1);

    let mut again = ScanIndex::load(&path).unwrap();
    assert_eq!(again.codex_proof_incarnation_in_use(), nonce);
    assert_eq!(again.codex_parent_proof_seq, 1);
    assert!(again.owe_codex_parent_proof("/c/a", OWE_P, cause, OwedOrigin::Child, false));
    assert_eq!(again.codex_parent_proof_seq, 2, "seq never repeats");

    again.save(&path).unwrap();
    let saved = ScanIndex::load(&path).unwrap();
    assert_eq!(
        saved.codex_proof_index_incarnation, nonce,
        "persisted and kept"
    );
    assert_eq!(saved.codex_parent_proof_seq, 2);

    let bare = temp_index_path("mint-bare");
    ScanIndex::default().save(&bare).unwrap();
    let bytes = fs::read(&bare).unwrap();
    let mut unused = ScanIndex::load(&bare).unwrap();
    unused.save(&bare).unwrap();
    let mut first_index = ScanIndex::load(&bare).unwrap();
    assert!(
        fs::read(&bare).unwrap().len() == bytes.len()
            && serde_json::to_value(&first_index)
                .unwrap()
                .get("codex_proof_index_incarnation")
                .is_none(),
        "no proof work, no persisted incarnation"
    );
    let first = first_index.codex_proof_incarnation_in_use().to_owned();
    assert!(is_nonce(&first));
    assert_ne!(first, nonce);
    assert_eq!(
        ScanIndex::load(&bare)
            .unwrap()
            .codex_proof_incarnation_in_use(),
        first,
        "the same file reuses"
    );
    let other = temp_index_path("mint-other");
    ScanIndex::default().save(&other).unwrap();
    fs::rename(&other, &bare).unwrap();
    assert_ne!(
        ScanIndex::load(&bare)
            .unwrap()
            .codex_proof_incarnation_in_use(),
        first,
        "a replaced file mints"
    );

    fs::write(&path, b"not json").unwrap();
    let mut quarantined = ScanIndex::load(&path).unwrap();
    assert!(!path.exists(), "quarantined");
    let fresh = quarantined.codex_proof_incarnation_in_use().to_owned();
    assert!(is_nonce(&fresh));
    assert_ne!(fresh, nonce);
    assert_eq!(
        quarantined.codex_parent_proof_seq, 2,
        "the path's high-water"
    );
    assert_eq!(
        ScanIndex::load(&path)
            .unwrap()
            .codex_proof_incarnation_in_use(),
        fresh
    );
}

fn side_request(ino: u64) -> SideRequest {
    serde_json::from_value(serde_json::json!({
        "dev_ino": [1, ino],
        "needed_extent": 4096,
        "state": { "kind": "live" },
        "state_extent": 4096,
        "state_ctime": [1_792_540_800, 0],
        "attempt_extent": 4096,
        "attempt_ctime": [1_792_540_800, 0],
        "attempts": 0,
        "not_before_unix_seconds": 0,
    }))
    .unwrap()
}

/// Row 30 (rev 11 §2.7, lease "→ ledger `Gone`"): a dropped key's side
/// record, side request and proof entry go (the owed-parent fold with
/// them), and its ledger entries in the pass's namespace end their
/// generation, every object of that key; other keys and other namespaces
/// are untouched; a second drop changes nothing. Reconciliation drops the
/// same items for each key it retires, and only for those.
#[test]
fn drop_retires_a_keys_side_and_proof_items_and_its_ledger_generation() {
    use crate::snapshots::sampled_scan::side_ledger::{
        namespace_of, parent_of, LedgerEntry, LedgerKey, LedgerTag,
    };
    let cause = CodexParentUnresolvable::DeferredRef.index() as u8;
    let (dropped, kept) = ("/s/dropped.jsonl", "/s/kept.jsonl");
    let record: CodexParentSide = serde_json::from_value(held_side_record(cause)).unwrap();
    let mut index = ScanIndex::default();
    for key in [dropped, kept] {
        index.codex_parent_side.insert(key.into(), record.clone());
        index
            .codex_parent_side_requests
            .insert(key.into(), side_request(7));
    }
    assert!(index.owe_codex_parent_proof(dropped, OWE_P, cause, OwedOrigin::Child, false));
    assert!(index.owe_codex_parent_proof(kept, OWE_Q, cause, OwedOrigin::Child, false));

    let cache = sampled_scan::SharedCache::default();
    let ns = namespace_of(Path::new("/idx/a.json"));
    let other_ns = namespace_of(Path::new("/idx/b.json"));
    let now = 1_792_540_800;
    let ledger_key = |ns, key: &str, ino| LedgerKey {
        ns,
        p: parent_of(key),
        dev: 1,
        ino,
    };
    let layout = crate::heap_layout_bound::layout_supported();
    let ledger_keys = [
        ledger_key(ns, dropped, 7),
        ledger_key(ns, dropped, 8),
        ledger_key(ns, kept, 7),
        ledger_key(other_ns, dropped, 7),
    ];
    if layout {
        let mut ledger = cache.side_ledger();
        for key in ledger_keys {
            ledger
                .charge(key, LedgerEntry::of_request(&side_request(key.ino)), now)
                .unwrap();
        }
    }
    let before = |key: &LedgerKey| cache.side_ledger().get(key).copied();
    let stamped = ledger_keys.map(|key| before(&key));

    index.drop_codex_proof_items(dropped, Some((&cache, ns)));
    for map_has in [
        index.codex_parent_side.contains_key(dropped),
        index.codex_parent_side_requests.contains_key(dropped),
        index.codex_parent_prefix_proofs.contains_key(dropped),
    ] {
        assert!(!map_has);
    }
    assert!(index.codex_parent_side.contains_key(kept));
    assert!(index.codex_parent_side_requests.contains_key(kept));
    assert!(index.codex_parent_prefix_proofs.contains_key(kept));
    assert_eq!(index.codex_parent_proof_parents_live, fold(&[(OWE_Q, 1)]));
    assert_eq!(
        index.codex_parent_proof_parents_live,
        codex_parent_proof_parents_live(&index.codex_parent_prefix_proofs)
    );
    if layout {
        let ledger = cache.side_ledger();
        for (at, key) in ledger_keys.iter().enumerate() {
            let entry = ledger.get(key).copied().unwrap();
            let was = stamped[at].unwrap();
            if at < 2 {
                assert_eq!(entry.tag, LedgerTag::Gone, "{at}");
                assert!(entry.wseq > was.wseq, "{at}: freshly stamped");
                assert_eq!(entry.needed_extent, was.needed_extent);
            } else {
                assert_eq!(entry, was, "{at}: untouched");
            }
        }
    }
    let after = ledger_keys.map(|key| before(&key));
    index.drop_codex_proof_items(dropped, Some((&cache, ns)));
    assert_eq!(
        ledger_keys.map(|key| before(&key)),
        after,
        "a second drop is a no-op"
    );

    // Reconciliation: the unobserved, unprotected key goes with its items.
    let mut reconciled = ScanIndex {
        files: [dropped, kept]
            .into_iter()
            .map(|key| {
                (
                    key.to_owned(),
                    super::tests::manifest_index_entry(Some(key)),
                )
            })
            .collect(),
        traversal: Some(ScanTraversalCheckpoint {
            context_fingerprint: "context".to_string(),
            census_window_end: "2026-07-31T00:00:00Z".to_string(),
            scan_roots: Vec::new(),
            pending_directories: VecDeque::new(),
            pending_candidates: VecDeque::new(),
            observed_index_keys: [kept.to_owned()].into_iter().collect(),
            oversized_discovery: Default::default(),
            codex_rollout_paths: BTreeSet::new(),
            codex_join_directory_census: None,
            reconciliation_upper_bound: Some(kept.to_owned()),
            reconciliation_after: None,
            reconciliation_started: false,
            watcher_hint_seen: false,
            codex_freshness_yield: false,
            codex_parent_resolution_retry_required: false,
            unhealthy_retry_attempt: 0,
            unhealthy_retry_not_before_unix_seconds: None,
            counts: ScanTraversalCounts::default(),
            residue: ScanTraversalResidue::default(),
            context_inputs: None,
        }),
        ..ScanIndex::default()
    };
    for key in [dropped, kept] {
        reconciled
            .codex_parent_side
            .insert(key.into(), record.clone());
        reconciled
            .codex_parent_side_requests
            .insert(key.into(), side_request(7));
        assert!(reconciled.owe_codex_parent_proof(key, OWE_P, cause, OwedOrigin::Child, false));
    }
    assert!(reconcile_missing_index_entries_with_limit(
        &mut reconciled,
        8
    ));
    assert_eq!(reconciled.files.keys().collect::<Vec<_>>(), [kept]);
    assert_eq!(
        reconciled.codex_parent_side.keys().collect::<Vec<_>>(),
        [kept]
    );
    assert_eq!(
        reconciled
            .codex_parent_side_requests
            .keys()
            .collect::<Vec<_>>(),
        [kept]
    );
    assert_eq!(
        reconciled
            .codex_parent_prefix_proofs
            .keys()
            .collect::<Vec<_>>(),
        [kept]
    );
    assert_eq!(
        reconciled.codex_parent_proof_parents_live,
        fold(&[(OWE_P, 1)])
    );
}

/// Row 36 (rev 16 §2.3, lease "→ ledger `Gone`"): replay reports whether
/// it reset the index; after a reset, the index's ledger entries end their
/// generation, so the next C14 hydrates none of them back. Control: without
/// the mirror, C14 restores the request replay cleared. Another
/// namespace's entry is untouched.
#[test]
fn replay_ends_the_namespace_ledger_generation_so_c14_restores_nothing() {
    use crate::snapshots::sampled_scan::side_ledger::{
        namespace_of, parent_of, LedgerEntry, LedgerKey, LedgerTag,
    };
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let key = "/s/replayed.jsonl";
    let path = Path::new("/idx/replay.json");
    let other = Path::new("/idx/other.json");
    let now = 1_792_540_800;
    let ledger_key = |index_path| LedgerKey {
        ns: namespace_of(index_path),
        p: parent_of(key),
        dev: 1,
        ino: 7,
    };
    for mirror in [false, true] {
        let cache = sampled_scan::SharedCache::default();
        {
            let mut ledger = cache.side_ledger();
            for index_path in [path, other] {
                ledger
                    .charge(
                        ledger_key(index_path),
                        LedgerEntry::of_request(&side_request(7)),
                        now,
                    )
                    .unwrap();
            }
        }
        let mut index = ScanIndex::default();
        index
            .codex_parent_side_requests
            .insert(key.into(), side_request(7));
        assert!(index.prepare_historical_replay("replay-1".into()));
        assert!(!index.prepare_historical_replay("replay-1".into()));
        assert!(index.codex_parent_side_requests.is_empty());
        if mirror {
            note_codex_side_replay(&cache, path);
            let ledger = cache.side_ledger();
            assert_eq!(ledger.get(&ledger_key(path)).unwrap().tag, LedgerTag::Gone);
            assert_eq!(ledger.get(&ledger_key(other)).unwrap().tag, LedgerTag::Live);
        }
        // The replay pass indexes P again; the next pass's C14 runs on it.
        index
            .files
            .insert(key.into(), super::tests::manifest_index_entry(Some(key)));
        begin_codex_side_pass(&cache, path, &mut index);
        assert_eq!(
            index.codex_parent_side_requests.contains_key(key),
            !mirror,
            "mirror={mirror}"
        );
        let ledger = cache.side_ledger();
        assert_eq!(ledger.get(&ledger_key(path)).is_some(), !mirror);
        assert_eq!(ledger.get(&ledger_key(other)).unwrap().tag, LedgerTag::Live);
    }
}

/// U1a-2a sync-6 (Q1 grant): the pass's replay runs for every source; only
/// an actual reset of a Codex index ends that index's ledger generation. No
/// pending replay, or a repeated same-generation replay, ends nothing, not
/// even an entry charged since; another namespace is never touched.
#[test]
fn sync6_replays_every_source_and_mirrors_only_a_codex_reset() {
    use crate::snapshots::sampled_scan::side_ledger::{
        namespace_of, parent_of, LedgerEntry, LedgerKey, LedgerTag,
    };
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let key = "/s/sync6.jsonl";
    let path = Path::new("/idx/sync6.json");
    let other = Path::new("/idx/sync6-other.json");
    let ledger_key = |index_path: &Path, ino: u64| LedgerKey {
        ns: namespace_of(index_path),
        p: parent_of(key),
        dev: 1,
        ino,
    };
    let charge = |cache: &sampled_scan::SharedCache, index_path: &Path, ino: u64| {
        cache
            .side_ledger()
            .charge(
                ledger_key(index_path, ino),
                LedgerEntry::of_request(&side_request(ino)),
                1_792_540_800,
            )
            .unwrap();
    };
    let entry = |cache: &sampled_scan::SharedCache, index_path: &Path, ino: u64| {
        cache
            .side_ledger()
            .get(&ledger_key(index_path, ino))
            .copied()
    };
    for source in [
        SnapshotSource::Codex,
        SnapshotSource::ClaudeCode,
        SnapshotSource::Pi,
    ] {
        let ended = if source == SnapshotSource::Codex {
            LedgerTag::Gone
        } else {
            LedgerTag::Live
        };
        let cache = sampled_scan::SharedCache::default();
        charge(&cache, path, 7);
        charge(&cache, other, 7);
        let mut index = ScanIndex::default();
        index
            .codex_parent_side_requests
            .insert(key.into(), side_request(7));
        let replay = |index: &mut ScanIndex, pending: bool, generation: &str| {
            prepare_historical_replay_with_side(
                index,
                pending,
                generation.into(),
                source,
                &cache,
                path,
            )
        };

        // No replay pending: nothing runs.
        assert!(!replay(&mut index, false, "g1"));
        assert_eq!(index.historical_replay_generation, None);
        assert_eq!(index.codex_parent_side_requests.len(), 1);
        assert_eq!(entry(&cache, path, 7).unwrap().tag, LedgerTag::Live);

        // The replay runs for every source; only a Codex reset is mirrored.
        assert!(replay(&mut index, true, "g1"), "{source:?}");
        assert_eq!(index.historical_replay_generation.as_deref(), Some("g1"));
        assert!(index.codex_parent_side_requests.is_empty(), "{source:?}");
        assert_eq!(entry(&cache, path, 7).unwrap().tag, ended, "{source:?}");
        assert_eq!(entry(&cache, other, 7).unwrap().tag, LedgerTag::Live);

        // Charged since: a repeated same-generation replay ends nothing.
        charge(&cache, path, 9);
        let since = entry(&cache, path, 9);
        assert!(!replay(&mut index, true, "g1"), "{source:?}");
        assert_eq!(entry(&cache, path, 9), since, "{source:?}");
        assert_eq!(entry(&cache, other, 7).unwrap().tag, LedgerTag::Live);

        // A new generation is a new replay.
        assert!(replay(&mut index, true, "g2"), "{source:?}");
        assert_eq!(entry(&cache, path, 9).unwrap().tag, ended, "{source:?}");
        assert_eq!(entry(&cache, other, 7).unwrap().tag, LedgerTag::Live);
    }
}

/// U1a-2a sync-6 (Q1 grant) custody, on a real index file. After a Codex
/// replay ends the pre-replay entry, the save fails: the reloaded pre-replay
/// index hydrates nothing old (the replay re-runs: its generation never
/// reached disk). A save callback in flight for the pre-replay slot
/// incarnation lands on the slot's next incarnation and proves nothing. A
/// repeated replay retires nothing of the new generation, and another
/// namespace is never touched.
#[test]
fn sync6_after_a_replay_a_failed_save_or_stale_slot_restores_nothing_old_and_retires_nothing_new() {
    use crate::snapshots::sampled_scan::side_ledger::{
        namespace_of, parent_of, LedgerEntry, LedgerKey, LedgerTag,
    };
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    const GENERATION: &str = "codex:sync6-custody:g1";
    let key = "/s/sync6-custody.jsonl";
    let path = temp_index_path("sync6-custody");
    let other = Path::new("/idx/sync6-custody-other.json");
    let ledger_key = |index_path: &Path, ino: u64| LedgerKey {
        ns: namespace_of(index_path),
        p: parent_of(key),
        dev: 1,
        ino,
    };
    let cache = sampled_scan::SharedCache::default();
    let charge = |index_path: &Path, ino: u64| {
        cache
            .side_ledger()
            .charge(
                ledger_key(index_path, ino),
                LedgerEntry::of_request(&side_request(ino)),
                1_792_540_800,
            )
            .unwrap();
    };
    let tag = |index_path: &Path, ino: u64| {
        cache
            .side_ledger()
            .get(&ledger_key(index_path, ino))
            .map(|entry| entry.tag)
    };
    // The pass's replay, pending exactly as `sync` derives it.
    let replay = |index: &mut ScanIndex| {
        let pending = index.historical_replay_generation.as_deref() != Some(GENERATION);
        prepare_historical_replay_with_side(
            index,
            pending,
            GENERATION.into(),
            SnapshotSource::Codex,
            &cache,
            &path,
        )
    };
    let requested = |index: &ScanIndex| {
        index
            .codex_parent_side_requests
            .get(key)
            .map(|request| request.dev_ino)
    };
    let mut disk = ScanIndex::default();
    disk.files
        .insert(key.into(), super::tests::manifest_index_entry(Some(key)));
    disk.save(&path).unwrap();
    // A pre-replay entry the file does not hold yet, and another namespace's.
    charge(&path, 7);
    charge(other, 7);

    // Pass 1: C14 hydrates it; the replay ends it; the save fails.
    let mut index = ScanIndex::load(&path).unwrap();
    begin_codex_side_pass(&cache, &path, &mut index);
    assert_eq!(requested(&index), Some((1, 7)));
    assert!(replay(&mut index));
    assert_eq!(requested(&index), None);
    assert_eq!(tag(&path, 7), Some(LedgerTag::Gone));
    let stale = codex_side_save_mark(&cache, &path);
    drop(index);

    // Eight other namespaces' passes replace this index's gate slot.
    for fill in 0..8 {
        begin_codex_side_pass(
            &cache,
            Path::new(&format!("/idx/sync6-custody-fill-{fill}.json")),
            &mut ScanIndex::default(),
        );
    }

    // Pass 2, on the reloaded pre-replay file: nothing old is current.
    let mut index = ScanIndex::load(&path).unwrap();
    assert_eq!(index.historical_replay_generation, None);
    let pass = begin_codex_side_pass(&cache, &path, &mut index);
    assert!(pass.gate.side_allowed, "a fresh slot incarnation");
    assert_eq!(requested(&index), None, "no pre-replay entry hydrated");
    assert_eq!(tag(&path, 7), None, "the ended generation is pruned");
    assert!(replay(&mut index), "the replay re-runs");
    // The save fails again, and pass 1's callback lands late.
    drop(index);
    note_codex_side_pass_saved(&cache, &path, true, stale);

    // Pass 3: the stale incarnation's callback proved no save.
    let mut index = ScanIndex::load(&path).unwrap();
    let pass = begin_codex_side_pass(&cache, &path, &mut index);
    assert!(!pass.gate.side_allowed, "the stale callback moved nothing");
    assert!(replay(&mut index));
    // The replay pass indexes P again; G7 writes its request and entry.
    index
        .files
        .insert(key.into(), super::tests::manifest_index_entry(Some(key)));
    index
        .codex_parent_side_requests
        .insert(key.into(), side_request(9));
    charge(&path, 9);
    let mark = codex_side_save_mark(&cache, &path);
    index.save(&path).unwrap();
    note_codex_side_pass_saved(&cache, &path, true, mark);

    // Pass 4: the replay is held; a repeated one retires nothing new.
    let mut index = ScanIndex::load(&path).unwrap();
    assert_eq!(
        index.historical_replay_generation.as_deref(),
        Some(GENERATION)
    );
    let pass = begin_codex_side_pass(&cache, &path, &mut index);
    assert!(pass.gate.side_allowed, "the fresh save is proven");
    assert_eq!(requested(&index), Some((1, 9)));
    charge(&path, 11);
    assert!(!prepare_historical_replay_with_side(
        &mut index,
        true,
        GENERATION.into(),
        SnapshotSource::Codex,
        &cache,
        &path,
    ));
    assert_eq!(requested(&index), Some((1, 9)));
    assert_eq!(tag(&path, 11), Some(LedgerTag::Live));
    assert_eq!(tag(other, 7), Some(LedgerTag::Live));
}

/// U1a-2a row 35 (disclosed review item): a poisoned `MINTED` lock is
/// recovered on the next use, uncounted, with its memo intact; a failed save
/// after first use (nothing reaches the file) keeps the incarnation and the
/// seq high-water, so the reloaded, unchanged file reuses the nonce and its
/// next owe never repeats a seq.
#[test]
fn minted_poison_recovers_and_a_failed_save_keeps_the_incarnation_and_seq() {
    let cause = CodexParentUnresolvable::DeferredRef.index() as u8;
    let path = temp_index_path("mint-poison");
    ScanIndex::default().save(&path).unwrap();
    let mut first = ScanIndex::load(&path).unwrap();
    let nonce = first.codex_proof_incarnation_in_use().to_owned();
    assert!(first.owe_codex_parent_proof("/c/a", OWE_P, cause, OwedOrigin::Child, false));
    assert_eq!(first.codex_parent_proof_seq, 1);
    drop(first);

    let poisoner = std::thread::spawn(|| {
        let _held = minted_proof_incarnations();
        panic!("poison MINTED (expected by this test)");
    });
    assert!(poisoner.join().is_err(), "the holder panicked");

    let mut reloaded = ScanIndex::load(&path).unwrap();
    assert!(!MINTED_PROOF_INCARNATIONS.is_poisoned(), "recovered");
    assert!(reloaded.codex_proof_index_incarnation.is_empty());
    assert_eq!(reloaded.codex_proof_incarnation_in_use(), nonce);
    assert!(reloaded.owe_codex_parent_proof("/c/a", OWE_P, cause, OwedOrigin::Child, false));
    assert_eq!(reloaded.codex_parent_proof_seq, 2, "seq never repeats");
}
