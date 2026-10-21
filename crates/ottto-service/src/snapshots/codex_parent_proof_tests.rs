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
