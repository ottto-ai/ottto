//! U1a-2a D6(a): proof consumption at `new_source_parser`'s Codex arm,
//! pinned against BASE (main's parse of the same bytes and evidence): a
//! refused, missing, mis-scoped or mismatched proof is BASE exactly; only an
//! admitted proof that decides as it says changes the child. Fixtures are
//! synthetic bytes; nothing comes from a provider account.
use super::*;
use crate::transcript_acquisition::{PrefixSeal, SAMPLE_BYTES};
use sampled_scan::codex_cursor::OpenStamp;
use std::os::unix::fs::FileExt;

const PARENT: &str = "019fd6a0-0000-7000-8000-000000000001";
const CHILD: &str = "019fd6a0-0000-7000-8000-000000000002";
const OTHER: &str = "019fd6a0-0000-7000-8000-000000000003";

fn temp_root(name: &str) -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "ottto-u1a2a-proof-use-{name}-{}-{unique}",
        std::process::id()
    ));
    fs::create_dir_all(&root).unwrap();
    root
}

fn rollout(dir: &Path, id: &str) -> PathBuf {
    dir.join(format!("rollout-2026-08-02T08-00-00-{id}.jsonl"))
}

fn write_values(path: &Path, values: &[Value]) {
    let mut bytes = Vec::new();
    for value in values {
        bytes.extend_from_slice(serde_json::to_string(value).unwrap().as_bytes());
        bytes.push(b'\n');
    }
    fs::write(path, bytes).unwrap();
}

fn turn(timestamp: &str, turn_id: &str) -> Value {
    json!({"timestamp": timestamp, "type": "turn_context", "payload": {"turn_id": turn_id, "model": "gpt-5.6-sol"}})
}

fn tokens(timestamp: &str, total: (u64, u64, u64, u64), last: (u64, u64, u64, u64)) -> Value {
    let usage = |(input, cached, output, reasoning): (u64, u64, u64, u64)| {
        json!({
            "input_tokens": input,
            "cached_input_tokens": cached,
            "output_tokens": output,
            "reasoning_output_tokens": reasoning,
        })
    };
    json!({
        "timestamp": timestamp,
        "type": "event_msg",
        "payload": {
            "type": "token_count",
            "info": {
                "total_token_usage": usage(total),
                "last_token_usage": usage(last),
                "model": "gpt-5.6-sol",
            }
        }
    })
}

fn parent_values() -> Vec<Value> {
    vec![
        json!({"timestamp": "2026-08-02T08:00:00Z", "type": "session_meta", "payload": {"id": PARENT, "thread_source": "user"}}),
        turn("2026-08-02T08:00:01Z", "parent-turn"),
        tokens("2026-08-02T08:00:02Z", (100, 80, 10, 2), (100, 80, 10, 2)),
        turn("2026-08-02T08:30:01Z", "parent-later"),
        tokens("2026-08-02T08:30:02Z", (150, 115, 18, 3), (50, 35, 8, 1)),
    ]
}

/// A fork of `PARENT` that inherits P's first turn, then diverges.
fn child_values() -> Vec<Value> {
    let parent = parent_values();
    vec![
        json!({"timestamp": "2026-08-02T08:20:00Z", "type": "session_meta", "payload": {"id": CHILD, "forked_from_id": PARENT, "thread_source": "user"}}),
        parent[1].clone(),
        parent[2].clone(),
        turn("2026-08-02T08:20:01Z", "child-local"),
        tokens("2026-08-02T08:20:02Z", (115, 92, 13, 3), (15, 12, 3, 1)),
    ]
}

fn signatures(values: &[Value]) -> Vec<String> {
    values
        .iter()
        .filter_map(codex_ownership_signature)
        .collect()
}

/// The proof of `child` against `parent`: m = the leading signatures the
/// child shares with P, the chain over the child's s_0..s_m.
fn proof_of(child: &[Value], parent: &[Value], seal: PrefixSeal) -> CodexParentPrefixProof {
    let parent = signatures(parent);
    let child = signatures(&child[1..]);
    let matched = parent
        .iter()
        .zip(&child)
        .take_while(|(parent, child)| parent == child)
        .count();
    let mut digest = codex_parent_prefix_seed();
    for signature in &child[..=matched] {
        digest = codex_parent_prefix_chain(&digest, signature);
    }
    CodexParentPrefixProof {
        parent: PARENT.into(),
        parent_seal: seal,
        matched: matched as u64,
        child_digest: codex_digest_hex(&digest),
        owned: matched > 0,
        published: false,
    }
}

fn installed(proof: &CodexParentPrefixProof) -> (CodexParentPrefixProof, PrefixDigest) {
    let digest = codex_digest_from_hex(&proof.child_digest).unwrap();
    (proof.clone(), digest)
}

/// P's seal as it is now, the way `Checkpoint::seal_as` mints it (also the
/// cursor tests' proof fixtures).
pub(in crate::snapshots) fn seal_of(file: &File, verified: u64, scope: &str) -> PrefixSeal {
    let metadata = file.metadata().unwrap();
    let len = metadata.len();
    let window = len.min(SAMPLE_BYTES as u64);
    let digest = |offset: u64| {
        let mut bytes = vec![0; window as usize];
        file.read_exact_at(&mut bytes, offset).unwrap();
        Sha256::digest(&bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    };
    serde_json::from_value(json!({
        "stamp": {
            "length": len,
            "device": metadata.dev(),
            "inode": metadata.ino(),
            "modified": [metadata.mtime(), metadata.mtime_nsec()],
            "changed": [metadata.ctime(), metadata.ctime_nsec()],
        },
        "scope": scope,
        "sample_len": window,
        "head_sha256": digest(0),
        "boundary_sha256": digest(len - window),
        "verified_unix_seconds": verified,
        "sealed_unix_seconds": verified,
    }))
    .unwrap()
}

/// A placeholder seal for parse-only cases (the parse never reads it).
fn unused_seal() -> PrefixSeal {
    let root = temp_root("seal");
    let path = root.join("p.jsonl");
    fs::write(&path, b"{}\n").unwrap();
    seal_of(
        &File::open(&path).unwrap(),
        1,
        &codex_parent_proof_scope().0,
    )
}

fn witness(cause: CodexParentUnresolvable) -> BTreeMap<String, CodexParentOwnershipLedger> {
    BTreeMap::from([(
        PARENT.to_string(),
        CodexParentOwnershipLedger {
            unresolvable: Some(cause),
            ..Default::default()
        },
    )])
}

fn complete_ledger() -> BTreeMap<String, CodexParentOwnershipLedger> {
    BTreeMap::from([(
        PARENT.to_string(),
        CodexParentOwnershipLedger {
            signatures: signatures(&parent_values()),
            scan_complete: true,
            opened_object_identity: String::new(),
            unresolvable: None,
            opened_changed_nanos: 0,
            opened_modified_nanos: 0,
            opened_birth_nanos: 0,
        },
    )])
}

fn parse(
    path: &Path,
    ledgers: BTreeMap<String, CodexParentOwnershipLedger>,
    proof: Option<(CodexParentPrefixProof, PrefixDigest)>,
) -> ParsedJsonlFile {
    parse_forged(path, ledgers, proof, |_| {})
}

/// `parse`, with `forge` applied to the accumulator after the last step
/// and before the finish.
fn parse_forged(
    path: &Path,
    ledgers: BTreeMap<String, CodexParentOwnershipLedger>,
    proof: Option<(CodexParentPrefixProof, PrefixDigest)>,
    forge: impl FnOnce(&mut SnapshotAccumulator),
) -> ParsedJsonlFile {
    let metadata = CodexTitleMetadata::default();
    let mut file = File::open(path).unwrap();
    let identity = opened_object_identity(SnapshotSource::Codex, &mut file).unwrap();
    let mut parser = OwnedJsonlParser::new(
        file,
        path,
        SnapshotSource::Codex,
        apply_codex_line,
        Some(&metadata),
        None,
        Some(Arc::new(Mutex::new(ledgers))),
        true,
        true,
    )
    .unwrap();
    parser.accumulator.codex_parent_prefix_proof = proof;
    while !parser.step().unwrap() {}
    forge(&mut parser.accumulator);
    parser
        .finish(
            &identity,
            path,
            "2026-08-02T09:00:00Z",
            "fp".to_string(),
            Some(&metadata),
            None,
            None,
        )
        .unwrap()
}

/// Everything main's record site reads from a parse, minus the proof's own
/// carriers.
fn view(parsed: &ParsedJsonlFile) -> Value {
    json!({
        "snapshots": serde_json::to_value(&parsed.snapshots).unwrap(),
        "report": format!("{:?}", parsed.report),
        "complete": parsed.complete(),
        "pending": parsed.codex_parent_resolution_pending,
        "ownership_incomplete": parsed.ownership_incomplete_file_count,
        "recognized_drop": parsed.recognized_usage_drop_count,
        "dropped": parsed.dropped_usage_record_count,
        "session_ref": parsed.codex_parent_session_ref,
        "unresolvable": parsed.codex_parent_unresolvable.map(CodexParentUnresolvable::index),
        "unusable": parsed.codex_parent_ledger_unusable.map(CodexParentUnresolvable::index),
        "consulted": parsed.codex_parent_ledger_consulted,
        "identity_used": parsed.codex_parent_ledger_identity_used,
    })
}

/// An admitted proof decides as P's complete ledger would: the same owned
/// suffix, never main's cap hold. The proof leaves no ledger identity (no
/// stale-resolution invalidation) and records its decision.
#[test]
fn an_admitted_proof_decides_as_the_complete_ledger_would() {
    let root = temp_root("admit");
    let child = rollout(&root, CHILD);
    write_values(&child, &child_values());
    let proof = proof_of(&child_values(), &parent_values(), unused_seal());
    assert_eq!((proof.matched, proof.owned), (2, true));

    let base = parse(&child, witness(CodexParentUnresolvable::Oversize), None);
    assert_eq!(
        base.codex_parent_unresolvable,
        Some(CodexParentUnresolvable::Oversize)
    );
    assert!(!base.complete());
    let ledger = parse(&child, complete_ledger(), None);
    assert!(ledger.complete());

    for evidence in [
        witness(CodexParentUnresolvable::Oversize),
        witness(CodexParentUnresolvable::LedgerCapped),
        BTreeMap::new(),
    ] {
        let used = parse(&child, evidence, Some(installed(&proof)));
        assert_eq!(
            serde_json::to_value(&used.snapshots).unwrap(),
            serde_json::to_value(&ledger.snapshots).unwrap()
        );
        assert!(used.complete());
        assert_eq!(used.codex_parent_unresolvable, None);
        assert_eq!(used.codex_parent_ledger_identity_used, None);
        assert_eq!(used.codex_parent_proof_used.as_ref(), Some(&proof));
        assert_eq!(used.codex_parent_proof_refusal, None);
        assert_eq!(
            used.codex_parent_prefix_decided,
            Some((2, codex_digest_from_hex(&proof.child_digest).unwrap(), true))
        );
    }
    let _ = fs::remove_dir_all(root);
}

/// A held-at-0 proof holds as main's ledger arm does at index 0.
#[test]
fn a_held_at_zero_proof_holds_as_the_ledger_arm_does() {
    let root = temp_root("zero");
    let child = rollout(&root, CHILD);
    let values = {
        let mut values = child_values();
        values.drain(1..3);
        values
    };
    write_values(&child, &values);
    let proof = proof_of(&values, &parent_values(), unused_seal());
    assert_eq!((proof.matched, proof.owned), (0, false));
    let ledger = parse(&child, complete_ledger(), None);
    let used = parse(
        &child,
        witness(CodexParentUnresolvable::Oversize),
        Some(installed(&proof)),
    );
    assert_eq!(
        serde_json::to_value(&used.snapshots).unwrap(),
        serde_json::to_value(&ledger.snapshots).unwrap()
    );
    assert_eq!(used.complete(), ledger.complete());
    assert_eq!(used.codex_parent_unresolvable, None);
    assert_eq!(used.codex_parent_proof_refusal, None);
    assert_eq!(
        used.codex_parent_prefix_decided
            .map(|(m, _, owned)| (m, owned)),
        Some((0, false))
    );
    let _ = fs::remove_dir_all(root);
}

/// D6(a) BASE pins at the arm: a chain mismatch, EOF inside the proven
/// prefix, a held-at-0 claim the child does not make, and a proof for
/// another parent are each BASE exactly (main's witness hold, or main's
/// pending child with no evidence); a non-cap witness never consults a
/// proof.
#[test]
fn a_mismatched_or_undecided_proof_is_base_exactly() {
    let root = temp_root("mismatch");
    let child = rollout(&root, CHILD);
    write_values(&child, &child_values());
    let good = proof_of(&child_values(), &parent_values(), unused_seal());
    let wrong_chain = CodexParentPrefixProof {
        child_digest: codex_digest_hex(&codex_parent_prefix_chain(
            &codex_parent_prefix_seed(),
            "x",
        )),
        ..good.clone()
    };
    let beyond_eof = CodexParentPrefixProof {
        matched: 9,
        ..good.clone()
    };
    let held_claim = CodexParentPrefixProof {
        matched: 0,
        owned: false,
        child_digest: codex_digest_hex(&codex_parent_prefix_chain(
            &codex_parent_prefix_seed(),
            &signatures(&child_values()[3..])[0],
        )),
        ..good.clone()
    };
    for evidence in [
        witness(CodexParentUnresolvable::Oversize),
        witness(CodexParentUnresolvable::LedgerCapped),
        BTreeMap::new(),
    ] {
        let base = parse(&child, evidence.clone(), None);
        for (name, proof) in [
            ("chain", &wrong_chain),
            ("eof", &beyond_eof),
            ("held", &held_claim),
        ] {
            let refused = parse(&child, evidence.clone(), Some(installed(proof)));
            assert_eq!(view(&refused), view(&base), "{name}");
            assert_eq!(
                refused.codex_parent_proof_refusal,
                Some(ProofRefusal::Decision),
                "{name}"
            );
            assert_eq!(refused.codex_parent_prefix_decided, None, "{name}");
            assert!(!refused.complete(), "{name}");
        }
        let other_parent = CodexParentPrefixProof {
            parent: OTHER.into(),
            ..good.clone()
        };
        let ignored = parse(&child, evidence.clone(), Some(installed(&other_parent)));
        assert_eq!(view(&ignored), view(&base));
        assert_eq!(ignored.codex_parent_proof_used, None);
        assert_eq!(ignored.codex_parent_proof_refusal, None);
    }
    // No evidence: BASE is main's pending child.
    assert!(parse(&child, BTreeMap::new(), None).codex_parent_resolution_pending);
    // A non-cap witness never consults the proof.
    for cause in [
        CodexParentUnresolvable::Absent,
        CodexParentUnresolvable::Duplicated,
        CodexParentUnresolvable::ParentHeld,
    ] {
        let base = parse(&child, witness(cause), None);
        let ignored = parse(&child, witness(cause), Some(installed(&good)));
        assert_eq!(view(&ignored), view(&base), "{cause:?}");
        assert_eq!(ignored.codex_parent_proof_used, None);
    }
    // R1-L3: an arm that decided, but not as the proof says (forged: it
    // cannot occur), fails closed in every build: held under main's cause
    // (`NoLedger` with none), never pending, ownership-incomplete.
    for evidence in [witness(CodexParentUnresolvable::Oversize), BTreeMap::new()] {
        let forged = parse_forged(&child, evidence, Some(installed(&good)), |accumulator| {
            let (matched, digest, owned) = accumulator
                .codex_parent_prefix_decided
                .expect("the arm decided as proven");
            assert_eq!((matched, owned), (good.matched, good.owned));
            accumulator.codex_parent_prefix_decided = Some((matched - 1, digest, owned));
        });
        assert_eq!(
            forged.codex_parent_proof_refusal,
            Some(ProofRefusal::Decision)
        );
        assert_eq!(forged.codex_parent_prefix_decided, None);
        assert_eq!(forged.ownership_incomplete_file_count, 1);
        assert!(!forged.codex_parent_resolution_pending);
        assert!(!forged.complete());
    }
    // A complete ledger wins over the proof.
    let base = parse(&child, complete_ledger(), None);
    let ignored = parse(&child, complete_ledger(), Some(installed(&wrong_chain)));
    assert_eq!(view(&ignored), view(&base));
    assert_eq!(ignored.codex_parent_proof_used, None);
    let _ = fs::remove_dir_all(root);
}

struct Scene {
    root: PathBuf,
    parent: PathBuf,
    child: CandidateFile,
    index: ScanIndex,
}

impl Scene {
    /// P and C on a frozen-valid census, P's side settled and covering, and
    /// C's `Proven` proof sealed over P as it is now.
    fn new(name: &str) -> Self {
        let root = temp_root(name);
        let parent = rollout(&root, PARENT);
        write_values(&parent, &parent_values());
        let child_path = rollout(&root, CHILD);
        write_values(&child_path, &child_values());
        let now = sampled_scan::now_seconds();
        let p_file = File::open(&parent).unwrap();
        let proof = proof_of(
            &child_values(),
            &parent_values(),
            seal_of(&p_file, now, &codex_parent_proof_scope().0),
        );
        let mut index = ScanIndex {
            traversal: Some(ScanTraversalCheckpoint {
                context_fingerprint: "proof-use".to_string(),
                census_window_end: "2026-08-03T00:00:00Z".to_string(),
                scan_roots: vec![root.clone()],
                pending_directories: VecDeque::new(),
                pending_candidates: VecDeque::new(),
                observed_index_keys: BTreeSet::new(),
                oversized_discovery: Default::default(),
                codex_rollout_paths: BTreeSet::from([
                    local_index_key(&parent),
                    local_index_key(&child_path),
                ]),
                codex_join_directory_census: None,
                reconciliation_upper_bound: None,
                reconciliation_after: None,
                reconciliation_started: false,
                watcher_hint_seen: false,
                codex_freshness_yield: false,
                codex_parent_resolution_retry_required: false,
                unhealthy_retry_attempt: 0,
                unhealthy_retry_not_before_unix_seconds: None,
                counts: ScanTraversalCounts::default(),
                residue: ScanTraversalResidue::default(),
            }),
            ..ScanIndex::default()
        };
        index.codex_parent_prefix_proofs.insert(
            local_index_key(&child_path),
            CodexParentProofState::Proven(proof),
        );
        let mut scene = Self {
            root: root.clone(),
            parent,
            child: CandidateFile {
                physical_identity: None,
                scan_root: root,
                path: child_path,
                size_bytes: 0,
                modified_unix_seconds: 0,
                modified_unix_nanos: 0,
                source_file_fingerprint: String::new(),
                legacy_source_file_fingerprint: String::new(),
                legacy_config_reconciliation_required: false,
                opened_object_identity: String::new(),
                fingerprint_changed_nanos: 0,
                fingerprint_birth_nanos: 0,
                withheld_content_stamp: None,
            },
            index,
        };
        scene.settle_side(now);
        scene
    }

    fn settle_side(&mut self, now: u64) {
        let file = File::open(&self.parent).unwrap();
        self.index.codex_parent_side.insert(
            local_index_key(&self.parent),
            CodexParentSide {
                verdict: SideVerdict::Settled,
                seal: seal_of(&file, now, &codex_parent_side_scope().0),
                parsed: OpenStamp::capture(&file).unwrap(),
                pace: None,
                generation: 1,
                referenced_epoch: 0,
            },
        );
    }

    fn key(&self) -> String {
        local_index_key(&self.child.path)
    }

    fn proof(&self) -> CodexParentPrefixProof {
        match self.index.codex_parent_prefix_proofs.get(&self.key()) {
            Some(CodexParentProofState::Proven(proof)) => proof.clone(),
            other => panic!("not proven: {other:?}"),
        }
    }

    /// One install into a fresh parser: (opened, installed, refusal).
    fn install(&mut self) -> (bool, Option<CodexParentPrefixProof>, Option<ProofRefusal>) {
        let identities =
            CodexParentIdentities::new(SnapshotSource::Codex, self.index.traversal.as_ref());
        let mut parser = OwnedJsonlParser::new(
            File::open(&self.child.path).unwrap(),
            &self.child.path,
            SnapshotSource::Codex,
            apply_codex_line,
            None,
            None,
            None,
            true,
            true,
        )
        .unwrap();
        let opened = install_codex_parent_proof(
            &mut parser,
            &self.child,
            &mut self.index,
            &identities,
            None,
            sampled_scan::now_seconds(),
        );
        (
            opened,
            parser
                .accumulator
                .codex_parent_prefix_proof
                .take()
                .map(|(proof, _)| proof),
            parser.accumulator.codex_parent_proof_refusal.take(),
        )
    }
}

impl Drop for Scene {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

/// The install admits only this pass's own `Proven` entry, in scope, on a
/// unique cap-free locate, a settled covering side record and the seal.
#[test]
fn the_install_admits_only_a_fenced_in_scope_proof() {
    let mut scene = Scene::new("install");
    let proof = scene.proof();
    assert_eq!(scene.install(), (true, Some(proof.clone()), None));
    // No `published` write, no request armed: a use is never a publication.
    assert_eq!(scene.proof(), proof);
    assert!(scene.index.codex_parent_side_requests.is_empty());
}

/// D6(a) BASE pins at the install: missing proof, wrong namespace or scope
/// (another index, another proof scope, an owed entry), an unavailable
/// census, an ambiguous parent, an unsettled side and a stale seal each
/// install nothing, so the parse is main's exactly.
#[test]
fn a_missing_foreign_or_refused_proof_installs_nothing() {
    // Missing proof / wrong namespace: this pass's index holds no entry for
    // C (the proof lives in another index), or only an owed one.
    let mut scene = Scene::new("missing");
    let proof = scene.proof();
    let key = scene.key();
    let foreign = std::mem::take(&mut scene.index.codex_parent_prefix_proofs);
    assert!(foreign.contains_key(&key));
    assert_eq!(scene.install(), (false, None, None));
    scene.index.codex_parent_prefix_proofs.insert(
        key.clone(),
        CodexParentProofState::Owed(CodexParentProofOwed::new(
            PARENT.into(),
            0,
            CodexParentUnresolvable::Oversize.index() as u8,
            OwedOrigin::Child,
        )),
    );
    assert_eq!(scene.install(), (false, None, None));
    // Another proof scope (a parser, identity or format bump).
    let mut other_scope = proof.clone();
    other_scope.parent_seal = seal_of(
        &File::open(&scene.parent).unwrap(),
        sampled_scan::now_seconds(),
        &sha256_hex(&["another-proof-scope"]),
    );
    scene
        .index
        .codex_parent_prefix_proofs
        .insert(key.clone(), CodexParentProofState::Proven(other_scope));
    assert_eq!(scene.install(), (false, None, None));

    // An unavailable census (an unfrozen page).
    let mut scene = Scene::new("census");
    scene
        .index
        .traversal
        .as_mut()
        .unwrap()
        .pending_directories
        .push_back(ScanTraversalPath {
            scan_root: scene.root.clone(),
            path: scene.root.join("sub"),
            census_member: true,
            watcher_hint: false,
        });
    assert_eq!(scene.install(), (false, None, None));

    // An ambiguous parent: two rollouts claim P's id.
    let mut scene = Scene::new("ambiguous");
    let twin_dir = scene.root.join("twin");
    fs::create_dir_all(&twin_dir).unwrap();
    let twin = rollout(&twin_dir, PARENT);
    write_values(&twin, &parent_values());
    scene
        .index
        .traversal
        .as_mut()
        .unwrap()
        .codex_rollout_paths
        .insert(local_index_key(&twin));
    assert_eq!(
        scene.install(),
        (
            false,
            None,
            Some(ProofRefusal::Identity(CodexParentUnresolvable::Duplicated))
        )
    );

    // P's side unsettled: no record (held or unknown).
    let mut scene = Scene::new("side");
    scene.index.codex_parent_side.clear();
    let (opened, installed, refusal) = scene.install();
    assert!(opened);
    assert_eq!(installed, None);
    assert!(
        matches!(
            refusal,
            Some(ProofRefusal::Side(ProofWake::ParentHeld { .. }))
        ),
        "{refusal:?}"
    );

    // A stale seal: P's head was rewritten after the proof was sealed; P's
    // side was re-settled over the new bytes, so only the seal refuses.
    let mut scene = Scene::new("stale");
    std::thread::sleep(std::time::Duration::from_millis(20));
    fs::OpenOptions::new()
        .write(true)
        .open(&scene.parent)
        .unwrap()
        .write_all_at(b" ", 0)
        .unwrap();
    scene.settle_side(sampled_scan::now_seconds());
    let (opened, installed, refusal) = scene.install();
    assert!(opened);
    assert_eq!(installed, None);
    assert!(
        matches!(refusal, Some(ProofRefusal::Seal(_))),
        "{refusal:?}"
    );
}

fn parsed(parent: Option<&str>) -> ParsedJsonlFile {
    ParsedJsonlFile {
        snapshots: Vec::new(),
        report: JsonlReadReport::default(),
        recognized_usage_drop_count: 0,
        cause: ownership::PARSER,
        ownership_incomplete_file_count: 0,
        zero_snapshot_usage_evidence: false,
        dropped_usage_record_count: 0,
        terminal_line_loss_count: 0,
        claude_compaction_unlinked_parent_count: 0,
        state_only_blocked_session_ids: BTreeSet::new(),
        codex_parent_session_ref: parent.map(str::to_owned),
        codex_parent_ledger_identity_used: None,
        codex_parent_resolution_pending: false,
        codex_parent_ownership_ledger: None,
        codex_parent_unresolvable: None,
        codex_parent_ledger_unusable: None,
        codex_parent_ledger_consulted: true,
        codex_parent_prefix_decided: None,
        codex_parent_proof_used: None,
        codex_parent_proof_refusal: None,
    }
}

fn held(cause: CodexParentUnresolvable) -> ParsedJsonlFile {
    ParsedJsonlFile {
        ownership_incomplete_file_count: 1,
        codex_parent_unresolvable: Some(cause),
        ..parsed(Some(PARENT))
    }
}

/// rev 3 §3.2 at the record site, one row per outcome.
#[test]
fn the_record_site_settles_the_entry_per_the_table() {
    let scene = Scene::new("settle");
    let key = scene.key();
    let proof = scene.proof();
    let proven = || {
        let mut index = ScanIndex::default();
        index
            .codex_parent_prefix_proofs
            .insert(key.clone(), CodexParentProofState::Proven(proof.clone()));
        index
    };
    let state = |index: &ScanIndex| index.codex_parent_prefix_proofs.get(&key).cloned();
    let wake = ProofWake::Due;

    // Admitted: kept, never a publication.
    let mut index = proven();
    index.settle_codex_parent_proof_use(
        &key,
        &ParsedJsonlFile {
            codex_parent_proof_used: Some(proof.clone()),
            codex_parent_prefix_decided: Some((2, [0; 32], true)),
            ..parsed(Some(PARENT))
        },
    );
    assert_eq!(
        state(&index),
        Some(CodexParentProofState::Proven(proof.clone()))
    );

    // Seal or decision refused (child held): removed, the owe re-proves.
    for refusal in [
        ProofRefusal::Seal(crate::transcript_acquisition::FullReason::Replaced),
        ProofRefusal::Decision,
    ] {
        let mut index = proven();
        index.settle_codex_parent_proof_use(
            &key,
            &ParsedJsonlFile {
                codex_parent_proof_refusal: Some(refusal),
                ..held(CodexParentUnresolvable::Oversize)
            },
        );
        assert_eq!(state(&index), None);
    }

    // Identity refused: kept.
    let mut index = proven();
    index.settle_codex_parent_proof_use(
        &key,
        &ParsedJsonlFile {
            codex_parent_proof_refusal: Some(ProofRefusal::Identity(
                CodexParentUnresolvable::Duplicated,
            )),
            ..held(CodexParentUnresolvable::Oversize)
        },
    );
    assert_eq!(
        state(&index),
        Some(CodexParentProofState::Proven(proof.clone()))
    );

    // Side refused under a proof-owed cause: owed, proof kept.
    let mut index = proven();
    index.settle_codex_parent_proof_use(
        &key,
        &ParsedJsonlFile {
            codex_parent_proof_refusal: Some(ProofRefusal::Side(wake.clone())),
            ..held(CodexParentUnresolvable::Oversize)
        },
    );
    match state(&index) {
        Some(CodexParentProofState::Owed(owed)) => {
            assert_eq!(owed.kept.as_deref(), Some(&proof));
            assert_eq!(owed.cause, CodexParentUnresolvable::Oversize.index() as u8);
            assert_eq!(owed.wake, wake);
        }
        other => panic!("not owed: {other:?}"),
    }
    // Side refused under a cause no proof cures: kept as it was.
    let mut index = proven();
    index.settle_codex_parent_proof_use(
        &key,
        &ParsedJsonlFile {
            codex_parent_proof_refusal: Some(ProofRefusal::Side(wake.clone())),
            ..held(CodexParentUnresolvable::Absent)
        },
    );
    assert_eq!(
        state(&index),
        Some(CodexParentProofState::Proven(proof.clone()))
    );

    // Complete without the proof (resolved another way): removed, even
    // beside a refusal.
    for refusal in [None, Some(ProofRefusal::Side(wake.clone()))] {
        let mut index = proven();
        index.settle_codex_parent_proof_use(
            &key,
            &ParsedJsonlFile {
                codex_parent_proof_refusal: refusal,
                ..parsed(Some(PARENT))
            },
        );
        assert_eq!(state(&index), None);
    }

    // Held under a cause no proof cures: an owed entry goes, a proven stays.
    let mut index = ScanIndex::default();
    assert!(index.owe_codex_parent_proof(
        &key,
        PARENT,
        CodexParentUnresolvable::Oversize.index() as u8,
        OwedOrigin::Child,
        false,
    ));
    index.settle_codex_parent_proof_use(&key, &held(CodexParentUnresolvable::Absent));
    assert_eq!(state(&index), None);
    assert!(index.codex_parent_proof_parents_live.is_empty());
    let mut index = proven();
    index.settle_codex_parent_proof_use(&key, &held(CodexParentUnresolvable::Absent));
    assert_eq!(
        state(&index),
        Some(CodexParentProofState::Proven(proof.clone()))
    );

    // Another parent, or none: removed.
    for parent in [Some(OTHER), None] {
        let mut index = proven();
        index.settle_codex_parent_proof_use(
            &key,
            &ParsedJsonlFile {
                codex_parent_session_ref: parent.map(str::to_owned),
                ..held(CodexParentUnresolvable::Oversize)
            },
        );
        assert_eq!(state(&index), None, "{parent:?}");
    }
}

// U1a-2a row 33 (D6(c)/(d)): the job's readers and lockstep.

fn job_of(parent: &Path, children: &[&Path]) -> CodexProofReaders {
    let now = sampled_scan::now_seconds();
    let parent_reader = CodexProofReader::parent(
        local_index_key(parent),
        parent.to_path_buf(),
        File::open(parent).unwrap(),
        now,
    )
    .unwrap();
    let children = children
        .iter()
        .map(|child| {
            CodexProofReader::child(
                local_index_key(child),
                child.to_path_buf(),
                File::open(child).unwrap(),
            )
            .unwrap()
        })
        .collect();
    CodexProofReaders::new(PARENT.into(), parent_reader, now, children)
}

fn run_to_end(job: &mut CodexProofReaders) -> Vec<ChildResult> {
    let mut budget = u64::MAX;
    assert_eq!(job.run(&mut budget, usize::MAX), CodexProofRun::Done);
    job.children
        .iter()
        .map(|child| child.result.expect("every child has a result"))
        .collect()
}

/// End offset of `values[..=row]` as `write_values` lays them out.
fn row_end(values: &[Value], row: usize) -> u64 {
    values[..=row]
        .iter()
        .map(|value| serde_json::to_string(value).unwrap().len() as u64 + 1)
        .sum()
}

fn unsigned(timestamp: &str) -> Value {
    json!({"timestamp": timestamp, "type": "response_item", "payload": {"type": "message", "role": "user"}})
}

fn proven_from(result: ChildResult) -> CodexParentPrefixProof {
    let ChildResult::Decided {
        matched,
        digest,
        owned,
        ..
    } = result
    else {
        panic!("not decided: {result:?}");
    };
    CodexParentPrefixProof {
        parent: PARENT.into(),
        parent_seal: unused_seal(),
        matched,
        child_digest: codex_digest_hex(&digest),
        owned,
        published: false,
    }
}

/// Ledger/ring parity: each job child's result is the decision main's arm
/// makes from P's complete ledger, and a decided child's proof reparses
/// (under main's cap hold) exactly as the complete ledger does. Covers an
/// owned divergence, a hold at 0, P exhausted, the child exhausted, another
/// parent, an unsigned record between matches, and a boundary-buffer
/// overflow (count-only in job mode, the same 64-record rule).
#[test]
#[cfg_attr(
    not(any(target_os = "macos", target_os = "linux")),
    ignore = "needs macOS heap layout"
)]
fn a_job_decides_as_the_complete_ledger_and_its_proof_reparses_as_main() {
    let root = temp_root("job-parity");
    let parent = rollout(&root, PARENT);
    let parent_rows = parent_values();
    write_values(&parent, &parent_rows);
    let meta = |id: &str, from: &str| json!({"timestamp": "2026-08-02T08:20:00Z", "type": "session_meta", "payload": {"id": id, "forked_from_id": from, "thread_source": "user"}});
    let local = [
        turn("2026-08-02T08:20:01Z", "child-local"),
        tokens("2026-08-02T08:20:02Z", (115, 92, 13, 3), (15, 12, 3, 1)),
    ];
    let fixture = |name: &str, values: Vec<Value>| {
        let dir = root.join(name);
        fs::create_dir_all(&dir).unwrap();
        let path = rollout(&dir, CHILD);
        write_values(&path, &values);
        (path, values)
    };
    let owned = fixture("owned", child_values());
    let held = fixture(
        "held",
        vec![meta(CHILD, PARENT), local[0].clone(), local[1].clone()],
    );
    let parent_exhausted = fixture("p-exhausted", {
        let mut values = vec![meta(CHILD, PARENT)];
        values.extend(parent_rows[1..].iter().cloned());
        values.extend(local.iter().cloned());
        values
    });
    let child_exhausted = fixture(
        "c-exhausted",
        vec![meta(CHILD, PARENT), parent_rows[1].clone()],
    );
    let other = fixture("other", {
        let mut values = child_values();
        values[0] = meta(CHILD, OTHER);
        values
    });
    let gap = fixture(
        "gap",
        vec![
            meta(CHILD, PARENT),
            parent_rows[1].clone(),
            unsigned("2026-08-02T08:00:01Z"),
            parent_rows[2].clone(),
            local[0].clone(),
            local[1].clone(),
        ],
    );
    let overflow = fixture("overflow", {
        let mut values = vec![meta(CHILD, PARENT), parent_rows[1].clone()];
        values.extend((0..65).map(|_| unsigned("2026-08-02T08:00:01Z")));
        values.extend([parent_rows[2].clone(), local[0].clone(), local[1].clone()]);
        values
    });

    let mut first = job_of(
        &parent,
        &[&owned.0, &held.0, &parent_exhausted.0, &child_exhausted.0],
    );
    let mut second = job_of(&parent, &[&other.0, &gap.0, &overflow.0]);
    let results = [run_to_end(&mut first), run_to_end(&mut second)].concat();
    // P's signature 2 is its row 3 (the session_meta row is unsigned).
    let at_m2 = row_end(&parent_rows, 3);
    let at_m0 = row_end(&parent_rows, 1);
    let expect_owned = proof_of(&owned.1, &parent_rows, unused_seal());
    assert_eq!(
        results[0],
        ChildResult::Decided {
            matched: 2,
            digest: codex_digest_from_hex(&expect_owned.child_digest).unwrap(),
            owned: true,
            at: at_m2,
        }
    );
    assert!(matches!(
        results[1],
        ChildResult::Decided { matched: 0, owned: false, at, .. } if at == at_m0
    ));
    assert_eq!(results[2], ChildResult::ParentExhausted);
    assert_eq!(results[3], ChildResult::ChildExhausted);
    assert_eq!(results[4], ChildResult::NotAFork);
    assert!(matches!(
        results[5],
        ChildResult::Decided { matched: 2, owned: true, at, .. } if at == at_m2
    ));
    assert_eq!(results[6], ChildResult::Undecidable);

    // Decided → the proof reparses exactly as the complete ledger.
    for (path, result) in [
        (&owned.0, results[0]),
        (&held.0, results[1]),
        (&gap.0, results[5]),
    ] {
        let ledger = parse(path, complete_ledger(), None);
        let proof = proven_from(result);
        let used = parse(
            path,
            witness(CodexParentUnresolvable::Oversize),
            Some(installed(&proof)),
        );
        assert_eq!(
            serde_json::to_value(&used.snapshots).unwrap(),
            serde_json::to_value(&ledger.snapshots).unwrap(),
            "{}",
            path.display()
        );
        assert_eq!(used.complete(), ledger.complete());
        assert_eq!(used.codex_parent_proof_refusal, None);
    }
    // Undecided under the ledger too: main holds these children.
    for path in [&parent_exhausted.0, &child_exhausted.0, &overflow.0] {
        assert!(
            !parse(path, complete_ledger(), None).complete(),
            "{}",
            path.display()
        );
    }
    let _ = fs::remove_dir_all(root);
}

/// D6(d): P's row straddling its frozen extent is withheld (the sealed
/// fragment): never parsed or observed, so it pushes no signature, and the
/// seal would sit at the last newline. A child that diverges exactly there
/// is `ParentExhausted`, while P's complete ledger (which saw the row) would
/// decide it: the job never decides on a withheld row.
#[test]
#[cfg_attr(
    not(any(target_os = "macos", target_os = "linux")),
    ignore = "needs macOS heap layout"
)]
fn a_straddling_parent_row_pushes_no_signature() {
    let root = temp_root("job-straddle");
    let parent = rollout(&root, PARENT);
    let parent_rows = parent_values();
    write_values(&parent, &parent_rows);
    // Drop the final newline: P's last row now straddles its extent.
    let bytes = fs::read(&parent).unwrap();
    fs::write(&parent, &bytes[..bytes.len() - 1]).unwrap();
    let child = root.join("child");
    fs::create_dir_all(&child).unwrap();
    let child = rollout(&child, CHILD);
    let mut values = vec![
        json!({"timestamp": "2026-08-02T08:40:00Z", "type": "session_meta", "payload": {"id": CHILD, "forked_from_id": PARENT, "thread_source": "user"}}),
    ];
    // P's rows 1..=3 (signatures 0..3), then the child's own turn where P
    // has its withheld row (signature 3).
    values.extend(parent_rows[1..4].iter().cloned());
    values.extend([
        turn("2026-08-02T08:40:01Z", "child-local"),
        tokens("2026-08-02T08:40:02Z", (160, 120, 20, 4), (10, 5, 2, 1)),
    ]);
    write_values(&child, &values);

    let mut job = job_of(&parent, &[&child]);
    assert_eq!(run_to_end(&mut job), vec![ChildResult::ParentExhausted]);
    assert!(job.parent.parser.reader.sealed_fragment());
    assert_eq!(
        job.parent.parser.reader.last_complete_line_end(),
        row_end(&parent_rows, 3)
    );
    // Signatures 0..3 only: the straddling row's never entered the window.
    assert_eq!(job.ring.end(), Some(3));
    // With P's complete ledger (its full parse) main decides at 3.
    let ledger = parse(&child, complete_ledger(), None);
    assert!(ledger.complete());
    assert_eq!(
        ledger
            .codex_parent_prefix_decided
            .map(|(matched, _, owned)| (matched, owned)),
        None,
        "the ledger arm records no proof decision"
    );
    let _ = fs::remove_dir_all(root);
}

/// No overshoot: a run reads only while one more step fits its budget.
#[test]
#[cfg_attr(
    not(any(target_os = "macos", target_os = "linux")),
    ignore = "needs macOS heap layout"
)]
fn a_job_reads_nothing_past_its_budget() {
    let root = temp_root("job-budget");
    let parent = rollout(&root, PARENT);
    write_values(&parent, &parent_values());
    let child = rollout(&root, CHILD);
    write_values(&child, &child_values());
    let reserve = codex_proof_step_reserve();

    let mut job = job_of(&parent, &[&child]);
    let mut budget = reserve - 1;
    assert_eq!(job.run(&mut budget, usize::MAX), CodexProofRun::Budget);
    assert_eq!((budget, job.consumed), (reserve - 1, 0));

    let mut budget = reserve;
    assert_eq!(job.run(&mut budget, usize::MAX), CodexProofRun::Budget);
    assert!(job.consumed > 0 && budget == reserve - job.consumed);

    let mut budget = u64::MAX;
    assert_eq!(job.run(&mut budget, usize::MAX), CodexProofRun::Done);
    assert!(matches!(
        job.children[0].result,
        Some(ChildResult::Decided {
            matched: 2,
            owned: true,
            ..
        })
    ));
    let _ = fs::remove_dir_all(root);
}

/// R2-B1 (rev 5/6 §5.1): before every step the readers' charge and one
/// more line must fit the room. A run whose next line would not fit stops
/// with `Memory` before reading it (at the start and mid-run, buffers
/// already shrunk), and a run's walked peak after any step never passes the
/// room it checked.
#[test]
fn a_run_steps_only_while_one_more_line_fits_its_room() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let root = temp_root("job-room");
    let parent = rollout(&root, PARENT);
    write_values(&parent, &parent_values());
    let child = rollout(&root, CHILD);
    write_values(&child, &child_values());
    // Owner note 4 (r79): the charge of a fresh walk `W` with buffers `B`
    // before one more line: `W + (W - B) + MAX_JSONL_LINE_BYTES`.
    let walk = |job: &mut CodexProofReaders| {
        job.shrink_buffers();
        let walked = crate::heap_layout_bound::bound(&*job, usize::MAX).unwrap();
        walked + (walked - job.buffers()) + MAX_JSONL_LINE_BYTES
    };

    let mut job = job_of(&parent, &[&child]);
    let worst = walk(&mut job);
    let mut budget = u64::MAX;
    assert_eq!(job.run(&mut budget, worst - 1), CodexProofRun::Memory);
    assert_eq!((budget, job.consumed), (u64::MAX, 0), "nothing read");
    // One step, then a room one byte short of the next line.
    let mut budget = codex_proof_step_reserve();
    assert_eq!(job.run(&mut budget, usize::MAX), CodexProofRun::Budget);
    let consumed = job.consumed;
    assert!(consumed > 0);
    let worst = walk(&mut job);
    let mut budget = u64::MAX;
    assert_eq!(job.run(&mut budget, worst - 1), CodexProofRun::Memory);
    assert_eq!((budget, job.consumed), (u64::MAX, consumed));

    // The in-run peak stays within the checked room.
    let mut job = job_of(&parent, &[&child]);
    let room = walk(&mut job) + (1 << 20);
    proof_run_peak();
    let mut budget = u64::MAX;
    assert_eq!(job.run(&mut budget, room), CodexProofRun::Done);
    let (peak, checked) = proof_run_peak();
    assert_eq!(checked, room);
    assert!(peak > 0 && peak <= room, "{peak} > {room}");
    let _ = fs::remove_dir_all(root);
}

/// R2-B1: a suspend shrinks every reader buffer first, so a long line read
/// earlier is not charged while the job waits: the suspended charge is the
/// job's walk with each reader buffer at most 64 KiB.
#[test]
fn a_suspended_job_does_not_keep_a_long_lines_buffer() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let root = temp_root("job-long-line");
    let parent = rollout(&root, PARENT);
    let mut values = parent_values();
    let long = values.len();
    values.push(json!({
        "timestamp": "2026-08-02T08:40:00Z",
        "type": "response_item",
        "payload": {"type": "message", "role": "user", "content": "x".repeat(MAX_JSONL_LINE_BYTES - 4096)},
    }));
    for at in 0..400 {
        values.push(unsigned(&format!("2026-08-02T08:50:{:02}Z", at % 60)));
    }
    write_values(&parent, &values);
    let child = rollout(&root, CHILD);
    write_values(&child, &child_values());
    let mut job = job_of(&parent, &[&child]);
    // Past the long line, well short of P's end.
    let mut budget = codex_proof_step_reserve() + row_end(&values, long) + 4096;
    assert_eq!(job.run(&mut budget, usize::MAX), CodexProofRun::Budget);
    assert!(job.consumed > row_end(&values, long) && !job.parent.done);
    assert!(
        job.parent.parser.reader.buf.capacity() >= MAX_JSONL_LINE_BYTES - 4096,
        "the long line grew P's buffer"
    );
    let buffers = job.buffers();
    let readers = 1 + job.children.len();
    let job = Box::new(sampled_scan::codex_cursor::ProofJob {
        namespace: "proof-hook".into(),
        index_path: PathBuf::from(HOOK_INDEX),
        incarnation: "u1a2a-hook-incarnation".into(),
        entries: Vec::new(),
        next_row_end: 0,
        touched_page: 0,
        readers: Some(Box::new(job)),
    });
    let walked = crate::heap_layout_bound::bound(&*job, usize::MAX).unwrap();
    let cache = Arc::new(sampled_scan::SharedCache::default());
    assert!(sampled_scan::codex_cursor::ProofLease::new(&cache, job).suspend());
    let (_, charge) = cache.proof_suspended_for_test().unwrap();
    assert!(
        charge <= walked - buffers + readers * 64 * 1024,
        "{charge} {walked} {buffers}"
    );
    let _ = fs::remove_dir_all(root);
}

/// Fix round 2b (DM1 ruling (a)): the derived fixed amount an ordinary
/// line adds to the readers' retained state, whatever its length or shape:
/// P's ledger row and one ring slot and a child's paged signature (64-byte
/// signatures), plus the acquisition's head and boundary samples
/// (`SAMPLE_BYTES` each, at most doubled capacity).
const ORDINARY_LINE_RETAINED: usize = 4 * SAMPLE_BYTES + 1024;

/// The job's walked bound less its reader buffers' capacity (the buffer is
/// the charged `MAX_JSONL_LINE_BYTES` term).
fn retained(job: &CodexProofReaders) -> usize {
    crate::heap_layout_bound::bound(job, usize::MAX).unwrap() - job.buffers()
}

/// Readers that have taken their first `session_meta` line.
fn headers_seen(job: &CodexProofReaders) -> usize {
    job.children
        .iter()
        .map(|child| &child.reader)
        .chain(std::iter::once(&job.parent))
        .filter(|reader| reader.parser.accumulator.codex_session_meta_seen)
        .count()
}

/// One reader step (`run` with exactly one step's reserve); the retained
/// growth it caused and whether it took a reader's first header.
fn one_step(job: &mut CodexProofReaders) -> (CodexProofRun, isize, bool) {
    let (before, seen) = (retained(job), headers_seen(job));
    let mut budget = codex_proof_step_reserve();
    let run = job.run(&mut budget, usize::MAX);
    let grew = retained(job) as isize - before as isize;
    (run, grew, headers_seen(job) != seen)
}

/// Fix round 2b (DM1 ruling (a), adversarial control): max-length,
/// container-heavy and field-heavy lines, signed and unsigned, through P's
/// ledger reader and a deciding child: every ordinary step's retained
/// growth is at most `ORDINARY_LINE_RETAINED`, independent of the line.
#[test]
fn an_ordinary_proof_line_retains_a_fixed_amount_whatever_its_length_or_shape() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let root = temp_root("job-line-k");
    let long = MAX_JSONL_LINE_BYTES - 4096;
    // Container-heavy (~2 MiB of empty arrays) and field-heavy (100k keys).
    let items = vec![json!([]); 700_000];
    let fields: serde_json::Map<String, Value> = (0..100_000)
        .map(|at| (format!("k{at:06}"), json!(at)))
        .collect();
    let shared = [
        turn("2026-08-02T08:00:01Z", &"t".repeat(long)),
        json!({"timestamp": "2026-08-02T08:00:02Z", "type": "response_item", "payload": {"type": "message", "role": "user", "content": "x".repeat(long)}}),
        json!({"timestamp": "2026-08-02T08:00:03Z", "type": "response_item", "payload": {"items": items}}),
        json!({"timestamp": "2026-08-02T08:00:04Z", "type": "response_item", "payload": {"fields": fields}}),
        json!({"timestamp": "2026-08-02T08:00:05Z", "type": "token_usage_record", "payload": {"response_id": "r".repeat(1 << 20)}}),
        tokens("2026-08-02T08:00:06Z", (100, 80, 10, 2), (100, 80, 10, 2)),
    ];
    let mut parent_rows = vec![parent_values()[0].clone()];
    parent_rows.extend(shared.iter().cloned());
    parent_rows.push(turn("2026-08-02T08:30:01Z", "parent-later"));
    parent_rows.push(tokens(
        "2026-08-02T08:30:02Z",
        (150, 115, 18, 3),
        (50, 35, 8, 1),
    ));
    let mut child_rows = vec![child_values()[0].clone()];
    child_rows.extend(shared.iter().cloned());
    child_rows.push(turn("2026-08-02T08:20:01Z", "child-local"));
    child_rows.push(tokens(
        "2026-08-02T08:20:02Z",
        (115, 92, 13, 3),
        (15, 12, 3, 1),
    ));
    let parent = rollout(&root, PARENT);
    write_values(&parent, &parent_rows);
    let child = rollout(&root, CHILD);
    write_values(&child, &child_rows);

    let mut job = job_of(&parent, &[&child]);
    let (mut ordinary, mut headers, mut max) = (0, 0, 0);
    loop {
        let (run, grew, header) = one_step(&mut job);
        if header {
            headers += 1;
        } else {
            assert!(
                grew <= ORDINARY_LINE_RETAINED as isize,
                "an ordinary step grew {grew}"
            );
            max = max.max(grew);
            ordinary += 1;
        }
        if run == CodexProofRun::Done {
            break;
        }
        assert_eq!(run, CodexProofRun::Budget);
    }
    assert_eq!(headers, 2, "P's and the child's first header");
    assert!(ordinary >= shared.len() * 2, "{ordinary} ordinary steps");
    assert!(
        matches!(
            job.children[0].result,
            Some(ChildResult::Decided { owned: true, .. })
        ),
        "{:?} (max ordinary growth {max})",
        job.children[0].result
    );
    let _ = fs::remove_dir_all(root);
}

/// Fix round 2b (DM1 reader evidence): what a fixed `k` cannot cover. A
/// reader's first header keeps its strings (the id twice: at least
/// `2 × id`), and an overlong line's paused skip keeps its salvaged
/// timestamp: both line-proportional, so fix rounds 2c/3 charge them by
/// their known lengths (`a_first_header_is_charged_its_kept_strings_...`,
/// `a_salvage_over_its_room_is_not_taken`). A decision-only child whose header
/// takes the legacy arm keeps no decoded record (count-only), however
/// container-heavy the header.
#[test]
fn a_proof_readers_header_and_overlong_salvage_retain_line_proportional_bytes() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let root = temp_root("job-line-proportional");
    let big = 1 << 20;

    // A header with a long id: P's first step keeps it twice.
    let parent = rollout(&root, PARENT);
    let mut values = parent_values();
    values[0] = json!({"timestamp": "2026-08-02T08:00:00Z", "type": "session_meta", "payload": {"id": "p".repeat(big), "thread_source": "user"}});
    write_values(&parent, &values);
    let mut job = job_of(&parent, &[]);
    let (run, grew, header) = one_step(&mut job);
    assert_eq!(run, CodexProofRun::Budget);
    assert!(header && grew >= 2 * big as isize, "header grew {grew}");

    // An overlong line whose capped prefix carries a long timestamp: the
    // paused skip keeps it (the buffer is cleared, E4).
    let timestamp = "2".repeat(4 * big);
    let mut bytes = Vec::new();
    bytes.extend_from_slice(
        serde_json::to_string(&parent_values()[0])
            .unwrap()
            .as_bytes(),
    );
    bytes.push(b'\n');
    bytes.extend_from_slice(format!("{{\"timestamp\":\"{timestamp}\",\"ordinal\":7,\"type\":\"response_item\",\"payload\":{{\"content\":\"").as_bytes());
    bytes.resize(bytes.len() + MAX_JSONL_LINE_BYTES, b'y');
    bytes.extend_from_slice(b"\"}}\n");
    fs::write(&parent, bytes).unwrap();
    sampled_scan::codex_cursor::with_test_limits(2048, 8192, 64 * 1024, || {
        let mut job = job_of(&parent, &[]);
        let (_, _, header) = one_step(&mut job);
        assert!(header);
        let (run, grew, header) = one_step(&mut job);
        assert_eq!(run, CodexProofRun::Budget);
        assert!(
            job.parent.parser.reader.skipping.is_some(),
            "the skip paused"
        );
        assert!(job.parent.parser.reader.buf.is_empty());
        assert!(
            !header && grew >= timestamp.len() as isize,
            "salvage grew {grew}"
        );
    });

    // A legacy-arm job child: count-only, then `NotAFork`.
    write_values(&parent, &parent_values());
    let child = rollout(&root, CHILD);
    let mut rows = child_values();
    let items = vec![json!([]); 350_000];
    rows[0] = json!({"timestamp": "2026-08-02T08:20:00Z", "type": "session_meta", "payload": {
        "id": CHILD, "forked_from_id": PARENT, "source": {"subagent": {"thread_spawn": {}}},
        "type": "task_started", "items": items,
    }});
    write_values(&child, &rows);
    let mut job = job_of(&parent, &[&child]);
    let child_header = loop {
        let seen = job.children[0]
            .reader
            .parser
            .accumulator
            .codex_session_meta_seen;
        let (run, grew, _) = one_step(&mut job);
        if !seen
            && job.children[0]
                .reader
                .parser
                .accumulator
                .codex_session_meta_seen
        {
            break grew;
        }
        assert_eq!(run, CodexProofRun::Budget);
    };
    let accumulator = &job.children[0].reader.parser.accumulator;
    assert_eq!(
        accumulator.codex_ownership_boundary,
        CodexOwnershipBoundary::AwaitingLegacyTrigger
    );
    assert!(accumulator.codex_legacy_bootstrap_buffer.is_empty());
    assert!(
        child_header < 64 * 1024,
        "the child header grew {child_header}"
    );
    assert_eq!(run_to_end(&mut job), vec![ChildResult::NotAFork]);
    let _ = fs::remove_dir_all(root);
}

/// D6(c): the window is allocated once; a push past it, or of an odd shape,
/// is refused (never a silent drop), and indices stay absolute.
#[test]
fn the_ring_refuses_past_its_window_and_odd_shapes() {
    let mut ring = CodexParentRing::new();
    let capacity = ring.entries.capacity();
    assert!(capacity >= CODEX_PROOF_RING_ENTRIES);
    let signature = |at: usize| sha256_hex(&[at.to_string().as_str()]);
    for at in 0..CODEX_PROOF_RING_ENTRIES {
        assert!(ring.push(&signature(at), at as u64));
    }
    assert!(!ring.push(&signature(64), 64));
    assert_eq!(ring.entries.capacity(), capacity, "no growth");
    assert_eq!(ring.end(), Some(64));
    ring.drop_below(10);
    assert_eq!(
        (ring.base, ring.get(9), ring.get(10).map(|entry| entry.1)),
        (10, None, Some(10))
    );
    assert!(ring.push(&signature(64), 64));
    assert_eq!(
        ring.get(64).map(|entry| entry.0.as_str()),
        Some(signature(64).as_str())
    );
    assert!(!ring.push("short", 65));
    assert!(ring
        .entries
        .iter()
        .all(|(value, _)| value.capacity() == CODEX_SIGNATURE_HEX_BYTES));
    assert_eq!(ring.entries.capacity(), capacity, "no growth");
}

// U1a-2a row 31: the proof hook end to end (visit, start, run, finish).

const HOOK_INDEX: &str = "/nonexistent/u1a2a-proof-hook-index.json";

fn hook_context(cache: &Arc<sampled_scan::SharedCache>) -> sampled_scan::Context {
    sampled_scan::Context {
        cache: Arc::clone(cache),
        namespace: crate::transcript_acquisition::Scope("proof-hook".into()),
        audit_metadata_supported: true,
        audit_slots: 0,
        full_files: 0,
        tail_files: 0,
        unchanged_files: 0,
        native_bytes: 0,
        sample_bytes: 0,
        full_reasons: [0; 11],
        priority_replays: 0,
        audits_started: 0,
        audits_completed: 0,
        audit_quiet_retired: 0,
        audit_cap_full: 0,
        audit_cap_delay: 0,
        pace_evicted: 0,
        start_overdue_seconds: 0,
        completion_overdue_seconds: 0,
        admission: Default::default(),
    }
}

fn hook_pass() -> CodexSidePass {
    CodexSidePass {
        ns: sampled_scan::side_ledger::namespace_of(Path::new(HOOK_INDEX)),
        gate: sampled_scan::side_ledger::GateOpen {
            side_allowed: true,
            first_in_process: false,
        },
        index_path: PathBuf::from(HOOK_INDEX),
        kind: CodexPageKind::Ordinary,
    }
}

impl Scene {
    /// C owed (`Due`) against P under main's cap cause, in a minted index.
    fn owed(name: &str) -> Self {
        let mut scene = Self::new(name);
        let key = scene.key();
        // Main indexed both (the sweep drops a side record whose P is not).
        for indexed in [local_index_key(&scene.parent), key.clone()] {
            let entry = super::tests::manifest_index_entry(Some(indexed.as_str()));
            scene.index.files.insert(indexed, entry);
        }
        scene.index.remove_codex_parent_proof(&key);
        scene.index.codex_proof_index_incarnation = "u1a2a-hook-incarnation".into();
        assert!(scene.index.owe_codex_parent_proof(
            &key,
            PARENT,
            CodexParentUnresolvable::Oversize.index() as u8,
            OwedOrigin::Child,
            false,
        ));
        scene
    }

    /// One page's proof hook on `page`.
    fn hook(&mut self, cache: &Arc<sampled_scan::SharedCache>, page: &mut PageBudget) {
        self.hook_in(cache, &hook_pass(), page, sampled_scan::now_seconds());
    }

    /// One page's proof hook on `page`, in `pass`, at `now`.
    fn hook_in(
        &mut self,
        cache: &Arc<sampled_scan::SharedCache>,
        pass: &CodexSidePass,
        page: &mut PageBudget,
        now: u64,
    ) {
        let identities =
            CodexParentIdentities::new(SnapshotSource::Codex, self.index.traversal.as_ref());
        codex_parent_proof_hook::codex_parent_proof_step(
            &mut self.index,
            &hook_context(cache),
            pass,
            &identities,
            page,
            now,
        );
    }

    fn owed_entry(&self) -> CodexParentProofOwed {
        match self.index.codex_parent_prefix_proofs.get(&self.key()) {
            Some(CodexParentProofState::Owed(owed)) => owed.clone(),
            other => panic!("not owed: {other:?}"),
        }
    }
}

use sampled_scan::codex_cursor::{Limits, PageBudget};

/// The hook proves an owed child in one page: P's ledger-only reader and
/// C's decision-only reader lockstep to C's decision, the finish seals P
/// under the proof scope, P's settled side record admits it, and the entry
/// is `Proven` as the complete ledger decides. Its install then reparses C
/// exactly as the complete ledger does. Nothing is left in the holder.
#[test]
#[cfg_attr(
    not(any(target_os = "macos", target_os = "linux")),
    ignore = "needs macOS heap layout"
)]
fn the_hook_proves_an_owed_child_end_to_end() {
    let mut scene = Scene::owed("hook-e2e");
    let cache = Arc::new(sampled_scan::SharedCache::default());
    let mut page = PageBudget::default();
    scene.hook(&cache, &mut page);

    let proof = scene.proof();
    assert_eq!(
        (proof.matched, proof.owned, proof.published),
        (2, true, false)
    );
    assert_eq!(proof.parent, PARENT);
    let expected = proof_of(&child_values(), &parent_values(), unused_seal());
    assert_eq!(proof.child_digest, expected.child_digest);
    assert!(proof.installable(&codex_parent_proof_scope()).is_some());
    assert_eq!(
        proof.parent_seal.sealed_offset(),
        fs::metadata(&scene.parent).unwrap().len()
    );
    assert_eq!(cache.proof_suspended_for_test(), None);
    assert_eq!(scene.index.codex_parent_proof_cursor, Some(scene.key()));
    assert!(page.singleton_remaining(Limits::current()) < Limits::current().singleton());

    let (opened, installed_proof, refusal) = scene.install();
    assert!(opened);
    assert_eq!(refusal, None);
    assert_eq!(installed_proof.as_ref(), Some(&proof));
    let used = parse(
        &scene.child.path,
        witness(CodexParentUnresolvable::Oversize),
        Some(installed(&proof)),
    );
    let ledger = parse(&scene.child.path, complete_ledger(), None);
    assert_eq!(view(&used)["snapshots"], view(&ledger)["snapshots"]);
    assert!(used.complete() && ledger.complete());
}

/// A page whose leftover covers one step only suspends the job (RAM,
/// charged in the holder); the next page takes it back as `Mine`,
/// revalidates its held FDs and P's locate, and finishes it. The entry
/// stays `Owed` in between.
#[test]
#[cfg_attr(
    not(any(target_os = "macos", target_os = "linux")),
    ignore = "needs macOS heap layout"
)]
fn a_budget_short_page_suspends_and_the_next_page_finishes() {
    let mut scene = Scene::owed("hook-suspend");
    let cache = Arc::new(sampled_scan::SharedCache::default());
    let limits = Limits::current();
    let mut page = PageBudget::default();
    // Exactly one step's reserve left after P's fence: P's first row, then
    // `Budget`.
    page.charge(
        false,
        limits.singleton() - codex_proof_step_reserve() - SIDE_FENCE_READ_BYTES,
    );
    scene.hook(&cache, &mut page);
    assert_eq!(scene.owed_entry().outcome, 0, "no finished attempt yet");
    assert!(
        cache
            .proof_suspended_for_test()
            .is_some_and(|(namespace, charge)| namespace == "proof-hook" && charge > 0),
        "suspended in the holder"
    );

    let mut next = PageBudget::default();
    scene.hook(&cache, &mut next);
    assert_eq!(cache.proof_suspended_for_test(), None);
    assert_eq!((scene.proof().matched, scene.proof().owned), (2, true));
}

/// P that the frozen census cannot resolve refuses the batch as `Identity`
/// with a `Census` wake; the next visit does not retry it until the census
/// fingerprint (or C) changes. Then P is back and the job proves C.
#[test]
#[cfg_attr(
    not(any(target_os = "macos", target_os = "linux")),
    ignore = "needs macOS heap layout"
)]
fn an_identity_refusal_waits_for_its_census_wake() {
    let mut scene = Scene::owed("hook-identity");
    let parent_key = local_index_key(&scene.parent);
    let traversal = scene.index.traversal.as_mut().unwrap();
    traversal.codex_rollout_paths.remove(&parent_key);
    let cache = Arc::new(sampled_scan::SharedCache::default());
    scene.hook(&cache, &mut PageBudget::default());
    let owed = scene.owed_entry();
    assert_eq!(owed.outcome, ProofOutcome::Identity as u8);
    assert_eq!(owed.attempts, 1);
    assert!(matches!(
        &owed.wake,
        ProofWake::Census { matches, .. } if matches == "absent"
    ));

    // Same census: not due (the wake has not fired), so nothing is retried.
    scene.hook(&cache, &mut PageBudget::default());
    assert_eq!(scene.owed_entry(), owed);

    // P is in the census again: the wake fires (past its backoff).
    let traversal = scene.index.traversal.as_mut().unwrap();
    traversal.codex_rollout_paths.insert(parent_key);
    if let Some(CodexParentProofState::Owed(owed)) =
        scene.index.codex_parent_prefix_proofs.get_mut(&scene.key())
    {
        owed.not_before_unix_seconds = 0;
    }
    scene.hook(&cache, &mut PageBudget::default());
    assert_eq!((scene.proof().matched, scene.proof().owned), (2, true));
}

/// The singleton bytes `page` spent.
fn spent(page: &PageBudget) -> u64 {
    let limits = Limits::current();
    limits.singleton() - page.singleton_remaining(limits)
}

/// A page with `leftover` singleton bytes.
fn page_with(leftover: u64) -> PageBudget {
    let mut page = PageBudget::default();
    page.charge(false, Limits::current().singleton() - leftover);
    page
}

/// R2-B2: a job dropped for memory backs every entry off (`after_attempt`
/// paces the restart). With no room to suspend (state budget 0), a page
/// that cannot finish P records `MemoryRefused` + `Backoff`, and further
/// passes inside the backoff read nothing: P's bytes are bounded by one
/// leftover per backoff, not one per pass. With no room to step (a full
/// cache), `StepRefusedMemory`, and P is never read. Nothing is proven.
#[test]
fn a_memory_dropped_job_backs_off_and_rereads_nothing_inside_the_backoff() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    // P's fence, then one step: P is not done.
    let leftover = codex_proof_step_reserve() + SIDE_FENCE_READ_BYTES;
    let mut scene = Scene::owed("hook-refused-suspend");
    // After the scene: it seals P's side record at its own clock read, and
    // an earlier `now` is a clock regression to the side fence.
    let now = sampled_scan::now_seconds();
    let cache = Arc::new(sampled_scan::SharedCache::default());
    let mut read = Vec::new();
    for _ in 0..5 {
        let mut page = page_with(leftover);
        sampled_scan::codex_cursor::with_test_state_budget(0, || {
            scene.hook_in(&cache, &hook_pass(), &mut page, now);
        });
        read.push(leftover - page.singleton_remaining(Limits::current()));
    }
    assert!(read[0] > SIDE_FENCE_READ_BYTES, "the first pass read P");
    assert_eq!(read[1..], [0; 4], "inside the backoff: nothing");
    let owed = scene.owed_entry();
    assert_eq!(owed.outcome, ProofOutcome::MemoryRefused as u8);
    assert_eq!((owed.attempts, &owed.wake), (1, &ProofWake::Backoff));
    assert!(owed.not_before_unix_seconds > now);
    assert_eq!(cache.proof_suspended_for_test(), None);
    // Past the backoff: one more paced attempt.
    let later = owed.not_before_unix_seconds + 1;
    let mut page = page_with(leftover);
    sampled_scan::codex_cursor::with_test_state_budget(0, || {
        scene.hook_in(&cache, &hook_pass(), &mut page, later);
    });
    let owed = scene.owed_entry();
    assert_eq!(
        (owed.attempts, owed.outcome),
        (2, ProofOutcome::MemoryRefused as u8)
    );
    assert!(owed.not_before_unix_seconds > later);

    // A full cache: no room for one step.
    let mut scene = Scene::owed("hook-refused-step");
    let (full, _) = crate::snapshots::cache_policy_tests::filled_cache();
    let mut page = PageBudget::default();
    scene.hook_in(&full, &hook_pass(), &mut page, now);
    assert_eq!(spent(&page), SIDE_FENCE_READ_BYTES, "P is never read");
    let owed = scene.owed_entry();
    assert_eq!(owed.outcome, ProofOutcome::StepRefusedMemory as u8);
    assert_eq!((owed.attempts, &owed.wake), (1, &ProofWake::Backoff));
    let mut page = PageBudget::default();
    scene.hook_in(&full, &hook_pass(), &mut page, now);
    assert_eq!(spent(&page), 0);
    assert_eq!(full.proof_suspended_for_test(), None);
}

/// R2-M1: after a failed save the side gate is closed. The next pass starts
/// no proof (nothing read, the entry untouched) and finishes none: a held
/// job steps fd-only and suspends again. A saved pass finishes it.
#[test]
#[cfg_attr(
    not(any(target_os = "macos", target_os = "linux")),
    ignore = "needs macOS heap layout"
)]
fn a_closed_side_gate_starts_and_finishes_no_proof() {
    let limits = Limits::current();
    let index_path = Path::new(HOOK_INDEX);
    // Free: a closed gate starts nothing.
    let mut scene = Scene::owed("hook-gate-free");
    let cache = Arc::new(sampled_scan::SharedCache::default());
    assert!(
        begin_codex_side_pass(&cache, index_path, &mut scene.index)
            .gate
            .side_allowed
    );
    // The pass's save failed: no `note_codex_side_pass_saved`.
    let closed = begin_codex_side_pass(&cache, index_path, &mut scene.index);
    assert!(!closed.gate.side_allowed);
    let owed = scene.owed_entry();
    let mut page = PageBudget::default();
    scene.hook_in(&cache, &closed, &mut page, sampled_scan::now_seconds());
    assert_eq!(spent(&page), 0);
    assert_eq!(scene.owed_entry(), owed);
    assert_eq!(cache.proof_suspended_for_test(), None);

    // Mine: a job suspended in an open pass resumes in a closed one, steps
    // to its end and suspends unfinished.
    let mut scene = Scene::owed("hook-gate-mine");
    let cache = Arc::new(sampled_scan::SharedCache::default());
    let open = begin_codex_side_pass(&cache, index_path, &mut scene.index);
    let mut page = page_with(codex_proof_step_reserve() + SIDE_FENCE_READ_BYTES);
    scene.hook_in(&cache, &open, &mut page, sampled_scan::now_seconds());
    assert!(cache.proof_suspended_for_test().is_some());
    let closed = begin_codex_side_pass(&cache, index_path, &mut scene.index);
    assert!(!closed.gate.side_allowed);
    let mut page = PageBudget::default();
    scene.hook_in(&cache, &closed, &mut page, sampled_scan::now_seconds());
    assert!(spent(&page) > 0 && spent(&page) < limits.singleton());
    assert!(cache.proof_suspended_for_test().is_some(), "not finished");
    assert_eq!(scene.owed_entry().outcome, 0);
    // The pass's save succeeds: the next pass finishes it.
    let mark = codex_side_save_mark(&cache, index_path);
    note_codex_side_pass_saved(&cache, index_path, false, mark);
    let reopened = begin_codex_side_pass(&cache, index_path, &mut scene.index);
    assert!(reopened.gate.side_allowed);
    scene.hook_in(
        &cache,
        &reopened,
        &mut PageBudget::default(),
        sampled_scan::now_seconds(),
    );
    assert_eq!(cache.proof_suspended_for_test(), None);
    assert_eq!((scene.proof().matched, scene.proof().owned), (2, true));
}

/// R1-L4 / R2-M2: P's side record held for P's own lineage refuses the
/// batch at the start's fence (charged; P is never read) as `LineageHeld`
/// and owes P nothing in 2a. Held only by the finish (the record turned
/// held while the job was suspended), the finish records the same and owes
/// nothing either.
#[test]
#[cfg_attr(
    not(any(target_os = "macos", target_os = "linux")),
    ignore = "needs macOS heap layout"
)]
fn a_lineage_held_parent_is_refused_before_its_read_and_owes_nothing() {
    let held = SideVerdict::Held {
        lineage: true,
        cause: CAUSE_NO_EVIDENCE,
    };
    let mut scene = Scene::owed("hook-lineage-start");
    let p_key = local_index_key(&scene.parent);
    scene
        .index
        .codex_parent_side
        .get_mut(&p_key)
        .unwrap()
        .verdict = held;
    let cache = Arc::new(sampled_scan::SharedCache::default());
    let mut page = PageBudget::default();
    scene.hook(&cache, &mut page);
    assert_eq!(spent(&page), SIDE_FENCE_READ_BYTES, "P is not read");
    let owed = scene.owed_entry();
    assert_eq!(owed.outcome, ProofOutcome::LineageHeld as u8);
    assert!(matches!(
        owed.wake,
        ProofWake::ParentHeld { lineage: true, .. }
    ));
    assert!(
        !scene.index.codex_parent_prefix_proofs.contains_key(&p_key),
        "no lineage owe"
    );

    let mut scene = Scene::owed("hook-lineage-finish");
    let p_key = local_index_key(&scene.parent);
    let cache = Arc::new(sampled_scan::SharedCache::default());
    let mut page = page_with(codex_proof_step_reserve() + SIDE_FENCE_READ_BYTES);
    scene.hook(&cache, &mut page);
    assert!(cache.proof_suspended_for_test().is_some());
    scene
        .index
        .codex_parent_side
        .get_mut(&p_key)
        .unwrap()
        .verdict = held;
    scene.hook(&cache, &mut PageBudget::default());
    assert_eq!(cache.proof_suspended_for_test(), None);
    assert_eq!(scene.owed_entry().outcome, ProofOutcome::LineageHeld as u8);
    assert!(
        !scene.index.codex_parent_prefix_proofs.contains_key(&p_key),
        "no lineage owe"
    );
}

/// Stage 1 interface (parent r79): the four continuation exclusions are
/// predicates of the pass's kind. A continuation page gets no G7 charge, no
/// side due, no proof hook and no sweep whatever its gate; an ordinary page
/// gets the hook and the sweep always, and G7 and side due only while its
/// gate is open (the ordinary save outage).
#[test]
fn the_stage1_gates_exclude_a_continuation_page_whatever_its_gate() {
    for kind in [CodexPageKind::Ordinary, CodexPageKind::Continuation] {
        for side_allowed in [true, false] {
            let pass = CodexSidePass {
                kind,
                gate: sampled_scan::side_ledger::GateOpen {
                    side_allowed,
                    first_in_process: false,
                },
                ..hook_pass()
            };
            let ordinary = kind == CodexPageKind::Ordinary;
            assert_eq!(
                (
                    pass.side_charge_allowed(),
                    pass.side_due_allowed(),
                    pass.proof_hook_allowed(),
                    pass.sweep_allowed(),
                ),
                (
                    ordinary && side_allowed,
                    ordinary && side_allowed,
                    ordinary,
                    ordinary,
                ),
                "{kind:?} {side_allowed}"
            );
        }
    }
}

/// Stage 1 (parent r79): a continuation page runs no part of the hook, a
/// held (`Mine`) job included: nothing is read or stepped, the job stays
/// suspended with the same charge, no entry is recorded and the sweep
/// mutates nothing (an orphan record stays). The next ordinary page sweeps
/// the orphan and finishes the job. (The ordinary save outage, where a held
/// job steps fd-only and suspends, is `a_closed_side_gate_...`.)
#[test]
#[cfg_attr(
    not(any(target_os = "macos", target_os = "linux")),
    ignore = "needs macOS heap layout"
)]
fn a_continuation_page_steps_no_held_job_and_sweeps_nothing() {
    let mut scene = Scene::owed("hook-continuation");
    let cache = Arc::new(sampled_scan::SharedCache::default());
    let mut page = page_with(codex_proof_step_reserve() + SIDE_FENCE_READ_BYTES);
    scene.hook(&cache, &mut page);
    let held = cache.proof_suspended_for_test().expect("held");
    let owed = scene.owed_entry();
    let orphan = "/nonexistent/u1a2a-orphan-rollout.jsonl".to_owned();
    let record = scene.index.codex_parent_side[&local_index_key(&scene.parent)].clone();
    scene.index.codex_parent_side.insert(orphan.clone(), record);
    let side = serde_json::to_value(&scene.index.codex_parent_side).unwrap();
    let cursor = scene.index.codex_parent_side_cursor.clone();
    let continuation = CodexSidePass {
        kind: CodexPageKind::Continuation,
        ..hook_pass()
    };
    for _ in 0..3 {
        let mut page = PageBudget::default();
        scene.hook_in(
            &cache,
            &continuation,
            &mut page,
            sampled_scan::now_seconds(),
        );
        assert_eq!(spent(&page), 0, "nothing read");
        assert_eq!(cache.proof_suspended_for_test(), Some(held.clone()));
        assert_eq!(scene.owed_entry(), owed);
        assert_eq!(
            serde_json::to_value(&scene.index.codex_parent_side).unwrap(),
            side,
            "not swept"
        );
        assert_eq!(scene.index.codex_parent_side_cursor, cursor);
    }
    scene.hook(&cache, &mut PageBudget::default());
    assert!(!scene.index.codex_parent_side.contains_key(&orphan));
    assert_eq!(cache.proof_suspended_for_test(), None);
    assert_eq!((scene.proof().matched, scene.proof().owned), (2, true));
}

/// Owner note 3 (r79): main's retirement of a suspended job (here its copy
/// step's) keeps the job's entries for its index's next hook, which backs
/// each off (`MemoryRefused` + `Backoff`). Repeated retirements therefore
/// pace the restarts: one per backoff, none inside it, never proven.
#[test]
#[cfg_attr(
    not(any(target_os = "macos", target_os = "linux")),
    ignore = "needs macOS heap layout"
)]
fn main_retirements_pace_the_restarts() {
    let leftover = codex_proof_step_reserve() + SIDE_FENCE_READ_BYTES;
    let mut scene = Scene::owed("hook-retired");
    let cache = Arc::new(sampled_scan::SharedCache::default());
    let mut at = sampled_scan::now_seconds();
    for attempt in 1..=3 {
        let mut page = page_with(leftover);
        scene.hook_in(&cache, &hook_pass(), &mut page, at);
        assert!(spent(&page) > SIDE_FENCE_READ_BYTES, "restarted: P read");
        assert!(cache.proof_suspended_for_test().is_some());
        cache.retire_proof_over_room(0);
        assert_eq!(cache.proof_suspended_for_test(), None);
        for _ in 0..3 {
            let mut page = PageBudget::default();
            scene.hook_in(&cache, &hook_pass(), &mut page, at);
            assert_eq!(spent(&page), 0, "inside the backoff: nothing");
        }
        let owed = scene.owed_entry();
        assert_eq!(
            (owed.attempts, owed.outcome, &owed.wake),
            (
                attempt,
                ProofOutcome::MemoryRefused as u8,
                &ProofWake::Backoff
            )
        );
        assert!(owed.not_before_unix_seconds > at);
        at = owed.not_before_unix_seconds + 1;
    }
}

/// R2-B3 (r79): a page that cannot finish (invalid census) and cannot
/// suspend (no room) backs the job off; further pages at the same time,
/// invalid or valid, read nothing, and nothing is proven.
#[test]
fn an_invalid_page_whose_suspend_fails_backs_off_and_publishes_nothing() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let mut scene = Scene::owed("hook-invalid-refused");
    // After the scene: it seals P's side record at its own clock read, and
    // an earlier `now` is a clock regression to the side fence.
    let now = sampled_scan::now_seconds();
    let cache = Arc::new(sampled_scan::SharedCache::default());
    let mut page = page_with(codex_proof_step_reserve() + SIDE_FENCE_READ_BYTES);
    scene.hook_in(&cache, &hook_pass(), &mut page, now);
    assert!(cache.proof_suspended_for_test().is_some());
    let traversal = scene.index.traversal.take();
    let mut page = PageBudget::default();
    sampled_scan::codex_cursor::with_test_state_budget(0, || {
        scene.hook_in(&cache, &hook_pass(), &mut page, now);
    });
    assert!(spent(&page) > 0, "the held job ran to P's end");
    assert_eq!(cache.proof_suspended_for_test(), None);
    let owed = scene.owed_entry();
    assert_eq!(
        (owed.attempts, owed.outcome, &owed.wake),
        (1, ProofOutcome::MemoryRefused as u8, &ProofWake::Backoff)
    );
    for valid in [false, true, false, true] {
        scene.index.traversal = if valid { traversal.clone() } else { None };
        let mut page = PageBudget::default();
        scene.hook_in(&cache, &hook_pass(), &mut page, now);
        assert_eq!(spent(&page), 0, "valid {valid}");
        assert_eq!(scene.owed_entry(), owed);
    }
}

/// Fix round 2 (R2-L3): a retired job's backoff is drained only on a
/// side-allowed page. On a save-outage page its ring entry waits (no
/// backoff write, nothing read); the next open page drains it.
#[test]
#[cfg_attr(
    not(any(target_os = "macos", target_os = "linux")),
    ignore = "needs macOS heap layout"
)]
fn a_save_outage_page_leaves_the_retired_record_for_an_open_gate() {
    let leftover = codex_proof_step_reserve() + SIDE_FENCE_READ_BYTES;
    let mut scene = Scene::owed("hook-retired-outage");
    let cache = Arc::new(sampled_scan::SharedCache::default());
    let now = sampled_scan::now_seconds();
    let mut page = page_with(leftover);
    scene.hook_in(&cache, &hook_pass(), &mut page, now);
    assert!(cache.proof_suspended_for_test().is_some());
    cache.retire_proof_over_room(0);
    let owed = scene.owed_entry();
    let closed = CodexSidePass {
        gate: sampled_scan::side_ledger::GateOpen {
            side_allowed: false,
            first_in_process: false,
        },
        ..hook_pass()
    };
    for _ in 0..3 {
        let mut page = PageBudget::default();
        scene.hook_in(&cache, &closed, &mut page, now);
        assert_eq!(spent(&page), 0);
        assert_eq!(scene.owed_entry(), owed, "no backoff write");
    }
    let mut page = PageBudget::default();
    scene.hook_in(&cache, &hook_pass(), &mut page, now);
    assert_eq!(spent(&page), 0);
    let drained = scene.owed_entry();
    assert_eq!(
        (drained.attempts, drained.outcome, &drained.wake),
        (1, ProofOutcome::MemoryRefused as u8, &ProofWake::Backoff)
    );
}

// Fix rounds 2c/3 (DM1, DL1, DB2): the two line-proportional classes are
// charged by a length known before they keep anything.

/// The need `run` charges before a step from a fresh walk:
/// `W + (W - B) + MAX_JSONL_LINE_BYTES + CODEX_PROOF_LINE_RETAINED`.
fn fresh_need(job: &CodexProofReaders) -> usize {
    let walked = crate::heap_layout_bound::bound(job, usize::MAX).unwrap();
    walked + (walked - job.buffers()) + MAX_JSONL_LINE_BYTES + CODEX_PROOF_LINE_RETAINED
}

/// Fix round 3 (DL1): a first header is kept only when the strings it keeps
/// (`codex_proof_header_retained`, after decode) fit the slack after the
/// step's charge. One byte short: `Memory`, and none of its header state is
/// kept. With that room: admitted, and its measured growth (P's and a
/// child's) stays within the charge. A header whose bulk is not kept (a
/// ~15 MiB `base_instructions`) is charged its kept strings only.
#[test]
fn a_first_header_is_charged_its_kept_strings_after_it_is_decoded() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let root = temp_root("job-header-charge");
    let big = 1 << 20;
    let parent = rollout(&root, PARENT);
    let mut values = parent_values();
    values[0] = json!({"timestamp": "2026-08-02T08:00:00Z", "type": "session_meta", "payload": {
        "id": "p".repeat(big), "cwd": "c".repeat(big), "originator": "o".repeat(big),
        "thread_source": "user",
    }});
    write_values(&parent, &values);
    let charge = codex_proof_header_retained(&values[0], &values[0]["payload"]);
    assert!(charge >= 4 * big, "id twice, cwd, originator: {charge}");

    let mut job = job_of(&parent, &[]);
    let (before, room) = (retained(&job), fresh_need(&job) + charge - 1);
    let mut budget = codex_proof_step_reserve();
    assert_eq!(job.run(&mut budget, room), CodexProofRun::Memory);
    let accumulator = &job.parent.parser.accumulator;
    assert!(!accumulator.codex_session_meta_seen);
    assert_eq!(accumulator.source_session_id, None);
    assert_eq!(accumulator.codex_creator_header_id, None);
    assert_eq!(accumulator.workspace_path, None);
    assert!(job
        .parent
        .parser
        .reader
        .retain_room
        .is_some_and(|room| room.refused));
    assert!(retained(&job) <= before + CODEX_PROOF_LINE_RETAINED);
    // R1-L1: a refused reader steps nothing, whatever its room.
    let consumed = job.parent.parser.reader.consumed_bytes();
    assert_eq!(job.parent.step(usize::MAX), 0);
    assert!(job.parent.refused());
    assert_eq!(job.parent.parser.reader.consumed_bytes(), consumed);

    let mut job = job_of(&parent, &[]);
    let (before, room) = (retained(&job), fresh_need(&job) + charge);
    let mut budget = codex_proof_step_reserve();
    assert_eq!(job.run(&mut budget, room), CodexProofRun::Budget);
    assert!(job.parent.parser.accumulator.codex_session_meta_seen);
    let grew = retained(&job) - before;
    assert!(grew >= 2 * big, "the id twice: {grew}");
    assert!(
        grew <= charge + CODEX_PROOF_LINE_RETAINED,
        "{grew} > {charge}"
    );

    // Bulk the header does not keep: charged its kept strings, admitted
    // in a slack far below its framed length.
    values[0] = json!({"timestamp": "2026-08-02T08:00:00Z", "type": "session_meta", "payload": {
        "id": PARENT, "thread_source": "user", "base_instructions": {"text": "b".repeat(15 << 20)},
    }});
    write_values(&parent, &values);
    let charge = codex_proof_header_retained(&values[0], &values[0]["payload"]);
    assert!(charge < 1 << 20, "{charge}");
    let mut job = job_of(&parent, &[]);
    let room = fresh_need(&job) + charge;
    let mut budget = codex_proof_step_reserve();
    assert_eq!(job.run(&mut budget, room), CodexProofRun::Budget);
    assert!(job.parent.parser.accumulator.codex_session_meta_seen);
    assert!(!job.parent.refused());

    // A child's first header (its prelude parser too) within its charge.
    write_values(&parent, &parent_values());
    let child = rollout(&root, CHILD);
    let mut rows = child_values();
    rows[0] = json!({"timestamp": "2026-08-02T08:20:00Z", "type": "session_meta", "payload": {
        "id": CHILD, "forked_from_id": PARENT, "thread_source": "user",
        "cwd": "c".repeat(big), "originator": "o".repeat(big), "cli_version": "0.99.0",
    }});
    write_values(&child, &rows);
    let mut job = job_of(&parent, &[&child]);
    let grew = loop {
        let seen = job.children[0]
            .reader
            .parser
            .accumulator
            .codex_session_meta_seen;
        let (run, grew, _) = one_step(&mut job);
        if !seen
            && job.children[0]
                .reader
                .parser
                .accumulator
                .codex_session_meta_seen
        {
            break grew;
        }
        assert_eq!(run, CodexProofRun::Budget);
    };
    let charge =
        codex_proof_header_retained(&rows[0], &rows[0]["payload"]) + CODEX_PROOF_LINE_RETAINED;
    assert!(grew >= 2 * big as isize, "cwd and originator: {grew}");
    assert!(grew <= charge as isize, "{grew} > {charge}");
    let _ = fs::remove_dir_all(root);
}

/// Fix round 3 (DB2): a paused overlong skip keeps its salvage only if the
/// extracted timestamp's capacity fits its slack (not the buffered prefix):
/// one byte short, nothing is salvaged and the step is refused (`Memory`);
/// with the timestamp's room, the salvage is kept.
#[test]
fn a_salvage_over_its_room_is_not_taken() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let root = temp_root("job-salvage-charge");
    let parent = rollout(&root, PARENT);
    let mut bytes = Vec::new();
    bytes.extend_from_slice(
        serde_json::to_string(&parent_values()[0])
            .unwrap()
            .as_bytes(),
    );
    bytes.push(b'\n');
    bytes.extend_from_slice(b"{\"timestamp\":\"");
    bytes.resize(bytes.len() + (4 << 20), b'2');
    bytes.extend_from_slice(
        b"\",\"ordinal\":7,\"type\":\"response_item\",\"payload\":{\"content\":\"",
    );
    bytes.resize(bytes.len() + MAX_JSONL_LINE_BYTES, b'y');
    bytes.extend_from_slice(b"\"}}\n");
    fs::write(&parent, bytes).unwrap();
    sampled_scan::codex_cursor::with_test_limits(2048, 8192, 64 * 1024, || {
        // The timestamp's capacity, from a salvage kept in ample room.
        let mut job = job_of(&parent, &[]);
        let (_, _, header) = one_step(&mut job);
        assert!(header);
        let room = fresh_need(&job) + MAX_JSONL_LINE_BYTES;
        let mut budget = codex_proof_step_reserve();
        assert_eq!(job.run(&mut budget, room), CodexProofRun::Budget);
        let cap = job
            .parent
            .parser
            .reader
            .skipping
            .as_ref()
            .and_then(|salvage| salvage.envelope.as_ref())
            .map(|envelope| envelope.timestamp.capacity())
            .unwrap();
        assert!((4 << 20..MAX_JSONL_LINE_BYTES).contains(&cap), "{cap}");
        for (short, salvaged) in [(1, false), (0, true)] {
            let mut job = job_of(&parent, &[]);
            let (_, _, header) = one_step(&mut job);
            assert!(header);
            let before = retained(&job);
            let room = fresh_need(&job) + cap - short;
            let mut budget = codex_proof_step_reserve();
            let run = job.run(&mut budget, room);
            let reader = &job.parent.parser.reader;
            assert_eq!(reader.skipping.is_some(), salvaged);
            if salvaged {
                assert_eq!(run, CodexProofRun::Budget);
            } else {
                assert_eq!(run, CodexProofRun::Memory);
                assert!(reader.retain_room.is_some_and(|room| room.refused));
                assert!(retained(&job) <= before + CODEX_PROOF_LINE_RETAINED);
                // R1-L1: a refused reader steps nothing, whatever its room.
                let consumed = job.parent.parser.reader.consumed_bytes();
                assert_eq!(job.parent.step(usize::MAX), 0);
                assert!(job.parent.refused());
                assert_eq!(job.parent.parser.reader.consumed_bytes(), consumed);
            }
        }
    });
    let _ = fs::remove_dir_all(root);
}

/// A max-length first header cannot fit any proof room (its kept
/// originator alone is near 16 MiB, over any slack): the hook frames and
/// decodes it, refuses it before keeping any of it (`StepRefusedMemory`,
/// paced), keeps no job and proves nothing; inside the backoff nothing is
/// read.
#[test]
fn a_header_over_its_room_is_refused_paced_and_keeps_nothing() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let now = sampled_scan::now_seconds();
    let mut scene = Scene::owed("hook-header-refused");
    let mut values = parent_values();
    values[0] = json!({"timestamp": "2026-08-02T08:00:00Z", "type": "session_meta", "payload": {
        "id": PARENT, "thread_source": "user", "originator": "o".repeat(MAX_JSONL_LINE_BYTES - 4096),
    }});
    write_values(&scene.parent, &values);
    scene.settle_side(now);
    let framed = serde_json::to_string(&values[0]).unwrap().len() as u64;
    let cache = Arc::new(sampled_scan::SharedCache::default());
    let mut page = PageBudget::default();
    scene.hook_in(&cache, &hook_pass(), &mut page, now);
    assert!(
        spent(&page) > SIDE_FENCE_READ_BYTES + framed,
        "the header was framed: {}",
        spent(&page)
    );
    let owed = scene.owed_entry();
    assert_eq!(owed.outcome, ProofOutcome::StepRefusedMemory as u8);
    assert_eq!((owed.attempts, &owed.wake), (1, &ProofWake::Backoff));
    assert!(owed.not_before_unix_seconds > now);
    assert_eq!(cache.proof_suspended_for_test(), None);
    let mut page = PageBudget::default();
    scene.hook_in(&cache, &hook_pass(), &mut page, now);
    assert_eq!(spent(&page), 0, "inside the backoff: nothing");
}

/// `values` with one overlong row (`timestamp` first, then a payload past
/// `MAX_JSONL_LINE_BYTES` by 1 MiB) before its row 3.
fn write_with_overlong(path: &Path, values: &[Value], timestamp: &[u8]) {
    let mut bytes = Vec::new();
    for (row, value) in values.iter().enumerate() {
        if row == 3 {
            bytes.extend_from_slice(b"{\"timestamp\":\"");
            bytes.extend_from_slice(timestamp);
            bytes.extend_from_slice(
                b"\",\"ordinal\":9,\"type\":\"response_item\",\"payload\":{\"content\":\"",
            );
            bytes.resize(bytes.len() + MAX_JSONL_LINE_BYTES + (1 << 20), b'y');
            bytes.extend_from_slice(b"\"}}\n");
        }
        bytes.extend_from_slice(serde_json::to_string(value).unwrap().as_bytes());
        bytes.push(b'\n');
    }
    fs::write(path, bytes).unwrap();
}

/// Fix round 3 (DB2), at the real proof room through the hook: an overlong
/// row (over 17 MiB) whose salvage keeps a 27-byte timestamp is skipped
/// through and its salvage kept. In the deciding child: the child decides
/// and the hook proves it as without the row. In P: P is read to its end
/// and finishes under its own lossy rule (`ParentLossy`), not a memory
/// refusal. The same row with a timestamp over any slack (15 MiB: the room
/// is under `MAX_JSONL_LINE_BYTES` + 14 MiB) keeps no salvage:
/// `StepRefusedMemory`, paced, and nothing is read inside the backoff.
#[test]
fn an_overlong_row_is_charged_its_salvaged_timestamp_at_the_real_room() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let now = sampled_scan::now_seconds();
    let short = b"2026-08-02T08:20:00.500000Z";

    let mut scene = Scene::owed("hook-overlong-child");
    write_with_overlong(&scene.child.path, &child_values(), short);
    let cache = Arc::new(sampled_scan::SharedCache::default());
    let key = scene.key();
    for _ in 0..4 {
        if matches!(
            scene.index.codex_parent_prefix_proofs.get(&key),
            Some(CodexParentProofState::Proven(_))
        ) {
            break;
        }
        let mut page = PageBudget::default();
        scene.hook(&cache, &mut page);
    }
    let proof = scene.proof();
    assert_eq!((proof.matched, proof.owned), (2, true));
    assert_eq!(cache.proof_suspended_for_test(), None);

    let mut scene = Scene::owed("hook-overlong-parent");
    write_with_overlong(&scene.parent, &parent_values(), short);
    scene.settle_side(now);
    let cache = Arc::new(sampled_scan::SharedCache::default());
    let mut page = PageBudget::default();
    scene.hook_in(&cache, &hook_pass(), &mut page, now);
    let parent_len = fs::metadata(&scene.parent).unwrap().len();
    assert!(
        spent(&page) > parent_len,
        "P read to its end: {}",
        spent(&page)
    );
    let owed = scene.owed_entry();
    assert_eq!(owed.outcome, ProofOutcome::ParentLossy as u8, "{owed:?}");
    assert_eq!(owed.attempts, 1);
    assert_eq!(cache.proof_suspended_for_test(), None);

    let mut scene = Scene::owed("hook-overlong-refused");
    let mut timestamp = b"2026-08-02T08:20:00Z".to_vec();
    timestamp.resize(15 << 20, b'0');
    write_with_overlong(&scene.child.path, &child_values(), &timestamp);
    // P's record sealed at the hook's `now` (a later wall-clock seal is a
    // clock regression to the side fence).
    scene.settle_side(now);
    let cache = Arc::new(sampled_scan::SharedCache::default());
    let mut page = PageBudget::default();
    scene.hook_in(&cache, &hook_pass(), &mut page, now);
    assert!(spent(&page) > SIDE_FENCE_READ_BYTES + (15 << 20));
    let owed = scene.owed_entry();
    assert_eq!(owed.outcome, ProofOutcome::StepRefusedMemory as u8);
    assert_eq!((owed.attempts, &owed.wake), (1, &ProofWake::Backoff));
    assert!(owed.not_before_unix_seconds > now);
    assert_eq!(cache.proof_suspended_for_test(), None);
    let mut page = PageBudget::default();
    scene.hook_in(&cache, &hook_pass(), &mut page, now);
    assert_eq!(spent(&page), 0, "inside the backoff: nothing");
}

// Fix round 4: the AutoReview findings at 396b1f32.

/// Fix round 4 (AutoReview #1): a consumed proof is re-fenced against P at
/// completion, in main's completion fence
/// (`invalidate_stale_codex_parent_resolution`), by the install's own P
/// checks. P unchanged: the parse is untouched and the record site admits.
/// P rewritten in place or replaced after the install: child usage and its
/// ledger are refused, the parse is pending (a later page retries), the
/// proof is refused `Seal` and the entry is removed (the owe re-proves),
/// never `Admitted`. P gone: refused `Identity`, the entry kept (PR-P holds
/// the child). Function level: the same fence ends every completion,
/// ordinary or a cursor job's.
#[test]
fn a_consumed_proof_is_refenced_against_p_at_completion() {
    let consumed = |name: &str| {
        let scene = Scene::new(name);
        let proof = scene.proof();
        let parsed = parse(
            &scene.child.path,
            witness(CodexParentUnresolvable::Oversize),
            Some(installed(&proof)),
        );
        assert!(parsed.complete() && parsed.codex_parent_prefix_decided.is_some());
        assert!(!parsed.snapshots.is_empty());
        // Fix round 5 (R2-N2): the predicate the call site charges
        // `SAMPLE_READ_BYTES` on.
        assert!(codex_parent_proof_refenced(&parsed));
        (scene, proof, parsed)
    };
    let fence = |scene: &Scene, parsed: &mut ParsedJsonlFile| {
        let mut ids =
            CodexParentIdentities::new(SnapshotSource::Codex, scene.index.traversal.as_ref());
        let census = ids.census(&scene.index);
        invalidate_stale_codex_parent_resolution(parsed, &mut ids, census)
    };
    let refused = |parsed: &ParsedJsonlFile| {
        assert!(!codex_parent_proof_refenced(parsed));
        assert!(parsed.snapshots.is_empty());
        assert!(parsed.codex_parent_resolution_pending);
        assert!(!parsed.complete());
        assert!(parsed
            .codex_parent_ownership_ledger
            .as_ref()
            .map_or(true, |(_, ledger)| !ledger.scan_complete
                && ledger.signatures.is_empty()));
    };

    // Unchanged: nothing changes; admitted (kept) as before.
    let (mut scene, proof, mut parsed) = consumed("refence-unchanged");
    let before = view(&parsed);
    assert!(!fence(&scene, &mut parsed));
    assert_eq!(view(&parsed), before);
    assert_eq!(parsed.codex_parent_proof_refusal, None);
    let key = scene.key();
    scene.index.settle_codex_parent_proof_use(&key, &parsed);
    assert_eq!(scene.proof(), proof);

    // Rewritten in place (same inode, new head): `Seal`, removed.
    let (mut scene, _, mut parsed) = consumed("refence-rewritten");
    let mut values = parent_values();
    values[1] = turn("2026-08-02T08:00:01Z", "parent-turn-rewritten");
    write_values(&scene.parent, &values);
    assert!(fence(&scene, &mut parsed));
    refused(&parsed);
    assert!(
        matches!(
            parsed.codex_parent_proof_refusal,
            Some(ProofRefusal::Seal(_))
        ),
        "{:?}",
        parsed.codex_parent_proof_refusal
    );
    let key = scene.key();
    scene.index.settle_codex_parent_proof_use(&key, &parsed);
    assert_eq!(scene.index.codex_parent_prefix_proofs.get(&key), None);

    // Replaced (a new object at P's path): `Seal`, removed.
    let (mut scene, _, mut parsed) = consumed("refence-replaced");
    let staged = scene.parent.with_extension("staged");
    write_values(&staged, &parent_values());
    fs::rename(&staged, &scene.parent).unwrap();
    assert!(fence(&scene, &mut parsed));
    refused(&parsed);
    assert!(
        matches!(
            parsed.codex_parent_proof_refusal,
            Some(ProofRefusal::Seal(_))
        ),
        "{:?}",
        parsed.codex_parent_proof_refusal
    );
    let key = scene.key();
    scene.index.settle_codex_parent_proof_use(&key, &parsed);
    assert_eq!(scene.index.codex_parent_prefix_proofs.get(&key), None);

    // Gone: `Identity`, the entry kept for PR-P.
    let (mut scene, proof, mut parsed) = consumed("refence-gone");
    fs::remove_file(&scene.parent).unwrap();
    assert!(fence(&scene, &mut parsed));
    refused(&parsed);
    assert!(matches!(
        parsed.codex_parent_proof_refusal,
        Some(ProofRefusal::Identity(_))
    ));
    let key = scene.key();
    scene.index.settle_codex_parent_proof_use(&key, &parsed);
    assert_eq!(scene.proof(), proof);
}

/// A singleton hold memo for `key` in the hook's namespace; its memo key.
fn held_memo(cache: &sampled_scan::SharedCache, key: &str, file: &Path) -> String {
    use sampled_scan::codex_cursor::{DebtReason, Disclosure, HeldCounts, LiveWitness, MemoEntry};
    let file = File::open(file).unwrap();
    let entry = MemoEntry::new(
        "digest".into(),
        LiveWitness::read(Path::new("fixture.jsonl"), &file, 8).unwrap(),
        OpenStamp::capture(&file).unwrap(),
        None,
        None,
        Disclosure {
            reason: DebtReason::HeldTerminal,
            cause: ownership::PARENT,
            ownership_incomplete_file_count: 1,
            zero_snapshot_usage_evidence: false,
            state_only_blocked_session_ids: vec![CHILD.into()],
            diagnostic_reason: crate::codex_scan_diagnostics::FileReason::OwnershipIncomplete,
            parsed_snapshot_count: 0,
            held: HeldCounts::default(),
            parent_ref: Some(PARENT.into()),
            parent_unresolvable: Some(CodexParentUnresolvable::LedgerCapped),
        },
    );
    let memo_key = sampled_scan::codex_cursor::memo_key(
        &crate::transcript_acquisition::Scope("proof-hook".into()),
        key,
    );
    cache.memo_record(memo_key.clone(), entry);
    assert!(cache.memo_lookup(&memo_key).is_some());
    memo_key
}

/// Fix round 4 (AutoReview #2): a child's singleton hold memo ends when its
/// entry becomes `Proven`, at the job's finish and at a kept proof's
/// re-fence, so the child's next page parses and reaches the install
/// instead of replaying the hold recorded before the proof. A job that
/// proves nothing keeps the memo; other memos are untouched.
#[test]
fn a_proven_entry_ends_its_childs_hold_memo() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    // The job's finish proves C.
    let mut scene = Scene::owed("hook-memo-proven");
    let cache = Arc::new(sampled_scan::SharedCache::default());
    let child = held_memo(&cache, &scene.key(), &scene.child.path);
    let other = held_memo(&cache, "/other/rollout.jsonl", &scene.parent);
    let mut page = PageBudget::default();
    scene.hook(&cache, &mut page);
    assert_eq!((scene.proof().matched, scene.proof().owned), (2, true));
    assert!(cache.memo_lookup(&child).is_none(), "the hold memo ended");
    assert!(cache.memo_lookup(&other).is_some());

    // A kept proof re-fenced to `Proven` (no job).
    let mut scene = Scene::owed("hook-memo-refenced");
    let key = scene.key();
    let now = sampled_scan::now_seconds();
    let proof = proof_of(
        &child_values(),
        &parent_values(),
        seal_of(
            &File::open(&scene.parent).unwrap(),
            now,
            &codex_parent_proof_scope().0,
        ),
    );
    scene.index.remove_codex_parent_proof(&key);
    scene
        .index
        .codex_parent_prefix_proofs
        .insert(key.clone(), CodexParentProofState::Proven(proof.clone()));
    scene.index.settle_codex_parent_proof_use(
        &key,
        &ParsedJsonlFile {
            codex_parent_proof_refusal: Some(ProofRefusal::Side(ProofWake::Due)),
            ..held(CodexParentUnresolvable::Oversize)
        },
    );
    assert!(scene.owed_entry().kept.is_some());
    let cache = Arc::new(sampled_scan::SharedCache::default());
    let child = held_memo(&cache, &key, &scene.child.path);
    let mut page = PageBudget::default();
    scene.hook(&cache, &mut page);
    assert_eq!(scene.proof(), proof);
    assert!(cache.memo_lookup(&child).is_none(), "the hold memo ended");

    // No proof (P's record held: the batch is refused, C stays owed): the
    // memo replays as before.
    let mut scene = Scene::owed("hook-memo-kept");
    let p_key = local_index_key(&scene.parent);
    scene
        .index
        .codex_parent_side
        .get_mut(&p_key)
        .unwrap()
        .verdict = SideVerdict::Held {
        lineage: true,
        cause: CAUSE_NO_EVIDENCE,
    };
    let cache = Arc::new(sampled_scan::SharedCache::default());
    let child = held_memo(&cache, &scene.key(), &scene.child.path);
    let mut page = PageBudget::default();
    scene.hook(&cache, &mut page);
    assert_eq!(scene.owed_entry().outcome, ProofOutcome::LineageHeld as u8);
    assert!(cache.memo_lookup(&child).is_some(), "no proof: kept");
}

/// Fix round 4 (AutoReview #3): a `ParentHeld` wake fires when P's settled
/// record is refreshed with a seal inside its horizon under the same
/// verdict and generation; an unchanged expired seal does not wake it, and
/// the backoff still governs.
#[test]
#[cfg_attr(
    not(any(target_os = "macos", target_os = "linux")),
    ignore = "needs macOS heap layout"
)]
fn a_parent_held_wake_fires_on_a_refreshed_seal_only() {
    let now = sampled_scan::now_seconds();
    let mut scene = Scene::owed("hook-seal-refresh");
    let key = scene.key();
    let p_key = local_index_key(&scene.parent);
    let parent = scene.parent.clone();
    let side_seal = |verified: u64| {
        seal_of(
            &File::open(&parent).unwrap(),
            verified,
            &codex_parent_side_scope().0,
        )
    };
    // P's record expired (verified two audit intervals ago), same generation.
    let expired = side_seal(now - 2 * crate::transcript_acquisition::AUDIT_INTERVAL_SECONDS);
    scene.index.codex_parent_side.get_mut(&p_key).unwrap().seal = expired;
    let generation = scene.index.codex_parent_side[&p_key].generation;
    let wake = ProofWake::ParentHeld {
        parent_key: p_key.clone(),
        generation,
        parent_entry: scene.index.codex_parent_entry_fingerprint(&p_key),
        parent: OpenStamp::of_path(&scene.parent).unwrap(),
        lineage: false,
        needed_extent: 0,
    };
    let set_owed = |scene: &mut Scene, not_before: u64| {
        let Some(CodexParentProofState::Owed(owed)) =
            scene.index.codex_parent_prefix_proofs.get_mut(&key)
        else {
            panic!("not owed");
        };
        owed.wake = wake.clone();
        owed.not_before_unix_seconds = not_before;
    };
    set_owed(&mut scene, 0);
    let cache = Arc::new(sampled_scan::SharedCache::default());
    let before = scene.owed_entry();

    // Unchanged expired seal: no wake, nothing read.
    let mut page = PageBudget::default();
    scene.hook_in(&cache, &hook_pass(), &mut page, now);
    assert_eq!(spent(&page), 0);
    assert_eq!(scene.owed_entry(), before);

    // Refreshed by a side read (same verdict and generation), but backed off:
    // still nothing.
    scene.index.codex_parent_side.get_mut(&p_key).unwrap().seal = side_seal(now);
    assert_eq!(scene.index.codex_parent_side[&p_key].generation, generation);
    set_owed(&mut scene, now + 600);
    let mut page = PageBudget::default();
    scene.hook_in(&cache, &hook_pass(), &mut page, now);
    assert_eq!(spent(&page), 0, "the backoff governs");

    // After the backoff: the wake fires and C is proven again.
    set_owed(&mut scene, 0);
    let mut page = PageBudget::default();
    scene.hook_in(&cache, &hook_pass(), &mut page, now);
    assert_eq!((scene.proof().matched, scene.proof().owned), (2, true));
}

/// E1 S3 (C1): proof wakes compare raw path stamps exactly, ctime included,
/// as before S3. A path stamp carries no birth witness, so ctime is the only
/// signal of a same-inode replacement or an mtime-restored rewrite until a
/// birth fence exists (S3b). An untouched pair keeps a `Rewritten` wake
/// asleep; a metadata-only change of C, or of P, fires it and C is proven.
#[test]
#[cfg_attr(
    not(any(target_os = "macos", target_os = "linux")),
    ignore = "needs macOS heap layout"
)]
fn a_rewritten_proof_wake_fires_on_a_metadata_only_change() {
    use std::os::unix::fs::PermissionsExt;
    // A chmod, retried until the path stamp moves: ctime alone.
    let chmod = |path: &Path| {
        let before = OpenStamp::of_path(path).unwrap();
        for _ in 0..2000 {
            let mode = fs::metadata(path).unwrap().permissions().mode();
            fs::set_permissions(path, fs::Permissions::from_mode(mode ^ 0o004)).unwrap();
            let after = OpenStamp::of_path(path).unwrap();
            assert!(before.same_content(&after), "metadata only");
            if after != before {
                assert!(before.append_compatible(&after), "S3's shared rule");
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        panic!("chmod never moved ctime");
    };
    for parent_changed in [false, true] {
        let mut scene = Scene::owed("hook-rewritten-ctime");
        // After the scene: it seals P's side record at its own clock read, and
        // an earlier `now` is a clock regression to the side fence.
        let now = sampled_scan::now_seconds();
        let key = scene.key();
        let Some(CodexParentProofState::Owed(owed)) =
            scene.index.codex_parent_prefix_proofs.get_mut(&key)
        else {
            panic!("not owed");
        };
        owed.wake = ProofWake::Rewritten {
            parent: Some(OpenStamp::of_path(&scene.parent).unwrap()),
            child: OpenStamp::of_path(&scene.child.path).unwrap(),
        };
        owed.not_before_unix_seconds = 0;
        let cache = Arc::new(sampled_scan::SharedCache::default());
        let before = scene.owed_entry();

        // Untouched: no wake, nothing read.
        let mut page = PageBudget::default();
        scene.hook_in(&cache, &hook_pass(), &mut page, now);
        assert_eq!(spent(&page), 0, "parent_changed={parent_changed}");
        assert_eq!(scene.owed_entry(), before);

        if parent_changed {
            chmod(&scene.parent);
            // P's side record follows P, so only the wake decides.
            scene.settle_side(now);
        } else {
            chmod(&scene.child.path);
        }
        let mut page = PageBudget::default();
        scene.hook_in(&cache, &hook_pass(), &mut page, now);
        assert_eq!(
            (scene.proof().matched, scene.proof().owned),
            (2, true),
            "parent_changed={parent_changed}"
        );
    }
}

/// Fix round 5 (N1): a held completion whose parser was built before its
/// entry turned `Proven` (a cursor job paused across the transition: no
/// install, no refusal) does not memoize its hold, so the next page parses,
/// reaches the install and resolves. Every install outcome (an `Identity`
/// refusal included) and every persistent skip (a mis-scoped or mislabelled
/// proof, no `Proven` entry, another parent, an unavailable census, a cause
/// the proof arm does not consume) keeps today's memo: no per-page reparse.
#[test]
fn a_hold_built_before_its_proof_is_not_memoized() {
    use CodexParentUnresolvable::*;
    let awaits = |scene: &Scene, parsed: &ParsedJsonlFile| {
        let ids = CodexParentIdentities::new(SnapshotSource::Codex, scene.index.traversal.as_ref());
        codex_held_memo_awaits_proof_install(
            &scene.index,
            ids.census(&scene.index),
            &scene.key(),
            parsed,
            false,
        )
    };
    let held = |scene: &Scene, cause: CodexParentUnresolvable| {
        let parsed = parse(&scene.child.path, witness(cause), None);
        assert!(!parsed.complete());
        assert_eq!(parsed.codex_parent_unresolvable, Some(cause));
        parsed
    };

    // The paused job's parse: held on P's cap, no install tried: no memo.
    let mut scene = Scene::new("await-proof");
    assert!(awaits(&scene, &held(&scene, Oversize)));
    assert!(awaits(&scene, &held(&scene, LedgerCapped)));
    // The next page installs, the child resolves, and records as today.
    let proof = scene.proof();
    assert_eq!(scene.install(), (true, Some(proof.clone()), None));
    let resolved = parse(
        &scene.child.path,
        witness(Oversize),
        Some(installed(&proof)),
    );
    assert!(resolved.complete());
    assert_eq!(resolved.codex_parent_proof_used.as_ref(), Some(&proof));
    assert!(!awaits(&scene, &resolved));
    // A cause the proof arm does not consume: the memo stays.
    let lossy = parse(&scene.child.path, witness(ParentLossy), None);
    assert!(!lossy.complete());
    assert!(!awaits(&scene, &lossy));

    // An `Identity` refusal: the install ran; the memo stays.
    let mut scene = Scene::new("await-identity");
    fs::remove_file(&scene.parent).unwrap();
    let (_, _, refusal) = scene.install();
    assert!(
        matches!(refusal, Some(ProofRefusal::Identity(_))),
        "{refusal:?}"
    );
    let refused = parse_forged(&scene.child.path, witness(Oversize), None, |acc| {
        acc.codex_parent_proof_refusal = refusal.clone();
    });
    assert!(!refused.complete());
    assert!(!awaits(&scene, &refused));

    // Persistent skips: each keeps the memo.
    let mut scene = Scene::new("await-skips");
    let key = scene.key();
    let parsed = held(&scene, Oversize);
    let p_file = File::open(&scene.parent).unwrap();
    let now = sampled_scan::now_seconds();
    let mis_scoped = proof_of(
        &child_values(),
        &parent_values(),
        seal_of(&p_file, now, &codex_parent_side_scope().0),
    );
    let mislabelled = CodexParentPrefixProof {
        owned: false,
        ..scene.proof()
    };
    let other_parent = CodexParentPrefixProof {
        parent: OTHER.into(),
        ..scene.proof()
    };
    for proof in [mis_scoped, mislabelled, other_parent] {
        scene
            .index
            .codex_parent_prefix_proofs
            .insert(key.clone(), CodexParentProofState::Proven(proof));
        assert!(!awaits(&scene, &parsed));
    }
    scene.index.remove_codex_parent_proof(&key);
    assert!(!awaits(&scene, &parsed), "no proven entry");

    let mut scene = Scene::new("await-census");
    let parsed = held(&scene, Oversize);
    scene
        .index
        .traversal
        .as_mut()
        .unwrap()
        .pending_directories
        .push_back(ScanTraversalPath {
            scan_root: scene.root.clone(),
            path: scene.root.join("sub"),
            census_member: true,
            watcher_hint: false,
        });
    assert!(!awaits(&scene, &parsed), "an unavailable census");
}

/// Stage 1 S1-a (§7 exclusion row 31, owner default NO): the proof hook
/// never spends a continuation page's leftover. On the production
/// continuation pass (`begin_codex_continuation_side_pass`) with a leftover
/// that proves the owed child on an ordinary page, nothing is read, no job
/// starts and the entry is unchanged; the ordinary control spends it.
#[test]
fn the_proof_hook_spends_no_continuation_leftover() {
    let leftover = codex_proof_step_reserve() + SIDE_FENCE_READ_BYTES;
    let mut scene = Scene::owed("hook-continuation-leftover");
    let cache = Arc::new(sampled_scan::SharedCache::default());
    let continuation =
        begin_codex_continuation_side_pass(&cache, Path::new(HOOK_INDEX), &mut scene.index);
    assert_eq!(continuation.kind, CodexPageKind::Continuation);
    let owed = scene.owed_entry();
    for _ in 0..3 {
        let mut page = page_with(leftover);
        scene.hook_in(
            &cache,
            &continuation,
            &mut page,
            sampled_scan::now_seconds(),
        );
        assert_eq!(
            page.singleton_remaining(Limits::current()),
            leftover,
            "the leftover is untouched"
        );
        assert_eq!(cache.proof_suspended_for_test(), None, "no job");
        assert_eq!(scene.owed_entry(), owed);
    }
    let mut page = page_with(leftover);
    scene.hook(&cache, &mut page);
    assert!(
        page.singleton_remaining(Limits::current()) < leftover,
        "the ordinary page spends it"
    );
}

/// Stage 1 S1-a (§7 exclusion row 32): the side sweep never runs on the
/// production continuation pass, with no held job either: an orphan side
/// record and the sweep cursor stay as they are until an ordinary page.
#[test]
fn the_side_sweep_never_runs_on_a_continuation_pass() {
    let mut scene = Scene::owed("hook-continuation-sweep");
    let cache = Arc::new(sampled_scan::SharedCache::default());
    let continuation =
        begin_codex_continuation_side_pass(&cache, Path::new(HOOK_INDEX), &mut scene.index);
    let orphan = "/nonexistent/s1a-orphan-rollout.jsonl".to_owned();
    let record = scene.index.codex_parent_side[&local_index_key(&scene.parent)].clone();
    scene.index.codex_parent_side.insert(orphan.clone(), record);
    let side = serde_json::to_value(&scene.index.codex_parent_side).unwrap();
    let cursor = scene.index.codex_parent_side_cursor.clone();
    for _ in 0..3 {
        let mut page = PageBudget::default();
        scene.hook_in(
            &cache,
            &continuation,
            &mut page,
            sampled_scan::now_seconds(),
        );
        assert_eq!(
            serde_json::to_value(&scene.index.codex_parent_side).unwrap(),
            side,
            "not swept"
        );
        assert_eq!(scene.index.codex_parent_side_cursor, cursor);
    }
    scene.hook(&cache, &mut PageBudget::default());
    assert!(!scene.index.codex_parent_side.contains_key(&orphan));
}

/// Stage 1 C-1 (a), (b), (d), on the production passes: a continuation
/// page's C14 (non-EOF, or refused after C14: it charges nothing and never
/// saves) neither closes nor opens the outage gate. After a saved ordinary
/// pass the next ordinary pass may charge and due side work; after a failed
/// ordinary save it stays gated.
#[test]
fn a_continuation_pass_neither_closes_nor_opens_the_side_gate() {
    let index_path = Path::new(HOOK_INDEX);
    for ordinary_saved in [true, false] {
        let cache = Arc::new(sampled_scan::SharedCache::default());
        let mut index = ScanIndex::default();
        assert!(
            begin_codex_side_pass(&cache, index_path, &mut index)
                .gate
                .side_allowed
        );
        if ordinary_saved {
            let mark = codex_side_save_mark(&cache, index_path);
            note_codex_side_pass_saved(&cache, index_path, false, mark);
        }
        for _ in 0..3 {
            let continuation = begin_codex_continuation_side_pass(&cache, index_path, &mut index);
            assert_eq!(continuation.kind, CodexPageKind::Continuation);
            assert_eq!(continuation.gate.side_allowed, ordinary_saved);
            assert!(!continuation.side_charge_allowed() && !continuation.side_due_allowed());
        }
        let next = begin_codex_side_pass(&cache, index_path, &mut index);
        assert_eq!(next.gate.side_allowed, ordinary_saved, "the next ordinary");
        assert_eq!(next.side_charge_allowed(), ordinary_saved);
        assert_eq!(next.side_due_allowed(), ordinary_saved);
    }
}

/// Stage 1 C-1 (c): the EOF continuation page's full save (C15, `full`,
/// mark read before it) is what reopens a gate a failed ordinary save
/// closed.
#[test]
fn an_eof_continuation_save_reopens_the_side_gate() {
    let index_path = Path::new(HOOK_INDEX);
    let cache = Arc::new(sampled_scan::SharedCache::default());
    let mut index = ScanIndex::default();
    begin_codex_side_pass(&cache, index_path, &mut index);
    // That ordinary save failed: no C15.
    let eof = begin_codex_continuation_side_pass(&cache, index_path, &mut index);
    assert!(!eof.gate.side_allowed);
    let mark = codex_side_save_mark(&cache, index_path);
    note_codex_side_pass_saved(&cache, index_path, true, mark);
    assert!(
        begin_codex_side_pass(&cache, index_path, &mut index)
            .gate
            .side_allowed
    );
}

#[test]
fn ownership_deferred_parent_site_sets_parent_cause_for_both_restart_dispositions() {
    for cause in [
        CodexParentUnresolvable::DeferredRef,
        CodexParentUnresolvable::DeferredRestart,
    ] {
        let mut file = parsed(Some(PARENT));
        file.codex_parent_resolution_pending = true;
        file.defer_parent_resolution(cause);
        assert_eq!(file.ownership_incomplete_file_count, 1);
        assert_eq!(file.cause, ownership::PARENT);
        assert!(!file.codex_parent_resolution_pending);
    }
}
