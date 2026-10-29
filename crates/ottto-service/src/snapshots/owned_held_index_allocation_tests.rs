// Reuses the synthetic S6 fixture shape and existing thread-local M2 probe.
// Both incoming graphs are born inside the measurement. This avoids charging
// frees of pre-existing allocations as negative allocation savings.
use super::*;
use crate::retry_allocation_probe::{self as probe, Stats};

const REQUESTS_PER_ROOT: usize = 16;
const MEMBERS_PER_ROOT: usize = 2;
const MAX_DUPLICATE_OWNERS: usize = 1024;
const MAX_FIXTURE_BYTES: u64 = 8 * 1024 * 1024;

fn digest(tag: u64, value: usize) -> String {
    format!("{tag:016x}{value:048x}")
}

fn root_id(root: usize) -> String {
    format!("{:08x}-5a5a-4000-8000-000000000006", 0x6e00_0000 + root)
}

fn member_keys(root: usize) -> [(String, String); MEMBERS_PER_ROOT] {
    let session = root_id(root);
    [
        (
            session.clone(),
            format!("/synthetic/m2/projects/{session}.jsonl"),
        ),
        (
            format!("{session}_agent-m2{root:04x}"),
            format!("/synthetic/m2/projects/{session}/subagents/agent-m2{root:04x}.jsonl"),
        ),
    ]
}

/// Committed files, pending occurrence maps, retained witnesses, and
/// duplicate owners for `roots` families. Every collection grows with
/// `roots`; ids are fixed width so string sizes do not.
fn synthetic_index(roots: usize) -> ScanIndex {
    let mut index = ScanIndex {
        accepted_snapshot_fingerprint_ledger_version: SNAPSHOT_ACCEPTED_LEDGER_VERSION,
        ..ScanIndex::default()
    };
    for root in 0..roots {
        let mut pending = ClaudeUsageFamilyPending {
            derived_request_members: std::collections::BTreeSet::new(),
            census_window_end: WINDOW.to_string(),
            member_request_id_hashes: BTreeMap::new(),
            member_occurrences: BTreeMap::new(),
            invalid: false,
            idless_revision: None,
        };
        let mut witness = ClaudeUsageFamilyWitness {
            evidence_fingerprint: digest(1, root),
            member_request_id_fingerprints: BTreeMap::new(),
            member_occurrence_fingerprints: BTreeMap::new(),
            assigned_request_id_fingerprints: BTreeMap::new(),
            legacy_excluded_request_id_hashes: BTreeMap::new(),
            legacy_exclusion_evidence_fingerprint: None,
            legacy_owner_roots: BTreeSet::new(),
        };
        for (slot, (member, key)) in member_keys(root).into_iter().enumerate() {
            let file = root * MEMBERS_PER_ROOT + slot;
            index_file(&mut index, &key, &digest(2, file), &digest(3, file), WINDOW);
            index.accepted_snapshot_fingerprints.insert(digest(3, file));
            let requests = (0..REQUESTS_PER_ROOT / MEMBERS_PER_ROOT)
                .map(|request| file * REQUESTS_PER_ROOT + request)
                .collect::<Vec<_>>();
            pending.member_request_id_hashes.insert(
                member.clone(),
                requests.iter().map(|request| digest(4, *request)).collect(),
            );
            pending.member_occurrences.insert(
                member.clone(),
                requests
                    .iter()
                    .map(|request| {
                        (
                            digest(4, *request),
                            occurrence(*request as u64, 1 + (*request % 7) as u64),
                        )
                    })
                    .collect(),
            );
            witness
                .member_request_id_fingerprints
                .insert(member.clone(), digest(5, file));
            witness
                .member_occurrence_fingerprints
                .insert(member.clone(), digest(6, file));
            witness
                .assigned_request_id_fingerprints
                .insert(member, digest(7, file));
        }
        index
            .claude_usage_family_pending
            .insert(root_id(root), pending);
        index
            .claude_usage_family_witnesses
            .insert(root_id(root), witness);
    }
    for request in 0..(roots * REQUESTS_PER_ROOT).min(MAX_DUPLICATE_OWNERS) {
        let first = root_id(request / REQUESTS_PER_ROOT);
        let second = root_id((request / REQUESTS_PER_ROOT + 1) % roots);
        index.claude_duplicate_request_owners.insert(
            digest(8, request),
            BTreeSet::from([
                claude_duplicate_request_owner(&first, &first),
                claude_duplicate_request_owner(&second, &second),
            ]),
        );
    }
    index
}

fn replace_body(index: &mut ScanIndex, key: &str, fingerprint: &str) {
    index
        .files
        .get_mut(key)
        .expect("indexed synthetic root")
        .last_snapshot_fingerprint = Some(fingerprint.to_string());
    index
        .file_snapshot_fingerprints
        .insert(key.to_string(), BTreeSet::from([fingerprint.to_string()]));
    index
        .snapshot_activity_at
        .insert(fingerprint.to_string(), Some(WINDOW.to_string()));
}

fn value<T: Serialize>(value: &T) -> Value {
    serde_json::to_value(value).expect("serialize synthetic index state")
}

struct Measured {
    output: ScanIndex,
    incoming_bytes: usize,
    phase_peak: usize,
    helper_allocations: usize,
    whole: Stats,
}

fn measure_restore(
    current: &ScanIndex,
    previous: &ScanIndex,
    held: &BTreeSet<String>,
    reparse: &BTreeSet<String>,
    consume: bool,
) -> Measured {
    let ((output, before, after, phase_peak), whole) = probe::measure(|| {
        let incoming = current.clone();
        let before = probe::stats();
        probe::phase_begin();
        let output = if consume {
            incoming.into_locally_held_keys_reverted(previous, held, reparse)
        } else {
            incoming.with_locally_held_keys_reverted(previous, held, reparse)
        };
        let after = probe::stats();
        let peak = probe::phase_peak();
        (output, before, after, peak)
    });
    Measured {
        output,
        incoming_bytes: usize::try_from(before.requested_live).expect("incoming graph bytes"),
        phase_peak,
        helper_allocations: after.allocations - before.allocations,
        whole,
    }
}

fn emit(roots: usize, debt: bool, stage: &str, measured: &Measured) {
    use std::io::Write as _;
    let line = serde_json::json!({
        "receipt": "owned_held_index_restoration:v1",
        "synthetic_family_roots": roots,
        "requests_per_root": REQUESTS_PER_ROOT,
        "reparse_debt": debt,
        "stage": stage,
        "incoming_requested_bytes": measured.incoming_bytes,
        "additional_requested_phase_peak_bytes": measured.phase_peak,
        "helper_allocations": measured.helper_allocations,
        "scope_requested_peak_bytes": measured.whole.requested_peak,
        "scope_requested_live_bytes": measured.whole.requested_live,
        "scope_usable_peak_bytes": measured.whole.usable_peak,
    });
    std::io::stderr()
        .write_all(format!("{line}\n").as_bytes())
        .expect("allocation receipt");
}

fn compare(roots: usize, debt: bool) {
    let previous = synthetic_index(roots);
    let mut current = previous.clone();
    let mut held = BTreeSet::new();
    let mut reparse = BTreeSet::new();
    for root in 0..roots {
        let changed = digest(9, root);
        let [(_, key), _] = member_keys(root);
        replace_body(&mut current, &key, &changed);
        if root % 4 == 0 {
            held.insert(changed.clone());
            if debt {
                if root % 8 == 0 {
                    current
                        .files
                        .get_mut(&key)
                        .unwrap()
                        .source_file_fingerprint
                        .clear();
                } else {
                    reparse.insert(changed);
                }
            }
        } else {
            current.accepted_snapshot_fingerprints.insert(changed);
        }
    }
    let current_before = serde_json::to_vec(&current).unwrap();
    let previous_before = serde_json::to_vec(&previous).unwrap();
    assert!((current_before.len() as u64) <= MAX_FIXTURE_BYTES);
    let borrowed = measure_restore(&current, &previous, &held, &reparse, false);
    let owned = measure_restore(&current, &previous, &held, &reparse, true);
    assert_eq!(
        serde_json::to_vec(&owned.output).unwrap(),
        serde_json::to_vec(&borrowed.output).unwrap(),
        "every serialized field, exact body/ACK ledger and debt agrees"
    );
    assert_eq!(serde_json::to_vec(&current).unwrap(), current_before);
    assert_eq!(serde_json::to_vec(&previous).unwrap(), previous_before);
    for root in 0..roots {
        let [(_, key), _] = member_keys(root);
        let mut expected = if root % 4 == 0 {
            previous.files[&key].clone()
        } else {
            current.files[&key].clone()
        };
        if root % 4 == 0 && debt {
            expected.source_file_fingerprint.clear();
        }
        assert_eq!(value(&owned.output.files[&key]), value(&expected));
        let reference = if root % 4 == 0 { &previous } else { &current };
        assert_eq!(
            owned.output.file_snapshot_fingerprints.get(&key),
            reference.file_snapshot_fingerprints.get(&key)
        );
    }
    let active = owned.output.current_snapshot_fingerprints();
    for fingerprint in &held {
        assert!(!active.contains(fingerprint));
        assert!(!owned
            .output
            .accepted_snapshot_fingerprints
            .contains(fingerprint));
        assert!(!owned.output.snapshot_activity_at.contains_key(fingerprint));
    }
    assert!(previous
        .accepted_snapshot_fingerprints
        .iter()
        .filter(|fingerprint| active.contains(*fingerprint))
        .all(|fingerprint| owned
            .output
            .accepted_snapshot_fingerprints
            .contains(fingerprint)));
    assert!(
        borrowed.phase_peak >= borrowed.incoming_bytes,
        "borrowed retains a second graph"
    );
    assert!(
        owned.phase_peak.saturating_mul(4) < borrowed.phase_peak,
        "owned phase must remove the full clone peak: borrowed{} owned{}",
        borrowed.phase_peak,
        owned.phase_peak
    );
    assert!(owned.helper_allocations < borrowed.helper_allocations);
    emit(roots, debt, "borrowed", &borrowed);
    emit(roots, debt, "owned", &owned);

    // Exercise the unchanged real CAS/save/load path on both exact outputs.
    let scratch = crate::test_scratch::ScratchDir::new("owned-held-index-parity");
    let old_path = scratch.join("borrowed.json");
    let new_path = scratch.join("owned.json");
    let mut old_output = borrowed.output;
    let mut new_output = owned.output;
    old_output.save(&old_path).expect("save borrowed reference");
    new_output.save(&new_path).expect("save owned output");
    assert_eq!(
        fs::read(&old_path).unwrap(),
        fs::read(&new_path).unwrap(),
        "exact durable bytes"
    );
    let restored = ScanIndex::load(&new_path).expect("reload owned output");
    assert_eq!(
        serde_json::to_vec(&restored).unwrap(),
        serde_json::to_vec(&new_output).unwrap()
    );
}

#[test]
fn owned_held_index_restoration_preserves_output_and_removes_clone_peak() {
    for roots in [32, 64] {
        for debt in [false, true] {
            compare(roots, debt);
        }
    }
}
