//! Reader, serializer, custody and joint-budget fixtures for the identity latch.
use super::*;
use desktop_identity::IdentityLatch::{Pending, Refused, Settled};
include!("desktop_lineage_legacy_fields.rs");

const CHILD: &str = "/synthetic/child.jsonl";

fn seed() -> ScanIndex {
    let mut index = ScanIndex::default();
    index.files.insert(
        CHILD.into(),
        super::super::tests::manifest_index_entry(Some(&"a".repeat(64))),
    );
    index
        .claude_desktop_identity_latches
        .insert(CHILD.into(), Pending);
    index
}

fn read_registry(bytes: &[u8], fields: &'static [&'static str], pass: Pass) -> ScanIndex {
    let mut reader = std::io::Cursor::new(bytes);
    let census_resources = validate_original(&mut reader).unwrap();
    let mut decoder = Decoder {
        reader,
        input_len: bytes.len() as u64,
        held_bytes: 0,
        held_count: 0,
        holds: Holds::default(),
        counts: Counts::default(),
        family_spans: BTreeMap::new(),
        census_resources,
        persistence_map: false,
    };
    decoder.index_fields(pass, fields).unwrap()
}

fn selector_drops(rows: &[Value]) -> u64 {
    rows.iter()
        .filter_map(|row| row["counts"]["desktop_metadata"]["lineage_selector_drops"].as_u64())
        .sum()
}

#[test]
fn desktop_identity_latch_roundtrips_closed_states_through_every_reader() {
    let mut index = seed();
    for latch in [Pending, Settled, Refused(0x0123_4567_89ab_cdef)] {
        index
            .claude_desktop_identity_latches
            .insert(CHILD.into(), latch);
        let bytes = serde_json::to_vec(&index).unwrap();
        let text = String::from_utf8_lossy(&bytes);
        let value = match latch {
            Pending => "identity_pending",
            Settled => "settled",
            Refused(_) => "refused:0123456789abcdef",
        };
        assert!(text.contains(&format!(
            r#""claude_desktop_identity_latches":{{"/synthetic/child.jsonl":"{value}"}}"#
        )));
        let native: ScanIndex = serde_json::from_slice(&bytes).unwrap();
        let streaming = read(std::io::Cursor::new(&bytes), "load", "claude_code").unwrap();
        let bounded = read_bounded(&bytes).unwrap();
        for loaded in [native, streaming, bounded] {
            assert_eq!(
                loaded.claude_desktop_identity_latches,
                index.claude_desktop_identity_latches
            );
        }
    }
    index.claude_desktop_identity_latches.clear();
    let bytes = serde_json::to_vec(&index).unwrap();
    assert!(!String::from_utf8_lossy(&bytes).contains("claude_desktop_identity_latches"));
    #[cfg(target_pointer_width = "64")]
    assert_eq!(std::mem::size_of::<ScanIndexEntry>(), 560);
}

#[test]
fn desktop_identity_old_201_202_203_registries_drop_latches_and_reload_unsettled() {
    // Old readers skip the unknown root name and their save drops it. The
    // re-upgraded reader sees no entry: not settled, never a wrong account.
    let seed = seed();
    let bytes = serde_json::to_vec(&seed).unwrap();
    for (version, fields) in [
        ("0.1.201", FIELDS_201),
        ("0.1.202", FIELDS_202_203),
        ("0.1.203", FIELDS_202_203),
    ] {
        let old = read_registry(&bytes, fields, Pass::Full);
        assert!(old.claude_desktop_identity_latches.is_empty(), "{version}");
        assert_eq!(old.files.len(), 1, "{version}");
        let old_save = serde_json::to_vec(&old).unwrap();
        assert!(!String::from_utf8_lossy(&old_save).contains("claude_desktop_identity_latches"));
        let upgraded = read(std::io::Cursor::new(old_save), "load", "claude_code").unwrap();
        assert!(upgraded.claude_desktop_identity_latches.is_empty());
    }
}

#[test]
fn desktop_identity_malformed_latches_default_empty_count_once_and_keep_custody() {
    let over_count: BTreeMap<_, _> = (0..=desktop_lineage::MAX_EDGES)
        .map(|n| (format!("/synthetic/{n}.jsonl"), "settled"))
        .collect();
    for bad in [
        json!(["wrong shape"]),
        // Closed state only: no account, digest or open value is admitted.
        json!({CHILD:"complete"}),
        json!({CHILD:{"account":"a"}}),
        json!({CHILD:3}),
        json!({("k".repeat(8193)):"settled"}),
        json!({CHILD:"x".repeat(desktop_lineage::MAX_DECODE_BYTES as usize)}),
        serde_json::to_value(over_count).unwrap(),
    ] {
        let original = seed();
        let mut value = serde_json::to_value(&original).unwrap();
        value["claude_desktop_identity_latches"] = bad;
        let bytes = serde_json::to_vec(&value).unwrap();
        let (loaded, rows) = crate::local_resource_diagnostics::capture(|| {
            read(std::io::Cursor::new(&bytes), "load", "claude_code").unwrap()
        });
        assert!(loaded.claude_desktop_identity_latches.is_empty());
        assert_eq!(loaded.files.len(), 1, "selector damage never loses custody");
        assert_eq!(selector_drops(&rows), 1);
        let (bounded, rows) =
            crate::local_resource_diagnostics::capture(|| read_bounded(&bytes).unwrap());
        assert!(bounded.claude_desktop_identity_latches.is_empty());
        assert_eq!(bounded.files.len(), 1);
        assert!(selector_drops(&rows) >= 1);
    }
}

#[test]
fn desktop_identity_repair_capture_carries_latches_without_census_authority() {
    let seed = seed();
    let carry = read_registry(
        &serde_json::to_vec(&seed).unwrap(),
        FIELDS,
        Pass::IdentityCarry,
    );
    assert_eq!(
        carry.claude_desktop_identity_latches,
        seed.claude_desktop_identity_latches
    );
    let mut repaired = ScanIndex::default();
    repaired.carry_identity_from(carry).unwrap();
    assert_eq!(
        repaired.claude_desktop_identity_latches,
        seed.claude_desktop_identity_latches
    );
    assert!(!repaired.claude_desktop_identity_census_complete);
    assert!(repaired.files.is_empty());
}

#[test]
fn desktop_identity_partial_save_commits_only_ack_settled_latches() {
    // E1/SOURCE: a failed upload or partial save keeps the previous state.
    let previous = seed();
    let mut working = previous.clone();
    let other = "/synthetic/other.jsonl";
    working.files.insert(
        other.into(),
        super::super::tests::manifest_index_entry(Some(&"b".repeat(64))),
    );
    working
        .claude_desktop_identity_latches
        .insert(CHILD.into(), Settled);
    working
        .claude_desktop_identity_latches
        .insert(other.into(), Pending);
    let safe = BTreeSet::from([other.to_string()]);
    let committed = desktop_identity::committable_identity_latches(
        &working,
        &previous,
        &safe,
        &BTreeMap::new(),
    );
    assert_eq!(committed[CHILD], Pending, "unsettled ACK keeps pending");
    assert_eq!(committed[other], Pending);
    let committed = desktop_identity::committable_identity_latches(
        &working,
        &previous,
        &BTreeSet::new(),
        &BTreeMap::new(),
    );
    assert_eq!(committed, previous.claude_desktop_identity_latches);
}

#[test]
fn desktop_identity_joint_budget_refuses_new_latch_counted_without_evicting_edges() {
    // One decode-span budget for both root selector maps: lineage baselines
    // that nearly fill it leave no room for a new latch, and nothing evicts.
    let mut index = seed();
    index.claude_desktop_identity_latches.clear();
    let entry = index.files[CHILD].clone();
    let edge = desktop_lineage::edge_fingerprint(None);
    let mut n = 0;
    loop {
        let key = format!("/synthetic/{n:03}/{}", "\\".repeat(8000));
        index.files.insert(key.clone(), entry.clone());
        let before = index.claude_desktop_lineage_file_edges.len();
        let (_, rows) = crate::local_resource_diagnostics::capture(|| {
            index.record_desktop_lineage_file_edge(&key, edge.clone())
        });
        if index.claude_desktop_lineage_file_edges.len() == before {
            assert_eq!(selector_drops(&rows), 1);
            index.files.remove(&key);
            break;
        }
        n += 1;
    }
    let edges = index.claude_desktop_lineage_file_edges.clone();
    // The remaining room is below one escaped key, but an ordinary key fits.
    let small = "/synthetic/small.jsonl";
    index.files.insert(small.into(), entry.clone());
    let wide = format!("/synthetic/wide/{}", "\\".repeat(8000));
    index.files.insert(wide.clone(), entry);
    let (_, rows) = crate::local_resource_diagnostics::capture(|| {
        index.record_desktop_identity_latch(&wide, Pending)
    });
    assert!(!index.claude_desktop_identity_latches.contains_key(&wide));
    assert_eq!(selector_drops(&rows), 1, "refusal at the cap is counted");
    assert_eq!(
        index.claude_desktop_lineage_file_edges, edges,
        "no eviction"
    );
    let (_, rows) = crate::local_resource_diagnostics::capture(|| {
        index.record_desktop_identity_latch(small, Pending)
    });
    assert_eq!(selector_drops(&rows), 0);
    let (_, rows) = crate::local_resource_diagnostics::capture(|| {
        index.record_desktop_identity_latch(small, Settled)
    });
    assert_eq!(selector_drops(&rows), 0, "existing latches stay updateable");
    assert_eq!(index.claude_desktop_identity_latches[small], Settled);
    let joint = serde_json::to_vec(&index.claude_desktop_lineage_file_edges)
        .unwrap()
        .len()
        + serde_json::to_vec(&index.claude_desktop_identity_latches)
            .unwrap()
            .len();
    assert!(joint as u64 <= desktop_lineage::MAX_DECODE_BYTES);
    let scratch = crate::test_scratch::ScratchDir::new("desktop-identity-joint-budget");
    let path = scratch.join("index.json");
    index.save(&path).unwrap();
    let (loaded, rows) =
        crate::local_resource_diagnostics::capture(|| ScanIndex::load(&path).unwrap());
    assert_eq!(selector_drops(&rows), 0);
    assert_eq!(loaded.claude_desktop_lineage_file_edges, edges);
    assert_eq!(
        loaded.claude_desktop_identity_latches,
        index.claude_desktop_identity_latches
    );
}

#[test]
fn desktop_identity_record_cap_refuses_only_new_children() {
    let mut index = seed();
    let entry = index.files[CHILD].clone();
    index.claude_desktop_identity_latches.clear();
    for n in 0..desktop_lineage::MAX_EDGES {
        let key = format!("/s/{n}.jsonl");
        index.files.insert(key.clone(), entry.clone());
        index.claude_desktop_identity_latches.insert(key, Settled);
    }
    let previous = index.claude_desktop_identity_latches.clone();
    let (_, rows) = crate::local_resource_diagnostics::capture(|| {
        index.record_desktop_identity_latch(CHILD, Pending)
    });
    assert_eq!(index.claude_desktop_identity_latches, previous);
    assert_eq!(selector_drops(&rows), 1);
    assert!(rows
        .iter()
        .any(|row| row["stage"] == "native_collection_page"));
}
