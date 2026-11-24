//! Test-only historical bytes, never a historical counting producer.
use super::*;
use crate::snapshots::state_v2::Collection;
use serde_json::Value;

#[derive(Clone, Copy)]
pub(in crate::snapshots) enum Frozen {
    Legacy,
    V2,
    StickyLegacy,
    /// Released revision-1 head with three markers and no counted curve.
    RevisionOne,
}

pub(in crate::snapshots) fn decode(
    kind: Frozen,
) -> (SnapshotAccumulator, Vec<String>, DecodedHead) {
    let text = match kind {
        Frozen::Legacy => include_str!("../../../tests/fixtures/codex-counting/legacy-head.json"),
        Frozen::V2 => include_str!("../../../tests/fixtures/codex-counting/v2-head.json"),
        Frozen::StickyLegacy => {
            include_str!("../../../tests/fixtures/codex-counting/sticky-legacy-head.json")
        }
        Frozen::RevisionOne => {
            include_str!("../../../tests/fixtures/codex-counting/revision-one-head.json")
        }
    };
    let frozen: Value = serde_json::from_str(text).unwrap();
    let bytes: Vec<u8> = serde_json::from_value(frozen["head"].clone()).unwrap();
    let mut acc = SnapshotAccumulator::new(SnapshotSource::Codex);
    let decoded = codex::Codex::decode_head(
        frozen["revision"].as_u64().unwrap() as u32,
        &bytes,
        &mut acc,
    )
    .unwrap();
    for page in frozen["pages"].as_array().unwrap() {
        let collection = match page[0].as_str().unwrap() {
            "CodexActiveTurns" => Collection::CodexActiveTurns,
            "CodexOpenCalls" => Collection::CodexOpenCalls,
            "CodexNameCounts" => Collection::CodexNameCounts,
            "PriorityTurns" => Collection::PriorityTurns,
            "Signatures" => Collection::Signatures,
            "Requests" => Collection::Requests,
            "Compactions" => Collection::Compactions,
            "UsageHours" => Collection::UsageHours,
            "CapabilityHours" => Collection::CapabilityHours,
            "ChangedFiles" => Collection::ChangedFiles,
            "SessionFacts" => Collection::SessionFacts,
            other => panic!("unexpected historical collection {other}"),
        };
        let bytes: Vec<u8> = serde_json::from_value(page[2].clone()).unwrap();
        codex::Codex::decode_page(collection, page[1].as_u64().unwrap(), &bytes, &mut acc).unwrap();
    }
    let id = HeadIdentity::take(&mut Dec::new(&bytes)).unwrap();
    let view = PreFinalization::new(&acc, &decoded.report, decoded.scalars);
    // Revision 1 bytes stay exact; the re-encode only appends revision 2's
    // extension, here with every counted position unknown.
    assert_eq!(acc.counted_requests, None);
    assert!(acc
        .codex_compaction_sizes
        .request_indices()
        .iter()
        .all(Option::is_none));
    assert_eq!(
        codex::Codex::encode_head(&view, &decoded.certificate, &id).unwrap(),
        [bytes.clone(), codex::counted_trailer_bytes(&acc)].concat(),
        "historical head bytes and shape must remain exact"
    );
    if !matches!(kind, Frozen::RevisionOne) {
        assert_eq!(acc.codex_counting_v2(), matches!(kind, Frozen::V2));
    }
    (
        acc,
        serde_json::from_value(frozen["lines"].clone()).unwrap(),
        decoded,
    )
}

pub(in crate::snapshots) fn read(kind: Frozen) -> (SnapshotAccumulator, Vec<String>) {
    let (acc, lines, _) = decode(kind);
    (acc, lines)
}

/// Transplant the immutable reduction into its same-input synthetic file's
/// physical envelope. No transcript is interpreted under the old formula.
pub(in crate::snapshots) fn seed(index: &mut ScanIndex, path: &Path, root: &Path, kind: Frozen) {
    let key = local_index_key(path);
    let route = state_v2::tail_route_path(index).unwrap().unwrap();
    let current = state_v2::load_head(index, &key, codex::Codex::REDUCTION_REVISION)
        .unwrap()
        .unwrap();
    let mut unused = SnapshotAccumulator::new(SnapshotSource::Codex);
    let decoded = codex::Codex::decode_head(current.revision, &current.body, &mut unused).unwrap();
    let capture = HeadIdentity::take(&mut Dec::new(&current.body))
        .unwrap()
        .capture;
    let (mut old, _, historical) = decode(kind);
    old.codex_sidecar_binding = unused.codex_sidecar_binding;
    let entry = &index.files[&key];
    let items = old.clone().into_items(
        path,
        "2026-10-27T08:00:00Z",
        entry.source_file_fingerprint.clone(),
        None,
    );
    assert_eq!(items.len(), 1);
    let fingerprints = items
        .iter()
        .map(|item| snapshot_fingerprint(SnapshotSource::Codex, item))
        .collect::<BTreeSet<_>>();
    let view = PreFinalization::new(&old, &historical.report, historical.scalars);
    let staged = seam::TailBase::default()
        .stage::<codex::Codex>(
            &view,
            &decoded.certificate,
            &HeadIdentity::new(&route, SnapshotSource::Codex, root, path, capture),
            state_v2::Change::Reset,
        )
        .unwrap()
        .unwrap();
    state_v2::stage_tail(&route, &key, staged).unwrap();
    let entry = index.files.get_mut(&key).unwrap();
    entry.codex_counting_v2 = matches!(kind, Frozen::V2);
    entry.codex_counting_owner = old
        .source_session_id
        .as_deref()
        .map(codex_protected_owner)
        .map(String::into_boxed_str);
    entry.last_snapshot_fingerprint = Some(snapshot_file_entity_set_hex(fingerprints.clone()));
    entry.last_upload_body_witness = Some(snapshot_upload_body_witness(&items[0]));
    index
        .file_snapshot_fingerprints
        .insert(key, fingerprints.clone());
    index.record_accepted_snapshot_fingerprints(&fingerprints);
}
