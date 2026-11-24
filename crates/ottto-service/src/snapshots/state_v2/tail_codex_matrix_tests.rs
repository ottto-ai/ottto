//! The common Tail head and the Codex reduction revision are separate decode
//! axes. Each cell commits a Codex head through the real store and reads it
//! back with this build's reader and with a revision-1 reader.
use super::super::super::tail::{FileJob, JobUpdate};
use super::*;
use crate::session_attribution::job_template::JobState;
use crate::snapshots::tail_source::codex::{counted_trailer_bytes, Codex};
use crate::snapshots::tail_source::historical_codex::{decode, Frozen};
use crate::snapshots::tail_source::TailSource;
use crate::snapshots::{CountedRequests, SnapshotAccumulator, SnapshotSource};
use std::num::{NonZeroU32, NonZeroU64};

/// The released revision-1 Codex head bytes and their decoded state.
fn revision_one() -> (Vec<u8>, SnapshotAccumulator) {
    let frozen: serde_json::Value = serde_json::from_str(include_str!(
        "../../../tests/fixtures/codex-counting/revision-one-head.json"
    ))
    .unwrap();
    assert_eq!(frozen["revision"].as_u64(), Some(1));
    let bytes: Vec<u8> = serde_json::from_value(frozen["head"].clone()).unwrap();
    let (acc, _, _) = decode(Frozen::RevisionOne);
    (bytes, acc)
}

/// Revision-2 bytes of the same state with every counted position known:
/// twelve requests, and the three markers at requests 4, 8 and 12.
fn revision_two_known(bytes: &[u8]) -> (Vec<u8>, CountedRequests) {
    let (_, mut counted) = revision_one();
    let mut curve = Some(CountedRequests::default());
    for size in 1..=12 {
        CountedRequests::note(&mut curve, 1_000 + size);
    }
    counted.counted_requests = curve;
    counted
        .codex_compaction_sizes
        .restore_request_indices([4, 8, 12].map(NonZeroU64::new).to_vec())
        .unwrap();
    (
        [bytes.to_vec(), counted_trailer_bytes(&counted)].concat(),
        curve.unwrap(),
    )
}

fn job() -> FileJob {
    FileJob {
        inode: 11,
        birth_nanos: 12,
        state: JobState::NoId,
    }
}

/// [format] Old common (version 1 envelope, no job block, as 0.1.262 writes
/// it) and new common (a job block and a write generation count, version 2)
/// each carry a revision-1 and a revision-2 Codex reduction. Every cell loads
/// at this build's revision with its common facts and reduction bytes exact
/// and decodes; a revision-1 reader reads the revision-1 cells and holds the
/// revision-2 cells; a common-only read at `u32::MAX` serves all four. A
/// revision-1 cell restaged at revision 2 keeps its job and its counts stay
/// unknown.
#[test]
fn codex_revision_and_common_envelope_matrix() {
    let (one, frozen) = revision_one();
    let unknown = [one.clone(), counted_trailer_bytes(&frozen)].concat();
    let (two, curve) = revision_two_known(&one);
    for new_common in [false, true] {
        for revision in [1_u32, 2] {
            let cell = format!("new_common={new_common} revision={revision}");
            let body = if revision == 1 { &one } else { &two };
            let f = Fixture::new();
            f.published();
            let mut index = load_with(&f.path, false).unwrap().unwrap();
            if new_common {
                super::super::tail_route::stage_job(&f.path, FILE, JobUpdate::Set(job())).unwrap();
            }
            stage_tail(
                &f.path,
                FILE,
                StagedFile {
                    revision,
                    head: body.clone(),
                    write_generation: new_common.then(|| NonZeroU32::new(7).unwrap()),
                    ..Default::default()
                },
            )
            .unwrap();
            save_with(&f.path, &mut index).unwrap();
            let index = load_with(&f.path, false).unwrap().unwrap();

            let head = load_head(&index, FILE, Codex::REDUCTION_REVISION)
                .unwrap()
                .unwrap();
            assert_eq!(head.revision, revision, "{cell}");
            assert_eq!(&head.body, body, "{cell}");
            assert_eq!(head.common.job, new_common.then(job), "{cell}");
            assert!(!head.job_corrupt, "{cell}");
            assert_eq!(
                head.write_generation,
                new_common.then(|| NonZeroU32::new(7).unwrap()),
                "{cell}"
            );
            let bytes = tail::encode_head(
                head.revision,
                &head.table,
                &head.common,
                Some(&head.body),
                head.write_generation,
            )
            .unwrap();
            assert_eq!(&bytes[..4], &revision.to_be_bytes(), "{cell}");
            assert_eq!(bytes[4], 0, "no collections: {cell}");
            assert_eq!(bytes[5], 1 + u8::from(new_common), "envelope: {cell}");
            assert_eq!(bytes[30], 1 + 4 * u8::from(new_common), "parts: {cell}");

            let mut acc = SnapshotAccumulator::new(SnapshotSource::Codex);
            Codex::decode_head(head.revision, &head.body, &mut acc).unwrap();
            let indices: Vec<_> = acc
                .codex_compaction_sizes
                .request_indices()
                .into_iter()
                .map(|index| index.map(NonZeroU64::get))
                .collect();
            if revision == 1 {
                assert_eq!(acc.counted_requests, None, "{cell}");
                assert_eq!(indices, [None; 3], "{cell}");
            } else {
                assert_eq!(acc.counted_requests, Some(curve), "{cell}");
                assert_eq!(indices, [Some(4), Some(8), Some(12)], "{cell}");
            }

            let older = load_head(&index, FILE, 1);
            if revision == 1 {
                let older = older.unwrap().unwrap();
                assert_eq!(older.common.job, head.common.job, "{cell}");
                assert_eq!(older.write_generation, head.write_generation, "{cell}");
                assert_eq!(older.body, head.body, "{cell}");
            } else {
                let error = older.err().expect("a revision-1 reader holds");
                assert_eq!(error.downcast_ref::<Hold>(), Some(&Hold::Future), "{cell}");
            }
            let common_only = load_head(&index, FILE, u32::MAX).unwrap().unwrap();
            assert_eq!(common_only.common.job, head.common.job, "{cell}");
            assert_eq!(
                common_only.write_generation, head.write_generation,
                "{cell}"
            );

            if revision == 1 {
                let mut index = index;
                stage_tail(
                    &f.path,
                    FILE,
                    StagedFile {
                        revision: 2,
                        head: unknown.clone(),
                        write_generation: NonZeroU32::new(8),
                        ..Default::default()
                    },
                )
                .unwrap();
                save_with(&f.path, &mut index).unwrap();
                let index = load_with(&f.path, false).unwrap().unwrap();
                let grown = load_head(&index, FILE, Codex::REDUCTION_REVISION)
                    .unwrap()
                    .unwrap();
                assert_eq!(grown.revision, 2, "{cell}");
                assert_eq!(grown.common.job, new_common.then(job), "{cell}");
                assert_eq!(grown.write_generation, NonZeroU32::new(8), "{cell}");
                let mut acc = SnapshotAccumulator::new(SnapshotSource::Codex);
                Codex::decode_head(2, &grown.body, &mut acc).unwrap();
                assert_eq!(acc.counted_requests, None, "{cell}");
                let error = load_head(&index, FILE, 1)
                    .err()
                    .expect("held after restage");
                assert_eq!(error.downcast_ref::<Hold>(), Some(&Hold::Future), "{cell}");
            }
        }
    }
}
