//! The Codex half of the previous-release per-file carry check, run only by
//! the carry harness. The target stores Codex Tail heads whose prelude fact
//! is version 2, a sealed start as a later build writes it, and grows one
//! transcript. After the previous release has run on that store, the target
//! resumes the files it held, and every sealed start is still there byte for
//! byte.
use super::{lines, SESSION};
use crate::durable_tail_codec::{Dec, Enc};
use crate::snapshots::e2_pipeline_scan_fixture::E2ScanFixture;
use crate::snapshots::session_start::SessionStartState;
use crate::snapshots::state_v2::{self, Change, Collection};
use crate::snapshots::tail_source::{self, codex::Codex, seam::TailBase, HeadIdentity, TailSource};
use crate::snapshots::{
    finalize_scan_after_policy, local_index_key, PreFinalization, ScanIndex, SnapshotAccumulator,
    SnapshotSource,
};
use crate::transcript_acquisition::ReadMode;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

const SOURCE: SnapshotSource = SnapshotSource::Codex;
/// The Codex prelude session fact.
const PRELUDE: u64 = 5;
const GROWN: &str = "019a0c2a-8e11-7222-8333-94444555a001";
const QUIET: &str = "019a0c2a-8e11-7222-8333-94444555a002";
const PROVEN: &str = "019a0c2a-8e11-7222-8333-94444555a004";
const CONTROL: &str = "019a0c2a-8e11-7222-8333-94444555a003";

#[derive(Deserialize, Serialize)]
struct Manifest {
    index_path: PathBuf,
    corpus_root: PathBuf,
    support: PathBuf,
    tail_keys: Vec<String>,
    control_key: String,
    /// Closed turns each file holds now.
    turns: BTreeMap<String, usize>,
    /// The length-prefixed sealed start each file's prelude fact ends with.
    sealed: BTreeMap<String, Vec<u8>>,
}

#[derive(Debug, Deserialize, PartialEq, Serialize)]
struct Format {
    revision: u32,
    facts: BTreeMap<u64, u64>,
}

fn carry_dir() -> PathBuf {
    PathBuf::from(std::env::var_os("OTTTO_CODEX_PER_FILE_CARRY_DIR").expect("the carry harness"))
        .canonicalize()
        .unwrap()
}

fn rollout(root: &Path, session: &str) -> PathBuf {
    root.join(format!("rollout-2026-10-18T10-00-00-{session}.jsonl"))
}

fn session_lines(session: &str, turns: usize) -> Vec<String> {
    lines(turns)
        .into_iter()
        .map(|line| line.replace(SESSION, session))
        .collect()
}

fn write_rollout(root: &Path, session: &str, turns: usize) -> PathBuf {
    let path = rollout(root, session);
    fs::write(&path, session_lines(session, turns).join("\n") + "\n").unwrap();
    path
}

/// Grow `key` by one closed turn; `lines(n)` is a prefix of `lines(n + 1)`.
fn grow(manifest: &mut Manifest, key: &str) {
    let session = Path::new(key)
        .file_stem()
        .unwrap()
        .to_str()
        .unwrap()
        .rsplit_once("-00-00-")
        .unwrap()
        .1
        .to_owned();
    let turns = manifest.turns.get_mut(key).unwrap();
    let before = session_lines(&session, *turns).len();
    *turns += 1;
    let mut file = fs::OpenOptions::new().append(true).open(key).unwrap();
    for line in &session_lines(&session, *turns)[before..] {
        writeln!(file, "{line}").unwrap();
    }
}

fn scan_and_save(scanner: &E2ScanFixture, manifest: &Manifest, index: ScanIndex) -> ScanIndex {
    let (mut index, mut scan, _) = scanner.scan_other(
        SOURCE,
        std::slice::from_ref(&manifest.corpus_root),
        &manifest.support,
        index,
        true,
    );
    finalize_scan_after_policy(SOURCE, &mut scan, &mut index);
    scan.finish_codex_capture_boundary(&mut index);
    index.save(&manifest.index_path).unwrap();
    index
}

/// The committed head's revision, each session fact's version, and the
/// prelude fact's bytes.
fn stored(index: &ScanIndex, key: &str) -> (Format, Vec<u8>) {
    let head = state_v2::load_head(index, key, Codex::REDUCTION_REVISION)
        .unwrap()
        .expect("committed Codex Tail head");
    assert!(!head.metadata_only);
    let mut accumulator = SnapshotAccumulator::new(SOURCE);
    Codex::decode_head(head.revision, &head.body, &mut accumulator).unwrap();
    let (mut facts, mut prelude) = (BTreeMap::new(), Vec::new());
    state_v2::load_tail(index, key, &head, |collection, page, bytes| {
        Codex::decode_page(collection, page, &bytes, &mut accumulator).unwrap();
        if collection == Collection::SessionFacts {
            let mut fact = Dec::new(&bytes);
            assert_eq!(fact.varint().unwrap(), page);
            facts.insert(page, fact.varint().unwrap());
            if page == PRELUDE {
                prelude = bytes;
            }
        }
        Ok(())
    })
    .unwrap();
    let format = Format {
        revision: head.revision,
        facts,
    };
    (format, prelude)
}

/// Restage `path`'s committed reduction with its prelude fact as version 2:
/// the version 1 fields, then `sealed`. This build decodes it as it would
/// any later build's sealed start; nothing is read from the transcript.
fn seal(index: &ScanIndex, path: &Path, root: &Path, sealed: &[u8]) {
    let key = local_index_key(path);
    let route = state_v2::tail_route_path(index).unwrap().unwrap();
    let head = state_v2::load_head(index, &key, Codex::REDUCTION_REVISION)
        .unwrap()
        .unwrap();
    let mut accumulator = SnapshotAccumulator::new(SOURCE);
    let decoded = Codex::decode_head(head.revision, &head.body, &mut accumulator).unwrap();
    let capture = HeadIdentity::take(&mut Dec::new(&head.body))
        .unwrap()
        .capture;
    let mut written = None;
    state_v2::load_tail(index, &key, &head, |collection, page, mut bytes| {
        if collection == Collection::SessionFacts && page == PRELUDE {
            assert_eq!(
                bytes[..2],
                [5, 1],
                "this build writes sealed Codex starts itself: seal the fixture's \
                 starts natively and drop this splice"
            );
            bytes[1] = 2;
            bytes.extend_from_slice(sealed);
            written = Some(bytes.clone());
        }
        Codex::decode_page(collection, page, &bytes, &mut accumulator).unwrap();
        Ok(())
    })
    .unwrap();
    let written = written.expect("a Codex prelude fact");
    let view = PreFinalization::new(&accumulator, &decoded.report, decoded.scalars);
    let staged = TailBase::default()
        .stage::<Codex>(
            &view,
            &decoded.certificate,
            &HeadIdentity::new(&route, SOURCE, root, path, capture),
            Change::Reset,
        )
        .unwrap()
        .unwrap();
    assert_eq!(
        staged.pages[&(Collection::SessionFacts, PRELUDE)],
        written,
        "the sealed start restages byte for byte"
    );
    state_v2::stage_tail(&route, &key, staged).unwrap();
}

#[test]
#[ignore = "run by the historical carry harness"]
fn write_codex_per_file_carry_fixture() {
    let dir = carry_dir();
    let support = dir.join("support");
    let parent = support.join("snapshots/destinations").join("a".repeat(64));
    fs::create_dir_all(&parent).unwrap();
    let corpus_root = dir.join("sessions");
    fs::create_dir(&corpus_root).unwrap();
    let len_prefixed =
        |bytes: &[u8]| Enc::count_write(usize::MAX, |e| e.len_prefixed(bytes)).unwrap();
    let token_state = len_prefixed(b"token state");
    let extension = SessionStartState::codex_start_extension_for_test;
    // Each file: its session, closed turns, whether it grows before the
    // previous release runs, and its sealed start. One grown file's start is
    // sealed at a layout this build does not know, the other's with a proven
    // request-1 breakdown; the quiet file's has no proven breakdown.
    let files = [
        (
            GROWN,
            3,
            true,
            extension(2, 1, 2, None, b"what a later layout appends"),
        ),
        (
            PROVEN,
            3,
            true,
            extension(1, 1, 1, Some((7, 3, Some(2), None)), &token_state),
        ),
        (QUIET, 2, false, extension(1, 1, 2, None, &token_state)),
    ];
    let (mut tail_keys, mut turns, mut sealed, mut growing) =
        (Vec::new(), BTreeMap::new(), BTreeMap::new(), Vec::new());
    for (session, count, grows, start) in files {
        let key = local_index_key(&write_rollout(&corpus_root, session, count));
        turns.insert(key.clone(), count);
        sealed.insert(key.clone(), len_prefixed(&start));
        if grows {
            growing.push(key.clone());
        }
        tail_keys.push(key);
    }
    let mut manifest = Manifest {
        index_path: parent.join("codex-test-scan-index.json"),
        control_key: local_index_key(&rollout(&corpus_root, CONTROL)),
        turns,
        tail_keys,
        corpus_root,
        support,
        sealed,
    };
    let index =
        ScanIndex::load_for_snapshot_source(&manifest.index_path, SOURCE, &manifest.support)
            .unwrap();
    assert!(state_v2::published(&manifest.index_path).unwrap());
    let mut index = scan_and_save(&E2ScanFixture::default(), &manifest, index);
    for key in &manifest.tail_keys {
        seal(
            &index,
            Path::new(key),
            &manifest.corpus_root,
            &manifest.sealed[key],
        );
    }
    index.save(&manifest.index_path).unwrap();
    let formats: BTreeMap<_, _> = manifest
        .tail_keys
        .iter()
        .map(|key| {
            let (format, prelude) = stored(&index, key);
            assert_eq!(format.facts.get(&PRELUDE), Some(&2), "{format:?}");
            assert!(
                prelude.ends_with(&manifest.sealed[key]),
                "the sealed start is stored"
            );
            (key.clone(), format)
        })
        .collect();
    state_v2::clean_checkpoint_for_test(&index);

    for key in &growing {
        grow(&mut manifest, key);
    }
    // A fresh file proves collection can progress past every held file.
    write_rollout(&manifest.corpus_root, CONTROL, 2);
    fs::write(
        dir.join("manifest.json"),
        serde_json::to_vec(&manifest).unwrap(),
    )
    .unwrap();
    fs::write(
        dir.join("formats.json"),
        serde_json::to_vec(&formats).unwrap(),
    )
    .unwrap();
    println!("CODEX_PER_FILE_CARRY_FIXTURE_WRITTEN");
}

#[test]
#[ignore = "run by the historical carry harness"]
fn verify_codex_per_file_carry_reupgrade() {
    let dir = carry_dir();
    let mut manifest: Manifest =
        serde_json::from_slice(&fs::read(dir.join("manifest.json")).unwrap()).unwrap();
    let formats: BTreeMap<String, Format> =
        serde_json::from_slice(&fs::read(dir.join("formats.json")).unwrap()).unwrap();
    let held: Vec<String> =
        serde_json::from_slice(&fs::read(dir.join("held.json")).unwrap()).unwrap();
    let index = ScanIndex::load(&manifest.index_path).unwrap();
    // The previous release kept every sealed start, whether it held the file
    // or read it on.
    for key in &manifest.tail_keys {
        let (format, prelude) = stored(&index, key);
        assert_eq!(
            format.facts.get(&PRELUDE),
            Some(&2),
            "{key}: prelude fact version"
        );
        assert!(
            prelude.ends_with(&manifest.sealed[key]),
            "Codex (sealed start, {key}): the previous release dropped or changed a sealed \
             Codex start extension"
        );
    }
    let mut continuations = BTreeMap::new();
    for key in held {
        assert_eq!(
            stored(&index, &key).0,
            formats[&key],
            "Codex Tail format changed during downgrade"
        );
        let offset = tail_source::committed_sealed_offset(SOURCE, &index, &key)
            .expect("target reads the committed Codex Tail checkpoint");
        continuations.insert(key, Some(offset));
    }
    if continuations.is_empty() {
        continuations.insert(manifest.tail_keys[0].clone(), None);
    }
    // Grow even a quiet held file so this pass must continue its Tail.
    for key in continuations.keys() {
        grow(&mut manifest, key);
    }
    let scanner = E2ScanFixture::default();
    let index = scan_and_save(&scanner, &manifest, index);
    assert!(
        index.files.contains_key(&manifest.control_key),
        "control file was not collected"
    );
    let acquisitions = scanner.acquisitions.lock().unwrap();
    for (key, offset) in continuations {
        let path = Path::new(&key);
        if let Some(offset) = offset {
            assert!(
                acquisitions.iter().any(|read| {
                    read.path == path && matches!(read.mode, ReadMode::Tail) && read.start == offset
                }),
                "target did not resume the held Codex Tail checkpoint"
            );
        }
        assert_eq!(
            tail_source::committed_sealed_offset(SOURCE, &index, &key),
            Some(fs::metadata(path).unwrap().len()),
            "target did not commit the appended suffix"
        );
    }
    for key in &manifest.tail_keys {
        assert!(
            stored(&index, key).1.ends_with(&manifest.sealed[key]),
            "the target dropped a sealed Codex start"
        );
    }
    println!("CODEX_PER_FILE_CARRY_REUPGRADE_VERIFIED");
}
