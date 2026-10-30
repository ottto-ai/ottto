//! Hash-pinned, test-only copies of old record writers.
//!
//! The transition seed checks a post-save artifact against one of these instead
//! of against current production source, so a later writer can change freely
//! without invalidating proof about bytes already on users' disks. Each archive
//! is one `w_<sha8>.rs` plus its `w_<sha8>_helpers.json`; adding one never touches
//! another. `transition_serializer_regions.py --archive <sha>` documents the
//! verification. The live-source check in `transition_seed.rs` is separate and
//! keeps following current code.
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::path::Path;

use sha2::{Digest, Sha256};

#[rustfmt::skip]
#[path = "w_53d05a43.rs"]
pub(crate) mod w_53d05a43;

pub(crate) use w_53d05a43::W_53d05a43;

const KNOWN_PINS: [&str; 1] = [W_53d05a43::PIN];

/// One copied source unit: `roots` select its regions, `sha256` pins their tokens.
pub(crate) struct Region {
    pub(crate) path: &'static str,
    pub(crate) roots: &'static [&'static str],
    pub(crate) sha256: &'static str,
}

/// Everything a v1 envelope records, free of current store types. `source_tag`
/// is the store's on-disk source byte.
#[derive(Clone)]
pub(crate) struct ArchivedRecord {
    pub(crate) source_tag: u8,
    pub(crate) key: [u8; 32],
    pub(crate) context: [u8; 32],
    pub(crate) scope: [u8; 32],
    pub(crate) entry: [u8; 32],
    pub(crate) allowlist: [u8; 32],
    pub(crate) generation: u64,
    pub(crate) device: u64,
    pub(crate) inode: u64,
    pub(crate) length: u64,
    pub(crate) modified: (i64, i64),
    pub(crate) birth_nanos: u64,
    pub(crate) sealed_offset: u64,
    pub(crate) sample_len: u32,
    pub(crate) head_sha256: [u8; 32],
    pub(crate) boundary_sha256: [u8; 32],
    pub(crate) verified_unix_seconds: u64,
    pub(crate) audit_debt: Option<u64>,
    pub(crate) body: Vec<u8>,
}

pub(crate) enum Golden {
    /// The whole record for an opaque body: framing only.
    Frame {
        record: Box<ArchivedRecord>,
        expected: Vec<u8>,
    },
    /// A body this writer must parse and re-emit byte for byte.
    Body { source_tag: u8, body: Vec<u8> },
}

pub(crate) trait ArchivedWriter {
    /// The full 40-hex commit the regions were copied from.
    const SOURCE_SHA: &'static str;
    /// The short name fixture rows select the writer by.
    const PIN: &'static str;
    const FORMAT: u16;
    fn regions() -> &'static [Region];
    /// The allowlist digest this writer stamps for a source.
    fn allowlist(source_tag: u8) -> Result<[u8; 32], String>;
    /// The body bytes this writer emits for a record, or why it never could.
    fn encode_body(source_tag: u8, body: &[u8]) -> Result<Vec<u8>, String>;
    /// Header, opaque body and trailer.
    fn frame(record: &ArchivedRecord) -> Result<Vec<u8>, String>;
    fn goldens() -> Vec<Golden>;

    fn encode(record: &ArchivedRecord) -> Result<Vec<u8>, String> {
        let mut framed = record.clone();
        framed.body = Self::encode_body(record.source_tag, &record.body)?;
        Self::frame(&framed)
    }
}

pub(crate) fn decode_hex(hex: &str) -> Vec<u8> {
    hex.as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

pub(crate) fn assert_archive_matches_goldens<W: ArchivedWriter>() {
    let goldens = W::goldens();
    assert!(!goldens.is_empty(), "{} has no goldens", W::PIN);
    for golden in goldens {
        match golden {
            Golden::Frame { record, expected } => {
                assert_eq!(W::allowlist(record.source_tag), Ok(record.allowlist));
                assert_eq!(W::frame(&record), Ok(expected));
            }
            Golden::Body { source_tag, body } => {
                assert_eq!(W::encode_body(source_tag, &body), Ok(body));
            }
        }
    }
}

#[derive(serde::Deserialize)]
struct ArchiveReport {
    archive: String,
    hashes: BTreeMap<String, String>,
    roots: BTreeMap<String, BTreeSet<String>>,
    references: BTreeSet<String>,
}

fn source_root() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src")
}

fn verify_archive_in(
    pin: &str,
    text_only: bool,
    overrides: &[(&str, &str)],
    root: &Path,
    directory: Option<&Path>,
) -> Result<ArchiveReport, String> {
    let mut args = vec![OsStr::new("--archive"), OsStr::new(pin)];
    if text_only {
        args.push(OsStr::new("--archive-text-only"));
    }
    let output = super::run_extractor(&args, overrides, OsStr::new("python3"), root, directory);
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).into_owned());
    }
    Ok(serde_json::from_slice(&output.stdout).expect("archive verification returned invalid JSON"))
}

/// Text-only verification: tests run on shallow checkouts without `SOURCE_SHA`.
fn verify_archive(pin: &str, overrides: &[(&str, &str)]) -> Result<ArchiveReport, String> {
    verify_archive_in(pin, true, overrides, &source_root(), None)
}

/// Refuse a writer the rows have no archive for, before touching any store.
pub(super) fn require_known(pin: &str) {
    assert!(KNOWN_PINS.contains(&pin), "unknown archived writer: {pin}");
}

/// Guard the seed calls first. It reads only the archive, so production source
/// changes cannot refuse an old writer; region edits and helper drift do.
pub(super) fn assert_provenance<W: ArchivedWriter>() {
    static VERIFIED: std::sync::Mutex<BTreeSet<&'static str>> =
        std::sync::Mutex::new(BTreeSet::new());
    let mut verified = VERIFIED.lock().unwrap();
    if verified.contains(W::SOURCE_SHA) {
        return;
    }
    let report = verify_archive(W::PIN, &[])
        .unwrap_or_else(|error| panic!("archived writer {} refused: {error}", W::PIN));
    assert_eq!(report.archive, W::SOURCE_SHA);
    let declared = W::regions()
        .iter()
        .map(|region| (region.path.to_string(), region.sha256.to_string()))
        .collect::<BTreeMap<_, _>>();
    assert_eq!(report.hashes, declared);
    let roots = W::regions()
        .iter()
        .map(|region| {
            let names = region.roots.iter().map(ToString::to_string).collect();
            (region.path.to_string(), names)
        })
        .collect::<BTreeMap<_, BTreeSet<_>>>();
    assert_eq!(report.roots, roots);
    verified.insert(W::SOURCE_SHA);
}

const ARCHIVE_PATH: &str = "snapshots/sampled_scan/archived_writers/w_53d05a43.rs";
const INVENTORY_PATH: &str = "snapshots/sampled_scan/archived_writers/w_53d05a43_helpers.json";
const ARCHIVE_TEXT: &str = include_str!("w_53d05a43.rs");
const INVENTORY_TEXT: &str = include_str!("w_53d05a43_helpers.json");
const SYNTHETIC_UNIT: &str = "durable_tail_codec.rs";
const SYNTHETIC_SOURCE: &str = "fn a() {}";

fn synthetic_tokens_sha256() -> String {
    let tokens = ["fn", "a", "(", ")", "{", "}"].join("\0");
    format!("{:x}", Sha256::digest(tokens.as_bytes()))
}

/// A second, minimal archive, in the same file form as a real one.
fn synthetic_archive(sha: &str, pinned: &str) -> String {
    format!(
        "const SOURCE_SHA: &str = \"{sha}\";\n\
         const ARCHIVE_ROOT: &str = \"crate::snapshots::w_{short}\";\n\
         const REGIONS: &[Region] = &[Region {{\n\
         path: \"{SYNTHETIC_UNIT}\",\n\
         roots: &[],\n\
         sha256: \"{pinned}\",\n\
         }}];\n\
         // archive-region: {SYNTHETIC_UNIT}\n\
         {SYNTHETIC_SOURCE}\n\
         // archive-region-end\n",
        short = &sha[..8],
    )
}

fn refusal(result: Result<ArchiveReport, String>) -> String {
    match result {
        Ok(report) => panic!("archive {} must be refused", report.archive),
        Err(error) => error,
    }
}

fn assert_text_edit_refused(before: &str, after: &str, expected: &str) {
    assert_eq!(ARCHIVE_TEXT.matches(before).count(), 1, "edit premise");
    let edited = ARCHIVE_TEXT.replacen(before, after, 1);
    let error = refusal(verify_archive(W_53d05a43::PIN, &[(ARCHIVE_PATH, &edited)]));
    assert!(error.contains(expected), "{error}");
}

#[test]
fn archived_writer_53d05a43_matches_its_goldens() {
    assert_archive_matches_goldens::<W_53d05a43>();
}

#[test]
fn archived_writer_provenance_accepts_the_pinned_archive() {
    assert_provenance::<W_53d05a43>();
    let report = verify_archive(W_53d05a43::SOURCE_SHA, &[]).unwrap();
    assert_eq!(report.archive.len(), 40);
    assert_eq!(report.archive, W_53d05a43::SOURCE_SHA);
    assert_eq!(report.hashes.len(), W_53d05a43::regions().len());
    let inventory: BTreeMap<String, String> = serde_json::from_str(INVENTORY_TEXT).unwrap();
    assert_eq!(
        report.references,
        inventory.into_keys().collect::<BTreeSet<_>>()
    );
}

#[test]
fn archived_writer_one_byte_region_edit_fails_provenance() {
    assert_text_edit_refused(
        "    0 => Codex,",
        "    9 => Codex,",
        "archive region does not match its pin: snapshots.rs",
    );
    // Frozen framing and field lists sit behind the same guard.
    assert_text_edit_refused(
        "*b\"ottto-dt\"",
        "*b\"ottto-du\"",
        "archive region does not match its pin: durable_tail_store.rs",
    );
    assert_text_edit_refused(
        "    H session_start: Option<[u8; 32]>,\n    H title",
        "    H session_start: Option<[u8; 33]>,\n    H title",
        "archive region does not match its pin: snapshots/sampled_jsonl/durable.rs",
    );
}

#[test]
fn archived_writer_pin_or_marker_tampering_fails_provenance() {
    let region = &W_53d05a43::regions()[0];
    let flipped = if region.sha256.starts_with('0') {
        "1"
    } else {
        "0"
    };
    let edited = format!("{flipped}{}", &region.sha256[1..]);
    assert_text_edit_refused(
        region.sha256,
        &edited,
        "archive region does not match its pin",
    );
    let unmarked = ARCHIVE_TEXT.replace("// archive-region: snapshots/context_curve.rs\n", "");
    let error = refusal(verify_archive(
        W_53d05a43::PIN,
        &[(ARCHIVE_PATH, &unmarked)],
    ));
    assert!(
        error.contains("unbalanced archive region markers"),
        "{error}"
    );
}

#[test]
fn archived_writer_unknown_sha_fails() {
    for pin in ["00000000", &"0".repeat(40), "53d05a4", ""] {
        let error = refusal(verify_archive_in(pin, true, &[], &source_root(), None));
        assert!(error.contains("unknown archived writer"), "{error}");
    }
}

#[test]
#[should_panic(expected = "unknown archived writer: 00000000")]
fn archived_writer_unknown_pin_panics_before_any_store_read() {
    require_known("00000000");
}

#[test]
fn archived_writer_second_archive_leaves_the_first_unchanged() {
    let before = verify_archive(W_53d05a43::PIN, &[]).unwrap();
    let sha = "0123abcd".repeat(5);
    let path = "snapshots/sampled_scan/archived_writers/w_0123abcd.rs";
    let inventory = "snapshots/sampled_scan/archived_writers/w_0123abcd_helpers.json";
    let archive = synthetic_archive(&sha, &synthetic_tokens_sha256());
    let overrides = [(path, archive.as_str()), (inventory, "{}")];
    let after = verify_archive(W_53d05a43::PIN, &overrides).unwrap();
    assert_eq!(after.hashes, before.hashes);
    assert_eq!(after.references, before.references);
    let second = verify_archive(&sha, &overrides).unwrap();
    assert_eq!(second.archive, sha);
    assert_eq!(
        second.hashes,
        BTreeMap::from([(SYNTHETIC_UNIT.to_string(), synthetic_tokens_sha256())])
    );
}

#[test]
fn archived_writer_cannot_reach_production_paths() {
    assert_text_edit_refused(
        "use sha2::{Digest, Sha256};\n\npub(crate) struct W_53d05a43;",
        "use crate::snapshots::SnapshotSource;\n\npub(crate) struct W_53d05a43;",
        "archive reaches outside itself",
    );
    assert_text_edit_refused(
        "use super::{decode_hex,",
        "use super::super::{decode_hex,",
        "archive reaches outside itself",
    );
}

#[test]
fn archived_writer_helper_inventory_change_fails() {
    let mut inventory: BTreeMap<String, String> = serde_json::from_str(INVENTORY_TEXT).unwrap();
    let dropped = inventory.keys().next().unwrap().clone();
    inventory.remove(&dropped);
    let edited = serde_json::to_string(&inventory).unwrap();
    let error = refusal(verify_archive(
        W_53d05a43::PIN,
        &[(INVENTORY_PATH, &edited)],
    ));
    assert!(
        error.contains("archive helper inventory changed"),
        "{error}"
    );
    let mut inventory: BTreeMap<String, String> = serde_json::from_str(INVENTORY_TEXT).unwrap();
    inventory.insert(dropped, "reviewed later".to_string());
    let edited = serde_json::to_string(&inventory).unwrap();
    let error = refusal(verify_archive(
        W_53d05a43::PIN,
        &[(INVENTORY_PATH, &edited)],
    ));
    assert!(error.contains("unreviewed archive helper"), "{error}");
}

#[test]
fn archived_writer_stays_out_of_the_live_catalog() {
    let live = super::extract_with_python(None);
    assert!(live
        .hashes
        .keys()
        .all(|path| !path.contains("archived_writers")));
}

#[test]
fn archived_writer_refuses_bytes_it_could_not_have_written() {
    let body = W_53d05a43::goldens()
        .into_iter()
        .find_map(|golden| match golden {
            Golden::Body {
                source_tag: 1,
                body,
            } => Some(body),
            _ => None,
        })
        .unwrap();
    assert_eq!(W_53d05a43::encode_body(1, &body).as_ref(), Ok(&body));
    let mut extended = body.clone();
    extended.push(0);
    assert!(W_53d05a43::encode_body(1, &extended).is_err());
    assert!(W_53d05a43::encode_body(1, &body[..body.len() - 1]).is_err());
    assert_eq!(
        W_53d05a43::encode_body(2, &body),
        Err("body belongs to another source".to_string())
    );
    assert!(W_53d05a43::encode_body(3, &body).is_err());
    assert!(W_53d05a43::allowlist(3).is_err());
}

#[test]
fn archived_writer_encode_frames_its_own_body() {
    let golden = W_53d05a43::goldens();
    let Golden::Frame { record, expected } = &golden[0] else {
        panic!("frame goldens come first");
    };
    let body = golden
        .iter()
        .find_map(|golden| match golden {
            Golden::Body { source_tag, body } if *source_tag == record.source_tag => Some(body),
            _ => None,
        })
        .unwrap();
    let mut with_body = record.clone();
    with_body.body = body.clone();
    let framed = W_53d05a43::encode(&with_body).unwrap();
    assert_eq!(W_53d05a43::frame(&with_body).unwrap(), framed);
    assert_eq!(&framed[..8], &expected[..8]);
    assert_eq!(
        u16::from_le_bytes(framed[8..10].try_into().unwrap()),
        W_53d05a43::FORMAT
    );
    let digest_at = framed.len() - 32;
    assert_eq!(
        &framed[digest_at..],
        Sha256::digest(&framed[..digest_at]).as_slice()
    );
    let mut opaque = record.clone();
    opaque.body = b"opaque-v1-body".to_vec();
    assert!(W_53d05a43::encode(&opaque).is_err());
}

struct SyntheticRepo(std::path::PathBuf);
impl SyntheticRepo {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "ottto-archived-writer-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(path.join("crates/ottto-service/src")).unwrap();
        let repo = Self(path);
        repo.git(&["init", "--quiet"]);
        repo
    }
    fn git(&self, args: &[&str]) -> String {
        let output = std::process::Command::new("git")
            .args([
                "-c",
                "user.name=fixture",
                "-c",
                "user.email=fixture@example.invalid",
                "-c",
                "commit.gpgsign=false",
            ])
            .args(args)
            .current_dir(&self.0)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .output()
            .expect("git is a test prerequisite");
        assert!(output.status.success(), "{args:?}: {output:?}");
        String::from_utf8(output.stdout).unwrap().trim().to_string()
    }
    fn commit(&self, source: &str) -> String {
        let unit = format!("crates/ottto-service/src/{SYNTHETIC_UNIT}");
        std::fs::write(self.0.join(&unit), source).unwrap();
        self.git(&["add", &unit]);
        self.git(&["commit", "--quiet", "--allow-empty", "-m", "unit"]);
        self.git(&["rev-parse", "HEAD"])
    }
    fn verify(&self, sha: &str, archive: &str) -> Result<ArchiveReport, String> {
        let short = &sha[..8];
        let path = format!("snapshots/sampled_scan/archived_writers/w_{short}.rs");
        let inventory = format!("snapshots/sampled_scan/archived_writers/w_{short}_helpers.json");
        std::fs::create_dir_all(
            self.0
                .join("crates/ottto-service/src/snapshots/sampled_scan/archived_writers"),
        )
        .unwrap();
        verify_archive_in(
            sha,
            false,
            &[(path.as_str(), archive), (inventory.as_str(), "{}")],
            &self.0.join("crates/ottto-service/src"),
            Some(&self.0),
        )
    }
}
impl Drop for SyntheticRepo {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn archived_writer_git_mode_compares_the_named_commit() {
    let repo = SyntheticRepo::new();
    let pinned = synthetic_tokens_sha256();
    let frozen = repo.commit(SYNTHETIC_SOURCE);
    let report = repo.verify(&frozen, &synthetic_archive(&frozen, &pinned));
    assert_eq!(report.unwrap().archive, frozen);
    // Same archive text and pin, but this commit's source says otherwise.
    let drifted = repo.commit("fn b() {}");
    let error = refusal(repo.verify(&drifted, &synthetic_archive(&drifted, &pinned)));
    assert!(
        error.contains("archive region differs from its commit"),
        "{error}"
    );
}
