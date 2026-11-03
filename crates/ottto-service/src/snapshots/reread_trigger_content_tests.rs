// The re-read rule at the real scan seam, for Claude and Codex: only
// content (size, mtime, sampled bytes) or output-relevant inputs may trigger
// a re-read. ctime-only changes (xattr, mode, hard link) are cross-checks
// that re-validate the bounded content samples and never read the file
// again on their own. mtime stays a trigger: it moves only on content
// writes, including a truncate/regrow the samples cannot see. A new object
// (device, inode, birth) is output-relevant: the parse consumes it. All
// fixtures are synthetic and content-free.
use super::*;
use std::io::{Seek, SeekFrom, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};

const CLAUDE_LINE: &str = "{\"type\":\"assistant\",\"sessionId\":\"019e2700-5555-7000-9000-555555555555\",\"uuid\":\"019e2700-5555-7000-9000-5555555555a1\",\"timestamp\":\"2026-07-22T08:00:01Z\",\"cwd\":\"/tmp/ottto\",\"message\":{\"id\":\"msg_1\",\"model\":\"claude-sonnet-4-6\",\"usage\":{\"input_tokens\":12,\"output_tokens\":4,\"cache_read_input_tokens\":0,\"cache_creation_input_tokens\":0}}}\n";
const CLAUDE_APPEND: &str = "{\"type\":\"assistant\",\"sessionId\":\"019e2700-5555-7000-9000-555555555555\",\"uuid\":\"019e2700-5555-7000-9000-5555555555a2\",\"timestamp\":\"2026-07-22T08:00:02Z\",\"cwd\":\"/tmp/ottto\",\"message\":{\"id\":\"msg_2\",\"model\":\"claude-sonnet-4-6\",\"usage\":{\"input_tokens\":7,\"output_tokens\":3,\"cache_read_input_tokens\":0,\"cache_creation_input_tokens\":0}}}\n";
const CLAUDE_MIDDLE: &str = "{\"type\":\"assistant\",\"sessionId\":\"019e2700-5555-7000-9000-555555555555\",\"uuid\":\"019e2700-5555-7000-9000-5555555555a3\",\"timestamp\":\"2026-07-22T08:00:01.500Z\",\"cwd\":\"/tmp/ottto\",\"message\":{\"id\":\"msg_3\",\"model\":\"claude-sonnet-4-6\",\"usage\":{\"input_tokens\":21,\"output_tokens\":5,\"cache_read_input_tokens\":0,\"cache_creation_input_tokens\":0}}}\n";
const CODEX_HEADER: &str = "{\"timestamp\":\"2026-07-22T08:00:00Z\",\"type\":\"session_meta\",\"payload\":{\"id\":\"019e253c-aaaa-7000-9000-aaaaaaaaaaaa\"}}\n";
const CODEX_USAGE: &str = "{\"timestamp\":\"2026-07-22T08:00:01Z\",\"type\":\"event_msg\",\"payload\":{\"type\":\"token_count\",\"info\":{\"total_token_usage\":{\"input_tokens\":12,\"output_tokens\":4},\"model\":\"gpt-5.5\"}}}\n";
const CODEX_APPEND: &str = "{\"timestamp\":\"2026-07-22T08:00:02Z\",\"type\":\"event_msg\",\"payload\":{\"type\":\"token_count\",\"info\":{\"total_token_usage\":{\"input_tokens\":19,\"output_tokens\":7},\"model\":\"gpt-5.5\"}}}\n";

struct Fixture {
    source: SnapshotSource,
    home: PathBuf,
    root: PathBuf,
    path: PathBuf,
    index: ScanIndex,
    minute: u32,
}

impl Fixture {
    /// One transcript, read once and settled: the next scan reads nothing.
    fn settled(source: SnapshotSource, name: &str, body: &[u8]) -> Self {
        let home = temp_dir(&format!("reread-{name}"));
        let root = home.join("transcripts");
        fs::create_dir_all(&root).expect("create root");
        let path = match source {
            SnapshotSource::Codex => {
                root.join("rollout-2026-07-22T08-00-00-019e253c-aaaa-7000-9000-aaaaaaaaaaaa.jsonl")
            }
            _ => root.join("019e2700-5555-7000-9000-555555555555.jsonl"),
        };
        fs::write(&path, body).expect("write fixture");
        let mut fixture = Self {
            source,
            home,
            root,
            path,
            index: ScanIndex::default(),
            minute: 2,
        };
        assert_eq!(fixture.rescan(), 1, "{name}: first scan reads the file");
        // The daemon persists the index as JSON; the stored ctime round-trips.
        let changed = fixture.entry().opened_changed_nanos;
        assert_ne!(changed, 0, "{name}: the read stores its opened ctime");
        let reloaded: ScanIndexEntry =
            serde_json::from_value(serde_json::to_value(fixture.entry()).expect("encode"))
                .expect("decode");
        assert_eq!(
            reloaded.opened_changed_nanos, changed,
            "{name}: stored ctime round-trip"
        );
        assert_eq!(fixture.rescan(), 0, "{name}: unchanged control rescan");
        fixture
    }

    /// One scan plus the post-upload settle; returns the files read.
    fn rescan(&mut self) -> usize {
        let collected_at = format!("2026-07-22T08:{:02}:00Z", self.minute);
        self.minute += 1;
        let mut result = scan_source_roots_with_limit(
            self.source,
            std::slice::from_ref(&self.root),
            &mut self.index,
            &collected_at,
            BACKFILL_WINDOW_DAYS,
            MAX_BACKFILL_FILES_PER_SOURCE,
        )
        .expect("scan");
        finalize_scan_after_policy(self.source, &mut result, &mut self.index);
        result.scanned_file_count
    }

    fn entry(&self) -> &ScanIndexEntry {
        &self.index.files[&local_index_key(&self.path)]
    }

    fn fingerprint(&self) -> String {
        self.entry().source_file_fingerprint.clone()
    }

    fn metadata(&self) -> fs::Metadata {
        fs::metadata(&self.path).expect("stat fixture")
    }

    fn modified(&self) -> SystemTime {
        self.metadata().modified().expect("mtime")
    }

    fn set_modified(&self, modified: SystemTime) {
        fs::OpenOptions::new()
            .write(true)
            .open(&self.path)
            .and_then(|file| file.set_modified(modified))
            .expect("set mtime");
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.home);
    }
}

fn ctime(metadata: &fs::Metadata) -> (i64, i64) {
    (metadata.ctime(), metadata.ctime_nsec())
}

/// Wait long enough that the next inode change gets a distinct ctime.
fn tick() {
    std::thread::sleep(std::time::Duration::from_millis(20));
}

fn sources() -> [(SnapshotSource, &'static str, Vec<u8>); 2] {
    [
        (
            SnapshotSource::ClaudeCode,
            "claude",
            CLAUDE_LINE.as_bytes().to_vec(),
        ),
        (
            SnapshotSource::Codex,
            "codex",
            format!("{CODEX_HEADER}{CODEX_USAGE}").into_bytes(),
        ),
    ]
}

/// Best-effort extended attribute; `false` when the filesystem refuses.
fn set_test_xattr(path: &Path) -> bool {
    use std::os::unix::ffi::OsStrExt;
    let Ok(path) = std::ffi::CString::new(path.as_os_str().as_bytes()) else {
        return false;
    };
    let value = b"1";
    #[cfg(target_os = "macos")]
    let status = unsafe {
        libc::setxattr(
            path.as_ptr(),
            c"com.ottto.reread-test".as_ptr(),
            value.as_ptr().cast(),
            value.len(),
            0,
            0,
        )
    };
    #[cfg(target_os = "linux")]
    let status = unsafe {
        libc::setxattr(
            path.as_ptr(),
            c"user.ottto_reread_test".as_ptr(),
            value.as_ptr().cast(),
            value.len(),
            0,
        )
    };
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    let status = {
        let _ = (path, value);
        -1
    };
    status == 0
}

#[test]
fn metadata_only_changes_never_trigger_a_reread() {
    for (source, name, body) in sources() {
        let mut fixture = Fixture::settled(source, name, &body);
        let stored = fixture.fingerprint();

        // Permission/mode flip: ctime moves, content does not.
        let before = ctime(&fixture.metadata());
        tick();
        let mode = fixture.metadata().permissions().mode();
        fs::set_permissions(&fixture.path, fs::Permissions::from_mode(mode ^ 0o004))
            .expect("chmod");
        assert_ne!(
            ctime(&fixture.metadata()),
            before,
            "{name}: chmod moved ctime"
        );
        assert_eq!(fixture.rescan(), 0, "{name}: mode flip reads nothing");
        assert_eq!(fixture.fingerprint(), stored, "{name}: mode flip");

        // Extended attribute (Spotlight, quarantine, backup tags).
        let before = ctime(&fixture.metadata());
        tick();
        if set_test_xattr(&fixture.path) {
            assert_ne!(
                ctime(&fixture.metadata()),
                before,
                "{name}: xattr moved ctime"
            );
            assert_eq!(fixture.rescan(), 0, "{name}: xattr reads nothing");
            assert_eq!(fixture.fingerprint(), stored, "{name}: xattr");
        }

        // A hard link elsewhere (backup/sync tools) moves ctime and nlink.
        let before = ctime(&fixture.metadata());
        tick();
        fs::hard_link(&fixture.path, fixture.home.join("backup-link")).expect("hard link");
        assert_ne!(
            ctime(&fixture.metadata()),
            before,
            "{name}: link moved ctime"
        );
        assert_eq!(fixture.rescan(), 0, "{name}: hard link reads nothing");
        assert_eq!(fixture.fingerprint(), stored, "{name}: hard link");
    }
}

/// Same bytes under a new inode: the samples re-validate, but the object's
/// device, inode and birth time are parse inputs (Claude request births and
/// money birth cutoffs, Codex created-thread matching; see
/// `e2_pipeline_inode_replacement_matches_full`), so it is read exactly once
/// and then settles. Never a loop.
#[test]
fn same_bytes_under_a_new_inode_read_once_for_its_object_inputs() {
    for (source, name, body) in sources() {
        for preserve_mtime in [false, true] {
            let mut fixture =
                Fixture::settled(source, &format!("{name}-inode-{preserve_mtime}"), &body);
            let stored = fixture.fingerprint();
            let original = fixture.metadata();
            let modified = fixture.modified();
            tick();
            // Atomic same-bytes replacement (restore, sync, editor save).
            let staged = fixture.home.join("staged-copy");
            fs::copy(&fixture.path, &staged).expect("copy");
            if preserve_mtime {
                fs::OpenOptions::new()
                    .write(true)
                    .open(&staged)
                    .and_then(|file| file.set_modified(modified))
                    .expect("preserve mtime");
            }
            fs::rename(staged, &fixture.path).expect("replace");
            let replaced = fixture.metadata();
            assert_ne!(
                (original.dev(), original.ino()),
                (replaced.dev(), replaced.ino()),
                "{name}: the copy is a new inode"
            );
            assert_eq!(
                fixture.rescan(),
                1,
                "{name} (preserve mtime {preserve_mtime}): new object is read once"
            );
            assert_ne!(fixture.fingerprint(), stored, "{name}: new object");
            assert_ne!(
                fixture.entry().opened_changed_nanos,
                0,
                "{name}: the read stores the ctime its fingerprint used"
            );
            assert_eq!(fixture.rescan(), 0, "{name}: then settled, no loop");
            // A ctime-only change on the new object reads nothing.
            tick();
            let mode = fixture.metadata().permissions().mode();
            fs::set_permissions(&fixture.path, fs::Permissions::from_mode(mode ^ 0o004))
                .expect("chmod");
            assert_eq!(fixture.rescan(), 0, "{name}: chmod after replace");
        }
    }
}

#[test]
fn real_content_changes_are_reread() {
    for (source, name, body) in sources() {
        // Append: size moves.
        let mut fixture = Fixture::settled(source, &format!("{name}-append"), &body);
        let stored = fixture.fingerprint();
        tick();
        fs::OpenOptions::new()
            .append(true)
            .open(&fixture.path)
            .and_then(|mut file| {
                file.write_all(match source {
                    SnapshotSource::Codex => CODEX_APPEND.as_bytes(),
                    _ => CLAUDE_APPEND.as_bytes(),
                })
            })
            .expect("append");
        assert_eq!(fixture.rescan(), 1, "{name}: append is re-read");
        assert_ne!(fixture.fingerprint(), stored, "{name}: append");
        assert_eq!(fixture.rescan(), 0, "{name}: settled after the append");

        // Touch: an explicit content-time change is re-read, then settles.
        let stored = fixture.fingerprint();
        tick();
        fixture.set_modified(SystemTime::now() + std::time::Duration::from_secs(5));
        assert_eq!(fixture.rescan(), 1, "{name}: touch is re-read");
        assert_ne!(fixture.fingerprint(), stored, "{name}: touch");
        assert_eq!(fixture.rescan(), 0, "{name}: settled after the touch");

        // Same-size edit inside the sampled bytes, mtime restored: the
        // content samples differ, so the cross-check reads.
        let mut fixture = Fixture::settled(source, &format!("{name}-edit"), &body);
        let stored = fixture.fingerprint();
        let modified = fixture.modified();
        tick();
        let edited = String::from_utf8(body.clone())
            .expect("utf8 fixture")
            .replacen("\"input_tokens\":12", "\"input_tokens\":13", 1);
        assert_eq!(edited.len(), body.len());
        fs::OpenOptions::new()
            .write(true)
            .open(&fixture.path)
            .and_then(|mut file| file.write_all(edited.as_bytes()))
            .expect("same-size edit");
        fixture.set_modified(modified);
        assert_eq!(fixture.metadata().len(), body.len() as u64);
        assert_eq!(fixture.rescan(), 1, "{name}: same-size edit is re-read");
        assert_ne!(fixture.fingerprint(), stored, "{name}: same-size edit");
    }
}

/// A ctime mismatch is a cross-check that runs only the bounded
/// content-sample re-validation. A rewrite outside the head/tail samples
/// with size and mtime restored is invisible to it, by design: the parse
/// path's TOCTOU check still compares the live opened identity (which moves;
/// see `opened_object_identity_moves_on_middle_rewrite_with_size_and_mtime_restored`).
#[test]
fn ctime_mismatch_revalidates_samples_without_a_full_read() {
    for (source, name, head) in sources() {
        let padding_line = format!(
            "{{\"type\":\"ottto_reread_padding\",\"pad\":\"{}\"}}\n",
            "a".repeat(3 * FILE_CONTENT_SAMPLE_BYTES)
        );
        let tail = match source {
            SnapshotSource::Codex => CODEX_APPEND,
            _ => CLAUDE_APPEND,
        };
        let mut body = head.clone();
        body.extend_from_slice(padding_line.as_bytes());
        body.extend_from_slice(tail.as_bytes());
        let mut fixture = Fixture::settled(source, &format!("{name}-middle"), &body);
        let stored = fixture.fingerprint();
        let modified = fixture.modified();
        let before = ctime(&fixture.metadata());
        tick();
        let middle = (body.len() / 2) as u64;
        assert!(middle > FILE_CONTENT_SAMPLE_BYTES as u64);
        assert!(middle + 1 < body.len() as u64 - FILE_CONTENT_SAMPLE_BYTES as u64);
        let mut file = fs::OpenOptions::new()
            .write(true)
            .open(&fixture.path)
            .expect("open for middle rewrite");
        file.seek(SeekFrom::Start(middle)).expect("seek middle");
        file.write_all(b"b").expect("middle rewrite");
        drop(file);
        fixture.set_modified(modified);
        assert_ne!(ctime(&fixture.metadata()), before, "{name}: ctime moved");
        assert_eq!(fixture.rescan(), 0, "{name}: samples match, no Full read");
        assert_eq!(fixture.fingerprint(), stored, "{name}: middle rewrite");
    }
}

/// A truncate/regrow on the same inode to the same length, leaving the
/// first and last 4 KiB byte-identical but changing a usage row in between,
/// with its natural mtime: the samples cannot see it, mtime does. Re-read.
#[test]
fn truncate_regrow_with_unchanged_samples_is_reread_by_mtime() {
    for (source, name, _) in sources() {
        let padding = format!(
            "{{\"type\":\"ottto_reread_padding\",\"pad\":\"{}\"}}\n",
            "a".repeat(FILE_CONTENT_SAMPLE_BYTES + 512)
        );
        let (head, middle, edited, tail) = match source {
            SnapshotSource::Codex => (
                CODEX_HEADER.to_string(),
                CODEX_USAGE.replace("\"input_tokens\":12", "\"input_tokens\":15"),
                CODEX_USAGE.replace("\"input_tokens\":12", "\"input_tokens\":16"),
                CODEX_APPEND,
            ),
            _ => (
                CLAUDE_LINE.to_string(),
                CLAUDE_MIDDLE.to_string(),
                CLAUDE_MIDDLE.replace("\"input_tokens\":21", "\"input_tokens\":22"),
                CLAUDE_APPEND,
            ),
        };
        let body = format!("{head}{padding}{middle}{padding}{tail}");
        let regrown = format!("{head}{padding}{edited}{padding}{tail}");
        assert_eq!(body.len(), regrown.len());
        assert_ne!(body, regrown);
        let mut fixture = Fixture::settled(source, &format!("{name}-regrow"), body.as_bytes());
        let stored = fixture.fingerprint();
        let original = fixture.metadata();
        tick();
        // `File::create` truncates the same inode, then regrows it.
        fs::File::create(&fixture.path)
            .and_then(|mut file| file.write_all(regrown.as_bytes()))
            .expect("truncate and regrow");
        let regrown_metadata = fixture.metadata();
        assert_eq!(
            (original.dev(), original.ino(), original.len()),
            (
                regrown_metadata.dev(),
                regrown_metadata.ino(),
                regrown_metadata.len()
            ),
            "{name}: same object and length"
        );
        let sample = FILE_CONTENT_SAMPLE_BYTES;
        assert_eq!(body.as_bytes()[..sample], regrown.as_bytes()[..sample]);
        assert_eq!(
            body.as_bytes()[body.len() - sample..],
            regrown.as_bytes()[regrown.len() - sample..]
        );
        assert_eq!(fixture.rescan(), 1, "{name}: truncate/regrow is re-read");
        assert_ne!(fixture.fingerprint(), stored, "{name}: truncate/regrow");
        assert_eq!(fixture.rescan(), 0, "{name}: then settled");
    }
}

/// The live file birth (unix nanos). APFS and ext4 (the CI file systems)
/// report it; `money_birth_is_the_open_time_read_shared_with_the_birth_rule`
/// relies on the same.
fn birth_nanos(metadata: &fs::Metadata) -> u64 {
    metadata
        .created()
        .ok()
        .and_then(unix_nanos)
        .expect("the test file system must report file birth")
}

const TWO_HOURS_NANOS: u64 = 2 * 3600 * 1_000_000_000;

/// Moves ctime only: a mode flip.
fn chmod_flip(path: &Path) {
    let before = ctime(&fs::metadata(path).expect("stat"));
    tick();
    let mode = fs::metadata(path).expect("stat").permissions().mode();
    fs::set_permissions(path, fs::Permissions::from_mode(mode ^ 0o004)).expect("chmod");
    assert_ne!(
        ctime(&fs::metadata(path).expect("stat")),
        before,
        "ctime moved"
    );
}

/// A stored ctime binds only to its own object generation.
/// The stored entry models an earlier object A on the same device and inode
/// (deleted, the inode reused for B after a clock rollback): same bytes, the
/// same preserved mtime and a stored ctime not before B's birth (so ordering
/// against ctime would accept B), but another birth. A later live ctime on B
/// (chmod) must read B, never adopt A's ctime.
#[test]
fn reused_inode_with_an_unequal_birth_is_read() {
    for (source, name, body) in sources() {
        for earlier in [true, false] {
            let mut fixture =
                Fixture::settled(source, &format!("{name}-reused-birth-{earlier}"), &body);
            let stored = fixture.fingerprint();
            let modified = fixture.modified();
            let live_birth = birth_nanos(&fixture.metadata());
            let key = local_index_key(&fixture.path);
            let entry = fixture.index.files.get_mut(&key).expect("entry");
            assert_eq!(
                entry.opened_birth_nanos, live_birth,
                "{name}: the read stores its birth"
            );
            assert!(
                entry.opened_changed_nanos >= live_birth,
                "{name}: rollback shape: stored ctime not before the live birth"
            );
            entry.opened_birth_nanos = if earlier {
                live_birth - TWO_HOURS_NANOS
            } else {
                live_birth + 1
            };
            chmod_flip(&fixture.path);
            assert_eq!(fixture.modified(), modified, "{name}: preserved mtime");
            assert_eq!(fixture.rescan(), 1, "{name}: another birth is read");
            assert_ne!(fixture.fingerprint(), stored, "{name}: live ctime used");
            assert_eq!(
                fixture.entry().opened_birth_nanos,
                live_birth,
                "{name}: the read binds the live birth"
            );
            assert_eq!(fixture.rescan(), 0, "{name}: then settled");
            // Bound to B now: its own later ctime-only change reads nothing.
            chmod_flip(&fixture.path);
            assert_eq!(fixture.rescan(), 0, "{name}: chmod on the bound object");
        }
    }
}

/// An unavailable birth, stored (older entries, file systems without birth)
/// or live, never adopts a stored ctime: the normal path reads.
#[test]
fn unavailable_birth_never_adopts_a_stored_ctime() {
    for (source, name, body) in sources() {
        // Stored birth unavailable.
        let mut fixture = Fixture::settled(source, &format!("{name}-no-birth"), &body);
        let stored = fixture.fingerprint();
        let live_birth = birth_nanos(&fixture.metadata());
        let key = local_index_key(&fixture.path);
        fixture
            .index
            .files
            .get_mut(&key)
            .expect("entry")
            .opened_birth_nanos = 0;
        chmod_flip(&fixture.path);
        assert_eq!(fixture.rescan(), 1, "{name}: no stored birth is read");
        assert_ne!(fixture.fingerprint(), stored, "{name}: live ctime used");
        assert_eq!(fixture.entry().opened_birth_nanos, live_birth);
        assert_eq!(fixture.rescan(), 0, "{name}: then settled");

        // Live birth unavailable, at the adoption seam itself.
        chmod_flip(&fixture.path);
        let mut candidate = CandidateFile {
            physical_identity: None,
            scan_root: fixture.root.clone(),
            path: fixture.path.clone(),
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
        };
        let (mut file, live) = open_candidate_file_stat(source, &mut candidate).expect("open");
        let live = live.expect("unix object stat");
        let stored_changed = fixture.entry().opened_changed_nanos;
        assert_ne!(
            live.changed_unix_nanos(),
            stored_changed,
            "{name}: ctime moved"
        );
        // Control: the same birth adopts the stored ctime.
        let mut bound = candidate.clone();
        assert!(
            adopt_stored_changed_time(&mut bound, &fixture.index.files, Some(live), &mut file)
                .expect("adopt")
                .is_some(),
            "{name}: an equal known birth adopts"
        );
        assert_eq!(bound.fingerprint_changed_nanos, stored_changed);
        let unbound = OpenedObjectStat {
            birth_nanos: None,
            ..live
        };
        assert_eq!(
            adopt_stored_changed_time(
                &mut candidate,
                &fixture.index.files,
                Some(unbound),
                &mut file
            )
            .expect("adopt"),
            None,
            "{name}: no live birth never adopts"
        );
        assert_eq!(
            candidate.fingerprint_changed_nanos,
            live.changed_unix_nanos()
        );
        drop(file);
        assert_eq!(fixture.rescan(), 0, "{name}: the real scan still binds");
    }
}
