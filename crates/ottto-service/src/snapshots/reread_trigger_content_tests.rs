// Ron's re-read rule at the real scan seam, for Claude and Codex: only
// content (size, sampled bytes) or output-relevant inputs may trigger a
// re-read. ctime, xattr, mode, hard-link and mtime flips are cross-checks
// that re-validate the bounded content samples and never read the file
// again on their own. A new object (device, inode, birth) is output-relevant:
// the parse consumes it. All fixtures are synthetic and content-free.
use super::*;
use std::io::{Seek, SeekFrom, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};

const CLAUDE_LINE: &str = "{\"type\":\"assistant\",\"sessionId\":\"019e2700-5555-7000-9000-555555555555\",\"uuid\":\"019e2700-5555-7000-9000-5555555555a1\",\"timestamp\":\"2026-07-22T08:00:01Z\",\"cwd\":\"/tmp/ottto\",\"message\":{\"id\":\"msg_1\",\"model\":\"claude-sonnet-4-6\",\"usage\":{\"input_tokens\":12,\"output_tokens\":4,\"cache_read_input_tokens\":0,\"cache_creation_input_tokens\":0}}}\n";
const CLAUDE_APPEND: &str = "{\"type\":\"assistant\",\"sessionId\":\"019e2700-5555-7000-9000-555555555555\",\"uuid\":\"019e2700-5555-7000-9000-5555555555a2\",\"timestamp\":\"2026-07-22T08:00:02Z\",\"cwd\":\"/tmp/ottto\",\"message\":{\"id\":\"msg_2\",\"model\":\"claude-sonnet-4-6\",\"usage\":{\"input_tokens\":7,\"output_tokens\":3,\"cache_read_input_tokens\":0,\"cache_creation_input_tokens\":0}}}\n";
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
        // The daemon persists the index as JSON; the witness round-trips.
        let witness = fixture.entry().opened_witness.clone();
        assert!(
            witness.is_some(),
            "{name}: the read stores its opened witness"
        );
        let reloaded: ScanIndexEntry =
            serde_json::from_value(serde_json::to_value(fixture.entry()).expect("encode"))
                .expect("decode");
        assert_eq!(
            reloaded.opened_witness, witness,
            "{name}: witness round-trip"
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
            true,
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

        // A touch moves mtime and ctime only.
        tick();
        fixture.set_modified(SystemTime::now() + std::time::Duration::from_secs(5));
        assert_eq!(fixture.rescan(), 0, "{name}: touch reads nothing");
        assert_eq!(fixture.fingerprint(), stored, "{name}: touch");
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
            assert_eq!(
                fixture.entry().opened_witness.as_ref().map(|w| w.inode),
                Some(replaced.ino()),
                "{name}: the read stores the live witness"
            );
            assert_eq!(fixture.rescan(), 0, "{name}: then settled, no loop");
            // A metadata-only change on the new object reads nothing.
            tick();
            fixture.set_modified(SystemTime::now() + std::time::Duration::from_secs(5));
            assert_eq!(fixture.rescan(), 0, "{name}: touch after replace");
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

/// Rule 3: a ctime mismatch is a cross-check that runs only the bounded
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
