//! On-demand support inspection only. Recovered rows never enter account/usage
//! readers, upload DTOs, the scanner, or a persistent store. Output is counters.
use super::*;
use ottto_protocol::RedactedValue;
use std::ffi::CString;
use std::io::{Read, Take};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::MetadataExt;

const MAX_FILES_PER_STORE: usize = 4;
const MAX_DIRECTORY_ENTRIES: usize = 64;
const MAX_BYTES_PER_FILE: u64 = 64 * 1024;
const MAX_LINE_BYTES: usize = 16 * 1024;
const MAX_ROWS_PER_FILE: usize = 128;
const PAGE_LINES: usize = 32;

#[derive(Default)]
struct Health {
    files: u64,
    missing_stores: u64,
    oversized_files: u64,
    malformed_lines: u64,
    oversized_lines: u64,
    unframed_lines: u64,
    invalid_rows: u64,
    conflicting_requests: u64,
    duplicate_rows: u64,
    unreadable_files: u64,
    changed_files: u64,
    limited_files: u64,
    available_rows: u64,
    bytes_read: u64,
    selection_limited: bool,
}

// Keep dedup/upgrade semantics from the typed API reader. Trace requests have
// no identity-upgrade exception. All retained maps are bounded by physical rows.
enum Rows {
    Api {
        rows: Vec<ClaudeLocalOtelEvidence>,
        seen: BTreeSet<String>,
        requests: BTreeMap<String, usize>,
    },
    Trace {
        rows: Vec<ClaudeTraceOwnershipEvidence>,
        seen: BTreeSet<String>,
        requests: BTreeMap<String, String>,
    },
}
impl Rows {
    fn new(trace: bool) -> Self {
        if trace {
            Self::Trace {
                rows: Vec::new(),
                seen: BTreeSet::new(),
                requests: BTreeMap::new(),
            }
        } else {
            Self::Api {
                rows: Vec::new(),
                seen: BTreeSet::new(),
                requests: BTreeMap::new(),
            }
        }
    }
    fn len(&self) -> usize {
        match self {
            Self::Api { rows, .. } => rows.len(),
            Self::Trace { rows, .. } => rows.len(),
        }
    }
    fn observe(&mut self, line: &[u8], file_digest: &str, health: &mut Health) {
        macro_rules! decode {
            ($ty:ty) => {
                match serde_json::from_slice::<$ty>(line) {
                    Ok(row) => row,
                    Err(_) => {
                        health.malformed_lines += 1;
                        return;
                    }
                }
            };
        }
        match self {
            Self::Api {
                rows,
                seen,
                requests,
            } => {
                let row = decode!(ClaudeLocalOtelEvidence);
                let mut canonical = row.clone();
                canonical.fingerprint.clear();
                if !valid_row(
                    &row.session_id,
                    &row.request_id,
                    &row.observed_at,
                    &row.capture_revision,
                    API_REQUEST_CAPTURE_REVISION,
                    &row.fingerprint,
                    &canonical,
                    file_digest,
                ) {
                    health.invalid_rows += 1;
                    return;
                }
                let before = rows.len();
                if append_request_evidence(rows, seen, requests, row) {
                    health.conflicting_requests += 1;
                }
                if rows.len() == before {
                    health.duplicate_rows += 1;
                }
            }
            Self::Trace {
                rows,
                seen,
                requests,
            } => {
                let row = decode!(ClaudeTraceOwnershipEvidence);
                let mut canonical = row.clone();
                canonical.fingerprint.clear();
                if !valid_row(
                    &row.session_id,
                    &row.request_id,
                    &row.observed_at,
                    &row.capture_revision,
                    TRACE_OWNERSHIP_CAPTURE_REVISION,
                    &row.fingerprint,
                    &canonical,
                    file_digest,
                ) {
                    health.invalid_rows += 1;
                    return;
                }
                if !seen.insert(row.fingerprint.clone()) {
                    health.duplicate_rows += 1;
                    return;
                }
                if requests
                    .insert(row.request_id.clone(), row.fingerprint.clone())
                    .is_some_and(|old| old != row.fingerprint)
                {
                    health.conflicting_requests += 1;
                }
                rows.push(row);
            }
        }
    }
}
#[allow(clippy::too_many_arguments)]
fn valid_row<T: Serialize>(
    session: &str,
    request: &str,
    observed: &str,
    revision: &str,
    expected_revision: &str,
    fingerprint: &str,
    canonical: &T,
    file_digest: &str,
) -> bool {
    !session.is_empty()
        && !request.is_empty()
        && revision == expected_revision
        && OffsetDateTime::parse(observed, &Rfc3339).is_ok()
        && format!("{:x}", Sha256::digest(session.as_bytes())) == file_digest
        && serde_json::to_vec(canonical)
            .ok()
            .is_some_and(|bytes| format!("sha256:{:x}", Sha256::digest(bytes)) == fingerprint)
}

struct Recovery {
    reader: BufReader<Take<File>>,
    rows: Rows,
    physical_lines: usize,
    finished: bool,
    size: u64,
}
impl Recovery {
    fn new(file: File, trace: bool, health: &mut Health) -> std::io::Result<Self> {
        let size = file.metadata()?.len();
        health.files += 1;
        if size >= MAX_EVIDENCE_FILE_BYTES {
            health.oversized_files += 1;
        }
        Ok(Self {
            reader: BufReader::new(file.take(MAX_BYTES_PER_FILE)),
            rows: Rows::new(trace),
            physical_lines: 0,
            finished: false,
            size,
        })
    }
    // Continuation stays on this opened object and retains bounded dedup state.
    // A page boundary cannot reset conflicts, pretend EOF, or authorize a prefix.
    fn page(&mut self, digest: &str, health: &mut Health) {
        for _ in 0..PAGE_LINES {
            if self.finished {
                return;
            }
            if self.physical_lines == MAX_ROWS_PER_FILE {
                self.finished = true;
                health.limited_files += 1;
                return;
            }
            let mut line = Vec::new();
            let count = match self
                .reader
                .by_ref()
                .take((MAX_LINE_BYTES + 1) as u64)
                .read_until(b'\n', &mut line)
            {
                Ok(count) => count,
                Err(_) => {
                    health.unreadable_files += 1;
                    self.finished = true;
                    return;
                }
            };
            if count == 0 {
                self.finished = true;
                let read = MAX_BYTES_PER_FILE - self.reader.get_ref().limit();
                if read < self.size {
                    health.limited_files += 1;
                }
                return;
            }
            self.physical_lines += 1;
            if line.len() > MAX_LINE_BYTES {
                health.oversized_lines += 1;
                // Never decode a line fragment or resume in its middle.
                self.finished = true;
                health.limited_files += 1;
                return;
            }
            if !line.ends_with(b"\n") {
                health.unframed_lines += 1;
                self.finished = true;
                if MAX_BYTES_PER_FILE - self.reader.get_ref().limit() < self.size {
                    health.limited_files += 1;
                }
                // A complete JSON value without its append delimiter is not
                // a validated framed row. Preserve it on disk for recovery.
                return;
            }
            self.rows.observe(&line, digest, health);
        }
    }
    fn finish(self, before: &fs::Metadata, health: &mut Health) {
        health.bytes_read += MAX_BYTES_PER_FILE - self.reader.get_ref().limit();
        health.available_rows += self.rows.len() as u64;
        match self.reader.get_ref().get_ref().metadata() {
            Ok(after)
                if same_object(before, &after)
                    && before.len() == after.len()
                    && before.mtime() == after.mtime()
                    && before.mtime_nsec() == after.mtime_nsec() => {}
            _ => health.changed_files += 1,
        }
    }
}
fn same_object(a: &fs::Metadata, b: &fs::Metadata) -> bool {
    a.dev() == b.dev() && a.ino() == b.ino()
}
fn open_directory(path: &Path) -> std::io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
}
fn open_child(dir: &File, name: &str, directory: bool) -> std::io::Result<File> {
    let name = CString::new(name).map_err(|_| std::io::Error::other("invalid name"))?;
    let mut flags = libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK;
    if directory {
        flags |= libc::O_DIRECTORY;
    }
    // The returned descriptor is owned once, and all child opens are anchored
    // to an already opened directory (no parent-symlink escape).
    let fd = unsafe { libc::openat(dir.as_raw_fd(), name.as_ptr(), flags) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}
fn inspect_store(root: &File, support: &Path, store: &str, trace: bool) -> Health {
    let mut h = Health::default();
    let local = match open_child(root, "local-otel", true) {
        Ok(dir) => dir,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            h.missing_stores += 1;
            return h;
        }
        Err(_) => {
            h.unreadable_files += 1;
            return h;
        }
    };
    let dir = match open_child(&local, store, true) {
        Ok(dir) => dir,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            h.missing_stores += 1;
            return h;
        }
        Err(_) => {
            h.unreadable_files += 1;
            return h;
        }
    };
    let path = support.join("local-otel").join(store);
    let before = match dir.metadata() {
        Ok(m) => m,
        Err(_) => {
            h.unreadable_files += 1;
            return h;
        }
    };
    let entries = match fs::read_dir(&path) {
        Ok(e) => e,
        Err(_) => {
            h.unreadable_files += 1;
            return h;
        }
    };
    let mut names = Vec::new();
    for (n, entry) in entries.enumerate() {
        if n == MAX_DIRECTORY_ENTRIES {
            h.selection_limited = true;
            break;
        }
        let Ok(entry) = entry else {
            h.unreadable_files += 1;
            continue;
        };
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        let Some(digest) = name.strip_suffix(".jsonl") else {
            continue;
        };
        if digest.len() != 64
            || !digest
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            continue;
        }
        if names.len() == MAX_FILES_PER_STORE {
            h.selection_limited = true;
            break;
        }
        names.push(name);
    }
    names.sort();
    for name in names {
        let file = match open_child(&dir, &name, false) {
            Ok(f) => f,
            Err(_) => {
                h.unreadable_files += 1;
                continue;
            }
        };
        let before = match file.metadata() {
            Ok(m) if m.is_file() => m,
            _ => {
                h.unreadable_files += 1;
                continue;
            }
        };
        let mut read = match Recovery::new(file, trace, &mut h) {
            Ok(r) => r,
            Err(_) => {
                h.unreadable_files += 1;
                continue;
            }
        };
        while !read.finished {
            read.page(name.trim_end_matches(".jsonl"), &mut h);
        }
        read.finish(&before, &mut h);
    }
    match fs::symlink_metadata(&path) {
        Ok(after) if after.is_dir() && same_object(&before, &after) => {}
        _ => h.changed_files += 1,
    }
    h
}
fn health_items(h: Health) -> RedactedValue {
    let mut fields = BTreeMap::new();
    macro_rules! counts { ($($name:ident),*) => { $(fields.insert(stringify!($name).into(), RedactedValue::Number(h.$name as i64));)* }; }
    counts!(
        files,
        missing_stores,
        oversized_files,
        malformed_lines,
        oversized_lines,
        unframed_lines,
        invalid_rows,
        conflicting_requests,
        duplicate_rows,
        unreadable_files,
        changed_files,
        limited_files,
        available_rows,
        bytes_read
    );
    fields.insert(
        "incomplete_read".into(),
        RedactedValue::Bool(
            h.selection_limited
                || h.missing_stores > 0
                || h.oversized_files > 0
                || h.malformed_lines > 0
                || h.oversized_lines > 0
                || h.unframed_lines > 0
                || h.invalid_rows > 0
                || h.conflicting_requests > 0
                || h.unreadable_files > 0
                || h.changed_files > 0
                || h.limited_files > 0,
        ),
    );
    fields.insert(
        "selection_limited".into(),
        RedactedValue::Bool(h.selection_limited),
    );
    RedactedValue::Object(fields)
}
pub(crate) fn diagnostics_items(support: &Path) -> BTreeMap<String, RedactedValue> {
    let mut fields = BTreeMap::new();
    fields.insert(
        "complete_capture_authority".into(),
        RedactedValue::Bool(false),
    );
    fields.insert(
        "purpose".into(),
        RedactedValue::String("bounded_support_inspection_only".into()),
    );
    fields.insert(
        "maximum_bytes_read".into(),
        RedactedValue::Number((2 * MAX_FILES_PER_STORE as u64 * MAX_BYTES_PER_FILE) as i64),
    );
    match open_directory(support) {
        Ok(root) => {
            fields.insert(
                "api".into(),
                health_items(inspect_store(&root, support, "claude-code-effort", false)),
            );
            fields.insert(
                "trace".into(),
                health_items(inspect_store(
                    &root,
                    support,
                    "claude-code-trace-ownership",
                    true,
                )),
            );
        }
        Err(_) => {
            fields.insert("store_unavailable".into(), RedactedValue::Bool(true));
        }
    }
    fields
}

#[cfg(test)]
mod tests {
    use super::*;
    fn scratch() -> PathBuf {
        crate::test_scratch::private_dir("claude-support-health")
    }
    fn api(id: &str) -> ClaudeLocalOtelEvidence {
        let mut row = ClaudeLocalOtelEvidence {
            capture_revision: API_REQUEST_CAPTURE_REVISION.into(),
            session_id: "private-root".into(),
            request_id: id.into(),
            observed_at: "2026-10-07T00:00:00Z".into(),
            model: "synthetic".into(),
            request_count: 1,
            ..Default::default()
        };
        sign_api(&mut row);
        row
    }
    fn sign_api(row: &mut ClaudeLocalOtelEvidence) {
        row.fingerprint.clear();
        row.fingerprint = format!(
            "sha256:{:x}",
            Sha256::digest(serde_json::to_vec(row).unwrap())
        );
    }
    fn trace(id: &str) -> ClaudeTraceOwnershipEvidence {
        let mut row = ClaudeTraceOwnershipEvidence {
            capture_revision: TRACE_OWNERSHIP_CAPTURE_REVISION.into(),
            session_id: "private-root".into(),
            request_id: id.into(),
            observed_at: "2026-10-07T00:00:00Z".into(),
            ..Default::default()
        };
        row.fingerprint = format!(
            "sha256:{:x}",
            Sha256::digest(serde_json::to_vec(&row).unwrap())
        );
        row
    }
    fn line(row: &impl Serialize) -> Vec<u8> {
        let mut bytes = serde_json::to_vec(row).unwrap();
        bytes.push(b'\n');
        bytes
    }
    fn inspect(bytes: &[u8], trace: bool, size: Option<u64>) -> (Recovery, Health, PathBuf) {
        let dir = scratch();
        let path = dir.join("fixture");
        fs::write(&path, bytes).unwrap();
        if let Some(size) = size {
            OpenOptions::new()
                .write(true)
                .open(&path)
                .unwrap()
                .set_len(size)
                .unwrap();
        }
        let file = File::open(&path).unwrap();
        let mut h = Health::default();
        let mut r = Recovery::new(file, trace, &mut h).unwrap();
        let digest = format!("{:x}", Sha256::digest(b"private-root"));
        while !r.finished {
            r.page(&digest, &mut h);
        }
        (r, h, dir)
    }
    #[test]
    fn support_preserves_prefix_and_distinguishes_bad_tail_from_cap() {
        for trace_kind in [false, true] {
            let bytes = if trace_kind {
                line(&trace("first"))
            } else {
                line(&api("first"))
            };
            for tail in [b"{broken}\n".as_slice(), b"{partial".as_slice()] {
                let mut fixture = bytes.clone();
                fixture.extend_from_slice(tail);
                let (r, h, dir) = inspect(&fixture, trace_kind, None);
                assert_eq!(r.rows.len(), 1);
                assert_eq!(h.malformed_lines + h.unframed_lines, 1);
                assert_eq!(fs::read(dir.join("fixture")).unwrap(), fixture);
                fs::remove_dir_all(dir).unwrap();
            }
            let (r, h, dir) = inspect(&bytes, trace_kind, Some(MAX_EVIDENCE_FILE_BYTES));
            assert_eq!(r.rows.len(), 1);
            assert_eq!(h.oversized_files, 1);
            assert!(h.limited_files > 0 || h.oversized_lines > 0);
            assert_eq!(
                fs::metadata(dir.join("fixture")).unwrap().len(),
                MAX_EVIDENCE_FILE_BYTES
            );
            fs::remove_dir_all(dir).unwrap();
        }
    }
    #[test]
    fn support_requires_append_delimiter_and_bounds_oversized_rows() {
        for trace_kind in [false, true] {
            let first = if trace_kind {
                line(&trace("first"))
            } else {
                line(&api("first"))
            };
            let mut second = if trace_kind {
                line(&trace("second"))
            } else {
                line(&api("second"))
            };
            second.pop();
            let mut fixture = first.clone();
            fixture.extend(second);
            let (r, h, dir) = inspect(&fixture, trace_kind, None);
            assert_eq!(r.rows.len(), 1);
            assert_eq!(h.unframed_lines, 1);
            fs::remove_dir_all(dir).unwrap();
            let mut fixture = first;
            fixture.extend(vec![b'x'; MAX_LINE_BYTES + 100]);
            fixture.push(b'\n');
            let (r, h, dir) = inspect(&fixture, trace_kind, None);
            assert_eq!(r.rows.len(), 1);
            assert_eq!(h.oversized_lines, 1);
            assert_eq!(h.limited_files, 1);
            assert!(MAX_BYTES_PER_FILE - r.reader.get_ref().limit() <= MAX_BYTES_PER_FILE);
            fs::remove_dir_all(dir).unwrap();
        }
    }
    #[test]
    fn support_page_continuation_keeps_duplicates_conflicts_and_identity_negative() {
        let first = api("same");
        let mut conflict = first.clone();
        conflict.output_tokens = 9;
        sign_api(&mut conflict);
        let mut invalid = first.clone();
        invalid.request_id = "invalid".into();
        invalid.fingerprint = "forged".into();
        let mut unknown = api("unknown");
        unknown.session_id = "wrong-file".into();
        sign_api(&mut unknown);
        let mut negative = api("negative");
        negative.account_identity_checked = true;
        negative.request_identity = Some(ClaudeRequestIdentityEvidence {
            identity_hash_scheme: "provider-sha256:v1".into(),
            account: ClaudeIdentityAttributeEvidence {
                origin: ClaudeIdentityAttributeOrigin::Missing,
                disposition: ClaudeIdentityDisposition::Missing,
                resource_hash: None,
                log_record_hash: None,
            },
            organization: ClaudeIdentityAttributeEvidence {
                origin: ClaudeIdentityAttributeOrigin::Missing,
                disposition: ClaudeIdentityDisposition::Missing,
                resource_hash: None,
                log_record_hash: None,
            },
            disposition: ClaudeIdentityDisposition::Missing,
        });
        sign_api(&mut negative);
        let mut bytes = Vec::new();
        for n in 0..PAGE_LINES {
            bytes.extend(line(&if n == 0 {
                first.clone()
            } else {
                api(&format!("p{n}"))
            }));
        }
        for row in [&first, &conflict, &invalid, &unknown, &negative] {
            bytes.extend(line(row));
        }
        let dir = scratch();
        let path = dir.join("fixture");
        fs::write(&path, &bytes).unwrap();
        let mut h = Health::default();
        let mut r = Recovery::new(File::open(&path).unwrap(), false, &mut h).unwrap();
        let digest = format!("{:x}", Sha256::digest(b"private-root"));
        r.page(&digest, &mut h);
        assert!(!r.finished);
        assert_eq!(r.rows.len(), PAGE_LINES);
        while !r.finished {
            r.page(&digest, &mut h);
        }
        assert_eq!(h.duplicate_rows, 1);
        assert_eq!(h.conflicting_requests, 1);
        assert_eq!(h.invalid_rows, 2);
        match r.rows {
            Rows::Api { rows, .. } => assert_eq!(
                rows.last()
                    .unwrap()
                    .request_identity
                    .as_ref()
                    .unwrap()
                    .disposition,
                ClaudeIdentityDisposition::Missing
            ),
            _ => panic!(),
        }
        assert_eq!(fs::read(path).unwrap(), bytes);
        fs::remove_dir_all(dir).unwrap();
        let mut bytes = line(&trace("same"));
        bytes.extend(line(&trace("same")));
        let mut changed = trace("same");
        changed.agent_id = "other".into();
        changed.fingerprint.clear();
        changed.fingerprint = format!(
            "sha256:{:x}",
            Sha256::digest(serde_json::to_vec(&changed).unwrap())
        );
        bytes.extend(line(&changed));
        let (r, h, dir) = inspect(&bytes, true, None);
        assert_eq!(r.rows.len(), 2);
        assert_eq!(h.duplicate_rows, 1);
        assert_eq!(h.conflicting_requests, 1);
        fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn support_row_and_byte_limits_are_not_eof_or_authority() {
        let mut bytes = Vec::new();
        for n in 0..MAX_ROWS_PER_FILE + 10 {
            bytes.extend(line(&trace(&format!("r{n}"))));
        }
        let (r, h, dir) = inspect(&bytes, true, None);
        assert_eq!(r.rows.len(), MAX_ROWS_PER_FILE);
        assert_eq!(h.limited_files, 1);
        fs::remove_dir_all(dir).unwrap();
        let mut bytes = Vec::new();
        for _ in 0..10 {
            let mut row = trace("large");
            row.agent_id = "x".repeat(8000);
            row.fingerprint.clear();
            row.fingerprint = format!(
                "sha256:{:x}",
                Sha256::digest(serde_json::to_vec(&row).unwrap())
            );
            bytes.extend(line(&row));
        }
        let (r, h, dir) = inspect(&bytes, true, None);
        assert_eq!(
            MAX_BYTES_PER_FILE - r.reader.get_ref().limit(),
            MAX_BYTES_PER_FILE
        );
        assert_eq!(h.limited_files, 1);
        assert_eq!(h.unframed_lines, 1);
        fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn support_consumer_is_counter_only_bounded_and_refuses_symlinks() {
        let dir = scratch();
        let row = api("private-request");
        append_evidence(&dir, &row).unwrap();
        append_trace_ownership_evidence(&dir, &trace("private-request")).unwrap();
        let before = fs::read(evidence_path(&dir, &row.session_id)).unwrap();
        let fields = diagnostics_items(&dir);
        assert_eq!(
            fields["complete_capture_authority"],
            RedactedValue::Bool(false)
        );
        let encoded = serde_json::to_string(&fields).unwrap();
        for secret in [
            "private-root",
            "private-request",
            "sha256:",
            "synthetic",
            dir.to_str().unwrap(),
        ] {
            assert!(!encoded.contains(secret));
        }
        assert!(encoded.contains("available_rows"));
        assert_eq!(
            fs::read(evidence_path(&dir, &row.session_id)).unwrap(),
            before
        );
        let strict = load_claude_api_request_evidence_report(&dir, [row.session_id.clone()]);
        assert!(strict.health.is_complete());
        let file = evidence_path(&dir, &row.session_id);
        fs::remove_file(&file).unwrap();
        let outside = dir.join("outside");
        fs::write(&outside, &before).unwrap();
        std::os::unix::fs::symlink(&outside, &file).unwrap();
        let fields = diagnostics_items(&dir);
        match &fields["api"] {
            RedactedValue::Object(api) => {
                assert_eq!(api["unreadable_files"], RedactedValue::Number(1))
            }
            _ => panic!(),
        }
        fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn support_detects_opened_object_change_and_refuses_store_directory_symlink() {
        let dir = scratch();
        let row = api("one");
        let path = dir.join("fixture");
        fs::write(&path, line(&row)).unwrap();
        let file = File::open(&path).unwrap();
        let before = file.metadata().unwrap();
        let mut h = Health::default();
        let mut recovery = Recovery::new(file, false, &mut h).unwrap();
        let digest = format!("{:x}", Sha256::digest(b"private-root"));
        while !recovery.finished {
            recovery.page(&digest, &mut h);
        }
        OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(b"changed\n")
            .unwrap();
        recovery.finish(&before, &mut h);
        assert_eq!(h.changed_files, 1);
        let outside = dir.join("outside");
        fs::create_dir(&outside).unwrap();
        fs::create_dir(dir.join("local-otel")).unwrap();
        std::os::unix::fs::symlink(&outside, dir.join("local-otel/claude-code-effort")).unwrap();
        let fields = diagnostics_items(&dir);
        match &fields["api"] {
            RedactedValue::Object(api) => {
                assert_eq!(api["files"], RedactedValue::Number(0));
                assert_eq!(api["bytes_read"], RedactedValue::Number(0));
                assert_eq!(api["incomplete_read"], RedactedValue::Bool(true));
            }
            _ => panic!(),
        }
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn support_store_and_selection_limits_are_explicit_and_strict_cap_stays_refused() {
        let dir = scratch();
        let row = api("one");
        append_evidence(&dir, &row).unwrap();
        let path = evidence_path(&dir, &row.session_id);
        let prefix = fs::read(&path).unwrap();
        OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .set_len(MAX_EVIDENCE_FILE_BYTES)
            .unwrap();
        let fields = diagnostics_items(&dir);
        match &fields["api"] {
            RedactedValue::Object(api) => {
                assert_eq!(api["oversized_files"], RedactedValue::Number(1));
                assert_eq!(api["incomplete_read"], RedactedValue::Bool(true));
                assert_eq!(api["available_rows"], RedactedValue::Number(1));
            }
            _ => panic!(),
        }
        let strict = load_claude_api_request_evidence_report(&dir, [row.session_id.clone()]);
        assert_eq!(strict.health.oversized_files, 1);
        assert!(strict.evidence.is_empty());
        assert!(!strict.health.is_complete());
        assert_eq!(
            BufReader::new(File::open(&path).unwrap())
                .take(prefix.len() as u64)
                .bytes()
                .collect::<std::io::Result<Vec<_>>>()
                .unwrap(),
            prefix
        );
        for n in 0..MAX_FILES_PER_STORE + 2 {
            let mut row = api(&format!("req{n}"));
            row.session_id = format!("root{n}");
            sign_api(&mut row);
            append_evidence(&dir, &row).unwrap();
        }
        let fields = diagnostics_items(&dir);
        match &fields["api"] {
            RedactedValue::Object(api) => {
                assert_eq!(
                    api["files"],
                    RedactedValue::Number(MAX_FILES_PER_STORE as i64)
                );
                assert_eq!(api["selection_limited"], RedactedValue::Bool(true));
                assert!(
                    matches!(api["bytes_read"],RedactedValue::Number(n) if n<=MAX_FILES_PER_STORE as i64*MAX_BYTES_PER_FILE as i64)
                );
            }
            _ => panic!(),
        }
        fs::remove_dir_all(dir).unwrap();
    }
}
