//! The shared relay journal. The relay appends each accepted request's rows
//! here, under `append_lock` and before it answers, instead of to one file per
//! session. A drain moves them to their per-session files in arrival order,
//! one append per file: at daemon start, at each scan start, and each time a
//! request takes the journal past another multiple of its size threshold.
//! Readers keep reading only the per-session files.
//!
//! Each line is a one-byte kind (`a` API, `t` trace) followed by the row's
//! JSON exactly as its per-session file stores it. A drain first renames the
//! journal to `prev` and keeps `prev` until a drain at least a minute later,
//! so rows already on disk keep an on-disk copy until their per-session writes
//! have long been written back (no fsync of those writes). Such a drain
//! replaces `prev`, or removes it when the journal is empty, so `prev` never
//! outlives retention. The first drain in a process replays `prev`, then the
//! journal. A replay or a crash mid-drain can copy rows twice; the
//! per-session decoders drop identical rows. A torn line (a crash mid-append,
//! so never acknowledged) is never copied. Rows a per-session file refuses
//! wait in the journal until it accepts them.
use super::*;
use std::ops::Range;

/// Under `local-otel`, so an uninstall removes it with the stores; outside
/// both store directories, so no stem listing or support inspection reads it.
const JOURNAL: &str = "local-otel/claude-code-relay-journal.jsonl";
const PREV: &str = "local-otel/claude-code-relay-journal.prev.jsonl";
/// Drained at each scan start, the journal holds about one interval of rows.
/// A request that takes it this far past its length after the last drain
/// (scans stalled) drains it inline; nothing is ever refused or dropped for
/// size.
pub(super) const DRAIN_AT_BYTES: u64 = 16 * 1024 * 1024;
/// `prev` is replaced or removed only once its rows reached their per-session
/// files at least this long ago; a sooner drain adds the journal to `prev`.
const PREV_MIN_AGE: Duration = Duration::from_secs(60);
/// One counts-only local alarm per drain while refused rows exceed this size.
const KEPT_ALERT_BYTES: u64 = 32 * 1024 * 1024;

#[derive(Clone, Copy)]
pub(super) enum Kind {
    Api,
    Trace,
}

impl Kind {
    fn tag(self) -> u8 {
        match self {
            Kind::Api => b'a',
            Kind::Trace => b't',
        }
    }
}

/// One support directory's journal facts, held under `append_lock`.
#[derive(Default)]
pub(super) struct State {
    /// When a drain last appended rows from `prev` to the per-session files;
    /// `None` until `prev` is replayed in this process.
    pub(super) prev_drained: Option<Instant>,
    /// Rows waiting because their per-session file refused them: per file,
    /// (rows, bytes).
    pub(super) kept: BTreeMap<PathBuf, (u64, u64)>,
    /// The journal's length after the last drain attempt: rows it could not
    /// move. A request drains inline only once the journal has grown
    /// `DRAIN_AT_BYTES` past it, so a refused backlog never drains per request.
    pub(super) len_after_drain: u64,
}

pub(super) fn journal_path(support_dir: &Path) -> PathBuf {
    support_dir.join(JOURNAL)
}

pub(super) fn prev_path(support_dir: &Path) -> PathBuf {
    support_dir.join(PREV)
}

#[cfg(test)]
thread_local! {
    static KEEP_WAITING: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Test seam: other tests read the per-session files right after a capture,
/// so captures drain at once unless a test keeps rows waiting on this thread.
#[cfg(test)]
pub(super) fn keep_rows_waiting_for_test(keep: bool) {
    KEEP_WAITING.with(|slot| slot.set(keep));
}

/// One request's rows as one journal write. The caller holds `append_lock`.
pub(super) fn append<'a, T: Serialize + 'a>(
    handles: &mut AppendHandles,
    support_dir: &Path,
    kind: Kind,
    rows: impl IntoIterator<Item = (&'a str, &'a T)>,
) -> Result<usize> {
    use crate::local_resource_diagnostics::cache_lifecycle::{self, Event};

    anyhow::ensure!(
        !handles.disabled,
        "Claude evidence appends disabled for uninstall"
    );
    let mut encoded = Vec::new();
    let mut roots = BTreeSet::new();
    let mut count = 0;
    for (root, row) in rows {
        if crate::internal_session::is_internal_session_id(root) {
            continue;
        }
        encoded.push(kind.tag());
        serde_json::to_writer(&mut encoded, row)?;
        encoded.push(b'\n');
        roots.insert(root);
        count += 1;
    }
    if count == 0 {
        return Ok(0);
    }
    let path = journal_path(support_dir);
    let mut file =
        open_private_append(&mut handles.prepared, &path).context("open Claude relay journal")?;
    let before = file.metadata()?.len();
    append_lines(&mut file, &encoded).context("append Claude relay journal")?;
    drop(file);
    cache_lifecycle::record(Event::OtlpRelayJournalAppends);
    cache_lifecycle::add(Event::OtlpRelayAppendedRows, count as u64);
    // The bytes the per-session files will hold: no kind tag.
    cache_lifecycle::add(
        Event::OtlpRelayAppendedBytes,
        (encoded.len() - count) as u64,
    );
    for root in roots {
        telemetry_notices::captured(support_dir, root);
    }
    let after = before + encoded.len() as u64;
    let floor = handles
        .journals
        .get(support_dir)
        .map_or(0, |state| state.len_after_drain);
    let full = after >= floor.saturating_add(DRAIN_AT_BYTES);
    #[cfg(test)]
    let full = full || !KEEP_WAITING.with(std::cell::Cell::get);
    if full {
        // The rows are stored, so the request succeeds; a failed drain leaves
        // them waiting for the next one.
        let _ = drain_locked(handles, support_dir);
    }
    Ok(count)
}

/// A complete journal line: its byte range, per-session file and root.
struct Line {
    range: Range<usize>,
    target: PathBuf,
    root: String,
}

/// Every line in order; `None` for a torn or invalid line, never copied.
fn lines<'a>(bytes: &'a [u8], support_dir: &'a Path) -> impl Iterator<Item = Option<Line>> + 'a {
    #[derive(Deserialize)]
    struct Root {
        session_id: String,
    }
    let mut start = 0;
    bytes
        .split_inclusive(|&byte| byte == b'\n')
        .map(move |chunk| {
            let range = start..start + chunk.len();
            start = range.end;
            let json = chunk.strip_suffix(b"\n")?.get(1..)?;
            let root = serde_json::from_slice::<Root>(json).ok()?.session_id;
            let target = match chunk[0] {
                b'a' => evidence_path(support_dir, &root),
                b't' => trace_evidence_path(support_dir, &root),
                _ => return None,
            };
            Some(Line {
                range,
                target,
                root,
            })
        })
}

/// A missing file reads as empty.
fn read_present(path: &Path) -> std::io::Result<Vec<u8>> {
    match fs::read(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        read => read,
    }
}

/// Move the journal's complete lines to their per-session files. The caller
/// holds `append_lock`, so no row arrives meanwhile. Under the uninstall fence
/// nothing moves: the rows go with the support dir.
pub(super) fn drain_locked(handles: &mut AppendHandles, support_dir: &Path) -> Result<()> {
    use crate::local_resource_diagnostics::cache_lifecycle::{self, Event};

    if handles.disabled {
        return Ok(());
    }
    let started = Instant::now();
    let (journal, prev) = (journal_path(support_dir), prev_path(support_dir));
    let state = handles
        .journals
        .entry(support_dir.to_path_buf())
        .or_default();
    let drained_at = state.prev_drained;
    let current = read_present(&journal).context("read Claude relay journal")?;
    // Until the rewrite below, a failed attempt leaves the journal as read.
    state.len_after_drain = current.len() as u64;
    let keep_prev = drained_at.is_none_or(|at| at.elapsed() < PREV_MIN_AGE)
        && fs::symlink_metadata(&prev).is_ok();
    let mut input = Vec::new();
    if keep_prev {
        // Not replayed yet in this process, or its rows reached their files
        // too recently to drop: keep `prev` and add the journal to it.
        if drained_at.is_none() {
            input = fs::read(&prev).context("read previous Claude relay journal")?;
            if ends_inside_row(&input) == Some(true) {
                input.push(b'\n');
            }
        } else if current.is_empty() {
            return Ok(());
        }
        if !current.is_empty() {
            let mut file = open_private_append(&mut handles.prepared, &prev)?;
            append_lines(&mut file, &current)?;
            // The journal is cut next; after a restart its rows may be in
            // `prev` alone.
            file.sync_data()
                .context("sync previous Claude relay journal")?;
        }
    } else if current.is_empty() {
        if drained_at.is_some() {
            // `prev`'s rows reached their per-session files at least a minute
            // ago; a later replay must not recreate files retention removed.
            let removed = fs::remove_file(&prev);
            if removed
                .as_ref()
                .is_err_and(|error| error.kind() != std::io::ErrorKind::NotFound)
            {
                removed.context("remove previous Claude relay journal")?;
            }
        }
        return Ok(());
    } else {
        // `prev`'s rows reached their per-session files at least a minute ago.
        fs::rename(&journal, &prev).context("rotate Claude relay journal")?;
    }
    input.extend_from_slice(&current);

    let mut batches = BTreeMap::<PathBuf, (Vec<Range<usize>>, BTreeSet<String>)>::new();
    let mut skipped = 0;
    for line in lines(&input, support_dir) {
        let Some(Line {
            range,
            target,
            root,
        }) = line
        else {
            skipped += 1;
            continue;
        };
        let (ranges, roots) = batches.entry(target).or_default();
        ranges.push(range);
        roots.insert(root);
    }
    let (mut kept, mut kept_files, mut drained) = (Vec::new(), BTreeMap::new(), 0);
    for (target, (ranges, roots)) in batches {
        let mut encoded = Vec::new();
        for range in &ranges {
            encoded.extend_from_slice(&input[range.start + 1..range.end]);
        }
        let roots = roots.iter().map(String::as_str);
        match append_file_batch(handles, support_dir, &target, &encoded, roots) {
            Ok(()) => drained += ranges.len(),
            Err(_) => {
                kept_files.insert(target, (ranges.len() as u64, encoded.len() as u64));
                kept.extend(ranges);
            }
        }
    }
    // The journal now holds only refused rows, in arrival order; `prev` keeps
    // every row until a later drain replaces it.
    kept.sort_by_key(|range| range.start);
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let rewritten = options.open(&journal).and_then(|mut file| {
        kept.iter()
            .try_for_each(|range| file.write_all(&input[range.clone()]))
    });
    let state = handles
        .journals
        .entry(support_dir.to_path_buf())
        .or_default();
    // A journal that could not be rewritten replays `prev` at the next drain.
    state.prev_drained = rewritten.is_ok().then(Instant::now);
    state.kept = kept_files;
    state.len_after_drain = kept.iter().map(|range| range.len() as u64).sum();
    let (kept_rows, kept_bytes) = kept_totals(handles);
    if kept_bytes > KEPT_ALERT_BYTES {
        crate::local_resource_diagnostics::otlp_relay_journal_kept_alarm(kept_rows, kept_bytes);
    }
    let elapsed = started.elapsed();
    cache_lifecycle::record(Event::OtlpRelayJournalDrains);
    cache_lifecycle::add(Event::OtlpRelayJournalDrainedRows, drained as u64);
    cache_lifecycle::add(Event::OtlpRelayJournalSkippedLines, skipped);
    cache_lifecycle::add(
        Event::OtlpRelayJournalDrainMs,
        u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX),
    );
    if elapsed >= Duration::from_secs(1) {
        cache_lifecycle::record(Event::OtlpRelayJournalDrainsGe1s);
    }
    rewritten.context("rewrite Claude relay journal")
}

/// Rows and bytes waiting for a refusing per-session file, all directories.
pub(super) fn kept_totals(handles: &AppendHandles) -> (u64, u64) {
    let kept = handles
        .journals
        .values()
        .flat_map(|state| state.kept.values());
    kept.fold((0, 0), |(rows, bytes), &(r, b)| (rows + r, bytes + b))
}

/// Whether a row for `stem` is still in the journal or in `prev`, which a
/// restart replays until a drain removes it. An unreadable file counts as
/// waiting.
pub(super) fn waits_for(support_dir: &Path, stem: &str) -> bool {
    let targets = telemetry_member_paths(support_dir, stem);
    let paths = [journal_path(support_dir), prev_path(support_dir)];
    paths.iter().any(|path| match read_present(path) {
        Ok(bytes) => lines(&bytes, support_dir)
            .flatten()
            .any(|line| targets.contains(&line.target)),
        Err(_) => true,
    })
}

/// Complete journal rows waiting for a drain (not `prev`, which normally
/// holds rows already drained): a standalone reader's incompleteness hint.
pub(super) fn waiting_rows(support_dir: &Path) -> std::io::Result<usize> {
    let bytes = read_present(&journal_path(support_dir))?;
    Ok(lines(&bytes, support_dir).flatten().count())
}
