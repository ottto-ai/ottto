use super::*;
use crate::heap_layout_bound::{Counter, HeapLayoutBound};
use crate::snapshots::line_delivery::{
    DeliveryEnd, DeliveryMode, FileView, LineObserver, PhysicalLine, Want,
};
use crate::transcript_acquisition::FileObject;
use std::collections::HashMap;
use std::mem::{align_of, size_of};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
const STALE: Duration = Duration::from_secs(14 * 86400);
const FEED_BYTES: usize = 4 * 1024 * 1024;
const ROOT_BYTES: usize = 16 * 1024;
const AGENTS_BYTES: usize = 128 * 1024;
const SKILLS_BYTES: usize = 96 * 1024;
const OBSERVER_BYTES: usize =
    crate::snapshots::line_delivery::checked_observer_heap_bytes(256 * 1024);
pub(super) type Start = (FileObject, CodexPrelude, PathBuf, bool, SystemTime);
type Scopes = Vec<(String, String)>;
#[derive(Default)]
pub(crate) struct CodexPreludeFeed(Mutex<Feed>, OnceLock<std::io::Result<()>>);
impl std::fmt::Debug for CodexPreludeFeed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CodexPreludeFeed(..)")
    }
}
#[derive(Default)]
struct Feed {
    files: Vec<(FileObject, Entry)>,
    positions: HashMap<FileObject, usize>,
    table_slots: usize,
    payload_bytes: usize,
    scope_bytes: usize,
    scopes: Vec<(String, String)>,
    evicted: u64,
    text_capped: u64,
    unseen: u64,
    gaps: u64,
    root_missing: u64,
}
struct Entry {
    bytes: usize,
    home: PathBuf,
    mtime: SystemTime,
    state: State,
}
enum State {
    Pending(Box<Observation>),
    Done(Box<CodexPrelude>, bool),
    Unseen,
}
struct Observation {
    parser: CodexPreludeParser,
    rows: usize,
    next: u64,
    terminal: bool,
    capped: bool,
}
impl Entry {
    fn heap_bytes(&self) -> usize {
        let mut c = Counter::new(usize::MAX);
        let bound = match &self.state {
            State::Pending(o) => c
                .add(size_of::<Observation>() + align_of::<Observation>())
                .and_then(|_| o.parser.heap_bound(&mut c)),
            State::Done(p, _) => p.heap_bound(&mut c),
            State::Unseen => Some(()),
        };
        self.home
            .capacity()
            .saturating_add(bound.map_or(usize::MAX, |_| c.bytes))
    }
}
impl Feed {
    fn bytes(&self) -> usize {
        size_of::<Self>() + 64 + self.payload_bytes + self.scope_bytes
            + self.files.capacity() * size_of::<(FileObject, Entry)>()
            // High-water includes tombstones and rebuild overlap.
            + self.table_slots * (size_of::<(FileObject, usize)>() + 32) * 2
    }
    fn rebuild(&mut self) {
        self.positions.clear();
        self.positions
            .extend(self.files.iter().enumerate().map(|(i, (id, _))| (*id, i)));
        if self.table_slots > 2 * self.files.len() + 8 {
            self.positions.shrink_to_fit();
            self.table_slots = self.positions.capacity();
        }
        if self.files.capacity() > 2 * self.files.len() + 8 {
            self.files.shrink_to_fit();
        }
    }
    fn take(&mut self, object: FileObject) -> Option<Entry> {
        let i = self.positions.remove(&object)?;
        let (_, entry) = self.files.swap_remove(i);
        if let Some((id, _)) = self.files.get(i) {
            self.positions.insert(*id, i);
        }
        self.payload_bytes -= entry.bytes;
        Some(entry)
    }
    fn put(&mut self, file: &FileView, home: PathBuf, state: State) {
        self.take(file.object);
        let mut entry = Entry {
            bytes: 0,
            home,
            mtime: file.mtime.unwrap_or(SystemTime::UNIX_EPOCH),
            state,
        };
        entry.bytes = entry.heap_bytes();
        let growth = usize::from(self.files.len() == self.files.capacity())
            * self.files.capacity().max(4)
            * size_of::<(FileObject, Entry)>()
            + usize::from(self.positions.len() == self.positions.capacity())
                * self.table_slots.max(4)
                * (size_of::<(FileObject, usize)>() + 32)
                * 2;
        let extra = entry.bytes.saturating_add(growth);
        self.trim(extra);
        let refused = self.bytes().saturating_add(extra) > FEED_BYTES
            || self.positions.try_reserve(1).is_err();
        self.table_slots = self.table_slots.max(self.positions.capacity());
        if refused || self.files.try_reserve(1).is_err() {
            self.evicted += 1;
            return;
        }
        self.payload_bytes += entry.bytes;
        self.positions.insert(file.object, self.files.len());
        self.files.push((file.object, entry));
        if self.table_slots > 2 * self.files.len() + 8 {
            self.rebuild();
        }
    }
    fn trim(&mut self, extra: usize) {
        while !self.files.is_empty() && self.bytes().saturating_add(extra) > FEED_BYTES {
            let n = self.files.len().div_ceil(2);
            self.files
                .select_nth_unstable_by_key(n - 1, |(_, e)| e.mtime);
            for (_, e) in self.files.drain(..n) {
                self.payload_bytes -= e.bytes;
                self.evicted += 1;
            }
            self.rebuild();
        }
    }
}
impl CodexPreludeFeed {
    fn lock(&self) -> MutexGuard<'_, Feed> {
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }
    pub(crate) fn observer(self: &Arc<Self>, roots: &[PathBuf]) -> Box<impl LineObserver + Send> {
        let slots = roots.len().saturating_mul(size_of::<(PathBuf, PathBuf)>());
        let mut bytes = 64usize.saturating_add(slots);
        let mut snapshot = Vec::with_capacity(if bytes <= ROOT_BYTES { roots.len() } else { 0 });
        for root in roots {
            if bytes.saturating_add(root.as_os_str().len()) > ROOT_BYTES {
                snapshot.clear();
                break;
            }
            let resolved = fs::canonicalize(root).unwrap_or_else(|_| root.clone());
            bytes = bytes.saturating_add(resolved.capacity() + root.as_os_str().len());
            if bytes > ROOT_BYTES {
                snapshot.clear();
                break;
            }
            snapshot.push((root.clone(), resolved));
        }
        let roots = snapshot.into();
        Box::new(Observer {
            feed: Arc::clone(self),
            roots,
            active: None,
        })
    }
    pub(super) fn snapshot(&self, now: SystemTime) -> (Vec<Start>, Scopes) {
        let (mut starts, mut scopes): (Vec<Start>, Scopes) = {
            let f = self.lock();
            (
                f.files
                    .iter()
                    .filter_map(|(i, e)| match &e.state {
                        State::Done(p, c) => Some((*i, (**p).clone(), e.home.clone(), *c, e.mtime)),
                        _ => None,
                    })
                    .collect(),
                f.scopes.clone(),
            )
        };
        starts.retain(|s| now.duration_since(s.4).unwrap_or_default() <= STALE);
        scopes.retain(|(cwd, _)| starts.iter().any(|s| s.1.cwd.as_ref() == Some(cwd)));
        (starts, scopes)
    }
    pub(super) fn remember_scopes(&self, mut scopes: Scopes) {
        scopes.truncate(512); // Cache only; a miss recomputes git outside callbacks.
        if scopes.capacity() > 2 * scopes.len() {
            scopes.shrink_to_fit();
        }
        let scope_bytes = scopes.iter().fold(
            scopes.capacity() * size_of::<(String, String)>(),
            |n, (k, v)| n + k.capacity() + v.capacity(),
        );
        let mut f = self.lock();
        f.scopes = scopes;
        f.scope_bytes = scope_bytes;
        let now = SystemTime::now();
        for i in (0..f.files.len()).rev() {
            let age = now.duration_since(f.files[i].1.mtime).unwrap_or_default();
            if age > STALE {
                let object = f.files[i].0;
                f.take(object);
            }
        }
        if f.table_slots > 2 * f.files.len() + 8 {
            f.rebuild();
        }
        f.trim(0);
    }
    // TODO(E4): remove this exact-file migration after two stable releases.
    pub(super) fn cleanup_index(&self, support: &Path) {
        self.1
            .get_or_init(|| fs::remove_file(support.join(STATE_DIR).join("index.json")));
    }
    pub(crate) fn metrics(&self) -> String {
        let f = self.lock();
        let cleanup = self.1.get();
        format!("feed_files={} feed_bytes={} pending={} evicted={} text_capped={} codex_prelude_unseen_prefix={} codex_prelude_gap_dropped={} root_missing={} index_cleanup_removed={} index_cleanup_absent={} index_cleanup_failed={}", f.files.len(), f.bytes(), f.files.iter().filter(|(_, e)| matches!(e.state, State::Pending(_))).count(), f.evicted, f.text_capped, f.unseen, f.gaps, f.root_missing, u8::from(matches!(cleanup, Some(Ok(())))), u8::from(matches!(cleanup, Some(Err(e)) if e.kind() == std::io::ErrorKind::NotFound)), u8::from(matches!(cleanup, Some(Err(e)) if e.kind() != std::io::ErrorKind::NotFound)))
    }
}
// Daemon-owned, capped at 4 MiB; no ticket discard frees it (18b precedent).
impl HeapLayoutBound for CodexPreludeFeed {
    fn heap_bound(&self, _: &mut Counter) -> Option<()> {
        Some(())
    }
}
struct Observer {
    feed: Arc<CodexPreludeFeed>,
    roots: Arc<[(PathBuf, PathBuf)]>,
    active: Option<(PathBuf, Observation)>,
}
impl LineObserver for Observer {
    fn declared_heap_bytes(&self) -> usize {
        OBSERVER_BYTES
    }
    fn root_ordinal(&self, root: &Path, _: &[PathBuf]) -> Option<u16> {
        self.roots
            .iter()
            .position(|(configured, resolved)| root == configured || root == resolved)
            .and_then(|i| u16::try_from(i).ok())
    }
    fn begin(&mut self, file: &FileView) -> Want {
        self.active = None;
        if file.source != SnapshotSource::Codex {
            return Want::Skip;
        }
        let mut f = self.feed.lock();
        let old = f.take(file.object).map(|entry| entry.state);
        let home = file
            .root
            .and_then(|i| self.roots.get(usize::from(i)))
            .and_then(|r| r.0.parent())
            .filter(|h| h.as_os_str().len() <= 4096);
        let Some(home) = home else {
            f.root_missing += 1;
            f.put(file, PathBuf::new(), State::Unseen);
            return Want::Skip;
        };
        let home = home.to_path_buf();
        let observation = match (file.mode, old) {
            (DeliveryMode::Full, _) => Observation {
                parser: CodexPreludeParser {
                    agents_md_cap: AGENTS_BYTES,
                    ..CodexPreludeParser::default()
                },
                rows: 0,
                next: file.start,
                terminal: false,
                capped: false,
            },
            (DeliveryMode::Tail, Some(State::Pending(o))) if file.start == o.next => *o,
            (DeliveryMode::Tail, Some(State::Pending(_))) => {
                f.gaps += 1;
                f.put(file, home, State::Unseen);
                return Want::Skip;
            }
            (_, old) => {
                if old.is_none() {
                    f.unseen += 1;
                }
                f.put(file, home, old.unwrap_or(State::Unseen));
                return Want::Skip;
            }
        };
        self.active = Some((home, observation));
        Want::Lines
    }
    fn line(&mut self, file: &FileView, line: &PhysicalLine<'_>) {
        let Some((_, o)) = self.active.as_mut() else {
            return;
        };
        if o.terminal {
            return;
        }
        if line.end <= o.next {
            let (home, _) = self.active.take().expect("active observation");
            let mut f = self.feed.lock();
            f.gaps += 1;
            f.put(file, home, State::Unseen);
            return;
        }
        o.next = line.end;
        o.rows += 1;
        let (step, capped) = o
            .parser
            .observe_bounded(line.value.unwrap_or(&Value::Null), SKILLS_BYTES);
        o.capped |= capped || o.parser.prelude().agents_md_capped;
        o.terminal = step == PreludeStep::Done || o.rows == MAX_PRELUDE_LINES;
    }
    fn end(&mut self, file: &FileView, end: &DeliveryEnd) {
        let Some((home, o)) = self.active.take() else {
            return;
        };
        let mut f = self.feed.lock();
        let state = if o.terminal {
            f.text_capped += u64::from(o.capped);
            let mut p = o.parser.finish();
            if o.capped {
                (p.agents_md, p.skills_body) = (None, None);
            }
            State::Done(Box::new(p), o.capped)
        } else if *end == DeliveryEnd::Complete {
            State::Pending(Box::new(o))
        } else {
            f.gaps += 1;
            State::Unseen
        };
        f.put(file, home, state);
    }
}
#[cfg(test)]
#[path = "feed_tests.rs"]
mod tests;
