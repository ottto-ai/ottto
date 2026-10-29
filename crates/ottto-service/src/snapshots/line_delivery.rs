//! LD: RAM-only delivery of the lines the one primary reader already read; no
//! transcript open, seek or read is added and no line outlives its callback.
use super::{OwnedActiveFile, OwnedJsonlParser, OwnedSourceScan, SnapshotSource};
use crate::local_resource_diagnostics::LineDeliveryCounts;
use crate::transcript_acquisition::{FileObject, ReadMode};
use serde_json::Value;
use std::time::SystemTime;

pub(crate) const fn checked_observer_heap_bytes(bytes: usize) -> usize {
    assert!(bytes <= 256 * 1024);
    bytes
}
/// Default declared pass-state charge, preserved for the Claude observer.
const OBSERVER_HEAP_BYTES: usize = checked_observer_heap_bytes(64 * 1024);
/// Synchronous in the read: O(line), no I/O or cache/rotation lock, pass
/// state within its static declaration; never paces or blocks acquisition.
pub(crate) trait LineObserver {
    fn declared_heap_bytes(&self) -> usize {
        OBSERVER_HEAP_BYTES
    }
    fn root_ordinal(&self, root: &std::path::Path, roots: &[std::path::PathBuf]) -> Option<u16> {
        roots
            .iter()
            .position(|r| r == root)
            .and_then(|i| u16::try_from(i).ok())
    }
    fn begin(&mut self, file: &FileView) -> Want;
    fn line(&mut self, file: &FileView, line: &PhysicalLine<'_>);
    /// Exactly once per `begin`, `Want::Skip` included.
    fn end(&mut self, file: &FileView, end: &DeliveryEnd);
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Want {
    Lines,
    Skip,
}
/// `Full` (also without a ReadPlan) starts at 0 and replaces object state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DeliveryMode {
    Full,
    Tail,
    Unchanged,
}
/// No path or key text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct FileView {
    pub(crate) source: SnapshotSource,
    pub(crate) object: FileObject,
    pub(crate) mtime: Option<SystemTime>,
    pub(crate) mode: DeliveryMode,
    /// Checked ordinal into the immutable roots used to construct this scan.
    pub(crate) root: Option<u16>,
    pub(crate) start: u64,
}
/// A complete line's one parse; none if blank, malformed, non-UTF-8 or overlong.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) struct PhysicalLine<'a> {
    /// Absolute physical end after the newline, including skipped bytes.
    pub(crate) end: u64,
    pub(crate) value: Option<&'a Value>,
}
/// `Incomplete`: the file left the pass before its read completed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DeliveryEnd {
    Complete,
    Incomplete,
}
/// Reader-level tap: physical length (newline and skipped bytes) and line.
pub(super) type LineTap<'a> = &'a mut dyn FnMut(u64, &PhysicalLine<'_>);
pub(super) struct LineDelivery {
    name: &'static str,
    observer: Box<dyn LineObserver + Send>,
    /// A fresh primary file is active and not yet dispatched.
    armed: bool,
    open: Option<(FileView, bool)>,
    counts: LineDeliveryCounts,
    declared_heap_bytes: usize,
}
impl OwnedSourceScan {
    /// `name` keys the page counts (`line_delivery.<name>`).
    pub(crate) fn with_line_observer(
        mut self,
        name: &'static str,
        observer: Box<dyn LineObserver + Send>,
    ) -> Self {
        let declared_heap_bytes = observer.declared_heap_bytes();
        debug_assert!(declared_heap_bytes <= 256 * 1024);
        self.line_delivery = Some(LineDelivery {
            declared_heap_bytes,
            name,
            observer,
            armed: false,
            open: None,
            counts: LineDeliveryCounts::default(),
        });
        self
    }
}
impl OwnedActiveFile {
    /// Shared primary-reader role gate for borrowed consumers.
    pub(super) fn is_primary_for(&self, source: SnapshotSource) -> bool {
        self.parser.source == source
            && self.side_origin.is_none()
            && !self.comparison_target
            && self.group.is_none()
    }
}
impl LineDelivery {
    /// A fresh primary read of the active file: opened, or replaced in place.
    pub(super) fn arm(&mut self) {
        self.end_open(DeliveryEnd::Incomplete);
        self.armed = true;
    }
    /// The single begin site: the common step dispatch, roles final.
    pub(super) fn begin_armed(&mut self, active: &OwnedActiveFile, roots: &[std::path::PathBuf]) {
        if !std::mem::take(&mut self.armed) || !active.is_primary_for(active.parser.source) {
            return;
        }
        let reader = &active.parser.reader;
        let Some((object, held)) = FileObject::of(reader.reader.get_ref()) else {
            return;
        };
        let mode = match reader.acquisition.as_ref().map(|plan| plan.mode()) {
            None | Some(ReadMode::Full(_)) => DeliveryMode::Full,
            Some(ReadMode::Tail) => DeliveryMode::Tail,
            Some(ReadMode::Unchanged) => DeliveryMode::Unchanged,
        };
        let view = FileView {
            source: active.parser.source,
            object,
            mtime: held.modified().ok(),
            mode,
            root: self
                .observer
                .root_ordinal(&active.candidate.scan_root, roots),
            start: reader
                .acquisition
                .as_ref()
                .map_or(0, |plan| plan.start_offset()),
        };
        let want = self.observer.begin(&view) == Want::Lines;
        self.open = Some((view, want));
    }
    pub(super) fn step(&mut self, parser: &mut OwnedJsonlParser) -> anyhow::Result<bool> {
        let stepped = match &self.open {
            Some((view, true)) => {
                let (observer, counts) = (&mut self.observer, &mut self.counts);
                parser.step_delivering(Some(&mut |length: u64, line: &PhysicalLine<'_>| {
                    counts.lines = counts.lines.saturating_add(1);
                    counts.bytes = counts.bytes.saturating_add(length);
                    observer.line(view, line);
                }))
            }
            _ => parser.step(),
        };
        match stepped {
            Ok(true) if !parser.reader.reader.is_compressed() => {
                self.end_open(DeliveryEnd::Complete)
            }
            Ok(true) => {}
            Ok(false) => {}
            Err(_) => self.end_open(DeliveryEnd::Incomplete),
        }
        stepped
    }
    pub(super) fn archive_complete(&mut self) {
        self.end_open(DeliveryEnd::Complete);
    }
    /// The active file is gone: an armed one never began, an open one ends.
    pub(super) fn left_active(&mut self) {
        self.armed = false;
        self.end_open(DeliveryEnd::Incomplete);
    }
    pub(super) fn take_page(&mut self) -> (&'static str, LineDeliveryCounts) {
        (self.name, std::mem::take(&mut self.counts))
    }
    fn end_open(&mut self, end: DeliveryEnd) {
        let Some((view, want)) = self.open.take() else {
            return;
        };
        if want && end == DeliveryEnd::Incomplete {
            self.counts.incomplete = self.counts.incomplete.saturating_add(1);
        }
        self.observer.end(&view, &end);
    }
}
impl Drop for LineDelivery {
    fn drop(&mut self) {
        self.end_open(DeliveryEnd::Incomplete);
    }
}
impl crate::heap_layout_bound::HeapLayoutBound for LineDelivery {
    fn heap_bound(&self, c: &mut crate::heap_layout_bound::Counter) -> Option<()> {
        c.add(std::mem::size_of_val(&*self.observer).checked_add(self.declared_heap_bytes)?)
    }
}
