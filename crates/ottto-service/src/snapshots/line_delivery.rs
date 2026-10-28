//! LD: RAM-only delivery of the lines the one primary reader already read; no
//! transcript open, seek or read is added and no line outlives its callback.
use super::{OwnedActiveFile, OwnedJsonlParser, OwnedSourceScan, SnapshotSource};
use crate::local_resource_diagnostics::LineDeliveryCounts;
use crate::transcript_acquisition::{FileObject, ReadMode};
use serde_json::Value;
use std::time::SystemTime;

/// The scan's heap bound charges an observer's pass state as this constant.
const OBSERVER_HEAP_BYTES: usize = 64 * 1024;
/// Synchronous in the read: O(line), no I/O or cache/rotation lock, pass
/// state within `OBSERVER_HEAP_BYTES`; never paces or blocks acquisition.
pub(crate) trait LineObserver {
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
}
/// A complete line's one parse; none if blank, malformed, non-UTF-8 or overlong.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) struct PhysicalLine<'a> {
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
}
impl OwnedSourceScan {
    /// `name` keys the page counts (`line_delivery.<name>`).
    pub(crate) fn with_line_observer(
        mut self,
        name: &'static str,
        observer: Box<dyn LineObserver + Send>,
    ) -> Self {
        self.line_delivery = Some(LineDelivery {
            name,
            observer,
            armed: false,
            open: None,
            counts: LineDeliveryCounts::default(),
        });
        self
    }
}
impl LineDelivery {
    /// A fresh primary read of the active file: opened, or replaced in place.
    pub(super) fn arm(&mut self) {
        self.end_open(DeliveryEnd::Incomplete);
        self.armed = true;
    }
    /// The single begin site: the common step dispatch, roles final.
    pub(super) fn begin_armed(&mut self, active: &OwnedActiveFile) {
        if !std::mem::take(&mut self.armed)
            || active.side_origin.is_some()
            || active.comparison_target
            || active.group.is_some()
        {
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
        c.add(std::mem::size_of_val(&*self.observer).checked_add(OBSERVER_HEAP_BYTES)?)
    }
}
