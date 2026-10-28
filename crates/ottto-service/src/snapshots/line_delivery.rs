//! LD: synchronous, RAM-only delivery of the physical lines the one primary
//! reader already read. No transcript open, seek or read is added and no line
//! outlives its callback. Only `OwnedSourceScan` registers an observer.

use super::{OwnedActiveFile, OwnedJsonlParser, OwnedSourceScan, SnapshotSource};
use crate::local_resource_diagnostics::LineDeliveryCounts;
use crate::transcript_acquisition::{FileObject, FullReason, ReadMode};
use serde_json::Value;
use std::time::{Instant, SystemTime};

/// Called synchronously inside the read: O(line), no I/O, no cache or
/// rotation lock; it never paces, blocks or retries acquisition.
pub(crate) trait LineObserver {
    /// Fixed diagnostics key (`line_delivery.<name>`).
    fn name(&self) -> &'static str;
    fn begin(&mut self, file: &FileView) -> Want;
    fn line(&mut self, file: &FileView, line: &PhysicalLine<'_>);
    /// Exactly once per `begin`, `Want::Skip` included.
    fn end(&mut self, file: &FileView, end: &DeliveryEnd);
    /// The observer's own pass state, charged to the scan's heap bound.
    fn heap_bound(&self, c: &mut crate::heap_layout_bound::Counter) -> Option<()>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Want {
    Lines,
    Skip,
}

/// `Full` starts at 0 and replaces the object's state; `None` is a read
/// without a ReadPlan (unsampled, Pi or sampling-ineligible). `Tail` starts
/// at the sealed offset; `Unchanged` delivers nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DeliveryMode {
    Full(Option<FullReason>),
    Tail,
    Unchanged,
}

/// No path or key text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct FileView {
    pub(crate) source: SnapshotSource,
    pub(crate) object: FileObject,
    pub(crate) mtime: Option<SystemTime>,
    pub(crate) start: u64,
    pub(crate) mode: DeliveryMode,
}

/// A newline-complete line: absolute offsets, `end` past the newline, bytes
/// without it (`\r` kept), the reader's one parse. Blank, malformed and
/// invalid UTF-8 lines have no value; overlong lines no bytes either.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) struct PhysicalLine<'a> {
    pub(crate) start: u64,
    pub(crate) end: u64,
    pub(crate) bytes: &'a [u8],
    pub(crate) value: Option<&'a Value>,
    pub(crate) overlong: bool,
}

/// `fragment` is an unterminated tail `(X, L)`, delivered after its newline.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum DeliveryEnd {
    Complete {
        sealed_x: u64,
        fragment: Option<(u64, u64)>,
    },
    Incomplete {
        gaps: Vec<Gap>,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Gap {
    pub(crate) from: u64,
    pub(crate) to: u64,
    pub(crate) cause: GapCause,
}

/// `Held`: removed unfinished by a hold or refusal. `Yielded`: a paged job
/// paused, or the pass ended or dropped mid-file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum GapCause {
    Held,
    ReadFailed,
    Yielded,
}

/// Reader-level tap; offsets are relative to the reader's start.
pub(super) type LineTap<'a> = &'a mut dyn FnMut(&PhysicalLine<'_>);

pub(super) struct LineDelivery {
    observer: Box<dyn LineObserver + Send>,
    /// A fresh primary file is active and not yet dispatched.
    armed: bool,
    open: Option<OpenFile>,
    counts: LineDeliveryCounts,
    observer_ns: u128,
}

struct OpenFile {
    view: FileView,
    want: bool,
    cursor: bool,
    delivered: u64,
    length: u64,
}

impl OwnedSourceScan {
    pub(crate) fn with_line_observer(mut self, observer: Box<dyn LineObserver + Send>) -> Self {
        self.line_delivery = Some(LineDelivery {
            observer,
            armed: false,
            open: None,
            counts: LineDeliveryCounts::default(),
            observer_ns: 0,
        });
        self
    }
}

impl LineDelivery {
    /// A newly opened primary file became active.
    pub(super) fn arm(&mut self) {
        self.close(None);
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
        // One fstat of the held descriptor.
        let Ok(held) = reader.reader.get_ref().metadata() else {
            return;
        };
        let Some(object) = FileObject::of(&held) else {
            return;
        };
        let (start, mode) =
            reader
                .acquisition
                .as_ref()
                .map_or((0, DeliveryMode::Full(None)), |plan| {
                    let mode = match plan.mode() {
                        ReadMode::Full(reason) => DeliveryMode::Full(Some(reason)),
                        ReadMode::Tail => DeliveryMode::Tail,
                        ReadMode::Unchanged => DeliveryMode::Unchanged,
                    };
                    (plan.start_offset(), mode)
                });
        let view = FileView {
            source: active.parser.source,
            object,
            mtime: held.modified().ok(),
            start,
            mode,
        };
        let started = Instant::now();
        let want = self.observer.begin(&view) == Want::Lines;
        self.observer_ns += started.elapsed().as_nanos();
        self.open = Some(OpenFile {
            view,
            want,
            cursor: active.cursor.is_some(),
            delivered: start,
            length: held.len(),
        });
    }

    pub(super) fn step(&mut self, parser: &mut OwnedJsonlParser) -> anyhow::Result<bool> {
        let stepped = match self.open.as_mut() {
            Some(file) if file.want => {
                let (observer, counts, ns) =
                    (&mut self.observer, &mut self.counts, &mut self.observer_ns);
                let (view, delivered) = (&file.view, &mut file.delivered);
                parser.step_delivering(Some(&mut |line: &PhysicalLine<'_>| {
                    let line = PhysicalLine {
                        start: view.start + line.start,
                        end: view.start + line.end,
                        ..*line
                    };
                    counts.lines = counts.lines.saturating_add(1);
                    counts.bytes = counts.bytes.saturating_add(line.end - line.start);
                    *delivered = line.end;
                    let started = Instant::now();
                    observer.line(view, &line);
                    *ns += started.elapsed().as_nanos();
                }))
            }
            _ => parser.step(),
        };
        match stepped {
            Ok(true) => {
                let sealed = parser.reader.last_complete_line_end();
                let pending = parser.reader.consumed_bytes() - sealed;
                self.end_open(|file| DeliveryEnd::Complete {
                    sealed_x: file.view.start + sealed,
                    fragment: (pending > 0).then_some((file.view.start + sealed, pending)),
                });
            }
            Ok(false) => {}
            Err(_) => self.close(Some(GapCause::ReadFailed)),
        }
        stepped
    }

    /// The active file is gone: an armed one never began, an open one ends.
    pub(super) fn left_active(&mut self) {
        self.armed = false;
        self.close(None);
    }

    pub(super) fn take_page(&mut self) -> (&'static str, LineDeliveryCounts) {
        let mut counts = std::mem::take(&mut self.counts);
        let ns = std::mem::take(&mut self.observer_ns);
        counts.observer_us = u64::try_from(ns / 1000).unwrap_or(u64::MAX);
        (self.observer.name(), counts)
    }

    /// End an open file unfinished; `None` derives the cause from its job.
    fn close(&mut self, cause: Option<GapCause>) {
        self.end_open(|file| DeliveryEnd::Incomplete {
            gaps: vec![Gap {
                from: file.delivered,
                to: file.length.max(file.delivered),
                cause: cause.unwrap_or(match file.cursor {
                    true => GapCause::Yielded,
                    false => GapCause::Held,
                }),
            }],
        });
    }

    fn end_open(&mut self, end: impl FnOnce(&OpenFile) -> DeliveryEnd) {
        let Some(file) = self.open.take() else {
            return;
        };
        let end = end(&file);
        if let (true, DeliveryEnd::Incomplete { gaps }) = (file.want, &end) {
            let incomplete = &mut self.counts.incomplete;
            for gap in gaps {
                let count = match gap.cause {
                    GapCause::Held => &mut incomplete.held,
                    GapCause::ReadFailed => &mut incomplete.read_failure,
                    GapCause::Yielded => &mut incomplete.yielded,
                };
                *count = count.saturating_add(1);
            }
        }
        let started = Instant::now();
        self.observer.end(&file.view, &end);
        self.observer_ns += started.elapsed().as_nanos();
    }
}

impl Drop for LineDelivery {
    fn drop(&mut self) {
        self.close(Some(GapCause::Yielded));
    }
}

impl crate::heap_layout_bound::HeapLayoutBound for LineDelivery {
    fn heap_bound(&self, c: &mut crate::heap_layout_bound::Counter) -> Option<()> {
        let observer = &*self.observer;
        c.add(std::mem::size_of_val(observer).checked_add(std::mem::align_of_val(observer))?)?;
        observer.heap_bound(c)
    }
}
