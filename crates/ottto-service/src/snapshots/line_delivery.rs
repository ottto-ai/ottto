//! LD: synchronous, RAM-only delivery of the physical lines the one primary
//! reader has already read. It adds no transcript open, seek or read, and no
//! line outlives its callback. A pass registers at most one observer on its
//! `OwnedSourceScan`; proof, parent, one-shot and root parsers never do.

use super::{OwnedActiveFile, OwnedJsonlParser, OwnedSourceScan, SnapshotSource};
use crate::local_resource_diagnostics::{LineDeliveryCounts, LineDeliveryPage};
use crate::transcript_acquisition::{FileObject, FullReason, ReadMode};
use serde_json::Value;
use std::time::{Instant, SystemTime};

/// A consumer of the primary read's physical lines. Calls are synchronous
/// inside the read: O(line), no I/O and no cache or rotation lock. An
/// observer never paces, blocks or retries acquisition.
pub(crate) trait LineObserver {
    /// Fixed diagnostics label (`line_delivery.<name>`).
    fn name(&self) -> &'static str;
    fn begin(&mut self, file: &FileView) -> Want;
    /// Every newline-complete physical line after `Want::Lines`, in order.
    fn line(&mut self, file: &FileView, line: &PhysicalLine<'_>);
    /// Exactly once per `begin`, also after `Want::Skip`.
    fn end(&mut self, file: &FileView, end: &DeliveryEnd);
    /// Requested-layout bound of the observer's own pass state, charged to
    /// the scan like its other owned state. Shared projections are not owned.
    fn heap_bound(&self, c: &mut crate::heap_layout_bound::Counter) -> Option<()>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Want {
    Lines,
    Skip,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DeliveryMode {
    /// Starts at 0: the observer replaces its state for the object. `None`
    /// is a read without a ReadPlan (unsampled, Pi or sampling-ineligible).
    Full(Option<FullReason>),
    /// Starts at the sealed offset of the last acquisition.
    Tail,
    /// Delivers no lines.
    Unchanged,
}

/// One delivered file. No path or key text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct FileView {
    pub(crate) source: SnapshotSource,
    pub(crate) object: FileObject,
    pub(crate) mtime: Option<SystemTime>,
    /// Absolute offset of the first byte this read consumes.
    pub(crate) start: u64,
    pub(crate) mode: DeliveryMode,
}

/// A newline-complete physical line. Blank, malformed and invalid UTF-8
/// lines have no `value`; an overlong line has neither bytes nor value.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) struct PhysicalLine<'a> {
    pub(crate) start: u64,
    /// Just past the newline.
    pub(crate) end: u64,
    /// Without the newline; a `\r` is kept.
    pub(crate) bytes: &'a [u8],
    /// The reader's own parse, which money then receives.
    pub(crate) value: Option<&'a Value>,
    pub(crate) overlong: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum DeliveryEnd {
    /// Every line through `sealed_x` (the last newline) was delivered.
    /// `fragment` is an unterminated tail `(X, L)`: delivered once its
    /// newline arrives, never before.
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum GapCause {
    /// Removed unfinished by a hold or refusal.
    Held,
    ReadFailed,
    /// A paged job paused, or the pass ended or dropped mid-file.
    Yielded,
}

/// Reader-level tap; offsets are relative to the reader's start.
pub(super) type LineTap<'a> = &'a mut dyn FnMut(&PhysicalLine<'_>);

/// One pass's observer and its at most one open file.
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
    /// A paged cursor job: leaving unfinished is a yield.
    cursor: bool,
    /// Absolute end of the last delivered line.
    delivered: u64,
    length: u64,
}

impl OwnedSourceScan {
    /// LD: this pass's observer of its primary reads.
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
    /// A newly opened primary file became the active file. Its final role
    /// is checked at its first dispatch (`begin_armed`).
    pub(super) fn arm(&mut self) {
        self.close(None);
        self.armed = true;
    }

    /// The single begin site, at the common step dispatch.
    pub(super) fn begin_armed(&mut self, active: &OwnedActiveFile) {
        if !std::mem::take(&mut self.armed)
            || active.side_origin.is_some()
            || active.comparison_target
            || active.group.is_some()
        {
            return;
        }
        let reader = &active.parser.reader;
        // One fstat of the held descriptor: metadata only.
        let Ok(held) = reader.reader.get_ref().metadata() else {
            return;
        };
        let Some(object) = FileObject::of(&held) else {
            return;
        };
        let (start, mode) = match reader.acquisition.as_ref() {
            Some(plan) => (
                plan.start_offset(),
                match plan.mode() {
                    ReadMode::Full(reason) => DeliveryMode::Full(Some(reason)),
                    ReadMode::Tail => DeliveryMode::Tail,
                    ReadMode::Unchanged => DeliveryMode::Unchanged,
                },
            ),
            None => (0, DeliveryMode::Full(None)),
        };
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

    /// Step the active primary parser, delivering while its file is open.
    pub(super) fn step(&mut self, parser: &mut OwnedJsonlParser) -> anyhow::Result<bool> {
        let stepped = match self.open.as_mut() {
            None => return parser.step(),
            Some(file) if !file.want => parser.step(),
            Some(file) => {
                let (observer, counts, observer_ns) =
                    (&mut self.observer, &mut self.counts, &mut self.observer_ns);
                let (view, delivered) = (&file.view, &mut file.delivered);
                let base = view.start;
                parser.step_delivering(Some(&mut |line: &PhysicalLine<'_>| {
                    let line = PhysicalLine {
                        start: base + line.start,
                        end: base + line.end,
                        bytes: line.bytes,
                        value: line.value,
                        overlong: line.overlong,
                    };
                    counts.lines = counts.lines.saturating_add(1);
                    counts.bytes = counts.bytes.saturating_add(line.end - line.start);
                    *delivered = line.end;
                    let started = Instant::now();
                    observer.line(view, &line);
                    *observer_ns += started.elapsed().as_nanos();
                }))
            }
        };
        match stepped {
            Ok(false) => {}
            Ok(true) => {
                let sealed = parser.reader.last_complete_line_end();
                let pending = parser.reader.consumed_bytes() - sealed;
                self.end_open(|file| {
                    let sealed_x = file.view.start + sealed;
                    DeliveryEnd::Complete {
                        sealed_x,
                        fragment: (pending > 0).then_some((sealed_x, pending)),
                    }
                });
            }
            Err(_) => self.close(Some(GapCause::ReadFailed)),
        }
        stepped
    }

    /// The active file is gone between steps: an armed file never began, an
    /// open one left unfinished.
    pub(super) fn left_active(&mut self) {
        self.armed = false;
        self.close(None);
    }

    /// This page's counts (`line_delivery` on `native_collection_page`).
    pub(super) fn take_page(&mut self) -> LineDeliveryPage {
        let mut counts = std::mem::take(&mut self.counts);
        counts.observer_us =
            u64::try_from(std::mem::take(&mut self.observer_ns) / 1000).unwrap_or(u64::MAX);
        LineDeliveryPage {
            observer: self.observer.name(),
            counts,
        }
    }

    /// End an open file unfinished; `None` derives the cause from its job.
    fn close(&mut self, cause: Option<GapCause>) {
        self.end_open(|file| DeliveryEnd::Incomplete {
            gaps: vec![Gap {
                from: file.delivered,
                to: file.length.max(file.delivered),
                cause: cause.unwrap_or(if file.cursor {
                    GapCause::Yielded
                } else {
                    GapCause::Held
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

/// A pass dropped mid-file still ends its open file once.
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
