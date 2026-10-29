//! Bounded delivery from the one primary reader. Callbacks borrow its parse;
//! feature boundaries run outside the read and outside native shared locks.
use super::{OwnedActiveFile, OwnedSourceScan, SnapshotSource};
use crate::local_resource_diagnostics::LineDeliveryCounts;
use crate::transcript_acquisition::{FileObject, FullReason, ReadMode};
use serde_json::Value;
use std::time::{Instant, SystemTime};

const INVENTORY: usize = 3;
const GAP_CAUSES: usize = 7;
pub(crate) const fn checked_observer_heap_bytes(bytes: usize) -> usize {
    assert!(bytes <= 256 * 1024);
    bytes
}
const OBSERVER_HEAP_BYTES: usize = checked_observer_heap_bytes(64 * 1024);

/// Fixed registration identity, never an arbitrary diagnostics label.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ObserverId(u8);
impl ObserverId {
    const FOOTPRINT: Self = Self(0);
    const PRELUDE: Self = Self(1);
    fn named(name: &'static str) -> Result<Self, RegistrationError> {
        match name {
            "footprint" => Ok(Self::FOOTPRINT),
            "codex_prelude" => Ok(Self::PRELUDE),
            #[cfg(test)]
            "test" => Ok(Self(2)),
            #[cfg(test)]
            "test_second" => Ok(Self(3)),
            _ => Err(RegistrationError::UnknownId),
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Continuity {
    FreshRead,
    SingletonJob,
}
#[derive(Clone, Copy)]
pub(crate) struct ObserverSpec {
    id: ObserverId,
    name: &'static str,
    source: Option<SnapshotSource>,
    continuity: Continuity,
}
impl ObserverSpec {
    pub(crate) fn named(
        name: &'static str,
        continuity: Continuity,
    ) -> Result<Self, RegistrationError> {
        let id = ObserverId::named(name)?;
        Ok(Self {
            id,
            name,
            source: match id {
                ObserverId::FOOTPRINT => Some(SnapshotSource::ClaudeCode),
                ObserverId::PRELUDE => Some(SnapshotSource::Codex),
                _ => None,
            },
            continuity,
        })
    }
}
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum RegistrationError {
    UnknownId,
    Duplicate,
    InventoryFull,
    HeapBound,
}

/// Pure O(line) callbacks: no I/O, locks, pacing or acquisition authority.
/// Hydration/publication are explicit, separately timed feature boundaries.
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
    fn boundary(&mut self, _event: ObserverBoundary<'_>) {}
    fn begin(&mut self, file: &FileView) -> Want;
    fn line(&mut self, file: &FileView, line: &PhysicalLine<'_>);
    fn line_action(&mut self, file: &FileView, line: &PhysicalLine<'_>) -> LineAction {
        if line.end < line.start {
            return LineAction::Stop {
                gap: Gap {
                    from: line.end,
                    to: line.start,
                    cause: GapCause::ReadFailed,
                    conservative: true,
                },
            };
        }
        self.line(file, line);
        LineAction::Continue
    }
    /// Exactly once per begin, including Skip. Yielded is nonterminal.
    fn end(&mut self, file: &FileView, end: &DeliveryEnd);
    /// Only a feature owner with verified continuous lineage may supply C.
    /// It is an accounted prefix (output plus persisted gaps), never max-seen end.
    /// Native restart/failed-receipt certification is added by P4b, not inferred here.
    fn accounted_prefix(&self, _file: &FileView) -> Option<u64> {
        None
    }
    fn resume(&mut self, _file: &FileView) {}
    fn status(&mut self, _file: &FileView, _cause: GapCause) {}
    /// A selected native exit without a delivery open cannot invent O or X.
    fn unavailable(&mut self, status: &UnavailableView) {
        let _ = (status.source, status.key, status.gap);
    }
}
/// Begin/End boundaries may take a feature lock and publish RAM only (no I/O); callers never hold Stores/cache locks.
/// There is deliberately no durable committer until certified P4b custody is available.
pub(crate) enum ObserverBoundary<'a> {
    Begin(&'a FileView),
    End(&'a FileView, &'a DeliveryEnd),
    Native(&'a FileView, NativeRoute),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Want {
    Lines,
    Skip,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DeliveryMode {
    /// None means the native owner exposed no cause; never infer FirstRead.
    Full {
        cause: Option<FullCause>,
    },
    Tail,
    Unchanged,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FullCause {
    Planned(FullReason),
    Selected(&'static str),
}
impl DeliveryMode {
    pub(crate) fn is_full(self) -> bool {
        matches!(self, Self::Full { .. })
    }
}
#[cfg(unix)]
pub(crate) type RecordKey = crate::durable_tail_store::Digest32;
#[cfg(not(unix))]
pub(crate) type RecordKey = [u8; 32];
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct FileView {
    pub(crate) source: SnapshotSource,
    pub(crate) object: FileObject,
    pub(crate) mtime: Option<SystemTime>,
    pub(crate) mode: DeliveryMode,
    pub(crate) root: Option<u16>,
    pub(crate) start: u64,
    /// Digest exposure alone does not implement D10 move/re-key delivery.
    pub(crate) key: Option<RecordKey>,
    pub(crate) redelivery: bool,
}
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) struct PhysicalLine<'a> {
    pub(crate) start: u64,
    pub(crate) end: u64,
    /// Original bytes without newline, retaining CR. Empty for overlong lines.
    pub(crate) bytes: &'a [u8],
    pub(crate) value: Option<&'a Value>,
    pub(crate) overlong: bool,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(usize)]
pub(crate) enum GapCause {
    RestoredPrefix,
    ProcessStart,
    Held,
    ReadFailed,
    Yielded,
    ObserverOverBudget,
    CommitFailed,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Gap {
    pub(crate) from: u64,
    pub(crate) to: u64,
    pub(crate) cause: GapCause,
    /// Coalesced enclosing spans are coverage summaries, not exact lost bytes.
    pub(crate) conservative: bool,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub(crate) struct Gaps([Option<Gap>; GAP_CAUSES]);
impl GapCause {
    const ALL: [Self; GAP_CAUSES] = [
        Self::RestoredPrefix,
        Self::ProcessStart,
        Self::Held,
        Self::ReadFailed,
        Self::Yielded,
        Self::ObserverOverBudget,
        Self::CommitFailed,
    ];
}
impl Gaps {
    fn insert(&mut self, gap: Gap) {
        debug_assert_eq!(GapCause::ALL[gap.cause as usize], gap.cause);
        let slot = &mut self.0[gap.cause as usize];
        *slot = Some(match *slot {
            None => gap,
            Some(old) => Gap {
                from: old.from.min(gap.from),
                to: old.to.max(gap.to),
                cause: gap.cause,
                conservative: true,
            },
        });
    }
    fn is_empty(&self) -> bool {
        self.0.iter().all(Option::is_none)
    }
    pub(crate) fn iter(&self) -> impl Iterator<Item = &Gap> {
        self.0.iter().flatten()
    }
}
/// Unknown coverage: a zero-width conservative gap carries no lost-byte claim.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct UnavailableView {
    pub(crate) source: SnapshotSource,
    pub(crate) key: Option<RecordKey>,
    pub(crate) gap: Gap,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DeliveryEnd {
    Complete {
        sealed_x: u64,
        fragment: Option<(u64, u64)>,
    },
    Incomplete {
        gaps: Gaps,
    },
}
impl DeliveryEnd {
    pub(crate) fn is_complete(self) -> bool {
        matches!(self, Self::Complete { .. })
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LineAction {
    Continue,
    Stop { gap: Gap },
}

/// Names follow the G1/G2 consuming operations. P4b owns activating the first
/// three routes, their validated cuts, and per-attempt outcome custody.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NativeRoute {
    ResolveUnprepared,
    NativeError,
    FenceOrHeld,
    Unchanged,
}
pub(super) const NATIVE_ROUTE_TABLE: [(&str, &str); 9] = [
    ("Prepared", "before commit_prepared"),
    ("StoreFailed", "before resolve_failed_preparation"),
    ("NotPersisted/Degraded", "before resolve_unprepared"),
    (
        "existing-pending",
        "reuse original outcome before reconcile_receipt",
    ),
    ("native Err", "no data commit"),
    ("fence/Held", "no data commit"),
    ("D3", "feature-independent degraded publish"),
    ("Yielded", "nonterminal; retain the same job"),
    ("Unchanged", "no catch-up; disclose unseen prefix"),
];
/// A completion boundary has no certified cut on the M1 base. No byte counter,
/// file length or money extent is promoted to an acquisition receipt here.
pub(super) fn before_acquisition_commit(
    delivery: &mut LineDelivery,
    job: &mut ParkedDelivery,
    route: NativeRoute,
) {
    debug_assert_eq!(NATIVE_ROUTE_TABLE.len(), 9);
    #[cfg(test)]
    NATIVE_ROUTES.with(|routes| routes.borrow_mut().push(route));
    delivery.before_acquisition_commit(job, route);
}

pub(super) type LineTap<'a> = &'a mut dyn FnMut(u64, &PhysicalLine<'_>);
type ReadEnd = (u64, Option<(u64, u64)>);
struct Open {
    view: FileView,
    want: bool,
    subscribed: bool,
    next: u64,
    gaps: Gaps,
    read_end: Option<ReadEnd>,
}
struct Slot {
    spec: ObserverSpec,
    order: usize,
    observer: Box<dyn LineObserver + Send>,
    open: Option<Open>,
    native_view: Option<FileView>,
    counts: LineDeliveryCounts,
    declared_heap_bytes: usize,
}
impl Slot {
    fn boundary(&mut self, event: ObserverBoundary<'_>) {
        let at = Instant::now();
        self.observer.boundary(event);
        self.counts.boundary_us = self.counts.boundary_us.saturating_add(micros(at));
    }
    fn deliver(&mut self, length: u64, line: &PhysicalLine<'_>) {
        let Some(open) = self.open.as_mut().filter(|o| o.want) else {
            return;
        };
        if self.spec.continuity == Continuity::SingletonJob && line.start != open.next {
            open.gaps.insert(Gap {
                from: open.next.min(line.start),
                to: open.next.max(line.start),
                cause: GapCause::ProcessStart,
                conservative: true,
            });
            open.want = false;
            return;
        }
        open.next = line.end;
        if open.view.redelivery {
            self.counts.redelivered_bytes = self.counts.redelivered_bytes.saturating_add(length);
            if self
                .observer
                .accounted_prefix(&open.view)
                .is_some_and(|c| line.end <= c)
            {
                return;
            }
        }
        self.counts.lines = self.counts.lines.saturating_add(1);
        self.counts.bytes = self.counts.bytes.saturating_add(length);
        let at = Instant::now();
        let action = self.observer.line_action(&open.view, line);
        self.counts.observer_us = self.counts.observer_us.saturating_add(micros(at));
        if let LineAction::Stop { gap } = action {
            open.gaps.insert(gap);
            open.want = false;
        }
    }
    fn finish(&mut self, cause: Option<GapCause>) {
        self.finish_inner(cause, true);
    }
    fn finish_inner(&mut self, cause: Option<GapCause>, publish_ram: bool) {
        let Some(mut open) = self.open.take() else {
            return;
        };
        if let Some(cause) = cause {
            open.gaps.insert(Gap {
                from: open.next,
                to: open.next,
                cause,
                conservative: true,
            });
        }
        let end = match open.read_end.filter(|_| open.gaps.is_empty()) {
            Some((sealed_x, fragment)) => DeliveryEnd::Complete { sealed_x, fragment },
            None => DeliveryEnd::Incomplete { gaps: open.gaps },
        };
        if open.subscribed && !end.is_complete() {
            self.counts.incomplete = self.counts.incomplete.saturating_add(1);
            for gap in open.gaps.iter() {
                let n = &mut self.counts.incomplete_by_cause[gap.cause as usize];
                *n = n.saturating_add(1);
            }
        }
        let at = Instant::now();
        self.observer.end(&open.view, &end);
        self.counts.observer_us = self.counts.observer_us.saturating_add(micros(at));
        if publish_ram {
            self.boundary(ObserverBoundary::End(&open.view, &end));
        }
    }
}
fn ordered_slots(
    first: &mut [Option<Box<Slot>>; INVENTORY],
    second: &mut [Option<Box<Slot>>; INVENTORY],
    mut visit: impl FnMut(&mut Slot),
) {
    for order in 0..INVENTORY {
        for slot in first
            .iter_mut()
            .chain(second.iter_mut())
            .flatten()
            .filter(|s| s.order == order)
        {
            visit(slot);
        }
    }
}
fn micros(at: Instant) -> u64 {
    u64::try_from(at.elapsed().as_micros()).unwrap_or(u64::MAX)
}

/// Fixed slots account inline metadata; no vector capacity or arbitrary labels.
#[derive(Default)]
pub(super) struct LineDelivery {
    slots: [Option<Box<Slot>>; INVENTORY],
    armed: bool,
    registrations: usize,
    page_counts: [Option<(&'static str, LineDeliveryCounts)>; INVENTORY],
}
/// Same move-only subscriber state, owned and charged by the native cursor job.
#[derive(Default)]
pub(super) struct ParkedDelivery {
    slots: [Option<Box<Slot>>; INVENTORY],
    resuming: bool,
}
/// Native active-budget walks must still charge file-local state while the
/// scoped return guard owns it. Attach moves the same graph back and clears
/// this reservation, so parked jobs never count an uncharged copy.
#[derive(Default)]
pub(super) struct DeliveryReservation(usize);
impl crate::heap_layout_bound::HeapLayoutBound for DeliveryReservation {
    fn heap_bound(&self, c: &mut crate::heap_layout_bound::Counter) -> Option<()> {
        c.add(self.0)
    }
}
/// Scoped return of terminal/cancelled file state to this pass's inventory.
/// A live/pause handoff explicitly moves it back to the native job first.
pub(super) struct ActiveDelivery<'a> {
    worker: Option<&'a mut LineDelivery>,
    job: ParkedDelivery,
}
impl<'a> ActiveDelivery<'a> {
    pub(super) fn new(worker: Option<&'a mut LineDelivery>, active: &mut OwnedActiveFile) -> Self {
        let job = std::mem::take(&mut active.line_delivery);
        let mut bound = crate::heap_layout_bound::Counter::new(usize::MAX);
        slots_bound(&job.slots, &mut bound).expect("fixed inventory bound");
        active.delivery_reservation = DeliveryReservation(bound.bytes);
        Self { worker, job }
    }
    pub(super) fn delivery(&mut self) -> Option<&mut LineDelivery> {
        self.worker.as_deref_mut()
    }
    pub(super) fn attach(&mut self, active: &mut OwnedActiveFile) {
        debug_assert!(active.line_delivery.slots.iter().all(Option::is_none));
        active.line_delivery = std::mem::take(&mut self.job);
        active.delivery_reservation = DeliveryReservation::default();
    }
    pub(super) fn step(&mut self, active: &mut OwnedActiveFile) -> anyhow::Result<bool> {
        self.attach(active);
        let result = match self.worker.as_deref_mut() {
            Some(worker) => worker.step(active),
            None => active.parser.step(),
        };
        self.job = std::mem::take(&mut active.line_delivery);
        let mut bound = crate::heap_layout_bound::Counter::new(usize::MAX);
        slots_bound(&self.job.slots, &mut bound).expect("fixed inventory bound");
        active.delivery_reservation = DeliveryReservation(bound.bytes);
        result
    }
    pub(super) fn pause(&mut self, active: &mut OwnedActiveFile) {
        self.attach(active);
        if let Some(worker) = self.worker.as_deref_mut() {
            worker.pause(active);
        }
    }
    pub(super) fn before_acquisition_commit(&mut self, route: NativeRoute) {
        if let Some(worker) = self.worker.as_deref_mut() {
            before_acquisition_commit(worker, &mut self.job, route);
        }
    }
}
impl Drop for ActiveDelivery<'_> {
    fn drop(&mut self) {
        if let Some(worker) = self.worker.as_deref_mut() {
            worker.reclaim_job(&mut self.job);
        }
    }
}
impl ParkedDelivery {
    pub(super) fn mark_resumed(&mut self) {
        self.resuming = true;
    }
}
impl OwnedSourceScan {
    /// Compatibility wrapper; checked inventory registration appends, never replaces.
    pub(crate) fn with_line_observer(
        self,
        name: &'static str,
        observer: Box<dyn LineObserver + Send>,
    ) -> Self {
        let spec = ObserverSpec::named(name, Continuity::FreshRead).expect("compiled observer id");
        self.try_with_line_observer(spec, observer)
            .unwrap_or_else(|error| panic!("invalid line observer: {error:?}"))
    }
    pub(crate) fn try_with_line_observer(
        mut self,
        spec: ObserverSpec,
        observer: Box<dyn LineObserver + Send>,
    ) -> Result<Self, RegistrationError> {
        let result = self
            .line_delivery
            .get_or_insert_with(LineDelivery::default)
            .register(spec, observer);
        result?;
        Ok(self)
    }
}
impl OwnedActiveFile {
    pub(super) fn is_primary_for(&self, source: SnapshotSource) -> bool {
        self.parser.source == source
            && self.side_origin.is_none()
            && !self.comparison_target
            && self.group.is_none()
    }
}
impl LineDelivery {
    fn register(
        &mut self,
        spec: ObserverSpec,
        observer: Box<dyn LineObserver + Send>,
    ) -> Result<(), RegistrationError> {
        if self.slots.iter().flatten().any(|s| s.spec.id == spec.id) {
            return Err(RegistrationError::Duplicate);
        }
        if self.registrations >= INVENTORY {
            return Err(RegistrationError::InventoryFull);
        }
        let declared_heap_bytes = observer.declared_heap_bytes();
        if declared_heap_bytes > 256 * 1024 {
            return Err(RegistrationError::HeapBound);
        }
        let slot = self
            .slots
            .iter_mut()
            .find(|s| s.is_none())
            .ok_or(RegistrationError::InventoryFull)?;
        *slot = Some(Box::new(Slot {
            spec,
            order: self.registrations,
            observer,
            declared_heap_bytes,
            open: None,
            native_view: None,
            counts: LineDeliveryCounts::default(),
        }));
        self.registrations += 1;
        Ok(())
    }
    pub(super) fn arm(&mut self) {
        self.left_active();
        self.armed = true;
    }
    pub(super) fn begin_armed(
        &mut self,
        active: &mut OwnedActiveFile,
        roots: &[std::path::PathBuf],
    ) {
        // File-local subscribers stay with the native owner even if its scan
        // frame drops and returns the job to the cursor. Never duplicate them.
        for slot in active.line_delivery.slots.iter_mut().flatten() {
            if let Some(replacement) = self
                .slots
                .iter_mut()
                .find(|s| s.as_ref().is_some_and(|s| s.spec.id == slot.spec.id))
            {
                slot.order = replacement.as_ref().expect("matched registration").order;
                *replacement = None;
            }
            if active.line_delivery.resuming {
                if let Some(open) = slot.open.as_mut() {
                    open.view.redelivery = true;
                    slot.native_view = Some(open.view);
                    let at = Instant::now();
                    slot.observer.resume(&open.view);
                    slot.counts.observer_us = slot.counts.observer_us.saturating_add(micros(at));
                }
            }
        }
        active.line_delivery.resuming = false;
        if !std::mem::take(&mut self.armed) || !active.is_primary_for(active.parser.source) {
            return;
        }
        if self
            .slots
            .iter()
            .chain(&active.line_delivery.slots)
            .flatten()
            .all(|s| {
                s.spec
                    .source
                    .is_some_and(|source| source != active.parser.source)
            })
        {
            return;
        }
        let reader = &active.parser.reader;
        let Some((object, held)) = FileObject::of(reader.reader.get_ref()) else {
            return;
        };
        let mode = match reader.acquisition.as_ref().map(|plan| plan.mode()) {
            None => DeliveryMode::Full {
                cause: active.delivery_full_cause.map(FullCause::Selected),
            },
            Some(ReadMode::Full(cause)) => DeliveryMode::Full {
                cause: Some(FullCause::Planned(cause)),
            },
            Some(ReadMode::Tail) => DeliveryMode::Tail,
            Some(ReadMode::Unchanged) => DeliveryMode::Unchanged,
        };
        #[cfg(unix)]
        let key =
            super::sampled_scan::durable_tail::durable_source(active.parser.source).map(|source| {
                crate::durable_tail_store::key_digest(
                    source,
                    &super::local_index_key(&active.candidate.path),
                )
            });
        #[cfg(not(unix))]
        let key = None;
        ordered_slots(&mut self.slots, &mut active.line_delivery.slots, |slot| {
            slot.finish(Some(GapCause::Held));
            if slot.spec.source.is_some_and(|s| s != active.parser.source) {
                return;
            }
            let view = FileView {
                source: active.parser.source,
                object,
                mtime: held.modified().ok(),
                mode,
                root: slot
                    .observer
                    .root_ordinal(&active.candidate.scan_root, roots),
                start: reader
                    .acquisition
                    .as_ref()
                    .map_or(0, |plan| plan.start_offset()),
                key,
                redelivery: false,
            };
            slot.boundary(ObserverBoundary::Begin(&view));
            let at = Instant::now();
            let want = slot.observer.begin(&view) == Want::Lines;
            slot.counts.observer_us = slot.counts.observer_us.saturating_add(micros(at));
            let mut gaps = Gaps::default();
            if slot.spec.continuity == Continuity::SingletonJob && view.start > 0 {
                gaps.insert(Gap {
                    from: 0,
                    to: view.start,
                    cause: GapCause::RestoredPrefix,
                    conservative: false,
                });
            }
            slot.native_view = Some(view);
            slot.open = Some(Open {
                view,
                want,
                subscribed: want,
                next: view.start,
                gaps,
                read_end: None,
            });
        });
        for slot in &mut self.slots {
            if slot
                .as_ref()
                .is_some_and(|s| s.spec.continuity == Continuity::SingletonJob && s.open.is_some())
            {
                let dest = active
                    .line_delivery
                    .slots
                    .iter_mut()
                    .find(|s| s.is_none())
                    .expect("funded inventory");
                *dest = slot.take();
            }
        }
    }
    pub(super) fn step(&mut self, active: &mut OwnedActiveFile) -> anyhow::Result<bool> {
        let parser = &mut active.parser;
        let job = &mut active.line_delivery;
        let stepped = parser.step_delivering(Some(&mut |length, line| {
            ordered_slots(&mut self.slots, &mut job.slots, |slot| {
                slot.deliver(length, line)
            });
        }));
        match stepped {
            Ok(true) => {
                let start = parser
                    .reader
                    .acquisition
                    .as_ref()
                    .map_or(0, |p| p.start_offset());
                let sealed_x = start.saturating_add(parser.reader.last_complete_line_end());
                let consumed = start.saturating_add(parser.reader.consumed_bytes());
                let fragment = (consumed > sealed_x).then_some((sealed_x, consumed));
                for slot in self.slots.iter_mut().chain(&mut job.slots).flatten() {
                    if let Some(open) = slot.open.as_mut() {
                        open.read_end = Some((sealed_x, fragment));
                    }
                    // Preserve FreshRead publication at reader EOF.
                    if slot.spec.continuity == Continuity::FreshRead {
                        slot.finish(None);
                    }
                }
            }
            Err(_) => {
                before_acquisition_commit(self, job, NativeRoute::NativeError);
                for slot in self.slots.iter_mut().chain(&mut job.slots).flatten() {
                    slot.finish(Some(GapCause::ReadFailed));
                }
            }
            Ok(false) => {}
        }
        stepped
    }
    pub(super) fn pause(&mut self, active: &mut OwnedActiveFile) {
        for slot in self.slots.iter_mut().flatten() {
            slot.finish(Some(GapCause::Yielded));
        }
        for slot in active.line_delivery.slots.iter_mut().flatten() {
            if let Some(open) = &slot.open {
                let at = Instant::now();
                slot.observer.status(&open.view, GapCause::Yielded);
                slot.counts.observer_us = slot.counts.observer_us.saturating_add(micros(at));
            }
        }
        active.line_delivery.resuming = true;
        self.drain_job_counts(&mut active.line_delivery);
    }
    fn reclaim_job(&mut self, job: &mut ParkedDelivery) {
        for slot in job.slots.iter_mut().flatten() {
            // A native exit may precede finish. Only pure terminal notification
            // here; the normal worker boundary handles unavailable provenance.
            slot.finish_inner(Some(GapCause::Held), false);
        }
        self.drain_job_counts(job);
        for slot in &mut job.slots {
            if let Some(slot) = slot.take() {
                self.registrations = self.registrations.max(slot.order + 1);
                if let Some(dest) = self.slots.iter_mut().find(|s| s.is_none()) {
                    *dest = Some(slot);
                }
            }
        }
    }
    fn drain_job_counts(&mut self, job: &mut ParkedDelivery) {
        for slot in job.slots.iter_mut().flatten() {
            let name = slot.spec.name;
            let dest = if let Some(i) = self
                .page_counts
                .iter()
                .position(|s| s.is_some_and(|s| s.0 == name))
            {
                i
            } else {
                self.page_counts
                    .iter()
                    .position(Option::is_none)
                    .expect("fixed inventory counts")
            };
            let counts =
                self.page_counts[dest].get_or_insert((name, LineDeliveryCounts::default()));
            counts.1.add(std::mem::take(&mut slot.counts));
        }
    }
    fn before_acquisition_commit(&mut self, job: &mut ParkedDelivery, route: NativeRoute) {
        ordered_slots(&mut self.slots, &mut job.slots, |slot| {
            if let Some(view) = slot.native_view.take() {
                slot.boundary(ObserverBoundary::Native(&view, route));
            }
            if slot.spec.continuity == Continuity::SingletonJob {
                slot.finish(match route {
                    NativeRoute::ResolveUnprepared => None,
                    NativeRoute::NativeError => Some(GapCause::ReadFailed),
                    NativeRoute::FenceOrHeld => Some(GapCause::Held),
                    NativeRoute::Unchanged => Some(GapCause::RestoredPrefix),
                });
            }
        });
        self.drain_job_counts(job);
    }
    pub(super) fn left_active(&mut self) {
        self.armed = false;
        before_acquisition_commit(
            self,
            &mut ParkedDelivery::default(),
            NativeRoute::FenceOrHeld,
        );
        for slot in self.slots.iter_mut().flatten() {
            slot.finish(Some(GapCause::Held));
        }
    }
    pub(super) fn unavailable(
        &mut self,
        source: SnapshotSource,
        index_key: &str,
        route: NativeRoute,
    ) {
        before_acquisition_commit(self, &mut ParkedDelivery::default(), route);
        #[cfg(unix)]
        let key = super::sampled_scan::durable_tail::durable_source(source)
            .map(|s| crate::durable_tail_store::key_digest(s, index_key));
        #[cfg(not(unix))]
        let key = {
            let _ = index_key;
            None
        };
        let cause = if route == NativeRoute::Unchanged {
            GapCause::RestoredPrefix
        } else {
            GapCause::Held
        };
        let status = UnavailableView {
            source,
            key,
            gap: Gap {
                from: 0,
                to: 0,
                cause,
                conservative: true,
            },
        };
        for slot in self.slots.iter_mut().flatten().filter(|s| {
            s.spec.continuity == Continuity::SingletonJob
                && s.spec.source.map_or(true, |s| s == source)
        }) {
            let at = Instant::now();
            slot.observer.unavailable(&status);
            slot.counts.observer_us = slot.counts.observer_us.saturating_add(micros(at));
            slot.counts.incomplete = slot.counts.incomplete.saturating_add(1);
            let n = &mut slot.counts.incomplete_by_cause[cause as usize];
            *n = n.saturating_add(1);
        }
    }
    pub(super) fn take_page(
        &mut self,
    ) -> std::collections::BTreeMap<&'static str, LineDeliveryCounts> {
        let mut counts: std::collections::BTreeMap<_, _> = self
            .page_counts
            .iter_mut()
            .filter_map(Option::take)
            .collect();
        for slot in self.slots.iter_mut().flatten() {
            counts
                .entry(slot.spec.name)
                .or_default()
                .add(std::mem::take(&mut slot.counts));
        }
        counts
    }
}
impl Drop for LineDelivery {
    fn drop(&mut self) {
        // End boundaries publish RAM only; native commit is never called in Drop.
        for slot in self.slots.iter_mut().flatten() {
            slot.finish(Some(GapCause::ProcessStart));
        }
    }
}
impl Drop for ParkedDelivery {
    fn drop(&mut self) {
        // Native cursor custody may be destroyed while its mutex is held.
        // Only the pure terminal callback is legal here: no feature boundary.
        for slot in self.slots.iter_mut().flatten() {
            slot.finish_inner(Some(GapCause::ProcessStart), false);
        }
    }
}
fn slots_bound(
    slots: &[Option<Box<Slot>>; INVENTORY],
    c: &mut crate::heap_layout_bound::Counter,
) -> Option<()> {
    for slot in slots.iter().flatten() {
        c.add(std::mem::size_of::<Slot>().checked_add(std::mem::align_of::<Slot>())?)?;
        c.add(
            std::mem::size_of_val(&*slot.observer)
                .checked_add(std::mem::align_of_val(&*slot.observer))?
                .checked_add(slot.declared_heap_bytes)?,
        )?;
    }
    Some(())
}
impl crate::heap_layout_bound::HeapLayoutBound for LineDelivery {
    fn heap_bound(&self, c: &mut crate::heap_layout_bound::Counter) -> Option<()> {
        slots_bound(&self.slots, c)
    }
}
impl crate::heap_layout_bound::HeapLayoutBound for ParkedDelivery {
    fn heap_bound(&self, c: &mut crate::heap_layout_bound::Counter) -> Option<()> {
        slots_bound(&self.slots, c)
    }
}

#[cfg(test)]
thread_local! { static NATIVE_ROUTES: std::cell::RefCell<Vec<NativeRoute>> = const { std::cell::RefCell::new(Vec::new()) }; }
#[cfg(test)]
pub(super) fn take_native_routes() -> Vec<NativeRoute> {
    NATIVE_ROUTES.with(|routes| std::mem::take(&mut *routes.borrow_mut()))
}

#[cfg(test)]
pub(crate) trait TestObserverBoundary: LineObserver {
    fn begin_at_boundary(&mut self, view: &FileView) -> Want {
        self.boundary(ObserverBoundary::Begin(view));
        self.begin(view)
    }
    fn end_at_boundary(&mut self, view: &FileView, end: &DeliveryEnd) {
        self.end(view, end);
        self.boundary(ObserverBoundary::End(view, end));
    }
}
#[cfg(test)]
impl<T: LineObserver + ?Sized> TestObserverBoundary for T {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    type Calls = Arc<Mutex<Vec<(&'static str, u64, usize)>>>;
    struct Observer {
        name: &'static str,
        calls: Calls,
        c: Option<u64>,
        stop: bool,
        heap: usize,
    }
    impl LineObserver for Observer {
        fn declared_heap_bytes(&self) -> usize {
            self.heap
        }
        fn begin(&mut self, _: &FileView) -> Want {
            Want::Lines
        }
        fn line(&mut self, _: &FileView, line: &PhysicalLine<'_>) {
            self.calls.lock().unwrap().push((
                self.name,
                line.end,
                line.value.map_or(0, |v| v as *const Value as usize),
            ));
        }
        fn accounted_prefix(&self, _: &FileView) -> Option<u64> {
            self.c
        }
        fn line_action(&mut self, file: &FileView, line: &PhysicalLine<'_>) -> LineAction {
            self.line(file, line);
            if self.stop {
                LineAction::Stop {
                    gap: Gap {
                        from: line.start,
                        to: line.end,
                        cause: GapCause::ObserverOverBudget,
                        conservative: false,
                    },
                }
            } else {
                LineAction::Continue
            }
        }
        fn end(&mut self, _: &FileView, _: &DeliveryEnd) {}
    }
    fn observer(name: &'static str, calls: &Calls) -> Box<Observer> {
        Box::new(Observer {
            name,
            calls: Arc::clone(calls),
            c: None,
            stop: false,
            heap: 1024,
        })
    }
    fn view() -> FileView {
        FileView {
            source: SnapshotSource::ClaudeCode,
            object: FileObject::from_opened_identity(Some([1, 2]), 1_000_000_000).unwrap(),
            mtime: None,
            mode: DeliveryMode::Full { cause: None },
            root: None,
            start: 0,
            key: None,
            redelivery: false,
        }
    }
    fn open(slot: &mut Slot, file: FileView) {
        slot.open = Some(Open {
            view: file,
            want: true,
            subscribed: true,
            next: file.start,
            gaps: Gaps::default(),
            read_end: None,
        });
    }
    #[test]
    fn ld2_registration_is_bounded_append_only_and_charges_every_box() {
        use crate::heap_layout_bound::{Counter, HeapLayoutBound};
        let calls = Calls::default();
        let mut delivery = LineDelivery::default();
        let spec = ObserverSpec::named("test", Continuity::FreshRead).unwrap();
        delivery.register(spec, observer("a", &calls)).unwrap();
        assert_eq!(
            delivery.register(spec, observer("duplicate", &calls)),
            Err(RegistrationError::Duplicate)
        );
        assert_eq!(
            ObserverSpec::named("arbitrary", Continuity::FreshRead).err(),
            Some(RegistrationError::UnknownId)
        );
        let second = ObserverSpec::named("test_second", Continuity::SingletonJob).unwrap();
        let mut over = observer("over", &calls);
        over.heap = 256 * 1024 + 1;
        assert_eq!(
            delivery.register(second, over),
            Err(RegistrationError::HeapBound)
        );
        delivery.register(second, observer("b", &calls)).unwrap();
        let mut counter = Counter::new(usize::MAX);
        delivery.heap_bound(&mut counter).unwrap();
        let expected = 2
            * (std::mem::size_of::<Slot>()
                + std::mem::align_of::<Slot>()
                + std::mem::size_of::<Observer>()
                + std::mem::align_of::<Observer>()
                + 1024);
        assert_eq!(counter.bytes, expected);
        delivery
            .register(
                ObserverSpec::named("footprint", Continuity::FreshRead).unwrap(),
                observer("third", &calls),
            )
            .unwrap();
        assert_eq!(
            delivery.register(
                ObserverSpec::named("codex_prelude", Continuity::FreshRead).unwrap(),
                observer("fourth", &calls)
            ),
            Err(RegistrationError::InventoryFull)
        );
    }
    #[test]
    fn ld2_fanout_preserves_parse_identity_order_and_local_stop_across_owners() {
        let calls = Calls::default();
        let mut delivery = LineDelivery::default();
        let mut first = observer("first", &calls);
        first.stop = true;
        delivery
            .register(
                ObserverSpec::named("test", Continuity::SingletonJob).unwrap(),
                first,
            )
            .unwrap();
        delivery
            .register(
                ObserverSpec::named("test_second", Continuity::FreshRead).unwrap(),
                observer("second", &calls),
            )
            .unwrap();
        for slot in delivery.slots.iter_mut().flatten() {
            open(slot, view());
        }
        let mut job = ParkedDelivery::default();
        job.slots[0] = delivery.slots[0].take();
        let value = serde_json::json!({"n":1});
        for (start, end) in [(0, 2), (2, 4)] {
            let line = PhysicalLine {
                start,
                end,
                bytes: b"1",
                value: Some(&value),
                overlong: false,
            };
            ordered_slots(&mut delivery.slots, &mut job.slots, |s| s.deliver(2, &line));
        }
        let ptr = &value as *const Value as usize;
        assert_eq!(
            *calls.lock().unwrap(),
            [("first", 2, ptr), ("second", 2, ptr), ("second", 4, ptr)]
        );
        let first = job.slots[0].as_ref().unwrap();
        assert_eq!(
            first.open.as_ref().unwrap().gaps.0[GapCause::ObserverOverBudget as usize]
                .unwrap()
                .from,
            0
        );
        assert_eq!(delivery.slots[1].as_ref().unwrap().counts.lines, 2);
    }
    #[test]
    fn ld2_end_le_c_dedup_is_redelivery_only_and_full_resets_the_binding() {
        let calls = Calls::default();
        let mut delivery = LineDelivery::default();
        let mut consumer = observer("accounted", &calls);
        consumer.c = Some(4);
        delivery
            .register(
                ObserverSpec::named("test", Continuity::SingletonJob).unwrap(),
                consumer,
            )
            .unwrap();
        let slot = delivery.slots[0].as_mut().unwrap();
        let mut file = view();
        file.mode = DeliveryMode::Tail;
        file.redelivery = true;
        open(slot, file);
        for (start, end) in [(0, 2), (2, 4), (4, 6)] {
            slot.deliver(
                2,
                &PhysicalLine {
                    start,
                    end,
                    bytes: b"x",
                    value: None,
                    overlong: false,
                },
            );
        }
        assert_eq!(*calls.lock().unwrap(), [("accounted", 6, 0)]);
        assert_eq!(slot.counts.redelivered_bytes, 6);
        assert_eq!(slot.counts.bytes, 2);
        open(slot, view());
        slot.deliver(
            2,
            &PhysicalLine {
                start: 0,
                end: 2,
                bytes: b"x",
                value: None,
                overlong: false,
            },
        );
        assert_eq!(
            *calls.lock().unwrap(),
            [("accounted", 6, 0), ("accounted", 2, 0)]
        );
    }
    #[test]
    fn ld2_gaps_coalesce_by_cause_without_exact_loss_claims() {
        let mut gaps = Gaps::default();
        for cause in GapCause::ALL {
            gaps.insert(Gap {
                from: 2,
                to: 4,
                cause,
                conservative: false,
            });
            gaps.insert(Gap {
                from: 8,
                to: 9,
                cause,
                conservative: false,
            });
        }
        assert_eq!(gaps.0.iter().flatten().count(), 7);
        for gap in gaps.0.iter().flatten() {
            assert_eq!((gap.from, gap.to, gap.conservative), (2, 9, true));
        }
        assert!(!DeliveryEnd::Incomplete { gaps }.is_complete());
    }
    #[test]
    fn ld2_offset_mismatch_stops_only_the_subscription() {
        let calls = Calls::default();
        let mut delivery = LineDelivery::default();
        delivery
            .register(
                ObserverSpec::named("test", Continuity::SingletonJob).unwrap(),
                observer("one", &calls),
            )
            .unwrap();
        let slot = delivery.slots[0].as_mut().unwrap();
        open(slot, view());
        slot.deliver(
            2,
            &PhysicalLine {
                start: 4,
                end: 6,
                bytes: b"x",
                value: None,
                overlong: false,
            },
        );
        assert!(calls.lock().unwrap().is_empty());
        let state = slot.open.as_ref().unwrap();
        assert!(!state.want);
        assert_eq!(state.gaps.0[GapCause::ProcessStart as usize].unwrap().to, 4);
    }
    #[test]
    fn ld2_route_table_covers_g1_g2_and_keeps_empty_inventory_live() {
        assert_eq!(
            NATIVE_ROUTE_TABLE[0],
            ("Prepared", "before commit_prepared")
        );
        assert_eq!(
            NATIVE_ROUTE_TABLE[1],
            ("StoreFailed", "before resolve_failed_preparation")
        );
        assert_eq!(
            NATIVE_ROUTE_TABLE[2],
            ("NotPersisted/Degraded", "before resolve_unprepared")
        );
        assert_eq!(NATIVE_ROUTE_TABLE[3].0, "existing-pending");
        let mut delivery = LineDelivery::default();
        let mut job = ParkedDelivery::default();
        for route in [
            NativeRoute::ResolveUnprepared,
            NativeRoute::NativeError,
            NativeRoute::FenceOrHeld,
        ] {
            before_acquisition_commit(&mut delivery, &mut job, route);
        }
        assert!(delivery.take_page().is_empty());
    }
}
