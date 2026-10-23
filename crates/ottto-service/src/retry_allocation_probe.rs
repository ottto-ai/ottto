// Test-only requested/usable allocator probe, per test thread.
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

#[derive(Clone, Copy, Default, Debug)]
pub(crate) struct Stats {
    pub requested_live: isize,
    pub usable_live: isize,
    pub requested_peak: usize,
    pub usable_peak: usize,
    pub requested_peak_with_overlap: usize,
    pub usable_peak_with_overlap: usize,
    // Successful allocation/retirement events; realloc counts once in each.
    pub deallocations: usize,
    pub allocations: usize,
}

thread_local! {
    static ACTIVE: Cell<bool> = const { Cell::new(false) };
    static STATS: Cell<Stats> = Cell::new(Stats::default());
    static PHASE_BASE: Cell<isize> = const { Cell::new(0) };
    static PHASE_PEAK: Cell<usize> = const { Cell::new(0) };
}

#[cfg(target_os = "macos")]
extern "C" {
    fn malloc_size(ptr: *const std::ffi::c_void) -> usize;
}

unsafe fn usable(ptr: *const std::ffi::c_void, requested: usize) -> usize {
    #[cfg(target_os = "macos")]
    {
        let _ = requested;
        malloc_size(ptr)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = ptr;
        requested
    }
}
// Test-only sampling at allocator events; this is the SHARED admission
// counter, not an exact per-phase reservation high-water mark. Reservations
// with no caller allocation between admission/drop are deliberately unobserved.
thread_local! {
    static MONEY_ADMISSION_SAMPLE: Cell<Option<usize>> = const { Cell::new(None) };
}
fn sample_money_admission() {
    let _ = MONEY_ADMISSION_SAMPLE.try_with(|sample| {
        if let Some(peak) = sample.get() {
            sample.set(Some(
                peak.max(crate::snapshots::claude_request_money::reserved_for_test()),
            ));
        }
    });
}

pub(crate) fn measure_money_caller_thread<T>(f: impl FnOnce() -> T) -> (T, Stats, usize) {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            MONEY_ADMISSION_SAMPLE.with(|sample| sample.set(None));
        }
    }
    MONEY_ADMISSION_SAMPLE.with(|sample| {
        assert!(sample.get().is_none());
        sample.set(Some(
            crate::snapshots::claude_request_money::reserved_for_test(),
        ));
    });
    let reset = Reset;
    let (value, stats) = measure_caller_thread(f);
    let peak = MONEY_ADMISSION_SAMPLE.with(|sample| sample.get().unwrap());
    drop(reset);
    (value, stats, peak)
}

// Opt-in settlement-only receipts. The synchronous production region uses the
// same born-pointer table as a whole-caller audit, so these are separate modes.
// Fixed receipt storage and atomic reservation sampling allocate no heap.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct MoneySettlementReceipt {
    pub required: usize,
    pub offered: usize,
    pub admitted: bool,
    pub funds: usize,
    pub pairs: usize,
    pub skipped: bool,
    pub allocation: Stats,
    pub shared_admission_peak: usize,
}

#[derive(Clone, Copy)]
pub(crate) struct MoneySettlementReceipts {
    entries: [Option<MoneySettlementReceipt>; 64],
    len: usize,
}
impl MoneySettlementReceipts {
    const EMPTY: Self = Self {
        entries: [None; 64],
        len: 0,
    };
    pub(crate) fn iter(&self) -> impl Iterator<Item = &MoneySettlementReceipt> {
        self.entries[..self.len]
            .iter()
            .map(|receipt| receipt.as_ref().unwrap())
    }
}
thread_local! {
    static MONEY_SETTLEMENT_RECEIPTS: Cell<Option<MoneySettlementReceipts>> = const { Cell::new(None) };
    static MONEY_SETTLEMENT_CURRENT: Cell<MoneySettlementReceipt> = Cell::new(MoneySettlementReceipt::default());
}
static MONEY_ADMISSION_OBSERVING: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);
static MONEY_ADMISSION_HIGH_WATER: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

// Linearize the test observer's start/stop with reservation mutations. Without
// this guard a delayed callback could land after the receipt has been closed.
static MONEY_ADMISSION_EVENTS: std::sync::Mutex<()> = std::sync::Mutex::new(());
pub(crate) fn money_admission_event() -> std::sync::MutexGuard<'static, ()> {
    MONEY_ADMISSION_EVENTS
        .lock()
        .unwrap_or_else(|p| p.into_inner())
}

// Called at every successful admit, shrink and drop, including writer events.
// The value comes from that atomic mutation, rather than a later racy load.
pub(crate) fn money_admission_changed(total: usize) {
    use std::sync::atomic::Ordering;
    if MONEY_ADMISSION_OBSERVING.load(Ordering::Acquire) {
        MONEY_ADMISSION_HIGH_WATER.fetch_max(total, Ordering::AcqRel);
    }
}
fn push_money_settlement(receipt: MoneySettlementReceipt) {
    MONEY_SETTLEMENT_RECEIPTS.with(|cell| {
        if let Some(mut receipts) = cell.get() {
            assert!(
                receipts.len < receipts.entries.len(),
                "settlement receipt overflow"
            );
            receipts.entries[receipts.len] = Some(receipt);
            receipts.len += 1;
            cell.set(Some(receipts));
        }
    });
}
pub(crate) fn money_settlement_skipped() {
    push_money_settlement(MoneySettlementReceipt {
        skipped: true,
        ..Default::default()
    });
}
pub(crate) fn money_settlement_admitted(funds: usize) {
    MONEY_SETTLEMENT_CURRENT.with(|cell| {
        let mut receipt = cell.get();
        receipt.admitted = true;
        receipt.funds = funds;
        cell.set(receipt);
    });
}
pub(crate) fn money_settlement_pairs(pairs: usize) {
    MONEY_SETTLEMENT_CURRENT.with(|cell| {
        let mut receipt = cell.get();
        receipt.pairs = pairs;
        cell.set(receipt);
    });
}
pub(crate) fn observe_money_settlement<T>(
    required: usize,
    offered: usize,
    f: impl FnOnce() -> T,
) -> T {
    use std::sync::atomic::Ordering;
    if !MONEY_SETTLEMENT_RECEIPTS.with(|cell| cell.get().is_some()) {
        return f();
    }
    MONEY_SETTLEMENT_CURRENT.with(|cell| {
        cell.set(MoneySettlementReceipt {
            required,
            offered,
            ..Default::default()
        })
    });
    {
        let _event = money_admission_event();
        MONEY_ADMISSION_HIGH_WATER.store(
            crate::snapshots::claude_request_money::reserved_for_test(),
            Ordering::Release,
        );
        assert!(!MONEY_ADMISSION_OBSERVING.swap(true, Ordering::AcqRel));
    }
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            let _event = money_admission_event();
            MONEY_ADMISSION_OBSERVING.store(false, Ordering::Release);
        }
    }
    let reset = Reset;
    let (value, allocation) = measure_caller_thread(f);
    drop(reset);
    let mut receipt = MONEY_SETTLEMENT_CURRENT.with(Cell::get);
    receipt.allocation = allocation;
    receipt.shared_admission_peak = MONEY_ADMISSION_HIGH_WATER.load(Ordering::Acquire);
    push_money_settlement(receipt);
    value
}
pub(crate) fn measure_money_settlements<T>(f: impl FnOnce() -> T) -> (T, MoneySettlementReceipts) {
    MONEY_SETTLEMENT_RECEIPTS.with(|cell| {
        assert!(cell.get().is_none());
        cell.set(Some(MoneySettlementReceipts::EMPTY));
    });
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            MONEY_SETTLEMENT_RECEIPTS.with(|cell| cell.set(None));
        }
    }
    let reset = Reset;
    let value = f();
    let receipts = MONEY_SETTLEMENT_RECEIPTS.with(|cell| cell.get().unwrap());
    drop(reset);
    (value, receipts)
}

#[derive(Clone, Copy)]
pub(crate) enum MoneyIoKind {
    Open,
    Metadata,
    Read,
    Write,
    Sync,
    Mutate,
    ReadDir,
    ReadFile,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct MoneyIoReceipt {
    pub open: usize,
    pub metadata: usize,
    pub read: usize,
    pub write: usize,
    pub sync: usize,
    pub mutate: usize,
    pub read_dir: usize,
}
static MONEY_IO: std::sync::Mutex<Option<MoneyIoReceipt>> = std::sync::Mutex::new(None);
// Boundary attempts, including failed calls; not OS syscall or byte counts.
// Writer and telemetry-sidecar operations share this observer.
pub(crate) fn money_io_attempt(kind: MoneyIoKind) {
    let mut observation = MONEY_IO.lock().unwrap_or_else(|p| p.into_inner());
    if let Some(receipt) = observation.as_mut() {
        match kind {
            MoneyIoKind::Open => receipt.open += 1,
            MoneyIoKind::Metadata => receipt.metadata += 1,
            MoneyIoKind::Read => receipt.read += 1,
            MoneyIoKind::Write => receipt.write += 1,
            MoneyIoKind::Sync => receipt.sync += 1,
            MoneyIoKind::Mutate => receipt.mutate += 1,
            MoneyIoKind::ReadDir => receipt.read_dir += 1,
            MoneyIoKind::ReadFile => {
                receipt.open += 1;
                receipt.read += 1;
            }
        }
    }
}
pub(crate) fn measure_money_io<T>(f: impl FnOnce() -> T) -> (T, MoneyIoReceipt) {
    {
        let mut observation = MONEY_IO.lock().unwrap_or_else(|p| p.into_inner());
        assert!(observation.is_none(), "money I/O receipt already active");
        *observation = Some(MoneyIoReceipt::default());
    }
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            *MONEY_IO.lock().unwrap_or_else(|p| p.into_inner()) = None;
        }
    }
    let reset = Reset;
    let value = f();
    let receipt = MONEY_IO.lock().unwrap_or_else(|p| p.into_inner()).unwrap();
    drop(reset);
    (value, receipt)
}

thread_local! {static MONEY_SETTLEMENT_REFUSE:Cell<bool>=const{Cell::new(false)};}
pub(crate) fn money_settlement_refused_for_test() -> bool {
    MONEY_SETTLEMENT_REFUSE.with(Cell::get)
}
pub(crate) fn refuse_money_settlement_for_test<T>(f: impl FnOnce() -> T) -> T {
    struct Reset(bool);
    impl Drop for Reset {
        fn drop(&mut self) {
            MONEY_SETTLEMENT_REFUSE.with(|cell| cell.set(self.0));
        }
    }
    let reset = Reset(MONEY_SETTLEMENT_REFUSE.with(|cell| cell.replace(true)));
    let value = f();
    drop(reset);
    value
}

struct Probe;
#[global_allocator]
static ALLOCATOR: Probe = Probe;

fn record(requested: isize, usable: isize, alloc: bool) {
    let _ = ACTIVE.try_with(|active| {
        if active.get() {
            let _ = STATS.try_with(|cell| {
                let mut s = cell.get();
                s.requested_live += requested;
                s.usable_live += usable;
                s.requested_peak = s.requested_peak.max(s.requested_live.max(0) as usize);
                s.usable_peak = s.usable_peak.max(s.usable_live.max(0) as usize);
                s.allocations += usize::from(alloc);
                s.deallocations += usize::from(!alloc);
                s.requested_peak_with_overlap = s.requested_peak_with_overlap.max(s.requested_peak);
                s.usable_peak_with_overlap = s.usable_peak_with_overlap.max(s.usable_peak);
                PHASE_BASE.with(|base| {
                    PHASE_PEAK.with(|peak| {
                        peak.set(
                            peak.get()
                                .max((s.requested_live - base.get()).max(0) as usize),
                        )
                    })
                });
                cell.set(s);
            });
        }
    });
}

// A failed realloc leaves the old allocation alive and changes no counters.
// Successful in-place realloc is conservatively charged as old + new too.
fn record_reallocation(old: usize, old_usable: usize, new: Option<(usize, usize)>) {
    let Some((requested, usable)) = new else {
        return;
    };
    let _ = ACTIVE.try_with(|active| {
        if active.get() {
            let _ = STATS.try_with(|cell| {
                let mut s = cell.get();
                s.requested_peak_with_overlap = s
                    .requested_peak_with_overlap
                    .max((s.requested_live + requested as isize).max(0) as usize);
                s.usable_peak_with_overlap = s
                    .usable_peak_with_overlap
                    .max((s.usable_live + usable as isize).max(0) as usize);
                s.deallocations += 1;
                cell.set(s);
            });
        }
    });
    record(
        requested as isize - old as isize,
        usable as isize - old_usable as isize,
        true,
    );
}

unsafe impl GlobalAlloc for Probe {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = System.alloc(layout);
        if !ptr.is_null() {
            sample_money_admission();
            process::allocated(ptr, layout.size(), usable(ptr.cast(), layout.size()));
            record(
                layout.size() as isize,
                usable(ptr.cast(), layout.size()) as isize,
                true,
            );
        }
        ptr
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        process::deallocated(ptr);
        record(
            -(layout.size() as isize),
            -(usable(ptr.cast(), layout.size()) as isize),
            false,
        );
        System.dealloc(ptr, layout);
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        sample_money_admission();
        let old_usable = usable(ptr.cast(), layout.size());
        let result = process::reallocate(ptr, layout, size);
        if !result.is_null() {
            record_reallocation(
                layout.size(),
                old_usable,
                Some((size, usable(result.cast(), size))),
            );
        }
        result
    }
}

pub(crate) fn measure<T>(f: impl FnOnce() -> T) -> (T, Stats) {
    STATS.with(|s| s.set(Stats::default()));
    ACTIVE.with(|a| {
        assert!(!a.get());
        a.set(true);
    });
    let result = f();
    ACTIVE.with(|a| a.set(false));
    let stats = STATS.with(Cell::get);
    assert!(stats.requested_live >= 0 && stats.usable_live >= 0);
    (result, stats)
}

pub(crate) fn stats() -> Stats {
    STATS.with(Cell::get)
}
pub(crate) fn phase_begin() {
    assert!(ACTIVE.with(Cell::get));
    PHASE_BASE.with(|b| b.set(stats().requested_live));
    PHASE_PEAK.with(|p| p.set(0));
}
pub(crate) fn phase_peak() -> usize {
    PHASE_PEAK.with(Cell::get)
}

// Independent born-in-scope audits. The fixed tables allocate no Rust heap and
// leave System/Layouts untouched. Only pointers born inside this scope are
// charged: freeing a pre-existing allocation cannot hide a later peak. Charge
// realloc's old+new overlap conservatively even when System grows in place.
// The process table charges every thread. The caller table charges only the
// measuring thread's allocations; a free on any thread retires a charged
// pointer exactly, and unrelated threads' allocations are never charged.
mod process {
    use super::Stats;
    use std::cell::Cell;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Mutex, MutexGuard};
    // The cap receipt can serialize 65,536 ledger records in one caller.
    // Each record owns several pointers; table overflow must not masquerade
    // as a resource peak or force reducing the fixture's production cap.
    const SLOTS: usize = 1_048_576;
    #[derive(Clone, Copy)]
    struct Entry {
        pointer: usize,
        requested: usize,
        usable: usize,
    }
    const EMPTY: Entry = Entry {
        pointer: 0,
        requested: 0,
        usable: 0,
    };
    struct Audit {
        active: bool,
        overflow: bool,
        stats: Stats,
        entries: [Entry; SLOTS],
    }
    const IDLE: Audit = Audit {
        active: false,
        overflow: false,
        stats: Stats {
            requested_live: 0,
            usable_live: 0,
            requested_peak: 0,
            usable_peak: 0,
            allocations: 0,
            deallocations: 0,
            requested_peak_with_overlap: 0,
            usable_peak_with_overlap: 0,
        },
        entries: [EMPTY; SLOTS],
    };
    struct Table {
        active: AtomicBool,
        audit: Mutex<Audit>,
    }
    static PROCESS: Table = Table {
        active: AtomicBool::new(false),
        audit: Mutex::new(IDLE),
    };
    static CALLER: Table = Table {
        active: AtomicBool::new(false),
        audit: Mutex::new(IDLE),
    };
    // One caller-thread audit at a time; others wait rather than share stats.
    static CALLER_GATE: Mutex<()> = Mutex::new(());
    thread_local! {
        static CALLER_THREAD: Cell<bool> = const { Cell::new(false) };
    }
    fn on_caller_thread() -> bool {
        CALLER_THREAD.try_with(Cell::get).unwrap_or(false)
    }
    impl Audit {
        fn lookup(&self, pointer: usize) -> Option<usize> {
            let first = (pointer >> 4).wrapping_mul(0x9e3779b1) % SLOTS;
            for i in 0..SLOTS {
                let slot = (first + i) % SLOTS;
                if self.entries[slot].pointer == 0 {
                    return None;
                }
                if self.entries[slot].pointer == pointer {
                    return Some(slot);
                }
            }
            None
        }
        fn insert(&mut self, pointer: usize, requested: usize, usable: usize) {
            self.stats.requested_live += requested as isize;
            self.stats.usable_live += usable as isize;
            self.stats.requested_peak = self
                .stats
                .requested_peak
                .max(self.stats.requested_live as usize);
            self.stats.usable_peak = self.stats.usable_peak.max(self.stats.usable_live as usize);
            self.stats.allocations += 1;
            self.stats.requested_peak_with_overlap = self.stats.requested_peak;
            self.stats.usable_peak_with_overlap = self.stats.usable_peak;
            let first = (pointer >> 4).wrapping_mul(0x9e3779b1) % SLOTS;
            for i in 0..SLOTS {
                let slot = (first + i) % SLOTS;
                if self.entries[slot].pointer <= 1 {
                    self.entries[slot] = Entry {
                        pointer,
                        requested,
                        usable,
                    };
                    return;
                }
            }
            self.overflow = true;
        }
        fn remove(&mut self, pointer: usize) {
            if let Some(slot) = self.lookup(pointer) {
                let entry = self.entries[slot];
                self.stats.requested_live -= entry.requested as isize;
                self.stats.usable_live -= entry.usable as isize;
                self.stats.deallocations += 1;
                self.entries[slot].pointer = 1;
            }
        }
        fn reallocated(&mut self, old: usize, new: usize, requested: usize, usable: usize) {
            self.stats.requested_peak = self
                .stats
                .requested_peak
                .max(self.stats.requested_live as usize + requested);
            self.stats.usable_peak = self
                .stats
                .usable_peak
                .max(self.stats.usable_live as usize + usable);
            self.remove(old);
            self.insert(new, requested, usable);
        }
    }
    impl Table {
        /// Locked active audit, or None while this table is idle.
        fn active(&self) -> Option<MutexGuard<'_, Audit>> {
            if !self.active.load(Ordering::Relaxed) {
                return None;
            }
            let audit = self.audit.lock().unwrap_or_else(|p| p.into_inner());
            if audit.active {
                Some(audit)
            } else {
                None
            }
        }
        fn measure<T>(&self, f: impl FnOnce() -> T) -> (T, Stats) {
            {
                let mut audit = self.audit.lock().unwrap_or_else(|p| p.into_inner());
                if audit.active {
                    drop(audit);
                    panic!("native allocation audit already active");
                }
                audit.entries.fill(EMPTY);
                audit.stats = Stats::default();
                audit.overflow = false;
                audit.active = true;
                self.active.store(true, Ordering::Release);
            }
            struct Stop<'a>(&'a Table);
            impl Drop for Stop<'_> {
                fn drop(&mut self) {
                    self.0.active.store(false, Ordering::Release);
                    self.0
                        .audit
                        .lock()
                        .unwrap_or_else(|p| p.into_inner())
                        .active = false;
                }
            }
            let stop = Stop(self);
            let result = f();
            drop(stop);
            let (overflow, stats) = {
                let audit = self.audit.lock().unwrap_or_else(|p| p.into_inner());
                (audit.overflow, audit.stats)
            };
            assert!(!overflow, "native allocation audit table overflow");
            (result, stats)
        }
    }
    pub(super) fn allocated(pointer: *mut u8, requested: usize, usable: usize) {
        if let Some(mut audit) = PROCESS.active() {
            audit.insert(pointer as usize, requested, usable);
        }
        if on_caller_thread() {
            if let Some(mut audit) = CALLER.active() {
                audit.insert(pointer as usize, requested, usable);
            }
        }
    }
    pub(super) fn deallocated(pointer: *mut u8) {
        for table in [&PROCESS, &CALLER] {
            if let Some(mut audit) = table.active() {
                audit.remove(pointer as usize);
            }
        }
    }
    pub(super) unsafe fn reallocate(
        old: *mut u8,
        layout: std::alloc::Layout,
        requested: usize,
    ) -> *mut u8 {
        use std::alloc::{GlobalAlloc, System};
        // Keep the table locks (always process, then caller) across System's
        // native realloc: another thread may immediately reuse the old address
        // after System frees it.
        let (mut process, mut caller) = (PROCESS.active(), CALLER.active());
        if process.is_none() && caller.is_none() {
            return System.realloc(old, layout, requested);
        }
        let new = System.realloc(old, layout, requested);
        if !new.is_null() {
            let usable = super::usable(new.cast(), requested);
            if let Some(audit) = process.as_deref_mut() {
                audit.reallocated(old as usize, new as usize, requested, usable);
            }
            if let Some(audit) = caller.as_deref_mut() {
                if on_caller_thread() {
                    audit.reallocated(old as usize, new as usize, requested, usable);
                } else {
                    // The old pointer is retired; an unrelated thread owns the new one.
                    audit.remove(old as usize);
                }
            }
        }
        new
    }
    // Copy bookkeeping only; never walk pointers or allocate. A snapshot is
    // meaningful only inside this thread's existing born-pointer audit.
    pub(super) fn caller_stats() -> Option<Stats> {
        if !on_caller_thread() {
            return None;
        }
        CALLER.active().map(|audit| audit.stats)
    }
    pub(super) fn measure<T>(f: impl FnOnce() -> T) -> (T, Stats) {
        PROCESS.measure(f)
    }
    pub(super) fn measure_caller<T>(f: impl FnOnce() -> T) -> (T, Stats) {
        // Fail closed instead of deadlocking on the gate this thread holds.
        assert!(
            !on_caller_thread(),
            "caller-thread allocation audit already active on this thread"
        );
        let _gate = CALLER_GATE.lock().unwrap_or_else(|p| p.into_inner());
        struct Leave;
        impl Drop for Leave {
            fn drop(&mut self) {
                CALLER_THREAD.with(|caller| caller.set(false));
            }
        }
        CALLER.measure(|| {
            CALLER_THREAD.with(|caller| caller.set(true));
            let _leave = Leave;
            f()
        })
    }
}

pub(crate) fn caller_thread_stats() -> Option<Stats> {
    process::caller_stats()
}

pub(crate) fn measure_process<T>(f: impl FnOnce() -> T) -> (T, Stats) {
    process::measure(f)
}

/// Born-in-scope audit of allocations made by the calling thread only. Unlike
/// `measure`, freeing pre-existing storage cannot hide a later peak; unlike
/// `measure_process`, other threads' allocations are never charged, so it is
/// safe in parallel test runs. Use only for synchronous closures that hand no
/// allocation to another thread. Not reentrant on one thread.
pub(crate) fn measure_caller_thread<T>(f: impl FnOnce() -> T) -> (T, Stats) {
    process::measure_caller(f)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Explicit serial run because the nested process probe sees every thread.
    #[test]
    #[ignore = "explicit serial native allocator audit"]
    fn m1_allocator_accounting_self_tests() {
        for new_size in [256, 32] {
            let (((), thread), process) = measure_process(|| {
                measure(|| unsafe {
                    let layout = Layout::from_size_align(64, 8).unwrap();
                    let ptr = std::alloc::alloc(layout);
                    assert!(!ptr.is_null());
                    let grown = std::alloc::realloc(ptr, layout, new_size);
                    assert!(!grown.is_null());
                    assert_eq!(stats().requested_live, new_size as isize);
                    std::alloc::dealloc(grown, Layout::from_size_align(new_size, 8).unwrap());
                })
            });
            assert_eq!(thread.requested_peak_with_overlap, 64 + new_size);
            assert_eq!(thread.requested_peak_with_overlap, process.requested_peak);
            assert_eq!(thread.usable_peak_with_overlap, process.usable_peak);
            assert_eq!(thread.requested_live, 0);
            assert_eq!((thread.allocations, thread.deallocations), (2, 2));
            assert_eq!(thread.deallocations, process.deallocations);
        }
        // Native OOM return-null is not reliable on every allocator/platform.
        // Exercise the exact success-gated accounting entry point synthetically.
        let (_, failed) = measure(|| {
            let value = Box::new([0u8; 64]);
            let before = stats();
            record_reallocation(64, 64, None);
            let after = stats();
            assert_eq!(formatless(before), formatless(after));
            drop(std::hint::black_box(value));
        });
        assert_eq!((failed.allocations, failed.deallocations), (1, 1));

        // Create the receiver before measuring so thread startup is excluded.
        let (send, receive) = std::sync::mpsc::sync_channel(0);
        let worker = std::thread::spawn(move || {
            drop(receive.recv().unwrap());
            drop(receive.recv().unwrap());
        });
        send.send(Box::new([0u8; 64])).unwrap(); // Initialize sender TLS first.
        let (_, escaped) = measure(|| send.send(Box::new([0u8; 64])).unwrap());
        worker.join().unwrap();
        assert_eq!(escaped.requested_live, 64);
        assert_eq!(escaped.deallocations, 0);

        let external = Box::new([0u8; 64]);
        let negative = std::panic::catch_unwind(|| measure(|| drop(external)));
        assert!(negative.is_err()); // Preserve measure's existing nonnegative guard.
        assert_eq!(stats().requested_live, -64);

        let external = Box::new([0u8; 64]);
        let (leaked, compensated) = measure(|| {
            drop(external);
            Box::into_raw(Box::new([0u8; 64]))
        });
        assert_eq!(compensated.requested_live, 0);
        assert_eq!(compensated.usable_live, 0);
        assert_eq!(compensated.allocations, compensated.deallocations);
        assert_eq!(compensated.requested_peak, 0); // Hidden peak: not detected.
        unsafe {
            drop(Box::from_raw(leaked));
        }
    }

    #[test]
    fn caller_thread_stats_is_allocation_free_and_observational() {
        assert!(caller_thread_stats().is_none());
        let ((), total) = measure_caller_thread(|| {
            let before = caller_thread_stats().unwrap();
            let after = caller_thread_stats().unwrap();
            assert_eq!(formatless(before), formatless(after));
        });
        assert_eq!((total.allocations, total.deallocations), (0, 0));
        assert!(caller_thread_stats().is_none());
    }

    // Parallel-safe: the caller table never charges another thread.
    #[test]
    fn caller_thread_audit_keeps_born_peak_and_excludes_other_threads() {
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
        use std::sync::Arc;
        let pre_existing = Box::new([0u8; 4096]);
        let mut grown = Vec::<u8>::with_capacity(64);
        let stop = Arc::new(AtomicBool::new(false));
        let ticks = Arc::new(AtomicUsize::new(0));
        let worker = {
            let (stop, ticks) = (stop.clone(), ticks.clone());
            std::thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    drop(std::hint::black_box(Box::new([0u8; 65_536])));
                    ticks.fetch_add(1, Ordering::Relaxed);
                }
            })
        };
        let ((), audit) = measure_caller_thread(|| {
            drop(pre_existing); // Cannot offset the growth below.
            let born = std::hint::black_box(Box::new([0u8; 256]));
            // Pre-existing buffer: only its new side is charged.
            grown.reserve_exact(1024);
            // The unrelated thread allocates while this window is open.
            let seen = ticks.load(Ordering::Relaxed);
            while ticks.load(Ordering::Relaxed) < seen + 2 {
                std::hint::spin_loop();
            }
            drop(born);
        });
        stop.store(true, Ordering::Relaxed);
        worker.join().unwrap();
        assert_eq!(audit.requested_peak_with_overlap, 256 + 1024);
        assert_eq!(audit.requested_live, 1024);
        assert_eq!((audit.allocations, audit.deallocations), (2, 1));
        assert!(audit.usable_peak_with_overlap >= audit.requested_peak_with_overlap);
        drop(grown);
    }

    #[test]
    #[serial_test::serial(claude_request_money_shadow)]
    fn money_settlement_observer_tracks_short_reservations_and_keeps_returned_funds() {
        use crate::snapshots::claude_request_money::{store, ShadowReservation};
        store::flush();
        let (retained, receipts) = measure_money_settlements(|| {
            observe_money_settlement(4096, 1, || {
                let reservation = ShadowReservation::admit(4096).unwrap();
                money_settlement_admitted(reservation.bytes());
                let temporary = ShadowReservation::admit(8192).unwrap();
                drop(temporary); // No allocator event occurs during this reservation.
                let bytes = std::hint::black_box(Box::new([0_u8; 1024]));
                money_settlement_pairs(1);
                (reservation, bytes)
            })
        });
        let receipt = receipts.iter().next().unwrap();
        assert_eq!(
            (receipt.required, receipt.funds, receipt.pairs),
            (4096, 4096, 1)
        );
        assert!(receipt.admitted);
        assert!(!receipt.skipped);
        assert!(receipt.shared_admission_peak >= 4096 + 8192);
        assert_eq!(receipt.allocation.requested_peak_with_overlap, 1024);
        assert_eq!(
            retained.0.bytes(),
            4096,
            "the seam cannot retire save funds"
        );
        drop(retained);
        let (_, skipped) = measure_money_settlements(money_settlement_skipped);
        let receipt = skipped.iter().next().unwrap();
        assert!(receipt.skipped);
        assert_eq!(
            (receipt.funds, receipt.pairs, receipt.allocation.allocations),
            (0, 0, 0)
        );
    }

    #[test]
    #[serial_test::serial(claude_request_money_shadow)]
    fn money_io_observer_counts_real_ledger_file_boundaries() {
        use crate::snapshots::claude_request_money::store;
        let scratch = crate::test_scratch::ScratchDir::new("money-io-observer");
        let mut ledger = store::ClaudeLedger::new_for_test();
        let mut writer = store::WriterState::default();
        let (_, io) = measure_money_io(|| {
            let (_, _, unwritten) =
                store::save_page_for_test(scratch.as_ref(), &mut ledger, &mut writer).unwrap();
            assert_eq!(unwritten, 0);
        });
        assert!(io.open >= 257 * 2, "create plus directory open: {io:?}");
        assert!(io.write >= 257, "shard writes: {io:?}");
        assert!(io.sync >= 257 * 2, "file plus directory sync: {io:?}");
        assert!(io.mutate >= 257, "atomic rename: {io:?}");
        let (_, io) = measure_money_io(|| store::reload_for_test(scratch.as_ref()).unwrap());
        assert!(
            io.open >= 257 && io.metadata >= 257 && io.read >= 257,
            "loaded shard operations: {io:?}"
        );
    }

    fn formatless(s: Stats) -> (isize, isize, usize, usize, usize, usize, usize, usize) {
        (
            s.requested_live,
            s.usable_live,
            s.requested_peak,
            s.usable_peak,
            s.requested_peak_with_overlap,
            s.usable_peak_with_overlap,
            s.allocations,
            s.deallocations,
        )
    }
}
