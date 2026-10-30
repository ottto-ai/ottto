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
    if process::caller_phase_begin() {
        return;
    }
    assert!(ACTIVE.with(Cell::get));
    PHASE_BASE.with(|b| b.set(stats().requested_live));
    PHASE_PEAK.with(|p| p.set(0));
}
pub(crate) fn phase_peak() -> usize {
    process::caller_phase_peak().unwrap_or_else(|| PHASE_PEAK.with(Cell::get))
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
    const SLOTS: usize = 65_536;
    #[derive(Clone, Copy)]
    struct Entry {
        pointer: usize,
        requested: usize,
        usable: usize,
        in_phase: bool,
    }
    const EMPTY: Entry = Entry {
        pointer: 0,
        requested: 0,
        usable: 0,
        in_phase: false,
    };
    struct Audit {
        active: bool,
        overflow: bool,
        stats: Stats,
        phase_live: usize,
        phase_peak: usize,
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
        phase_live: 0,
        phase_peak: 0,
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
            self.phase_live += requested;
            self.phase_peak = self.phase_peak.max(self.phase_live);
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
                        in_phase: true,
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
                if entry.in_phase {
                    self.phase_live -= entry.requested;
                }
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
            self.phase_peak = self.phase_peak.max(self.phase_live + requested);
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
                audit.phase_live = 0;
                audit.phase_peak = 0;
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
    // Phase peaks count only pointers born since phase_begin. A free of an
    // older pointer must not offset a later phase allocation. Realloc charges
    // the full new side plus any still-live phase allocations conservatively.
    pub(super) fn caller_phase_begin() -> bool {
        if !on_caller_thread() {
            return false;
        }
        let mut audit = CALLER.active().expect("active caller-thread audit");
        for entry in &mut audit.entries {
            entry.in_phase = false;
        }
        audit.phase_live = 0;
        audit.phase_peak = 0;
        true
    }
    pub(super) fn caller_phase_peak() -> Option<usize> {
        if !on_caller_thread() {
            return None;
        }
        Some(
            CALLER
                .active()
                .expect("active caller-thread audit")
                .phase_peak,
        )
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
    fn legacy_measure_keeps_phase_accounting() {
        let ((), audit) = measure(|| {
            phase_begin();
            let value = std::hint::black_box(Box::new([0u8; 128]));
            assert_eq!(stats().requested_live, 128);
            assert_eq!(phase_peak(), 128);
            drop(value);
        });
        assert_eq!(audit.requested_live, 0);
    }

    #[test]
    fn caller_phases_exclude_old_frees_without_hiding_growth() {
        let external = Box::new([0u8; 4096]);
        let mut grown = Vec::<u8>::with_capacity(64);
        let ((), audit) = measure_caller_thread(|| {
            let earlier_phase = std::hint::black_box(Box::new([0u8; 512]));
            phase_begin();
            drop(external);
            drop(earlier_phase);
            assert_eq!(phase_peak(), 0);
            let born = std::hint::black_box(Box::new([0u8; 256]));
            grown.reserve_exact(1024); // Only the new side belongs to this audit.
            assert_eq!(phase_peak(), 256 + 1024);
            drop(born);
            assert_eq!(caller_thread_stats().unwrap().requested_live, 1024);
            phase_begin();
            drop(grown); // Born in scope, but before this phase: no peak credit.
            let mut bytes = Vec::<u8>::with_capacity(64);
            bytes.push(1);
            bytes.reserve_exact(255);
            assert_eq!(phase_peak(), 64 + 256); // Conservative realloc overlap.
            drop(std::hint::black_box(bytes));
            assert_eq!(caller_thread_stats().unwrap().requested_live, 0);
        });
        assert_eq!(audit.requested_peak_with_overlap, 256 + 1024);
        assert_eq!((audit.requested_live, audit.usable_live), (0, 0));
        assert_eq!((audit.allocations, audit.deallocations), (5, 5));
        // A new scope starts with no phase history.
        measure_caller_thread(|| assert_eq!(phase_peak(), 0));
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
