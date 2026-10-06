// Test-only requested/usable allocator probe, per test thread.
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

#[derive(Clone, Copy, Default, Debug)]
pub(crate) struct Stats {
    pub requested_live: isize,
    pub usable_live: isize,
    pub requested_peak: usize,
    pub usable_peak: usize,
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
            record(
                size as isize - layout.size() as isize,
                usable(result.cast(), size) as isize - old_usable as isize,
                true,
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

// Independent all-thread audit. The fixed table allocates no Rust heap and
// leaves System/Layouts untouched. Only pointers born inside this scope are
// charged: freeing a pre-existing allocation cannot hide a later peak. Charge
// realloc's old+new overlap conservatively even when System grows in place.
mod process {
    use super::Stats;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Mutex;
    static ACTIVE: AtomicBool = AtomicBool::new(false);
    const SLOTS: usize = 65_536;
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
    static AUDIT: Mutex<Audit> = Mutex::new(Audit {
        active: false,
        overflow: false,
        stats: Stats {
            requested_live: 0,
            usable_live: 0,
            requested_peak: 0,
            usable_peak: 0,
            allocations: 0,
        },
        entries: [EMPTY; SLOTS],
    });
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
                self.entries[slot].pointer = 1;
            }
        }
    }
    pub(super) fn allocated(pointer: *mut u8, requested: usize, usable: usize) {
        if !ACTIVE.load(Ordering::Relaxed) {
            return;
        }
        let mut audit = AUDIT.lock().unwrap_or_else(|p| p.into_inner());
        if audit.active {
            audit.insert(pointer as usize, requested, usable);
        }
    }
    pub(super) fn deallocated(pointer: *mut u8) {
        if !ACTIVE.load(Ordering::Relaxed) {
            return;
        }
        let mut audit = AUDIT.lock().unwrap_or_else(|p| p.into_inner());
        if audit.active {
            audit.remove(pointer as usize);
        }
    }
    pub(super) unsafe fn reallocate(
        old: *mut u8,
        layout: std::alloc::Layout,
        requested: usize,
    ) -> *mut u8 {
        use std::alloc::{GlobalAlloc, System};
        if !ACTIVE.load(Ordering::Relaxed) {
            return System.realloc(old, layout, requested);
        }
        // Keep the table lock across System's native realloc: another thread
        // may immediately reuse the old address after System frees it.
        let mut audit = AUDIT.lock().unwrap_or_else(|p| p.into_inner());
        let new = System.realloc(old, layout, requested);
        if audit.active && !new.is_null() {
            let usable = super::usable(new.cast(), requested);
            audit.stats.requested_peak = audit
                .stats
                .requested_peak
                .max(audit.stats.requested_live as usize + requested);
            audit.stats.usable_peak = audit
                .stats
                .usable_peak
                .max(audit.stats.usable_live as usize + usable);
            audit.remove(old as usize);
            audit.insert(new as usize, requested, usable);
        }
        new
    }
    pub(super) fn measure<T>(f: impl FnOnce() -> T) -> (T, Stats) {
        {
            let mut audit = AUDIT.lock().unwrap_or_else(|p| p.into_inner());
            if audit.active {
                drop(audit);
                panic!("native allocation audit already active");
            }
            audit.entries.fill(EMPTY);
            audit.stats = Stats::default();
            audit.overflow = false;
            audit.active = true;
            ACTIVE.store(true, Ordering::Release);
        }
        struct Stop;
        impl Drop for Stop {
            fn drop(&mut self) {
                ACTIVE.store(false, Ordering::Release);
                AUDIT.lock().unwrap_or_else(|p| p.into_inner()).active = false;
            }
        }
        let stop = Stop;
        let result = f();
        drop(stop);
        let (overflow, stats) = {
            let audit = AUDIT.lock().unwrap_or_else(|p| p.into_inner());
            (audit.overflow, audit.stats)
        };
        assert!(!overflow, "native allocation audit table overflow");
        (result, stats)
    }
}

pub(crate) fn measure_process<T>(f: impl FnOnce() -> T) -> (T, Stats) {
    process::measure(f)
}
