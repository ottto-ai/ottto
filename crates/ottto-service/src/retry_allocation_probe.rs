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
            record(
                layout.size() as isize,
                usable(ptr.cast(), layout.size()) as isize,
                true,
            );
        }
        ptr
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        record(
            -(layout.size() as isize),
            -(usable(ptr.cast(), layout.size()) as isize),
            false,
        );
        System.dealloc(ptr, layout);
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        let old_usable = usable(ptr.cast(), layout.size());
        let result = System.realloc(ptr, layout, size);
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
