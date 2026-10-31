//! Native decoder allocations spend the already admitted credit. Darwin's
//! allocator size classes, rather than ZSTD_sizeof_DCtx, determine the charge.
use std::alloc::{alloc, dealloc, Layout};
use std::cell::Cell;
use std::ffi::c_void;
use std::ptr::{self, NonNull};
use zstd::zstd_safe::zstd_sys as sys;

const HEADER: usize = 16;

#[cfg(target_os = "macos")]
extern "C" {
    fn malloc_size(ptr: *const c_void) -> usize;
    fn malloc_good_size(size: usize) -> usize;
}

struct Charge {
    live: Cell<usize>,
    peak: Cell<usize>,
    refusals: Cell<u64>,
    limit: usize,
}

impl Charge {
    fn refuse(&self) -> *mut c_void {
        self.refusals.set(self.refusals.get().saturating_add(1));
        ptr::null_mut()
    }
}

unsafe fn allocated_size(ptr: *const u8, requested: usize) -> usize {
    #[cfg(target_os = "macos")]
    {
        // SAFETY: every pointer queried here is a live Rust system allocation.
        unsafe { malloc_size(ptr.cast()) }.max(requested)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = ptr;
        requested
    }
}

unsafe extern "C" fn allocate(opaque: *mut c_void, size: usize) -> *mut c_void {
    // SAFETY: Context owns this stable Box until after ZSTD_freeDCtx returns.
    let charge = unsafe { &*opaque.cast::<Charge>() };
    let Some(total) = size.checked_add(HEADER) else {
        return charge.refuse();
    };
    let Ok(layout) = Layout::from_size_align(total, HEADER) else {
        return charge.refuse();
    };
    #[cfg(target_os = "macos")]
    // Preflight the native size class before allocating; confirm with malloc_size.
    let predicted = unsafe { malloc_good_size(total) }.max(total);
    #[cfg(not(target_os = "macos"))]
    let predicted = total;
    if charge.live.get().saturating_add(predicted) > charge.limit {
        return charge.refuse();
    }
    // SAFETY: layout is valid; null is reported to zstd without unwinding.
    let base = unsafe { alloc(layout) };
    if base.is_null() {
        return charge.refuse();
    }
    let actual = unsafe { allocated_size(base, total) };
    // Include even an unexpectedly larger size class immediately refused below.
    charge.peak.set(
        charge
            .peak
            .get()
            .max(charge.live.get().saturating_add(actual)),
    );
    let Some(live) = charge
        .live
        .get()
        .checked_add(actual)
        .filter(|n| *n <= charge.limit)
    else {
        unsafe { dealloc(base, layout) };
        return charge.refuse();
    };
    // Store the Rust layout size and actual charge, preserving malloc alignment.
    unsafe {
        base.cast::<usize>().write(total);
        base.add(std::mem::size_of::<usize>())
            .cast::<usize>()
            .write(actual);
    }
    charge.live.set(live);
    unsafe { base.add(HEADER).cast() }
}

unsafe extern "C" fn release(opaque: *mut c_void, address: *mut c_void) {
    if address.is_null() {
        return;
    }
    // SAFETY: zstd frees only pointers returned by allocate, with this context.
    let charge = unsafe { &*opaque.cast::<Charge>() };
    let base = unsafe { address.cast::<u8>().sub(HEADER) };
    let total = unsafe { base.cast::<usize>().read() };
    let actual = unsafe {
        base.add(std::mem::size_of::<usize>())
            .cast::<usize>()
            .read()
    };
    charge.live.set(charge.live.get() - actual);
    unsafe { dealloc(base, Layout::from_size_align_unchecked(total, HEADER)) };
}

pub(super) struct Context {
    native: NonNull<sys::ZSTD_DCtx>,
    charge: Box<Charge>,
}
// SAFETY: zstd and its callbacks are used only through this uniquely owned
// context. Moving it does not move Charge; Cell keeps Context non-Sync.
unsafe impl Send for Context {}

impl Context {
    pub(super) fn new(limit: usize) -> Option<Self> {
        let mut charge = Box::new(Charge {
            live: Cell::new(0),
            peak: Cell::new(0),
            refusals: Cell::new(0),
            limit,
        });
        let own = unsafe {
            allocated_size(
                (&*charge as *const Charge).cast(),
                std::mem::size_of::<Charge>(),
            )
        };
        if own > limit {
            return None;
        }
        charge.live.set(own);
        charge.peak.set(own);
        let memory = sys::ZSTD_customMem {
            customAlloc: Some(allocate),
            customFree: Some(release),
            opaque: (&mut *charge as *mut Charge).cast(),
        };
        // SAFETY: callbacks and opaque remain live until the context is freed.
        let native = NonNull::new(unsafe { sys::ZSTD_createDCtx_advanced(memory) })?;
        Some(Self { native, charge })
    }
    pub(super) fn set_window_log(&mut self, log: u32) -> Result<(), ()> {
        let code = unsafe {
            sys::ZSTD_DCtx_setParameter(
                self.native.as_ptr(),
                sys::ZSTD_dParameter::ZSTD_d_windowLogMax,
                log as i32,
            )
        };
        if unsafe { sys::ZSTD_isError(code) } != 0 {
            Err(())
        } else {
            Ok(())
        }
    }
    pub(super) fn sizeof(&self) -> usize {
        self.charge.live.get()
    }
    pub(super) fn peak_bytes(&self) -> usize {
        self.charge.peak.get()
    }
    pub(super) fn allocation_refusals(&self) -> u64 {
        self.charge.refusals.get()
    }
    pub(super) fn decompress(
        &mut self,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<(usize, usize, usize), ()> {
        let mut src = sys::ZSTD_inBuffer {
            src: input.as_ptr().cast(),
            size: input.len(),
            pos: 0,
        };
        let mut dst = sys::ZSTD_outBuffer {
            dst: output.as_mut_ptr().cast(),
            size: output.len(),
            pos: 0,
        };
        // SAFETY: these disjoint slices stay live throughout the call; zstd
        // respects their lengths and invokes only this context's callbacks.
        let code = unsafe { sys::ZSTD_decompressStream(self.native.as_ptr(), &mut dst, &mut src) };
        if unsafe { sys::ZSTD_isError(code) } != 0 {
            Err(())
        } else {
            Ok((code, src.pos, dst.pos))
        }
    }
}
impl Drop for Context {
    fn drop(&mut self) {
        // SAFETY: this is the sole owner, and Charge still exists during free.
        unsafe { sys::ZSTD_freeDCtx(self.native.as_ptr()) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// [behaviour] Native decoder resize overlap spends live native bytes against the admitted
    /// credit.
    #[test]
    fn resize_overlap_spends_live_native_bytes_before_admission() {
        let mut charge = Charge {
            live: Cell::new(0),
            peak: Cell::new(0),
            refusals: Cell::new(0),
            limit: 16 * 1024,
        };
        let opaque = ptr::addr_of_mut!(charge).cast();
        // SAFETY: this test owns both the stable charge and all returned blocks.
        unsafe {
            let first = allocate(opaque, 512);
            assert!(!first.is_null());
            let live = charge.live.get();
            assert!(live >= 512 + HEADER);
            charge.limit = 2 * live - 1;
            assert!(
                allocate(opaque, 512).is_null(),
                "old + new must fit together"
            );
            assert_eq!(charge.live.get(), live, "refusal creates no charge");
            assert_eq!(charge.peak.get(), live);
            assert_eq!(charge.refusals.get(), 1, "preflight is a counted backstop");
            release(opaque, first);
            assert_eq!(charge.live.get(), 0);
            release(opaque, ptr::null_mut());
            assert_eq!(charge.live.get(), 0);
        }
        assert!(Context::new(0).is_none());
    }
}
