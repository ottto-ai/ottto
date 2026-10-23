// Record-local load containment (follow-up to #694). Red-first scaffold: the
// count type and its test reader only; the containment lands next.

/// Content-free counts of the records one load or save dropped or normalized.
#[cfg(test)]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ScanIndexLoadDrops {
    pub(crate) activity: usize,
    pub(crate) accepted: usize,
    pub(crate) cursor: usize,
    pub(crate) quarantine: usize,
}

#[cfg(test)]
impl ScanIndexLoadDrops {
    const NONE: Self = Self {
        activity: 0,
        accepted: 0,
        cursor: 0,
        quarantine: 0,
    };
}

#[cfg(test)]
thread_local! {
    static SCAN_INDEX_LOAD_DROPS_FOR_TEST: std::cell::Cell<ScanIndexLoadDrops> =
        const { std::cell::Cell::new(ScanIndexLoadDrops::NONE) };
}

/// This thread's cumulative record-local load and save drops.
#[cfg(test)]
pub(crate) fn scan_index_load_drops_for_test() -> ScanIndexLoadDrops {
    SCAN_INDEX_LOAD_DROPS_FOR_TEST.with(std::cell::Cell::get)
}
