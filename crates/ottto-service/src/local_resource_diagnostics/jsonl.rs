//! Per-source scalars for existing page records. Never admission authority or wire state.
use super::*;
use std::cell::Cell;

#[derive(Clone, Copy, Default, Serialize)]
pub(crate) struct Counts {
    #[serde(skip_serializing_if = "is_zero")]
    max_line_bytes: u64,
    #[serde(skip_serializing_if = "is_zero")]
    max_line_buffer_bytes: u64,
}

impl Counts {
    /// The page's line sizes as their own record after `native_collection_page`,
    /// which keeps that line under its size bound. Nothing when every size is zero.
    pub(super) fn emit_page_lines(&self, source: &str) {
        if self.max_line_bytes == 0 && self.max_line_buffer_bytes == 0 {
            return;
        }
        emit(&Record {
            schema_version: SCHEMA_VERSION,
            process_id: std::process::id(),
            stage: "native_collection_jsonl_lines",
            source: Source::from_slug(source),
            observation: Observation::point(),
            counts: self,
        });
    }
}

const NO_COUNTS: Counts = Counts {
    max_line_bytes: 0,
    max_line_buffer_bytes: 0,
};
thread_local! {
    static PAGES: Cell<[Counts; 3]> = const { Cell::new([NO_COUNTS; 3]) };
    static SOURCE: Cell<Option<usize>> = const { Cell::new(None) };
}

fn take_slot(slot: Option<usize>) -> Counts {
    slot.map_or_else(Counts::default, |at| {
        PAGES.with(|pages| {
            let mut counts = pages.get();
            let taken = std::mem::take(&mut counts[at]);
            pages.set(counts);
            taken
        })
    })
}

/// This page's counts for `source`, leaving it empty.
pub(super) fn take(source: &str) -> Counts {
    take_slot(source_slot(source))
}

pub(crate) struct Scope {
    previous: Option<usize>,
    slot: Option<usize>,
}
impl Scope {
    pub(crate) fn begin(source: &str) -> Self {
        let slot = source_slot(source);
        Self {
            previous: SOURCE.with(|current| current.replace(slot)),
            slot,
        }
    }
    pub(super) fn take(&self) -> Counts {
        take_slot(self.slot)
    }
}
impl Drop for Scope {
    fn drop(&mut self) {
        SOURCE.with(|source| source.set(self.previous));
    }
}

/// Source rotation may interleave steps; each source keeps separate page totals.
pub(crate) fn page<T>(source: &str, inner: impl FnOnce() -> T) -> T {
    let _scope = Scope::begin(source);
    inner()
}

fn update(change: impl FnOnce(&mut Counts)) {
    if let Some(at) = SOURCE.with(Cell::get) {
        PAGES.with(|pages| {
            let mut counts = pages.get();
            change(&mut counts[at]);
            pages.set(counts);
        });
    }
}

/// Raw size before parsing, including lines that fail JSON decoding.
pub(crate) fn line(bytes: usize) {
    update(|counts| counts.max_line_bytes = counts.max_line_bytes.max(bytes as u64));
}

/// Line-buffer capacity: not RSS, parsed-value storage or an upper bound.
pub(crate) fn line_buffer(capacity: usize) {
    update(|counts| {
        counts.max_line_buffer_bytes = counts.max_line_buffer_bytes.max(capacity as u64);
    });
}
