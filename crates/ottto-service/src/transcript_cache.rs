//! A reduction continued from its committed checkpoint, and the shared state
//! budget constants the sampled scan still charges against.
use crate::heap_layout_bound::{Counter, HeapLayoutBound};
use crate::transcript_acquisition::Checkpoint;

pub(crate) const CACHE_BYTES: usize = 64 * 1024 * 1024;
pub(crate) const ENTRY_BYTES: usize = 8 * 1024 * 1024;
pub(crate) const CACHE_ENTRIES: usize = 256;

pub(crate) struct Retained<S> {
    pub(crate) checkpoint: Checkpoint,
    pub(crate) state: S,
}
impl<S: HeapLayoutBound> HeapLayoutBound for Retained<S> {
    fn heap_bound(&self, c: &mut Counter) -> Option<()> {
        let Self { checkpoint, state } = self;
        checkpoint.heap_bound(c)?;
        state.heap_bound(c)
    }
}
