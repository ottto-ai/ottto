use serde::{Serialize, Serializer};
use std::path::Path;
#[derive(Clone, Copy, Debug)]
pub(crate) enum Parent {
    Missing,
    Symlink,
    NotDirectory,
    MetadataError,
    Live,
}
impl Parent {
    pub(crate) fn is_removal(self, path: &Path) -> bool {
        if !matches!(self, Self::Live) {
            super::claude_reread::update(|counts| {
                let c = &mut counts.absence.0;
                c[self as usize] = c[self as usize].saturating_add(1);
                if path.iter().any(|part| part == "subagents") {
                    c[self as usize + 4] = c[self as usize + 4].saturating_add(1);
                }
            });
        }
        matches!(self, Self::Live)
    }
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Counts([u64; 8]);
impl Counts {
    pub(crate) fn merge(&mut self, other: Self) {
        for (count, incoming) in self.0.iter_mut().zip(other.0) {
            *count = count.saturating_add(incoming);
        }
    }
}
impl Serialize for Counts {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_map(
            self.0
                .iter()
                .enumerate()
                .filter(|(_, n)| **n != 0)
                .map(|(i, n)| {
                    let split = if i < 4 { "" } else { "subagent_" };
                    let class = ["missing", "symlink", "not_directory", "metadata_error"][i % 4];
                    (format!("claude_absence_parent_{split}{class}"), n)
                }),
        )
    }
}
