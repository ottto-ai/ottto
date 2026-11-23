use serde::{ser::SerializeMap, Serialize, Serializer};
use std::path::Path;
#[derive(Clone, Copy, Debug)]
pub(crate) enum Parent {
    Missing,
    Symlink,
    NotDirectory,
    MetadataError,
    Live,
    OtherSource,
}
impl Parent {
    pub(crate) fn is_removal(self, path: &Path) -> bool {
        if !matches!(self, Self::Live | Self::OtherSource) {
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
pub(crate) struct Counts(pub(super) [u64; 8]);
impl Serialize for Counts {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(None)?;
        for (i, n) in self.0.iter().enumerate().filter(|(_, n)| **n != 0) {
            let split = if i < 4 { "" } else { "subagent_" };
            let class = ["missing", "symlink", "not_directory", "metadata_error"][i % 4];
            map.serialize_entry(&format!("claude_absence_parent_{split}{class}"), n)?;
        }
        map.end()
    }
}
