//! Shared, bounded discovery of Desktop app profiles. Only the existing
//! config and session metadata readers consume these roots.
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

const MAX_ROOTS: usize = 64;
const MAX_DISCOVERY_ENTRIES: usize = 4096;

pub(crate) fn support_roots(home: &Path) -> Vec<PathBuf> {
    let support = home.join("Library/Application Support");
    // Preserve the default root even without config.json: older installs can
    // have session metadata alone, and detection already supports that case.
    let mut roots = vec![support.join("Claude")];
    let Ok(entries) = fs::read_dir(&support) else {
        return roots;
    };
    let mut siblings = BTreeSet::new();
    for entry in entries.take(MAX_DISCOVERY_ENTRIES).flatten() {
        if !entry
            .file_name()
            .to_str()
            .is_some_and(|name| name.starts_with("Claude-"))
            || !entry.file_type().is_ok_and(|kind| kind.is_dir())
        {
            continue;
        }
        let root = entry.path();
        if root.join("config.json").is_file() {
            siblings.insert(root);
        }
    }
    roots.extend(siblings.into_iter().take(MAX_ROOTS - 1));
    roots
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discovers_only_configured_immediate_siblings() {
        let home = crate::test_scratch::ScratchDir::new("desktop-roots");
        let support = home.join("Library/Application Support");
        assert_eq!(support_roots(&home), vec![support.join("Claude")]);
        for name in ["Claude-ALT", "Claude-B", "Claude-3p", "Other/Claude-nested"] {
            fs::create_dir_all(support.join(name)).unwrap();
        }
        for name in ["Claude-ALT", "Claude-B", "Other/Claude-nested"] {
            fs::write(support.join(name).join("config.json"), "{}").unwrap();
        }
        fs::write(support.join("Claude-file"), "{}").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(support.join("Claude-ALT"), support.join("Claude-link"))
            .unwrap();
        assert_eq!(
            support_roots(&home),
            vec![
                support.join("Claude"),
                support.join("Claude-ALT"),
                support.join("Claude-B")
            ]
        );
    }

    #[test]
    fn bounds_root_count_and_sorts_siblings() {
        let home = crate::test_scratch::ScratchDir::new("desktop-roots-bound");
        let support = home.join("Library/Application Support");
        for i in (0..MAX_ROOTS + 2).rev() {
            let root = support.join(format!("Claude-{i:03}"));
            fs::create_dir_all(&root).unwrap();
            fs::write(root.join("config.json"), "{}").unwrap();
        }
        let roots = support_roots(&home);
        assert_eq!(roots.len(), MAX_ROOTS);
        assert_eq!(roots[0], support.join("Claude"));
        assert_eq!(roots[1], support.join("Claude-000"));
        assert_eq!(
            roots[MAX_ROOTS - 1],
            support.join(format!("Claude-{:03}", MAX_ROOTS - 2))
        );
    }
}
