//! Shared, bounded discovery of Desktop app profiles. Only the existing
//! config and session metadata readers consume these roots.
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

pub(crate) const MAX_ROOTS: usize = 64;
pub(crate) const MAX_DISCOVERY_ENTRIES: usize = 4096;

#[derive(Debug)]
pub(crate) struct Discovery {
    pub(crate) roots: Vec<PathBuf>,
    pub(crate) capped: bool,
    pub(crate) error: bool,
}

pub(crate) fn support_roots(home: &Path) -> Vec<PathBuf> {
    discover_support_roots(home).roots
}

pub(crate) fn discover_support_roots(home: &Path) -> Discovery {
    let support = home.join("Library/Application Support");
    // Preserve the default root even without config.json: older installs can
    // have session metadata alone, and detection already supports that case.
    let mut discovery = Discovery {
        roots: vec![support.join("Claude")],
        capped: false,
        error: false,
    };
    match fs::read_dir(&support) {
        Ok(entries) => discovery.collect(entries),
        Err(error) => discovery.error = error.kind() != std::io::ErrorKind::NotFound,
    }
    discovery
}

impl Discovery {
    fn collect(&mut self, entries: impl Iterator<Item = std::io::Result<fs::DirEntry>>) {
        let mut siblings = BTreeSet::new();
        let mut inspected = 0;
        for entry in entries.take(MAX_DISCOVERY_ENTRIES) {
            inspected += 1;
            let entry = match entry {
                Ok(entry) => entry,
                Err(_) => {
                    self.error = true;
                    continue;
                }
            };
            if !entry
                .file_name()
                .to_str()
                .is_some_and(|name| name.starts_with("Claude-"))
            {
                continue;
            }
            match entry.file_type() {
                Ok(kind) if kind.is_dir() => {}
                Ok(_) => continue,
                Err(_) => {
                    self.error = true;
                    continue;
                }
            }
            let root = entry.path();
            match fs::metadata(root.join("config.json")) {
                Ok(metadata) if metadata.is_file() => {
                    siblings.insert(root);
                }
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => self.error = true,
            }
        }
        // At the exact entry cap we cannot prove exhaustion without exceeding
        // the read budget. Keep that boundary conservative, too.
        self.capped = inspected == MAX_DISCOVERY_ENTRIES || siblings.len() > MAX_ROOTS - 1;
        self.roots.extend(siblings.into_iter().take(MAX_ROOTS - 1));
    }
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
    #[test]
    fn discovery_marks_only_root_overflow_incomplete() {
        let home = crate::test_scratch::ScratchDir::new("desktop-root-coverage");
        let support = home.join("Library/Application Support");
        for i in 0..MAX_ROOTS {
            let root = support.join(format!("Claude-{i:03}"));
            fs::create_dir_all(&root).unwrap();
            fs::write(root.join("config.json"), "{}").unwrap();
            if i >= MAX_ROOTS - 3 {
                let discovery = discover_support_roots(&home);
                assert_eq!(discovery.capped, i == MAX_ROOTS - 1);
                assert!(!discovery.error);
                assert_eq!(discovery.roots.len(), (i + 2).min(MAX_ROOTS));
            }
        }
    }

    #[test]
    fn discovery_entry_budget_includes_exact_cap() {
        let home = crate::test_scratch::ScratchDir::new("desktop-entry-coverage");
        let support = home.join("Library/Application Support");
        fs::create_dir_all(&support).unwrap();
        for i in 0..MAX_DISCOVERY_ENTRIES + 1 {
            fs::write(support.join(format!("other-{i:04}")), "").unwrap();
            if i >= MAX_DISCOVERY_ENTRIES - 2 {
                let discovery = discover_support_roots(&home);
                assert_eq!(discovery.capped, i + 1 >= MAX_DISCOVERY_ENTRIES);
                assert!(!discovery.error);
                assert_eq!(discovery.roots, vec![support.join("Claude")]);
            }
        }
    }

    #[test]
    fn discovery_distinguishes_absence_open_and_iterator_errors() {
        let home = crate::test_scratch::ScratchDir::new("desktop-discovery-errors");
        let missing = discover_support_roots(&home);
        assert!(!missing.error && !missing.capped);
        fs::create_dir_all(home.join("Library")).unwrap();
        fs::write(home.join("Library/Application Support"), "not a directory").unwrap();
        let failed = discover_support_roots(&home);
        assert!(failed.error && !failed.capped);
        let mut interrupted = missing;
        interrupted.collect(std::iter::once(Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "synthetic enumeration error",
        ))));
        assert!(interrupted.error && !interrupted.capped);
    }
}
