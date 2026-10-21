//! Local-only list of Claude Code sessions that the one-time history re-read
//! (body-witness adoption) must not re-emit until their own recovery settles
//! them.
//!
//! The Mac's runtime owner writes the file; the daemon only reads it. Each
//! line is the lowercase hex SHA-256 of one exact, full `source_session_id`.
//! Blank lines and `#` lines are ignored. No id, digest or path is logged;
//! only counts. A missing file is an empty list, so every other Mac is
//! unaffected. An unreadable, oversized or malformed file fails closed for
//! adoption only: the caller defers every adoption-only file that cycle.

use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::io::Read;
use std::path::{Path, PathBuf};

const FILE_NAME: &str = "claude_code-reemission-exclusions.txt";
const MAX_BYTES: u64 = 64 * 1024;
const MAX_LINES: usize = 1_024;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct ReemissionExclusions {
    digests: BTreeSet<String>,
    invalid: bool,
}

crate::heap_layout_bound::fields!(ReemissionExclusions; digests, invalid);

impl ReemissionExclusions {
    pub(crate) fn path(support_dir: &Path) -> PathBuf {
        support_dir.join("snapshots").join(FILE_NAME)
    }

    pub(crate) fn load(support_dir: &Path) -> Self {
        let file = match std::fs::File::open(Self::path(support_dir)) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Self::default(),
            Err(_) => return Self::refused(),
        };
        let mut bytes = Vec::new();
        match file.take(MAX_BYTES + 1).read_to_end(&mut bytes) {
            Ok(_) if bytes.len() as u64 <= MAX_BYTES => Self::parse(&bytes),
            _ => Self::refused(),
        }
    }

    pub(crate) fn parse(bytes: &[u8]) -> Self {
        let Ok(text) = std::str::from_utf8(bytes) else {
            return Self::refused();
        };
        let mut digests = BTreeSet::new();
        for (count, line) in text.lines().enumerate() {
            if count >= MAX_LINES {
                return Self::refused();
            }
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if line.len() != 64
                || !line
                    .bytes()
                    .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
            {
                return Self::refused();
            }
            digests.insert(line.to_string());
        }
        Self {
            digests,
            invalid: false,
        }
    }

    fn refused() -> Self {
        Self {
            digests: BTreeSet::new(),
            invalid: true,
        }
    }

    pub(crate) fn is_invalid(&self) -> bool {
        self.invalid
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.digests.is_empty()
    }

    /// True when the exact full id of the family root or of this member is
    /// listed.
    pub(crate) fn excludes(&self, root_session_id: &str, member_session_id: &str) -> bool {
        !self.is_empty()
            && [root_session_id, member_session_id].iter().any(|id| {
                self.digests
                    .contains(&format!("{:x}", Sha256::digest(id.as_bytes())))
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(id: &str) -> String {
        format!("{:x}", Sha256::digest(id.as_bytes()))
    }

    #[test]
    fn missing_file_is_an_empty_valid_list() {
        let dir = crate::test_scratch::ScratchDir::new("reemission-exclusions-missing");
        let loaded = ReemissionExclusions::load(&dir);
        assert_eq!(loaded, ReemissionExclusions::default());
        assert!(!loaded.is_invalid());
        assert!(!loaded.excludes("root", "root"));
    }

    #[test]
    fn listed_root_or_member_digest_is_excluded() {
        let text = format!(
            "# h527\n\n{}\n  {}  \n",
            digest("root-a"),
            digest("root-b_agent-1")
        );
        let parsed = ReemissionExclusions::parse(text.as_bytes());
        assert!(!parsed.is_invalid());
        assert!(parsed.excludes("root-a", "root-a"));
        assert!(parsed.excludes("root-a", "root-a_agent-9"));
        assert!(parsed.excludes("root-b", "root-b_agent-1"));
        assert!(!parsed.excludes("root-b", "root-b"));
        assert!(!parsed.excludes("root-b", "root-b_agent-2"));
    }

    #[test]
    fn malformed_or_oversized_list_fails_closed() {
        let upper = digest("root-a").to_uppercase();
        for bad in [
            "not-a-digest\n".to_string(),
            format!("{}\n", &digest("root-a")[..63]),
            format!("{upper}\n"),
            format!("{} extra\n", digest("root-a")),
        ] {
            assert!(
                ReemissionExclusions::parse(bad.as_bytes()).is_invalid(),
                "{bad:?}"
            );
        }
        assert!(ReemissionExclusions::parse(&[0xff, 0xfe]).is_invalid());
        let too_many = "#\n".repeat(MAX_LINES + 1);
        assert!(ReemissionExclusions::parse(too_many.as_bytes()).is_invalid());
        let at_limit = "#\n".repeat(MAX_LINES);
        assert!(!ReemissionExclusions::parse(at_limit.as_bytes()).is_invalid());

        let dir = crate::test_scratch::ScratchDir::new("reemission-exclusions-oversized");
        let path = ReemissionExclusions::path(&dir);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, vec![b'#'; MAX_BYTES as usize + 1]).unwrap();
        assert!(ReemissionExclusions::load(&dir).is_invalid());
        std::fs::write(&path, format!("{}\n", digest("root-a"))).unwrap();
        let loaded = ReemissionExclusions::load(&dir);
        assert!(!loaded.is_invalid());
        assert!(loaded.excludes("root-a", "root-a"));
    }
}
