//! A deliberately narrow native dependency closure: Pi without attribution.
//! Capture precedes the native scan. Retries inspect only frozen paths, never
//! enumerate or parse providers. Unsupported/larger trees stay ordinary work.
use super::*;
use crate::heap_layout_bound::{Counter, HeapLayoutBound};

const MAX_PATHS: usize = 128;
const MAX_PATH_BYTES: usize = 32 * 1024;
const MAX_CONTENT_BYTES: u64 = 8 * 1024 * 1024;

pub(crate) struct PiRetryInputs {
    root: PathBuf,
    paths: Vec<Input>,
}
struct Input {
    path: PathBuf,
    stamp: [u8; 32],
    file_fingerprint: Option<String>,
}

fn stamp(metadata: &fs::Metadata) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(metadata.len().to_be_bytes());
    #[cfg(unix)]
    for n in [
        metadata.dev(),
        metadata.ino(),
        metadata.ctime() as u64,
        metadata.ctime_nsec() as u64,
        metadata.mtime() as u64,
        metadata.mtime_nsec() as u64,
    ] {
        h.update(n.to_be_bytes());
    }
    h.finalize().into()
}

fn identify(root: &Path, path: &Path) -> Option<String> {
    let mut candidate = CandidateFile {
        scan_root: root.to_owned(),
        path: path.to_owned(),
        size_bytes: 0,
        modified_unix_seconds: 0,
        modified_unix_nanos: 0,
        source_file_fingerprint: String::new(),
        legacy_source_file_fingerprint: String::new(),
        legacy_config_reconciliation_required: false,
        opened_object_identity: String::new(),
    };
    let _file = open_candidate_file(SnapshotSource::Pi, &mut candidate).ok()?;
    Some(scan_file_fingerprint_with_opened_identity(
        path,
        candidate.size_bytes,
        candidate.modified_unix_nanos,
        SnapshotSource::Pi.scan_identity_version(),
        "",
        &candidate.opened_object_identity,
    ))
}

impl PiRetryInputs {
    pub(crate) fn capture(root: &Path) -> Option<Self> {
        // Canonicalize once to reject symlink roots and every ancestor. The
        // native opener subsequently uses no-follow descriptor-relative opens.
        if !root.is_absolute() || root.canonicalize().ok()?.as_path() != root {
            return None;
        }
        let mut result = Self {
            root: root.to_owned(),
            paths: Vec::new(),
        };
        let mut pending = vec![root.to_owned()];
        let mut path_bytes = root.as_os_str().len();
        let mut content_bytes = 0u64;
        while let Some(path) = pending.pop() {
            if result.paths.len() + pending.len() >= MAX_PATHS {
                return None;
            }
            let before = fs::symlink_metadata(&path).ok()?;
            if before.file_type().is_symlink() {
                return None;
            }
            let fingerprint = if before.is_dir() {
                for entry in fs::read_dir(&path).ok()? {
                    let child = entry.ok()?.path();
                    path_bytes = path_bytes.checked_add(child.as_os_str().len())?;
                    if path_bytes > MAX_PATH_BYTES
                        || result.paths.len() + pending.len() + 1 >= MAX_PATHS
                    {
                        return None;
                    }
                    pending.push(child);
                }
                None
            } else if before.is_file() && path.extension().is_some_and(|e| e == "jsonl") {
                content_bytes = content_bytes.checked_add(before.len())?;
                if content_bytes > MAX_CONTENT_BYTES {
                    return None;
                }
                Some(identify(root, &path)?)
            } else {
                // Non-transcript files and special objects have no closed
                // provider semantics in this initial admission.
                return None;
            };
            let after = fs::symlink_metadata(&path).ok()?;
            if stamp(&before) != stamp(&after) {
                return None;
            }
            result.paths.push(Input {
                path,
                stamp: stamp(&after),
                file_fingerprint: fingerprint,
            });
        }
        result.validate().ok()?;
        Some(result)
    }

    pub(crate) fn root(&self) -> &Path {
        &self.root
    }

    pub(crate) fn validate(&self) -> Result<()> {
        anyhow::ensure!(
            self.root.canonicalize()?.as_path() == self.root,
            "optional Pi ancestor changed"
        );
        // Read ancestors before and after all leaves so mutation during this
        // pass cannot be blessed by only checking a directory once.
        for input in self.paths.iter().chain(self.paths.iter().rev()) {
            let current = fs::symlink_metadata(&input.path)?;
            anyhow::ensure!(
                !current.file_type().is_symlink() && stamp(&current) == input.stamp,
                "optional Pi dependency changed"
            );
            if let Some(expected) = &input.file_fingerprint {
                anyhow::ensure!(
                    identify(&self.root, &input.path).as_ref() == Some(expected),
                    "optional Pi opened file changed"
                );
            }
        }
        Ok(())
    }

    pub(crate) fn covers(&self, items: &[SnapshotItem]) -> bool {
        items.iter().all(|item| {
            // Workspace/repository identity can read mutable Git metadata
            // outside these frozen transcript roots. Decline that graph until
            // it has its own complete source-owned dependency witness.
            item.workspace_hash.is_none()
                && item.repository_hash.is_none()
                && item.repository_label.is_none()
                && item.repository_label_source.is_none()
                && item.repository_identity_source.is_none()
                && item.workspace_kind.is_none()
                && item.source_file_fingerprint.as_ref().is_some_and(|fp| {
                    self.paths
                        .iter()
                        .any(|input| input.file_fingerprint.as_ref() == Some(fp))
                })
        })
    }
}
impl HeapLayoutBound for PiRetryInputs {
    fn heap_bound(&self, c: &mut Counter) -> Option<()> {
        let Self { root, paths } = self;
        root.heap_bound(c)?;
        c.add(paths.capacity().checked_mul(std::mem::size_of::<Input>())?)?;
        for input in paths {
            let Input {
                path,
                stamp: _,
                file_fingerprint,
            } = input;
            path.heap_bound(c)?;
            file_fingerprint.heap_bound(c)?;
        }
        Some(())
    }
}
