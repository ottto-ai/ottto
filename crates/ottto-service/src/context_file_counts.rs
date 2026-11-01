//! Bounded local-file measurements. Only counts and a device-salted digest
//! leave this module; file text and resolved paths never enter the wire model.

use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;

pub(crate) const MAX_FILE_BYTES: usize = 1024 * 1024;
// Claude Code auto-memory limits (UTF-16 units, whole lines). Reverify on
// harness upgrades. These do not apply to CLAUDE.md or imported instructions.
pub(crate) const AUTO_MEMORY_LIMIT: (usize, usize) = (200, 25_000);
const HASH_DOMAIN: &[u8] = b"ottto-context-file-v1\0";

#[derive(Debug, Clone, Default, serde::Serialize, PartialEq)]
pub(crate) struct FileCounts {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) file_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) file_lines: Option<u64>,
    /// JavaScript string length, not Unicode scalar count or UTF-8 bytes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) file_chars: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) content_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) loaded_lines: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) truncated_by_limit: Option<bool>,
}

/// Counts for complete file bytes already in memory (never a partial prefix).
pub(crate) fn measure_bytes(
    bytes: &[u8],
    auto_memory: bool,
    salt: Option<&[u8; 32]>,
) -> Option<FileCounts> {
    if bytes.len() > MAX_FILE_BYTES {
        return None;
    }
    let text = std::str::from_utf8(bytes).ok()?;
    // split_terminator excludes the phantom line after a final newline, while
    // retaining empty lines and CR units in CRLF input.
    let mut file_lines = 0usize;
    let mut loaded_lines = 0usize;
    let mut loaded_chars = 0usize;
    let mut cut = false;
    for line in text.split_terminator('\n') {
        file_lines += 1;
        let joined_chars =
            loaded_chars + usize::from(loaded_lines > 0) + line.encode_utf16().count();
        if !cut && loaded_lines < AUTO_MEMORY_LIMIT.0 && joined_chars <= AUTO_MEMORY_LIMIT.1 {
            loaded_lines += 1;
            loaded_chars = joined_chars;
        } else {
            cut = true;
        }
    }
    Some(FileCounts {
        file_bytes: Some(bytes.len() as u64),
        file_lines: Some(file_lines as u64),
        file_chars: Some(text.encode_utf16().count() as u64),
        content_hash: salt.map(|salt| salted_content_hash(salt, bytes)),
        loaded_lines: auto_memory.then_some(loaded_lines as u64),
        truncated_by_limit: auto_memory.then_some(loaded_lines < file_lines),
    })
}

/// Shared hash format for local instruction collectors. The random salt is
/// local-only, stable across restarts, and never included in an upload. Hashes
/// are comparable only within a device; cross-device size checks use bytes.
pub(crate) fn salted_content_hash(salt: &[u8; 32], bytes: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(HASH_DOMAIN);
    digest.update(salt);
    digest.update(bytes);
    format!("{:x}", digest.finalize())
}

/// The device salt for collectors without a support-dir handle (the snapshot
/// pass), read once per process. Tests use a fixed salt and touch no files.
pub(crate) fn device_salt() -> Option<[u8; 32]> {
    #[cfg(test)]
    {
        Some([0x5a; 32])
    }
    #[cfg(not(test))]
    {
        static SALT: std::sync::OnceLock<Option<[u8; 32]>> = std::sync::OnceLock::new();
        *SALT.get_or_init(|| load_or_create_salt(&ottto_core::default_support_dir()))
    }
}

pub(crate) fn load_or_create_salt(support_dir: &Path) -> Option<[u8; 32]> {
    let dir = support_dir.join("context-footprint");
    fs::create_dir_all(&dir).ok()?;
    let path = dir.join("content-hash-salt-v1");
    if path.exists() {
        return read_salt(&path);
    }
    let mut salt = [0u8; 32];
    getrandom::fill(&mut salt).ok()?;
    let suffix = salted_content_hash(&salt, b"temporary");
    let temporary = dir.join(format!(".salt-{}", &suffix[..16]));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let result = (|| {
        let mut file = options.open(&temporary).ok()?;
        file.write_all(&salt).ok()?;
        file.sync_all().ok()?;
        // Publish complete bytes without replacing a concurrent creator's salt.
        match fs::hard_link(&temporary, &path) {
            Ok(()) => Some(salt),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => read_salt(&path),
            Err(_) => None,
        }
    })();
    let _ = fs::remove_file(temporary);
    result
}

fn read_salt(path: &Path) -> Option<[u8; 32]> {
    let mut bytes = Vec::new();
    File::open(path)
        .ok()?
        .take(33)
        .read_to_end(&mut bytes)
        .ok()?;
    bytes.try_into().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn measured(text: &str, auto_memory: bool) -> FileCounts {
        measure_bytes(text.as_bytes(), auto_memory, Some(&[7; 32])).unwrap()
    }

    #[test]
    fn counts_utf16_and_limits_whole_lines() {
        let text = format!("{}\n{}\n", "😀".repeat(6_000), "é".repeat(14_000));
        let counts = measured(&text, true);
        assert_eq!(counts.file_bytes, Some(text.len() as u64));
        assert_eq!(counts.file_chars, Some(26_002));
        assert_eq!(counts.file_lines, Some(2));
        assert_eq!(counts.loaded_lines, Some(1));
        assert_eq!(counts.truncated_by_limit, Some(true));
        let counts = measured(&text, false);
        assert_eq!(counts.loaded_lines, None);
        assert_eq!(counts.truncated_by_limit, None);
    }

    #[test]
    fn line_limit_empty_crlf_and_exact_boundary() {
        assert_eq!(measured("", true).loaded_lines, Some(0));
        assert_eq!(measured("a\r\n\r\n", true).file_chars, Some(5));
        assert_eq!(measured("a\r\n\r\n", true).file_lines, Some(2));
        assert_eq!(
            measured(&"x\n".repeat(200), true).truncated_by_limit,
            Some(false)
        );
        assert_eq!(measured(&"x\n".repeat(201), true).loaded_lines, Some(200));
        assert_eq!(measured(&"x".repeat(25_000), true).loaded_lines, Some(1));
        assert_eq!(measured(&"x".repeat(25_001), true).loaded_lines, Some(0));
        assert_eq!(measured("\n\n", true).loaded_lines, Some(2));
    }

    #[test]
    fn oversize_and_binary_are_unknown() {
        assert!(measure_bytes(&[0xff], true, None).is_none());
        assert!(measure_bytes("x".repeat(MAX_FILE_BYTES + 1).as_bytes(), true, None).is_none());
    }

    #[test]
    fn salt_is_persistent_private_and_device_specific() {
        let dir = crate::test_scratch::private_dir("context-file-salt");
        let salt = load_or_create_salt(&dir).unwrap();
        assert_eq!(load_or_create_salt(&dir), Some(salt));
        assert_ne!(
            salted_content_hash(&salt, b"same"),
            salted_content_hash(&[0; 32], b"same")
        );
        assert_ne!(
            salted_content_hash(&salt, b"same"),
            salted_content_hash(&salt, b"edit")
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(dir.join("context-footprint/content-hash-salt-v1"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
        fs::remove_dir_all(dir).unwrap();
    }
}
