//! Encoded per-source admission, independent of verification memo residency.
//! No eviction: a file that can append remains active even when idle or ACKed.
use super::*;

pub(crate) const CLAUDE_QUOTA_BYTES: u64 = 512 * 1024 * 1024;
pub(crate) const CODEX_QUOTA_BYTES: u64 = 128 * 1024 * 1024;
// Pi's registration is owned by its source adapter; no new representation here.
pub(crate) const PI_QUOTA_BYTES: u64 = 32 * 1024 * 1024;

impl DurableTailStore {
    /// Called only by the restart_restore source owner. Zero preserves M1.
    pub(crate) fn enable_capacity_quota(&mut self) {
        self.capacity_quota = match self.source {
            DurableSource::ClaudeCode => CLAUDE_QUOTA_BYTES,
            DurableSource::Codex => CODEX_QUOTA_BYTES,
        };
        self.counters.tail_quota_bytes = self.capacity_quota;
    }

    /// Stream names and lstat metadata only, including protected/unknown files.
    /// There is no population-sized map, payload read, or deletion authority.
    /// `staged` means the caller's exact candidate is already included in temps.
    pub(super) fn admit_capacity(
        &mut self,
        key: &Digest32,
        encoded_len: u64,
        staged: bool,
    ) -> io::Result<bool> {
        if self.capacity_quota == 0 {
            return Ok(true);
        }
        let mut records = 0u64;
        let mut bytes = 0u64;
        let mut temps = 0u64;
        let mut prior = 0u64;
        let entries = match fs::read_dir(&self.dir) {
            Ok(entries) => Some(entries),
            Err(e) if e.kind() == io::ErrorKind::NotFound => None,
            Err(e) => return Err(e),
        };
        for entry in entries.into_iter().flatten() {
            let entry = entry?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            let record_key = name.strip_suffix(RECORD_SUFFIX).and_then(parse_hex_digest);
            if record_key.is_none() && !name.ends_with(TEMP_SUFFIX) {
                continue;
            }
            let metadata = fs::symlink_metadata(entry.path())?;
            // An uninterpretable occupant never becomes free quota credit.
            if !metadata.is_file() || metadata.uid() != our_uid() {
                return Err(io::Error::other("unaccountable capacity occupant"));
            }
            if let Some(record_key) = record_key {
                records = records.saturating_add(1);
                bytes = bytes.saturating_add(metadata.len());
                if record_key == *key {
                    prior = metadata.len();
                }
            } else {
                temps = temps.saturating_add(metadata.len());
            }
        }
        self.counters.tail_checkpoint_files = records;
        self.counters.tail_referenced_bytes = bytes;
        self.counters.tail_staged_bytes = temps;
        let admitted = bytes.saturating_sub(prior).saturating_add(encoded_len)
            <= self.capacity_quota
            && temps.saturating_add(if staged { 0 } else { encoded_len })
                <= WRITE_PASS_BYTES as u64;
        if !admitted {
            self.counters.capacity_refused += 1;
        }
        Ok(admitted)
    }
}
