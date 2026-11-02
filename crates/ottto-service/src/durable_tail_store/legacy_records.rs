//! Legacy per-key erasure. An unlink settles only after its directory barrier.
use super::*;

impl DurableTailStore {
    /// OFF may remove only the retired v1 record for this published key.
    /// Failure never gates native publication; the next publication retries.
    pub(crate) fn invalidate_outgrown_v1<W: SingleWriter>(
        &mut self,
        writer: &W,
        key: &Digest32,
        published_end: u64,
    ) -> io::Result<bool> {
        let result = (|| -> io::Result<bool> {
            self.check_writer(writer)?;
            // Retry only our own unlink barrier, never the startup restore sync.
            self.sync_off_v1_unlink()?;
            if self.pending.contains_key(key) {
                return Ok(false);
            }
            let header = match self.classify(key, "off_invalidate", Some(writer)) {
                Ok(Some(header)) => header,
                Ok(None) => return Ok(self.record_missing(key)),
                Err(_) => return Err(io::Error::other("OFF v1 classification refused")),
            };
            if published_end <= header.record.certificate.length {
                return Ok(false);
            }
            let path = self.record_path(key);
            if stamp_at(&path)? != header.stamp {
                return Ok(false); // Never unlink a replacement of the identified header.
            }
            remove_if_present(&path)?;
            self.durable.remove(key);
            // If the barrier fails, the next classification retries it even
            // though the pathname is now absent. No deletion is reported early.
            self.startup_synced = false;
            self.off_v1_sync_due = true;
            self.sync_off_v1_unlink()?;
            Ok(true)
        })();
        if result.is_err() {
            self.counters.off_v1_invalidate_failed += 1;
        }
        result
    }

    /// Physical absence after any outstanding OFF unlink barrier. A missing
    /// name alone cannot settle a deletion whose directory sync failed.
    pub(crate) fn record_missing(&self, key: &Digest32) -> bool {
        !self.off_v1_sync_due && matches!(stamp_at(&self.record_path(key)), Ok(None))
    }

    /// Destination changes cannot drop an unlink that still owes its barrier.
    pub(crate) fn retry_off_v1_unlink(
        &mut self,
        writer: Option<&dyn SingleWriter>,
    ) -> io::Result<()> {
        if !self.off_v1_sync_due {
            return Ok(());
        }
        let result = (|| {
            self.check_writer(
                writer.ok_or_else(|| io::Error::from(io::ErrorKind::PermissionDenied))?,
            )?;
            self.sync_off_v1_unlink()
        })();
        if result.is_err() {
            self.counters.off_v1_invalidate_failed += 1;
        }
        result
    }

    pub(crate) fn inherit_off_v1_counts(&mut self, previous: &Self) {
        debug_assert!(!previous.off_v1_sync_due);
        self.counters.off_v1_invalidated += previous.counters.off_v1_invalidated;
        self.counters.off_v1_invalidate_failed += previous.counters.off_v1_invalidate_failed;
    }

    fn sync_off_v1_unlink(&mut self) -> io::Result<()> {
        if self.off_v1_sync_due {
            if self.read_only_directory()? {
                self.sync_store()?;
            } else {
                // A removed whole store is settled by its parent's barrier.
                sync_dir(
                    self.dir
                        .parent()
                        .ok_or_else(|| io::Error::other("store parent"))?,
                )?;
            }
            self.off_v1_sync_due = false;
            self.startup_synced = true;
            self.counters.off_v1_invalidated += 1;
        }
        Ok(())
    }
}
