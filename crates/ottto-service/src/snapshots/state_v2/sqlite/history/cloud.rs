//! Codex cloud-task ACK cache in the upload-history file: the digest and head
//! etag of each task's last exact server ACK, and the UTC day of the last
//! finished daily crawl. A discardable dedupe aid: provider facts and the
//! server stay the truth, and these rows never enter diagnostic receipt
//! pages, appends, ring import or retention.
use super::Store;
use anyhow::Result;
use rusqlite::{params, OptionalExtension, TransactionBehavior};
use std::collections::HashMap;

/// Added by `user_version` 2, atomically with the version bump.
pub(super) const SCHEMA: &str = "
CREATE TABLE cloud_task_acks(
 scope_key BLOB NOT NULL CHECK(length(scope_key)=32),
 entity_key TEXT NOT NULL CHECK(length(entity_key) BETWEEN 1 AND 128),
 semantic_digest BLOB NOT NULL CHECK(length(semantic_digest)=32),
 head_etag TEXT CHECK(head_etag IS NULL OR length(head_etag)=64),
 acked_at_unix INTEGER NOT NULL,
 expires_at_unix INTEGER NOT NULL,
 PRIMARY KEY(scope_key, entity_key)
) STRICT, WITHOUT ROWID;
CREATE INDEX cloud_task_acks_expiry ON cloud_task_acks(expires_at_unix);
CREATE TABLE cloud_collector_state(
 scope_key BLOB PRIMARY KEY CHECK(length(scope_key)=32),
 crawl_completed_date TEXT
) STRICT, WITHOUT ROWID;";

/// An entry lives this long from its exact ACK; unchanged polls never extend
/// it. After expiry the task is offered again and the server answers noop.
pub(crate) const ACK_TTL_SECONDS: i64 = 30 * 24 * 60 * 60;
/// Expired rows are deleted this many at a time, continuing at later commits.
const PRUNE_PAGE: i64 = 200;
const READ: &str = "SELECT semantic_digest, head_etag FROM cloud_task_acks WHERE scope_key=?1 AND entity_key=?2 AND expires_at_unix>?3";
const UPSERT: &str = "INSERT INTO cloud_task_acks(scope_key,entity_key,semantic_digest,head_etag,acked_at_unix,expires_at_unix) VALUES(?1,?2,?3,?4,?5,?6) ON CONFLICT(scope_key,entity_key) DO UPDATE SET semantic_digest=excluded.semantic_digest, head_etag=excluded.head_etag, acked_at_unix=excluded.acked_at_unix, expires_at_unix=excluded.expires_at_unix";
const PRUNE: &str = "DELETE FROM cloud_task_acks WHERE (scope_key,entity_key) IN (SELECT scope_key,entity_key FROM cloud_task_acks INDEXED BY cloud_task_acks_expiry WHERE expires_at_unix<=?1 LIMIT ?2)";
const READ_STATE: &str =
    "SELECT crawl_completed_date FROM cloud_collector_state WHERE scope_key=?1";
const WRITE_STATE: &str = "INSERT INTO cloud_collector_state(scope_key,crawl_completed_date) VALUES(?1,?2) ON CONFLICT(scope_key) DO UPDATE SET crawl_completed_date=excluded.crawl_completed_date";
const ERASE_ACKS: &str = "DELETE FROM cloud_task_acks WHERE (scope_key,entity_key) IN (SELECT scope_key,entity_key FROM cloud_task_acks LIMIT ?1)";

/// One task's remembered ACK. `head_etag` is `None` for a per-task refusal of
/// exactly this content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CloudAck {
    pub(crate) digest: [u8; 32],
    pub(crate) head_etag: Option<String>,
}

/// One settled task to remember.
pub(crate) struct CloudAckWrite<'a> {
    pub(crate) entity_key: &'a str,
    pub(crate) digest: [u8; 32],
    pub(crate) head_etag: Option<&'a str>,
}

impl Store {
    /// Unexpired ACKs for exactly `keys`, in one short read transaction of
    /// primary-key lookups. A row that fails its shape check reads as absent.
    pub(crate) fn cloud_read_acks(
        &mut self,
        scope: &[u8; 32],
        keys: &[&str],
        now_unix: i64,
    ) -> Result<HashMap<String, CloudAck>> {
        self.check_object()?;
        let tx = self.conn.transaction()?;
        let mut found = HashMap::new();
        {
            let mut read = tx.prepare_cached(READ)?;
            for key in keys {
                let row = read
                    .query_row(params![&scope[..], key, now_unix], |row| {
                        Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Option<String>>(1)?))
                    })
                    .optional()?;
                if let Some((digest, head_etag)) = row {
                    if let Ok(digest) = <[u8; 32]>::try_from(digest.as_slice()) {
                        found.insert((*key).to_owned(), CloudAck { digest, head_etag });
                    }
                }
            }
        }
        tx.commit()?;
        Ok(found)
    }

    /// One write transaction per work slice: the slice's settled tasks, the
    /// crawl completion day when it changed, and one page of expired rows.
    pub(crate) fn cloud_commit(
        &mut self,
        scope: &[u8; 32],
        acks: &[CloudAckWrite<'_>],
        crawl_completed_date: Option<&str>,
        now_unix: i64,
    ) -> Result<()> {
        self.check_object()?;
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        {
            let mut upsert = tx.prepare_cached(UPSERT)?;
            for ack in acks {
                upsert.execute(params![
                    &scope[..],
                    ack.entity_key,
                    &ack.digest[..],
                    ack.head_etag,
                    now_unix,
                    now_unix.saturating_add(ACK_TTL_SECONDS),
                ])?;
            }
        }
        if let Some(date) = crawl_completed_date {
            tx.prepare_cached(WRITE_STATE)?
                .execute(params![&scope[..], date])?;
        }
        tx.prepare_cached(PRUNE)?
            .execute(params![now_unix, PRUNE_PAGE])?;
        tx.commit()?;
        Ok(())
    }

    pub(crate) fn cloud_crawl_completed_date(
        &mut self,
        scope: &[u8; 32],
    ) -> Result<Option<String>> {
        self.check_object()?;
        Ok(self
            .conn
            .prepare_cached(READ_STATE)?
            .query_row([&scope[..]], |row| row.get::<_, Option<String>>(0))
            .optional()?
            .flatten())
    }

    /// Delete every cloud row, a bounded page per transaction, after a local
    /// revoke. Only one grant scope exists per installation.
    pub(crate) fn cloud_erase_all(&mut self) -> Result<()> {
        self.check_object()?;
        loop {
            let tx = self
                .conn
                .transaction_with_behavior(TransactionBehavior::Immediate)?;
            let deleted = tx.prepare_cached(ERASE_ACKS)?.execute([1_000_i64])?;
            if deleted == 0 {
                tx.execute("DELETE FROM cloud_collector_state", [])?;
                tx.commit()?;
                return Ok(());
            }
            tx.commit()?;
        }
    }
}

#[cfg(test)]
pub(crate) const QUERIES_FOR_TEST: [(&str, &str); 3] =
    [("read", READ), ("prune", PRUNE), ("read_state", READ_STATE)];
