//! The real resumable upload loop and its exact-body progress, for Tail transition
//! fixtures: POSTs are counted, every one is accepted, and nothing is persisted.
use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};

pub(crate) struct AckLedger {
    progress: SnapshotUploadProgress,
    accepted: u64,
    posts: usize,
    scope: String,
}

impl AckLedger {
    pub(crate) fn new(source: SnapshotSource) -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        Self {
            progress: SnapshotUploadProgress::new(
                format!("{:064x}", 99),
                snapshot_quarantine_witness(source),
            ),
            accepted: 0,
            posts: 0,
            scope: format!("tail-ack-ledger-{}", NEXT.fetch_add(1, Ordering::Relaxed)),
        }
    }

    /// Offers `items`: an exact body already accepted posts nothing.
    pub(crate) fn deliver(&mut self, items: &[SnapshotItem]) {
        let posts = &mut self.posts;
        upload_resumable_batches_with_body_witness(
            items,
            &self.scope,
            &mut self.progress,
            &mut self.accepted,
            |item| item.snapshot_fingerprint.as_str(),
            crate::snapshots::snapshot_upload_body_witness,
            |batch| {
                *posts += batch.len();
                Ok(crate::snapshot_client::SnapshotBatchResponse {
                    conflict_rescans: Default::default(),
                    accepted: batch.len() as u64,
                    sessions_reconciled: batch.len() as u64,
                    session_ids: Vec::new(),
                    disabled: false,
                    disabled_reason: None,
                    entity_ack_contract: None,
                    accepted_entities: Vec::new(),
                    unchanged_entities: Vec::new(),
                    rejected_entities: Vec::new(),
                    conflict_entities: Vec::new(),
                })
            },
            |_| Ok(()),
        )
        .unwrap();
    }

    /// This exact body has a durable ACK.
    pub(crate) fn settled(&self, item: &SnapshotItem) -> bool {
        self.progress
            .accepted_fingerprints
            .contains(&item.snapshot_fingerprint)
            && self
                .progress
                .accepted_body_witnesses
                .get(&item.snapshot_fingerprint)
                == Some(&crate::snapshots::snapshot_upload_body_witness(item))
    }

    pub(crate) fn posts(&self) -> usize {
        self.posts
    }
}
