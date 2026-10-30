//! Diagnostic ACK ages only. No persisted clock, acceptance or timeout policy.
use super::*;
use std::time::{SystemTime, UNIX_EPOCH};
const ACK_AGE_MEMO_MAX: usize = 65_536;
#[derive(Default)]
struct AckAges {
    // Hash of destination, entity and exact body; never raw identifiers/logs.
    first: BTreeMap<[u8; 32], u64>,
    order: VecDeque<[u8; 32]>,
}
fn key(destination: &str, entity: &str, body: &str) -> [u8; 32] {
    use sha2::Digest;
    let mut digest = sha2::Sha256::new();
    for part in [destination, entity, body] {
        digest.update((part.len() as u64).to_le_bytes());
        digest.update(part.as_bytes());
    }
    digest.finalize().into()
}
impl AckAges {
    fn accept(&mut self, key: [u8; 32], now: u64) {
        if self.first.contains_key(&key) {
            return;
        }
        if self.first.len() == ACK_AGE_MEMO_MAX {
            if let Some(oldest) = self.order.pop_front() {
                self.first.remove(&oldest);
            }
        }
        self.first.insert(key, now);
        self.order.push_back(key);
        // A newly ACKed exact body always gets its real acceptance time.
        // Eviction makes an older diagnostic age unknown; it never evicts an
        // accepted ledger entry, settles debt or drives an age-based decision.
    }
    fn gauge(&self, keys: impl Iterator<Item = [u8; 32]>, now: u64) -> (Option<u64>, usize) {
        let (mut oldest, mut unknown) = (None, 0usize);
        for key in keys {
            if let Some(first) = self.first.get(&key) {
                oldest = Some(oldest.unwrap_or(0).max(now.saturating_sub(*first)));
            } else {
                unknown = unknown.saturating_add(1);
            }
        }
        (oldest, unknown)
    }
}
fn memo() -> &'static Mutex<AckAges> {
    static MEMO: std::sync::OnceLock<Mutex<AckAges>> = std::sync::OnceLock::new();
    MEMO.get_or_init(Default::default)
}
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
pub(super) fn accepted(destination: &str, entity: &str, body: &str) {
    if !crate::snapshots::claude_terminal_off() {
        return;
    }

    if let Ok(mut ages) = memo().lock() {
        ages.accept(key(destination, entity, body), now());
    }
}
pub(super) fn note(index: &ScanIndex, progress: &SnapshotUploadProgress) {
    let keys = progress.accepted_fingerprints.iter().map(|entity| {
        key(
            &progress.destination_namespace_hash,
            entity,
            progress
                .accepted_body_witnesses
                .get(entity)
                .map(String::as_str)
                .unwrap_or(""),
        )
    });
    let (age, unknown) = memo()
        .lock()
        .map(|ages| ages.gauge(keys, now()))
        .unwrap_or((None, progress.accepted_fingerprints.len()));
    let bytes = crate::snapshots::retained_metadata_bytes(&(
        &progress.accepted_fingerprints,
        &progress.accepted_body_witnesses,
        &progress.accepted_cache_states,
        &progress.accepted_cache_heads,
    ));
    index.note_terminal_off_transport_retention(
        &progress.accepted_fingerprints,
        bytes,
        age,
        unknown,
    );
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn terminal_off_new_exact_ack_has_real_process_age_legacy_stays_unknown() {
        let (new, legacy) = (key("D", "new", "body"), key("D", "legacy", "body"));
        let mut memo = AckAges::default();
        assert_eq!(memo.gauge([legacy].into_iter(), 100), (None, 1));
        memo.accept(new, 100);
        memo.accept(new, 120); // repeated observation cannot make age younger
        assert_eq!(memo.gauge([new, legacy].into_iter(), 130), (Some(30), 1));
        assert_eq!(memo.gauge([new].into_iter(), 90), (Some(0), 0));
        assert_eq!(AckAges::default().gauge([new].into_iter(), 140), (None, 1));
        assert_ne!(new, key("C", "new", "body"));
        assert_ne!(new, key("D", "new", "changed"));
        for number in 0..ACK_AGE_MEMO_MAX {
            let mut next = [0; 32];
            next[..8].copy_from_slice(&(number as u64).to_le_bytes());
            memo.accept(next, 200);
        }
        let newest = key("D", "after-cap", "body");
        memo.accept(newest, 300);
        assert_eq!(memo.first.len(), ACK_AGE_MEMO_MAX);
        assert_eq!(memo.order.len(), ACK_AGE_MEMO_MAX);
        assert_eq!(memo.gauge([newest, new].into_iter(), 310), (Some(10), 1));
    }
}
