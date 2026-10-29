//! E3: RAM-only re-parse memo for withheld-account holds. A held key re-parses
//! once per process, then only when its stamp or the account evidence its
//! resolver reads changes. Losing the memo costs one re-parse, never a Skip.
use super::*;
use crate::local_resource_diagnostics::{withheld_event, WithheldEvent};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Seen {
    size_bytes: u64,
    modified_unix_nanos: u64,
    evidence: [u8; 32],
}
crate::heap_layout_bound::fields!(Seen; size_bytes, modified_unix_nanos, evidence);

/// Keyed by a digest of the index key, so entries have a fixed size; at most
/// `MAX_CLAUDE_ACCOUNT_DEFERRED_HOLDS` entries.
type Memo = BTreeMap<[u8; 32], Seen>;
#[cfg(not(test))]
static MEMO: Mutex<Memo> = Mutex::new(BTreeMap::new());
#[cfg(test)]
thread_local! {
    static MEMO: Mutex<Memo> = const { Mutex::new(BTreeMap::new()) };
}
/// A poisoned memo is unknown: nothing is skipped.
fn with_memo<R>(f: impl FnOnce(&mut Memo) -> R) -> Option<R> {
    #[cfg(test)]
    {
        MEMO.with(|memo| memo.lock().ok().map(|mut memo| f(&mut memo)))
    }
    #[cfg(not(test))]
    {
        MEMO.lock().ok().map(|mut memo| f(&mut memo))
    }
}

fn digest(parts: &[&str]) -> [u8; 32] {
    let mut digest = Sha256::new();
    for part in parts {
        digest.update((part.len() as u64).to_be_bytes());
        digest.update(part.as_bytes());
    }
    digest.finalize().into()
}

fn memo_key(index_key: &str) -> [u8; 32] {
    digest(&["claude_withheld_account_memo_key:v1", index_key])
}

impl ScanIndex {
    /// What `bind_session_accounts_with_mixed` reads besides the insert-only
    /// owner binding: the transcript and its api/trace sidecar stamps, which the
    /// candidate fingerprint folds in, and the identity contract.
    fn withheld_seen(&self, size_bytes: u64, modified_unix_nanos: u64, fingerprint: &str) -> Seen {
        let contract = self.claude_request_identity_contract.as_deref();
        let evidence = digest(&[
            "claude_withheld_account_evidence:v1",
            fingerprint,
            contract.unwrap_or("\0none"),
        ]);
        Seen {
            size_bytes,
            modified_unix_nanos,
            evidence,
        }
    }

    /// A held key whose stamp and evidence match its last parse in this
    /// process would re-derive the same withheld body: skip it (zero bytes).
    pub(super) fn withheld_account_unchanged(&self, key: &str, candidate: &CandidateFile) -> bool {
        if !self.claude_account_deferred_holds.contains_key(key) {
            return false;
        }
        let fingerprint = &candidate.source_file_fingerprint;
        let now = self.withheld_seen(
            candidate.size_bytes,
            candidate.modified_unix_nanos,
            fingerprint,
        );
        with_memo(|memo| memo.get(&memo_key(key)) == Some(&now)).unwrap_or(false)
    }

    /// After a completed parse: count a held key's re-parse by trigger, then
    /// remember the parsed revision while the key stays held.
    pub(super) fn note_withheld_account_parse(&self, key: &str, fingerprint: &str, was_held: bool) {
        let held = self.claude_account_deferred_holds.contains_key(key);
        if !was_held && !held {
            return;
        }
        let parsed = self
            .files
            .get(key)
            .filter(|entry| entry.source_file_fingerprint == fingerprint);
        let parsed = parsed.map(|entry| {
            let nanos = entry.modified_unix_nanos.unwrap_or_default();
            self.withheld_seen(entry.size_bytes, nanos, fingerprint)
        });
        let key = memo_key(key);
        with_memo(|memo| {
            let trigger = match (memo.get(&key), parsed) {
                (None, _) => Some(WithheldEvent::ReparseStart),
                (Some(seen), Some(now)) if seen.evidence == now.evidence => None,
                (Some(seen), Some(now))
                    if (seen.size_bytes, seen.modified_unix_nanos)
                        == (now.size_bytes, now.modified_unix_nanos) =>
                {
                    Some(WithheldEvent::ReparseEvidence)
                }
                (Some(_), Some(_)) => Some(WithheldEvent::ReparseGrowth),
                (Some(_), None) => None,
            };
            if let Some(trigger) = trigger.filter(|_| was_held) {
                withheld_event(trigger);
            }
            match parsed.filter(|_| held) {
                Some(now)
                    if memo.len() < MAX_CLAUDE_ACCOUNT_DEFERRED_HOLDS
                        || memo.contains_key(&key) =>
                {
                    memo.insert(key, now);
                }
                _ => {
                    memo.remove(&key);
                }
            }
        });
    }
}

/// A hold released because its file was proved absent: counted, and the key
/// leaves the memo.
pub(super) fn released_deleted(key: &str) {
    with_memo(|memo| memo.remove(&memo_key(key)));
    withheld_event(WithheldEvent::ReleasedDeleted);
}

/// A process restart, for one key: its next selection re-parses once.
#[cfg(test)]
pub(super) fn restart_for_test(key: &str) {
    with_memo(|memo| memo.remove(&memo_key(key)));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::heap_layout_bound::{completed_bound, tree_node_bytes};

    /// Priced at the hold cap: one modeled B-tree node per entry plus a root,
    /// independent of path length (keys are digests).
    #[test]
    fn memo_at_the_hold_cap_is_priced_by_the_layout_bound() {
        let seen = Seen {
            size_bytes: u64::MAX,
            modified_unix_nanos: u64::MAX,
            evidence: [0xff; 32],
        };
        let full: Memo = (0..MAX_CLAUDE_ACCOUNT_DEFERRED_HOLDS)
            .map(|slot| (memo_key(&format!("/opaque/{slot}.jsonl")), seen))
            .collect();
        let node = tree_node_bytes::<[u8; 32], Seen>().unwrap();
        let expected = std::mem::size_of::<Memo>() + (MAX_CLAUDE_ACCOUNT_DEFERRED_HOLDS + 1) * node;
        assert_eq!(completed_bound(&full, usize::MAX), Some(expected));
        assert!(expected < 6 << 20, "{expected} bytes at the cap");
    }
}
