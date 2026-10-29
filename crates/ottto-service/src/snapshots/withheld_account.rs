//! E3: RAM-only re-parse memo for withheld-account holds. A held key re-parses
//! once per process, then only when its content or the account evidence its
//! resolver reads changes; never on mtime, ctime or xattr alone (SOURCE
//! condition 1). Losing the memo costs one re-parse, never a Skip.
use super::*;
use crate::local_resource_diagnostics::{withheld_event, WithheldEvent};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Seen {
    size_bytes: u64,
    evidence: [u8; 32],
}
crate::heap_layout_bound::fields!(Seen; size_bytes, evidence);

/// A completed parse is remembered by its revision fingerprint (which moves
/// with mtime); the next pass that sees that exact revision re-keys it by its
/// content-only stamp (`CandidateFile::withheld_content_stamp`).
const PARSED: &str = "claude_withheld_account_evidence:v1";
const CONTENT: &str = "claude_withheld_account_content:v1";

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
    /// owner binding: the transcript and its api/trace sidecar stamps (folded
    /// into both the fingerprint and the content stamp), and the contract.
    fn withheld_seen(&self, kind: &str, size_bytes: u64, stamp: &str) -> Seen {
        let contract = self.claude_request_identity_contract.as_deref();
        let evidence = digest(&[kind, stamp, contract.unwrap_or("\0none")]);
        Seen {
            size_bytes,
            evidence,
        }
    }

    /// A held key whose content and evidence match its last parse in this
    /// process would re-derive the same withheld body: skip it (zero bytes).
    pub(super) fn withheld_account_unchanged(&self, key: &str, candidate: &CandidateFile) -> bool {
        let held = self.claude_account_deferred_holds.contains_key(key);
        let Some(stamp) = candidate.withheld_content_stamp.as_deref().filter(|_| held) else {
            return false;
        };
        let size = candidate.size_bytes;
        let content = self.withheld_seen(CONTENT, size, stamp);
        let parsed = self.withheld_seen(PARSED, size, &candidate.source_file_fingerprint);
        with_memo(|memo| match memo.get_mut(&memo_key(key)) {
            Some(seen) if *seen == content => true,
            Some(seen) if *seen == parsed => {
                *seen = content;
                true
            }
            _ => false,
        })
        .unwrap_or(false)
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
        let parsed = parsed.map(|entry| self.withheld_seen(PARSED, entry.size_bytes, fingerprint));
        let key = memo_key(key);
        with_memo(|memo| {
            let trigger = match (memo.get(&key), parsed) {
                (None, _) => Some(WithheldEvent::ReparseStart),
                (Some(seen), Some(now)) if seen.evidence == now.evidence => None,
                (Some(seen), Some(now)) if seen.size_bytes == now.size_bytes => {
                    Some(WithheldEvent::ReparseEvidence)
                }
                (Some(_), Some(_)) => Some(WithheldEvent::ReparseGrowth),
                (Some(_), None) => None,
            };
            if let Some(trigger) = trigger.filter(|_| was_held) {
                withheld_event(trigger, 1);
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
    withheld_event(WithheldEvent::ReleasedDeleted, 1);
}

/// The memo's charge in the sync owner's process-retained bound
/// (`snapshot_sync.rs`, `Owner::retained_bound`). Entries own no heap, so one
/// `tree_nodes` charge prices the map as `completed_bound` does, without a
/// per-entry walk past the 4,096-visit cap. Unsupported layout: only an empty
/// memo is known.
pub(crate) fn retained_bound(limit: usize) -> Option<usize> {
    let len = with_memo(|memo| memo.len())?;
    if !crate::heap_layout_bound::layout_supported() {
        return (len == 0).then_some(0);
    }
    let mut c = crate::heap_layout_bound::Counter::new(limit);
    c.add(std::mem::size_of::<Memo>())?;
    crate::heap_layout_bound::tree_nodes::<[u8; 32], Seen>(len, &mut c)?;
    Some(c.bytes)
}

/// The rotation refused the charge: drop the memo; each held key then
/// re-parses once, counted `start`.
pub(crate) fn discard_retained() {
    with_memo(|memo| memo.clear());
}

/// #799 resource census gauge on the Claude page line; `None` while empty.
#[derive(Debug, Serialize)]
pub(crate) struct Census {
    entries: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    retained_bytes: Option<usize>,
}
pub(crate) fn census() -> Option<Census> {
    let entries = with_memo(|memo| memo.len()).filter(|entries| *entries > 0)?;
    let retained_bytes = retained_bound(usize::MAX);
    Some(Census {
        entries,
        retained_bytes,
    })
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

    /// At the hold cap the memo is charged to the owner's retained bound
    /// and reported on the #799 census line, with the bytes the generic
    /// completed walk prices (keys are digests, so path length is irrelevant).
    #[test]
    fn memo_at_the_hold_cap_is_charged_and_reported() {
        let seen = Seen {
            size_bytes: u64::MAX,
            evidence: [0xff; 32],
        };
        let full: Memo = (0..MAX_CLAUDE_ACCOUNT_DEFERRED_HOLDS)
            .map(|slot| (memo_key(&format!("/opaque/{slot}.jsonl")), seen))
            .collect();
        with_memo(|memo| *memo = full.clone());
        let charged = retained_bound(usize::MAX);
        // None on both sides where the requested layout is unsupported.
        assert_eq!(charged, completed_bound(&full, usize::MAX));
        if crate::heap_layout_bound::layout_supported() {
            let node = tree_node_bytes::<[u8; 32], Seen>().unwrap();
            let expected =
                std::mem::size_of::<Memo>() + (MAX_CLAUDE_ACCOUNT_DEFERRED_HOLDS + 1) * node;
            assert_eq!(charged, Some(expected));
            assert!(expected < 6 << 20, "{expected} bytes at the cap");
            assert_eq!(
                retained_bound(expected - 1),
                None,
                "over the limit is refused"
            );
        }
        let line = serde_json::to_value(census()).unwrap();
        assert_eq!(line["entries"], MAX_CLAUDE_ACCOUNT_DEFERRED_HOLDS);
        assert_eq!(
            line.get("retained_bytes").and_then(Value::as_u64),
            charged.map(|bytes| bytes as u64)
        );
        discard_retained();
        assert!(census().is_none(), "an empty memo is omitted");
    }
}
