//! RAM-only advisory state for withheld-account holds. Completed parses save
//! their content/evidence witness immediately; metadata alone cannot rearm it.
//! Losing state costs a reparse, never a Skip. Tokens are last-parse estimates
//! and held ages are wall-clock estimates since this process first saw a hold.
use super::*;
use crate::local_resource_diagnostics::{withheld_event, WithheldEvent};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Seen {
    size_bytes: u64,
    evidence: [u8; 32],
}
crate::heap_layout_bound::fields!(Seen; size_bytes, evidence);

const PARSED: &str = "claude_withheld_account_evidence:v1";
const CONTENT: &str = "claude_withheld_account_content:v1";

/// A single fixed-size value owns no heap and keeps the memo and W2 gauge in
/// the same bounded population. `None` tokens mean unknown, never zero owed.
#[derive(Clone, Copy, Debug)]
struct Entry {
    seen: Option<Seen>,
    tokens: Option<u64>,
    first_seen: u64,
}
crate::heap_layout_bound::fields!(Entry; seen, tokens, first_seen);
type Entries = BTreeMap<[u8; 32], Entry>;
struct State {
    entries: Entries,
    // Authoritative population supplied by the durable hold map, independent
    // of whether the advisory details could be retained.
    held_count: usize,
    unavailable: bool,
    refused: bool,
}
impl State {
    const fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
            held_count: 0,
            unavailable: false,
            refused: false,
        }
    }

    fn entry(&mut self, key: [u8; 32]) -> Option<&mut Entry> {
        if self.entries.len() >= MAX_CLAUDE_ACCOUNT_DEFERRED_HOLDS
            && !self.entries.contains_key(&key)
        {
            self.unavailable = true;
            return None;
        }
        Some(self.entries.entry(key).or_insert_with(|| Entry {
            seen: None,
            tokens: None,
            first_seen: super::sampled_scan::now_seconds(),
        }))
    }

    fn discard(&mut self) {
        // Replacing, rather than clearing, also frees an empty allocated root.
        self.entries = BTreeMap::new();
        self.unavailable = self.held_count != 0;
        self.refused = false;
    }
}
#[cfg(not(test))]
static STATE: Mutex<State> = Mutex::new(State::new());
#[cfg(test)]
thread_local! {
    static STATE: Mutex<State> = const { Mutex::new(State::new()) };
}
fn with_mutex<R>(f: impl FnOnce(&Mutex<State>) -> R) -> R {
    #[cfg(test)]
    {
        STATE.with(f)
    }
    #[cfg(not(test))]
    {
        f(&STATE)
    }
}
/// Poison is never selection evidence. Cleanup and population disclosure have
/// separate explicit recovery paths below.
fn with_state<R>(f: impl FnOnce(&mut State) -> R) -> Option<R> {
    with_mutex(|state| state.lock().ok().map(|mut state| f(&mut state)))
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

/// Reuse the already-read samples, with a known object-generation witness.
/// A reused device/inode with another birth must never inherit a Skip. No
/// stat or birth (including platforms without them) means no memo witness.
pub(super) fn content_stamp(
    len: u64,
    stat: Option<&OpenedObjectStat>,
    samples: &OpenedContentSamples,
) -> Option<String> {
    let stat = stat?;
    let birth = stat.birth_nanos?;
    let object = opened_object_identity_from(len, Some(&stat.with_changed_unix_nanos(0)), samples);
    let mut hash = Sha256::new();
    update_length_prefixed(&mut hash, b"claude_withheld_object_generation:v1");
    update_length_prefixed(&mut hash, object.as_bytes());
    update_length_prefixed(&mut hash, &birth.to_be_bytes());
    Some(format!("{:x}", hash.finalize()))
}

impl ScanIndex {
    /// Transcript and sidecar stamps plus the resolver identity contract.
    fn withheld_seen(&self, kind: &str, size_bytes: u64, stamp: &str) -> Seen {
        let contract = self.claude_request_identity_contract.as_deref();
        let evidence = digest(&[kind, stamp, contract.unwrap_or("\0none")]);
        Seen {
            size_bytes,
            evidence,
        }
    }

    /// Capture at validated parse completion, even before its first hold is
    /// recorded. The completion owner carries this RAM-only value to classify.
    pub(super) fn withheld_completed_seen(&self, candidate: &CandidateFile) -> Option<Seen> {
        candidate
            .withheld_content_stamp
            .as_deref()
            .map(|stamp| self.withheld_seen(CONTENT, candidate.size_bytes, stamp))
    }

    /// Call after recording the hold, using only the completed parse witness.
    pub(super) fn remember_withheld_content(&self, key: &str, seen: Seen) {
        if self.claude_account_deferred_holds.contains_key(key) {
            with_state(|state| {
                if let Some(entry) = state.entry(memo_key(key)) {
                    entry.seen = Some(seen);
                }
            });
        }
    }

    /// Direct CONTENT comparison: no later metadata-sensitive promotion step.
    /// This avoids parsing/line delivery, not the existing acquisition samples.
    pub(super) fn withheld_account_unchanged(&self, key: &str, candidate: &CandidateFile) -> bool {
        if !self.claude_account_deferred_holds.contains_key(key) {
            return false;
        }
        let Some(content) = self.withheld_completed_seen(candidate) else {
            return false;
        };
        with_state(|state| {
            !state.refused
                && state
                    .entries
                    .get(&memo_key(key))
                    .and_then(|entry| entry.seen)
                    == Some(content)
        })
        .unwrap_or(false)
    }

    /// Count EVERY completed reparse, even an identical PARSED digest. The
    /// temporary PARSED witness supports trigger accounting only; it cannot
    /// grant a Skip. Completion immediately overwrites it with CONTENT.
    pub(super) fn note_withheld_account_parse(&self, key: &str, fingerprint: &str, was_held: bool) {
        let held = self.claude_account_deferred_holds.contains_key(key);
        if !was_held && !held {
            return;
        }
        let parsed = self
            .files
            .get(key)
            .filter(|entry| entry.source_file_fingerprint == fingerprint)
            .map(|entry| self.withheld_seen(PARSED, entry.size_bytes, fingerprint));
        let key = memo_key(key);
        let trigger = with_state(|state| {
            let previous = (!state.refused)
                .then(|| state.entries.get(&key).and_then(|entry| entry.seen))
                .flatten();
            let trigger = match (previous, parsed) {
                (None, _) => WithheldEvent::ReparseStart,
                (Some(before), Some(now)) if before.size_bytes != now.size_bytes => {
                    WithheldEvent::ReparseGrowth
                }
                _ => WithheldEvent::ReparseEvidence,
            };
            if held {
                if let Some(entry) = state.entry(key) {
                    entry.seen = parsed;
                }
            } else {
                state.entries.remove(&key);
            }
            trigger
        })
        .unwrap_or(WithheldEvent::ReparseStart);
        // Lock failure still counts the actual parse; never emit under a
        // failed lock, and never let missing advisory state grant a Skip.
        if was_held {
            withheld_event(trigger, 1);
        }
    }
}

/// Parent calls at durable hold removal, before admitting a replacement.
pub(super) fn released_resolved(key: &str) {
    remove_released(key);
}
fn remove_released(key: &str) -> Option<u64> {
    with_mutex(|mutex| {
        let (mut state, poisoned) = match mutex.lock() {
            Ok(state) => (state, false),
            Err(poisoned) => (poisoned.into_inner(), true),
        };
        let entry = state.entries.remove(&memo_key(key));
        state.held_count = state.held_count.saturating_sub(1);
        state.unavailable |= poisoned;
        entry.filter(|_| !poisoned).and_then(|entry| entry.tokens)
    })
}
/// Proven absence releases the last-known parsed tokens, if known. This is
/// disclosure of discarded withheld usage, never upload/ACK credit.
pub(super) fn released_deleted(key: &str) {
    let tokens = remove_released(key);
    withheld_event(WithheldEvent::ReleasedDeleted, 1);
    if let Some(tokens) = tokens.filter(|tokens| *tokens > 0) {
        withheld_event(WithheldEvent::ReleasedDeletedTokens, tokens);
    }
}

pub(super) fn hold_tokens(key: &str, tokens: u64) {
    with_state(|state| {
        if let Some(entry) = state.entry(memo_key(key)) {
            entry.tokens = Some(tokens);
        }
    });
}

/// Refresh actual population even if details were refused. The temporary
/// digest vector is bounded by the durable hold cap and owns no retained state.
pub(super) fn retain_held(holds: &BTreeMap<String, String>) {
    let mut live = holds.keys().map(|key| memo_key(key)).collect::<Vec<_>>();
    live.sort_unstable();
    with_mutex(|mutex| {
        let (mut state, poisoned) = match mutex.lock() {
            Ok(state) => (state, false),
            Err(poisoned) => (poisoned.into_inner(), true),
        };
        state
            .entries
            .retain(|key, _| live.binary_search(key).is_ok());
        state.held_count = holds.len();
        state.unavailable = poisoned
            || state.refused
            || state.entries.len() != holds.len()
            || state.entries.values().any(|entry| entry.tokens.is_none());
    });
}

/// Portable conservative allowance for a full B-tree node per entry plus a
/// root. Fixed-size keys/values own no additional heap. This exceeds the
/// validated native tree_node_bytes layout; charging never gates on the
/// generic graph walk's layout_supported toolchain/platform whitelist.
const NODE_UPPER_BYTES: usize = 1536;
fn charge(entries: usize) -> Option<usize> {
    std::mem::size_of::<Mutex<State>>()
        .checked_add(entries.checked_add(1)?.checked_mul(NODE_UPPER_BYTES)?)
}
pub(crate) fn retained_bound(limit: usize) -> Option<usize> {
    with_state(|state| {
        let bytes = charge(state.entries.len()).filter(|bytes| *bytes <= limit);
        if bytes.is_none() {
            state.refused = true;
            state.unavailable = state.held_count != 0;
        }
        bytes
    })?
}

/// Clear poison and advisory allocations, retaining the actual held count.
pub(crate) fn discard_retained() {
    with_mutex(|mutex| {
        let mut state = mutex
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.discard();
        mutex.clear_poison();
    });
}
/// Other retained graphs may be unsupported without affecting this known
/// bounded graph. The owner must charge this graph FIRST, then use this hook
/// when discarding the others; only our own refusal/poison loses the memo.
pub(crate) fn discard_if_refused() {
    with_mutex(|mutex| {
        let (mut state, poisoned) = match mutex.lock() {
            Ok(state) => (state, false),
            Err(poisoned) => (poisoned.into_inner(), true),
        };
        if poisoned || state.refused {
            state.discard();
            mutex.clear_poison();
        }
    });
}

#[derive(Debug, Serialize)]
pub(crate) struct HeldGauge {
    withheld_held_count: usize,
    withheld_memo_unavailable: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    withheld_held_tokens: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    withheld_held_age: Option<BTreeMap<&'static str, u64>>,
}
pub(crate) fn held_gauge() -> Option<HeldGauge> {
    const DAY: u64 = 86_400;
    let now = super::sampled_scan::now_seconds();
    with_mutex(|mutex| {
        // A poisoned guard may disclose population; never use it for Skip.
        let (state, poisoned) = match mutex.lock() {
            Ok(state) => (state, false),
            Err(poisoned) => (poisoned.into_inner(), true),
        };
        if state.held_count == 0 {
            return None;
        }
        let unavailable = poisoned
            || state.unavailable
            || state.refused
            || state.entries.len() != state.held_count
            || state.entries.values().any(|entry| entry.tokens.is_none());
        let mut gauge = HeldGauge {
            withheld_held_count: state.held_count,
            withheld_memo_unavailable: unavailable,
            withheld_held_tokens: None,
            withheld_held_age: None,
        };
        if !unavailable {
            let mut age = BTreeMap::from([("le_30d", 0), ("31_90d", 0), ("gt_90d", 0)]);
            let mut tokens = 0u64;
            for entry in state.entries.values() {
                tokens = tokens.saturating_add(entry.tokens.unwrap_or_default());
                let bucket = match now.saturating_sub(entry.first_seen) {
                    held if held <= 30 * DAY => "le_30d",
                    held if held <= 90 * DAY => "31_90d",
                    _ => "gt_90d",
                };
                *age.entry(bucket).or_default() += 1;
            }
            gauge.withheld_held_tokens = Some(tokens);
            gauge.withheld_held_age = Some(age);
        }
        Some(gauge)
    })
}

#[derive(Debug, Serialize)]
pub(crate) struct Census {
    entries: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    retained_bytes: Option<usize>,
}
pub(crate) fn census() -> Option<Census> {
    let entries = with_state(|state| state.entries.len()).filter(|entries| *entries > 0)?;
    let retained_bytes = retained_bound(usize::MAX);
    Some(Census {
        entries,
        retained_bytes,
    })
}

#[cfg(test)]
pub(super) fn restart_for_test(key: &str) {
    with_state(|state| {
        state.entries.remove(&memo_key(key));
    });
}

#[cfg(test)]
pub(super) fn poison_for_test() {
    let result = std::panic::catch_unwind(|| {
        with_mutex(|mutex| {
            let _guard = mutex.lock().unwrap();
            panic!("injected full-selector advisory poison");
        });
    });
    assert!(result.is_err());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::heap_layout_bound::tree_node_bytes;

    #[test]
    fn held_gauge_sums_tokens_ages_from_first_seen_and_drops_on_release() {
        const DAY: u64 = 86_400;
        let dir = crate::test_scratch::unique_path("held-gauge-proven-absence");
        fs::create_dir_all(&dir).unwrap();
        let dir = fs::canonicalize(dir).unwrap();
        let a_path = dir.join("a.jsonl");
        let b_path = dir.join("b.jsonl");
        let (a, b) = (a_path.to_str().unwrap(), b_path.to_str().unwrap());
        let gauge = || serde_json::to_value(held_gauge()).unwrap();
        let mut index = ScanIndex::default();
        for (key, fingerprint) in [(a, "fa"), (b, "fb")] {
            index
                .file_snapshot_fingerprints
                .insert(key.to_string(), BTreeSet::from([fingerprint.to_string()]));
        }
        let deferred =
            |a_tokens: u64| BTreeMap::from([("fa".to_string(), a_tokens), ("fb".to_string(), 5)]);
        super::sampled_scan::set_test_now(Some(100 * DAY));
        assert!(index.record_claude_account_deferred_holds([(a, "a1")], &deferred(7)));
        assert_eq!(
            gauge(),
            json!({"withheld_held_count": 1, "withheld_memo_unavailable": false, "withheld_held_tokens": 7,
                "withheld_held_age": {"le_30d": 1, "31_90d": 0, "gt_90d": 0}})
        );
        // 31 days on: a moves to 31-90 d; b is new.
        super::sampled_scan::set_test_now(Some(131 * DAY));
        assert!(index.record_claude_account_deferred_holds([(b, "b1")], &deferred(7)));
        assert_eq!(
            gauge(),
            json!({"withheld_held_count": 2, "withheld_memo_unavailable": false, "withheld_held_tokens": 12,
                "withheld_held_age": {"le_30d": 1, "31_90d": 1, "gt_90d": 0}})
        );
        // a re-parses with more withheld tokens; its first-seen stays.
        super::sampled_scan::set_test_now(Some(191 * DAY));
        assert!(index.record_claude_account_deferred_holds([(a, "a2")], &deferred(9)));
        assert_eq!(
            gauge(),
            json!({"withheld_held_count": 2, "withheld_memo_unavailable": false, "withheld_held_tokens": 14,
                "withheld_held_age": {"le_30d": 0, "31_90d": 1, "gt_90d": 1}})
        );
        // a binds (resolved): its tokens and bucket leave.
        assert!(index.record_claude_account_deferred_holds([(a, "a3")], &BTreeMap::new()));
        assert_eq!(
            gauge(),
            json!({"withheld_held_count": 1, "withheld_memo_unavailable": false, "withheld_held_tokens": 5,
                "withheld_held_age": {"le_30d": 0, "31_90d": 1, "gt_90d": 0}})
        );
        // b's parent/root are positively readable; absence of an index entry
        // alone is no proof. Use the real traversal's configured root.
        ensure_bounded_traversal(
            SnapshotSource::ClaudeCode,
            &[dir.clone()],
            &mut index,
            "2026-10-07T12:00:00Z",
            7,
        );
        index.retain_observed_claude_account_deferred_holds(&BTreeSet::new());
        fs::remove_dir_all(dir).unwrap();
        assert!(index.claude_account_deferred_holds.is_empty());
        assert_eq!(gauge(), Value::Null);
        super::sampled_scan::set_test_now(None);
        let [released, _, _] = crate::local_resource_diagnostics::take_withheld_for_test();
        assert_eq!(
            released,
            BTreeMap::from([("deleted", 1), ("deleted_tokens", 5), ("resolved", 1)])
        );
    }

    fn reset() {
        with_mutex(|mutex| {
            *mutex
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()) = State::new();
            mutex.clear_poison();
        });
        crate::local_resource_diagnostics::take_withheld_for_test();
    }

    fn candidate(key: &str, size: u64, stamp: Option<&str>) -> CandidateFile {
        CandidateFile {
            physical_identity: Some([1, 2]),
            scan_root: PathBuf::from("/opaque"),
            path: PathBuf::from(key),
            size_bytes: size,
            modified_unix_seconds: 0,
            modified_unix_nanos: 0,
            source_file_fingerprint: "parsed".to_string(),
            legacy_source_file_fingerprint: String::new(),
            legacy_config_reconciliation_required: false,
            opened_object_identity: String::new(),
            fingerprint_changed_nanos: 0,
            fingerprint_birth_nanos: 1,
            withheld_content_stamp: stamp.map(str::to_string),
        }
    }

    fn parsed(index: &mut ScanIndex, key: &str, size: u64) {
        let mut entry = super::super::tests::manifest_index_entry(None);
        entry.size_bytes = size;
        entry.source_file_fingerprint = "parsed".to_string();
        index.files.insert(key.to_string(), entry);
    }

    #[test]
    fn completed_content_is_immediate_and_missing_stamp_fails_closed() {
        reset();
        let key = "/opaque/immediate.jsonl";
        let mut index = ScanIndex::default();
        let mut file = candidate(key, 5, Some("sample-and-evidence"));
        // Capture before the first hold exists, as the real completion seam does.
        let seen = index.withheld_completed_seen(&file).unwrap();
        index.remember_withheld_content(key, seen);
        assert_eq!(with_state(|state| state.entries.len()), Some(0));
        index
            .claude_account_deferred_holds
            .insert(key.to_string(), "parsed".to_string());
        parsed(&mut index, key, 5);
        hold_tokens(key, 7);
        retain_held(&index.claude_account_deferred_holds);
        index.note_withheld_account_parse(key, "parsed", false);
        assert!(
            !index.withheld_account_unchanged(key, &file),
            "PARSED is not CONTENT"
        );
        index.remember_withheld_content(key, seen);
        // No unchanged intermediate pass: touch before EVERY next selection.
        for touch in 1..=3 {
            file.modified_unix_nanos = touch;
            file.source_file_fingerprint = format!("touch-{touch}");
            assert!(index.withheld_account_unchanged(key, &file));
        }
        let [_, reparses, _] = crate::local_resource_diagnostics::take_withheld_for_test();
        assert!(
            reparses.is_empty(),
            "new admission and metadata touches are not reparses"
        );
        let mut no_stamp = file.clone();
        no_stamp.withheld_content_stamp = None;
        assert!(index.withheld_completed_seen(&no_stamp).is_none());
        assert!(!index.withheld_account_unchanged(key, &no_stamp));
        file.withheld_content_stamp = Some("changed-evidence".to_string());
        assert!(!index.withheld_account_unchanged(key, &file));
        file.withheld_content_stamp = Some("sample-and-evidence".to_string());
        file.size_bytes += 1;
        assert!(!index.withheld_account_unchanged(key, &file));
        file.size_bytes -= 1;
        index.claude_request_identity_contract = Some("next-contract".to_string());
        assert!(!index.withheld_account_unchanged(key, &file));
    }

    #[test]
    fn every_completed_reparse_is_counted_even_with_equal_parsed_evidence() {
        reset();
        let key = "/opaque/reparses.jsonl";
        let mut index = ScanIndex::default();
        index
            .claude_account_deferred_holds
            .insert(key.to_string(), "parsed".to_string());
        parsed(&mut index, key, 5);
        hold_tokens(key, 7);
        retain_held(&index.claude_account_deferred_holds);
        index.note_withheld_account_parse(key, "parsed", true);
        index.note_withheld_account_parse(key, "parsed", true);
        index.note_withheld_account_parse(key, "parsed", true);
        parsed(&mut index, key, 6);
        index.note_withheld_account_parse(key, "parsed", true);
        let [_, reparses, _] = crate::local_resource_diagnostics::take_withheld_for_test();
        assert_eq!(
            reparses,
            BTreeMap::from([("start", 1), ("evidence", 2), ("growth", 1)])
        );
    }

    #[test]
    fn content_generation_rejects_reused_inode_and_unknown_identity() {
        let samples = OpenedContentSamples {
            head: b"same head".to_vec(),
            tail: Some(b"same tail".to_vec()),
        };
        let stat = OpenedObjectStat {
            device: 1,
            inode: 2,
            changed_seconds: 3,
            changed_nanos: 4,
            birth_nanos: Some(5),
            modified_nanos: Some(6),
        };
        let original = content_stamp(100_000, Some(&stat), &samples).unwrap();
        let touch = OpenedObjectStat {
            changed_seconds: 30,
            changed_nanos: 40,
            modified_nanos: Some(60),
            ..stat
        };
        assert_eq!(
            content_stamp(100_000, Some(&touch), &samples).as_deref(),
            Some(original.as_str())
        );
        // Simulated delete/recreate: all sampled inputs and object id reused,
        // only the generation differs. No filesystem inode-allocation luck.
        let recreated = OpenedObjectStat {
            birth_nanos: Some(50),
            ..stat
        };
        assert_ne!(
            content_stamp(100_000, Some(&recreated), &samples).as_deref(),
            Some(original.as_str())
        );
        assert!(
            content_stamp(100_000, None, &samples).is_none(),
            "non-Unix/unknown object fails closed"
        );
        let unknown_birth = OpenedObjectStat {
            birth_nanos: None,
            ..stat
        };
        assert!(content_stamp(100_000, Some(&unknown_birth), &samples).is_none());
    }

    #[test]
    fn cap_churn_never_allocates_a_4097th_entry() {
        reset();
        let mut holds = BTreeMap::new();
        for slot in 0..MAX_CLAUDE_ACCOUNT_DEFERRED_HOLDS {
            let key = format!("/opaque/old-{slot}");
            holds.insert(key.clone(), String::new());
            hold_tokens(&key, 1);
        }
        retain_held(&holds);
        let len = || with_state(|state| state.entries.len()).unwrap();
        assert_eq!(len(), MAX_CLAUDE_ACCOUNT_DEFERRED_HOLDS);
        // Even if a caller delays removal, every insertion enforces the cap.
        hold_tokens("/opaque/refused", 9);
        assert_eq!(len(), MAX_CLAUDE_ACCOUNT_DEFERRED_HOLDS);
        assert_eq!(
            with_state(|state| state.entries.contains_key(&memo_key("/opaque/refused"))),
            Some(false)
        );
        // Whole-page churn, inspecting occupancy after EACH operation, not
        // just after final pruning. Parent removes resolved keys immediately.
        let mut peak = len();
        for slot in 0..MAX_CLAUDE_ACCOUNT_DEFERRED_HOLDS {
            let old = format!("/opaque/old-{slot}");
            holds.remove(&old);
            released_resolved(&old);
            assert_eq!(len(), MAX_CLAUDE_ACCOUNT_DEFERRED_HOLDS - 1);
            let new = format!("/opaque/new-{slot}");
            holds.insert(new.clone(), String::new());
            hold_tokens(&new, 2);
            peak = peak.max(len());
            assert!(len() <= MAX_CLAUDE_ACCOUNT_DEFERRED_HOLDS);
        }
        retain_held(&holds);
        assert_eq!(peak, MAX_CLAUDE_ACCOUNT_DEFERRED_HOLDS);
        let gauge = held_gauge().unwrap();
        assert!(!gauge.withheld_memo_unavailable);
        assert_eq!(gauge.withheld_held_count, MAX_CLAUDE_ACCOUNT_DEFERRED_HOLDS);
        assert_eq!(
            gauge.withheld_held_tokens,
            Some(2 * MAX_CLAUDE_ACCOUNT_DEFERRED_HOLDS as u64)
        );
    }

    #[test]
    fn memo_at_the_hold_cap_has_a_conservative_portable_charge() {
        reset();
        let seen = Seen {
            size_bytes: u64::MAX,
            evidence: [0xff; 32],
        };
        let full: Entries = (0..MAX_CLAUDE_ACCOUNT_DEFERRED_HOLDS)
            .map(|slot| {
                (
                    memo_key(&format!("/opaque/{slot}.jsonl")),
                    Entry {
                        seen: Some(seen),
                        tokens: Some(1),
                        first_seen: 0,
                    },
                )
            })
            .collect();
        with_state(|state| {
            state.entries = full.clone();
            state.held_count = full.len();
        });
        let expected = charge(MAX_CLAUDE_ACCOUNT_DEFERRED_HOLDS).unwrap();
        assert!(
            expected < 8 << 20,
            "{expected} bytes must fit the EXISTING owner allowance"
        );
        // Assert even on Linux or an unvalidated compiler. The real charge
        // has no layout gate, and its native comparison remains an extra check.
        assert!(tree_node_bytes::<[u8; 32], Entry>().unwrap() <= NODE_UPPER_BYTES);
        assert_eq!(retained_bound(usize::MAX), Some(expected));
        if crate::heap_layout_bound::layout_supported() {
            let native = crate::heap_layout_bound::completed_bound(&full, usize::MAX).unwrap();
            assert!(
                native <= expected,
                "native {native} exceeds portable {expected}"
            );
        }
        let line = serde_json::to_value(census()).unwrap();
        assert_eq!(line["entries"], MAX_CLAUDE_ACCOUNT_DEFERRED_HOLDS);
        assert_eq!(line["retained_bytes"], expected);
        discard_if_refused();
        assert_eq!(
            with_state(|state| state.entries.len()),
            Some(full.len()),
            "an unrelated graph fallback preserves this known bounded graph"
        );
        assert_eq!(
            retained_bound(expected - 1),
            None,
            "over the limit is refused"
        );
        discard_if_refused();
        assert!(
            census().is_none(),
            "discarded entries are omitted from the resource census"
        );
        assert_eq!(
            serde_json::to_value(held_gauge()).unwrap(),
            json!({
                "withheld_held_count": MAX_CLAUDE_ACCOUNT_DEFERRED_HOLDS,
                "withheld_memo_unavailable": true
            }),
            "refusal must neither omit population nor fabricate zero tokens"
        );
    }

    #[test]
    fn poison_discloses_count_counts_reparse_and_recovers_after_discard() {
        reset();
        let key = "/opaque/poison.jsonl";
        let mut index = ScanIndex::default();
        index
            .claude_account_deferred_holds
            .insert(key.to_string(), "parsed".to_string());
        parsed(&mut index, key, 5);
        hold_tokens(key, 7);
        retain_held(&index.claude_account_deferred_holds);
        let file = candidate(key, 5, Some("content"));
        let seen = index.withheld_completed_seen(&file).unwrap();
        index.remember_withheld_content(key, seen);
        assert!(index.withheld_account_unchanged(key, &file));
        let poison = std::panic::catch_unwind(|| {
            with_mutex(|mutex| {
                let _guard = mutex.lock().unwrap();
                panic!("injected advisory poison");
            })
        });
        assert!(poison.is_err());
        assert!(!index.withheld_account_unchanged(key, &file));
        assert_eq!(retained_bound(usize::MAX), None);
        assert_eq!(
            serde_json::to_value(held_gauge()).unwrap(),
            json!({
                "withheld_held_count": 1, "withheld_memo_unavailable": true
            })
        );
        index.note_withheld_account_parse(key, "parsed", true);
        let [_, reparses, _] = crate::local_resource_diagnostics::take_withheld_for_test();
        assert_eq!(
            reparses,
            BTreeMap::from([("start", 1)]),
            "failed lock must still count the completed parse"
        );
        discard_if_refused();
        assert!(!with_mutex(Mutex::is_poisoned));
        assert_eq!(with_state(|state| state.entries.len()), Some(0));
        assert_eq!(held_gauge().unwrap().withheld_held_count, 1);
        assert!(!index.withheld_account_unchanged(key, &file));
        // Next successful parse refills the same bounded graph and disclosure.
        hold_tokens(key, 8);
        index.note_withheld_account_parse(key, "parsed", true);
        index.remember_withheld_content(key, seen);
        retain_held(&index.claude_account_deferred_holds);
        assert!(index.withheld_account_unchanged(key, &file));
        let gauge = held_gauge().unwrap();
        assert!(!gauge.withheld_memo_unavailable);
        assert_eq!(gauge.withheld_held_tokens, Some(8));
        let [_, reparses, _] = crate::local_resource_diagnostics::take_withheld_for_test();
        assert_eq!(reparses, BTreeMap::from([("start", 1)]));
    }

    #[test]
    fn refused_population_is_explicit_and_unknown_deleted_tokens_are_not_invented() {
        reset();
        let key = "/opaque/refused.jsonl";
        let holds = BTreeMap::from([(key.to_string(), "parsed".to_string())]);
        hold_tokens(key, 9);
        retain_held(&holds);
        assert_eq!(retained_bound(0), None);
        discard_if_refused();
        assert_eq!(
            serde_json::to_value(held_gauge()).unwrap(),
            json!({
                "withheld_held_count": 1, "withheld_memo_unavailable": true
            })
        );
        released_deleted(key);
        assert!(held_gauge().is_none());
        let [released, _, _] = crate::local_resource_diagnostics::take_withheld_for_test();
        assert_eq!(released, BTreeMap::from([("deleted", 1)]));
    }
}
