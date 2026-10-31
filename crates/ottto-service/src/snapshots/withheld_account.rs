//! Correctness hold: withheld ownership debt cannot publish or settle. The approved
//! interim withheld_reparse{start,evidence,growth} Full exception is unpaced because
//! it publishes nothing and matches main; it is not a general ownership Full cause.
//! Cap refusal keeps debt; unknown identity disables CONTENT Skip.
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
    // Device, inode, birth: only CONTENT carries a usable generation.
    object: [u64; 3],
}
impl crate::heap_layout_bound::HeapLayoutBound for Seen {
    const INLINE_ONLY: bool = true;
    const STABLE_HEAP: bool = true;
    fn heap_bound(&self, c: &mut crate::heap_layout_bound::Counter) -> Option<()> {
        let Self {
            size_bytes: _,
            evidence: _,
            object: _,
        } = self;
        c.add(0)
    }
}

const PARSED: &str = "claude_withheld_account_evidence:v1";
const CONTENT: &str = "claude_withheld_account_content:v1";

/// One bounded entry keeps the boxed completion witness and W2 gauge in
/// the same capped population. `None` tokens mean unknown, never zero owed.
#[derive(Debug)]
struct Entry {
    seen: Option<Box<Seen>>,
    tokens: Option<u64>,
    first_seen: u64,
    absence: Option<(std::time::Instant, u64, Box<sampled_audit::AbsenceParent>)>,
}
crate::heap_layout_bound::fields!(Entry; seen, tokens, first_seen, absence);
type Entries = BTreeMap<[u8; 32], Entry>;
#[derive(Debug)]
struct State {
    entries: Entries,
    origin: std::time::Instant,
    clock: fn(std::time::Instant) -> std::time::Instant,
    // Authoritative population supplied by the durable hold map, independent
    // of whether the advisory details could be retained.
    held_count: usize,
    unavailable: bool,
    refused: bool,
}
impl State {
    fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
            origin: std::time::Instant::now(),
            clock: |_| std::time::Instant::now(),
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
            absence: None,
        }))
    }

    fn discard(&mut self) {
        // Replacing, rather than clearing, also frees an empty allocated root.
        self.entries = BTreeMap::new();
        self.unavailable = self.held_count != 0;
        self.refused = false;
    }
}
/// Shared by the existing transcript-cache owner and its working index handles.
/// The rotation owner prices entries once; handles charge only the shared header.
/// As with other Arc bounds, shared headers may be conservatively counted twice.
#[derive(Clone, Debug)]
pub(crate) struct Memo(Arc<Mutex<State>>);
impl Default for Memo {
    fn default() -> Self {
        Self(Arc::new(Mutex::new(State::new())))
    }
}
impl crate::heap_layout_bound::HeapLayoutBound for Memo {
    fn heap_bound(&self, c: &mut crate::heap_layout_bound::Counter) -> Option<()> {
        c.add(self.resident_header_bytes())
    }
}
impl Memo {
    fn resident_header_bytes(&self) -> usize {
        std::mem::size_of::<Mutex<State>>()
            + 2 * std::mem::size_of::<usize>()
            + std::mem::align_of::<Mutex<State>>()
    }
    fn with_mutex<R>(&self, f: impl FnOnce(&Mutex<State>) -> R) -> R {
        f(&self.0)
    }
    // Poison never grants selection authority.
    fn with_state<R>(&self, f: impl FnOnce(&mut State) -> R) -> Option<R> {
        self.with_mutex(|state| state.lock().ok().map(|mut state| f(&mut state)))
    }
    /// Same capped entry, now owned by the proven physical generation's new path.
    /// Moving custody grants no release counter or acceptance credit.
    pub(super) fn rekey(&self, from: &str, to: &str) {
        self.with_state(|state| {
            if let Some(mut entry) = state.entries.remove(&memo_key(from)) {
                entry.absence = None;
                if let Some(current) = state.entries.get_mut(&memo_key(to)) {
                    current.first_seen = current.first_seen.min(entry.first_seen);
                    current.tokens = current.tokens.or(entry.tokens);
                    current.seen = current.seen.take().or(entry.seen);
                    current.absence = None;
                } else {
                    state.entries.insert(memo_key(to), entry);
                }
            }
        });
    }
    pub(super) fn reset_absence(&self, key: &str) {
        self.with_state(|state| {
            if let Some(entry) = state.entries.get_mut(&memo_key(key)) {
                entry.absence = None;
            }
        });
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

/// Reuse the already-read samples, with a known object-generation witness.
/// Generation is checked separately by Seen; this digest binds the same
/// device/inode and bounded samples across metadata-only birth clamps. No
/// stat or birth (including platforms without them) means no memo witness.
pub(super) fn content_stamp(
    len: u64,
    stat: Option<&OpenedObjectStat>,
    samples: &OpenedContentSamples,
) -> Option<String> {
    let stat = stat?;
    stat.birth_nanos?;
    let object = opened_object_identity_from(len, Some(&stat.with_changed_unix_nanos(0)), samples);
    let mut hash = Sha256::new();
    update_length_prefixed(&mut hash, b"claude_withheld_object_content:v2");
    update_length_prefixed(&mut hash, object.as_bytes());
    Some(format!("{:x}", hash.finalize()))
}

// Platform-neutral: compare the timestamps already normalized to unix nanos.
// Linux keeps birth constant; the conjunction is platform-neutral. Reused
// object ids with every accepted clamp input matching remain indistinguishable.
fn birth_clamp_continues(before: Seen, after: Seen, modified: u64) -> bool {
    before.object[..2] == after.object[..2]
        && before.size_bytes == after.size_bytes
        && before.evidence == after.evidence
        && after.object[2] < before.object[2]
        && after.object[2] == modified
}

impl ScanIndex {
    /// Transcript and sidecar stamps plus the resolver identity contract.
    fn withheld_seen(&self, kind: &str, size_bytes: u64, stamp: &str) -> Seen {
        let contract = self.claude_request_identity_contract.as_deref();
        let evidence = digest(&[kind, stamp, contract.unwrap_or("\0none")]);
        Seen {
            size_bytes,
            evidence,
            object: [0; 3],
        }
    }

    /// Capture at validated parse completion, even before its first hold is
    /// recorded. The completion owner carries this RAM-only value to classify.
    pub(super) fn withheld_completed_seen(&self, candidate: &CandidateFile) -> Option<Seen> {
        let [device, inode] = candidate.physical_identity?;
        let birth = candidate.fingerprint_birth_nanos;
        if birth == 0 {
            return None;
        }
        candidate.withheld_content_stamp.as_deref().map(|stamp| {
            // Restored body/activity debt may be deferred only under the
            // authority that completed this parse. A revision or context
            // activation must invalidate CONTENT even with equal samples.
            let mut seen = self.withheld_seen(CONTENT, candidate.size_bytes, stamp);
            let authority = digest(&[
                CONTENT,
                &self
                    .active_effective_upload_body_witness_revision
                    .to_string(),
                self.active_upload_context_fingerprint
                    .as_deref()
                    .unwrap_or("\0none"),
            ]);
            let mut hash = Sha256::new();
            hash.update(seen.evidence);
            hash.update(authority);
            seen.evidence = hash.finalize().into();
            seen.object = [device, inode, birth];
            seen
        })
    }

    /// Call after recording the hold, using only the completed parse witness.
    pub(super) fn remember_withheld_content(&self, key: &str, seen: Seen) {
        if self.claude_account_deferred_holds.contains_key(key) {
            self.withheld_memo.with_state(|state| {
                if let Some(entry) = state.entry(memo_key(key)) {
                    entry.seen = Some(Box::new(seen));
                }
            });
        }
    }

    /// An unstampable object has no completed CONTENT witness. Keep token/age
    /// disclosure, but make its next recovery a start, not evidence inferred
    /// from the temporary PARSED accounting stamp.
    pub(super) fn forget_withheld_content(&self, key: &str) {
        if self.claude_account_deferred_holds.contains_key(key) {
            self.withheld_memo.with_state(|state| {
                if let Some(entry) = state.entries.get_mut(&memo_key(key)) {
                    entry.seen = None;
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
            self.forget_withheld_content(key);
            return false;
        };
        let (unchanged, clamped) = self
            .withheld_memo
            .with_state(|state| {
                if state.refused {
                    return (false, false);
                }
                let Some(before) = state
                    .entries
                    .get_mut(&memo_key(key))
                    .and_then(|entry| entry.seen.as_deref_mut())
                else {
                    return (false, false);
                };
                if *before == content {
                    return (true, false);
                }
                // Exact same object, sampled bytes, extent and resolver/output
                // evidence; only a backwards birth==mtime clamp may continue it.
                let clamped =
                    birth_clamp_continues(*before, content, candidate.modified_unix_nanos);
                if clamped {
                    // Adopt the clamp once. Identical later lookups neither loop
                    // nor count it again; a further clamp must reprove every gate.
                    *before = content;
                }
                (clamped, clamped)
            })
            .unwrap_or((false, false));
        if clamped {
            withheld_event(WithheldEvent::BirthClampAccepted, 1);
        }
        unchanged
    }

    /// Count EVERY completed reparse, even an identical PARSED digest. The
    /// temporary PARSED witness supports trigger accounting only; it cannot
    /// grant a Skip. Completion immediately overwrites it with CONTENT.
    pub(super) fn note_withheld_account_parse(&self, key: &str, fingerprint: &str, was_held: bool) {
        // Called before the durable hold is changed; only prior holds have
        // a reparse trigger. A first admission is recorded by completion.
        if !was_held {
            return;
        }
        let parsed = self
            .files
            .get(key)
            .filter(|entry| entry.source_file_fingerprint == fingerprint)
            .map(|entry| self.withheld_seen(PARSED, entry.size_bytes, fingerprint));
        let key = memo_key(key);
        let trigger = self
            .withheld_memo
            .with_state(|state| {
                let previous = (!state.refused)
                    .then(|| {
                        state
                            .entries
                            .get(&key)
                            .and_then(|entry| entry.seen.as_deref().copied())
                    })
                    .flatten();
                let trigger = match (previous, parsed) {
                    (None, _) => WithheldEvent::ReparseStart,
                    (Some(before), Some(now)) if before.size_bytes != now.size_bytes => {
                        WithheldEvent::ReparseGrowth
                    }
                    _ => WithheldEvent::ReparseEvidence,
                };
                if let Some(entry) = state.entry(key) {
                    entry.seen = parsed.map(Box::new);
                }
                trigger
            })
            .unwrap_or(WithheldEvent::ReparseStart);
        // Lock failure still counts the actual parse; never emit under a
        // failed lock, and never let missing advisory state grant a Skip.
        withheld_event(trigger, 1);
    }
}

/// The existing capped memo owns removal evidence too. Refusal, poison, clock
/// reversal or any uncertain/present observation starts a new sequence.
impl Memo {
    pub(super) fn absence_eligible(
        &self,
        key: &str,
        parent: Option<sampled_audit::AbsenceParent>,
        walk_window: u64,
    ) -> bool {
        self.with_state(|state| {
            if state.refused {
                return false;
            }
            let Some(parent) = parent else {
                if let Some(entry) = state.entries.get_mut(&memo_key(key)) {
                    entry.absence = None;
                }
                return false;
            };
            if state.entry(memo_key(key)).is_none() {
                return false;
            }
            let now = (state.clock)(state.origin);
            let Some(entry) = state.entries.get_mut(&memo_key(key)) else {
                return false;
            };
            if let Some((first, first_window, before)) = &entry.absence {
                if let Some(elapsed) = now.checked_duration_since(*first) {
                    if before.same_parent(&parent) {
                        // A later completed walk must have started after the first
                        // observation's traversal. A resumed/restarted generation
                        // cannot prove a destination was discovered after that probe.
                        return walk_window > *first_window
                            && elapsed >= std::time::Duration::from_secs(600);
                    }
                }
            }
            // Replacing an invalidated witness releases its old descriptor first.
            entry.absence = None;
            // Heap admission does not reserve descriptors. Keep at least seven
            // eighths of the soft limit for ordinary daemon I/O, and never retain
            // more than 32 pins. The existing memo owns the population accounting.
            let limit = crate::fd_guard::descriptor_limit().map_or(0, |n| (n / 8).min(32));
            if state
                .entries
                .values()
                .filter(|entry| entry.absence.is_some())
                .count()
                >= limit
            {
                return false;
            }
            let entry = state
                .entries
                .get_mut(&memo_key(key))
                .expect("admitted memo entry");
            entry.absence = Some((now, walk_window, Box::new(parent)));
            false
        })
        .unwrap_or(false)
    }
}

/// Parent calls at durable hold removal, before admitting a replacement.
impl Memo {
    pub(super) fn released_resolved(&self, key: &str) {
        self.remove_released(key);
    }
}
impl Memo {
    fn remove_released(&self, key: &str) -> Option<u64> {
        self.with_mutex(|mutex| {
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
}
/// Proven absence releases the last-known parsed tokens, if known. This is
/// disclosure of discarded withheld usage, never upload/ACK credit.
impl Memo {
    pub(super) fn released_deleted(&self, key: &str) {
        let tokens = self.remove_released(key);
        withheld_event(WithheldEvent::ReleasedDeleted, 1);
        if let Some(tokens) = tokens.filter(|tokens| *tokens > 0) {
            withheld_event(WithheldEvent::ReleasedDeletedTokens, tokens);
        }
    }
}

impl Memo {
    pub(super) fn hold_tokens(&self, key: &str, tokens: u64) {
        self.with_state(|state| {
            if let Some(entry) = state.entry(memo_key(key)) {
                entry.tokens = Some(tokens);
                entry.absence = None;
            }
        });
    }
}

/// Refresh actual population even if details were refused. The temporary
/// digest vector is bounded by the durable hold cap and owns no retained state.
impl Memo {
    pub(super) fn retain_held(&self, holds: &BTreeMap<String, String>) {
        let mut live = holds.keys().map(|key| memo_key(key)).collect::<Vec<_>>();
        live.sort_unstable();
        self.with_mutex(|mutex| {
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
}

/// Portable conservative allowance for a full B-tree node plus one boxed Seen
/// and one pinned absence witness per entry, and a root. This exceeds the
/// validated native tree_node_bytes layout; charging never gates on the
/// generic graph walk's layout_supported toolchain/platform whitelist.
const NODE_UPPER_BYTES: usize = 1536;
fn charge(entries: usize) -> Option<usize> {
    std::mem::size_of::<Mutex<State>>()
        .checked_add(entries.checked_add(1)?.checked_mul(NODE_UPPER_BYTES)?)
}
impl Memo {
    pub(crate) fn retained_bound(&self, limit: usize) -> Option<usize> {
        self.with_state(|state| {
            if state.entries.is_empty() {
                // Free any empty retained B-tree root. Shared header bytes are
                // charged by cache/index handles, never as a phantom tree node.
                state.entries = BTreeMap::new();
                return Some(0);
            }
            let bytes = charge(state.entries.len()).filter(|bytes| *bytes <= limit);
            if bytes.is_none() {
                state.refused = true;
                state.unavailable = state.held_count != 0;
            }
            bytes
        })?
    }
}

/// Clear poison and advisory allocations, retaining the actual held count.
impl Memo {
    pub(crate) fn discard_retained(&self) {
        self.with_mutex(|mutex| {
            let mut state = mutex
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            state.discard();
            mutex.clear_poison();
        });
    }
}
/// Other retained graphs may be unsupported without affecting this known
/// bounded graph. Sibling graphs are charged first; this graph is independently
/// refused from the remainder. Unrelated sibling refusal alone cannot erase a
/// fitting memo; only our own refusal/poison loses it.
impl Memo {
    pub(crate) fn discard_if_refused(&self) {
        self.with_mutex(|mutex| {
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
impl Memo {
    pub(crate) fn held_gauge(&self) -> Option<HeldGauge> {
        const DAY: u64 = 86_400;
        let now = super::sampled_scan::now_seconds();
        self.with_mutex(|mutex| {
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
}

#[derive(Debug, Serialize)]
pub(crate) struct Census {
    entries: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    retained_bytes: Option<usize>,
}
impl Memo {
    pub(crate) fn census(&self) -> Option<Census> {
        let entries = self
            .with_state(|state| state.entries.len())
            .filter(|entries| *entries > 0)?;
        let retained_bytes = self.retained_bound(usize::MAX);
        Some(Census {
            entries,
            retained_bytes,
        })
    }
}

#[cfg(test)]
pub(crate) mod support {
    use super::*;
    pub(crate) fn clock(memo: &Memo) {
        memo.with_state(|state| {
            state.clock =
                |origin| origin + std::time::Duration::from_secs(sampled_scan::now_seconds());
        });
    }
    pub(crate) fn restart(memo: &Memo) {
        memo.discard_retained();
    }
    pub(crate) fn poison(memo: &Memo) {
        assert!(std::panic::catch_unwind(|| memo.with_mutex(|mutex| {
            let _guard = mutex.lock().unwrap();
            panic!("injected full-selector advisory poison");
        }))
        .is_err());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// [behaviour] F4 requires consecutive rooted absence under one pinned parent.
    #[test]
    #[cfg(unix)]
    fn absence_sequence_resets_on_presence_substitution_or_uncertainty() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        for interruption in [
            "present",
            "parent",
            "symlink",
            "missing-root",
            "unreadable",
            "backward",
        ] {
            if interruption == "unreadable" && unsafe { libc::geteuid() } == 0 {
                continue;
            }
            let memo = Memo::default();
            support::clock(&memo);
            let scratch = crate::test_scratch::ScratchDir::new("withheld-absence-reset");
            let root = fs::canonicalize(&scratch).unwrap().join("root");
            let parent = root.join("parent");
            fs::create_dir_all(&parent).unwrap();
            let path = parent.join("held.jsonl");
            let key = local_index_key(&path);
            let mut index = ScanIndex {
                withheld_memo: memo.clone(),
                ..ScanIndex::default()
            };
            index
                .claude_account_deferred_holds
                .insert(key.clone(), "held".into());
            memo.hold_tokens(&key, 7);
            memo.retain_held(&index.claude_account_deferred_holds);
            ensure_bounded_traversal(
                SnapshotSource::ClaudeCode,
                std::slice::from_ref(&root),
                &mut index,
                "2026-10-07T12:00:00Z",
                7,
            );
            crate::snapshots::line_delivery_tests::walk_all(&mut index, 7);
            sampled_scan::set_test_now(Some(1_000));
            index.probe_absent_claude_account_deferred_holds();
            assert_eq!(index.claude_account_deferred_hold_count(), 1);
            if interruption == "backward" {
                for (now, held) in [(999, 1), (1_598, 1), (1_599, 0)] {
                    sampled_scan::set_test_now(Some(now));
                    crate::snapshots::line_delivery_tests::next_walk(&mut index, 7);
                    index.probe_absent_claude_account_deferred_holds();
                    assert_eq!(index.claude_account_deferred_hold_count(), held);
                }
                continue;
            }
            let saved = root.with_extension("saved");
            match interruption {
                "present" => fs::write(&path, b"present").unwrap(),
                "parent" | "symlink" => {
                    fs::rename(&parent, &saved).unwrap();
                    if interruption == "parent" {
                        fs::create_dir(&parent).unwrap();
                    } else {
                        symlink(&saved, &parent).unwrap();
                    }
                }
                "missing-root" => fs::rename(&root, &saved).unwrap(),
                "unreadable" => {
                    fs::set_permissions(&parent, fs::Permissions::from_mode(0o0)).unwrap()
                }
                _ => unreachable!(),
            }
            sampled_scan::set_test_now(Some(1_600));
            index.probe_absent_claude_account_deferred_holds();
            assert_eq!(
                index.claude_account_deferred_hold_count(),
                1,
                "{interruption}"
            );
            assert_eq!(memo.held_gauge().unwrap().withheld_held_tokens, Some(7));
            match interruption {
                "present" => fs::remove_file(&path).unwrap(),
                "symlink" => {
                    fs::remove_file(&parent).unwrap();
                    fs::rename(&saved, &parent).unwrap();
                }
                "missing-root" => fs::rename(&saved, &root).unwrap(),
                "unreadable" => {
                    fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap()
                }
                _ => (),
            }
            // A changed parent began a fresh sequence at 1600; uncertain
            // observations cannot begin one until the readable path returns.
            sampled_scan::set_test_now(Some(1_601));
            index.probe_absent_claude_account_deferred_holds();
            sampled_scan::set_test_now(Some(2_199));
            index.probe_absent_claude_account_deferred_holds();
            assert_eq!(
                index.claude_account_deferred_hold_count(),
                1,
                "{interruption}"
            );
            crate::snapshots::line_delivery_tests::next_walk(&mut index, 7);
            sampled_scan::set_test_now(Some(2_201));
            index.probe_absent_claude_account_deferred_holds();
            assert_eq!(
                index.claude_account_deferred_hold_count(),
                0,
                "{interruption}"
            );
        }
        sampled_scan::set_test_now(None);
    }
    /// [behaviour] Empty memo releases its root and charges no phantom node.

    #[test]
    fn empty_memo_releases_its_root_and_charges_no_phantom_node() {
        let memo = Memo::default();
        support::clock(&memo);
        memo.with_state(|state| {
            state.entry(memo_key("temporary"));
            state.entries.clear();
        });
        assert_eq!(memo.retained_bound(0), Some(0));
        assert!(memo.with_state(|state| state.entries.is_empty()).unwrap());
    }

    use crate::heap_layout_bound::tree_node_bytes;

    /// [behaviour] Held tokens and ages leave only on resolution or eligible absence.
    #[test]
    fn held_gauge_sums_tokens_ages_from_first_seen_and_drops_on_release() {
        let memo = Memo::default();
        support::clock(&memo);
        const DAY: u64 = 86_400;
        let dir = crate::test_scratch::unique_path("held-gauge-proven-absence");
        fs::create_dir_all(&dir).unwrap();
        let dir = fs::canonicalize(dir).unwrap();
        let a_path = dir.join("a.jsonl");
        let b_path = dir.join("b.jsonl");
        let (a, b) = (a_path.to_str().unwrap(), b_path.to_str().unwrap());
        let gauge = || serde_json::to_value(memo.held_gauge()).unwrap();
        let mut index = ScanIndex {
            withheld_memo: memo.clone(),
            ..ScanIndex::default()
        };
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
            std::slice::from_ref(&dir),
            &mut index,
            "2026-10-07T12:00:00Z",
            7,
        );
        crate::snapshots::line_delivery_tests::walk_all(&mut index, 7);
        index.probe_absent_claude_account_deferred_holds();
        assert_eq!(index.claude_account_deferred_hold_count(), 1);
        super::sampled_scan::set_test_now(Some(191 * DAY + 600));
        index.probe_absent_claude_account_deferred_holds();
        fs::remove_dir_all(dir).unwrap();
        assert!(index.claude_account_deferred_holds.is_empty());
        assert_eq!(gauge(), Value::Null);
        super::sampled_scan::set_test_now(None);
        let [released, _, _] = crate::local_resource_diagnostics::withheld_support::take_withheld();
        assert_eq!(
            released,
            BTreeMap::from([("deleted", 1), ("deleted_tokens", 5), ("resolved", 1)])
        );
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
    /// [behaviour] Completed content is immediate and missing stamp fails closed.

    #[test]
    fn completed_content_is_immediate_and_missing_stamp_fails_closed() {
        let memo = Memo::default();
        support::clock(&memo);
        let key = "/opaque/immediate.jsonl";
        let mut index = ScanIndex {
            withheld_memo: memo.clone(),
            ..ScanIndex::default()
        };
        let mut file = candidate(key, 5, Some("sample-and-evidence"));
        // Capture before the first hold exists, as the real completion seam does.
        let seen = index.withheld_completed_seen(&file).unwrap();
        index.remember_withheld_content(key, seen);
        assert_eq!(memo.with_state(|state| state.entries.len()), Some(0));
        index
            .claude_account_deferred_holds
            .insert(key.to_string(), "parsed".to_string());
        parsed(&mut index, key, 5);
        memo.hold_tokens(key, 7);
        memo.retain_held(&index.claude_account_deferred_holds);
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
        let [_, reparses, _] = crate::local_resource_diagnostics::withheld_support::take_withheld();
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
    /// [behaviour] Backward birth clamp after content memo skips without reparse.

    #[test]
    fn backward_birth_clamp_after_content_memo_skips_without_reparse() {
        let memo = Memo::default();
        support::clock(&memo);
        let key = "/opaque/clamp.jsonl";
        let mut index = ScanIndex {
            withheld_memo: memo.clone(),
            ..ScanIndex::default()
        };
        parsed(&mut index, key, 5);
        index
            .claude_account_deferred_holds
            .insert(key.into(), "parsed".into());
        let mut file = candidate(key, 5, Some("sample-and-account-evidence"));
        file.fingerprint_birth_nanos = 100;
        file.modified_unix_nanos = 200;
        let seen = index.withheld_completed_seen(&file).unwrap();
        index.remember_withheld_content(key, seen);
        file.fingerprint_birth_nanos = 50;
        file.modified_unix_nanos = 50;
        let (_, rows) = crate::local_resource_diagnostics::capture(|| {
            for pass in 0..5 {
                assert_eq!(
                    index.candidate_decision_at(&file, 300),
                    CandidateDecision::Skip,
                    "post-memo backward clamp pass {pass} must not select a transcript read"
                );
            }
            crate::local_resource_diagnostics::Probe::start().collection(
                "claude_code",
                crate::local_resource_diagnostics::CollectionCounts {
                    scanned_files: 0,
                    semantic_noops: 0,
                    sampled_acquisition: None,
                    full_causes: Default::default(),
                },
            );
        });
        assert_eq!(
            rows[0]["counts"]["withheld_birth_clamp_accepted"],
            json!({"events":1})
        );
        assert!(rows[0]["counts"]["withheld_reparse"].is_null());
        assert_eq!(
            memo.with_state(|s| s.entries[&memo_key(key)].seen.as_deref().unwrap().object[2]),
            Some(50)
        );
    }
    /// [behaviour] Birth clamp rejects replacement changed samples evidence and unknown identity.

    #[test]
    fn birth_clamp_rejects_replacement_changed_samples_evidence_and_unknown_identity() {
        let memo = Memo::default();
        support::clock(&memo);
        for cause in [
            "inode",
            "device",
            "sample",
            "evidence",
            "length",
            "forward",
            "not_mtime",
            "no_identity",
            "no_birth",
        ] {
            let memo = Memo::default();
            support::clock(&memo);
            let key = "/opaque/clamp-negative.jsonl";
            let mut index = ScanIndex {
                withheld_memo: memo.clone(),
                ..ScanIndex::default()
            };
            parsed(&mut index, key, 5);
            index
                .claude_account_deferred_holds
                .insert(key.into(), "parsed".into());
            let mut file = candidate(key, 5, Some("same-samples"));
            file.fingerprint_birth_nanos = 100;
            index.remember_withheld_content(key, index.withheld_completed_seen(&file).unwrap());
            file.fingerprint_birth_nanos = 50;
            file.modified_unix_nanos = 50;
            match cause {
                "inode" => file.physical_identity = Some([1, 3]),
                "device" => file.physical_identity = Some([2, 2]),
                "sample" => file.withheld_content_stamp = Some("changed-sample".into()),
                "evidence" => {
                    index.claude_request_identity_contract = Some("changed-account".into())
                }
                "length" => file.size_bytes += 1,
                "forward" => {
                    file.fingerprint_birth_nanos = 150;
                    file.modified_unix_nanos = 150;
                }
                "not_mtime" => file.modified_unix_nanos = 51,
                "no_identity" => file.physical_identity = None,
                "no_birth" => file.fingerprint_birth_nanos = 0,
                _ => unreachable!(),
            }
            assert_eq!(
                index.candidate_decision_at(&file, 300),
                CandidateDecision::Parse,
                "{cause}"
            );
        }
    }
    /// [behaviour] Every completed reparse is counted even with equal parsed evidence.

    #[test]
    fn every_completed_reparse_is_counted_even_with_equal_parsed_evidence() {
        let memo = Memo::default();
        support::clock(&memo);
        let key = "/opaque/reparses.jsonl";
        let mut index = ScanIndex {
            withheld_memo: memo.clone(),
            ..ScanIndex::default()
        };
        index
            .claude_account_deferred_holds
            .insert(key.to_string(), "parsed".to_string());
        parsed(&mut index, key, 5);
        memo.hold_tokens(key, 7);
        memo.retain_held(&index.claude_account_deferred_holds);
        index.note_withheld_account_parse(key, "parsed", true);
        index.note_withheld_account_parse(key, "parsed", true);
        index.note_withheld_account_parse(key, "parsed", true);
        parsed(&mut index, key, 6);
        index.note_withheld_account_parse(key, "parsed", true);
        let [_, reparses, _] = crate::local_resource_diagnostics::withheld_support::take_withheld();
        assert_eq!(
            reparses,
            BTreeMap::from([("start", 1), ("evidence", 2), ("growth", 1)])
        );
    }
    /// [behaviour] Content generation rejects reused inode and unknown identity.

    #[test]
    fn content_generation_rejects_reused_inode_and_unknown_identity() {
        let memo = Memo::default();
        support::clock(&memo);
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
        // Simulated delete/recreate with FORWARD birth movement (5 -> 50):
        // equal samples/object id still produce different Seen values. This
        // comparison is not a universal reused-inode fence: the selector accepts
        // a backwards birth==mtime clamp when device/inode, length, bounded
        // samples and evidence all match, even for an indistinguishable reused
        // object id. This control does not exercise that accepted exception.
        let recreated = OpenedObjectStat {
            birth_nanos: Some(50),
            ..stat
        };
        let mut file = candidate("/opaque/generation", 100_000, Some(&original));
        file.fingerprint_birth_nanos = stat.birth_nanos.unwrap();
        let index = ScanIndex {
            withheld_memo: memo.clone(),
            ..ScanIndex::default()
        };
        let original_seen = index.withheld_completed_seen(&file).unwrap();
        file.fingerprint_birth_nanos = recreated.birth_nanos.unwrap();
        assert_ne!(
            index.withheld_completed_seen(&file),
            Some(original_seen),
            "a reused inode with a different birth cannot inherit the memo"
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
    /// [behaviour] Cap churn never allocates a 4097th entry.

    #[test]
    fn cap_churn_never_allocates_a_4097th_entry() {
        let memo = Memo::default();
        support::clock(&memo);
        let mut holds = BTreeMap::new();
        for slot in 0..MAX_CLAUDE_ACCOUNT_DEFERRED_HOLDS {
            let key = format!("/opaque/old-{slot}");
            holds.insert(key.clone(), String::new());
            memo.hold_tokens(&key, 1);
        }
        memo.retain_held(&holds);
        let len = || memo.with_state(|state| state.entries.len()).unwrap();
        assert_eq!(len(), MAX_CLAUDE_ACCOUNT_DEFERRED_HOLDS);
        // Even if a caller delays removal, every insertion enforces the cap.
        memo.hold_tokens("/opaque/refused", 9);
        assert_eq!(len(), MAX_CLAUDE_ACCOUNT_DEFERRED_HOLDS);
        assert_eq!(
            memo.with_state(|state| state.entries.contains_key(&memo_key("/opaque/refused"))),
            Some(false)
        );
        // Whole-page churn, inspecting occupancy after EACH operation, not
        // just after final pruning. Parent removes resolved keys immediately.
        let mut peak = len();
        for slot in 0..MAX_CLAUDE_ACCOUNT_DEFERRED_HOLDS {
            let old = format!("/opaque/old-{slot}");
            holds.remove(&old);
            memo.released_resolved(&old);
            assert_eq!(len(), MAX_CLAUDE_ACCOUNT_DEFERRED_HOLDS - 1);
            let new = format!("/opaque/new-{slot}");
            holds.insert(new.clone(), String::new());
            memo.hold_tokens(&new, 2);
            peak = peak.max(len());
            assert!(len() <= MAX_CLAUDE_ACCOUNT_DEFERRED_HOLDS);
        }
        memo.retain_held(&holds);
        assert_eq!(peak, MAX_CLAUDE_ACCOUNT_DEFERRED_HOLDS);
        let gauge = memo.held_gauge().unwrap();
        assert!(!gauge.withheld_memo_unavailable);
        assert_eq!(gauge.withheld_held_count, MAX_CLAUDE_ACCOUNT_DEFERRED_HOLDS);
        assert_eq!(
            gauge.withheld_held_tokens,
            Some(2 * MAX_CLAUDE_ACCOUNT_DEFERRED_HOLDS as u64)
        );
    }

    /// [behaviour] The capped memo, including absence witnesses, fits its existing allowance.
    #[test]
    fn memo_at_the_hold_cap_has_a_conservative_portable_charge() {
        let memo = Memo::default();
        support::clock(&memo);
        let seen = Seen {
            size_bytes: u64::MAX,
            evidence: [0xff; 32],
            object: [1, 2, 3],
        };
        let full: Entries = (0..MAX_CLAUDE_ACCOUNT_DEFERRED_HOLDS)
            .map(|slot| {
                (
                    memo_key(&format!("/opaque/{slot}.jsonl")),
                    Entry {
                        seen: Some(Box::new(seen)),
                        tokens: Some(1),
                        first_seen: 0,
                        absence: None,
                    },
                )
            })
            .collect();

        let expected = charge(MAX_CLAUDE_ACCOUNT_DEFERRED_HOLDS).unwrap();
        assert!(
            expected < 8 << 20,
            "{expected} bytes must fit the EXISTING owner allowance"
        );
        // Assert even on Linux or an unvalidated compiler. The real charge
        // has no layout gate, and its native comparison remains an extra check.
        assert!(
            tree_node_bytes::<[u8; 32], Entry>().unwrap()
                + std::mem::size_of::<Seen>()
                + std::mem::size_of::<sampled_audit::AbsenceParent>()
                <= NODE_UPPER_BYTES
        );
        if crate::heap_layout_bound::layout_supported() {
            let native = crate::heap_layout_bound::completed_bound(&full, usize::MAX).unwrap();
            assert!(
                native <= expected,
                "native {native} exceeds portable {expected}"
            );
        }
        memo.with_state(|state| {
            state.held_count = full.len();
            state.entries = full;
        });
        assert_eq!(memo.retained_bound(usize::MAX), Some(expected));
        let line = serde_json::to_value(memo.census()).unwrap();
        assert_eq!(line["entries"], MAX_CLAUDE_ACCOUNT_DEFERRED_HOLDS);
        assert_eq!(line["retained_bytes"], expected);
        memo.discard_if_refused();
        assert_eq!(
            memo.with_state(|state| state.entries.len()),
            Some(MAX_CLAUDE_ACCOUNT_DEFERRED_HOLDS),
            "an unrelated graph fallback preserves this known bounded graph"
        );
        assert_eq!(
            memo.retained_bound(expected - 1),
            None,
            "over the limit is refused"
        );
        memo.discard_if_refused();
        assert!(
            memo.census().is_none(),
            "discarded entries are omitted from the resource census"
        );
        assert_eq!(
            serde_json::to_value(memo.held_gauge()).unwrap(),
            json!({
                "withheld_held_count": MAX_CLAUDE_ACCOUNT_DEFERRED_HOLDS,
                "withheld_memo_unavailable": true
            }),
            "refusal must neither omit population nor fabricate zero tokens"
        );
    }
    /// [behaviour] Poison discloses count counts reparse and recovers after discard.

    #[test]
    fn poison_discloses_count_counts_reparse_and_recovers_after_discard() {
        let memo = Memo::default();
        support::clock(&memo);
        let key = "/opaque/poison.jsonl";
        let mut index = ScanIndex {
            withheld_memo: memo.clone(),
            ..ScanIndex::default()
        };
        index
            .claude_account_deferred_holds
            .insert(key.to_string(), "parsed".to_string());
        parsed(&mut index, key, 5);
        memo.hold_tokens(key, 7);
        memo.retain_held(&index.claude_account_deferred_holds);
        let file = candidate(key, 5, Some("content"));
        let seen = index.withheld_completed_seen(&file).unwrap();
        index.remember_withheld_content(key, seen);
        assert!(index.withheld_account_unchanged(key, &file));
        let poison = std::panic::catch_unwind(|| {
            memo.with_mutex(|mutex| {
                let _guard = mutex.lock().unwrap();
                panic!("injected advisory poison");
            })
        });
        assert!(poison.is_err());
        assert!(!index.withheld_account_unchanged(key, &file));
        assert_eq!(memo.retained_bound(usize::MAX), None);
        assert_eq!(
            serde_json::to_value(memo.held_gauge()).unwrap(),
            json!({
                "withheld_held_count": 1, "withheld_memo_unavailable": true
            })
        );
        index.note_withheld_account_parse(key, "parsed", true);
        let [_, reparses, _] = crate::local_resource_diagnostics::withheld_support::take_withheld();
        assert_eq!(
            reparses,
            BTreeMap::from([("start", 1)]),
            "failed lock must still count the completed parse"
        );
        memo.discard_if_refused();
        assert!(!memo.with_mutex(Mutex::is_poisoned));
        assert_eq!(memo.with_state(|state| state.entries.len()), Some(0));
        assert_eq!(memo.held_gauge().unwrap().withheld_held_count, 1);
        assert!(!index.withheld_account_unchanged(key, &file));
        // Next successful parse refills the same bounded graph and disclosure.
        memo.hold_tokens(key, 8);
        index.note_withheld_account_parse(key, "parsed", true);
        index.remember_withheld_content(key, seen);
        memo.retain_held(&index.claude_account_deferred_holds);
        assert!(index.withheld_account_unchanged(key, &file));
        let gauge = memo.held_gauge().unwrap();
        assert!(!gauge.withheld_memo_unavailable);
        assert_eq!(gauge.withheld_held_tokens, Some(8));
        let [_, reparses, _] = crate::local_resource_diagnostics::withheld_support::take_withheld();
        assert_eq!(reparses, BTreeMap::from([("start", 1)]));
    }
    /// [behaviour] Refused population is explicit and unknown deleted tokens are not invented.

    #[test]
    fn refused_population_is_explicit_and_unknown_deleted_tokens_are_not_invented() {
        let memo = Memo::default();
        support::clock(&memo);
        let key = "/opaque/refused.jsonl";
        let holds = BTreeMap::from([(key.to_string(), "parsed".to_string())]);
        memo.hold_tokens(key, 9);
        memo.retain_held(&holds);
        assert_eq!(memo.retained_bound(0), None);
        memo.discard_if_refused();
        assert_eq!(
            serde_json::to_value(memo.held_gauge()).unwrap(),
            json!({
                "withheld_held_count": 1, "withheld_memo_unavailable": true
            })
        );
        memo.released_deleted(key);
        assert!(memo.held_gauge().is_none());
        let [released, _, _] = crate::local_resource_diagnostics::withheld_support::take_withheld();
        assert_eq!(released, BTreeMap::from([("deleted", 1)]));
    }
}
