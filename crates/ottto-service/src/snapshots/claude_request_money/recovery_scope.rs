//! Private replay dependency evidence. Ownership can cross family roots via
//! request and message holders. Freeze that connected component before POST,
//! and close it over current evidence before ordinary emission or replay.
use super::*;

const HASH_MAX: usize = 1024;
const FILE_MAX: usize = 256;
const ROOT_MAX: usize = 128;
const KEY_BYTES_MAX: usize = 24 * 1024;

#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Scope {
    pub roots: BTreeMap<String, Vec<String>>,
    requests: BTreeSet<u64>,
    messages: BTreeSet<u64>,
}
impl Scope {
    pub(crate) fn valid(&self) -> bool {
        !self.roots.is_empty()
            && self.roots.len() <= ROOT_MAX
            && self.requests.len().saturating_add(self.messages.len()) <= HASH_MAX
            && self.roots.values().map(Vec::len).sum::<usize>() <= FILE_MAX
            && self
                .roots
                .iter()
                .all(|(root, files)| root.len() <= 1024 && files.iter().all(|f| f.len() <= 4096))
            && self.roots.iter().fold(0_usize, |n, (root, files)| {
                n.saturating_add(root.len())
                    .saturating_add(files.iter().map(String::len).sum::<usize>())
            }) <= KEY_BYTES_MAX
    }
    pub(crate) fn intersects(&self, other: &Scope) -> bool {
        self.roots.keys().any(|root| other.roots.contains_key(root))
            || self
                .requests
                .iter()
                .any(|hash| other.requests.contains(hash))
            || self
                .messages
                .iter()
                .any(|hash| other.messages.contains(hash))
    }
    pub(crate) fn seed(roots: impl IntoIterator<Item = String>) -> Self {
        Self {
            roots: roots.into_iter().map(|r| (r, Vec::new())).collect(),
            ..Self::default()
        }
    }
}

// New hashes/roots are admitted one at a time; overflow never truncates scope.
fn merge(target: &mut BTreeSet<u64>, other: &BTreeSet<u64>, hashes: &[u64]) -> Option<()> {
    if hashes.len() > HASH_MAX {
        return None;
    }
    for hash in hashes {
        if !target.contains(hash) && target.len().saturating_add(other.len()) >= HASH_MAX {
            return None;
        }
        target.insert(*hash);
    }
    Some(())
}
fn overlaps(hashes: &[u64], scope: &BTreeSet<u64>) -> bool {
    scope.iter().any(|h| hashes.binary_search(h).is_ok())
}

fn admit_root<'a>(
    scope: &'a mut Scope,
    root: &str,
    key_bytes: &mut usize,
) -> Option<&'a mut Vec<String>> {
    if !scope.roots.contains_key(root) {
        if root.len() > 1024
            || scope.roots.len() >= ROOT_MAX
            || key_bytes.saturating_add(root.len()) > KEY_BYTES_MAX
        {
            return None;
        }
        *key_bytes += root.len();
        scope.roots.insert(root.to_owned(), Vec::new());
    }
    scope.roots.get_mut(root)
}

pub(crate) struct Closed {
    pub scope: Scope,
    _funds: ShadowReservation,
}
impl std::ops::Deref for Closed {
    type Target = Scope;
    fn deref(&self) -> &Scope {
        &self.scope
    }
}

/// No filesystem work and no evidence-map copy. Both temporary graph memory
/// and every fixed-point walk have explicit bounds; refusal holds emission.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Refusal {
    Admission,
    Evidence,
    Bounds,
    Deadline,
}
impl Refusal {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Admission => "closure_admission",
            Self::Evidence => "closure_evidence",
            Self::Bounds => "closure_bounds",
            Self::Deadline => "closure_deadline",
        }
    }
}
pub(crate) fn close(support: &Path, index: &ScanIndex, original: &Scope) -> Option<Closed> {
    close_with_reason(support, index, original).ok()
}
pub(crate) fn close_with_reason(
    support: &Path,
    index: &ScanIndex,
    original: &Scope,
) -> Result<Closed, Refusal> {
    let funds = ShadowReservation::admit(4 * 64 * 1024).ok_or(Refusal::Admission)?;
    let refusal = std::cell::Cell::new(Refusal::Bounds);
    let deadline = Instant::now() + Duration::from_millis(2);
    let scope = store::recovery_evidence(support, |ledger| {
        // Small inventories fit a borrowed directory inside the existing graph
        // admission. Avoid re-expanding/hashing every message query on each
        // fixed-point pass. Large inventories retain the exact point lookup.
        let message_views = ledger
            .census()
            .bounded_message_views(FILE_MAX)
            .map(|views| views.collect::<BTreeMap<_, _>>());
        let mut scope = original.clone();
        let frozen_files = original
            .roots
            .values()
            .flatten()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        if !scope.valid() {
            return None;
        }
        // Enforce the same bounds incrementally. Revalidating every path in
        // the entire growing graph after each file made this bounded walk
        // quadratic and exhausted its unchanged two-millisecond deadline.
        let mut file_count = scope.roots.values().map(Vec::len).sum::<usize>();
        let mut key_bytes = scope
            .roots
            .iter()
            .map(|(root, files)| root.len() + files.iter().map(String::len).sum::<usize>())
            .sum::<usize>();
        loop {
            let before = (
                scope.roots.len(),
                scope.requests.len(),
                scope.messages.len(),
            );
            // Seed telemetry-only requests even when this root has no indexed transcript.
            for root in scope.roots.keys() {
                if Instant::now() >= deadline {
                    refusal.set(Refusal::Deadline);
                    return None;
                }
                if let Some(record) = ledger.get(&telemetry_key(root)) {
                    merge(
                        &mut scope.requests,
                        &scope.messages,
                        record.request_hashes(),
                    )?;
                }
            }
            for (key, record) in ledger.census().records_with_prefix(TELEMETRY_KEY_PREFIX) {
                if Instant::now() >= deadline {
                    refusal.set(Refusal::Deadline);
                    return None;
                }
                if !overlaps(record.request_hashes(), &scope.requests) {
                    continue;
                }
                // Telemetry keys are SHA-256(session); only the bounded fact header names the root.
                refusal.set(Refusal::Evidence);
                let root = facts::ClaudeFacts::open(record.facts()?)?.header.session;
                if root.is_empty() || telemetry_key(&root) != key {
                    return None;
                }
                refusal.set(Refusal::Bounds);
                admit_root(&mut scope, &root, &mut key_bytes)?;
                merge(
                    &mut scope.requests,
                    &scope.messages,
                    record.request_hashes(),
                )?;
            }
            for key in index.files.keys() {
                if Instant::now() >= deadline {
                    refusal.set(Refusal::Deadline);
                    return None;
                }
                let Some(root) = logical_family_root_ref(index, key) else {
                    continue;
                };
                let requests = index
                    .claude_request_census
                    .get(key)
                    .map_or(&[][..], |r| r.request_hashes());
                let connected = scope.roots.contains_key(root)
                    || frozen_files.contains(key.as_str())
                    || overlaps(requests, &scope.requests);
                // Empty message targets cannot discover a new edge. A newly
                // connected file may seed messages below; changed hash/root
                // counts force the next pass to revisit every earlier file.
                if !connected && scope.messages.is_empty() {
                    continue;
                }
                let message = message_views
                    .as_ref()
                    .map_or_else(
                        || ledger.get(&message_key(key)),
                        |views| views.get(key.as_str()).copied(),
                    )
                    .filter(|record| {
                        !record.over_budget()
                            && index.claude_request_census.get(key).is_some_and(|file| {
                                file.money_revision() == record.money_revision()
                            })
                    });
                let messages = message.map_or(&[][..], |r| r.request_hashes());
                if !connected && !overlaps(messages, &scope.messages) {
                    continue;
                }
                let files = admit_root(&mut scope, root, &mut key_bytes)?;
                if !files.contains(key) {
                    if key.len() > 4096
                        || file_count >= FILE_MAX
                        || key_bytes.saturating_add(key.len()) > KEY_BYTES_MAX
                    {
                        return None;
                    }
                    file_count += 1;
                    key_bytes += key.len();
                    files.push(key.clone());
                }
                merge(&mut scope.requests, &scope.messages, requests)?;
                merge(&mut scope.messages, &scope.requests, messages)?;
            }
            if before
                == (
                    scope.roots.len(),
                    scope.requests.len(),
                    scope.messages.len(),
                )
            {
                if !scope.valid() {
                    return None;
                }
                for files in scope.roots.values_mut() {
                    files.sort();
                    files.dedup();
                }
                return Some(scope);
            }
        }
    })
    .ok_or(Refusal::Evidence)?
    .ok_or(refusal.get())?;
    Ok(Closed {
        scope,
        _funds: funds,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[serial_test::serial(claude_request_money_shadow)]
    fn a_frozen_dependency_path_cannot_escape_by_changing_family_and_hashes() {
        let support = crate::test_scratch::ScratchDir::new("money-recovery-file-scope");
        store::reload_for_test(&support).unwrap();
        store::with_ledger_for_test(&support, |ledger| {
            assert!(store::checkpoint_for_test(&support, ledger))
        })
        .unwrap();
        let old = "22222222-2222-4222-8222-222222222222";
        let new = "33333333-3333-4333-8333-333333333333";
        let key = format!("/fixture/projects/-repo/{new}.jsonl");
        let mut frozen = Scope::seed([old.to_owned()]);
        frozen.roots.get_mut(old).unwrap().push(key.clone());
        let mut index = ScanIndex::default();
        index.files.insert(
            key.clone(),
            serde_json::from_value(serde_json::json!({
                "size_bytes":1, "modified_unix_seconds":2,
                "source_file_fingerprint":"00".repeat(32), "last_snapshot_fingerprint":null
            }))
            .unwrap(),
        );
        // Current identity and evidence no longer connect the two roots. The
        // original contributing path still binds the immutable attempt.
        let closed = close(&support, &index, &frozen).unwrap();
        assert!(closed
            .roots
            .get(new)
            .is_some_and(|files| files.contains(&key)));
        assert!(closed.roots.contains_key(old));
        store::forget_for_test(&support);
    }
}
