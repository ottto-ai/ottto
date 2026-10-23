//! Local custody and consumed-evidence selection. None of this enters the wire.
use super::*;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct MoneyFileSelection {
    pub(crate) revision: String,
    pub(crate) root: String,
    member: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    consumed: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) synthetic_body: Option<String>,
    #[serde(skip)]
    reparse_union: Option<bool>,
}
crate::heap_layout_bound::fields!(MoneyFileSelection; revision, root, member, consumed, synthetic_body, reparse_union);

pub(crate) fn record_logical_member(
    index: &mut ScanIndex,
    key: &str,
    revision: &str,
    item: &SnapshotItem,
) {
    let root = claude_snapshot_family_root_ref(item);
    if item.source_session_id.len() > 128 || root.len() > 128 {
        return;
    }
    let consumed = index
        .claude_money_files
        .get(key)
        .and_then(|state| state.consumed.clone());
    index.claude_money_files.insert(
        key.to_owned(),
        MoneyFileSelection {
            revision: revision.to_owned(),
            root: root.to_owned(),
            member: item.source_session_id.clone(),
            consumed,
            synthetic_body: None,
            reparse_union: None,
        },
    );
}

pub(crate) fn logical_family_member(index: &ScanIndex, key: &str) -> Option<(String, String)> {
    if let Some(state) = index.claude_money_files.get(key).filter(|state| {
        state.root.len() <= 128
            && state.member.len() <= 128
            && index
                .files
                .get(key)
                .is_some_and(|entry| entry.source_file_fingerprint == state.revision)
    }) {
        return Some((state.root.clone(), state.member.clone()));
    }
    claude_index_path_family_member(Path::new(key))
}

pub(super) fn primary_order<'a>(index: &ScanIndex, key: &'a str) -> (u64, &'a str) {
    (
        index
            .claude_request_census
            .get(key)
            .and_then(ClaudeRequestCensusRecord::birth)
            .map_or(u64::MAX, |birth| birth.unix_seconds),
        key,
    )
}

pub(crate) fn bind_union_checkpoints(
    index: &ScanIndex,
    entities: &mut BTreeMap<String, BTreeSet<String>>,
    bodies: &mut BTreeMap<String, BTreeSet<String>>,
) {
    let mut unions = BTreeMap::<(&str, &str), Vec<&str>>::new();
    for (key, state) in &index.claude_money_files {
        if index
            .files
            .get(key)
            .is_some_and(|entry| entry.source_file_fingerprint == state.revision)
        {
            unions
                .entry((&state.root, &state.member))
                .or_default()
                .push(key);
        }
    }
    for keys in unions.values_mut().filter(|keys| keys.len() > 1) {
        keys.sort_unstable_by_key(|key| primary_order(index, key));
        let primary = &index.files[keys[0]].source_file_fingerprint;
        let (Some(entity), Some(body)) =
            (entities.get(primary).cloned(), bodies.get(primary).cloned())
        else {
            continue;
        };
        for key in &keys[1..] {
            let source = &index.files[*key].source_file_fingerprint;
            entities.insert(source.clone(), entity.clone());
            bodies.insert(source.clone(), body.clone());
        }
    }
}

/// The selection digest covers the evidence actually available to this page,
/// conservatively including other holders. Debt schedules the reread; this
/// local witness defeats equal-wire no-op suppression after ownership moves.
/// ACK/index subset rules, rather than parsing, decide whether it commits.
pub(crate) fn stage_selection_fingerprints(
    support: &Path,
    index: &mut ScanIndex,
    items: &[SnapshotItem],
) -> bool {
    if !request_owned_live(support) {
        return true;
    }
    let deadline = Instant::now() + PAGE_MAX_ELAPSED;
    let Some(_funds) = ShadowReservation::admit(
        index
            .files
            .len()
            .saturating_mul(512)
            .saturating_add(index.files.keys().map(String::len).sum::<usize>()),
    ) else {
        return false;
    };
    let ClaudeLedgerAcquire::Ready(ledger) = store::acquire(support) else {
        return false;
    };
    let mut digest = Sha256::new();
    digest.update(b"claude_money_selection:v1\0");
    for (key, record) in index
        .claude_request_census
        .records()
        .chain(ledger.census().records())
    {
        if key.starts_with("offer:")
            || key.starts_with("hold:")
            || key.starts_with("adopt:")
            || key.starts_with("due:")
            || key.starts_with("dirty:")
            || key.starts_with("unbuilt:")
            // Sweep cursors and shadow-family memos are publication progress,
            // not ownership evidence. Actual census/telemetry/watch evidence
            // stays conservative across families: request conflicts can cross
            // roots even when the resulting wire body happens to be equal.
            || key.starts_with("sweep:")
            || key.starts_with("fam:")
        {
            continue;
        }
        let Some(revision) = revision_of(record, deadline) else {
            return false;
        };
        digest.update((key.len() as u64).to_be_bytes());
        digest.update(key.as_bytes());
        digest.update(revision);
    }
    let consumed = format!("{:x}", digest.finalize());
    let selected = union_items_by_source(index, items)
        .keys()
        .map(|key| (*key).to_owned())
        .collect::<BTreeSet<_>>();
    let mut updates = Vec::new();
    for (key, state) in &index.claude_money_files {
        if Instant::now() >= deadline {
            return false;
        }
        if selected.contains(&state.revision) {
            updates.push((key.clone(), state.consumed.as_deref() != Some(&consumed)));
        }
    }
    index.claude_money_selection_changed.clear();
    for (key, changed) in updates {
        if changed {
            index.claude_money_selection_changed.insert(key.clone());
        }
        index
            .claude_money_files
            .get_mut(&key)
            .expect("selected state")
            .consumed = Some(consumed.clone());
    }
    index
        .claude_money_files
        .retain(|key, state| state.synthetic_body.is_some() || index.files.contains_key(key));
    true
}

/// Bind a covering primary offer/ACK to every physical member of its union.
/// This is local checkpoint custody, not a second upload or accepted entity.
pub(crate) fn union_items_by_source<'a>(
    index: &'a ScanIndex,
    items: &'a [SnapshotItem],
) -> BTreeMap<&'a str, &'a SnapshotItem> {
    let logical = items
        .iter()
        .map(|item| {
            (
                (
                    claude_snapshot_family_root_ref(item),
                    item.source_session_id.as_str(),
                ),
                item,
            )
        })
        .collect::<BTreeMap<_, _>>();
    let mut sources = items
        .iter()
        .filter_map(|item| Some((item.source_file_fingerprint.as_deref()?, item)))
        .collect::<BTreeMap<_, _>>();
    for (key, state) in &index.claude_money_files {
        if index
            .files
            .get(key)
            .is_some_and(|entry| entry.source_file_fingerprint == state.revision)
        {
            if let Some(item) = logical.get(&(state.root.as_str(), state.member.as_str())) {
                sources.insert(state.revision.as_str(), *item);
            }
        }
    }
    sources
}

fn logical_digest(root: &str, member: &str) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"claude_union_discovery:v1\0");
    digest.update((root.len() as u64).to_be_bytes());
    digest.update(root.as_bytes());
    digest.update((member.len() as u64).to_be_bytes());
    digest.update(member.as_bytes());
    digest.finalize().into()
}

/// Delivery-free discovery survives rollback in the bounded evidence ledger.
/// A later queue can group an alias even though no alias body/file committed.
/// It is a selection hint; the next opened parse must certify its identity.
pub(super) fn discovery_revision(index: &ScanIndex, key: &str) -> Option<[u8; 32]> {
    let state = index.claude_money_files.get(key)?;
    (index.files.get(key)?.source_file_fingerprint == state.revision)
        .then(|| logical_digest(&state.root, &state.member))
}

pub(crate) fn union_reparse(index: &ScanIndex, key: &str) -> Option<bool> {
    index.claude_money_files.get(key)?.reparse_union
}

/// Select a known logical union as a group before ordinary page selection.
/// Only queued paths participate; no stale path can be injected into a census.
/// A first traversal may discover an alias late; the next traversal has its
/// persisted membership and can select the complete union in one bounded page.
pub(in crate::snapshots) fn select_union_candidates(
    index: &mut ScanIndex,
    limit: usize,
) -> Vec<super::super::ScanTraversalPath> {
    for state in index.claude_money_files.values_mut() {
        state.reparse_union = None;
    }
    let Some(support) = index.active_request_money_support_dir.as_deref() else {
        return Vec::new();
    };
    if !request_owned_live(support) || limit == 0 {
        return Vec::new();
    }
    let deadline = Instant::now() + PAGE_MAX_ELAPSED;
    let mut bytes = 0_usize;
    for (key, state) in &index.claude_money_files {
        if Instant::now() >= deadline {
            return Vec::new();
        }
        bytes = bytes
            .saturating_add(key.len().saturating_mul(4))
            .saturating_add(state.root.len())
            .saturating_add(state.member.len())
            .saturating_add(512);
    }
    if let Some(traversal) = &index.traversal {
        for candidate in &traversal.pending_candidates {
            if Instant::now() >= deadline {
                return Vec::new();
            }
            bytes = bytes
                .saturating_add(candidate.path.as_os_str().len().saturating_mul(3))
                .saturating_add(256);
        }
    }
    let Some(_funds) = ShadowReservation::admit(bytes) else {
        return Vec::new();
    };
    let mut groups = BTreeMap::<[u8; 32], Vec<String>>::new();
    for (key, state) in &index.claude_money_files {
        if Instant::now() >= deadline {
            return Vec::new();
        }
        if index
            .files
            .get(key)
            .is_some_and(|entry| entry.source_file_fingerprint == state.revision)
            && !index
                .claude_reemission_exclusions
                .protected_root(&state.root)
        {
            groups
                .entry(logical_digest(&state.root, &state.member))
                .or_default()
                .push(key.clone());
        }
    }
    let Some(traversal) = index.traversal.as_ref() else {
        return Vec::new();
    };
    let mut queued = BTreeMap::new();
    for candidate in &traversal.pending_candidates {
        if Instant::now() >= deadline {
            return Vec::new();
        }
        queued.insert(super::super::local_index_key(&candidate.path), ());
    }
    // Release the ledger guard before money_due takes its own short lookup
    // lock. Only hash hints from already queued paths can augment a group.
    if let ClaudeLedgerAcquire::Ready(ledger) = store::acquire(support) {
        for key in queued.keys() {
            if Instant::now() >= deadline {
                return Vec::new();
            }
            if let Some(record) = ledger
                .get(&store::money_key("union:", key))
                .filter(|record| page_now(support).saturating_sub(record.window()) <= 35 * 86400)
            {
                let group = groups.entry(record.money_revision()).or_default();
                if !group.contains(key) {
                    group.push(key.clone());
                }
            }
        }
    }
    let mut chosen = BTreeSet::new();
    let mut reasons = Vec::new();
    let now = page_now(support);
    for keys in groups.values().filter(|keys| keys.len() > 1) {
        if Instant::now() >= deadline {
            break;
        }
        if keys.len() > limit.saturating_sub(chosen.len())
            || keys.iter().any(|key| !queued.contains_key(key))
        {
            continue;
        }
        let mut changed =
            index.upload_context_fingerprint != index.active_upload_context_fingerprint;
        let mut adoption = false;
        for key in keys {
            if Instant::now() >= deadline {
                return Vec::new();
            }
            let Some(entry) = index.files.get(key) else {
                changed = true;
                continue;
            };
            adoption |= entry.effective_upload_body_witness_revision < 3;
            changed |= (entry.effective_upload_body_witness_revision >= 3
                || store::has_offer(support, key))
                && money_due(support, key, now);
            // Metadata is only a selection hint. The ordinary opened-file
            // fingerprint/preflight still certifies every selected parse.
            changed |= std::fs::metadata(key).map_or(true, |metadata| {
                metadata.len() != entry.size_bytes
                    || metadata
                        .modified()
                        .ok()
                        .and_then(super::super::unix_seconds)
                        != Some(entry.modified_unix_seconds)
            });
        }
        if !changed && !adoption {
            continue;
        }
        for key in keys {
            chosen.insert(key.clone());
            reasons.push((key.clone(), !changed));
        }
    }
    let mut selected = Vec::new();
    let traversal = index.traversal.as_mut().expect("checked traversal");
    let inspect = traversal.pending_candidates.len();
    for _ in 0..inspect {
        let candidate = traversal
            .pending_candidates
            .pop_front()
            .expect("bounded queue");
        if chosen.contains(&super::super::local_index_key(&candidate.path)) {
            selected.push(candidate);
        } else {
            traversal.pending_candidates.push_back(candidate);
        }
    }
    for (key, adoption_only) in reasons {
        if let Some(state) = index.claude_money_files.get_mut(&key) {
            state.reparse_union = Some(adoption_only);
        }
    }
    selected
}

/// Optional local custody never makes unrelated committed state unreadable.
/// Persisted callers cap the entire raw field before this per-record decoder.
pub(crate) fn decode_selections<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<BTreeMap<String, MoneyFileSelection>, D::Error> {
    use serde::de::{IgnoredAny, MapAccess, Visitor};
    struct Selections;
    impl<'de> Visitor<'de> for Selections {
        type Value = BTreeMap<String, MoneyFileSelection>;
        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("optional local selection map")
        }
        fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
            let mut result = BTreeMap::new();
            let mut seen = BTreeSet::new();
            while let Some(key) = map.next_key::<String>()? {
                if seen.len() >= 65_536 || key.len() > 4096 {
                    map.next_value::<IgnoredAny>()?;
                    continue;
                }
                let raw = map.next_value::<Box<serde_json::value::RawValue>>()?;
                if !seen.insert(key.clone()) {
                    result.remove(&key);
                    continue;
                }
                if raw.get().len() > 8192 {
                    continue;
                }
                if let Ok(state) = serde_json::from_str::<MoneyFileSelection>(raw.get()) {
                    let digest =
                        |v: &str| v.len() == 64 && v.bytes().all(|b| b.is_ascii_hexdigit());
                    if digest(&state.revision)
                        && state.root.len() <= 128
                        && state.member.len() <= 128
                        && state.consumed.as_deref().map_or(true, digest)
                        && state.synthetic_body.as_deref().map_or(true, digest)
                    {
                        result.insert(key, state);
                    }
                }
            }
            Ok(result)
        }
    }
    let raw = Box::<serde_json::value::RawValue>::deserialize(deserializer)?;
    let mut isolated = serde_json::Deserializer::from_str(raw.get());
    Ok(serde::de::Deserializer::deserialize_map(&mut isolated, Selections).unwrap_or_default())
}

pub(crate) fn synthetic_fingerprints(index: &ScanIndex) -> impl Iterator<Item = &String> {
    index
        .claude_money_files
        .values()
        .filter(|state| state.synthetic_body.is_some())
        .map(|state| &state.revision)
}

pub(crate) fn finalize_synthetic(index: &mut ScanIndex, items: &[SnapshotItem]) {
    for item in items {
        let key = store::money_key("synthetic:", &item.source_session_id);
        if synthetic(item)
            && item.usage_accounting_contract.as_deref() == Some(REQUEST_OWNED_CONTRACT)
        {
            index.claude_money_files.insert(
                key,
                MoneyFileSelection {
                    revision: item.snapshot_fingerprint.clone(),
                    root: item.source_session_id.clone(),
                    member: item.source_session_id.clone(),
                    consumed: None,
                    synthetic_body: Some(super::super::snapshot_upload_body_witness(item)),
                    reparse_union: None,
                },
            );
        } else if item.source_file_fingerprint.is_some()
            && item.usage_accounting_contract.as_deref() == Some(REQUEST_OWNED_CONTRACT)
        {
            index.claude_money_files.remove(&key);
        }
    }
}

pub(crate) fn selected_money_files(
    index: &ScanIndex,
    previous: &ScanIndex,
    safe: &BTreeSet<String>,
    settled: impl Fn(&str) -> bool,
) -> BTreeMap<String, MoneyFileSelection> {
    let mut selected = previous
        .claude_money_files
        .iter()
        .filter(|(key, state)| {
            state.synthetic_body.is_some()
                || index.files.contains_key(*key)
                || previous.files.contains_key(*key)
        })
        .map(|(key, state)| (key.clone(), state.clone()))
        .collect::<BTreeMap<_, _>>();
    for (key, state) in &index.claude_money_files {
        if safe.contains(key) || (state.synthetic_body.is_some() && settled(&state.revision)) {
            selected.insert(key.clone(), state.clone());
        }
    }
    for (key, state) in &previous.claude_money_files {
        if state.synthetic_body.is_some() && !index.claude_money_files.contains_key(key) {
            let replacement = safe.iter().any(|file| {
                logical_family_member(index, file).is_some_and(|(_, member)| member == state.member)
            });
            if replacement {
                selected.remove(key);
            }
        }
    }
    selected
}

#[cfg(test)]
mod decoder_tests {
    use super::*;
    #[test]
    fn damaged_selection_isolated_through_load_cas_and_selected_save() {
        let scratch = crate::test_scratch::ScratchDir::new("money-selection-isolation");
        let path = scratch.join("index.json");
        let ordinary = serde_json::to_string(&ScanIndex::default()).unwrap();
        for malformed in [
            r#"{"x":{"revision":1e400,"root":"r"}}"#.to_owned(),
            r#"{"x":{"revision":null,"root":null,"member":false}}"#.to_owned(),
            r#"[1e400,{"future":true}]"#.to_owned(),
            format!(
                r#"{{"{}":{{"root":"{}"}}}}"#,
                "x".repeat(8192),
                "y".repeat(8192)
            ),
        ] {
            let bytes = format!(
                "{},\"claude_money_files\":{malformed}}}",
                &ordinary[..ordinary.len() - 1]
            );
            std::fs::write(&path, bytes).unwrap();
            let mut loaded =
                ScanIndex::load(&path).expect("optional damage cannot quarantine index");
            assert!(loaded.claude_money_files.is_empty());
            loaded
                .save(&path)
                .expect("CAS isolates the same optional damage");
            let mut selected =
                loaded.committable_subset(&loaded, &BTreeSet::new(), &BTreeMap::new());
            selected.save(&path).unwrap();
            assert_eq!(
                ScanIndex::load(&path).unwrap().generation,
                loaded.generation + 1
            );
        }
    }
}
