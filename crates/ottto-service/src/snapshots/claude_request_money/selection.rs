//! Local custody and consumed-evidence selection. None of this enters the wire.
use super::*;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct MoneyFileSelection {
    pub(crate) revision: String,
    pub(crate) root: String,
    pub(crate) member: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    consumed: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) synthetic_body: Option<String>,
    #[serde(skip)]
    reparse_union: Option<bool>,
}
crate::heap_layout_bound::fields!(MoneyFileSelection; revision, root, member, consumed, synthetic_body, reparse_union);

// A reserved local entry distinguishes capacity refusal from lost evidence.
// A capped index pauses live adoption; it never re-arms intentionally omitted
// selections or re-offers an untracked synthetic body after restart.
const CAPACITY_KEY: &str = "!selection-capacity";
const MAX_SELECTIONS: usize = 65_536;
const MAX_SELECTION_KEY: usize = 4096;
const MAX_SELECTION_RECORD: usize = 8192;
const MAX_SELECTION_BYTES: usize = super::super::claude_request_census::MAX_RAW_BYTES;

fn capacity_marker() -> MoneyFileSelection {
    MoneyFileSelection {
        revision: "0".repeat(64),
        root: String::new(),
        member: String::new(),
        consumed: None,
        synthetic_body: None,
        reparse_union: None,
    }
}
fn mark_capacity(states: &mut BTreeMap<String, MoneyFileSelection>) {
    states.insert(CAPACITY_KEY.into(), capacity_marker());
}
pub(crate) fn selections_capped(states: &BTreeMap<String, MoneyFileSelection>) -> bool {
    states.contains_key(CAPACITY_KEY)
}
pub(crate) fn capped_selection_json() -> Vec<u8> {
    serde_json::to_vec(&BTreeMap::from([(CAPACITY_KEY, capacity_marker())])).unwrap()
}
fn valid_state(state: &MoneyFileSelection) -> bool {
    let digest = |v: &str| v.len() == 64 && v.bytes().all(|b| b.is_ascii_hexdigit());
    digest(&state.revision)
        && state.root.len() <= 128
        && state.member.len() <= 128
        && state.consumed.as_deref().map_or(true, digest)
        && state.synthetic_body.as_deref().map_or(true, digest)
}

/// Compact raw JSON keeps pretty index saves inside the same raw-field cap
/// as the decoder. Existing valid entries retain deterministic key order.
fn bounded_selection_json(states: &BTreeMap<String, MoneyFileSelection>) -> (String, bool) {
    let marker = format!(
        "{}:{}",
        serde_json::to_string(CAPACITY_KEY).unwrap(),
        serde_json::to_string(&capacity_marker()).unwrap()
    );
    let mut rows = Vec::new();
    let mut bytes = 2;
    let mut capped = selections_capped(states);
    for (key, state) in states {
        if key == CAPACITY_KEY {
            continue;
        }
        let value = serde_json::to_string(state).expect("selection JSON");
        let key_json = serde_json::to_string(key).expect("selection key JSON");
        let charge = key_json.len() + 1 + value.len() + usize::from(!rows.is_empty());
        if key.len() > MAX_SELECTION_KEY
            || value.len() > MAX_SELECTION_RECORD
            || !valid_state(state)
            || rows.len() >= MAX_SELECTIONS
            || bytes + charge + marker.len() + 1 > MAX_SELECTION_BYTES
        {
            capped = true;
            continue;
        }
        bytes += charge;
        rows.push(format!("{key_json}:{value}"));
    }
    if capped {
        if rows.len() == MAX_SELECTIONS {
            rows.pop();
        }
        rows.insert(0, marker);
    }
    (format!("{{{}}}", rows.join(",")), capped)
}
pub(crate) struct BoundedSelections<'a>(pub(crate) &'a BTreeMap<String, MoneyFileSelection>);
impl Serialize for BoundedSelections<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let (json, _) = bounded_selection_json(self.0);
        serde_json::value::RawValue::from_string(json)
            .map_err(serde::ser::Error::custom)?
            .serialize(serializer)
    }
}

pub(crate) fn record_logical_member(
    index: &mut ScanIndex,
    key: &str,
    revision: &str,
    item: &SnapshotItem,
) {
    let root = claude_snapshot_family_root_ref(item);
    if item.source_session_id.len() > 128
        || root.len() > 128
        || key.len() > MAX_SELECTION_KEY
        || (index.claude_money_files.len() >= MAX_SELECTIONS
            && !index.claude_money_files.contains_key(key))
    {
        mark_capacity(&mut index.claude_money_files);
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

/// Borrow the root for bounded dependency walks; do not allocate both names
/// for every unrelated indexed file on every fixed-point pass.
pub(crate) fn logical_family_root_ref<'a>(index: &'a ScanIndex, key: &'a str) -> Option<&'a str> {
    if let Some(state) = index.claude_money_files.get(key).filter(|state| {
        state.root.len() <= 128
            && state.member.len() <= 128
            && index
                .files
                .get(key)
                .is_some_and(|entry| entry.source_file_fingerprint == state.revision)
    }) {
        return Some(&state.root);
    }
    Some(super::super::claude_index_path_member_ref(Path::new(key))?.root)
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
    if selections_capped(&index.claude_money_files) {
        return false;
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
        .map(|(key, record)| (key.clone(), super::custody::RecordRef::from(record)))
        .chain(ledger.census().semantic_records())
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
    digest.update(b"ever-indexed\0");
    for root in ledger.census().history() {
        if Instant::now() >= deadline {
            return false;
        }
        digest.update(root);
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
    index.claude_money_files.retain(|key, state| {
        key == CAPACITY_KEY || state.synthetic_body.is_some() || index.files.contains_key(key)
    });
    if bounded_selection_json(&index.claude_money_files).1 {
        mark_capacity(&mut index.claude_money_files);
        return false;
    }
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

pub(super) fn logical_digest(root: &str, member: &str) -> [u8; 32] {
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
            changed |= money_io!(Metadata, std::fs::metadata(key)).map_or(true, |metadata| {
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
                if seen.len() >= MAX_SELECTIONS || key.len() > MAX_SELECTION_KEY {
                    map.next_value::<IgnoredAny>()?;
                    mark_capacity(&mut result);
                    continue;
                }
                let raw = map.next_value::<Box<serde_json::value::RawValue>>()?;
                if !seen.insert(key.clone()) {
                    result.remove(&key);
                    continue;
                }
                if raw.get().len() > MAX_SELECTION_RECORD {
                    mark_capacity(&mut result);
                    continue;
                }
                if let Ok(state) = serde_json::from_str::<MoneyFileSelection>(raw.get()) {
                    if valid_state(&state) {
                        result.insert(key, state);
                    }
                }
            }
            Ok(result)
        }
    }
    let raw = Box::<serde_json::value::RawValue>::deserialize(deserializer)?;
    if raw.get().len() > MAX_SELECTION_BYTES {
        return Ok(BTreeMap::from([(CAPACITY_KEY.into(), capacity_marker())]));
    }
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

pub(crate) fn finalize_synthetic(index: &mut ScanIndex, items: &mut Vec<SnapshotItem>) {
    items.retain(|item| {
        if selections_capped(&index.claude_money_files) && synthetic(item) {
            return false;
        }
        let key = store::money_key("synthetic:", &item.source_session_id);
        if synthetic(item)
            && item.usage_accounting_contract.as_deref() == Some(REQUEST_OWNED_CONTRACT)
        {
            let body = super::super::snapshot_upload_body_witness(item);
            let unchanged = index.claude_money_files.get(&key).is_some_and(|old| {
                old.revision == item.snapshot_fingerprint
                    && old.synthetic_body.as_deref() == Some(body.as_str())
            }) && index
                .accepted_snapshot_fingerprints
                .contains(&item.snapshot_fingerprint)
                && !index.quarantine_requires_retry_body(&item.snapshot_fingerprint, &body)
                && !index
                    .active_request_money_support_dir
                    .as_deref()
                    .is_some_and(|support| {
                        super::money_due(
                            support,
                            &format!("synthetic:{}", item.source_session_id),
                            super::page_now(support),
                        )
                    });
            if unchanged {
                return false;
            }
            index.claude_money_files.insert(
                key,
                MoneyFileSelection {
                    revision: item.snapshot_fingerprint.clone(),
                    root: item.source_session_id.clone(),
                    member: item.source_session_id.clone(),
                    consumed: None,
                    synthetic_body: Some(body),
                    reparse_union: None,
                },
            );
            if bounded_selection_json(&index.claude_money_files).1 {
                mark_capacity(&mut index.claude_money_files);
                return false;
            }
        } else if item.source_file_fingerprint.is_some()
            && item.usage_accounting_contract.as_deref() == Some(REQUEST_OWNED_CONTRACT)
        {
            index.claude_money_files.remove(&key);
        }
        true
    });
}

pub(crate) fn selected_money_files(
    index: &ScanIndex,
    previous: &ScanIndex,
    safe: &BTreeSet<String>,
    accepted: &BTreeSet<String>,
    settled: impl Fn(&str) -> bool,
) -> BTreeMap<String, MoneyFileSelection> {
    let mut selected = previous
        .claude_money_files
        .iter()
        .filter(|(key, state)| {
            key.as_str() == CAPACITY_KEY
                || state.synthetic_body.is_some()
                || index.files.contains_key(*key)
                || previous.files.contains_key(*key)
        })
        .map(|(key, state)| (key.clone(), state.clone()))
        .collect::<BTreeMap<_, _>>();
    for (key, state) in &index.claude_money_files {
        if safe.contains(key)
            || (state.synthetic_body.is_some()
                && accepted.contains(&state.revision)
                && settled(&state.revision))
        {
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
    if selections_capped(&index.claude_money_files) {
        mark_capacity(&mut selected);
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

#[cfg(test)]
mod integration_selection_regressions {
    use super::*;
    #[test]
    fn capped_save_reload_never_reowes_or_reoffers_and_keeps_census_on_second_load() {
        crate::snapshots::claude_history_upgrade::with_max_gated_claude_revision(3, || {
            let scratch = crate::test_scratch::ScratchDir::new("money-selection-cap");
            let path = scratch.join("index.json");
            let key = "/home/projects/-fixture/ffffffff-ffff-4fff-8fff-ffffffffffff.jsonl";
            let mut index = ScanIndex::default();
            let mut entry = crate::snapshots::tests::manifest_index_entry(Some(&"d".repeat(64)));
            entry.source_file_fingerprint = "a".repeat(64);
            entry.effective_upload_body_witness_revision = 3;
            index.files.insert(key.into(), entry);
            index.claude_request_census.insert_for_test(
                key,
                ClaudeRequestCensusRecord::synthetic_for_test(
                    &"a".repeat(64),
                    1,
                    super::super::super::claude_request_census::ClaudeRequestCensusShape::Exact,
                    vec![1],
                ),
            );
            for at in 0..=MAX_SELECTIONS {
                let mut state = capacity_marker();
                state.root = "root".into();
                state.member = format!("member-{at}");
                index
                    .claude_money_files
                    .insert(format!("/capacity/{at:06}"), state);
            }
            index.save(&path).unwrap();
            let raw: serde_json::Value =
                serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
            assert!(raw["claude_money_files"].as_object().unwrap().len() <= MAX_SELECTIONS);
            let bytes = serde_json::to_vec(&raw["claude_money_files"]).unwrap();
            assert!(bytes.len() <= MAX_SELECTION_BYTES);
            for (_, value) in raw["claude_money_files"].as_object().unwrap() {
                assert!(serde_json::to_vec(value).unwrap().len() <= MAX_SELECTION_RECORD);
            }
            let mut first = ScanIndex::load(&path).unwrap();
            assert!(selections_capped(&first.claude_money_files));
            assert_eq!(first.files[key].effective_upload_body_witness_revision, 3);
            let census = serde_json::to_vec(&first.claude_request_census).unwrap();
            assert!(first.claude_request_census.get(key).is_some());
            let mut synthetic = super::super::synthetic_carrier("overflow", "2026-08-03T10:00:00Z");
            synthetic.usage_accounting_contract = Some(REQUEST_OWNED_CONTRACT.into());
            let mut items = vec![synthetic];
            finalize_synthetic(&mut first, &mut items);
            assert!(
                items.is_empty(),
                "capacity refusal cannot create a repeated untracked offer"
            );
            first.save(&path).unwrap();
            let second = ScanIndex::load(&path).unwrap();
            assert_eq!(second.files[key].effective_upload_body_witness_revision, 3);
            assert_eq!(
                serde_json::to_vec(&second.claude_request_census).unwrap(),
                census
            );
            assert_eq!(
                serde_json::to_vec(&first.claude_money_files).unwrap(),
                serde_json::to_vec(&second.claude_money_files).unwrap()
            );
        });
    }

    #[test]
    fn selection_writer_and_reader_share_key_record_and_raw_field_caps() {
        for (key, state) in [
            ("k".repeat(MAX_SELECTION_KEY + 1), capacity_marker()),
            (
                "record".into(),
                MoneyFileSelection {
                    root: "x".repeat(MAX_SELECTION_RECORD),
                    ..capacity_marker()
                },
            ),
        ] {
            let states = BTreeMap::from([(key, state)]);
            let (json, capped) = bounded_selection_json(&states);
            assert!(capped);
            let mut decoder = serde_json::Deserializer::from_str(&json);
            let read = decode_selections(&mut decoder).unwrap();
            assert!(selections_capped(&read));
            assert_eq!(read.len(), 1);
        }
    }

    #[test]
    fn assembled_lenient_decode_rearms_lost_claude_selection_without_touching_codex() {
        crate::snapshots::claude_history_upgrade::with_max_gated_claude_revision(3, || {
            let scratch = crate::test_scratch::ScratchDir::new("money-selection-assembled");
            let path = scratch.join("index.json");
            let key = "/home/projects/-fixture/a1111111-1111-4111-8111-111111111111.jsonl";
            let codex = "/home/sessions/2026/10/rollout-native.jsonl";
            let mut index = ScanIndex::default();
            let mut entry = crate::snapshots::tests::manifest_index_entry(Some(&"d".repeat(64)));
            entry.source_file_fingerprint = "a".repeat(64);
            entry.last_upload_body_witness = Some("e".repeat(64));
            entry.effective_upload_body_witness_revision = 3;
            index.files.insert(key.into(), entry.clone());
            entry.effective_upload_body_witness_revision = 24;
            index.files.insert(codex.into(), entry);
            index.claude_request_census.insert_for_test(
                key,
                ClaudeRequestCensusRecord::synthetic_for_test(
                    &"a".repeat(64),
                    1,
                    super::super::super::claude_request_census::ClaudeRequestCensusShape::Exact,
                    vec![1],
                ),
            );
            let mut wire = serde_json::to_value(&index).unwrap();
            wire["claude_money_files"] = serde_json::json!({key: {"revision": false}});
            std::fs::write(&path, serde_json::to_vec(&wire).unwrap()).unwrap();
            let loaded = ScanIndex::load(&path).unwrap();
            assert_eq!(loaded.files[key].effective_upload_body_witness_revision, 2);
            assert!(
                loaded.claude_request_census.get(key).is_none(),
                "selection loss invalidates evidence even without a birth stub"
            );
            assert_eq!(
                loaded.files[codex].effective_upload_body_witness_revision,
                24
            );
        });
    }
    #[test]
    fn accepted_synthetic_noop_requires_the_same_body_and_never_commits_a_refused_correction() {
        let mut index = ScanIndex::default();
        let mut item = super::super::synthetic_carrier("synthetic-root", "2026-08-03T10:00:00Z");
        item.snapshot_fingerprint = "a".repeat(64);
        item.usage_accounting_contract = Some(REQUEST_OWNED_CONTRACT.into());
        item.input_tokens = 10;
        let body = super::super::super::snapshot_upload_body_witness(&item);
        let mut first = vec![item.clone()];
        finalize_synthetic(&mut index, &mut first);
        assert_eq!(first.len(), 1, "unaccepted output remains owed");
        index
            .accepted_snapshot_fingerprints
            .insert(item.snapshot_fingerprint.clone());
        let previous = index.clone();
        let mut repeated = vec![item.clone()];
        finalize_synthetic(&mut index, &mut repeated);
        assert!(repeated.is_empty(), "the exact accepted body is a noop");
        item.tool_usage_truncated = true;
        let corrected_body = super::super::super::snapshot_upload_body_witness(&item);
        assert_ne!(body, corrected_body);
        let mut corrected = vec![item.clone()];
        finalize_synthetic(&mut index, &mut corrected);
        assert_eq!(
            corrected.len(),
            1,
            "same fingerprint does not cover a changed body"
        );
        let selected = selected_money_files(
            &index,
            &previous,
            &BTreeSet::new(),
            &BTreeSet::new(),
            |_| true,
        );
        let key = store::money_key("synthetic:", &item.source_session_id);
        assert_eq!(
            selected[&key].synthetic_body.as_deref(),
            Some(body.as_str()),
            "a quarantine/old ACK cannot certify this correction"
        );
    }
}
