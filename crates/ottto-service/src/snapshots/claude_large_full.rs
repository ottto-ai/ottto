//! Bounded scheduling priority only; pending traversal paths own read debt.
use super::*;
use serde::de::{DeserializeSeed, IgnoredAny, MapAccess, SeqAccess, Visitor};
use std::fmt;

pub(super) const LARGE_FULL_BYTES: u64 = 256 * 1024 * 1024;
// This leaf alone: no cache, scan, parser, visit or pin budget is enlarged.
pub(super) const MAX_KEYS: usize = 256;
pub(super) const MAX_BYTES: usize = 64 * 1024;
const MAX_KEY_BYTES: usize = 4096;
const FIXED_BYTES: usize = MAX_KEYS * std::mem::size_of::<String>() + 256;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(default)]
pub(super) struct Priority {
    #[serde(skip_serializing_if = "VecDeque::is_empty")]
    keys: VecDeque<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    scope: Option<String>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    overflow: bool,
}

#[cfg(not(test))]
static DECODE_DROPS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
#[cfg(test)]
thread_local! { static DECODE_DROPS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) }; }
fn note_decode_drop() {
    #[cfg(not(test))]
    let count = DECODE_DROPS.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
    #[cfg(test)]
    let count = DECODE_DROPS.with(|count| {
        count.set(count.get().saturating_add(1));
        count.get()
    });
    emit_scan_index_containment_line(format!(
        "local snapshot scan index: claude_large_full_debt_decode_drops={count} fallback=ordinary_census_fifo"
    ));
}

impl Priority {
    #[cfg(test)]
    pub(super) fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
    pub(super) fn is_idle(&self) -> bool {
        self.keys.is_empty() && !self.overflow
    }
    pub(super) fn iter(&self) -> impl Iterator<Item = &String> {
        self.keys.iter()
    }
    pub(super) fn contains(&self, key: &String) -> bool {
        self.keys.contains(key)
    }
    #[cfg(test)]
    pub(super) fn clear(&mut self) {
        *self = Self::default();
    }
    pub(super) fn fallback() -> Self {
        note_decode_drop();
        Self {
            overflow: true,
            ..Self::default()
        }
    }
    fn compact(&mut self) {
        if self.keys.is_empty() {
            self.keys = VecDeque::new();
        } else {
            self.keys.shrink_to_fit();
        }
    }
    fn remove(&mut self, key: &str) {
        self.keys.retain(|entry| entry != key);
        self.compact();
    }
    fn charge(&self) -> usize {
        FIXED_BYTES + self.keys.iter().map(|key| key_charge(key)).sum::<usize>()
    }
    // Refusal loses only cached priority. The path stays pending and overflow
    // reserves ordinary FIFO service before new audits/hints, including restart.
    pub(super) fn push_back(&mut self, key: String) {
        if self.keys.contains(&key) {
            return;
        }
        if self.overflow
            || self.keys.len() >= MAX_KEYS
            || key.len() > MAX_KEY_BYTES
            || !Path::new(&key).is_absolute()
            || self.charge().saturating_add(key_charge(&key)) > MAX_BYTES
        {
            self.overflow = true;
            return;
        }
        if self.keys.len() == self.keys.capacity() {
            self.keys.reserve_exact(1);
        }
        self.keys.push_back(key.into_boxed_str().into_string());
    }
    pub(super) fn begin(&mut self, context: &str, roots: &[PathBuf]) {
        if self.scope.as_deref() != Some(context) {
            let overflow = !self.is_idle();
            *self = Self {
                scope: Some(context.to_owned()),
                overflow,
                ..Self::default()
            };
        }
        self.keys.retain(|key| {
            let path = Path::new(key);
            if !roots.iter().any(|root| path.starts_with(root)) {
                return false;
            }
            match fs::symlink_metadata(path) {
                Ok(meta) => {
                    meta.is_file()
                        && meta.len() > LARGE_FULL_BYTES
                        && meta.len() <= MAX_JSONL_FILE_BYTES
                }
                Err(error) => error.kind() != std::io::ErrorKind::NotFound,
            }
        });
        self.compact();
    }
    pub(super) fn overflowing(&self) -> bool {
        self.overflow
    }
}
fn key_charge(key: &str) -> usize {
    // JSON lexical bytes (including escapes and comma) upper-bound owned UTF-8.
    3 + key
        .bytes()
        .map(|b| match b {
            b'"' | b'\\' => 2,
            0..=31 => 6,
            _ => 1,
        })
        .sum::<usize>()
}
impl<'a> IntoIterator for &'a Priority {
    type Item = &'a String;
    type IntoIter = std::collections::vec_deque::Iter<'a, String>;
    fn into_iter(self) -> Self::IntoIter {
        self.keys.iter()
    }
}
impl From<VecDeque<String>> for Priority {
    fn from(keys: VecDeque<String>) -> Self {
        let mut result = Self::default();
        for key in keys {
            result.push_back(key);
        }
        result
    }
}
impl crate::heap_layout_bound::HeapLayoutBound for Priority {
    const STABLE_HEAP: bool = true;
    fn heap_bound(&self, c: &mut crate::heap_layout_bound::Counter) -> Option<()> {
        self.keys.heap_bound(c)?;
        self.scope.heap_bound(c)
    }
}

// Native Serde never builds an unrestricted Value/VecDeque. Retained parse
// state has a shared byte/node fund; after refusal all remaining tokens drain
// through IgnoredAny. Production readers ALSO preflight raw lexical span size
// before Serde's string/escape scratch can be allocated.
struct Fund {
    bytes: usize,
    nodes: usize,
    bad: bool,
}
struct Seed<'a> {
    fund: &'a mut Fund,
    depth: usize,
}
impl<'de> DeserializeSeed<'de> for Seed<'_> {
    type Value = Value;
    fn deserialize<D: serde::Deserializer<'de>>(
        self,
        d: D,
    ) -> std::result::Result<Value, D::Error> {
        if self.fund.bad || self.depth > 3 || self.fund.nodes == 0 || self.fund.bytes < 128 {
            self.fund.bad = true;
            IgnoredAny::deserialize(d)?;
            return Ok(Value::Null);
        }
        self.fund.nodes -= 1;
        self.fund.bytes -= 128;
        d.deserialize_any(self)
    }
}
impl<'de> Visitor<'de> for Seed<'_> {
    type Value = Value;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("bounded scheduling state")
    }
    fn visit_unit<E: serde::de::Error>(self) -> std::result::Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_bool<E: serde::de::Error>(self, v: bool) -> std::result::Result<Value, E> {
        Ok(Value::Bool(v))
    }
    fn visit_u64<E: serde::de::Error>(self, v: u64) -> std::result::Result<Value, E> {
        Ok(Value::from(v))
    }
    fn visit_i64<E: serde::de::Error>(self, v: i64) -> std::result::Result<Value, E> {
        Ok(Value::from(v))
    }
    fn visit_f64<E: serde::de::Error>(self, _: f64) -> std::result::Result<Value, E> {
        self.fund.bad = true;
        Ok(Value::Null)
    }
    fn visit_str<E: serde::de::Error>(self, v: &str) -> std::result::Result<Value, E> {
        if v.len() > MAX_KEY_BYTES || v.len() > self.fund.bytes {
            self.fund.bad = true;
            return Ok(Value::Null);
        }
        self.fund.bytes -= v.len();
        Ok(Value::String(v.to_owned()))
    }
    fn visit_string<E: serde::de::Error>(self, v: String) -> std::result::Result<Value, E> {
        self.visit_str(&v)
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> std::result::Result<Value, A::Error> {
        let mut out = Vec::new();
        while let Some(value) = seq.next_element_seed(Seed {
            fund: self.fund,
            depth: self.depth + 1,
        })? {
            if self.fund.bad {
                out.clear();
            } else {
                out.push(value);
            }
        }
        Ok(Value::Array(out))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> std::result::Result<Value, A::Error> {
        let mut out = serde_json::Map::new();
        while let Some(key) = map.next_key_seed(Seed {
            fund: self.fund,
            depth: self.depth + 1,
        })? {
            let value = map.next_value_seed(Seed {
                fund: self.fund,
                depth: self.depth + 1,
            })?;
            if self.fund.bad {
                out.clear();
            } else if let Value::String(key) = key {
                if out.insert(key, value).is_some() {
                    self.fund.bad = true;
                    out.clear();
                }
            } else {
                self.fund.bad = true;
                out.clear();
            }
        }
        Ok(Value::Object(out))
    }
}
impl<'de> Deserialize<'de> for Priority {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        #[derive(Default, Deserialize)]
        #[serde(default, deny_unknown_fields)]
        struct Stored {
            keys: VecDeque<String>,
            scope: Option<String>,
            overflow: bool,
        }
        let mut fund = Fund {
            bytes: MAX_BYTES * 2,
            nodes: MAX_KEYS + 16,
            bad: false,
        };
        let value = Seed {
            fund: &mut fund,
            depth: 0,
        }
        .deserialize(d)?;
        if fund.bad {
            return Ok(Self::fallback());
        }
        // Legacy arrays carry scheduling only. Bind/GC them at scan start.
        let stored = if value.is_array() {
            serde_json::from_value(value).map(|keys| Stored {
                keys,
                ..Stored::default()
            })
        } else {
            serde_json::from_value::<Stored>(value)
        };
        let Ok(stored) = stored else {
            return Ok(Self::fallback());
        };
        if stored.keys.len() > MAX_KEYS
            || stored
                .scope
                .as_ref()
                .is_some_and(|s| s.len() != 64 || !s.bytes().all(|b| b.is_ascii_hexdigit()))
        {
            return Ok(Self::fallback());
        }
        let mut result = Self {
            scope: stored.scope,
            ..Self::default()
        };
        for key in stored.keys {
            if result.contains(&key) {
                return Ok(Self::fallback());
            }
            result.push_back(key);
            if result.overflow {
                return Ok(Self::fallback());
            }
        }
        result.overflow = stored.overflow;
        Ok(result)
    }
}

pub(super) fn is_large(candidate: &CandidateFile) -> bool {
    candidate.size_bytes > LARGE_FULL_BYTES
}

pub(super) fn select_deferred(
    debt: &mut Priority,
    pending: &mut VecDeque<ScanTraversalPath>,
    selected: &mut Vec<ScanTraversalPath>,
    limit: usize,
    discovery_done: bool,
) {
    for _ in 0..debt.keys.len() {
        let key = debt.keys.pop_front().expect("FIFO length");
        if let Some(position) = pending.iter().position(|p| p.path == Path::new(&key)) {
            if selected.len() < limit {
                selected.push(pending.remove(position).expect("pending position"));
            }
            debt.keys.push_back(key);
        } else if !discovery_done {
            debt.keys.push_back(key);
        }
    }
    debt.compact();
    if debt.overflow {
        if discovery_done && debt.keys.is_empty() && !pending.iter().any(|p| p.census_member) {
            debt.overflow = false;
        } else {
            // The bounded cache cannot describe the overflow order. The
            // separately persisted pending FIFO can, and never drops a path.
            for _ in 0..pending.len() {
                let path = pending.pop_front().expect("pending length");
                if selected.len() < limit && path.census_member {
                    selected.push(path);
                } else {
                    pending.push_back(path);
                }
            }
        }
    }
}

pub(super) fn admit(
    index: &mut ScanIndex,
    candidate: &CandidateFile,
    full: bool,
    started: &mut bool,
) -> bool {
    let key = local_index_key(&candidate.path);
    if full && is_large(candidate) {
        if *started {
            let traversal = index.traversal.as_mut().expect("active Claude traversal");
            if let Some(pending) = traversal
                .pending_candidates
                .iter_mut()
                .find(|pending| pending.path == candidate.path)
            {
                pending.census_member = true;
            } else {
                traversal.pending_candidates.push_back(ScanTraversalPath {
                    scan_root: candidate.scan_root.clone(),
                    path: candidate.path.clone(),
                    // Even a previously processed hinted/audited path holds
                    // this generation open until its scheduled read happens.
                    census_member: true,
                    watcher_hint: false,
                });
            }
            if let Some(slot) = index
                .held_audit_progress
                .as_mut()
                .filter(|slot| slot.key == key)
            {
                // Queueing was not an audit attempt. Keep its original turn
                // and deadline until native acquisition can actually start.
                slot.attempted = false;
            }
            if !index.claude_large_full_deferred.contains(&key) {
                index.claude_large_full_deferred.push_back(key);
            }
            return false;
        }
        *started = true;
    }
    index.claude_large_full_deferred.remove(&key);
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    fn path(n: usize) -> String {
        format!("/synthetic/{n:04}.jsonl")
    }
    #[test]
    fn insertion_has_entry_byte_key_and_capacity_bounds() {
        let mut debt = Priority::default();
        for n in 0..MAX_KEYS {
            debt.push_back(path(n));
        }
        assert_eq!(debt.keys.len(), MAX_KEYS);
        assert!(!debt.overflow);
        debt.push_back(path(MAX_KEYS));
        assert!(debt.overflow);
        assert_eq!(debt.keys.len(), MAX_KEYS);
        assert!(debt.charge() <= MAX_BYTES);
        assert!(debt.keys.capacity() <= MAX_KEYS);
        // Refusal cannot allocate/capture the excess key.
        let before = debt.clone();
        debt.push_back(format!("/{}", "x".repeat(MAX_BYTES)));
        assert_eq!(debt, before);
        let mut bytes = Priority::default();
        for n in 0..MAX_KEYS {
            bytes.push_back(format!("/{n:04}{}", "x".repeat(MAX_KEY_BYTES - 8)));
        }
        assert!(bytes.overflow);
        assert!(bytes.keys.len() < MAX_KEYS);
        assert!(bytes.charge() <= MAX_BYTES);
        assert!(serde_json::to_vec(&bytes).unwrap().len() <= MAX_BYTES);
        let roundtrip: Priority =
            serde_json::from_slice(&serde_json::to_vec(&bytes).unwrap()).unwrap();
        assert_eq!(roundtrip, bytes);
        for key in bytes.keys.clone() {
            bytes.remove(&key);
        }
        assert_eq!(bytes.keys.capacity(), 0, "GC releases prior peak capacity");
    }
    #[test]
    fn decode_bounds_and_damage_preserve_every_other_native_field() {
        let mut seed = ScanIndex::default();
        let fingerprint = "a".repeat(64);
        seed.files.insert(
            "/synthetic/committed.jsonl".into(),
            super::super::tests::manifest_index_entry(Some(&fingerprint)),
        );
        seed.accepted_snapshot_fingerprints.insert(fingerprint);
        let expected = serde_json::to_value(seed).unwrap();
        let mut damage = vec![
            serde_json::json!(null),
            serde_json::json!({"keys":[1]}),
            serde_json::json!({"keys":["/same","/same"]}),
            serde_json::json!({"scope":"bad"}),
            serde_json::json!({"keys":[format!("/{}","x".repeat(MAX_KEY_BYTES+1))]}),
            serde_json::json!((0..MAX_KEYS + 1).map(path).collect::<Vec<_>>()),
            serde_json::json!({"keys":[format!("/{}","\n".repeat(MAX_BYTES))]}),
        ];
        damage.push(serde_json::json!({"keys":[],"unknown":"x".repeat(MAX_BYTES*2)}));
        for bad in damage {
            let mut value = expected.clone();
            value["claude_large_full_deferred"] = bad;
            let bytes = serde_json::to_vec(&value).unwrap();
            let before = DECODE_DROPS.with(std::cell::Cell::get);
            let direct: ScanIndex = serde_json::from_slice(&bytes).unwrap();
            let gated = claude_request_census::decode_index(bytes.as_slice()).unwrap();
            let streamed =
                lenient_decode::read(std::io::Cursor::new(&bytes), "load", "claude_code").unwrap();
            assert_eq!(DECODE_DROPS.with(std::cell::Cell::get), before + 3);
            for index in [direct, gated, streamed] {
                assert!(index.claude_large_full_deferred.keys.is_empty());
                assert!(index.claude_large_full_deferred.overflow);
                assert_eq!(index.claude_large_full_deferred.keys.capacity(), 0);
                let mut actual = serde_json::to_value(index).unwrap();
                actual
                    .as_object_mut()
                    .unwrap()
                    .remove("claude_large_full_deferred");
                assert_eq!(actual, expected, "decode repair changes no native custody");
            }
        }
    }
    #[test]
    fn production_decode_preflights_deep_wide_and_nonfinite_tokens() {
        let expected = serde_json::to_value(ScanIndex::default()).unwrap();
        for raw in [
            format!("{}0{}", "[".repeat(300), "]".repeat(300)),
            "1e400".to_owned(),
            format!("[{}]", " ".repeat(MAX_BYTES + 1)),
        ] {
            let mut bytes = serde_json::to_string(&expected).unwrap();
            bytes.pop();
            bytes.push_str(",\"claude_large_full_deferred\":");
            bytes.push_str(&raw);
            bytes.push('}');
            let before = DECODE_DROPS.with(std::cell::Cell::get);
            let native = claude_request_census::decode_index(bytes.as_bytes()).unwrap();
            let streamed = lenient_decode::read(
                std::io::Cursor::new(bytes.as_bytes()),
                "load",
                "claude_code",
            )
            .unwrap();
            assert_eq!(DECODE_DROPS.with(std::cell::Cell::get), before + 2);
            for index in [native, streamed] {
                assert!(index.claude_large_full_deferred.overflowing());
                assert!(index.claude_large_full_deferred.keys.is_empty());
                let mut actual = serde_json::to_value(index).unwrap();
                actual
                    .as_object_mut()
                    .unwrap()
                    .remove("claude_large_full_deferred");
                assert_eq!(actual, expected);
            }
        }
    }
    #[test]
    fn gc_shrink_delete_scope_account_and_partial_walk_stale_keys() {
        let scratch = crate::test_scratch::ScratchDir::new("large-debt-gc");
        let root = scratch.as_ref().to_path_buf();
        let roots = std::slice::from_ref(&root);
        let mut index = ScanIndex::default();
        let context = scan_traversal_context_fingerprint(
            SnapshotSource::ClaudeCode,
            roots,
            &index,
            BACKFILL_WINDOW_DAYS,
        );
        let mut debt = Priority::default();
        debt.begin(&context, roots);
        let keep = root.join("keep.jsonl");
        let shrink = root.join("shrink.jsonl");
        let gone = root.join("gone.jsonl");
        for path in [&keep, &shrink, &gone] {
            fs::File::create(path)
                .unwrap()
                .set_len(LARGE_FULL_BYTES + 1)
                .unwrap();
            debt.push_back(local_index_key(path));
        }
        fs::File::options()
            .write(true)
            .open(&shrink)
            .unwrap()
            .set_len(LARGE_FULL_BYTES)
            .unwrap();
        fs::remove_file(&gone).unwrap();
        debt.begin(&context, roots);
        assert_eq!(debt.keys, VecDeque::from([local_index_key(&keep)]));
        // Stale paths do not accumulate across unfinished discovery pages.
        for page in 0..MAX_KEYS * 2 {
            debt.push_back(local_index_key(&root.join(format!("missing-{page}.jsonl"))));
            debt.begin(&context, roots);
            assert_eq!(debt.keys.len(), 1);
            assert!(debt.keys.capacity() <= MAX_KEYS);
        }
        let outside = root.join("other-scope");
        let changed = scan_traversal_context_fingerprint(
            SnapshotSource::ClaudeCode,
            std::slice::from_ref(&outside),
            &index,
            BACKFILL_WINDOW_DAYS,
        );
        debt.begin(&changed, std::slice::from_ref(&outside));
        assert!(debt.keys.is_empty());
        assert_eq!(debt.keys.capacity(), 0);
        debt = Priority::default();
        debt.begin(&context, roots);
        debt.push_back(local_index_key(&keep));
        assert_eq!(debt.keys.len(), 1);
        index.active_upload_context_fingerprint = Some("different-account".into());
        let account = scan_traversal_context_fingerprint(
            SnapshotSource::ClaudeCode,
            roots,
            &index,
            BACKFILL_WINDOW_DAYS,
        );
        debt.begin(&account, roots);
        assert!(debt.keys.is_empty());
        assert_eq!(debt.keys.capacity(), 0);
    }
}
