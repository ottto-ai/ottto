//! Claude-only physical births and move cutoffs, independent of upload settlement.
//! Sorted boxed slices avoid path strings and per-node/spare capacity overhead.
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
pub(crate) const ABSENT_RETENTION_SECONDS: u64 = 30 * 24 * 60 * 60;
// Domain-separated SHA-256 prefixes are local lookup keys, never move proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct LocationKey([u8; 16]);
fn key(domain: &[u8], value: &str) -> LocationKey {
    let mut h = Sha256::new();
    h.update(domain);
    h.update(value.as_bytes());
    LocationKey(h.finalize()[..16].try_into().expect("digest prefix"))
}
pub(crate) fn location_key(path: &str) -> LocationKey {
    key(b"claude-money-path-v1\0", path)
}
fn session_key(session: &str) -> LocationKey {
    key(b"claude-money-session-v1\0", session)
}
// Tuple wire shape: [session, owner, cutoff, absent-since, physical observations].
#[derive(Debug, Clone)]
struct Session(
    LocationKey,
    LocationKey,
    u64,
    u64,
    Box<[(LocationKey, u64)]>,
);
#[derive(Debug, Clone, Default)]
pub(crate) struct BirthStore(Box<[Session]>);
// One versioned binary string keeps the handwritten pretty index writer within
// the disk budget too. Integer fields are little endian; no wall time is invented.
impl Serialize for BirthStore {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let byte_len = self
            .0
            .iter()
            .try_fold(8usize, |n, s| {
                n.checked_add(52)?.checked_add(s.4.len().checked_mul(24)?)
            })
            .ok_or_else(|| serde::ser::Error::custom("birth table size overflow"))?;
        let mut bytes = Vec::with_capacity(byte_len);
        bytes.extend_from_slice(b"CMB1");
        bytes.extend_from_slice(&(self.0.len() as u32).to_le_bytes());
        for Session(session, owner, cutoff, absent, paths) in &self.0 {
            bytes.extend_from_slice(&session.0);
            bytes.extend_from_slice(&owner.0);
            bytes.extend_from_slice(&cutoff.to_le_bytes());
            bytes.extend_from_slice(&absent.to_le_bytes());
            bytes.extend_from_slice(&(paths.len() as u32).to_le_bytes());
            for (path, birth) in paths {
                bytes.extend_from_slice(&path.0);
                bytes.extend_from_slice(&birth.to_le_bytes());
            }
        }
        serializer.serialize_str(&URL_SAFE_NO_PAD.encode(bytes))
    }
}
impl<'de> Deserialize<'de> for BirthStore {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        fn decode(encoded: &str) -> Option<BirthStore> {
            if encoded.len() > 4 * 1024 * 1024 {
                return None;
            }
            let bytes = URL_SAFE_NO_PAD.decode(encoded).ok()?;
            let mut input = bytes.as_slice();
            fn take<const N: usize>(input: &mut &[u8]) -> Option<[u8; N]> {
                let value = input.get(..N)?.try_into().ok()?;
                *input = &input[N..];
                Some(value)
            }
            if take::<4>(&mut input)? != *b"CMB1" {
                return None;
            }
            let count = u32::from_le_bytes(take(&mut input)?) as usize;
            if count > input.len() / 52 {
                return None;
            }
            let mut sessions = Vec::with_capacity(count);
            for _ in 0..count {
                let session = LocationKey(take(&mut input)?);
                let owner = LocationKey(take(&mut input)?);
                let cutoff = u64::from_le_bytes(take(&mut input)?);
                let absent = u64::from_le_bytes(take(&mut input)?);
                let count = u32::from_le_bytes(take(&mut input)?) as usize;
                if count > input.len() / 24 {
                    return None;
                }
                let mut paths = Vec::with_capacity(count);
                for _ in 0..count {
                    paths.push((
                        LocationKey(take(&mut input)?),
                        u64::from_le_bytes(take(&mut input)?),
                    ));
                }
                sessions.push(Session(
                    session,
                    owner,
                    cutoff,
                    absent,
                    paths.into_boxed_slice(),
                ));
            }
            if !input.is_empty() {
                return None;
            }
            BirthStore(sessions.into_boxed_slice()).valid()
        }
        let encoded = String::deserialize(deserializer)?;
        decode(&encoded).ok_or_else(|| serde::de::Error::custom("invalid birth table"))
    }
}
impl BirthStore {
    pub(crate) fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
    fn get(&self, session: &str) -> Option<&Session> {
        let key = session_key(session);
        self.0
            .binary_search_by_key(&key, |s| s.0)
            .ok()
            .map(|i| &self.0[i])
    }
    pub(crate) fn observed_birth(&self, session: &str, path: &str) -> Option<i128> {
        let s = self.get(session)?;
        let key = location_key(path);
        s.4.binary_search_by_key(&key, |o| o.0)
            .ok()
            .map(|i| i128::from(s.4[i].1))
    }
    pub(crate) fn effective_cutoff(&self, session: &str, path: &str) -> Option<i128> {
        let s = self.get(session)?;
        if s.1 == location_key(path) {
            Some(i128::from(s.2))
        } else {
            self.observed_birth(session, path)
        }
    }
    pub(crate) fn session_effective_cutoff(&self, session: &str) -> Option<i128> {
        Some(i128::from(self.get(session)?.2))
    }
    pub(crate) fn live_location(&self, session: &str) -> Option<LocationKey> {
        Some(self.get(session)?.1)
    }
    /// Only opened-object physical birth belongs here, never an inherited cutoff.
    pub(crate) fn record_observation(&mut self, session: &str, path: &str, birth: i128) {
        let Ok(birth) = u64::try_from(birth) else {
            return;
        };
        if birth == 0 {
            return;
        }
        let sk = session_key(session);
        let pk = location_key(path);
        match self.0.binary_search_by_key(&sk, |s| s.0) {
            Ok(i) => {
                let s = &mut self.0[i];
                match s.4.binary_search_by_key(&pk, |o| o.0) {
                    Ok(j) => s.4[j].1 = s.4[j].1.min(birth),
                    Err(j) => {
                        let mut paths = std::mem::take(&mut s.4).into_vec();
                        paths.insert(j, (pk, birth));
                        s.4 = paths.into_boxed_slice();
                    }
                }
                let observed = s.4[s.4.binary_search_by_key(&pk, |o| o.0).unwrap()].1;
                if observed < s.2 {
                    s.1 = pk;
                    s.2 = observed;
                }
                s.3 = 0;
            }
            Err(i) => {
                let mut sessions = std::mem::take(&mut self.0).into_vec();
                sessions.insert(
                    i,
                    Session(sk, pk, birth, 0, vec![(pk, birth)].into_boxed_slice()),
                );
                self.0 = sessions.into_boxed_slice();
            }
        }
    }
    /// Caller proves a move of the current owner at the existing read boundary.
    /// Equal minima transfer ownership too; other live twins keep their cutoff.
    pub(crate) fn record_proven_move(
        &mut self,
        session: &str,
        from: LocationKey,
        to: &str,
    ) -> bool {
        let sk = session_key(session);
        let Ok(i) = self.0.binary_search_by_key(&sk, |s| s.0) else {
            return false;
        };
        let s = &mut self.0[i];
        let to = location_key(to);
        if s.1 != from || s.4.binary_search_by_key(&to, |o| o.0).is_err() {
            return false;
        }
        s.1 = to;
        s.3 = 0;
        true
    }
    /// Earlier effective birth, then digest order, prevents reciprocal deletion.
    /// Caller validates the opened live witness, rather than pathname existence.
    pub(crate) fn original_witness(
        &self,
        session: &str,
        path: &str,
        live: impl FnMut(LocationKey) -> bool,
    ) -> Option<LocationKey> {
        self.original_witness_at(session, path, self.effective_cutoff(session, path)?, live)
    }
    pub(crate) fn observations(
        &self,
        session: &str,
    ) -> impl Iterator<Item = (LocationKey, i128)> + '_ {
        self.get(session)
            .into_iter()
            .flat_map(|s| s.4.iter().map(|&(p, b)| (p, i128::from(b))))
    }
    pub(crate) fn original_witness_at(
        &self,
        session: &str,
        path: &str,
        opened_birth: i128,
        mut live: impl FnMut(LocationKey) -> bool,
    ) -> Option<LocationKey> {
        let s = self.get(session)?;
        let pk = location_key(path);
        let own = self
            .effective_cutoff(session, path)
            .map_or(opened_birth, |b| b.min(opened_birth));
        let current = (own, pk);
        s.4.iter()
            .filter_map(|&(p, b)| {
                let b = if p == s.1 { s.2 } else { b };
                (p != pk && (i128::from(b), p) < current && live(p)).then_some((b, p))
            })
            .min()
            .map(|(_, p)| p)
    }
    /// Observations survive partial/held save restoration independently of ACKs.
    pub(crate) fn preserve_missing_from(&mut self, previous: &Self) {
        for old in &previous.0 {
            match self.0.binary_search_by_key(&old.0, |s| s.0) {
                Err(i) => {
                    let mut sessions = std::mem::take(&mut self.0).into_vec();
                    sessions.insert(i, old.clone());
                    self.0 = sessions.into_boxed_slice();
                }
                Ok(i) => {
                    let s = &mut self.0[i];
                    for &(path, birth) in &old.4 {
                        match s.4.binary_search_by_key(&path, |o| o.0) {
                            Ok(j) => s.4[j].1 = s.4[j].1.min(birth),
                            Err(j) => {
                                let mut paths = std::mem::take(&mut s.4).into_vec();
                                paths.insert(j, (path, birth));
                                s.4 = paths.into_boxed_slice();
                            }
                        }
                    }
                    if old.2 < s.2 {
                        s.1 = old.1;
                        s.2 = old.2;
                    }
                }
            }
        }
    }
    /// Whole-session absence, not path absence; held keys count as indexed.
    pub(crate) fn prune<'a>(
        &mut self,
        now: u64,
        indexed: impl IntoIterator<Item = (&'a str, &'a str)>,
    ) {
        let mut live: Vec<_> = indexed.into_iter().map(|(s, _)| session_key(s)).collect();
        live.sort_unstable();
        live.dedup();
        for s in &mut self.0 {
            if live.binary_search(&s.0).is_ok() {
                s.3 = 0;
            } else if s.3 == 0 {
                s.3 = now.max(1);
            }
        }
        self.0 = std::mem::take(&mut self.0)
            .into_vec()
            .into_iter()
            .filter(|s| s.3 == 0 || now.saturating_sub(s.3) < ABSENT_RETENTION_SECONDS)
            .collect::<Vec<_>>()
            .into_boxed_slice();
    }
    /// Optional data is discarded as a unit if malformed or unordered.
    pub(crate) fn valid(self) -> Option<Self> {
        if self.0.windows(2).any(|w| w[0].0 >= w[1].0)
            || self.0.iter().any(|s| {
                s.2 == 0
                    || s.4.is_empty()
                    || s.4.windows(2).any(|w| w[0].0 >= w[1].0)
                    || s.4.iter().any(|o| o.1 == 0)
                    || !s.4.iter().any(|o| o.0 == s.1)
            })
        {
            None
        } else {
            Some(self)
        }
    }
    #[cfg(test)]
    fn memory_bytes(&self) -> usize {
        std::mem::size_of::<Self>()
            + std::mem::size_of_val(&*self.0)
            + self
                .0
                .iter()
                .map(|s| std::mem::size_of_val(&*s.4))
                .sum::<usize>()
    }
}
impl crate::heap_layout_bound::HeapLayoutBound for BirthStore {
    const STABLE_HEAP: bool = true;
    fn heap_bound(&self, c: &mut crate::heap_layout_bound::Counter) -> Option<()> {
        let mut bytes =
            std::mem::size_of_val(&*self.0).checked_add(std::mem::align_of::<Session>())?;
        for s in &self.0 {
            bytes = bytes
                .checked_add(std::mem::size_of_val(&*s.4))?
                .checked_add(std::mem::align_of::<(LocationKey, u64)>())?;
        }
        c.add(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::snapshots::{
        ScanIndex, ScanIndexEntry, SelectorCapture, SnapshotAccumulator, SnapshotSource,
        UsageTotals,
    };
    use std::collections::{BTreeMap, BTreeSet};

    fn entry() -> ScanIndexEntry {
        serde_json::from_value(serde_json::json!({"size_bytes":1,"modified_unix_seconds":1,
            "source_file_fingerprint":"birth-test"}))
        .unwrap()
    }
    fn temp(name: &str) -> std::path::PathBuf {
        static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let p = std::env::temp_dir().join(format!(
            "birth-store-{name}-{}-{}",
            std::process::id(),
            N.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&p).unwrap();
        p
    }
    #[test]
    fn physical_min_move_copy_and_equal_move() {
        let mut b = BirthStore::default();
        b.record_observation("s", "A", 100);
        b.record_observation("s", "A", 200); // inode replaced at same path
        assert_eq!(b.observed_birth("s", "A"), Some(100));
        b.record_observation("s", "B", 200);
        assert!(b.record_proven_move("s", location_key("A"), "B"));
        assert_eq!(b.effective_cutoff("s", "B"), Some(100));
        assert_eq!(b.observed_birth("s", "B"), Some(200));
        b.record_observation("s", "C", 300); // copy of live B
        assert_eq!(b.effective_cutoff("s", "C"), Some(300));
        assert_eq!(b.live_location("s"), Some(location_key("B")));
        assert!(!b.record_proven_move("s", location_key("A"), "C"));
        b.record_observation("s", "D", 100);
        assert!(b.record_proven_move("s", location_key("B"), "D"));
        assert_eq!(b.live_location("s"), Some(location_key("D")));
        assert_eq!(
            b.effective_cutoff("s", "B"),
            Some(200),
            "a live twin retains its own cutoff"
        );
    }
    #[test]
    fn equal_birth_witnesses_have_only_one_winner() {
        for (a, b) in [("A", "B"), ("B", "A")] {
            let mut births = BirthStore::default();
            births.record_observation("s", a, 100);
            births.record_observation("s", b, 100);
            let aw = births.original_witness("s", a, |_| true);
            let bw = births.original_witness("s", b, |_| true);
            assert_ne!(aw.is_some(), bw.is_some());
            assert!(births.original_witness("s", a, |_| false).is_none());
        }
    }
    #[test]
    fn retain_thirty_days_after_last_indexed_session_path() {
        let mut b = BirthStore::default();
        b.record_observation("s", "A", 100);
        b.prune(10, [("s", "B")]); // /cd keeps session alive even with a new path
        b.prune(100, std::iter::empty());
        b.prune(100 + ABSENT_RETENTION_SECONDS - 1, std::iter::empty());
        assert_eq!(b.session_effective_cutoff("s"), Some(100));
        b.prune(100 + ABSENT_RETENTION_SECONDS, std::iter::empty());
        assert!(b.is_empty());
    }
    #[test]
    fn actual_index_round_trip_restart_removed_original_subset_and_held() {
        let root = temp("round-trip");
        let file = root.join("index.json");
        let a = "/birth/projects/session.jsonl";
        let b = "/moved/projects/session.jsonl";
        let mut index = ScanIndex::default();
        index.files.insert(a.into(), entry());
        index
            .claude_money_birth_store
            .record_observation("session", a, 100);
        index.save(&file).unwrap();
        let mut loaded = ScanIndex::load(&file).unwrap();
        assert_eq!(
            loaded.claude_money_birth_store.observed_birth("session", a),
            Some(100)
        );
        loaded.files.remove(a);
        loaded.save(&file).unwrap();
        let mut loaded = ScanIndex::load(&file).unwrap();
        assert_eq!(
            loaded
                .claude_money_birth_store
                .session_effective_cutoff("session"),
            Some(100)
        );
        loaded
            .claude_money_birth_store
            .record_observation("session", b, 200);
        assert!(loaded
            .claude_money_birth_store
            .record_proven_move("session", location_key(a), b));
        loaded.files.insert(b.into(), entry());
        loaded
            .file_snapshot_fingerprints
            .insert(b.into(), BTreeSet::from(["held-body".into()]));
        let previous = ScanIndex::default();
        let subset = loaded.committable_subset(&previous, &BTreeSet::new(), &BTreeMap::new());
        assert_eq!(
            subset
                .claude_money_birth_store
                .effective_cutoff("session", b),
            Some(100)
        );
        let held = loaded.with_locally_held_keys_reverted(
            &previous,
            &BTreeSet::from(["held-body".into()]),
            &BTreeSet::new(),
        );
        assert!(
            !held.files.contains_key(b),
            "held file tuple is reverted, physical birth is kept"
        );
        assert_eq!(
            held.claude_money_birth_store.effective_cutoff("session", b),
            Some(100)
        );
        let mut held = held;
        held.save(&file).unwrap();
        let loaded = ScanIndex::load(&file).unwrap();
        assert_eq!(
            loaded.claude_money_birth_store.observed_birth("session", b),
            Some(200)
        );
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn partial_and_held_restores_preserve_previous_only_births() {
        let mut previous = ScanIndex::default();
        previous
            .claude_money_birth_store
            .record_observation("s", "A", 100);
        let scanned = ScanIndex::default();
        let partial = scanned.committable_subset(&previous, &BTreeSet::new(), &BTreeMap::new());
        assert_eq!(
            partial.claude_money_birth_store.observed_birth("s", "A"),
            Some(100)
        );
        let held =
            scanned.with_locally_held_keys_reverted(&previous, &BTreeSet::new(), &BTreeSet::new());
        assert_eq!(
            held.claude_money_birth_store.observed_birth("s", "A"),
            Some(100)
        );
    }
    #[test]
    fn old_and_malformed_optional_tables_do_not_rebuild_index() {
        let root = temp("optional");
        let file = root.join("index.json");
        let mut index = ScanIndex::default();
        index.files.insert("kept.jsonl".into(), entry());
        index.save(&file).unwrap();
        let original: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&file).unwrap()).unwrap();
        for bad in [
            None,
            Some(serde_json::json!({"wrong":"shape"})),
            Some(serde_json::json!([["bad"]])),
        ] {
            let mut wire = original.clone();
            if let Some(bad) = bad {
                wire["claude_money_birth_store"] = bad;
            } else {
                wire.as_object_mut()
                    .unwrap()
                    .remove("claude_money_birth_store");
            }
            std::fs::write(&file, serde_json::to_vec(&wire).unwrap()).unwrap();
            let loaded = ScanIndex::load(&file).unwrap();
            assert!(loaded.files.contains_key("kept.jsonl"));
            assert_eq!(loaded.generation, index.generation);
            assert!(loaded.claude_money_birth_store.is_empty());
        }
        assert!(!std::fs::read_dir(&root).unwrap().any(|e| e
            .unwrap()
            .file_name()
            .to_string_lossy()
            .contains("corrupt")));
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn m4_size_memory_and_wire_receipt() {
        let mut births = BirthStore::default();
        for i in 0..13_700 {
            births.record_observation(
                &format!("session-{}", i % 3_700),
                &format!("/slot/projects/{i}/session.jsonl"),
                1_761_400_000_000_000_000 + i as i128,
            );
        }
        let memory = births.memory_bytes();
        let compact = serde_json::to_vec(&births).unwrap().len();
        let pretty = serde_json::to_vec_pretty(&births).unwrap().len();
        println!("T1_BIRTH_SIZE files=13700 sessions=3700 memory_bytes={memory} compact_bytes={compact} pretty_bytes={pretty}");
        assert!(memory <= 1024 * 1024);
        assert!(compact <= 1_000_000);
        let restored: BirthStore =
            serde_json::from_slice(&serde_json::to_vec(&births).unwrap()).unwrap();
        assert!(restored.valid().is_some());
    }
    #[test]
    fn placement_equals_native_effort_billing_speed_and_fallback() {
        use crate::snapshots::claude_row_placement;
        for effort in [None, Some("high")] {
            for missing_time in [false, true] {
                for missing_model in [false, true] {
                    let mut native = SnapshotAccumulator::new(SnapshotSource::ClaudeCode);
                    native.latest_model = Some("fallback-model".into());
                    native.last_activity_at = Some("2026-10-25T12:34:56Z".into());
                    let mut base = SelectorCapture::default();
                    base.context
                        .insert("billing_provider".into(), "anthropic".into());
                    native.current_selector = base.clone();
                    let mut selector = SelectorCapture::default();
                    selector.context.insert("speed_mode".into(), "fast".into());
                    selector
                        .context
                        .insert("billing_channel".into(), "subscription".into());
                    let model = (!missing_model).then(|| "claude-sonnet-4-5".to_owned());
                    let timestamp = (!missing_time).then_some("2026-10-25T11:59:59Z");
                    let fallback = native.fallback_bucket_timestamp(None);
                    let expected = claude_row_placement(
                        model.as_deref().unwrap_or("fallback-model"),
                        &base,
                        selector.clone(),
                        effort,
                        timestamp,
                        fallback.as_deref(),
                    )
                    .unwrap();
                    native.add_usage_with_selector(
                        model,
                        UsageTotals {
                            input_tokens: 10,
                            request_count: 1,
                            ..Default::default()
                        },
                        selector,
                        timestamp,
                        effort.map(str::to_owned),
                    );
                    let bucket = &native.usage_buckets[&expected.bucket];
                    assert_eq!(bucket.rows.len(), 1);
                    let row = &bucket.rows[&expected.row_key];
                    assert_eq!(row.selector_context, expected.reduced_context);
                    assert_eq!(row.selector_sources, expected.reduced_sources);
                }
            }
        }
        assert!(claude_row_placement(
            "unknown",
            &SelectorCapture::default(),
            SelectorCapture::default(),
            None,
            None,
            None
        )
        .is_none());
    }
    #[test]
    fn cap_alarm_physical_record_boundaries() {
        use crate::local_resource_diagnostics::take_claude_record_caps_for_test as take;
        for (records, half, hits) in [
            (32_767, 0, 0),
            (32_768, 1, 0),
            (65_536, 1, 0),
            (65_537, 1, 1),
        ] {
            take();
            let mut a = SnapshotAccumulator::new(SnapshotSource::ClaudeCode);
            // Distinct physical records, deliberately the same response id until
            // its per-response cap, then another id: count is not resolved rows.
            for i in 0..records {
                a.observe_claude_response(
                    &serde_json::json!({"message":{"id":format!("m{}", i / 4_096)}}),
                    UsageTotals {
                        input_tokens: 10,
                        request_count: 1,
                        ..Default::default()
                    },
                    Some("claude-sonnet-4-5".into()),
                    SelectorCapture::default(),
                    Some("2026-10-25T12:00:00Z".into()),
                    None,
                    None,
                );
            }
            a.finalize_claude_responses();
            assert_eq!(take(), (half, hits), "physical records={records}");
        }
    }
}
