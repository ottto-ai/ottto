//! O3's negative release/key reservation in the legacy replay wire slot.
//! This never carries ACKs, money authority, ordinary reread budgets or pace.
use super::*;

const MAX_KEYS: usize = 256;
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct KeyHash([u8; 16]);
impl KeyHash {
    fn of(key: &str) -> Self {
        Self(
            Sha256::digest(key.as_bytes())[..16]
                .try_into()
                .expect("digest prefix"),
        )
    }
}
impl Serialize for KeyHash {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        serializer.collect_str(&format_args!("{:032x}", u128::from_be_bytes(self.0)))
    }
}
impl<'de> Deserialize<'de> for KeyHash {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        let key = String::deserialize(deserializer)?;
        if key.len() != 32
            || !key
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
            return Err(serde::de::Error::custom("invalid upgrade replay digest"));
        }
        u128::from_str_radix(&key, 16)
            .map(|n| Self(n.to_be_bytes()))
            .map_err(serde::de::Error::custom)
    }
}
impl crate::heap_layout_bound::HeapLayoutBound for KeyHash {
    const STABLE_HEAP: bool = true;
    fn heap_bound(&self, _: &mut crate::heap_layout_bound::Counter) -> Option<()> {
        Some(())
    }
}
#[derive(Debug, Default, Serialize)]
pub(super) struct State {
    replayed: BTreeMap<String, BTreeSet<KeyHash>>,
    closed: bool,
    // A ticket is usable only in the process that saved the negative spend.
    #[serde(skip)]
    reservations: BTreeMap<KeyHash, (bool, bool)>, // saved, claimed
}
crate::heap_layout_bound::fields!(State; replayed, closed, reservations);
// An index copy carries only negative evidence, never a live permission.
impl Clone for State {
    fn clone(&self) -> Self {
        Self {
            replayed: self.replayed.clone(),
            closed: self.closed,
            reservations: BTreeMap::new(),
        }
    }
}

fn unique_spends<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<BTreeMap<String, BTreeSet<KeyHash>>, D::Error> {
    struct Unique;
    impl<'de> serde::de::Visitor<'de> for Unique {
        type Value = BTreeMap<String, BTreeSet<KeyHash>>;
        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("unique release keys")
        }
        fn visit_map<A: serde::de::MapAccess<'de>>(
            self,
            mut map: A,
        ) -> std::result::Result<Self::Value, A::Error> {
            let mut spends = BTreeMap::new();
            while let Some((key, value)) = map.next_entry::<String, BTreeSet<KeyHash>>()? {
                if spends.insert(key, value).is_some() {
                    return Err(serde::de::Error::custom("duplicate O3 release key"));
                }
            }
            Ok(spends)
        }
    }
    deserializer.deserialize_map(Unique)
}

impl<'de> Deserialize<'de> for State {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        #[derive(Default, Deserialize)]
        #[serde(default)]
        struct Wire {
            #[serde(deserialize_with = "unique_spends")]
            replayed: BTreeMap<String, BTreeSet<KeyHash>>,
            closed: bool,
        }
        // Preserve duplicate members until the typed decoder can reject them;
        // a Value would silently keep the last member and erase negative proof.
        let raw = Box::<serde_json::value::RawValue>::deserialize(deserializer)?;
        if !restart_restore::enabled() {
            return Ok(Self::default());
        }
        // Old malformed diagnostic state must not poison the whole index.
        // It may only refuse O3 authority; the paced fallback remains usable.
        let Ok(mut wire) = serde_json::from_str::<Wire>(raw.get()) else {
            return Ok(Self {
                closed: true,
                ..Self::default()
            });
        };
        wire.replayed
            .retain(|release, _| *release == Self::release());
        let overflow = wire.replayed.values().any(|keys| keys.len() > MAX_KEYS);
        for keys in wire.replayed.values_mut() {
            while keys.len() > MAX_KEYS {
                keys.pop_last();
            }
        }
        Ok(Self {
            replayed: wire.replayed,
            closed: wire.closed || overflow,
            reservations: BTreeMap::new(),
        })
    }
}
impl State {
    fn release() -> String {
        format!(
            "upgrade_state_missing:{}",
            ottto_core::compiled_release_version()
        )
    }
    pub(super) fn refused() -> Self {
        Self {
            closed: true,
            ..Self::default()
        }
    }
    /// Copies carry only negative evidence. Union both checkpoint lineages so
    /// a partial/error settlement cannot mint a previously spent A5 grant.
    pub(super) fn preserve_spends_from(&mut self, other: &Self) {
        self.closed |= other.closed;
        for (release, keys) in &other.replayed {
            let spent = self.replayed.entry(release.clone()).or_default();
            for key in keys {
                if spent.contains(key) {
                    continue;
                }
                if spent.len() >= MAX_KEYS {
                    self.closed = true;
                    break;
                }
                spent.insert(*key);
            }
        }
    }
    pub(super) fn is_empty(&self) -> bool {
        !restart_restore::enabled() || (!self.closed && self.replayed.is_empty())
    }
    pub(super) fn upgrade_missing(&mut self, key: &str, consume: bool) -> bool {
        if self.closed {
            return false;
        }
        let id = KeyHash::of(key);
        if let Some((saved, claimed)) = self.reservations.get_mut(&id) {
            if *saved && !*claimed {
                *claimed = consume;
                return true;
            }
            return false;
        }
        let spent = self.replayed.entry(Self::release()).or_default();
        if spent.contains(&id) || spent.len() >= MAX_KEYS {
            return false;
        }
        spent.insert(id);
        self.reservations.insert(id, (false, false));
        false
    }
    pub(super) fn needs_save(&self) -> bool {
        self.reservations.values().any(|(saved, _)| !saved)
    }
    pub(super) fn upgrade_claimed(&self, key: &str) -> bool {
        !self.closed
            && self
                .reservations
                .get(&KeyHash::of(key))
                .is_some_and(|r| *r == (true, true))
    }
    fn saved(&mut self) {
        for (saved, _) in self.reservations.values_mut() {
            *saved = true;
        }
    }
}
impl OwnedSourceScan {
    /// Save only the negative O3 spend on the committed index. Working file
    /// state, ACKs, census and traversal never cross this pre-read boundary.
    pub(crate) fn persist_upgrade_reservations(
        &mut self,
        committed: &mut ScanIndex,
        path: &Path,
    ) -> Result<()> {
        if !super::restart_restore::enabled() || !self.index.o3_replay.needs_save() {
            return Ok(());
        }
        let previous = std::mem::replace(&mut committed.o3_replay, self.index.o3_replay.clone());
        if let Err(error) = committed.save(path) {
            committed.o3_replay = previous;
            return Err(error);
        }
        self.index.adopt_committed_save(committed);
        self.index.o3_replay.saved();
        committed.o3_replay.saved();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    /// [format] saved upgrade spend survives restart and index copy without grant.
    #[test]
    fn saved_upgrade_spend_survives_restart_and_index_copy_without_grant() {
        let _restart_restore = super::super::restart_restore::RestartRestoreForTest::enabled();
        let root = crate::test_scratch::private_dir("o3-negative-reservation");
        let path = root.join("index.json");
        let mut index = ScanIndex::default();
        assert!(!index.o3_replay.upgrade_missing("file", true));
        assert!(index.o3_replay.needs_save());
        index.save(&path).unwrap();
        index.o3_replay.saved();
        let mut copied = index.clone();
        assert!(!copied.o3_replay.upgrade_missing("file", true));
        let mut restarted = ScanIndex::load(&path).unwrap();
        assert!(!restarted.o3_replay.upgrade_missing("file", true));
        let encoded = std::fs::read(&path).unwrap();
        let mut native = claude_request_census::decode_index(encoded.as_slice()).unwrap();
        assert!(!native.o3_replay.upgrade_missing("file", true));
        let mut bounded = lenient_decode::read_bounded(&encoded).unwrap();
        assert!(!bounded.o3_replay.upgrade_missing("file", true));
        assert!(index.o3_replay.upgrade_missing("file", true));
        assert!(
            !index.o3_replay.upgrade_missing("file", true),
            "one live claim only"
        );
        let _ = std::fs::remove_dir_all(root);
    }
    /// A production-shaped path has a storage root, unlike `index.json`: a
    /// reservation saved on the committed copy moves it, and the same cycle's
    /// working save must still commit.
    #[cfg(unix)]
    /// [format] reservation save moves the working baseline on a bound path.
    #[test]
    fn reservation_save_moves_the_working_baseline_on_a_bound_path() {
        use std::os::unix::fs::PermissionsExt;
        let root = crate::test_scratch::private_dir("o3-bound-baseline");
        let namespace = root.join("a".repeat(64));
        std::fs::create_dir(&namespace).unwrap();
        std::fs::set_permissions(&namespace, std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = namespace.join("claude_code-scan-index-v3.json");
        let mut committed = ScanIndex::default();
        committed.save(&path).unwrap();
        assert!(committed.persistence_root.is_some(), "bound path premise");
        let mut scan = OwnedSourceScan::new_with_identity_capture(
            SnapshotSource::ClaudeCode,
            &[],
            committed.clone(),
            "2026-10-29T12:00:00Z",
            365,
            100,
            false,
            None,
            &[],
            false,
            true,
            true,
        );
        assert!(!scan.index.o3_replay.upgrade_missing("file", true));
        scan.persist_upgrade_reservations(&mut committed, &path)
            .unwrap();
        assert_eq!(scan.index.generation, committed.generation);
        scan.index
            .save(&path)
            .expect("the working save follows the reservation's publication");
        assert_eq!(scan.index.generation, committed.generation + 1);
        assert_eq!(
            ScanIndex::load(&path).unwrap().generation,
            scan.index.generation
        );
        let _ = std::fs::remove_dir_all(root);
    }

    /// [format] partial checkpoint unions negative spends without live permissions.
    #[test]
    fn partial_checkpoint_unions_negative_spends_without_live_permissions() {
        let mut committed = ScanIndex::default();
        assert!(!committed.o3_replay.upgrade_missing("old", true));
        committed.o3_replay.saved();
        assert!(committed.o3_replay.upgrade_missing("old", true));
        let mut working = ScanIndex::default();
        assert!(!working.o3_replay.upgrade_missing("new", true));
        working.o3_replay.saved();
        let mut partial = working.committable_subset_with_local_holds(
            &committed,
            &BTreeSet::new(),
            &BTreeMap::new(),
            &BTreeSet::from(["held".to_owned()]),
        );
        assert!(!partial.o3_replay.upgrade_missing("old", true));
        assert!(!partial.o3_replay.upgrade_missing("new", true));
        let encoded = serde_json::to_vec(&partial).unwrap();
        let mut restarted = lenient_decode::read_bounded(&encoded).unwrap();
        assert!(!restarted.o3_replay.upgrade_missing("old", true));
        assert!(!restarted.o3_replay.upgrade_missing("new", true));
        assert!(
            working.o3_replay.upgrade_missing("new", true),
            "original process owns its saved ticket"
        );
    }
}
