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
#[derive(Clone, Debug, Default, Serialize)]
pub(super) struct State {
    replayed: BTreeMap<String, BTreeSet<KeyHash>>,
    closed: bool,
    // A ticket is usable only in the process that saved the negative spend.
    #[serde(skip)]
    reservations: BTreeMap<KeyHash, (bool, bool)>, // saved, claimed
}
crate::heap_layout_bound::fields!(State; replayed, closed, reservations);
impl<'de> Deserialize<'de> for State {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        #[derive(Default, Deserialize)]
        #[serde(default)]
        struct Wire {
            replayed: BTreeMap<String, BTreeSet<KeyHash>>,
            closed: bool,
        }
        let value = serde_json::Value::deserialize(deserializer)?;
        // Old malformed diagnostic state must not poison the whole index.
        // It may only refuse O3 authority; the paced fallback remains usable.
        let Ok(mut wire) = serde_json::from_value::<Wire>(value) else {
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
    pub(super) fn is_empty(&self) -> bool {
        !self.closed && self.replayed.is_empty()
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
        if !self.index.o3_replay.needs_save() {
            return Ok(());
        }
        let previous = std::mem::replace(&mut committed.o3_replay, self.index.o3_replay.clone());
        if let Err(error) = committed.save(path) {
            committed.o3_replay = previous;
            return Err(error);
        }
        self.index.generation = committed.generation;
        self.index.o3_replay.saved();
        committed.o3_replay.saved();
        Ok(())
    }
}
