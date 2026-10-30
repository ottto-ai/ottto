//! Keep one owned request hash per occurrence, without changing the wire shape.
use super::*;
use serde::ser::SerializeMap;

#[derive(Clone, Copy)]
pub(super) struct Membership<'a>(&'a ClaudeUsageFamilyPending);

#[derive(Clone, Copy)]
pub(super) struct Hashes<'a> {
    explicit: Option<&'a BTreeSet<String>>,
    occurrences: Option<&'a BTreeMap<String, ClaudeTranscriptUsageOccurrenceWitness>>,
}

impl<'a> Hashes<'a> {
    pub(super) fn iter(self) -> impl Iterator<Item = &'a String> + Clone {
        self.explicit
            .into_iter()
            .flatten()
            .chain(self.occurrences.into_iter().flat_map(BTreeMap::keys))
    }
    pub(super) fn len(self) -> usize {
        self.explicit.map_or(0, BTreeSet::len) + self.occurrences.map_or(0, BTreeMap::len)
    }
    #[cfg(test)]
    pub(super) fn is_empty(self) -> bool {
        self.len() == 0
    }
    pub(super) fn contains(self, hash: &String) -> bool {
        self.explicit.is_some_and(|set| set.contains(hash))
            || self.occurrences.is_some_and(|map| map.contains_key(hash))
    }
    pub(super) fn is_disjoint(self, other: &BTreeSet<String>) -> bool {
        self.iter().all(|hash| !other.contains(hash))
    }
}

impl Serialize for Hashes<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_seq(self.iter())
    }
}

impl<'a> Membership<'a> {
    pub(super) fn keys(self) -> impl Iterator<Item = &'a String> + Clone {
        self.0.member_request_id_hashes.keys()
    }
    pub(super) fn get(self, member: &str) -> Option<Hashes<'a>> {
        let explicit = self.0.member_request_id_hashes.get(member)?;
        let occurrences = (explicit.is_empty() && self.0.derived_request_members.contains(member))
            .then(|| self.0.member_occurrences.get(member))
            .flatten();
        Some(Hashes {
            explicit: occurrences.is_none().then_some(explicit),
            occurrences,
        })
    }
    pub(super) fn contains_key(self, member: &str) -> bool {
        self.get(member).is_some()
    }
    pub(super) fn is_empty(self) -> bool {
        self.0.member_request_id_hashes.is_empty()
    }
    pub(super) fn iter(self) -> impl Iterator<Item = (&'a String, Hashes<'a>)> {
        self.keys()
            .map(move |member| (member, self.get(member).expect("membership key")))
    }
    pub(super) fn values(self) -> impl Iterator<Item = Hashes<'a>> {
        self.iter().map(|(_, hashes)| hashes)
    }
}

impl Serialize for Membership<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(self.0.member_request_id_hashes.len()))?;
        for (member, hashes) in self.iter() {
            map.serialize_entry(member, &hashes)?;
        }
        map.end()
    }
}

impl ClaudeUsageFamilyPending {
    pub(super) fn membership(&self) -> Membership<'_> {
        Membership(self)
    }
    fn deduplicate_membership(&mut self) {
        for (member, hashes) in &mut self.member_request_id_hashes {
            if self.derived_request_members.contains(member) {
                continue;
            }
            if self
                .member_occurrences
                .get(member)
                .is_some_and(|occurrences| hashes.iter().eq(occurrences.keys()))
            {
                hashes.clear();
                self.derived_request_members.insert(member.clone());
            }
        }
    }
}

impl PartialEq for ClaudeUsageFamilyPending {
    fn eq(&self, other: &Self) -> bool {
        self.census_window_end == other.census_window_end
            && self.invalid == other.invalid
            && self.idless_revision == other.idless_revision
            && self.member_occurrences == other.member_occurrences
            && self
                .membership()
                .iter()
                .map(|(m, h)| (m, h.iter()))
                .zip(other.membership().iter().map(|(m, h)| (m, h.iter())))
                .all(|((a, ah), (b, bh))| a == b && ah.eq(bh))
            && self.member_request_id_hashes.len() == other.member_request_id_hashes.len()
    }
}
impl Eq for ClaudeUsageFamilyPending {}

impl Serialize for ClaudeUsageFamilyPending {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct(
            "ClaudeUsageFamilyPending",
            3 + usize::from(!self.member_occurrences.is_empty())
                + usize::from(self.idless_revision.is_some()),
        )?;
        state.serialize_field("census_window_end", &self.census_window_end)?;
        state.serialize_field("member_request_id_hashes", &self.membership())?;
        if !self.member_occurrences.is_empty() {
            state.serialize_field("member_occurrences", &self.member_occurrences)?;
        }
        state.serialize_field("invalid", &self.invalid)?;
        if let Some(revision) = self.idless_revision {
            state.serialize_field("idless_revision", &revision)?;
        }
        state.end()
    }
}

impl<'de> Deserialize<'de> for ClaudeUsageFamilyPending {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire = ClaudeUsageFamilyPendingWire::deserialize(deserializer)?;
        let mut pending = Self {
            census_window_end: wire.census_window_end,
            member_request_id_hashes: wire.member_request_id_hashes,
            member_occurrences: wire.member_occurrences,
            invalid: wire.invalid,
            idless_revision: wire.idless_revision,
            derived_request_members: BTreeSet::new(),
        };
        pending.deduplicate_membership();
        Ok(pending)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wire() -> Value {
        json!({"census_window_end":"window", "member_request_id_hashes":{"root":["hash"], "empty":[], "key-only":["kept"], "different":["other"]},
            "member_occurrences":{"root":{"hash":{"sequence":3,"input_tokens":11,"output_tokens":7,"cache_read_tokens":2,"cache_creation_5m_tokens":1,"cache_creation_1h_tokens":4,"reasoning_output_tokens":5,"model":"model","speed_mode":null,"reasoning_effort":null}}, "empty":{}, "different":{}, "occurrence-only":{}}, "invalid":false})
    }

    #[test]
    fn membership_is_derived_only_for_equal_present_sets_and_wire_is_unchanged() {
        let original = wire();
        let mut pending: ClaudeUsageFamilyPending =
            serde_json::from_value(original.clone()).unwrap();
        assert_eq!(
            pending.derived_request_members,
            BTreeSet::from(["empty".into(), "root".into()])
        );
        assert!(pending.member_request_id_hashes["root"].is_empty());
        assert_eq!(
            pending
                .membership()
                .get("root")
                .unwrap()
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            ["hash"]
        );
        assert!(!pending.membership().contains_key("occurrence-only"));
        assert_eq!(
            pending.member_request_id_hashes["key-only"],
            BTreeSet::from(["kept".into()])
        );
        assert_eq!(
            pending.member_request_id_hashes["different"],
            BTreeSet::from(["other".into()])
        );
        for _ in 0..2 {
            assert_eq!(serde_json::to_value(&pending).unwrap(), original);
            let bytes = serde_json::to_vec(&pending).unwrap();
            let restored: ClaudeUsageFamilyPending = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(restored, pending);
            pending = restored;
        }
    }

    #[test]
    fn old_positional_pending_preserves_members_occurrences_and_nondefault_neighbors() {
        let value = wire();
        let array = json!([
            value["census_window_end"],
            value["member_request_id_hashes"],
            value["member_occurrences"],
            true,
            vec![7; 32]
        ]);
        let pending: ClaudeUsageFamilyPending = serde_json::from_value(array).unwrap();
        assert!(pending.invalid);
        assert_eq!(pending.idless_revision, Some([7; 32]));
        assert_eq!(
            serde_json::to_value(pending.membership()).unwrap(),
            value["member_request_id_hashes"]
        );
        assert_eq!(
            serde_json::to_value(&pending.member_occurrences).unwrap(),
            value["member_occurrences"]
        );
    }
}
