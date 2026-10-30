//! Durable selection projection. Live census/resolver evidence alone emits facts.
use super::*;
use serde::de::{MapAccess, Visitor};

pub(super) const MAX_EDGES: usize = 4096;
pub(super) const MAX_DECODE_BYTES: u64 = 1024 * 1024;
/// One raw decode allowance shared by the two file-keyed selector maps.
/// Refusal drops optional selection history only; file custody is independent.
#[derive(Default)]
pub(super) struct SelectorDecodeAllowance(u64);
impl SelectorDecodeAllowance {
    pub(super) fn remaining(&self) -> u64 {
        MAX_DECODE_BYTES.saturating_sub(self.0)
    }
    pub(super) fn admit(&mut self, bytes: u64) -> bool {
        let admitted = bytes <= self.remaining();
        self.0 = self.0.saturating_add(bytes);
        admitted
    }
}
// Each canonical UUID pair occupies 78 bytes including its comma. The final
// comma is replaced by the closing brace; this maximum always fits our reader.
pub(super) const MAX_PROJECTION_JSON_BYTES: usize = MAX_EDGES * 78 + 1;
const _: () = assert!(MAX_PROJECTION_JSON_BYTES as u64 <= MAX_DECODE_BYTES);

#[derive(Default, Deserialize)]
pub(super) struct Projection(
    #[serde(deserialize_with = "deserialize_projection")]
    pub(super)  Option<BTreeMap<String, String>>,
);
#[derive(Default, Deserialize)]
pub(super) struct FileEdges(
    #[serde(deserialize_with = "deserialize_file_edges")] pub(super) BTreeMap<String, String>,
);

pub(super) fn deserialize_projection<'de, D>(
    deserializer: D,
) -> std::result::Result<Option<BTreeMap<String, String>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct Projection;
    impl<'de> Visitor<'de> for Projection {
        type Value = Option<BTreeMap<String, String>>;
        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("a bounded canonical Desktop edge projection or null")
        }
        fn visit_none<E: serde::de::Error>(self) -> std::result::Result<Self::Value, E> {
            Ok(None)
        }
        fn visit_unit<E: serde::de::Error>(self) -> std::result::Result<Self::Value, E> {
            Ok(None)
        }
        fn visit_some<D: serde::Deserializer<'de>>(
            self,
            d: D,
        ) -> std::result::Result<Self::Value, D::Error> {
            d.deserialize_map(self)
        }
        fn visit_map<A: MapAccess<'de>>(
            self,
            mut a: A,
        ) -> std::result::Result<Self::Value, A::Error> {
            let mut edges = BTreeMap::new();
            while let Some((child, parent)) = a.next_entry::<String, String>()? {
                if edges.len() >= MAX_EDGES
                    || !canonical(&child)
                    || !canonical(&parent)
                    || child == parent
                    || edges.insert(child, parent).is_some()
                {
                    return Err(serde::de::Error::custom(
                        "invalid Desktop selector projection",
                    ));
                }
            }
            Ok(Some(edges))
        }
    }
    deserializer.deserialize_option(Projection)
}

pub(super) fn deserialize_file_edges<'de, D>(
    d: D,
) -> std::result::Result<BTreeMap<String, String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct FileEdges;
    impl<'de> Visitor<'de> for FileEdges {
        type Value = BTreeMap<String, String>;
        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("bounded hash-only file selection baselines")
        }
        fn visit_map<A: MapAccess<'de>>(
            self,
            mut a: A,
        ) -> std::result::Result<Self::Value, A::Error> {
            let mut edges = BTreeMap::new();
            while let Some((key, edge)) = a.next_entry::<String, String>()? {
                if edges.len() >= MAX_EDGES
                    || key.len() > 8192
                    || !is_sha256_hex(&edge)
                    || edges.insert(key, edge).is_some()
                {
                    return Err(serde::de::Error::custom(
                        "invalid Desktop file selector baseline",
                    ));
                }
            }
            Ok(edges)
        }
    }
    d.deserialize_map(FileEdges)
}

fn canonical(id: &str) -> bool {
    id.len() == 36 && crate::claude_local_otel::canonical_uuid(id).as_deref() == Some(id)
}
fn is_sha256_hex(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
pub(super) fn edge_fingerprint(parent: Option<&str>) -> String {
    sha256_hex(&["desktop_selector_edge:v1", parent.unwrap_or("")])
}
pub(super) fn dropped() {
    crate::local_resource_diagnostics::claude_reread::desktop_lineage_selector_drop();
}

impl ClaudeTitleMetadata {
    pub(super) fn install_completed_lineage(&mut self, index: &mut ScanIndex) {
        if !index.claude_desktop_lineage_census_complete || self.sidecar_census_incomplete {
            return;
        }
        if self.spawn_lineage.len() > MAX_EDGES {
            // Never publish a truncated complete graph. Oversized is unknown.
            self.completed_lineage = None;
            index.claude_desktop_completed_lineage = None;
            dropped();
            return;
        }
        let edges: BTreeMap<_, _> = self
            .spawn_lineage
            .iter()
            .map(|(child, edge)| (child.clone(), edge.parent_session_id.clone()))
            .collect();
        self.completed_lineage = Some(edges.clone());
        index.claude_desktop_completed_lineage = Some(edges);
    }
}

// Shared custody for the root selector maps keyed by the local file index key
// (lineage edge baselines and identity latches): the same record cap, key bound
// and ONE joint decode-span byte budget, counted refusal and no eviction.
pub(super) const EDGE_RECORD_BYTES: usize = 70;

// Compact JSON upper bound, including escaped path keys, before insert/clone.
// `record` covers quotes, colon, the widest fixed value and comma.
// The root serializer keeps each map compact even in held/pretty output.
pub(super) fn selector_bytes<V>(map: &BTreeMap<String, V>, record: usize) -> usize {
    2 + map
        .keys()
        .map(|key| escaped_len(key) + record)
        .sum::<usize>()
}
fn escaped_len(key: &str) -> usize {
    key.bytes()
        .map(|b| match b {
            b'"' | b'\\' => 2,
            0..=31 => 6,
            _ => 1,
        })
        .sum()
}
/// `others` is the compact size of the sibling selector map.
pub(super) fn insert_selector<V>(
    map: &mut BTreeMap<String, V>,
    record: usize,
    others: usize,
    key: &str,
    value: V,
) {
    if (!map.contains_key(key) && map.len() >= MAX_EDGES) || key.len() > 8192 {
        dropped();
        return;
    }
    // Updating an existing fixed-width record cannot increase its JSON length.
    if !map.contains_key(key)
        && selector_bytes(map, record)
            .saturating_add(2 + escaped_len(key) + record)
            .saturating_add(others)
            > MAX_DECODE_BYTES as usize
    {
        dropped();
        return;
    }
    map.insert(key.to_owned(), value);
}
/// Whether a NEW key could be admitted now; callers never select work whose
/// settlement the budget would refuse (no revisit loop at the cap).
pub(super) fn selector_admits<V>(
    map: &BTreeMap<String, V>,
    record: usize,
    others: usize,
    key: &str,
) -> bool {
    map.contains_key(key)
        || (map.len() < MAX_EDGES
            && key.len() <= 8192
            && selector_bytes(map, record)
                .saturating_add(2 + escaped_len(key) + record)
                .saturating_add(others)
                <= MAX_DECODE_BYTES as usize)
}
/// The committed map: the previous value plus only safe (ACK-settled) keys.
pub(super) fn committable_selector<V: Clone>(
    working: &BTreeMap<String, V>,
    previous: &BTreeMap<String, V>,
    safe: &BTreeSet<String>,
    record: usize,
    others: usize,
) -> BTreeMap<String, V> {
    let mut map = previous.clone();
    for (key, value) in working {
        if safe.contains(key) {
            insert_selector(&mut map, record, others, key, value.clone());
        }
    }
    map
}

impl ScanIndex {
    /// Known file baselines survive bounded pages and a root projection saved
    /// before this file is reached. None/absent is unknown, never no-edge proof.
    pub(super) fn desktop_lineage_edge_changed(&self, candidate: &CandidateFile) -> bool {
        if !self.claude_desktop_lineage_census_complete
            || claude_subagent_identity(&candidate.path).is_some()
        {
            return false;
        }
        let Some(edges) = self.claude_desktop_completed_lineage.as_ref() else {
            return false;
        };
        let Some(session) = candidate.path.file_stem().and_then(|v| v.to_str()) else {
            return false;
        };
        let key = local_index_key(&candidate.path);
        let Some(entry) = self.files.get(&key) else {
            return false;
        };
        let parent = edges.get(session).map(String::as_str);
        match self.claude_desktop_lineage_file_edges.get(&key) {
            Some(prior) => *prior != edge_fingerprint(parent),
            // Legacy upgrade visits are selected by the session's v2 metadata
            // hash. Do not force a loop if an old save/cap lost the baseline.
            None => {
                parent.is_some()
                    && entry.source_file_fingerprint != candidate.source_file_fingerprint
            }
        }
    }
    pub(super) fn record_desktop_lineage_file_edge(&mut self, key: &str, edge: String) {
        self.claude_desktop_lineage_file_edges
            .retain(|key, _| self.files.contains_key(key));
        let others = desktop_identity::latch_bytes(&self.claude_desktop_identity_latches);
        insert_selector(
            &mut self.claude_desktop_lineage_file_edges,
            EDGE_RECORD_BYTES,
            others,
            key,
            edge,
        );
    }
}

pub(super) fn committable_file_edges(
    working: &ScanIndex,
    previous: &ScanIndex,
    safe: &BTreeSet<String>,
) -> BTreeMap<String, String> {
    committable_selector(
        &working.claude_desktop_lineage_file_edges,
        &previous.claude_desktop_lineage_file_edges,
        safe,
        EDGE_RECORD_BYTES,
        desktop_identity::latch_bytes(&previous.claude_desktop_identity_latches),
    )
}
