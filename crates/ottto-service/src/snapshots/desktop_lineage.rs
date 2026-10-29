//! Durable selection projection. Live census/resolver evidence alone emits facts.
use super::*;
use serde::de::{MapAccess, Visitor};

pub(super) const MAX_EDGES: usize = 4096;
pub(super) const MAX_DECODE_BYTES: u64 = 1024 * 1024;

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

// Compact JSON upper bound, including escaped path keys, before insert/clone.
fn file_edges_bytes(edges: &BTreeMap<String, String>) -> usize {
    2 + edges
        .keys()
        .map(|key| {
            key.bytes()
                .map(|b| match b {
                    b'"' | b'\\' => 2,
                    0..=31 => 6,
                    _ => 1,
                })
                .sum::<usize>()
                + 70
        })
        .sum::<usize>()
}
fn insert_file_edge(edges: &mut BTreeMap<String, String>, key: &str, edge: &str) {
    if (!edges.contains_key(key) && edges.len() >= MAX_EDGES) || key.len() > 8192 {
        dropped();
        return;
    }
    // Updating an existing hash cannot increase its JSON length.
    if !edges.contains_key(key) {
        let mut extra = BTreeMap::new();
        extra.insert(key.to_owned(), edge.to_owned());
        if file_edges_bytes(edges).saturating_add(file_edges_bytes(&extra))
            > MAX_DECODE_BYTES as usize
        {
            dropped();
            return;
        }
    }
    edges.insert(key.to_owned(), edge.to_owned());
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
        insert_file_edge(&mut self.claude_desktop_lineage_file_edges, key, &edge);
    }
}

pub(super) fn committable_file_edges(
    working: &ScanIndex,
    previous: &ScanIndex,
    safe: &BTreeSet<String>,
) -> BTreeMap<String, String> {
    let mut edges = previous.claude_desktop_lineage_file_edges.clone();
    for (key, edge) in &working.claude_desktop_lineage_file_edges {
        if safe.contains(key) {
            insert_file_edge(&mut edges, key, edge);
        }
    }
    edges
}
