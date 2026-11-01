//! Small, resumable compaction history for the incremental composition reader.

use super::{paired_claude_legacy_compactions, ClaudeCompactionKind, ClaudeCompactionObservation};
use serde::{Deserialize, Serialize};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

// Provider identifiers are short. Malformed fields must not turn a bounded
// marker count into unbounded checkpoint or pairing allocations.
const MAX_FIELD_BYTES: usize = 128;

fn bounded_id(value: Option<&str>) -> Option<&str> {
    value.filter(|value| value.len() <= MAX_FIELD_BYTES)
}

fn bounded_timestamp(value: Option<&str>) -> Option<String> {
    bounded_id(value)
        .filter(|value| OffsetDateTime::parse(value, &Rfc3339).is_ok())
        .map(str::to_string)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Marker {
    boundary: bool,
    timestamp: Option<String>,
    key: Option<u64>,
    parent: bool,
}

impl Marker {
    fn observation(&self) -> ClaudeCompactionObservation {
        ClaudeCompactionObservation {
            kind: if self.boundary {
                ClaudeCompactionKind::CurrentBoundary
            } else {
                ClaudeCompactionKind::LegacySummary
            },
            timestamp: self.timestamp.clone(),
            pre_tokens: None,
            post_tokens: None,
            cumulative_dropped_tokens: None,
            duration_ms: None,
            response_count_before: 0,
            pair_key: self.key,
            has_parent_link: self.parent,
            trigger: None,
            id_less_before: false,
            id_less_after: false,
        }
    }
}

/// Only markers and the current attachment-chain tip survive a checkpoint.
/// Ordinary records, including large tool outputs, are never retained here.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub(crate) struct CompositionCompactions {
    markers: Vec<Marker>,
    tip: Option<(u64, String)>,
    next_key: u64,
}

impl CompositionCompactions {
    /// True only for the first record of a compaction. Pair selection uses
    /// the snapshot helper, including its parent-link precedence and greedy
    /// timestamp fallback. The normal provider order is boundary then summary;
    /// a parentless summary arriving first also consumes just one boundary.
    pub(crate) fn observe(
        &mut self,
        kind: &str,
        subtype: Option<&str>,
        summary: bool,
        uuid: Option<&str>,
        parent: Option<&str>,
        timestamp: Option<&str>,
    ) -> bool {
        let uuid = bounded_id(uuid);
        let parent_id = bounded_id(parent);
        let extends = self
            .tip
            .as_ref()
            .is_some_and(|(_, tip)| parent_id == Some(tip));
        if extends && kind == "attachment" {
            self.tip = self
                .tip
                .take()
                .and_then(|(key, _)| Some((key, uuid?.to_string())));
        }
        let boundary = kind == "system" && subtype == Some("compact_boundary");
        let legacy = kind == "user" && summary;
        if !boundary && !legacy {
            return false;
        }
        let key = if boundary {
            let key = self.next_key;
            self.next_key = self.next_key.wrapping_add(1);
            self.tip = uuid.map(|id| (key, id.to_string()));
            Some(key)
        } else if extends {
            self.tip.take().map(|(key, _)| key)
        } else {
            None
        };
        // Bound checkpoint history while keeping the active chain's boundary.
        if self.markers.len() >= 64 {
            let protected = self.tip.as_ref().map(|(key, _)| *key).or(key);
            if let Some(index) = self
                .markers
                .iter()
                .position(|m| !m.boundary || m.key != protected)
            {
                self.markers.remove(index);
            }
        }
        let before: Vec<_> = self.markers.iter().map(Marker::observation).collect();
        let prior_pairs = paired_claude_legacy_compactions(&before);
        self.markers.push(Marker {
            boundary,
            timestamp: bounded_timestamp(timestamp),
            key,
            parent: parent.is_some(),
        });
        let after: Vec<_> = self.markers.iter().map(Marker::observation).collect();
        let pairs = paired_claude_legacy_compactions(&after);
        if legacy {
            !pairs.contains(&(after.len() - 1))
        } else {
            // A boundary paired with a previously counted, parentless summary.
            pairs.difference(&prior_pairs).next().is_none()
        }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.markers.is_empty() && self.tip.is_none()
    }

    pub(crate) fn accounted_bytes(&self) -> usize {
        self.markers.capacity() * std::mem::size_of::<Marker>()
            + self
                .markers
                .iter()
                .filter_map(|m| m.timestamp.as_ref())
                .map(String::capacity)
                .sum::<usize>()
            + self.tip.as_ref().map_or(0, |(_, tip)| tip.capacity())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn composition_compaction_marker_fields_stay_bounded() {
        let large = "x".repeat(1024 * 1024);
        let mut history = CompositionCompactions::default();
        for _ in 0..70 {
            assert!(history.observe(
                "system",
                Some("compact_boundary"),
                false,
                Some(&large),
                None,
                Some(&large),
            ));
        }
        assert_eq!(history.markers.len(), 64);
        assert!(history
            .markers
            .iter()
            .all(|marker| marker.timestamp.is_none()));
        assert!(history.tip.is_none());
        assert!(history.accounted_bytes() < 16 * 1024);
        assert!(serde_json::to_vec(&history).unwrap().len() < 16 * 1024);

        let valid = "2026-07-19T10:00:00.123Z";
        assert!(history.observe(
            "system",
            Some("compact_boundary"),
            false,
            Some("boundary"),
            None,
            Some(valid)
        ));
        assert_eq!(
            history.markers.last().unwrap().timestamp.as_deref(),
            Some(valid)
        );
        assert!(!history.observe(
            "user",
            None,
            true,
            Some("summary"),
            Some("boundary"),
            Some(&large)
        ));
    }
}
