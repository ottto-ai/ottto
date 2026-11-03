//! Exact refusal revisions and counts-only owed observations.
use super::*;
use crate::upload_receipts::RejectedUsageReason;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct Exposure {
    first_held_unix: Option<u64>,
    requests: Option<u64>,
    tokens: Option<u64>,
}
impl Exposure {
    pub(super) fn new(now: u64) -> Self {
        Self {
            first_held_unix: Some(now),
            requests: None,
            tokens: None,
        }
    }
}
/// An invalid optional observation cannot discard the refusal that owns it.
pub(super) fn decode_exposure<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> std::result::Result<Option<Exposure>, D::Error> {
    let value = serde_json::Value::deserialize(d)?;
    Ok(serde_json::from_value(value).ok())
}
crate::heap_layout_bound::fields!(Exposure; first_held_unix, requests, tokens);

impl PermanentSnapshotRejection {
    pub(super) fn is_stale(&self) -> bool {
        self.reason == RejectedUsageReason::AcceptedLogStaleOlderUpload
    }
    pub(super) fn has_stale_debt(&self) -> bool {
        self.owed() || self.revisions.values().any(Self::owed)
    }
    pub(super) fn refused_body(&self, body: &str) -> bool {
        self.body_witness == body || self.revisions.contains_key(body)
    }
    pub(super) fn owed(&self) -> bool {
        // Only fresh refusals acquire exposure; legacy records are never
        // backfilled. Missing or invalid observations conservatively stay owed.
        self.is_stale() && self.exposure.is_none()
    }
}
impl SnapshotUploadProgress {
    pub(super) fn refused_body(&self, fp: &str, body: &str) -> bool {
        self.permanent_rejections
            .get(fp)
            .is_some_and(|r| r.refused_body(body))
    }
    pub(super) fn owed_stale_body(&self, fp: &str, body: &str) -> bool {
        self.permanent_rejections.get(fp).is_some_and(|r| {
            (r.owed() && r.body_witness == body)
                || r.revisions
                    .get(body)
                    .is_some_and(PermanentSnapshotRejection::owed)
        })
    }
    pub(super) fn retained_revisions(
        &mut self,
        fp: &str,
        next: &str,
    ) -> BTreeMap<String, PermanentSnapshotRejection> {
        let Some(mut old) = self.permanent_rejections.remove(fp) else {
            return BTreeMap::new();
        };
        let mut revisions = std::mem::take(&mut old.revisions);
        if old.owed() && old.body_witness != next {
            revisions.insert(old.body_witness.clone(), old);
        }
        revisions.remove(next);
        revisions
    }
    pub(super) fn note_refused_exposure<T: Serialize>(&mut self, fp: &str, item: &T) {
        let Some(e) = self
            .permanent_rejections
            .get_mut(fp)
            .and_then(|r| r.exposure.as_mut())
        else {
            return;
        };
        let Ok(v) = serde_json::to_value(item) else {
            return;
        };
        e.requests = v.get("request_count").and_then(serde_json::Value::as_u64);
        let scope = v
            .pointer("/provenance/input_token_scope")
            .and_then(serde_json::Value::as_str);
        e.tokens = match scope {
            Some("inclusive_cached" | "uncached" | "total_only") => [
                "input_tokens",
                "output_tokens",
                "cache_read_tokens",
                "cache_creation_5m_tokens",
                "cache_creation_1h_tokens",
            ]
            .iter()
            .filter(|key| !(scope == Some("inclusive_cached") && **key == "cache_read_tokens"))
            .try_fold(0u64, |sum, key| sum.checked_add(v.get(key)?.as_u64()?))
            .and_then(|sum| {
                sum.checked_add(
                    v.get("unattributed_total_tokens")
                        .and_then(serde_json::Value::as_u64)
                        .unwrap_or(0),
                )
            }),
            _ => None,
        };
    }

    pub(super) fn refusal_exposure(
        &self,
        now: u64,
    ) -> crate::local_resource_diagnostics::RefusalExposure {
        let mut counts = crate::local_resource_diagnostics::RefusalExposure::default();
        for refusal in self.permanent_rejections.values() {
            let mut owed = std::iter::once(refusal)
                .chain(refusal.revisions.values())
                .filter(|r| r.owed());
            let Some(first_owed) = owed.next() else {
                continue;
            };
            counts.owed_entities += 1;
            // Revisions can overlap; disclose one known revision per entity,
            // rather than adding overlapping request/token populations.
            let e = first_owed.exposure.as_ref();
            if let Some(n) = e.and_then(|e| e.requests) {
                counts.known_requests = counts.known_requests.saturating_add(n);
            } else {
                counts.unknown_request_entities += 1;
            }
            if let Some(n) = e.and_then(|e| e.tokens) {
                counts.known_tokens = counts.known_tokens.saturating_add(n);
            } else {
                counts.unknown_token_entities += 1;
            }
            let first = std::iter::once(first_owed)
                .chain(owed)
                .filter_map(|r| r.exposure.as_ref()?.first_held_unix)
                .min();
            if let Some(first) = first {
                counts.oldest_age_seconds =
                    counts.oldest_age_seconds.max(now.saturating_sub(first));
            } else {
                counts.unknown_age_entities += 1;
            }
        }
        counts
    }
}

#[cfg(test)]
mod tests;
