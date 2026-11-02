//! Exact refusal revisions and an explicit, receipt-bound operator trigger.
use super::*;
use crate::upload_receipts::RejectedUsageReason;

pub(super) fn is_stale_reason(reason: &str) -> bool {
    reason == "accepted_log_stale_older_upload"
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct Exposure {
    first_held_unix: Option<u64>,
    requests: Option<u64>,
    tokens: Option<u64>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub(super) covered: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub(super) reopen_pending: bool,
}
impl Exposure {
    pub(super) fn new(now: u64) -> Self {
        Self {
            first_held_unix: Some(now),
            requests: None,
            tokens: None,
            covered: false,
            reopen_pending: false,
        }
    }
    fn legacy() -> Self {
        Self {
            first_held_unix: None,
            ..Self::new(0)
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
crate::heap_layout_bound::fields!(Exposure; first_held_unix, requests, tokens, covered, reopen_pending);

impl PermanentSnapshotRejection {
    pub(super) fn is_stale(&self) -> bool {
        self.reason == RejectedUsageReason::AcceptedLogStaleOlderUpload
    }
    pub(super) fn refused_body(&self, body: &str) -> bool {
        self.body_witness == body || self.revisions.contains_key(body)
    }
    pub(super) fn owed(&self) -> bool {
        self.is_stale() && !self.exposure.as_ref().is_some_and(|e| e.covered)
    }
}
impl SnapshotUploadProgress {
    pub(super) fn refused_body(&self, fp: &str, body: &str) -> bool {
        self.permanent_rejections
            .get(fp)
            .is_some_and(|r| r.refused_body(body))
    }
    pub(super) fn stale_body(&self, fp: &str, body: &str) -> bool {
        self.permanent_rejections.get(fp).is_some_and(|r| {
            (r.is_stale() && r.body_witness == body)
                || r.revisions
                    .get(body)
                    .is_some_and(PermanentSnapshotRejection::is_stale)
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
        if old.is_stale() && old.body_witness != next {
            revisions.insert(old.body_witness.clone(), old);
        }
        revisions.remove(next);
        revisions
    }
    pub(super) fn stale_reopen_pending(&self, fp: &str) -> bool {
        self.permanent_rejections
            .get(fp)
            .is_some_and(|r| r.exposure.as_ref().is_some_and(|e| e.reopen_pending))
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

    /// The explicit list binds the server comparison to the exact local revision.
    /// No timestamp, activity order or transcript read can establish coverage.
    pub(super) fn reopen_stale_once(
        &mut self,
        path: &Path,
        source: SnapshotSource,
        machine: &str,
        index: &mut ScanIndex,
    ) -> Result<bool> {
        let marker = path.with_extension("stale-older-reopen-once");
        match std::fs::symlink_metadata(&marker) {
            Ok(m) if m.is_file() && !m.file_type().is_symlink() => (),
            Ok(_) => return Ok(false),
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(false),
            Err(e) => return Err(e).context("read local one-shot input"),
        }
        let request: Request = serde_json::from_slice(&std::fs::read(marker)?)
            .context("decode local one-shot input")?;
        anyhow::ensure!(!request.nonce.is_empty(), "one-shot requires a nonce");
        if self.stale_reopen_nonce.as_ref() == Some(&request.nonce) {
            return Ok(false);
        }
        // Validate the entire list before changing either existing owner.
        let mut seen = BTreeSet::new();
        for e in &request.entities {
            anyhow::ensure!(
                e.entity_hash == entity_hash(source.api_slug(), machine, &e.source_session_id)
                    && is_snapshot_fingerprint(&e.snapshot_fingerprint)
                    && is_snapshot_fingerprint(&e.body_witness)
                    && source == SnapshotSource::ClaudeCode
                    && index.stale_comparison_binds_entity(
                        &e.source_session_id,
                        &e.snapshot_fingerprint
                    )
                    && seen.insert(&e.snapshot_fingerprint),
                "invalid or duplicate one-shot entity binding"
            );
            let body_matches = self.refused_body(&e.snapshot_fingerprint, &e.body_witness)
                || index
                    .quarantined_snapshot_fingerprints
                    .get(&e.snapshot_fingerprint)
                    .is_some_and(|r| r.upload_body_witness.as_ref() == Some(&e.body_witness));
            anyhow::ensure!(
                body_matches
                    && self
                        .quarantined_fingerprints
                        .get(&e.snapshot_fingerprint)
                        .or_else(|| index
                            .quarantined_snapshot_fingerprints
                            .get(&e.snapshot_fingerprint))
                        .is_none_or(|r| r.upload_body_witness.as_ref() == Some(&e.body_witness)),
                "one-shot revision is no longer current"
            );
        }
        for e in request.entities {
            let active = self
                .active_quarantine_witness
                .clone()
                .expect("active upload witness");
            let record = self
                .quarantined_fingerprints
                .entry(e.snapshot_fingerprint.clone())
                .or_insert_with(|| {
                    index
                        .quarantined_snapshot_fingerprints
                        .get(&e.snapshot_fingerprint)
                        .cloned()
                        .unwrap_or(SnapshotQuarantineRecord {
                            contract_retry_claims: None,
                            reconstruction_contract:
                                crate::snapshots::terminal_contract_retry::current_contract(),
                            witness: active.clone(),
                            retry_after_unix_seconds: 0,
                            upload_body_witness: None,
                            failed_reconstruction_count: 1,
                            disposition: SnapshotQuarantineDisposition::RetryPending,
                        })
                });
            // A supplied verdict cannot be borrowed by another local body.
            record.upload_body_witness = Some(e.body_witness.clone());
            record.disposition = match e.verdict {
                Verdict::Covered => SnapshotQuarantineDisposition::SupersededTerminal,
                Verdict::Owed => SnapshotQuarantineDisposition::RetryPending,
            };
            record.contract_retry_claims = None;
            record.failed_reconstruction_count = 1;
            record.retry_after_unix_seconds = quarantine_retry_after(&e.snapshot_fingerprint);
            record.witness = self
                .active_quarantine_witness
                .clone()
                .expect("active upload witness");
            let refusal = self
                .permanent_rejections
                .entry(e.snapshot_fingerprint.clone())
                .or_insert_with(|| PermanentSnapshotRejection {
                    body_witness: e.body_witness.clone(),
                    reason: RejectedUsageReason::AcceptedLogStaleOlderUpload,
                    reoffer: None,
                    exposure: None,
                    revisions: BTreeMap::new(),
                });
            let refusal = if refusal.body_witness == e.body_witness {
                refusal
            } else {
                refusal
                    .revisions
                    .get_mut(&e.body_witness)
                    .expect("validated retained revision")
            };
            let exposure = refusal.exposure.get_or_insert_with(Exposure::legacy);
            exposure.covered = e.verdict == Verdict::Covered;
            exposure.reopen_pending = e.verdict == Verdict::Owed;
            index
                .quarantined_snapshot_fingerprints
                .insert(e.snapshot_fingerprint, record.clone());
        }
        // This records the trigger, not a lifetime retry limit. Pending work is
        // consumed only after the existing lease acquires an owning file.
        self.stale_reopen_nonce = Some(request.nonce);
        Ok(true)
    }

    pub(super) fn record_stale_acquisitions(&mut self, index: &ScanIndex) -> bool {
        let mut changed = false;
        for fp in &self.active_quarantine_retries {
            if index.quarantine_retry_has_owner(fp) {
                if let Some(e) = self
                    .permanent_rejections
                    .get_mut(fp)
                    .and_then(|r| r.exposure.as_mut())
                {
                    changed |= e.reopen_pending;
                    e.reopen_pending = false;
                }
            }
        }
        changed
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
                counts.unknown_requests += 1;
            }
            if let Some(n) = e.and_then(|e| e.tokens) {
                counts.known_tokens = counts.known_tokens.saturating_add(n);
            } else {
                counts.unknown_tokens += 1;
            }
            let first = std::iter::once(first_owed)
                .chain(owed)
                .filter_map(|r| r.exposure.as_ref()?.first_held_unix)
                .min();
            if let Some(first) = first {
                counts.oldest_age_seconds =
                    counts.oldest_age_seconds.max(now.saturating_sub(first));
            } else {
                counts.unknown_age += 1;
            }
        }
        counts
    }
}

#[derive(Deserialize)]
struct Request {
    nonce: String,
    entities: Vec<Entity>,
}
#[derive(Deserialize)]
struct Entity {
    entity_hash: String,
    source_session_id: String,
    snapshot_fingerprint: String,
    body_witness: String,
    verdict: Verdict,
}
#[derive(Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum Verdict {
    Covered,
    Owed,
}
fn entity_hash(source: &str, machine: &str, session: &str) -> String {
    format!(
        "{:x}",
        Sha256::digest(format!("{source}\x1f{machine}\x1f{session}"))
    )[..8]
        .into()
}

#[cfg(test)]
mod tests;
