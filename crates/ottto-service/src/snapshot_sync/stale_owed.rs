//! Refusal exposure and a destination-local, durably consumed operator action.
//! No acceptance evidence or scheduler lives here. All diagnostics are counts.
use super::*;
use crate::upload_receipts::RejectedUsageReason;

pub(super) fn is_stale_reason(reason: &str) -> bool {
    matches!(
        reason,
        "accepted_log_stale_older_upload" | "accepted_log_stale_older_mixed"
    )
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct Exposure {
    /// None for legacy records: observation today cannot establish their age.
    first_held_unix: Option<u64>,
    requests: Option<u64>,
    tokens: Option<u64>,
    /// The old reason vocabulary remains `other` for this retryable reason.
    mixed: bool,
    pub(super) reopen_pending: bool,
}
impl Exposure {
    pub(super) fn new(reason: &str, now: u64) -> Self {
        Self {
            first_held_unix: Some(now),
            requests: None,
            tokens: None,
            mixed: reason == "accepted_log_stale_older_mixed",
            reopen_pending: false,
        }
    }
    fn legacy() -> Self {
        Self {
            first_held_unix: None,
            ..Self::new("", 0)
        }
    }
}
crate::heap_layout_bound::fields!(Exposure; first_held_unix, requests, tokens, mixed, reopen_pending);

impl PermanentSnapshotRejection {
    pub(super) fn is_stale(&self) -> bool {
        self.reason == RejectedUsageReason::AcceptedLogStaleOlderUpload
            || self.exposure.as_ref().is_some_and(|e| e.mixed)
    }
    fn reason_label(&self) -> String {
        if self.exposure.as_ref().is_some_and(|e| e.mixed) {
            "accepted_log_stale_older_mixed".into()
        } else {
            // An enum serialization, never a server-provided diagnostic label.
            serde_json::to_value(self.reason)
                .ok()
                .and_then(|v| v.as_str().map(str::to_owned))
                .unwrap_or_else(|| "other".into())
        }
    }
}
impl SnapshotUploadProgress {
    pub(super) fn refused_body(&self, fingerprint: &str, body: &str) -> bool {
        self.permanent_rejections
            .get(fingerprint)
            .is_some_and(|r| r.body_witness == body)
            || self
                .retained_stale_rejections
                .get(fingerprint)
                .is_some_and(|revisions| revisions.contains_key(body))
    }

    pub(super) fn stale_body(&self, fingerprint: &str, body: &str) -> bool {
        self.permanent_rejections
            .get(fingerprint)
            .is_some_and(|r| r.is_stale() && r.body_witness == body)
            || self
                .retained_stale_rejections
                .get(fingerprint)
                .is_some_and(|revisions| revisions.contains_key(body))
    }

    pub(super) fn retain_replaced_stale(&mut self, fingerprint: &str, next_body: &str) {
        if self
            .permanent_rejections
            .get(fingerprint)
            .is_some_and(|r| r.is_stale() && r.body_witness != next_body)
        {
            let refusal = self
                .permanent_rejections
                .remove(fingerprint)
                .expect("checked refusal");
            self.retained_stale_rejections
                .entry(fingerprint.into())
                .or_default()
                .entry(refusal.body_witness.clone())
                .or_insert(refusal);
        }
    }

    pub(super) fn stale_reopen_pending(&self, fingerprint: &str) -> bool {
        self.permanent_rejections
            .get(fingerprint)
            .into_iter()
            .chain(
                self.retained_stale_rejections
                    .get(fingerprint)
                    .into_iter()
                    .flat_map(|r| r.values()),
            )
            .any(|r| r.exposure.as_ref().is_some_and(|e| e.reopen_pending))
    }

    pub(super) fn consume_stale_reopen_claim(&mut self, fingerprint: &str) {
        for refusal in self
            .permanent_rejections
            .get_mut(fingerprint)
            .into_iter()
            .chain(
                self.retained_stale_rejections
                    .get_mut(fingerprint)
                    .into_iter()
                    .flat_map(|r| r.values_mut()),
            )
        {
            if let Some(exposure) = &mut refusal.exposure {
                exposure.reopen_pending = false;
            }
        }
    }

    pub(super) fn note_refused_exposure<T: Serialize>(&mut self, fingerprint: &str, item: &T) {
        let Some(exposure) = self
            .permanent_rejections
            .get_mut(fingerprint)
            .and_then(|r| r.exposure.as_mut())
        else {
            return;
        };
        let Ok(value) = serde_json::to_value(item) else {
            return;
        };
        exposure.requests = value
            .get("request_count")
            .and_then(serde_json::Value::as_u64);
        // Reasoning is included in output. Cached input is a subset when
        // the body declares inclusive_cached; no source-name assumption.
        let scope = value
            .pointer("/provenance/input_token_scope")
            .and_then(serde_json::Value::as_str);
        exposure.tokens = match scope {
            Some("inclusive_cached" | "uncached" | "total_only") => [
                "input_tokens",
                "output_tokens",
                "cache_read_tokens",
                "cache_creation_5m_tokens",
                "cache_creation_1h_tokens",
            ]
            .iter()
            .filter(|key| !(scope == Some("inclusive_cached") && **key == "cache_read_tokens"))
            .try_fold(0u64, |sum, key| sum.checked_add(value.get(key)?.as_u64()?))
            .and_then(|sum| {
                sum.checked_add(
                    value
                        .get("unattributed_total_tokens")
                        .and_then(serde_json::Value::as_u64)
                        .unwrap_or(0),
                )
            }),
            _ => None,
        };
    }

    /// Owner-set regular-file sentinel, like existing local support markers.
    /// Save the returned mutation BEFORE preparing leases or acquiring sources.
    /// The consumed bit survives removal/re-delivery of the sentinel and ACKs.
    pub(super) fn reopen_stale_once(&mut self, progress_path: &Path) -> Result<bool> {
        if self.stale_reopen_consumed == Some(true) {
            return Ok(false);
        }
        let marker = progress_path.with_extension("stale-older-reopen-once");
        match std::fs::symlink_metadata(marker) {
            Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {}
            Ok(_) => return Ok(false),
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error).context("read local one-shot marker"),
        }
        self.stale_reopen_consumed = Some(true);
        let active = self
            .active_quarantine_witness
            .as_ref()
            .expect("upload progress has an active witness");
        for (fingerprint, refusal) in self.permanent_rejections.iter_mut().chain(
            self.retained_stale_rejections
                .iter_mut()
                .flat_map(|(fp, revisions)| revisions.values_mut().map(move |r| (fp, r))),
        ) {
            if !refusal.is_stale() {
                continue;
            }
            refusal
                .exposure
                .get_or_insert_with(Exposure::legacy)
                .reopen_pending = true;
            let record = self
                .quarantined_fingerprints
                .entry(fingerprint.clone())
                .or_insert_with(|| SnapshotQuarantineRecord {
                    contract_retry_claims: None,
                    reconstruction_contract:
                        crate::snapshots::terminal_contract_retry::current_contract(),
                    witness: active.clone(),
                    retry_after_unix_seconds: 0,
                    upload_body_witness: None,
                    failed_reconstruction_count: 1,
                    disposition: SnapshotQuarantineDisposition::RetryPending,
                });
            record.witness = active.clone();
            record.upload_body_witness = Some(refusal.body_witness.clone());
            record.disposition = SnapshotQuarantineDisposition::RetryPending;
            record.contract_retry_claims = None;
            record.failed_reconstruction_count = 1;
            record.retry_after_unix_seconds = quarantine_retry_after(fingerprint);
        }
        Ok(true)
    }
}

#[derive(Debug, Default, Clone, Copy, Serialize, PartialEq, Eq)]
struct Counts {
    entities: usize,
    known_requests: u64,
    known_tokens: u64,
    unknown_requests: usize,
    unknown_tokens: usize,
    unknown_age: usize,
    oldest_age_seconds: u64,
    reopen_pending: usize,
}
impl Counts {
    fn add(&mut self, exposure: Option<&Exposure>, now: u64) {
        self.entities += 1;
        if let Some(n) = exposure.and_then(|e| e.requests) {
            self.known_requests = self.known_requests.saturating_add(n);
        } else {
            self.unknown_requests += 1;
        }
        if let Some(n) = exposure.and_then(|e| e.tokens) {
            self.known_tokens = self.known_tokens.saturating_add(n);
        } else {
            self.unknown_tokens += 1;
        }
        if let Some(at) = exposure
            .and_then(|e| e.first_held_unix)
            .filter(|at| *at <= now)
        {
            self.oldest_age_seconds = self.oldest_age_seconds.max(now - at);
        } else {
            self.unknown_age += 1;
        }
        self.reopen_pending += usize::from(exposure.is_some_and(|e| e.reopen_pending));
    }
}
fn age_bucket(exposure: Option<&Exposure>, now: u64) -> &'static str {
    match exposure
        .and_then(|e| e.first_held_unix)
        .filter(|at| *at <= now)
        .map(|at| now - at)
    {
        None => "unknown",
        Some(0..=86_399) => "under_day",
        Some(86_400..=604_799) => "day_to_week",
        Some(_) => "week_or_more",
    }
}

/// Union mirrors at the entity grain before aggregation. Authority member aliases
/// resolve through the existing incidence table; unbound members stay unknown.
fn census(
    index: &ScanIndex,
    progress: &SnapshotUploadProgress,
    now: u64,
) -> BTreeMap<(String, &'static str), Counts> {
    let mut entities = BTreeMap::new();
    for (fingerprint, record) in &index.quarantined_snapshot_fingerprints {
        if record.disposition != SnapshotQuarantineDisposition::RetryPending {
            entities.insert(
                (
                    fingerprint.as_str(),
                    record.upload_body_witness.as_deref().unwrap_or(""),
                ),
                ("snapshot_terminal".to_string(), None),
            );
        }
    }
    for (fingerprint, record) in &progress.quarantined_fingerprints {
        if record.disposition != SnapshotQuarantineDisposition::RetryPending {
            entities.insert(
                (
                    fingerprint.as_str(),
                    record.upload_body_witness.as_deref().unwrap_or(""),
                ),
                ("snapshot_terminal".to_string(), None),
            );
        }
    }
    let (authority, unbound) = index.authority_owed_snapshot_fingerprints();
    for fingerprint in authority {
        entities
            .entry((fingerprint, ""))
            .or_insert_with(|| ("usage_authority_held".into(), None));
    }
    for (fingerprint, refusal) in progress.permanent_rejections.iter().chain(
        progress
            .retained_stale_rejections
            .iter()
            .flat_map(|(fp, revisions)| revisions.values().map(move |r| (fp, r))),
    ) {
        entities.insert(
            (fingerprint.as_str(), refusal.body_witness.as_str()),
            (refusal.reason_label(), refusal.exposure.as_ref()),
        );
    }
    let bound_entities = entities
        .keys()
        .filter(|(_, body)| !body.is_empty())
        .map(|(fp, _)| *fp)
        .collect::<BTreeSet<_>>();
    entities.retain(|(fp, body), _| !body.is_empty() || !bound_entities.contains(fp));
    let mut result: BTreeMap<_, Counts> = BTreeMap::new();
    for (reason, exposure) in entities.values() {
        result
            .entry((reason.clone(), age_bucket(*exposure, now)))
            .or_default()
            .add(*exposure, now);
    }
    if unbound > 0 {
        let counts = result
            .entry(("usage_authority_unbound".into(), "unknown"))
            .or_default();
        counts.entities += unbound;
        counts.unknown_age += unbound;
        counts.unknown_requests += unbound;
        counts.unknown_tokens += unbound;
    }
    result
}

#[derive(Default)]
struct LastReport {
    at: u64,
    entities: usize,
    oldest: u64,
}
static LAST: OnceLock<Mutex<BTreeMap<&'static str, LastReport>>> = OnceLock::new();

/// One page report, plus the existing-sync daily diagnostic. No scheduling input.
/// Legacy ages stay unknown. No identifiers, paths, dimensions or amounts.
pub(super) fn report(
    source: SnapshotSource,
    index: &ScanIndex,
    progress: &SnapshotUploadProgress,
    now: u64,
) {
    let rows = census(index, progress, now);
    let entities = rows.values().map(|c| c.entities).sum();
    let oldest = rows
        .values()
        .map(|c| c.oldest_age_seconds)
        .max()
        .unwrap_or(0);
    let (daily, alarm) = match LAST.get_or_init(|| Mutex::new(BTreeMap::new())).lock() {
        Ok(mut state) => {
            let last = state.entry(source.api_slug()).or_default();
            let daily = last.at == 0 || now.saturating_sub(last.at) >= 86_400;
            let alarm = entities > last.entities || oldest > last.oldest;
            last.entities = entities;
            last.oldest = oldest;
            if daily {
                last.at = now;
            }
            (daily, alarm)
        }
        Err(_) => (true, true),
    };
    for ((reason, age_bucket), counts) in rows {
        crate::local_resource_diagnostics::traversal_point(
            "owed_exposure",
            source.api_slug(),
            &serde_json::json!({"scope": "page", "reason": reason, "age_bucket": age_bucket, "counts": counts}),
        );
        if daily {
            crate::local_resource_diagnostics::traversal_point(
                "owed_exposure",
                source.api_slug(),
                &serde_json::json!({"scope": "daily", "reason": reason, "age_bucket": age_bucket, "counts": counts}),
            );
        }
    }
    if alarm {
        eprintln!("local snapshot owed exposure alarm: source={} entities={} oldest_age_seconds={} rising=true", source.api_slug(), entities, oldest);
    }
}

#[cfg(test)]
mod tests;
