//! The `cloud_session_changes.v1` upload: one body per changed task, and the
//! per-task ACK that alone may settle the local digest cache.
//!
//! The server owns task identity, the activity date and its accepted-body
//! hash. The local `semantic_digest` below only answers "did this task change
//! since its last exact ACK"; it never travels on the wire.

use super::{is_uuid, valid_hmac_fingerprint, valid_rfc3339, COLLECTOR_ID};
use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub(super) const CHANGES_SCHEMA_VERSION: &str = "cloud_session_changes.v1";
pub(super) const CHANGES_ACK_SCHEMA_VERSION: &str = "cloud_session_changes_ack.v1";
pub(super) const AUTHORITY_SCHEMA_VERSION: &str = "cloud_collector_grant_authority.v1";
/// Request packing only: a page with more changed tasks splits into more
/// requests; nothing is discarded.
pub(super) const MAX_CHANGES_PER_REQUEST: usize = 200;
const DIGEST_DOMAIN: &[u8] = b"ottto.cloud-session.task.v1";

/// One provider task's content-free facts, as sent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloudSessionChangeV1 {
    pub entity_key: String,
    /// The head etag of this task's last exact ACK; `null` when none is known.
    pub expected_head_etag: Option<String>,
    pub entity_kind: String,
    pub lifecycle: String,
    pub attempt_count: Option<u64>,
    pub environment_kind: String,
    pub measurement_basis: String,
    pub coverage: Vec<String>,
    pub created_at: Option<String>,
    pub started_at: Option<String>,
    pub updated_at: Option<String>,
    pub completed_at: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloudSessionChangesV1 {
    pub schema_version: String,
    pub grant_id: String,
    pub grant_version: u64,
    pub grant_scope_fingerprint: String,
    pub account_fingerprint: String,
    pub collector_id: String,
    /// Diagnostics only; never part of consent or task identity.
    pub collector_version: String,
    pub collected_at: String,
    pub observations: Vec<CloudSessionChangeV1>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CloudSessionChangeOutcome {
    Accepted,
    Noop,
    Conflict,
    Rejected,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudSessionChangeAckV1 {
    pub entity_key: String,
    pub outcome: CloudSessionChangeOutcome,
    #[serde(default)]
    pub head_etag: Option<String>,
    #[serde(default)]
    pub accepted_seq: Option<u64>,
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudSessionChangesAckV1 {
    pub schema_version: String,
    pub grant_id: String,
    pub grant_version: u64,
    pub entities: Vec<CloudSessionChangeAckV1>,
}

/// The relay-authenticated authority of one bound grant epoch, read once
/// before each due work slice.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudSessionGrantAuthorityV1 {
    pub schema_version: String,
    pub grant_id: String,
    pub grant_version: u64,
    /// `enabled`, `paused` or `revoked`.
    pub status: String,
    pub can_collect: bool,
    pub can_read_cloud_sessions: bool,
    #[serde(default)]
    pub paused_at: Option<String>,
    /// Provider-creation cutoff after an erasure: only tasks created later
    /// may be offered. The server enforces it; the collector filters early.
    #[serde(default)]
    pub collect_not_before: Option<String>,
    pub contract_version: String,
    pub disclosure_version: String,
}

/// What one offered task's ACK settles.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Settled {
    /// Accepted or unchanged at the server: cache this digest with its etag.
    Acked { head_etag: String },
    /// A per-task refusal of exactly this content: remember it so the same
    /// content is not offered again until it changes or the entry expires.
    Refused,
    /// The server's head differs. The etag is a predecessor hint for one
    /// retry of freshly enumerated facts, never an ACK.
    Conflict { head_etag: Option<String> },
}

impl CloudSessionChangeV1 {
    /// SHA-256 over the domain, a zero byte and the compact JSON of every
    /// semantic field with ASCII-sorted keys. The predecessor etag, poll
    /// clocks, binary version and packing are excluded.
    pub(super) fn semantic_digest(&self) -> [u8; 32] {
        #[derive(Serialize)]
        struct Semantic<'a> {
            attempt_count: Option<u64>,
            completed_at: Option<&'a str>,
            coverage: &'a [String],
            created_at: Option<&'a str>,
            entity_key: &'a str,
            entity_kind: &'a str,
            environment_kind: &'a str,
            lifecycle: &'a str,
            measurement_basis: &'a str,
            started_at: Option<&'a str>,
            updated_at: Option<&'a str>,
        }
        let canonical = serde_json::to_vec(&Semantic {
            attempt_count: self.attempt_count,
            completed_at: self.completed_at.as_deref(),
            coverage: &self.coverage,
            created_at: self.created_at.as_deref(),
            entity_key: &self.entity_key,
            entity_kind: &self.entity_kind,
            environment_kind: &self.environment_kind,
            lifecycle: &self.lifecycle,
            measurement_basis: &self.measurement_basis,
            started_at: self.started_at.as_deref(),
            updated_at: self.updated_at.as_deref(),
        })
        .expect("semantic fields serialize");
        let mut hash = Sha256::new();
        hash.update(DIGEST_DOMAIN);
        hash.update([0]);
        hash.update(&canonical);
        hash.finalize().into()
    }

    fn valid(&self) -> bool {
        let has_timing = self.created_at.is_some()
            || self.started_at.is_some()
            || self.updated_at.is_some()
            || self.completed_at.is_some();
        let mut sorted = self.coverage.clone();
        sorted.sort();
        sorted.dedup();
        let has = |field: &str| self.coverage.iter().any(|value| value == field);
        valid_hmac_fingerprint(&self.entity_key)
            && self.expected_head_etag.as_deref().map_or(true, valid_etag)
            && self.entity_kind == "task"
            && matches!(
                self.lifecycle.as_str(),
                "queued" | "running" | "completed" | "failed" | "cancelled" | "unknown"
            )
            && self.attempt_count.map_or(true, |value| value <= 100_000)
            && matches!(
                self.environment_kind.as_str(),
                "hosted" | "container" | "unknown"
            )
            && self.measurement_basis == "not_itemized"
            && sorted == self.coverage
            && self.coverage.iter().all(|field| {
                matches!(
                    field.as_str(),
                    "identity" | "status" | "timing" | "attempts"
                )
            })
            && has("identity")
            && has("status")
            && has("timing") == has_timing
            && has("attempts") == self.attempt_count.is_some()
            && [
                &self.created_at,
                &self.started_at,
                &self.updated_at,
                &self.completed_at,
            ]
            .into_iter()
            .flatten()
            .all(|value| valid_rfc3339(value))
    }
}

impl CloudSessionChangesV1 {
    pub(super) fn validate(&self) -> Result<()> {
        let mut keys = self
            .observations
            .iter()
            .map(|change| change.entity_key.as_str())
            .collect::<Vec<_>>();
        keys.sort_unstable();
        keys.dedup();
        if self.schema_version != CHANGES_SCHEMA_VERSION
            || !is_uuid(&self.grant_id)
            || self.grant_version == 0
            || !valid_hmac_fingerprint(&self.grant_scope_fingerprint)
            || !valid_hmac_fingerprint(&self.account_fingerprint)
            || self.collector_id != COLLECTOR_ID
            || self.collector_version.is_empty()
            || self.collector_version.len() > 32
            || !valid_rfc3339(&self.collected_at)
            || self.observations.is_empty()
            || self.observations.len() > MAX_CHANGES_PER_REQUEST
            || keys.len() != self.observations.len()
            || !self.observations.iter().all(CloudSessionChangeV1::valid)
        {
            return Err(anyhow!("invalid cloud-session changes request"));
        }
        Ok(())
    }

    /// Match the ACK to exactly the offered keys. A malformed ACK (wrong
    /// schema or grant epoch, a missing, duplicate or unsolicited key, or an
    /// accepted/unchanged entry without a valid etag) settles nothing.
    pub(super) fn settle(
        &self,
        ack: &CloudSessionChangesAckV1,
    ) -> Result<BTreeMap<String, Settled>> {
        if ack.schema_version != CHANGES_ACK_SCHEMA_VERSION
            || !ack.grant_id.eq_ignore_ascii_case(&self.grant_id)
            || ack.grant_version != self.grant_version
            || ack.entities.len() != self.observations.len()
        {
            return Err(anyhow!("cloud-session ACK does not match the request"));
        }
        let mut settled = BTreeMap::new();
        for entry in &ack.entities {
            if !self
                .observations
                .iter()
                .any(|change| change.entity_key == entry.entity_key)
            {
                return Err(anyhow!("cloud-session ACK names an unsolicited task"));
            }
            let etag = entry.head_etag.as_deref().filter(|etag| valid_etag(etag));
            if entry.head_etag.is_some() && etag.is_none() {
                return Err(anyhow!("cloud-session ACK head etag is invalid"));
            }
            let outcome = match (entry.outcome, etag) {
                (
                    CloudSessionChangeOutcome::Accepted | CloudSessionChangeOutcome::Noop,
                    Some(etag),
                ) => Settled::Acked {
                    head_etag: etag.to_string(),
                },
                (CloudSessionChangeOutcome::Accepted | CloudSessionChangeOutcome::Noop, None) => {
                    return Err(anyhow!("cloud-session ACK lacks a head etag"))
                }
                (CloudSessionChangeOutcome::Rejected, _) => Settled::Refused,
                (CloudSessionChangeOutcome::Conflict, etag) => Settled::Conflict {
                    head_etag: etag.map(str::to_string),
                },
            };
            if settled.insert(entry.entity_key.clone(), outcome).is_some() {
                return Err(anyhow!("cloud-session ACK repeats a task"));
            }
        }
        Ok(settled)
    }
}

/// Head etags are 64 lowercase hex characters.
pub(super) fn valid_etag(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}
