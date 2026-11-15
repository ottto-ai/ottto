//! The `cloud_session_changes.v3` upload: one body per changed task, and the
//! per-task ACK that alone may settle the local digest cache.
//!
//! A task's `source_session_id` is its raw provider task id, sent like a
//! local session id; the server builds its identity from (user, source, id).
//! The server owns the activity date and its accepted-body hash. The local
//! `semantic_digest` below only answers "did this task change since its last
//! exact ACK"; it never travels on the wire.

use super::{valid_rfc3339, valid_session_id};
use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub(super) const CHANGES_SCHEMA_VERSION: &str = "cloud_session_changes.v3";
pub(super) const CHANGES_ACK_SCHEMA_VERSION: &str = "cloud_session_changes_ack.v3";
/// The only source this collector speaks for.
pub(super) const CHANGES_SOURCE: &str = "codex";
/// Request packing only: a page with more changed tasks splits into more
/// requests; nothing is discarded.
pub(super) const MAX_CHANGES_PER_REQUEST: usize = 200;
/// The server's decoded body ceiling. Packing keeps every request under it,
/// so long titles split a page into more requests instead of failing it.
pub(super) const MAX_REQUEST_BYTES: usize = 512 * 1024;
/// Room for the envelope around the observations.
const ENVELOPE_BYTES: usize = 4 * 1024;
/// The server's wire bound for a title or environment name (it stores less).
pub(super) const MAX_LABEL_CHARS: usize = 2048;
const DIGEST_DOMAIN: &[u8] = b"ottto.cloud-session.task.v3";

/// The metadata policy applied to this body: the same two settings, read from
/// the same hint, that local session uploads use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloudUploadPolicyV2 {
    pub session_titles_enabled: bool,
    pub workspace_labels_enabled: bool,
}

/// One provider task's facts, as sent. `title` and `environment_label` are
/// present only when the policy allows them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloudSessionChangeV2 {
    /// The raw provider task id, byte for byte.
    pub source_session_id: String,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub environment_label: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloudSessionChangesV2 {
    pub schema_version: String,
    pub source: String,
    /// Diagnostics only; never part of task identity.
    pub collector_version: String,
    pub collected_at: String,
    pub upload_policy: CloudUploadPolicyV2,
    pub observations: Vec<CloudSessionChangeV2>,
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
pub struct CloudSessionChangeAckV2 {
    pub source_session_id: String,
    pub outcome: CloudSessionChangeOutcome,
    #[serde(default)]
    pub head_etag: Option<String>,
    #[serde(default)]
    pub accepted_seq: Option<u64>,
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudSessionChangesAckV2 {
    pub schema_version: String,
    pub entities: Vec<CloudSessionChangeAckV2>,
}

/// What one offered task's ACK settles.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Settled {
    /// Accepted (the server head moved) or unchanged at the server: cache
    /// this digest with its etag.
    Acked { head_etag: String, accepted: bool },
    /// A per-task refusal of exactly this content, or a conflict without a
    /// server head: remember the content, with no etag and no credit, so it is
    /// not offered again until it changes or the entry expires.
    Refused,
    /// The server's head differs. The etag is a predecessor hint for one
    /// retry of freshly enumerated facts, never an ACK.
    Conflict { head_etag: String },
}

impl CloudSessionChangeV2 {
    /// SHA-256 over the domain, a zero byte and the compact JSON of every
    /// semantic field and the applied policy, with ASCII-sorted keys. The
    /// predecessor etag, poll clocks, binary version and packing are excluded,
    /// so a policy flip or a title edit offers the task again.
    pub(super) fn semantic_digest(&self, policy: CloudUploadPolicyV2) -> [u8; 32] {
        #[derive(Serialize)]
        struct Semantic<'a> {
            attempt_count: Option<u64>,
            completed_at: Option<&'a str>,
            coverage: &'a [String],
            created_at: Option<&'a str>,
            entity_kind: &'a str,
            environment_kind: &'a str,
            environment_label: Option<&'a str>,
            lifecycle: &'a str,
            measurement_basis: &'a str,
            session_titles_enabled: bool,
            source_session_id: &'a str,
            started_at: Option<&'a str>,
            title: Option<&'a str>,
            updated_at: Option<&'a str>,
            workspace_labels_enabled: bool,
        }
        let canonical = serde_json::to_vec(&Semantic {
            attempt_count: self.attempt_count,
            completed_at: self.completed_at.as_deref(),
            coverage: &self.coverage,
            created_at: self.created_at.as_deref(),
            entity_kind: &self.entity_kind,
            environment_kind: &self.environment_kind,
            environment_label: self.environment_label.as_deref(),
            lifecycle: &self.lifecycle,
            measurement_basis: &self.measurement_basis,
            session_titles_enabled: policy.session_titles_enabled,
            source_session_id: &self.source_session_id,
            started_at: self.started_at.as_deref(),
            title: self.title.as_deref(),
            updated_at: self.updated_at.as_deref(),
            workspace_labels_enabled: policy.workspace_labels_enabled,
        })
        .expect("semantic fields serialize");
        let mut hash = Sha256::new();
        hash.update(DIGEST_DOMAIN);
        hash.update([0]);
        hash.update(&canonical);
        hash.finalize().into()
    }

    fn valid(&self, policy: CloudUploadPolicyV2) -> bool {
        let has_timing = self.created_at.is_some()
            || self.started_at.is_some()
            || self.updated_at.is_some()
            || self.completed_at.is_some();
        let mut sorted = self.coverage.clone();
        sorted.sort();
        sorted.dedup();
        let has = |field: &str| self.coverage.iter().any(|value| value == field);
        let label_ok = |value: &Option<String>, allowed: bool| {
            value
                .as_deref()
                .is_none_or(|value| allowed && value.chars().count() <= MAX_LABEL_CHARS)
        };
        valid_session_id(&self.source_session_id)
            && self.expected_head_etag.as_deref().is_none_or(valid_etag)
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
            && label_ok(&self.title, policy.session_titles_enabled)
            && label_ok(&self.environment_label, policy.workspace_labels_enabled)
    }
}

impl CloudSessionChangesV2 {
    pub(super) fn validate(&self) -> Result<()> {
        let mut ids = self
            .observations
            .iter()
            .map(|change| change.source_session_id.as_str())
            .collect::<Vec<_>>();
        ids.sort_unstable();
        ids.dedup();
        if self.schema_version != CHANGES_SCHEMA_VERSION
            || self.source != CHANGES_SOURCE
            || self.collector_version.is_empty()
            || self.collector_version.len() > 32
            || !valid_rfc3339(&self.collected_at)
            || self.observations.is_empty()
            || self.observations.len() > MAX_CHANGES_PER_REQUEST
            || ids.len() != self.observations.len()
            || !self
                .observations
                .iter()
                .all(|change| change.valid(self.upload_policy))
        {
            return Err(anyhow!("invalid cloud-session changes request"));
        }
        Ok(())
    }

    /// Match the ACK to exactly the offered ids, byte for byte (an echo the
    /// server normalized names an unsolicited task). A malformed ACK (wrong
    /// schema, a missing, duplicate or unsolicited id, or an
    /// accepted/unchanged entry without a valid etag) settles nothing.
    pub(super) fn settle(
        &self,
        ack: &CloudSessionChangesAckV2,
    ) -> Result<BTreeMap<String, Settled>> {
        if ack.schema_version != CHANGES_ACK_SCHEMA_VERSION
            || ack.entities.len() != self.observations.len()
        {
            return Err(anyhow!("cloud-session ACK does not match the request"));
        }
        let mut settled = BTreeMap::new();
        for entry in &ack.entities {
            if !self
                .observations
                .iter()
                .any(|change| change.source_session_id == entry.source_session_id)
            {
                return Err(anyhow!("cloud-session ACK names an unsolicited task"));
            }
            let etag = entry.head_etag.as_deref().filter(|etag| valid_etag(etag));
            if entry.head_etag.is_some() && etag.is_none() {
                return Err(anyhow!("cloud-session ACK head etag is invalid"));
            }
            let outcome = match (entry.outcome, etag) {
                (
                    outcome @ (CloudSessionChangeOutcome::Accepted
                    | CloudSessionChangeOutcome::Noop),
                    Some(etag),
                ) => Settled::Acked {
                    head_etag: etag.to_string(),
                    accepted: outcome == CloudSessionChangeOutcome::Accepted,
                },
                (CloudSessionChangeOutcome::Accepted | CloudSessionChangeOutcome::Noop, None) => {
                    return Err(anyhow!("cloud-session ACK lacks a head etag"))
                }
                (CloudSessionChangeOutcome::Conflict, Some(etag)) => Settled::Conflict {
                    head_etag: etag.to_string(),
                },
                (CloudSessionChangeOutcome::Rejected | CloudSessionChangeOutcome::Conflict, _) => {
                    Settled::Refused
                }
            };
            if settled
                .insert(entry.source_session_id.clone(), outcome)
                .is_some()
            {
                return Err(anyhow!("cloud-session ACK repeats a task"));
            }
        }
        Ok(settled)
    }
}

/// Split changed tasks into requests of at most `MAX_CHANGES_PER_REQUEST`
/// tasks and `MAX_REQUEST_BYTES` serialized bytes, keeping every task and its
/// order. One task is far below the byte budget (its labels are bounded).
pub(super) fn pack(changes: Vec<CloudSessionChangeV2>) -> Vec<Vec<CloudSessionChangeV2>> {
    let budget = MAX_REQUEST_BYTES - ENVELOPE_BYTES;
    let mut requests = Vec::new();
    let mut current = Vec::new();
    let mut bytes = 0;
    for change in changes {
        // One separator byte per task besides its JSON.
        let size = serde_json::to_vec(&change).map_or(budget, |json| json.len()) + 1;
        if !current.is_empty()
            && (current.len() == MAX_CHANGES_PER_REQUEST || bytes + size > budget)
        {
            requests.push(std::mem::take(&mut current));
            bytes = 0;
        }
        bytes += size;
        current.push(change);
    }
    if !current.is_empty() {
        requests.push(current);
    }
    requests
}

/// Head etags are 64 lowercase hex characters.
pub(super) fn valid_etag(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}
