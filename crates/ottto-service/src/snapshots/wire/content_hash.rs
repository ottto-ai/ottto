//! Content hashes of a `SnapshotItem`: the semantic component hashes, the
//! snapshot fingerprint, the upload body witness, the content identity hash,
//! the revision hashes and the semantic envelope built from them.
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

use super::{SnapshotItem, SnapshotSemanticEnvelope, SnapshotSource};
use crate::snapshots::{
    claude_request_identity, semantic_attribution, semantic_model_usage, semantic_usage_buckets,
    sha256_hex, snapshot_upload_body_witness_payload, SnapshotUploadPolicy,
    POLICY_NEUTRAL_COMPONENTS, SNAPSHOT_CONTENT_HASH_EPOCH, SNAPSHOT_REVISION_CONTRACT_VERSION,
    SNAPSHOT_REVISION_V2_CONTRACT_VERSION, SNAPSHOT_SEMANTIC_CONTRACT_VERSION,
};

pub(crate) fn snapshot_semantic_component_hashes(
    source: SnapshotSource,
    item: &SnapshotItem,
) -> BTreeMap<&'static str, String> {
    let mut components = BTreeMap::new();
    let mut insert = |name: &'static str, payload: Value| {
        components.insert(name, sha256_hex(&[&payload.to_string()]));
    };

    let mut usage_accounting = json!({
        "input_tokens": item.input_tokens,
        "output_tokens": item.output_tokens,
        "cache_read_tokens": item.cache_read_tokens,
        "cache_creation_5m_tokens": item.cache_creation_5m_tokens,
        "cache_creation_1h_tokens": item.cache_creation_1h_tokens,
        "reasoning_output_tokens": item.reasoning_output_tokens,
        "unattributed_total_tokens": item.unattributed_total_tokens,
        "request_count": item.request_count,
        "model_usage": item.model_usage.iter().map(semantic_model_usage).collect::<Vec<_>>(),
        "usage_buckets": semantic_usage_buckets(item),
        "cost": item.cost.as_ref().map(|cost| json!({
            "total_cost_usd": &cost.total_cost_usd,
            "input_cost_usd": &cost.input_cost_usd,
            "output_cost_usd": &cost.output_cost_usd,
            "cache_read_cost_usd": &cost.cache_read_cost_usd,
            "cache_creation_cost_usd": &cost.cache_creation_cost_usd,
        })),
    });
    if let Some(contract) = item.usage_accounting_contract.as_deref() {
        usage_accounting
            .as_object_mut()
            .expect("usage accounting semantic body is an object")
            .insert("usage_accounting_contract".to_string(), json!(contract));
    }
    #[cfg(not(test))]
    let identity_collector = claude_request_identity::COLLECTOR;
    #[cfg(test)]
    let identity_collector = claude_request_identity::cycle_contract(true);
    if item.provenance.collector == identity_collector {
        usage_accounting
            .as_object_mut()
            .expect("usage accounting semantic body is an object")
            .insert(
                "request_identity".to_string(),
                claude_request_identity::semantic_leaf(item),
            );
    }
    let mut ownership = serde_json::Map::new();
    if let Some(value) = item.removed_request_count {
        ownership.insert("removed_request_count".into(), json!(value));
    }
    if let Some(value) = item.removed_usage {
        ownership.insert("removed_usage".into(), json!(value));
    }
    if let Some(value) = item.telemetry_owned_complete {
        ownership.insert("telemetry_owned_complete".into(), json!(value));
    }
    if let Some(value) = item.resolver_conflict_count {
        ownership.insert("resolver_conflict_count".into(), json!(value));
    }
    if let Some(value) = item.copy_unproven_counts {
        usage_accounting["copy_unproven_counts"] = json!(value);
    }
    if !ownership.is_empty() {
        usage_accounting["request_ownership"] = Value::Object(ownership);
    }
    insert("usage_accounting", usage_accounting);
    insert(
        "lifecycle_activity",
        json!({
            "status": &item.status,
            "source_started_at": &item.source_started_at,
            "source_ended_at": &item.source_ended_at,
            "source_last_activity_at": &item.source_last_activity_at,
            "state_total_tokens": item.provenance.state_total_tokens,
            "state_archived": item.provenance.state_archived,
        }),
    );
    insert(
        "latency",
        json!({
            "avg_duration_ms": item.avg_duration_ms,
            "avg_time_to_first_token_ms": item.avg_time_to_first_token_ms,
            "max_duration_ms": item.max_duration_ms,
            "max_time_to_first_token_ms": item.max_time_to_first_token_ms,
        }),
    );
    if source.derives_context_posture() {
        insert(
            "context_posture",
            json!({
                // `last_turn_context_tokens` is deliberately ABSENT here. This
                // component is one of POLICY_NEUTRAL_COMPONENTS, so everything
                // in it feeds `content_hash`. Adding a field would re-mint every
                // session's content identity fleet-wide, which SNAPSHOT_CONTENT_HASH_EPOCH
                // reserves for a deliberate, announced epoch move — never a side
                // effect of shipping a field. The watermark still travels on the
                // wire as a SnapshotItem field; it just does not define identity.
                "peak_context_fill_tokens": item.peak_context_fill_tokens,
                "first_turn_context_tokens": item.first_turn_context_tokens,
                // The compaction NUMERICS are deliberately absent here. This
                // component is one of POLICY_NEUTRAL_COMPONENTS, so every field
                // in it feeds `content_hash`; adding one re-mints every
                // session's content identity fleet-wide, which
                // SNAPSHOT_CONTENT_HASH_EPOCH reserves for a deliberate,
                // announced epoch move — never a side effect of shipping a
                // field. They travel on the wire as SnapshotItem fields
                // instead. `context_posture_component_fields_are_pinned` guards
                // this.
                "compaction_count": item.compaction_count,
                "compaction_timestamps": &item.compaction_timestamps,
            }),
        );
    }
    if item.activity_summary.is_some() {
        insert("activity_summary", json!(&item.activity_summary));
    }
    insert(
        "display_identity",
        json!({
            "title": &item.session_display_name,
            "title_source": &item.session_display_name_source,
            "workspace_hash": &item.workspace_hash,
            "workspace_display_label": &item.workspace_display_label,
            "workspace_label_source": &item.workspace_label_source,
            "repository_hash": &item.repository_hash,
            "repository_label": &item.repository_label,
            "repository_label_source": &item.repository_label_source,
            "repository_identity_source": &item.repository_identity_source,
            "workspace_kind": &item.workspace_kind,
        }),
    );
    insert("attribution", semantic_attribution(item));
    insert("artifacts", json!(&item.session_artifacts));
    components
}

pub(crate) fn snapshot_fingerprint_from_component_hashes(
    source: SnapshotSource,
    source_session_id: &str,
    component_hashes: &BTreeMap<&'static str, String>,
) -> String {
    let component_payload = serde_json::to_string(&component_hashes)
        .expect("snapshot semantic component hashes serialize");
    sha256_hex(&[
        SNAPSHOT_SEMANTIC_CONTRACT_VERSION,
        source.api_slug(),
        source_session_id,
        &component_payload,
    ])
}

pub(crate) fn snapshot_fingerprint(source: SnapshotSource, item: &SnapshotItem) -> String {
    snapshot_fingerprint_from_component_hashes(
        source,
        &item.source_session_id,
        &snapshot_semantic_component_hashes(source, item),
    )
}

pub(crate) const SNAPSHOT_BODY_WITNESS_ENVELOPE_TOOL_VERSION: u64 = 9;
pub(crate) const SNAPSHOT_BODY_WITNESS_ENVELOPE_EXCLUSIVE_TOOL_VERSION: u64 = 10;
pub(crate) const SNAPSHOT_BODY_WITNESS_ENVELOPE_SESSION_ACCOUNT_VERSION: u64 = 23;
pub(crate) const SNAPSHOT_BODY_WITNESS_ENVELOPE_EXCLUSIVE_SESSION_ACCOUNT_VERSION: u64 = 24;

/// Backend-compatible, hash-neutral witness version for additive snapshot-body
/// evidence. Creator-bearing bodies use v23/v24, retaining tool fields.
/// Public ACKs select v7/v8 for creator-only and v13/v14 when cache is declared. Missing creator evidence
/// preserves previous versions and digests. Semantic identity remains owned
/// exclusively by the component/content hashes.
pub(crate) fn snapshot_upload_body_witness_version(item: &SnapshotItem) -> Option<u64> {
    let exclusive =
        item.usage_accounting_contract.as_deref() == Some("session_exclusive_reported_usage:v1");
    if item.session_account_evidence.is_some() {
        return Some(if exclusive {
            SNAPSHOT_BODY_WITNESS_ENVELOPE_EXCLUSIVE_SESSION_ACCOUNT_VERSION
        } else {
            SNAPSHOT_BODY_WITNESS_ENVELOPE_SESSION_ACCOUNT_VERSION
        });
    }
    if item.cache_observations.is_some() {
        return Some(if exclusive { 16 } else { 15 });
    }
    if item.tool_usage.is_some() || item.tool_usage_truncated {
        return Some(if exclusive {
            SNAPSHOT_BODY_WITNESS_ENVELOPE_EXCLUSIVE_TOOL_VERSION
        } else {
            SNAPSHOT_BODY_WITNESS_ENVELOPE_TOOL_VERSION
        });
    }
    None
}

/// RFC 8785 SHA-256 digest of additive snapshot-body evidence.
///
/// `context_curve` and tool evidence must not re-mint semantic entity identity,
/// but absent -> present and later corrections still need delivery. The digest
/// intentionally excludes the semantic fingerprint and witness version so its
/// bytes match the backend accepted-log/body-witness contract exactly. Local
/// progress keys it by fingerprint separately.
pub(crate) fn snapshot_upload_body_witness(item: &SnapshotItem) -> String {
    let payload = snapshot_upload_body_witness_payload(item);
    let canonical = crate::canonical_json::canonicalize(&payload)
        .expect("snapshot additive body witness canonicalizes");
    format!("{:x}", Sha256::digest(canonical))
}

/// The policy-neutral component hashes, in canonical order.
pub(crate) fn policy_neutral_component_hashes(
    component_hashes: &BTreeMap<&'static str, String>,
) -> BTreeMap<String, String> {
    POLICY_NEUTRAL_COMPONENTS
        .iter()
        .filter_map(|name| {
            component_hashes
                .get(name)
                .map(|value| ((*name).to_string(), value.clone()))
        })
        .collect()
}

/// The body `content_hash` is computed over.
///
/// It carries the content identity scope (source + session id) and the
/// policy-neutral semantic components, and nothing else. Every field of
/// `snapshot_revision_material` that is NOT here is excluded because it is
/// implementation state, mutable inventory, or wall-clock, and identity may not
/// depend on any of those:
///
/// * `source_file_fingerprint` — scan/inventory state; the same content read
///   from a rotated or recopied transcript is the same content.
/// * parser version and scan-identity version — a parser fix must not re-mint
///   every session's identity (they stay in `revision_hash`, which is the
///   *re-upload* trigger, not the identity).
/// * `provenance.collector` / `provenance.source_file_count` — implementation
///   state and mutable inventory.
/// * the lifecycle scalars (`status`, the three `source_*_at` timestamps,
///   `state_total_tokens`, `state_archived`) — already inside the
///   `lifecycle_activity` component hash, so restating them would double-count
///   without adding coverage.
///
/// Excluded by construction rather than by filter: the policy-scoped components
/// (`display_identity`, `attribution`, `artifacts`), which is what keeps an org
/// display toggle from re-minting identity for every session.
pub(crate) fn snapshot_content_identity_body(
    source: SnapshotSource,
    source_session_id: &str,
    component_hashes: &BTreeMap<&'static str, String>,
) -> Value {
    json!({
        "canonicalization": crate::canonical_json::CANONICAL_JSON_CONTRACT_VERSION,
        "components": policy_neutral_component_hashes(component_hashes),
        "hash_epoch": SNAPSHOT_CONTENT_HASH_EPOCH,
        "source": source.api_slug(),
        "source_session_id": source_session_id,
    })
}

/// SHA-256 over the RFC 8785 canonical bytes of the policy-neutral body.
///
/// SHA-256, not a faster hash: every component hash in this daemon is already
/// SHA-256, the backend has it everywhere, and a second cross-language hash
/// implementation would be a second thing to keep byte-identical for no
/// measurable gain at this item volume.
pub(crate) fn snapshot_content_hash(
    source: SnapshotSource,
    source_session_id: &str,
    component_hashes: &BTreeMap<&'static str, String>,
) -> String {
    let body = snapshot_content_identity_body(source, source_session_id, component_hashes);
    // Infallible by construction: the body is strings, one integer, and one
    // string-to-string map. `content_identity_body_stays_canonicalizable`
    // enforces that mechanically, so this is a proof obligation with a test
    // behind it rather than an assumption.
    let canonical = crate::canonical_json::canonicalize(&body)
        .expect("policy-neutral content identity body is canonicalizable");
    let mut digest = Sha256::new();
    digest.update(&canonical);
    format!("{:x}", digest.finalize())
}

fn snapshot_revision_material(
    item: &SnapshotItem,
    component_hashes: &BTreeMap<&'static str, String>,
) -> Value {
    let policy_neutral_component_hashes = policy_neutral_component_hashes(component_hashes);
    json!({
        "source_file_fingerprint": &item.source_file_fingerprint,
        "source_started_at": &item.source_started_at,
        "source_ended_at": &item.source_ended_at,
        "source_last_activity_at": &item.source_last_activity_at,
        "status": &item.status,
        "provenance": {
            "collector": &item.provenance.collector,
            "source_file_count": item.provenance.source_file_count,
            "input_token_scope": &item.provenance.input_token_scope,
            "state_total_tokens": item.provenance.state_total_tokens,
            "state_archived": item.provenance.state_archived,
        },
        "policy_neutral_component_hashes": policy_neutral_component_hashes,
    })
}

pub(crate) fn snapshot_revision_hash(
    source: SnapshotSource,
    item: &SnapshotItem,
    component_hashes: &BTreeMap<&'static str, String>,
) -> String {
    let material = snapshot_revision_material(item, component_hashes).to_string();
    sha256_hex(&[
        SNAPSHOT_REVISION_CONTRACT_VERSION,
        source.api_slug(),
        source.parser_version(),
        source.scan_identity_version(),
        &material,
    ])
}

pub(crate) fn snapshot_revision_v2_body(
    source: SnapshotSource,
    item: &SnapshotItem,
    upload_policy: SnapshotUploadPolicy,
    component_hashes: &BTreeMap<&'static str, String>,
) -> Value {
    json!({
        "canonicalization": crate::canonical_json::CANONICAL_JSON_CONTRACT_VERSION,
        "contract": SNAPSHOT_REVISION_V2_CONTRACT_VERSION,
        "component_hashes": component_hashes,
        "parser_version": source.parser_version(),
        "scan_identity_version": source.scan_identity_version(),
        "source": source.api_slug(),
        "source_session_id": &item.source_session_id,
        "source_file_fingerprint": &item.source_file_fingerprint,
        "lifecycle": {
            "status": &item.status,
            "source_started_at": &item.source_started_at,
            "source_ended_at": &item.source_ended_at,
            "source_last_activity_at": &item.source_last_activity_at,
        },
        "provenance": {
            "collector": &item.provenance.collector,
            "input_token_scope": &item.provenance.input_token_scope,
            "state_total_tokens": item.provenance.state_total_tokens,
            "state_archived": item.provenance.state_archived,
        },
        "upload_policy": upload_policy,
    })
}

pub(crate) fn snapshot_revision_v2_hash(
    source: SnapshotSource,
    item: &SnapshotItem,
    upload_policy: SnapshotUploadPolicy,
    component_hashes: &BTreeMap<&'static str, String>,
) -> String {
    let body = snapshot_revision_v2_body(source, item, upload_policy, component_hashes);
    let canonical = crate::canonical_json::canonicalize(&body)
        .expect("snapshot revision v2 body is canonicalizable");
    let mut digest = Sha256::new();
    digest.update(&canonical);
    format!("{:x}", digest.finalize())
}

impl SnapshotItem {
    /// Envelope head-CAS fields: (base, challenge, refused revision, forced).
    /// The backend refuses a base token combined with a challenge; the answer
    /// replaces the stale base rather than adding to it.
    fn cache_handshake(&self) -> (Option<String>, Option<String>, Option<String>, bool) {
        match &self.cache_conflict_answer {
            Some((challenge, revision)) => {
                (None, Some(challenge.clone()), Some(revision.clone()), true)
            }
            None => (self.cache_base_head_etag.clone(), None, None, false),
        }
    }
}

pub(crate) fn snapshot_semantic_envelope(
    source: SnapshotSource,
    item: &SnapshotItem,
    upload_policy: SnapshotUploadPolicy,
) -> SnapshotSemanticEnvelope {
    let component_hashes = snapshot_semantic_component_hashes(source, item);
    let (base_head_etag, conflict_head_challenge, rescan_from_revision_hash, forced_full_rescan) =
        item.cache_handshake();
    SnapshotSemanticEnvelope {
        component_contract_version: SNAPSHOT_SEMANTIC_CONTRACT_VERSION,
        revision_contract_version: SNAPSHOT_REVISION_CONTRACT_VERSION,
        upload_policy,
        revision_hash: snapshot_revision_hash(source, item, &component_hashes),
        revision_v2_contract_version: SNAPSHOT_REVISION_V2_CONTRACT_VERSION,
        revision_v2_canonicalization: crate::canonical_json::CANONICAL_JSON_CONTRACT_VERSION,
        revision_v2_parser_version: source.parser_version(),
        revision_v2_scan_identity_version: source.scan_identity_version(),
        revision_v2_hash: snapshot_revision_v2_hash(source, item, upload_policy, &component_hashes),
        content_hash: snapshot_content_hash(source, &item.source_session_id, &component_hashes),
        hash_epoch: SNAPSHOT_CONTENT_HASH_EPOCH,
        base_head_etag,
        conflict_head_challenge,
        rescan_from_revision_hash,
        forced_full_rescan,
        component_hashes,
    }
}
