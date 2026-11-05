//! The Claude usage ledger: legacy request owners, family and ledger
//! reconstruction from the local API and trace rows, the evidence and
//! occurrence fingerprints, transcript-occurrence matching, and the
//! prepared reported usage with its semantic projection.

use crate::snapshots::*;

/// One request's legacy owner: its root and the owner's evidence fingerprint.
#[derive(Clone, Copy)]
struct ClaudeLegacyRequestOwner<'a> {
    root_session_id: &'a str,
    evidence_fingerprint: &'a [u8; 32],
}

/// The legacy owner of each request, keyed by the request id's SHA-256: the
/// root whose own (root-member) API row and trace row claim it. Built root by
/// root in sorted root order, and the first refusal stops it, so the verdict
/// equals one pass over every root. Digests and a root ordinal keep a whole
/// corpus small; the fingerprint hashes the root STRING (kept in `roots`).
#[derive(Default)]
pub(crate) struct ClaudeLegacyRequestOwners {
    roots: Vec<String>,
    owners: BTreeMap<[u8; 32], (u32, [u8; 32])>,
    refusal: Option<IgnoredVeto>,
}

impl std::fmt::Debug for ClaudeLegacyRequestOwners {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClaudeLegacyRequestOwners")
            .field("roots", &self.roots.len())
            .field("owners", &self.owners.len())
            .field("refusal", &self.refusal)
            .finish()
    }
}

impl ClaudeLegacyRequestOwners {
    /// Owned request hashes so far; a diagnostics scalar.
    pub(crate) fn owner_count(&self) -> usize {
        self.owners.len()
    }
    /// Adds one healthy root's rows. Call in sorted root order, once per root
    /// with API rows; after a refusal nothing more is added.
    pub(crate) fn add_root(
        &mut self,
        root_session_id: &str,
        api_rows: &[crate::claude_local_otel::ClaudeLocalOtelEvidence],
        trace_rows: Option<&Vec<crate::claude_local_otel::ClaudeTraceOwnershipEvidence>>,
    ) {
        if self.refusal.is_none() {
            if let Err(refusal) = self.try_add_root(root_session_id, api_rows, trace_rows) {
                self.refusal = Some(refusal);
            }
        }
    }

    fn try_add_root(
        &mut self,
        root_session_id: &str,
        api_rows: &[crate::claude_local_otel::ClaudeLocalOtelEvidence],
        trace_rows: Option<&Vec<crate::claude_local_otel::ClaudeTraceOwnershipEvidence>>,
    ) -> Result<(), IgnoredVeto> {
        let trace_rows = trace_rows.ok_or(IgnoredVeto::EvidenceGap)?;
        let members = std::iter::once(root_session_id.to_owned())
            .chain(
                trace_rows
                    .iter()
                    .filter(|row| !row.agent_id.trim().is_empty())
                    .map(|row| claude_trace_owner_session_id(root_session_id, &row.agent_id)),
            )
            .collect::<BTreeSet<_>>();
        // This graph reads request ids and fingerprints only; the canonical
        // reducer can borrow rows instead of cloning their payload strings.
        let reduced = classify_claude_usage_ledger_with_rows(
            root_session_id,
            &members,
            api_rows,
            trace_rows,
            |row| row,
        )?;
        let trace_by_request = trace_rows
            .iter()
            .map(|row| (row.request_id.as_str(), row))
            .collect::<BTreeMap<_, _>>();
        let root = u32::try_from(self.roots.len()).map_err(|_| IgnoredVeto::EvidenceGap)?;
        self.roots.push(root_session_id.to_owned());
        for row in reduced
            .rows_by_member
            .get(root_session_id)
            .ok_or(IgnoredVeto::EvidenceGap)?
        {
            let trace = trace_by_request
                .get(row.request_id.as_str())
                .ok_or(IgnoredVeto::EvidenceGap)?;
            if !trace.agent_id.trim().is_empty() {
                return Err(IgnoredVeto::EvidenceGap);
            }
            let request_hash = <[u8; 32]>::from(Sha256::digest(row.request_id.as_bytes()));
            let evidence_fingerprint = <[u8; 32]>::from(sha256_digest(&[
                "claude_legacy_request_owner:v1",
                root_session_id,
                crate::hex::encode(&request_hash).as_str(),
                row.fingerprint.as_str(),
                trace.fingerprint.as_str(),
            ]));
            if self
                .owners
                .insert(request_hash, (root, evidence_fingerprint))
                .is_some()
            {
                return Err(IgnoredVeto::MultiRootClaims);
            }
        }
        Ok(())
    }

    /// The owners, or the first refusal that stopped them.
    pub(in crate::snapshots) fn verdict(&self) -> Result<&Self, IgnoredVeto> {
        self.refusal.map_or(Ok(self), Err)
    }

    /// The owner of the request whose SHA-256 hex is `request_hash`.
    fn get(&self, request_hash: &str) -> Option<ClaudeLegacyRequestOwner<'_>> {
        let request_hash =
            claude_request_identity::digest_hex::decode::<serde::de::value::Error>(request_hash)
                .ok()?;
        let (root, evidence_fingerprint) = self.owners.get(&request_hash)?;
        Some(ClaudeLegacyRequestOwner {
            root_session_id: &self.roots[*root as usize],
            evidence_fingerprint,
        })
    }
}

pub(in crate::snapshots) fn classify_claude_legacy_request_owners<'a>(
    api_rows: impl IntoIterator<
        Item = (
            &'a String,
            &'a Vec<crate::claude_local_otel::ClaudeLocalOtelEvidence>,
        ),
    >,
    trace_rows_by_root: &BTreeMap<
        String,
        Vec<crate::claude_local_otel::ClaudeTraceOwnershipEvidence>,
    >,
) -> Result<ClaudeLegacyRequestOwners, IgnoredVeto> {
    let mut owners = ClaudeLegacyRequestOwners::default();
    for (root_session_id, api_rows) in api_rows {
        owners.add_root(
            root_session_id,
            api_rows,
            trace_rows_by_root.get(root_session_id),
        );
    }
    match owners.refusal {
        Some(refusal) => Err(refusal),
        None => Ok(owners),
    }
}

fn claude_legacy_exclusion_evidence_fingerprint(
    child_root: &str,
    excluded_request_id_hashes: &BTreeSet<String>,
    request_owners: &ClaudeLegacyRequestOwners,
) -> Option<String> {
    if excluded_request_id_hashes.is_empty() {
        return None;
    }
    let mut digest = Sha256::new();
    digest.update(b"claude_legacy_usage_exclusion:v1\0");
    digest.update(child_root.as_bytes());
    digest.update(b"\0");
    for request_hash in excluded_request_id_hashes {
        let owner = request_owners.get(request_hash)?;
        if owner.root_session_id == child_root {
            return None;
        }
        digest.update(request_hash.as_bytes());
        digest.update(b"\0");
        digest.update(owner.root_session_id.as_bytes());
        digest.update(b"\0");
        digest.update(crate::hex::encode(owner.evidence_fingerprint).as_bytes());
        digest.update(b"\0");
    }
    Some(format!("{:x}", digest.finalize()))
}

fn validate_claude_legacy_exclusion_witness(
    witness: &ClaudeUsageFamilyWitness,
    request_owners: Option<&ClaudeLegacyRequestOwners>,
) -> bool {
    if witness.legacy_excluded_request_id_hashes.is_empty() {
        return witness.legacy_exclusion_evidence_fingerprint.is_none()
            && witness.legacy_owner_roots.is_empty();
    }
    if witness.legacy_excluded_request_id_hashes.len() != 1 {
        return false;
    }
    let Some((child_root, excluded)) = witness.legacy_excluded_request_id_hashes.first_key_value()
    else {
        return false;
    };
    let Some(owners) = request_owners else {
        return false;
    };
    let actual_owner_roots = excluded
        .iter()
        .filter_map(|request_hash| {
            owners
                .get(request_hash)
                .map(|owner| owner.root_session_id.to_owned())
        })
        .collect::<BTreeSet<_>>();
    actual_owner_roots == witness.legacy_owner_roots
        && claude_legacy_exclusion_evidence_fingerprint(child_root, excluded, owners)
            == witness.legacy_exclusion_evidence_fingerprint
}

pub(in crate::snapshots) fn reconstruct_claude_usage_family(
    root_session_id: &str,
    witness: &ClaudeUsageFamilyWitness,
    api_report: &crate::claude_local_otel::ClaudeLocalOtelLoadReport,
    trace_report: &crate::claude_local_otel::ClaudeTraceOwnershipLoadReport,
    legacy_request_owners: Option<&ClaudeLegacyRequestOwners>,
) -> Option<ProvenClaudeUsageFamily> {
    reconstruct_claude_usage_family_from_rows(
        root_session_id,
        witness,
        api_report.evidence.get(root_session_id)?,
        trace_report.evidence.get(root_session_id)?,
        legacy_request_owners,
    )
}

fn reconstruct_claude_usage_family_from_rows(
    root_session_id: &str,
    witness: &ClaudeUsageFamilyWitness,
    api_rows: &[crate::claude_local_otel::ClaudeLocalOtelEvidence],
    trace_rows: &[crate::claude_local_otel::ClaudeTraceOwnershipEvidence],
    legacy_request_owners: Option<&ClaudeLegacyRequestOwners>,
) -> Option<ProvenClaudeUsageFamily> {
    let reduced = reconstruct_claude_usage_ledger_from_rows(
        root_session_id,
        witness,
        api_rows,
        trace_rows,
        legacy_request_owners,
    )?;
    Some(ProvenClaudeUsageFamily {
        witness: witness.clone(),
        rows_by_member: reduced.rows_by_member,
    })
}

fn reconstruct_claude_usage_ledger_from_rows(
    root_session_id: &str,
    witness: &ClaudeUsageFamilyWitness,
    api_rows: &[crate::claude_local_otel::ClaudeLocalOtelEvidence],
    trace_rows: &[crate::claude_local_otel::ClaudeTraceOwnershipEvidence],
    legacy_request_owners: Option<&ClaudeLegacyRequestOwners>,
) -> Option<ReducedClaudeUsageLedger> {
    reconstruct_claude_usage_ledger_with_rows(
        root_session_id,
        witness,
        api_rows,
        trace_rows,
        legacy_request_owners,
        Clone::clone,
    )
}

fn reconstruct_claude_usage_ledger_with_rows<'a, R>(
    root_session_id: &str,
    witness: &ClaudeUsageFamilyWitness,
    api_rows: &'a [crate::claude_local_otel::ClaudeLocalOtelEvidence],
    trace_rows: &[crate::claude_local_otel::ClaudeTraceOwnershipEvidence],
    legacy_request_owners: Option<&ClaudeLegacyRequestOwners>,
    row_view: impl FnMut(&'a crate::claude_local_otel::ClaudeLocalOtelEvidence) -> R,
) -> Option<ReducedClaudeUsageLedger<R>> {
    let members = witness
        .member_request_id_fingerprints
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    let reduced = reduce_claude_usage_ledger_with_rows(
        root_session_id,
        &members,
        api_rows,
        trace_rows,
        row_view,
    )?;
    let assigned_request_id_fingerprints = reduced
        .assigned_request_id_hashes
        .iter()
        .map(|(member, hashes)| (member.clone(), claude_request_id_set_fingerprint(hashes)))
        .collect::<BTreeMap<_, _>>();
    if reduced.evidence_fingerprint != witness.evidence_fingerprint
        || assigned_request_id_fingerprints != witness.assigned_request_id_fingerprints
        || !validate_claude_legacy_exclusion_witness(witness, legacy_request_owners)
    {
        return None;
    }
    Some(reduced)
}

/// The per-row checks of a strict Claude API sidecar row, in this order:
/// revision, root session, request id, model, one request, evidence
/// fingerprint, RFC 3339 clock. Duplicate request ids are the caller's check.
/// Shared by the live telemetry reducers.
pub(crate) fn validate_claude_api_row(
    row: &crate::claude_local_otel::ClaudeLocalOtelEvidence,
    root_session_id: &str,
) -> bool {
    row.capture_revision == "claude_api_request:v2"
        && row.session_id == root_session_id
        && !row.request_id.is_empty()
        && !row.model.is_empty()
        && row.request_count == 1
        && claude_api_evidence_fingerprint_is_valid(row)
        && OffsetDateTime::parse(&row.observed_at, &Rfc3339).is_ok()
}

pub(in crate::snapshots) fn reduce_claude_usage_ledger_with_rows<'a, R>(
    root_session_id: &str,
    members: &BTreeSet<String>,
    api_rows: &'a [crate::claude_local_otel::ClaudeLocalOtelEvidence],
    trace_rows: &[crate::claude_local_otel::ClaudeTraceOwnershipEvidence],
    row_view: impl FnMut(&'a crate::claude_local_otel::ClaudeLocalOtelEvidence) -> R,
) -> Option<ReducedClaudeUsageLedger<R>> {
    classify_claude_usage_ledger_with_rows(root_session_id, members, api_rows, trace_rows, row_view)
        .ok()
}

fn classify_claude_usage_ledger_with_rows<'a, R>(
    root_session_id: &str,
    members: &BTreeSet<String>,
    api_rows: &'a [crate::claude_local_otel::ClaudeLocalOtelEvidence],
    trace_rows: &[crate::claude_local_otel::ClaudeTraceOwnershipEvidence],
    mut row_view: impl FnMut(&'a crate::claude_local_otel::ClaudeLocalOtelEvidence) -> R,
) -> Result<ReducedClaudeUsageLedger<R>, IgnoredVeto> {
    if !members.contains(root_session_id) || api_rows.is_empty() || trace_rows.is_empty() {
        return Err(IgnoredVeto::EvidenceGap);
    }
    let mut api_by_request = BTreeMap::new();
    for row in api_rows {
        if !validate_claude_api_row(row, root_session_id) {
            return Err(IgnoredVeto::InvalidRows);
        }
        if api_by_request
            .insert(row.request_id.as_str(), row)
            .is_some()
        {
            return Err(IgnoredVeto::DuplicateRows);
        }
    }
    let mut trace_by_request = BTreeMap::new();
    for row in trace_rows {
        if row.capture_revision != "claude_llm_request_ownership:v1"
            || row.session_id != root_session_id
            || row.request_id.is_empty()
            || !claude_trace_evidence_fingerprint_is_valid(row)
            || OffsetDateTime::parse(&row.observed_at, &Rfc3339).is_err()
        {
            return Err(IgnoredVeto::InvalidRows);
        }
        if trace_by_request
            .insert(row.request_id.as_str(), row)
            .is_some()
        {
            return Err(IgnoredVeto::DuplicateRows);
        }
    }
    if api_by_request.keys().ne(trace_by_request.keys()) {
        return Err(IgnoredVeto::EvidenceGap);
    }

    let mut assigned_hashes = members
        .iter()
        .map(|member| (member.clone(), BTreeSet::new()))
        .collect::<BTreeMap<_, _>>();
    let mut rows_by_member = members
        .iter()
        .map(|member| (member.clone(), Vec::new()))
        .collect::<BTreeMap<_, _>>();
    let mut digest = Sha256::new();
    digest.update(b"claude_reported_usage_ledger:v1\0");
    for (request_id, api_row) in api_by_request {
        let trace_row = trace_by_request
            .get(&request_id)
            .ok_or(IgnoredVeto::EvidenceGap)?;
        if !api_row.client_request_id.is_empty()
            && !trace_row.client_request_id.is_empty()
            && api_row.client_request_id != trace_row.client_request_id
        {
            return Err(IgnoredVeto::ClientMismatch);
        }
        let owner = claude_trace_owner_session_id(root_session_id, &trace_row.agent_id);
        if !members.contains(&owner) {
            return Err(IgnoredVeto::EvidenceGap);
        }
        let request_hash = format!("{:x}", Sha256::digest(request_id.as_bytes()));
        assigned_hashes
            .get_mut(&owner)
            .ok_or(IgnoredVeto::EvidenceGap)?
            .insert(request_hash.clone());
        rows_by_member
            .get_mut(&owner)
            .ok_or(IgnoredVeto::EvidenceGap)?
            .push(row_view(api_row));
        digest.update(request_hash.as_bytes());
        digest.update(b"\0");
        digest.update(owner.as_bytes());
        digest.update(b"\0");
        digest.update(api_row.fingerprint.as_bytes());
        digest.update(b"\0");
        digest.update(trace_row.fingerprint.as_bytes());
        digest.update(b"\0");
    }
    Ok(ReducedClaudeUsageLedger {
        evidence_fingerprint: format!("{:x}", digest.finalize()),
        assigned_request_id_hashes: assigned_hashes,
        rows_by_member,
    })
}

pub(in crate::snapshots) fn claude_trace_owner_session_id(
    root_session_id: &str,
    agent_id: &str,
) -> String {
    let agent_id = agent_id.trim();
    if agent_id.is_empty() {
        return root_session_id.to_string();
    }
    let agent_id = agent_id.strip_prefix("agent-").unwrap_or(agent_id);
    format!("{root_session_id}_agent-{agent_id}")
}

/// Hashed once per row: the first caller fills the row's kept result.
pub(in crate::snapshots) fn claude_api_evidence_fingerprint_is_valid(
    row: &crate::claude_local_otel::ClaudeLocalOtelEvidence,
) -> bool {
    row.fingerprint_check.get_or_check(|| {
        let mut canonical = row.clone();
        canonical.fingerprint.clear();
        serialized_json_digest(&canonical, b"")
            .map(|digest| format!("sha256:{:x}", digest.finalize()))
            .as_deref()
            == Some(row.fingerprint.as_str())
    })
}

pub(in crate::snapshots) fn claude_trace_evidence_fingerprint_is_valid(
    row: &crate::claude_local_otel::ClaudeTraceOwnershipEvidence,
) -> bool {
    let mut canonical = row.clone();
    canonical.fingerprint.clear();
    serialized_json_digest(&canonical, b"")
        .map(|digest| format!("sha256:{:x}", digest.finalize()))
        .as_deref()
        == Some(row.fingerprint.as_str())
}

pub(in crate::snapshots) fn claude_snapshot_request_id_hashes(
    item: &SnapshotItem,
) -> Option<BTreeSet<String>> {
    let expected = usize::try_from(item.request_count).ok()?;
    if expected == 0 || item.claude_usage_request_ids.len() != expected {
        return None;
    }
    Some(
        item.claude_usage_request_ids
            .iter()
            .map(|request_id| format!("{:x}", Sha256::digest(request_id.as_bytes())))
            .collect(),
    )
}

pub(in crate::snapshots) fn claude_request_id_set_fingerprint(
    request_id_hashes: &BTreeSet<String>,
) -> String {
    let mut digest = Sha256::new();
    digest.update(b"claude_request_id_set:v1\0");
    for request_id_hash in request_id_hashes {
        digest.update(request_id_hash.as_bytes());
        digest.update(b"\0");
    }
    format!("{:x}", digest.finalize())
}

pub(in crate::snapshots) fn claude_occurrence_map_fingerprint(
    occurrences: &BTreeMap<String, ClaudeTranscriptUsageOccurrenceWitness>,
) -> String {
    let domain = b"claude_transcript_occurrence_map:v1\0";
    let digest = serialized_json_digest(occurrences, domain).unwrap_or_else(|| {
        // Preserve the old to_vec(...).unwrap_or_default() error result.
        let mut digest = Sha256::new();
        digest.update(domain);
        digest
    });
    format!("{:x}", digest.finalize())
}

// The same canonical serde_json bytes go directly into SHA-256. This replaces
// the discarded Vec used only for hashing; no body, witness or serialization
// schema is changed, and no second projection is built for resource pricing.
pub(in crate::snapshots) fn serialized_json_digest<T: Serialize + ?Sized>(
    value: &T,
    domain: &[u8],
) -> Option<Sha256> {
    struct DigestWriter(Sha256);
    impl std::io::Write for DigestWriter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.update(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut writer = DigestWriter(Sha256::new());
    writer.0.update(domain);
    serde_json::to_writer(&mut writer, value).ok()?;
    Some(writer.0)
}

// Counts rejected interpretations, not unique requests: the same row can be
// checked during proof, account coverage and rebuild. No content or identity is
// retained, and this diagnostic never participates in an authority decision.
crate::local_resource_diagnostics::process_static!(fn with_claude_api_cache_creation_rejections:
    std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0));

pub(crate) fn claude_api_cache_creation_rejection_count() -> u64 {
    with_claude_api_cache_creation_rejections(|counter| {
        counter.load(std::sync::atomic::Ordering::Relaxed)
    })
}

/// New writers repeat the aggregate as a TTL split. Older writers expose only
/// the aggregate; preserve it without inventing a TTL. Contradictions and
/// overflow cannot authorize usage, even if their additive value would match.
pub(in crate::snapshots) fn claude_api_cache_creation(
    row: &crate::claude_local_otel::ClaudeLocalOtelEvidence,
) -> Option<(u64, u64, u64)> {
    use claude_request_money::CacheCreation;
    let interpreted = match claude_request_money::claude_cache_creation(
        row.cache_creation_tokens,
        row.cache_creation_5m_tokens,
        row.cache_creation_1h_tokens,
    ) {
        CacheCreation::Split { five_m, one_h } => Some((five_m, one_h, 0)),
        CacheCreation::Unattributed(total) => Some((0, 0, total)),
        CacheCreation::Contradictory => None,
    };
    if interpreted.is_none() {
        with_claude_api_cache_creation_rejections(|counter| {
            let _ = counter.fetch_update(
                std::sync::atomic::Ordering::Relaxed,
                std::sync::atomic::Ordering::Relaxed,
                |count| count.checked_add(1),
            );
        });
    }
    interpreted
}

/// Borrowed compatibility inputs: the live witness and `e2` use one predicate.
#[derive(Clone, Copy)]
pub(crate) struct ClaudeTranscriptUsageOccurrenceView<'a> {
    input_tokens: u64,
    output_tokens: u64,
    cache_read_tokens: u64,
    cache_creation_5m_tokens: u64,
    cache_creation_1h_tokens: u64,
    reasoning_output_tokens: u64,
    model: Option<&'a str>,
    speed_mode: Option<&'a str>,
    reasoning_effort: Option<&'a str>,
}
impl<'a> From<&'a ClaudeTranscriptUsageOccurrenceWitness>
    for ClaudeTranscriptUsageOccurrenceView<'a>
{
    fn from(o: &'a ClaudeTranscriptUsageOccurrenceWitness) -> Self {
        Self {
            input_tokens: o.input_tokens,
            output_tokens: o.output_tokens,
            cache_read_tokens: o.cache_read_tokens,
            cache_creation_5m_tokens: o.cache_creation_5m_tokens,
            cache_creation_1h_tokens: o.cache_creation_1h_tokens,
            reasoning_output_tokens: o.reasoning_output_tokens,
            model: o.model.as_deref(),
            speed_mode: o.speed_mode.as_deref(),
            reasoning_effort: o.reasoning_effort.as_deref(),
        }
    }
}
impl<'a> From<&'a ClaudeTranscriptUsageOccurrence> for ClaudeTranscriptUsageOccurrenceView<'a> {
    fn from(o: &'a ClaudeTranscriptUsageOccurrence) -> Self {
        Self {
            input_tokens: o.usage.input_tokens,
            output_tokens: o.usage.output_tokens,
            cache_read_tokens: o.usage.cache_read_tokens,
            cache_creation_5m_tokens: o.usage.cache_creation_5m_tokens,
            cache_creation_1h_tokens: o.usage.cache_creation_1h_tokens,
            reasoning_output_tokens: o.usage.reasoning_output_tokens,
            model: o.model.as_deref(),
            speed_mode: o.selector.context.get("speed_mode").map(String::as_str),
            reasoning_effort: o.reasoning_effort.as_deref(),
        }
    }
}

pub(crate) fn claude_api_matches_transcript_occurrence<'a>(
    row: &crate::claude_local_otel::ClaudeLocalOtelEvidence,
    occurrence: impl Into<ClaudeTranscriptUsageOccurrenceView<'a>>,
) -> bool {
    let occurrence = occurrence.into();
    let Some(api_cache_creation) =
        claude_api_cache_creation(row).and_then(|(five_m, one_h, unattributed)| {
            five_m.checked_add(one_h)?.checked_add(unattributed)
        })
    else {
        return false;
    };
    let transcript_cache_creation = occurrence
        .cache_creation_5m_tokens
        .checked_add(occurrence.cache_creation_1h_tokens);
    let reported_speed = (!row.speed.trim().is_empty())
        .then(|| normalize_selector_raw("speed_mode", &Value::String(row.speed.clone())))
        .flatten();
    let speed_matches = occurrence
        .speed_mode
        .zip(reported_speed.as_deref())
        .map_or(true, |(transcript, reported)| transcript == reported);
    let reported_effort = CLAUDE_EFFORT_TIERS
        .contains(&row.effort.as_str())
        .then_some(row.effort.as_str());
    let effort_matches = occurrence
        .reasoning_effort
        .zip(reported_effort)
        .map_or(true, |(transcript, reported)| transcript == reported);
    row.input_tokens == occurrence.input_tokens
        && row.output_tokens == occurrence.output_tokens
        && row.cache_read_tokens == occurrence.cache_read_tokens
        && claude_api_reasoning_matches(
            row.reasoning_output_tokens,
            occurrence.reasoning_output_tokens,
        )
        && Some(api_cache_creation) == transcript_cache_creation
        && occurrence.model.map_or(true, |model| model == row.model)
        && speed_matches
        && effort_matches
}

/// Claude Code's `api_request` event carries no thinking count, so the sidecar
/// reports 0 while the transcript holds the real count. Only a count the
/// sidecar actually reported must equal the transcript's.
pub(in crate::snapshots) fn claude_api_reasoning_matches(
    reported: impl Into<u128>,
    transcript: impl Into<u128>,
) -> bool {
    let reported = reported.into();
    reported == 0 || reported == transcript.into()
}

/// After an account owner retags rows. `e2` (gate on): the fold holds the
/// per-hour rows until emission, so the session rows are the body's only
/// rows and the owner has tagged them; rebuilding from no buckets would
/// drop them.
pub(in crate::snapshots) fn rebuild_retagged_model_usage(item: &mut SnapshotItem) {
    if item.usage_buckets.is_empty() && item.claude_money.is_some() {
        return;
    }
    rebuild_snapshot_model_usage(item);
}

fn rebuild_snapshot_model_usage(item: &mut SnapshotItem) {
    rebuild_snapshot_model_usage_with(item, &mut SelectorHashes::default());
}

pub(in crate::snapshots) fn rebuild_snapshot_model_usage_with(
    item: &mut SnapshotItem,
    hashes: &mut SelectorHashes,
) {
    let account_hashes = item
        .usage_buckets
        .iter()
        .flat_map(|bucket| &bucket.model_usage)
        .filter_map(|row| row.account_identifier_hash.as_deref())
        .collect::<BTreeSet<_>>();
    let has_missing_account_hash = item
        .usage_buckets
        .iter()
        .flat_map(|bucket| &bucket.model_usage)
        .any(|row| row.account_identifier_hash.is_none());
    let account_identifier_hash = (!has_missing_account_hash && account_hashes.len() == 1)
        .then(|| account_hashes.first().map(|value| (*value).to_string()))
        .flatten();
    drop(account_hashes);
    let mut session_rows: BTreeMap<RowKey, BucketRowAccumulator> = BTreeMap::new();
    for bucket in &item.usage_buckets {
        for row in &bucket.model_usage {
            let key = hashes.row_key(row);
            merge_session_row(
                &mut session_rows,
                key,
                BucketRowAccumulator {
                    selector_context: row.selector_context.clone(),
                    selector_sources: row.selector_sources.clone(),
                    usage: usage_totals_from_model_usage(row),
                    reasoning_effort: row.reasoning_effort.clone(),
                },
            );
        }
    }
    item.model_usage = session_rows
        .iter()
        .map(|(key, row)| model_usage_from_row(key, row))
        .collect();
    for row in &mut item.model_usage {
        row.account_identifier_hash = account_identifier_hash.clone();
    }
}

pub(in crate::snapshots) fn claude_reported_usage_inputs<'a>(
    item: &SnapshotItem,
    family: &'a ProvenClaudeUsageFamily,
) -> Option<(
    &'a [crate::claude_local_otel::ClaudeLocalOtelEvidence],
    BTreeSet<String>,
)> {
    claude_reported_usage_inputs_from_rows(item, &family.witness, &family.rows_by_member)
}

fn claude_reported_usage_inputs_from_rows<'a, R>(
    item: &SnapshotItem,
    witness: &ClaudeUsageFamilyWitness,
    rows_by_member: &'a BTreeMap<String, Vec<R>>,
) -> Option<(&'a [R], BTreeSet<String>)> {
    let rows = rows_by_member.get(&item.source_session_id)?;
    let excluded_request_hashes = witness
        .legacy_excluded_request_id_hashes
        .get(&item.source_session_id)
        .cloned()
        .unwrap_or_default();
    let request_hashes = item
        .claude_usage_request_ids
        .iter()
        .map(|request_id| format!("{:x}", Sha256::digest(request_id.as_bytes())))
        .filter(|request_hash| !excluded_request_hashes.contains(request_hash))
        .collect::<BTreeSet<_>>();
    if witness
        .member_request_id_fingerprints
        .get(&item.source_session_id)
        != Some(&claude_request_id_set_fingerprint(&request_hashes))
    {
        return None;
    }
    let current_occurrences = item
        .claude_usage_occurrences
        .iter()
        .map(|(request_id, occurrence)| {
            (
                format!("{:x}", Sha256::digest(request_id.as_bytes())),
                ClaudeTranscriptUsageOccurrenceWitness::from(occurrence),
            )
        })
        .filter(|(request_hash, _)| !excluded_request_hashes.contains(request_hash))
        .collect::<BTreeMap<_, _>>();
    if witness
        .member_occurrence_fingerprints
        .get(&item.source_session_id)
        != Some(&claude_occurrence_map_fingerprint(&current_occurrences))
    {
        return None;
    }
    Some((rows, excluded_request_hashes))
}

struct PreparedClaudeReportedUsage {
    totals: UsageTotals,
    model_usage: Vec<SnapshotModelUsage>,
    usage_buckets: Vec<SnapshotUsageBucket>,
    reported_activity: UsageBucketState,
    cost: Option<SnapshotCost>,
}

fn prepare_claude_reported_usage<
    R: std::borrow::Borrow<crate::claude_local_otel::ClaudeLocalOtelEvidence>,
>(
    item: &SnapshotItem,
    rows: &[R],
    excluded_request_hashes: &BTreeSet<String>,
    mut sink: Option<&mut claude_request_identity::RequestSink<'_, '_>>,
) -> Option<PreparedClaudeReportedUsage> {
    let row_refs = || rows.iter().map(std::borrow::Borrow::borrow);
    let owned_request_ids = item
        .claude_usage_request_ids
        .iter()
        .filter(|request_id| {
            !excluded_request_hashes
                .contains(&format!("{:x}", Sha256::digest(request_id.as_bytes())))
        })
        .collect::<BTreeSet<_>>();
    if rows.is_empty()
        || item.claude_usage_occurrences.len() != item.claude_usage_request_ids.len()
        || owned_request_ids.is_empty()
        || !owned_request_ids
            .iter()
            .all(|request_id| row_refs().any(|row| row.request_id == request_id.as_str()))
        || row_refs().any(|row| {
            excluded_request_hashes
                .contains(&format!("{:x}", Sha256::digest(row.request_id.as_bytes())))
        })
    {
        return None;
    }
    let account_hashes = row_refs()
        .filter_map(|row| row.account_identifier_hash.as_deref())
        .collect::<BTreeSet<_>>();
    let account_identifier_hash = (row_refs().all(|row| row.account_identity_checked)
        && account_hashes.len() == 1)
        .then(|| account_hashes.first().map(|value| (*value).to_string()))
        .flatten();
    let mut totals = UsageTotals::default();
    let mut buckets: BTreeMap<String, UsageBucketState> = BTreeMap::new();
    let mut total_cost_picos = 0_u128;
    let mut cost_complete = true;

    for row in row_refs() {
        let (cache_5m, cache_1h, cache_unattributed) = claude_api_cache_creation(row)?;
        let api_cache_creation = cache_5m
            .checked_add(cache_1h)?
            .checked_add(cache_unattributed)?;
        let cost_picos = row
            .cost_usd_micros
            .map(u128::from)
            .and_then(|value| value.checked_mul(1_000_000));
        if let Some(cost_picos) = cost_picos {
            total_cost_picos = total_cost_picos.checked_add(cost_picos)?;
        } else {
            cost_complete = false;
        }
        let occurrence = item.claude_usage_occurrences.get(&row.request_id);
        let mut selector = occurrence
            .map(|occurrence| SelectorCapture::clone(&occurrence.selector))
            .unwrap_or_default();
        if !row.speed.trim().is_empty() {
            let normalized_speed =
                normalize_selector_raw("speed_mode", &Value::String(row.speed.clone()));
            if normalized_speed.as_ref().is_some_and(|speed| {
                selector
                    .context
                    .get("speed_mode")
                    .is_some_and(|existing| existing != speed)
            }) {
                return None;
            }
            insert_selector_raw(
                &mut selector,
                "speed_mode",
                "claude_code.api_request.speed",
                &Value::String(row.speed.clone()),
            );
        }
        let reported_effort = CLAUDE_EFFORT_TIERS
            .contains(&row.effort.as_str())
            .then(|| row.effort.clone());
        if occurrence
            .and_then(|occurrence| occurrence.reasoning_effort.as_deref())
            .zip(reported_effort.as_deref())
            .is_some_and(|(transcript, reported)| transcript != reported)
        {
            return None;
        }
        let effort = occurrence
            .and_then(|occurrence| occurrence.reasoning_effort.clone())
            .or(reported_effort);
        let (mut usage, model, timestamp) = if let Some(occurrence) = occurrence {
            let transcript_cache_creation = occurrence
                .usage
                .cache_creation_5m_tokens
                .checked_add(occurrence.usage.cache_creation_1h_tokens);
            if row.input_tokens != occurrence.usage.input_tokens
                || row.output_tokens != occurrence.usage.output_tokens
                || row.cache_read_tokens != occurrence.usage.cache_read_tokens
                || !claude_api_reasoning_matches(
                    row.reasoning_output_tokens,
                    occurrence.usage.reasoning_output_tokens,
                )
                || Some(api_cache_creation) != transcript_cache_creation
                || occurrence
                    .model
                    .as_deref()
                    .is_some_and(|model| model != row.model)
            {
                return None;
            }
            (
                occurrence.usage.clone(),
                occurrence
                    .model
                    .clone()
                    .unwrap_or_else(|| row.model.clone()),
                occurrence
                    .timestamp
                    .clone()
                    .unwrap_or_else(|| row.observed_at.clone()),
            )
        } else {
            (
                UsageTotals {
                    input_tokens: row.input_tokens,
                    output_tokens: row.output_tokens,
                    cache_read_tokens: row.cache_read_tokens,
                    cache_creation_5m_tokens: cache_5m,
                    cache_creation_1h_tokens: cache_1h,
                    reasoning_output_tokens: row.reasoning_output_tokens,
                    // Aggregate-only writers cannot supply an honest TTL split.
                    unattributed_total_tokens: cache_unattributed,
                    request_count: 1,
                    costs: UsageCosts::default(),
                },
                row.model.clone(),
                row.observed_at.clone(),
            )
        };
        usage.request_count = 1;
        usage.costs = cost_picos.map_or_else(UsageCosts::default, |cost_picos| UsageCosts {
            observed: true,
            reported: true,
            total: Some(cost_picos),
            input: None,
            output: None,
            cache_read: None,
            cache_creation: None,
        });
        if !totals.add(&usage) {
            return None;
        }
        let (bucket_start, normalized_timestamp) = activity_bucket_from_timestamp(&timestamp)?;
        let (row_key, selector_context, selector_sources) =
            build_row_identity(&model, &selector, effort.as_deref());
        if let Some(sink) = sink.as_deref_mut() {
            sink.add(
                item,
                claude_request_identity::Request {
                    request_id: &row.request_id,
                    occurrence: occurrence
                        .map(|occurrence| (occurrence.sequence, occurrence.event_clock_complete)),
                    timestamp: &timestamp,
                    bucket_start: &bucket_start,
                    row_key: &row_key,
                    usage: &usage,
                },
            );
        }
        let bucket = buckets.entry(bucket_start).or_default();
        bucket.note_activity_at(&normalized_timestamp);
        match bucket.rows.get_mut(&row_key) {
            Some(existing) => {
                for (field, source) in selector_sources {
                    existing.selector_sources.insert(field, source);
                }
                if !existing.usage.add(&usage) {
                    return None;
                }
            }
            None => {
                bucket.rows.insert(
                    row_key,
                    BucketRowAccumulator {
                        selector_context,
                        selector_sources,
                        usage,
                        reasoning_effort: effort,
                    },
                );
            }
        }
    }

    let mut reported_activity = UsageBucketState::default();
    for bucket in buckets.values() {
        if let Some(first_activity_at) = bucket.first_activity_at.as_deref() {
            reported_activity.note_activity_at(first_activity_at);
        }
        if let Some(last_activity_at) = bucket.last_activity_at.as_deref() {
            reported_activity.note_activity_at(last_activity_at);
        }
    }
    let mut session_rows = BTreeMap::new();
    let mut usage_buckets = Vec::new();
    for (bucket_start, bucket) in buckets {
        let mut model_usage = Vec::new();
        for (row_key, row) in bucket.rows {
            let mut wire_row = model_usage_from_row(&row_key, &row);
            wire_row.account_identifier_hash = account_identifier_hash.clone();
            model_usage.push(wire_row);
            merge_session_row(&mut session_rows, row_key, row);
        }
        usage_buckets.push(SnapshotUsageBucket {
            bucket_start,
            model_usage,
            first_activity_at: bucket.first_activity_at,
            last_activity_at: bucket.last_activity_at,
        });
    }
    if session_rows.is_empty() {
        return None;
    }
    let mut model_usage = session_rows
        .iter()
        .map(|(row_key, row)| model_usage_from_row(row_key, row))
        .collect::<Vec<_>>();
    for row in &mut model_usage {
        row.account_identifier_hash = account_identifier_hash.clone();
    }
    Some(PreparedClaudeReportedUsage {
        totals,
        model_usage,
        usage_buckets,
        reported_activity,
        cost: cost_complete.then(|| SnapshotCost {
            total_cost_usd: Some(usd_picos_string(total_cost_picos)),
            input_cost_usd: None,
            output_cost_usd: None,
            cache_read_cost_usd: None,
            cache_creation_cost_usd: None,
            evidence_source: "claude_code_api_request".to_string(),
        }),
    })
}

pub(in crate::snapshots) fn rebuild_claude_reported_usage(
    item: &mut SnapshotItem,
    rows: &[crate::claude_local_otel::ClaudeLocalOtelEvidence],
    excluded_request_hashes: &BTreeSet<String>,
    sink: Option<&mut claude_request_identity::RequestSink<'_, '_>>,
) -> bool {
    let Some(PreparedClaudeReportedUsage {
        totals,
        model_usage,
        usage_buckets,
        reported_activity,
        cost,
    }) = prepare_claude_reported_usage(item, rows, excluded_request_hashes, sink)
    else {
        return false;
    };
    item.input_tokens = totals.input_tokens;
    item.output_tokens = totals.output_tokens;
    item.cache_read_tokens = totals.cache_read_tokens;
    item.cache_creation_5m_tokens = totals.cache_creation_5m_tokens;
    item.cache_creation_1h_tokens = totals.cache_creation_1h_tokens;
    item.reasoning_output_tokens = totals.reasoning_output_tokens;
    item.unattributed_total_tokens = totals.unattributed_total_tokens;
    item.request_count = totals.request_count;
    item.model_usage = model_usage;
    item.usage_buckets = usage_buckets;
    if let Some(first_activity_at) = reported_activity.first_activity_at {
        if item.source_started_at.as_ref().map_or(true, |current| {
            timestamp_is_before(&first_activity_at, current)
        }) {
            item.source_started_at = Some(first_activity_at);
        }
    }
    if let Some(last_activity_at) = reported_activity.last_activity_at {
        if item
            .source_last_activity_at
            .as_ref()
            .map_or(true, |current| {
                timestamp_is_after(&last_activity_at, current)
            })
        {
            item.source_last_activity_at = Some(last_activity_at.clone());
        }
        if item
            .source_ended_at
            .as_ref()
            .is_some_and(|current| timestamp_is_after(&last_activity_at, current))
        {
            item.source_ended_at = Some(last_activity_at);
        }
    }
    item.cost = cost;
    true
}

fn semantic_attribution_facts(item: &SnapshotItem) -> Vec<Value> {
    let mut facts = item
        .attribution_facts
        .iter()
        .map(|fact| {
            json!({
                "field": &fact.field,
                "value": &fact.value,
                "display_label": &fact.display_label,
                "display_label_source": &fact.display_label_source,
                "evidence_kind": &fact.evidence.kind,
                "evidence_strength": &fact.evidence.strength,
            })
        })
        .collect::<Vec<_>>();
    facts.sort_by_key(Value::to_string);
    facts
}

pub(in crate::snapshots) fn semantic_attribution(item: &SnapshotItem) -> Value {
    #[cfg(not(test))]
    let identity_collector = claude_request_identity::COLLECTOR;
    #[cfg(test)]
    let identity_collector = claude_request_identity::cycle_contract(true);
    let account_identifier_hashes = item
        .model_usage
        .iter()
        .chain(
            item.usage_buckets
                .iter()
                .flat_map(|bucket| bucket.model_usage.iter()),
        )
        .filter_map(|row| row.account_identifier_hash.as_deref())
        .collect::<BTreeSet<_>>();
    let mut value = json!({
        "origin": &item.origin,
        "facts": semantic_attribution_facts(item),
    });
    if matches!(
        item.provenance.collector.as_str(),
        claude_request_accounts::COMPLETE
            | claude_request_accounts::UNKNOWN
            | claude_request_accounts::MIXED
    ) || item.provenance.collector == identity_collector
    {
        value
            .as_object_mut()
            .expect("semantic attribution is an object")
            .insert(
                "request_account_coverage".to_string(),
                json!(item.provenance.collector),
            );
    }
    if !account_identifier_hashes.is_empty() {
        value
            .as_object_mut()
            .expect("semantic attribution is an object")
            .insert(
                "account_identifier_hashes".to_string(),
                json!(account_identifier_hashes),
            );
    }
    value
}

pub(in crate::snapshots) fn semantic_model_usage(row: &SnapshotModelUsage) -> Value {
    // `account_identifier_hash` remains outside hash epoch 1. The account-keyed
    // Claude sidecar fingerprint changes `source_file_fingerprint`, and thus
    // `revision_hash`, when exact evidence appears; changing epoch-1 content
    // semantics would reject older clients that already use this wire field.
    let mut value = json!({
        "model": &row.model,
        "input_tokens": row.input_tokens,
        "output_tokens": row.output_tokens,
        "cache_read_tokens": row.cache_read_tokens,
        "cache_creation_5m_tokens": row.cache_creation_5m_tokens,
        "cache_creation_1h_tokens": row.cache_creation_1h_tokens,
        "reasoning_output_tokens": row.reasoning_output_tokens,
        "reasoning_effort": &row.reasoning_effort,
        "unattributed_total_tokens": row.unattributed_total_tokens,
        "request_count": row.request_count,
        "selector_context": &row.selector_context,
        "selector_sources": &row.selector_sources,
        "auth_mode": &row.auth_mode,
        "billing_channel": &row.billing_channel,
        "billing_provider": &row.billing_provider,
        "gateway_provider": &row.gateway_provider,
        "model_provider": &row.model_provider,
        "subscription_product": &row.subscription_product,
        "cost_usd": &row.cost_usd,
        "input_cost_usd": &row.input_cost_usd,
        "output_cost_usd": &row.output_cost_usd,
        "cache_read_cost_usd": &row.cache_read_cost_usd,
        "cache_creation_cost_usd": &row.cache_creation_cost_usd,
    });
    if row.copy_unproven {
        value["copy_unproven"] = json!(true);
    }
    value
}

pub(in crate::snapshots) fn semantic_usage_buckets(item: &SnapshotItem) -> Vec<Value> {
    item.usage_buckets
        .iter()
        .map(|bucket| {
            json!({
                "bucket_start": &bucket.bucket_start,
                "model_usage": bucket.model_usage.iter().map(semantic_model_usage).collect::<Vec<_>>(),
                "first_activity_at": &bucket.first_activity_at,
                "last_activity_at": &bucket.last_activity_at,
            })
        })
        .collect()
}
