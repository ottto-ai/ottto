//! Borrowed observation of one current Claude completion graph. Not a peak
//! permit: future lazy C5/scratch/output growth remains unqualified. No cache
//! admission, event, native read or identity decision consumes these bytes.
use crate::claude_local_otel::{
    ClaudeIdentityAttributeEvidence, ClaudeLocalOtelEvidence, ClaudeLocalOtelLoadReport,
    ClaudeRequestIdentityEvidence, ClaudeTraceOwnershipEvidence, ClaudeTraceOwnershipLoadReport,
};
use crate::heap_layout_bound::{self, Counter, HeapLayoutBound};
use crate::snapshots::{
    claude_request_identity::ScanEvidence, ClaudeUsageAuthorityDisposition, ScanIndex,
    SessionAccountEvidence, SourceScanResult,
};
use std::collections::BTreeMap;
use std::mem::{size_of, size_of_val};

/// Report references must be the same actual owners used to build evidence in
/// the enclosing lexical source completion. No borrowed row referent is walked
/// again through evidence. Real cloned owners remain separate graph roots.
pub(crate) struct BorrowedClaudeCompletion<'frame, 'rows> {
    pub(crate) index: &'frame ScanIndex,
    pub(crate) scan: &'frame SourceScanResult,
    pub(crate) disposition: &'frame ClaudeUsageAuthorityDisposition,
    pub(crate) api: &'frame ClaudeLocalOtelLoadReport,
    pub(crate) trace: &'frame ClaudeTraceOwnershipLoadReport,
    pub(crate) evidence: Option<&'frame ScanEvidence<'rows>>,
    pub(crate) originals: &'frame BTreeMap<String, SessionAccountEvidence>,
}

/// Observes these owned graphs ONCE without allocation. This excludes the
/// preparation/cache owners and future growth; callers cannot treat it as an
/// admission allowance. Unsupported/opaque/over-budget observation is None.
pub(crate) fn observe_owned_completion(
    frame: BorrowedClaudeCompletion<'_, '_>,
    limit: usize,
) -> Option<usize> {
    if frame.index.active_copy_scan.is_none() || !heap_layout_bound::layout_supported() {
        return None;
    }
    let BorrowedClaudeCompletion {
        index,
        scan,
        disposition,
        api,
        trace,
        evidence,
        originals,
    } = frame;
    let mut c = Counter::new(limit);
    c.add(size_of::<ScanIndex>())?;
    index.completed_heap_bound(&mut c)?;
    c.add(size_of::<SourceScanResult>())?;
    scan.completed_claude_heap_bound(&mut c)?;
    c.add(size_of::<ClaudeUsageAuthorityDisposition>())?;
    disposition.completion_owned_heap_bound(&mut c)?;
    reports_owned_heap_bound(api, trace, &mut c, limit)?;
    if let Some(evidence) = evidence {
        c.add(size_of::<ScanEvidence<'_>>())?;
        evidence.completion_owned_heap_bound(&mut c)?;
    }
    c.add(size_of_val(originals))?;
    originals.completed_heap_bound(&mut c)?;
    Some(c.bytes)
}

/// Public report fields permit caller-side accounting without a decoder or
/// private-witness API change. Vec slots own rows; borrowed evidence indices
/// must charge only their own nodes, never these payloads for a second time.
pub(in crate::snapshots) fn reports_owned_heap_bound(
    api: &ClaudeLocalOtelLoadReport,
    trace: &ClaudeTraceOwnershipLoadReport,
    c: &mut Counter,
    limit: usize,
) -> Option<()> {
    let ClaudeLocalOtelLoadReport { evidence, health } = api;
    c.add(size_of_val(api))?;
    heap_layout_bound::tree_nodes::<String, Vec<ClaudeLocalOtelEvidence>>(evidence.len(), c)?;
    for (root, rows) in evidence {
        root.completed_heap_bound(c)?;
        c.add(
            rows.capacity()
                .checked_mul(size_of::<ClaudeLocalOtelEvidence>())?,
        )?;
        borrowed_owned_elements(rows, c, limit, api_row_owned_heap_bound)?;
    }
    let crate::claude_local_otel::ClaudeLocalOtelLoadHealth {
        missing_files,
        malformed_lines,
        unreadable_lines,
        oversized_files,
        invalid_session_rows,
        missing_request_ids,
        conflicting_request_ids,
    } = health;
    for value in [
        missing_files,
        malformed_lines,
        unreadable_lines,
        oversized_files,
        invalid_session_rows,
        missing_request_ids,
    ] {
        value.completed_heap_bound(c)?;
    }
    conflicting_request_ids.completed_heap_bound(c)?;
    let ClaudeTraceOwnershipLoadReport {
        evidence,
        missing_files,
        malformed_lines,
        unreadable_lines,
        oversized_files,
        invalid_session_rows,
        missing_request_ids,
        conflicting_request_ids,
    } = trace;
    for value in [
        missing_files,
        malformed_lines,
        unreadable_lines,
        oversized_files,
        invalid_session_rows,
        missing_request_ids,
    ] {
        value.completed_heap_bound(c)?;
    }
    c.add(size_of_val(trace))?;
    heap_layout_bound::tree_nodes::<String, Vec<ClaudeTraceOwnershipEvidence>>(evidence.len(), c)?;
    for (root, rows) in evidence {
        root.completed_heap_bound(c)?;
        c.add(
            rows.capacity()
                .checked_mul(size_of::<ClaudeTraceOwnershipEvidence>())?,
        )?;
        borrowed_owned_elements(rows, c, limit, trace_row_owned_heap_bound)?;
    }
    conflicting_request_ids.completed_heap_bound(c)
}

fn borrowed_owned_elements<T>(
    rows: &[T],
    c: &mut Counter,
    limit: usize,
    measure: fn(&T, &mut Counter) -> Option<()>,
) -> Option<()> {
    // Same completion composition as the existing owned container models:
    // storage once, ordinary visit guard per element, one checked byte total.
    let mut bytes = 0usize;
    for row in rows {
        let remaining = limit.checked_sub(c.bytes)?.checked_sub(bytes)?;
        let mut child = Counter::new(remaining);
        measure(row, &mut child)?;
        bytes = bytes.checked_add(child.bytes)?;
    }
    c.add(bytes)
}

fn api_row_owned_heap_bound(row: &ClaudeLocalOtelEvidence, c: &mut Counter) -> Option<()> {
    let ClaudeLocalOtelEvidence {
        capture_revision,
        fingerprint,
        session_id,
        request_id,
        client_request_id,
        observed_at,
        model,
        effort,
        query_source,
        speed,
        cost_usd_micros,
        event_sequence,
        app_version,
        input_tokens,
        output_tokens,
        cache_read_tokens,
        cache_creation_tokens,
        cache_creation_5m_tokens,
        cache_creation_1h_tokens,
        reasoning_output_tokens,
        request_count,
        account_identity_checked,
        account_identifier_hash,
        request_identity,
    } = row;
    cost_usd_micros.completed_heap_bound(c)?;
    event_sequence.completed_heap_bound(c)?;
    for value in [
        input_tokens,
        output_tokens,
        cache_read_tokens,
        cache_creation_tokens,
        cache_creation_5m_tokens,
        cache_creation_1h_tokens,
        reasoning_output_tokens,
        request_count,
    ] {
        value.completed_heap_bound(c)?;
    }
    account_identity_checked.completed_heap_bound(c)?;
    for value in [
        capture_revision,
        fingerprint,
        session_id,
        request_id,
        client_request_id,
        observed_at,
        model,
        effort,
        query_source,
        speed,
        app_version,
    ] {
        value.completed_heap_bound(c)?;
    }
    account_identifier_hash.completed_heap_bound(c)?;
    if let Some(identity) = request_identity {
        let ClaudeRequestIdentityEvidence {
            identity_hash_scheme,
            account,
            organization,
            disposition,
        } = identity;
        disposition_inline(disposition, c)?;
        identity_hash_scheme.completed_heap_bound(c)?;
        for attribute in [account, organization] {
            let ClaudeIdentityAttributeEvidence {
                origin,
                disposition,
                resource_hash,
                log_record_hash,
            } = attribute;
            use crate::claude_local_otel::ClaudeIdentityAttributeOrigin;
            match origin {
                ClaudeIdentityAttributeOrigin::Missing
                | ClaudeIdentityAttributeOrigin::Resource
                | ClaudeIdentityAttributeOrigin::LogRecord
                | ClaudeIdentityAttributeOrigin::ResourceAndLogRecord => c.add(0)?,
            }
            disposition_inline(disposition, c)?;
            resource_hash.completed_heap_bound(c)?;
            log_record_hash.completed_heap_bound(c)?;
        }
    }
    Some(())
}

fn trace_row_owned_heap_bound(row: &ClaudeTraceOwnershipEvidence, c: &mut Counter) -> Option<()> {
    let ClaudeTraceOwnershipEvidence {
        capture_revision,
        fingerprint,
        session_id,
        request_id,
        client_request_id,
        agent_id,
        parent_agent_id,
        workflow_run_id,
        observed_at,
    } = row;
    for value in [
        capture_revision,
        fingerprint,
        session_id,
        request_id,
        client_request_id,
        agent_id,
        parent_agent_id,
        workflow_run_id,
        observed_at,
    ] {
        value.completed_heap_bound(c)?;
    }
    Some(())
}

#[cfg(test)]
mod tests;

fn disposition_inline(
    disposition: &crate::claude_local_otel::ClaudeIdentityDisposition,
    c: &mut Counter,
) -> Option<()> {
    use crate::claude_local_otel::ClaudeIdentityDisposition;
    match disposition {
        ClaudeIdentityDisposition::Missing
        | ClaudeIdentityDisposition::Invalid
        | ClaudeIdentityDisposition::Conflict
        | ClaudeIdentityDisposition::Complete => c.add(0),
    }
}
