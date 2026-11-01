// Closed, pinned requested-layout bound for stripped ordinary typed pages.
use crate::session_attribution::{SessionAttributionFact, SessionFieldEvidence};
use crate::snapshots::*;
use std::collections::BTreeMap;
use std::mem::size_of;
pub(crate) const HEAP_CAP: usize = 4 * 1024 * 1024;
pub(crate) const PROOF_RESERVE: usize = 128 * 1024;
pub(crate) struct Budget {
    pub bytes: usize,
    pub cap: usize,
}
impl Budget {
    fn add(&mut self, bytes: usize) -> Option<()> {
        self.bytes = self.bytes.checked_add(bytes)?;
        if self.bytes > self.cap {
            return None;
        }
        Some(())
    }
}
trait Bound {
    fn heap(&self, b: &mut Budget) -> Option<()>;
}
macro_rules! scalars { ($($t:ty),*) => { $(impl Bound for $t {
    fn heap(&self, _: &mut Budget) -> Option<()> { Some(()) }
})* }; }
scalars!(bool, u8, u16, u32, u64, i64, usize, f64, &'static str);
scalars!(AccountSource);
impl Bound for String {
    fn heap(&self, b: &mut Budget) -> Option<()> {
        b.add(self.len())
    }
}
impl<T: Bound> Bound for Option<T> {
    fn heap(&self, b: &mut Budget) -> Option<()> {
        match self {
            Some(v) => v.heap(b),
            None => Some(()),
        }
    }
}
impl<T: Bound> Bound for Vec<T> {
    fn heap(&self, b: &mut Budget) -> Option<()> {
        b.add(self.len().checked_mul(size_of::<T>())?)?;
        for v in self {
            v.heap(b)?;
        }
        Some(())
    }
}
impl<T: Bound> Bound for Box<T> {
    fn heap(&self, b: &mut Budget) -> Option<()> {
        b.add(size_of::<T>())?;
        (**self).heap(b)
    }
}
impl<K: Bound, V: Bound> Bound for BTreeMap<K, V> {
    fn heap(&self, b: &mut Budget) -> Option<()> {
        // Closed ordinary schema uses String/String. On rustc1.88 every nonempty
        // clone node owns at least one of N pairs, so retained node count<=N.
        // An empty map may own one empty root. 1024B dominates the <=64B pair,
        // capacity11 arrays, header/padding and12 pointers (align<=8).
        if size_of::<K>() + size_of::<V>() > 64
            || std::mem::align_of::<K>() > 8
            || std::mem::align_of::<V>() > 8
        {
            return None;
        }
        b.add(self.len().max(1).checked_mul(1024)?)?;
        for (k, v) in self {
            k.heap(b)?;
            v.heap(b)?;
        }
        Some(())
    }
}
macro_rules! fields {
    ($t:ty; [$($skip:ident),*]; $($f:ident),*) => {
        impl Bound for $t { fn heap(&self,b:&mut Budget)->Option<()> {
            let Self { $($skip:_,)* $($f,)* } = self;
            $( $f.heap(b)?; )* Some(())
        } }
    }
}
fields!(SnapshotItem; [claude_usage_request_ids,claude_usage_occurrences,claude_org_markers,cache_observations,cache_observations_state,cache_base_head_etag,cache_requests,cache_requests_complete,claude_context_curve_boundaries,claude_context_curve_identity_complete,claude_context_curve_request_index_complete,claude_context_curve_owned_start_proven,claude_file_birth,claude_file_birth_verdict,claude_money,local_context_points]; session_account_evidence,source_session_id,snapshot_fingerprint,status,input_tokens,output_tokens,cache_read_tokens,cache_creation_5m_tokens,cache_creation_1h_tokens,reasoning_output_tokens,unattributed_total_tokens,request_count,usage_accounting_contract,removed_request_count,removed_usage,telemetry_owned_complete,resolver_conflict_count,copy_unproven_counts,avg_duration_ms,avg_time_to_first_token_ms,max_duration_ms,max_time_to_first_token_ms,peak_context_fill_tokens,first_turn_context_tokens,last_turn_context_tokens,first_turn_context_window_tokens,peak_context_fill_window_tokens,last_turn_context_window_tokens,compaction_count,compaction_timestamps,compaction_events,first_own_request_at,compaction_total_pre_tokens,compaction_total_post_tokens,compaction_total_cumulative_dropped_tokens,compaction_total_duration_ms,context_curve,activity_summary,tool_usage,tool_usage_truncated,session_start,model_usage,usage_buckets,cost,session_display_name,session_display_name_source,source_started_at,source_ended_at,source_last_activity_at,collected_at,workspace_hash,workspace_display_label,workspace_label_source,repository_hash,repository_label,repository_label_source,repository_identity_source,workspace_kind,source_file_fingerprint,session_artifacts,provenance,origin,originator,attribution_facts,request_evidence,request_identity_refusals,claude_account_withheld_reason,claude_account_display);
fields!(SnapshotCompactionEvent; []; at,before,after,trigger);
fields!(SnapshotSessionStart; []; client_version,user_turn_count,first_request_uncached_input_tokens,first_request_cache_read_tokens,first_request_cache_write_5m_tokens,first_request_cache_write_1h_tokens,opening_request_count,request_2_context_tokens,request_3_context_tokens,opening_output_tokens,opening_tool_calls,opening_truncated_outputs,opening_files,opening_file_overflow,instruction_load_cut,start_parts_method,start_chars_tools,start_chars_system,start_chars_instructions,start_chars_memory,start_chars_skills,start_chars_agents,start_chars_mcp_names,start_chars_mcp_instructions,start_chars_hooks_env,start_chars_prompt,start_chars_other,start_config_fingerprint,file_candidates,files_over_guard,policy_applied,opening_files_unknown);
fields!(SnapshotOpeningFile; []; request,tool,repo_path,path_hash,ext,chars,reads,instruction_segments,client_loaded,truncated);
fields!(OpeningFileCandidate; []; row,repo_path,path_hash,ext);
fields!(SnapshotOrigin; [parent_session_ref]; thread_source,source,source_subagent,originator,agent_role,entrypoint,is_sidechain,session_kind,used_workflow_orchestration);
fields!(SnapshotActivityCount; []; name,count);
fields!(SnapshotToolUsage; []; name,count);
fields!(SnapshotCapabilityCount; []; capability_id,raw_origin,count);
fields!(SnapshotCapabilityBucket; []; bucket_start,capability_id,raw_origin,call_count);
fields!(SnapshotActivitySummary; []; capability_collection_version,tool_calls,shell_commands,patch_operations,changed_files,lines_added,lines_deleted,web_searches,mcp_calls,subagent_spawns,tool_counts,mcp_tool_counts,capability_counts,capability_buckets,skills);
fields!(SessionAccountEvidence; []; provider,account_identifier_hash,provider_workspace_hash,identity_hash_scheme,evidence_source,identity_disposition,source_created_at);
fields!(SnapshotUsageBucket; []; bucket_start,model_usage,first_activity_at,last_activity_at);
fields!(SnapshotModelUsage; []; copy_unproven,model,input_tokens,output_tokens,cache_read_tokens,cache_creation_5m_tokens,cache_creation_1h_tokens,reasoning_output_tokens,reasoning_effort,unattributed_total_tokens,request_count,selector_context,selector_sources,auth_mode,billing_channel,billing_provider,gateway_provider,model_provider,subscription_product,account_identifier_hash,evidence_ref,identity_parts,identity_retained,copy_invalidated,cost_usd,input_cost_usd,output_cost_usd,cache_read_cost_usd,cache_creation_cost_usd);
fields!(SnapshotIdentityPart; []; account_identifier_hash,evidence_ref,input_tokens,output_tokens,cache_read_tokens,cache_creation_5m_tokens,cache_creation_1h_tokens,reasoning_output_tokens,unattributed_total_tokens,request_count,cost_usd,input_cost_usd,output_cost_usd,cache_read_cost_usd,cache_creation_cost_usd);
fields!(SnapshotRequestEvidence; []; identity_basis,provider_workspace_hash,account_source);
fields!(SnapshotCost; []; total_cost_usd,input_cost_usd,output_cost_usd,cache_read_cost_usd,cache_creation_cost_usd,evidence_source);
fields!(SnapshotProvenance; []; collector,source_file_count,input_token_scope,state_total_tokens,state_archived);
fields!(SessionArtifact; []; kind,value);
fields!(SnapshotContextCurve; []; contract_version,parser_revision,ownership_revision,sampling_revision,coverage,total_owned_request_count,retained_point_count,total_compaction_boundary_count,retained_boundary_count,points,boundaries,model_windows);
fields!(SnapshotContextCurvePoint; []; owned_request_ordinal,observed_at,effective_input_tokens,model_window_index,segment_ordinal,retention_flags,compaction_before_request_boundary_index,compaction_after_request_boundary_index);
fields!(SnapshotContextCurveBoundary; []; boundary_index,observed_at,before_owned_request_ordinal,after_owned_request_ordinal,segment_before_ordinal,segment_after_ordinal);
fields!(SnapshotContextCurveModelWindow; []; model_window_index,model,context_window_tokens,evidence_kind,evidence_revision);
fields!(SessionAttributionFact; []; field,value,display_label,display_label_source,evidence);
fields!(SessionFieldEvidence; []; kind,strength,observed_at,source_version,evidence_ref);
fields!(crate::snapshots::claude_request_identity::AccountDisplay; []; current,history);
fields!(ottto_protocol::ActiveSessionCurrentAccount; []; status,account_identifier_hash,organization_identifier_hash,subscription_product,latest_request_at,unknown_reason);
fields!(ottto_protocol::ActiveSessionAccountUse; []; account_identifier_hash,organization_identifier_hash,subscription_product,request_count,input_tokens,cache_read_tokens,cache_creation_5m_tokens,cache_creation_1h_tokens,output_tokens,last_used_at,current);

pub(crate) fn page_bound(items: &[SnapshotItem], cap: usize) -> Option<usize> {
    if items.is_empty()
        || items.len() > 50
        || items.iter().any(|i| {
            i.cache_observations.is_some()
                || i.cache_base_head_etag.is_some()
                || i.cache_observations_state.is_some()
        })
    {
        return None;
    }
    let mut b = Budget { bytes: 0, cap };
    b.add(PROOF_RESERVE)?;
    b.add(items.len().checked_mul(size_of::<SnapshotItem>())?)?;
    for i in items {
        i.heap(&mut b)?;
    }
    Some(b.bytes)
}

fields!(crate::snapshots::ClaudeRemovedUsage; []; input_tokens, output_tokens, cache_read_tokens, cache_creation_5m_tokens, cache_creation_1h_tokens, unattributed_total_tokens, reasoning_output_tokens);

fields!(CopyUnprovenCounts; []; rows,requests);
