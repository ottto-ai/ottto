// Terminal family-proof re-arm through the production reported-usage fold: a
// new or changed exact family witness reparses earlier-page members once, and
// an unchanged witness adds no reparse debt. Every fixture is synthetic and
// content-free; the index round-trips through the production save and load.
use super::*;
use crate::claude_local_otel::{
    ClaudeLocalOtelEvidence, ClaudeLocalOtelLoadReport, ClaudeTraceOwnershipEvidence,
    ClaudeTraceOwnershipLoadReport,
};

const CHILD_AGENT: &str = "a4d1585d310070d0f";
const REPORTED: Option<&str> = Some("session_exclusive_reported_usage:v1");

fn revision(seed: u64) -> String {
    format!("{seed:064x}")
}

fn refingerprint(mut row: ClaudeLocalOtelEvidence) -> ClaudeLocalOtelEvidence {
    row.fingerprint.clear();
    let bytes = serde_json::to_vec(&row).expect("serialize API evidence");
    row.fingerprint = format!("sha256:{:x}", Sha256::digest(bytes));
    row
}

/// A root transcript and one subagent transcript under the same family, with
/// complete paired API and trace evidence for every request. Each traversal
/// parses the root on an earlier page and the child on the terminal page.
struct Family {
    dir: PathBuf,
    state_dir: PathBuf,
    root_session_id: String,
    parent_path: PathBuf,
    child_path: PathBuf,
    parent_key: String,
    child_key: String,
    api_rows: Vec<ClaudeLocalOtelEvidence>,
    trace_rows: Vec<ClaudeTraceOwnershipEvidence>,
    index: ScanIndex,
}

impl Family {
    fn new() -> Self {
        let (dir, root_session_id, _) = claude_account_family_fixture();
        let parent_path = dir.join(format!("{root_session_id}.jsonl"));
        let child_path = dir
            .join(&root_session_id)
            .join("subagents")
            .join(format!("agent-{CHILD_AGENT}.jsonl"));
        let mut api_rows = (1..=4)
            .map(|index| {
                complete_api_row(&root_session_id, &format!("req_{index}"), index, 10, 10, 0)
            })
            .collect::<Vec<_>>();
        api_rows.push(complete_api_row(&root_session_id, "req_5", 5, 10, 1, 0));
        let mut trace_rows = (1..=4)
            .map(|index| complete_trace_row(&root_session_id, &format!("req_{index}"), ""))
            .collect::<Vec<_>>();
        trace_rows.push(complete_trace_row(&root_session_id, "req_5", CHILD_AGENT));
        let parent_key = local_index_key(&parent_path);
        let child_key = local_index_key(&child_path);
        let mut index = ScanIndex::default();
        for (key, seed) in [(&parent_key, 1), (&child_key, 2)] {
            let mut entry = manifest_index_entry(None);
            entry.source_file_fingerprint = revision(seed);
            index.files.insert(key.clone(), entry);
        }
        Self {
            dir,
            state_dir: temp_dir("claude-usage-proof-rearm-state"),
            root_session_id,
            parent_path,
            child_path,
            parent_key,
            child_key,
            api_rows,
            trace_rows,
            index,
        }
    }

    fn parse(&self, path: &Path, window: &str, seed: u64) -> Vec<SnapshotItem> {
        parse_claude_code_jsonl_file(path, window, revision(seed)).expect("parse family member")
    }

    fn parent(&self, window: &str) -> Vec<SnapshotItem> {
        self.parse(&self.parent_path, window, 1)
    }

    fn child(&self, window: &str, seed: u64) -> Vec<SnapshotItem> {
        self.parse(&self.child_path, window, seed)
    }

    fn page(
        &mut self,
        items: &mut [SnapshotItem],
        census_complete: bool,
        window: &str,
    ) -> ClaudeUsageAuthorityDisposition {
        let api_report = ClaudeLocalOtelLoadReport {
            evidence: BTreeMap::from([(self.root_session_id.clone(), self.api_rows.clone())]),
            health: Default::default(),
        };
        let trace_report = ClaudeTraceOwnershipLoadReport {
            evidence: BTreeMap::from([(self.root_session_id.clone(), self.trace_rows.clone())]),
            ..Default::default()
        };
        apply_claude_reported_usage_with_index(
            items,
            &api_report,
            &trace_report,
            &mut self.index,
            census_complete,
            window,
        )
    }

    /// Persist the index and restart from disk, as a daemon restart would.
    fn reload(&mut self) {
        let path = self.state_dir.join("scan-index.json");
        self.index.save(&path).expect("save scan index");
        self.index = ScanIndex::load(&path).expect("load scan index");
        assert!(
            self.index.files.contains_key(&self.parent_key),
            "the saved index reloads intact instead of being quarantined"
        );
    }

    /// An accepted upload commits the parsed revision again.
    fn settle(&mut self, key: &str, seed: u64) {
        self.index
            .files
            .get_mut(key)
            .expect("indexed family member")
            .source_file_fingerprint = revision(seed);
    }

    fn armed(&self, key: &str) -> bool {
        !self.index.files[key].source_file_fingerprint.is_empty()
    }

    fn witness(&self) -> ClaudeUsageFamilyWitness {
        self.index
            .claude_usage_family_witnesses
            .get(&self.root_session_id)
            .cloned()
            .expect("family witness")
    }

    /// First traversal proves the family, then the correction traversal
    /// rebuilds the re-armed root from the retained witness and settles it.
    fn proven_and_corrected(&mut self) -> ClaudeUsageFamilyWitness {
        let mut parent = self.parent("2026-08-02T07:10:00Z");
        self.page(&mut parent, false, "2026-08-02T07:10:00Z");
        assert_eq!(parent[0].usage_accounting_contract, None);
        let mut child = self.child("2026-08-02T07:10:00Z", 2);
        self.page(&mut child, true, "2026-08-02T07:10:00Z");
        assert_eq!(child[0].usage_accounting_contract.as_deref(), REPORTED);
        let first_witness = self.witness();
        assert!(
            !self.armed(&self.parent_key),
            "the first exact proof re-arms the earlier-page root once"
        );
        assert!(self.armed(&self.child_key));
        self.reload();

        let mut corrected = self.parent("2026-08-02T07:20:00Z");
        let disposition = self.page(&mut corrected, false, "2026-08-02T07:20:00Z");
        assert_eq!(disposition.quarantined_entity_count(), 0);
        assert_eq!(corrected[0].usage_accounting_contract.as_deref(), REPORTED);
        assert_eq!(corrected[0].request_count, 4);
        assert_eq!(corrected[0].input_tokens, 40);
        assert_eq!(corrected[0].output_tokens, 40);
        self.settle(&self.parent_key.clone(), 1);
        self.reload();
        first_witness
    }
}

impl Drop for Family {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
        let _ = fs::remove_dir_all(&self.state_dir);
    }
}

#[test]
fn unchanged_family_proof_does_not_rearm_corrected_earlier_page_member() {
    let mut family = Family::new();
    let first_witness = family.proven_and_corrected();
    let parent_key = family.parent_key.clone();

    // The correction traversal observed every member, so the terminal census
    // proves the family again. Its witness is unchanged: the root's settled
    // body already carries it, and re-arming would repeat the reparse forever.
    let mut child = family.child("2026-08-02T07:20:00Z", 2);
    let disposition = family.page(&mut child, true, "2026-08-02T07:20:00Z");
    assert_eq!(disposition.quarantined_entity_count(), 0);
    assert_eq!(child[0].usage_accounting_contract.as_deref(), REPORTED);
    assert_eq!(child[0].request_count, 1);
    assert_eq!(child[0].output_tokens, 1);
    assert_eq!(family.witness(), first_witness);
    assert_eq!(
        family.index.files[&parent_key].source_file_fingerprint,
        revision(1),
        "an unchanged exact family proof adds no reparse debt"
    );
    assert!(family.armed(&family.child_key));
    family.reload();

    // The next traversal skips the unchanged root, so its census no longer
    // proves the family. The retained witness stays and nothing is re-armed.
    family.page(&mut [], true, "2026-08-02T07:30:00Z");
    assert_eq!(family.witness(), first_witness);
    assert!(family.armed(&parent_key));
    assert!(family.index.claude_usage_authority_quarantine.is_empty());
}

#[test]
fn changed_family_evidence_rearms_earlier_page_member_after_unchanged_proof() {
    let mut family = Family::new();
    let first_witness = family.proven_and_corrected();
    let parent_key = family.parent_key.clone();
    let mut child = family.child("2026-08-02T07:20:00Z", 2);
    family.page(&mut child, true, "2026-08-02T07:20:00Z");
    assert!(family.armed(&parent_key));

    // The reported cost of a root request changes. The earlier page cannot
    // reconstruct the retained witness, so the root fails closed into the
    // bounded quarantine instead of uploading a transcript-only body.
    let mut changed = family.api_rows[0].clone();
    changed.cost_usd_micros = Some(250);
    family.api_rows[0] = refingerprint(changed);
    let mut parent = family.parent("2026-08-02T07:30:00Z");
    let disposition = family.page(&mut parent, false, "2026-08-02T07:30:00Z");
    assert_eq!(parent[0].usage_accounting_contract, None);
    assert_eq!(disposition.quarantined_entity_count(), 1);
    let mut uploadable = parent;
    disposition.retain_uploadable(&mut uploadable);
    assert!(uploadable.is_empty(), "the demoting root body is held");

    // The terminal census proves a changed exact witness and re-arms the
    // earlier-page root once, exactly like the first proof.
    let mut child = family.child("2026-08-02T07:30:00Z", 2);
    family.page(&mut child, true, "2026-08-02T07:30:00Z");
    assert_eq!(child[0].usage_accounting_contract.as_deref(), REPORTED);
    assert_ne!(family.witness(), first_witness);
    assert!(
        !family.armed(&parent_key),
        "a changed exact family proof re-arms the earlier-page root"
    );
    assert!(family.armed(&family.child_key));
}

#[test]
fn member_change_after_unchanged_proof_fails_closed_until_family_reparse() {
    let mut family = Family::new();
    let first_witness = family.proven_and_corrected();
    let parent_key = family.parent_key.clone();
    let child_key = family.child_key.clone();
    let mut child = family.child("2026-08-02T07:20:00Z", 2);
    family.page(&mut child, true, "2026-08-02T07:20:00Z");
    assert!(family.armed(&parent_key));

    // Only the child grows. Its new request is reported, so the retained
    // witness no longer reconstructs and the child is held, never downgraded.
    let root_session_id = family.root_session_id.clone();
    let appended = format!(
        "{{\"timestamp\":\"2026-08-02T07:00:05Z\",\"type\":\"assistant\",\"sessionId\":\"{root_session_id}\",\"agentId\":\"{CHILD_AGENT}\",\"isSidechain\":true,\"requestId\":\"req_6\",\"message\":{{\"model\":\"claude-haiku-4-5\",\"usage\":{{\"input_tokens\":10,\"output_tokens\":1}}}}}}\n"
    );
    let mut transcript = fs::read_to_string(&family.child_path).expect("read child transcript");
    transcript.push_str(&appended);
    fs::write(&family.child_path, transcript).expect("append child transcript");
    family
        .api_rows
        .push(complete_api_row(&root_session_id, "req_6", 6, 10, 1, 0));
    family
        .trace_rows
        .push(complete_trace_row(&root_session_id, "req_6", CHILD_AGENT));
    let mut grown = family.child("2026-08-02T07:30:00Z", 3);
    let disposition = family.page(&mut grown, false, "2026-08-02T07:30:00Z");
    assert_eq!(grown[0].usage_accounting_contract, None);
    assert_eq!(disposition.quarantined_entity_count(), 1);
    let mut uploadable = grown;
    disposition.retain_uploadable(&mut uploadable);
    assert!(uploadable.is_empty(), "the demoting child body is held");

    // The unchanged root was not parsed in this window, so the census cannot
    // prove the family. Nothing is re-armed here; the bounded quarantine bound
    // to the retained witness owns the family retry.
    family.page(&mut [], true, "2026-08-02T07:30:00Z");
    assert_eq!(family.witness(), first_witness);
    assert!(family.armed(&parent_key));
    let quarantine = family
        .index
        .claude_usage_authority_quarantine
        .get(&root_session_id)
        .expect("family is quarantined")
        .clone();
    assert_eq!(
        quarantine.disposition,
        ClaudeUsageAuthorityQuarantineDisposition::RetryPending
    );
    assert_eq!(
        quarantine.proven_witness_fingerprint,
        claude_usage_family_witness_fingerprint(&first_witness)
    );
    family.reload();

    // The quarantine's family reparse observes every member in one window.
    // Its census proves the changed witness and re-arms both members once.
    let mut parent = family.parent("2026-08-02T07:40:00Z");
    let mut grown = family.child("2026-08-02T07:40:00Z", 3);
    parent.append(&mut grown);
    let disposition = family.page(&mut parent, false, "2026-08-02T07:40:00Z");
    assert_eq!(disposition.quarantined_entity_count(), 2);
    family.page(&mut [], true, "2026-08-02T07:40:00Z");
    assert_ne!(family.witness(), first_witness);
    assert!(!family.armed(&parent_key));
    assert!(!family.armed(&child_key));

    // The re-armed members rebuild from the new witness with the grown usage,
    // which resolves the quarantine.
    let mut parent = family.parent("2026-08-02T07:50:00Z");
    let mut grown = family.child("2026-08-02T07:50:00Z", 3);
    parent.append(&mut grown);
    let disposition = family.page(&mut parent, false, "2026-08-02T07:50:00Z");
    assert_eq!(disposition.quarantined_entity_count(), 0);
    assert!(parent
        .iter()
        .all(|item| item.usage_accounting_contract.as_deref() == REPORTED));
    assert_eq!(parent[1].request_count, 2);
    assert_eq!(parent[1].output_tokens, 2);
    assert!(!family
        .index
        .claude_usage_authority_quarantine
        .contains_key(&root_session_id));
}

#[test]
fn closed_owner_fence_does_not_treat_bound_quarantine_as_current_coverage() {
    let mut family = Family::new();
    let witness = family.proven_and_corrected();
    family.index.claude_usage_authority_quarantine.insert(
        family.root_session_id.clone(),
        ClaudeUsageAuthorityQuarantineRecord {
            contract: CLAUDE_USAGE_AUTHORITY_QUARANTINE_CONTRACT_VERSION.to_string(),
            proven_witness_fingerprint: claude_usage_family_witness_fingerprint(&witness),
            member_source_file_fingerprints: BTreeMap::from([
                (family.root_session_id.clone(), revision(1)),
                (
                    format!("{}_agent-{CHILD_AGENT}", family.root_session_id),
                    revision(2),
                ),
            ]),
            failed_reconstruction_count: MAX_CLAUDE_USAGE_AUTHORITY_FAILURES,
            disposition: ClaudeUsageAuthorityQuarantineDisposition::UnprovenTerminal,
            retry_after_unix_seconds: claude_usage_authority_retry_deadline(
                &family.root_session_id,
                &claude_usage_family_witness_fingerprint(&witness),
            ),
        },
    );
    family.index.claude_duplicate_request_witness_overflowed = true;
    family.reload();
    let counts = family
        .page(&mut [], true, "2026-08-02T07:30:00Z")
        .duplicate_census;
    assert!(counts.fence_after);
    assert_eq!(counts.coverage_missing_member_count, 2);
    assert!(counts.full_rearm);
    family.reload();
    let counts = family
        .page(&mut [], true, "2026-08-02T07:30:01Z")
        .duplicate_census;
    assert!(counts.fence_after);
    assert!(!counts.full_rearm, "existing retry backoff remains bounded");
    family.reload();
    let window = "2026-08-02T07:40:00Z";
    let mut parent = family.parent(window);
    family.page(&mut parent, false, window);
    let mut child = family.child(window, 2);
    let counts = family.page(&mut child, true, window).duplicate_census;
    assert!(counts.coverage_complete);
    assert!(
        !counts.fence_after,
        "only actual current request observations reopen the fence"
    );
    family.reload();
}
