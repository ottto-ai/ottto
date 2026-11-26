// `e2` acceptance from synthetic files through the production scan, fresh
// sidecar read, native finalize, emission, policy, batch and ACK settlement.
// No supplied accumulators, literal bodies or money totals stand in for reads.
// Terminal policy is the production default. Quiet-context controls also need
// the separately paired upload-context receipt change; never opt this suite
// into future-paging completion just to make those controls pass.
use super::*;
use crate::snapshots::claude_request_money::e2;
use crate::snapshots::e2_pipeline_scan_fixture::{
    accept_upload_context_acks_for_test, birth_store_bytes, cold_restart,
    upload_context_owed_for_test, upload_context_receipt_earned_for_test, E2ScanFixture,
};
use serde_json::json;

const ROOT: &str = "1338a80a-f36e-4cbc-a5bb-50fc66430ba5";
const COPY: &str = "2338a80a-f36e-4cbc-a5bb-50fc66430ba5";
const AT: &str = "2026-08-02T07:00:10Z";
fn with_e2<T>(f: impl FnOnce() -> T) -> T {
    crate::snapshots::with_max_gated_claude_revision(3, f)
}
fn nanos(at: &str) -> i128 {
    OffsetDateTime::parse(at, &Rfc3339)
        .unwrap()
        .unix_timestamp_nanos()
}
fn line(session: &str, request: &str, at: &str, tokens: u64) -> String {
    line_by(session, request, at, tokens, "2.1.309")
}
/// A response line written by Claude Code `version` (a copy keeps it).
fn line_by(session: &str, request: &str, at: &str, tokens: u64, version: &str) -> String {
    json!({"type":"assistant", "sessionId":session, "version":version,
        "timestamp":at, "requestId":request,
        "message":{"id":format!("msg-{request}"), "model":"claude-haiku-4-5",
            "usage":{"input_tokens":tokens,"output_tokens":tokens,
                "cache_read_input_tokens":3,"cache_creation_input_tokens":7,
                "cache_creation":{"ephemeral_5m_input_tokens":5,"ephemeral_1h_input_tokens":2}}}})
    .to_string()
        + "\n"
}
fn canonical<T: Serialize + ?Sized>(value: &T) -> Vec<u8> {
    crate::canonical_json::canonicalize(&serde_json::to_value(value).unwrap()).unwrap()
}

struct Corpus {
    base: PathBuf,
    root: PathBuf,
    support: PathBuf,
    births: BTreeMap<PathBuf, i128>,
}
impl Corpus {
    fn new(name: &str) -> Self {
        let base = test_dir(name);
        let root = base.join("projects");
        let support = base.join("support");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&support).unwrap();

        std::fs::create_dir_all(support.join("snapshots")).unwrap();
        std::fs::write(
            support.join("snapshots/claude_code-reemission-exclusions.txt"),
            "# installed synthetic list, no protected sessions\n",
        )
        .unwrap();

        Self {
            base,
            root,
            support,
            births: BTreeMap::new(),
        }
    }
    fn write_at(&mut self, relative: &str, contents: &str, birth: &str) -> PathBuf {
        let path = self.root.join(relative);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, contents).unwrap();
        self.births.insert(path.clone(), nanos(birth));
        path
    }
    fn root(&mut self, session: &str, contents: &str) -> PathBuf {
        self.write_at(
            &format!("{session}.jsonl"),
            contents,
            "2026-08-02T07:00:00Z",
        )
    }
    fn agent(&mut self, agent: usize, contents: &str) -> PathBuf {
        self.write_at(
            &format!("{ROOT}/subagents/agent-{agent:03}.jsonl"),
            contents,
            AT,
        )
    }
    fn evidence(
        &self,
        rows: &[crate::claude_local_otel::ClaudeLocalOtelEvidence],
        traces: &[crate::claude_local_otel::ClaudeTraceOwnershipEvidence],
    ) {
        self.evidence_for(ROOT, rows, traces);
    }
    fn evidence_for(
        &self,
        session: &str,
        rows: &[crate::claude_local_otel::ClaudeLocalOtelEvidence],
        traces: &[crate::claude_local_otel::ClaudeTraceOwnershipEvidence],
    ) {
        for (directory, values) in [
            (
                "claude-code-effort",
                rows.iter()
                    .map(|r| serde_json::to_value(r).unwrap())
                    .collect::<Vec<_>>(),
            ),
            (
                "claude-code-trace-ownership",
                traces
                    .iter()
                    .map(|r| serde_json::to_value(r).unwrap())
                    .collect::<Vec<_>>(),
            ),
        ] {
            let path = self
                .support
                .join("local-otel")
                .join(directory)
                .join(format!("{:x}.jsonl", Sha256::digest(session.as_bytes())));
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(
                path,
                values
                    .iter()
                    .map(|v| v.to_string() + "\n")
                    .collect::<String>(),
            )
            .unwrap();
        }
    }
    fn raw(
        &self,
        scanner: &E2ScanFixture,
        mut index: ScanIndex,
        limit: usize,
        sampled: bool,
        hints: &[PathBuf],
    ) -> Page {
        if sampled {
            index = scanner.routed(index, &self.base);
        }
        index.activate_upload_context("e2-synthetic-destination".into());
        index.activate_effective_upload_body_witness_revision(3);
        index.adopt_effective_upload_body_witness_revision_monotonically();
        index.load_claude_reemission_exclusions(&self.support);
        // As prepare: the claim cutoff finish applies to this pass.
        index.backfill_cutoff_nanos =
            crate::backfill::load_backfill_state(&self.support).backfill_cutoff_nanos();
        let committed = index.clone();
        let (index, scan, modes) = scanner.scan(
            std::slice::from_ref(&self.root),
            &self.support,
            index,
            limit,
            sampled,
            &self.births,
            hints,
        );
        Page {
            cache: scanner.cache.clone(),
            committed,
            index,
            scan,
            modes,
            disposition: Default::default(),
            released: Default::default(),
            stats: Default::default(),
            delivered: None,
            upload_policy: SnapshotUploadPolicy::default(),
            cutoff_candidates: Vec::new(),
        }
    }

    fn reload(&self, index: &mut ScanIndex) -> ScanIndex {
        self.reload_in(index, "scan-index.json")
    }
    fn reload_in(&self, index: &mut ScanIndex, name: &str) -> ScanIndex {
        let path = crate::snapshots::e2_pipeline_scan_fixture::bind_fixture_route(
            SnapshotSource::ClaudeCode,
            index,
            self.base.join(name).parent().unwrap(),
            &e2_progress().destination_namespace_hash,
        );
        index.save_fixture(&path).unwrap();
        ScanIndex::load(&path).unwrap()
    }
}
impl Drop for Corpus {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.base);
        crate::snapshots::state_v2::close_removed_routes_for_test();
    }
}
struct Page {
    cache: std::sync::Arc<crate::snapshots::sampled_scan::SharedCache>,
    committed: ScanIndex,
    index: ScanIndex,
    scan: SourceScanResult,
    modes: (usize, usize, usize),
    disposition: crate::snapshots::ClaudeUsageAuthorityDisposition,
    released: e2::pipeline_test_observer::Released,
    stats: ClaudeLocalEvidenceStats,
    /// Exact ACKs of this page's final bodies, when `ready` delivered them:
    /// `finish` then earns the file receipts as the service finish does.
    delivered: Option<BTreeMap<String, String>>,
    /// What this pass's upload filter keeps.
    upload_policy: SnapshotUploadPolicy,
    /// The claim cutoff's Claude corrections, captured where the cutoff
    /// applies; finish settles them.
    cutoff_candidates: Vec<crate::snapshots::ClaudeCutoffCorrectionCandidate>,
}
impl Page {
    fn enrich(&mut self, corpus: &Corpus) -> crate::snapshots::ClaudeUsageAuthorityDisposition {
        self.enrich_with(corpus, None)
    }
    /// `enrich` with this cycle's accepted-share hints, which it then
    /// updates as the sync loop does before any upload.
    fn enrich_with(
        &mut self,
        corpus: &Corpus,
        accepted: Option<&mut crate::snapshots::claude_request_identity::AcceptedBuckets>,
    ) -> crate::snapshots::ClaudeUsageAuthorityDisposition {
        self.enrich_with_budget(corpus, accepted, Default::default())
    }
    fn enrich_with_budget(
        &mut self,
        corpus: &Corpus,
        mut accepted: Option<&mut crate::snapshots::claude_request_identity::AcceptedBuckets>,
        wire_budget: crate::snapshots::claude_request_identity::WireBudget<'_>,
    ) -> crate::snapshots::ClaudeUsageAuthorityDisposition {
        // The streamed-evidence arm: the same enrichment, keeping every root's
        // rows, first (taking the check so it does not recurse). It only
        // observes: the fixture's diag, read receipts and hooks stay its own.
        let checks = STREAMED_CHECKS.with(std::cell::Cell::take);
        let terminal = self.scan.census_complete;
        // Each reference arm folds its own copy of the page, index and
        // accepted buckets, and leaves this thread's remembered veto and
        // reemission latch as it found them.
        let reference = |seam: &'static std::thread::LocalKey<std::cell::Cell<bool>>| {
            unobserved(|| {
                evidence_chunk_tests::isolated(|| {
                    let mut page = twin(self);
                    let mut accepted = accepted.as_deref().cloned();
                    seam.with(|on| on.set(true));
                    let reads = api_reads(|| {
                        page.enrich_with_budget(corpus, accepted.as_mut(), wire_budget);
                    });
                    seam.with(|on| on.set(false));
                    (page, accepted, reads)
                })
            })
        };
        let whole = checks.map(|_| reference(&crate::snapshot_sync::WHOLE_CORPUS_EVIDENCE));
        // The same streamed fold over the page as one evidence chunk.
        let one = checks.map(|_| reference(&crate::snapshot_sync::ONE_EVIDENCE_CHUNK));
        let before = crate::claude_local_otel::evidence_read_counts_for_test().0;
        let chunks_before = crate::snapshot_sync::evidence_chunks_for_test();
        let ((mut disposition, _, stats), released) =
            e2::pipeline_test_observer::capture_released(|| {
                apply_claude_local_evidence_to_scan_with_ledger_and_budget(
                    &corpus.support,
                    &mut self.scan,
                    &mut self.index,
                    accepted.as_deref(),
                    wire_budget,
                    None,
                )
            });
        if let Some(accepted) = accepted.as_deref_mut() {
            accepted.invalidate_copy_derived(&std::mem::take(&mut disposition.copy_invalidated));
        }
        self.released = released;
        self.stats = stats;
        self.index
            .veto_claude_history_emission(SnapshotSource::ClaudeCode, &mut self.scan.snapshots);
        let deferred = self.index.bind_session_accounts_with_mixed(
            SnapshotSource::ClaudeCode,
            "e2-synthetic-machine",
            &mut self.scan.snapshots,
            &[],
            (&[], &mut [0; 9]),
            &disposition.mixed_uploads,
        );
        disposition.defer_sessions(deferred);
        crate::snapshots::apply_upload_policy(
            SnapshotSource::ClaudeCode,
            &mut self.scan.snapshots,
            self.upload_policy,
        );
        let backfill = crate::backfill::load_backfill_state(&corpus.support);
        (_, self.cutoff_candidates) = apply_backfill_cutoff_with_claude_corrections(
            &mut self.scan,
            &self.index,
            &disposition,
            &backfill,
        );
        self.disposition = disposition.clone();
        if let (
            Some(mut checks),
            Some((whole, whole_accepted, whole_reads)),
            Some((one, one_accepted, one_reads)),
        ) = (checks, whole, one)
        {
            let reads = crate::claude_local_otel::evidence_read_counts_for_test().0 - before;
            let chunks = crate::snapshot_sync::evidence_chunks_for_test() - chunks_before;
            unobserved(|| {
                checks.compare_references(
                    terminal,
                    [
                        (&whole, whole_accepted.as_ref(), whole_reads),
                        (&one, one_accepted.as_ref(), one_reads),
                    ],
                    (self, accepted.as_deref(), reads),
                    chunks,
                );
            });
            STREAMED_CHECKS.with(|slot| slot.set(Some(checks)));
        }
        disposition
    }
    fn finish(&mut self) -> LocalHoldSettlement {
        self.finish_with(snapshot_upload_body_witness)
    }
    fn finish_with(&mut self, witness: impl FnMut(&SnapshotItem) -> String) -> LocalHoldSettlement {
        exclude_held_effective_body_witness_revision(
            &mut self.index,
            &self.scan.snapshots,
            &self.disposition,
        );
        finalize_scan_after_policy_with_body_witness(
            SnapshotSource::ClaudeCode,
            &mut self.scan,
            &mut self.index,
            witness,
        );
        let holds = LocalHoldSettlement::classify(
            SnapshotSource::ClaudeCode,
            &mut self.index,
            &mut self.scan,
            &self.disposition,
        );
        self.index
            .retain_claude_history_emission_permitted(&mut self.scan.snapshots);
        if let Some(acks) = &self.delivered {
            accept_upload_context_acks_for_test(&mut self.index, &self.scan.snapshots, acks);
        }
        holds
    }

    fn receipt(&self) -> Vec<(String, String, String)> {
        self.scan
            .snapshots
            .iter()
            .map(|s| {
                (
                    s.source_session_id.clone(),
                    s.snapshot_fingerprint.clone(),
                    snapshot_upload_body_witness(s),
                )
            })
            .collect()
    }
}
// --- Streamed local evidence equals a whole-corpus fold (arm) -------------

thread_local! {
    /// `Some` while the arm runs: every enrichment is compared both ways.
    static STREAMED_CHECKS: std::cell::Cell<Option<StreamedChecks>> =
        const { std::cell::Cell::new(None) };
}

/// One side of a compared enrichment: the page, its accepted buckets and the
/// API sidecar opens its fold made.
type ComparedSide<'p> = (
    &'p Page,
    Option<&'p crate::snapshots::claude_request_identity::AcceptedBuckets>,
    usize,
);

/// What the compared enrichments exercised, so the arm cannot pass vacuously.
#[derive(Clone, Copy, Debug, Default)]
struct StreamedChecks {
    non_terminal: usize,
    terminal: usize,
    /// Enrichments whose terminal pass read more pairs than the whole fold.
    /// None: the terminal proof reread is gone.
    reread: usize,
    /// Enrichments whose bodies, both ways, carry the second login and its org forward to
    /// root A's own request that has no telemetry row.
    carried: usize,
    /// Enrichments whose page ran as two or more evidence chunks, and the
    /// most chunks one page ran.
    chunked: usize,
    max_chunks: usize,
}

impl StreamedChecks {
    /// One enrichment: the streamed fold (only the page's roots keep rows)
    /// against the same fold keeping every root's rows. Byte equality
    /// without normalization for bodies (contract-5 tags included), the
    /// persisted index, stats, holds and the finalized wire; the money oracle
    /// for totals and account placement.
    fn compare(&mut self, terminal: bool, whole: ComparedSide<'_>, streamed: ComparedSide<'_>) {
        use crate::snapshots::sampled_scan::transition_fixture::{money_oracle, Mode, RouteResult};
        let ((whole, whole_accepted, whole_reads), (streamed, accepted, reads)) = (whole, streamed);
        assert_eq!(
            canonical(&whole.scan.snapshots),
            canonical(&streamed.scan.snapshots),
            "bodies, contract-5 tags included"
        );
        assert_eq!(whole.scan.census_complete, streamed.scan.census_complete);
        // A routed index compares its resident graph.
        let resident = crate::snapshots::e2_pipeline_scan_fixture::resident_for_test;
        assert_eq!(
            canonical(&resident(&whole.index)),
            canonical(&resident(&streamed.index)),
            "index"
        );
        assert_eq!(canonical(&whole.stats), canonical(&streamed.stats), "stats");
        assert_eq!(whole.disposition, streamed.disposition, "holds and counts");
        assert_eq!(whole_accepted, accepted, "accepted buckets");
        let [(whole_index, whole_route), (index, route)] =
            [(whole, Mode::ColdFull), (streamed, Mode::Ram)].map(|(page, mode)| {
                let mut sent = twin(page);
                sent.finish();
                let (result, batches, _) = upload(&sent.scan.snapshots, &mut e2_progress(), ack);
                let route = matches!(result, Ok(ResumableUploadResult::Completed)).then(|| {
                    RouteResult::emitted(
                        mode,
                        SnapshotSource::ClaudeCode,
                        batches.clone(),
                        &sent.scan.snapshots,
                    )
                });
                (canonical(&resident(&sent.index)), (batches, route))
            });
        assert_eq!(whole_index, index, "settled index");
        assert_eq!(whole_route.0, route.0, "wire bytes");
        if let (Some(whole_route), Some(route)) = (&whole_route.1, &route.1) {
            if !whole_route.snapshots.is_empty() {
                money_oracle::assert_equivalent(whole_route, route);
                if terminal {
                    self.terminal += 1;
                } else {
                    self.non_terminal += 1;
                }
            }
        }
        let carried = [whole, streamed].map(|page| carried_forward(&page.scan.snapshots));
        assert_eq!(carried[0], carried[1], "carried accounts");
        self.carried += usize::from(carried[1].contains(&(
            ROOT.to_owned(),
            Some("2".repeat(64)),
            Some("8".repeat(64)),
            1,
        )));
        self.reread += usize::from(terminal && reads > whole_reads);
    }
}

/// Runs the arm's own work leaving this thread's e2 diag, stage timers,
/// evidence read receipts and pending trace hook as the fixture left them.
fn unobserved<T>(f: impl FnOnce() -> T) -> T {
    e2::without_diag(|| crate::claude_local_otel::without_read_receipts(f))
}

/// The API sidecar opens `read` makes on this thread.
fn api_reads(read: impl FnOnce()) -> usize {
    let before = crate::claude_local_otel::evidence_read_counts_for_test().0;
    read();
    crate::claude_local_otel::evidence_read_counts_for_test().0 - before
}

/// (session, login, org, requests) of every share placed by a carried-forward
/// account.
fn carried_forward(
    snapshots: &[SnapshotItem],
) -> Vec<(String, Option<String>, Option<String>, u64)> {
    let mut carried = Vec::new();
    for item in snapshots {
        let evidence = |at: Option<u16>| at.map(|at| &item.request_evidence[usize::from(at)]);
        for row in item
            .usage_buckets
            .iter()
            .flat_map(|bucket| &bucket.model_usage)
        {
            let shares = match &row.identity_parts {
                Some(parts) => parts
                    .iter()
                    .map(|part| {
                        (
                            &part.account_identifier_hash,
                            part.evidence_ref,
                            part.request_count,
                        )
                    })
                    .collect(),
                None => vec![(
                    &row.account_identifier_hash,
                    row.evidence_ref,
                    row.request_count,
                )],
            };
            for (login, at, requests) in shares {
                if let Some(evidence) = evidence(at).filter(|evidence| {
                    evidence.account_source == Some(crate::snapshots::AccountSource::CarriedForward)
                }) {
                    carried.push((
                        item.source_session_id.clone(),
                        login.clone(),
                        evidence.provider_workspace_hash.clone(),
                        requests,
                    ));
                }
            }
        }
    }
    carried
}

/// Runs `fixtures` with every enrichment compared both ways.
fn streamed_checks(fixtures: impl FnOnce()) -> StreamedChecks {
    STREAMED_CHECKS.with(|slot| slot.set(Some(StreamedChecks::default())));
    fixtures();
    STREAMED_CHECKS
        .with(std::cell::Cell::take)
        .expect("the arm's checks stay installed")
}

/// `api_for` with an intact `login` and, when given, a complete `org`.
fn api_login(
    session: &str,
    request: &str,
    tokens: u64,
    login: char,
    org: Option<char>,
) -> crate::claude_local_otel::ClaudeLocalOtelEvidence {
    api_login_org(
        session,
        request,
        tokens,
        login,
        org.map(|org| org.to_string().repeat(64)),
    )
}

/// `api_login` whose complete org is the given hash (e.g. a transcript
/// marker's organization hash, so telemetry and marker agree).
fn api_login_org(
    session: &str,
    request: &str,
    tokens: u64,
    login: char,
    org: Option<String>,
) -> crate::claude_local_otel::ClaudeLocalOtelEvidence {
    use crate::claude_local_otel::{
        ClaudeIdentityAttributeEvidence, ClaudeIdentityAttributeOrigin, ClaudeIdentityDisposition,
    };
    let attribute = |hash: Option<String>| ClaudeIdentityAttributeEvidence {
        origin: if hash.is_some() {
            ClaudeIdentityAttributeOrigin::LogRecord
        } else {
            ClaudeIdentityAttributeOrigin::Missing
        },
        disposition: if hash.is_some() {
            ClaudeIdentityDisposition::Complete
        } else {
            ClaudeIdentityDisposition::Missing
        },
        resource_hash: None,
        log_record_hash: hash,
    };
    let login = login.to_string().repeat(64);
    let mut row = api_for(session, request, tokens, tokens * 10);
    row.account_identity_checked = true;
    row.account_identifier_hash = Some(login.clone().into());
    row.request_identity = Some(std::sync::Arc::new(
        crate::claude_local_otel::ClaudeRequestIdentityEvidence {
            identity_hash_scheme: "provider-sha256:v1".into(),
            account: attribute(Some(login)),
            organization: attribute(org),
            disposition: ClaudeIdentityDisposition::Complete,
        },
    ));
    row.fingerprint.clear();
    row.fingerprint = format!(
        "sha256:{:x}",
        Sha256::digest(serde_json::to_vec(&row).unwrap())
    );
    row
}

const RESUMED: &str = "3338a80a-f36e-4cbc-a5bb-50fc66430ba5";
const LOGINS: &str = "4338a80a-f36e-4cbc-a5bb-50fc66430ba5";
const MALFORMED: &str = "5338a80a-f36e-4cbc-a5bb-50fc66430ba5";

/// Five roots swept one file per page, then again after the page root grows:
/// root A (side call, a switch from
/// login-only L1 to L2 with a complete org mid-stream, then an own request
/// with no telemetry row that carries L2 forward), legacy
/// fork F of A, resume copy C of A with no rows of its own, D (L1's complete
/// org, and C's own request reported under D: the tripwire and a foreign
/// owner), and U with a malformed sidecar. `multi_root`: F also claims A's
/// request (MultiRootClaims).
fn five_root_sweep(multi_root: bool) {
    five_root_sweep_paged(multi_root, 1);
}

/// `five_root_sweep` with up to `limit` files per page: with every root on
/// one page, its families run as packed evidence chunks.
fn five_root_sweep_paged(multi_root: bool, limit: usize) {
    with_e2(|| {
        let mut c = Corpus::new(&format!("e2-streamed-evidence-{multi_root}-{limit}"));
        let a = c.root(
            ROOT,
            &(line(ROOT, "shared", AT, 10)
                + &line(ROOT, "parent", "2026-08-02T07:01:00Z", 20)
                + &line(ROOT, "switch", "2026-08-02T07:02:00Z", 25)
                + &line(ROOT, "gap", "2026-08-02T07:02:30Z", 12)),
        );
        c.evidence_for(
            ROOT,
            &[
                api_login(ROOT, "shared", 10, '1', None),
                api_login(ROOT, "parent", 20, '1', None),
                api_login(ROOT, "switch", 25, '2', Some('8')),
                api_for(ROOT, "side", 4, 40),
            ],
            &[
                trace_for(ROOT, "shared", ""),
                trace_for(ROOT, "parent", ""),
                trace_for(ROOT, "switch", ""),
                trace_for(ROOT, "side", ""),
            ],
        );
        c.write_at(
            &format!("{COPY}.jsonl"),
            &(line(COPY, "shared", AT, 10) + &line(COPY, "child", "2026-08-02T07:04:00Z", 30)),
            "2026-08-02T07:03:00Z",
        );
        let mut fork_api = vec![api_for(COPY, "child", 30, 300)];
        let mut fork_trace = vec![trace_for(COPY, "child", "")];
        if multi_root {
            fork_api.push(api_for(COPY, "shared", 10, 100));
            fork_trace.push(trace_for(COPY, "shared", ""));
        }
        c.evidence_for(COPY, &fork_api, &fork_trace);
        c.write_at(
            &format!("{RESUMED}.jsonl"),
            &(line(RESUMED, "parent", "2026-08-02T07:01:00Z", 20)
                + &line(RESUMED, "resumed", "2026-08-02T07:05:00Z", 15)),
            "2026-08-02T07:04:30Z",
        );
        c.write_at(
            &format!("{LOGINS}.jsonl"),
            &line(LOGINS, "d-own", "2026-08-02T07:06:00Z", 5),
            "2026-08-02T07:05:30Z",
        );
        c.evidence_for(
            LOGINS,
            &[
                api_login(LOGINS, "d-own", 5, '1', Some('9')),
                api_for(LOGINS, "resumed", 15, 150),
            ],
            &[
                trace_for(LOGINS, "d-own", ""),
                trace_for(LOGINS, "resumed", ""),
            ],
        );
        c.write_at(
            &format!("{MALFORMED}.jsonl"),
            &line(MALFORMED, "u-own", "2026-08-02T07:07:00Z", 3),
            "2026-08-02T07:06:30Z",
        );
        c.evidence_for(
            MALFORMED,
            &[api_for(MALFORMED, "u-own", 3, 30)],
            &[trace_for(MALFORMED, "u-own", "")],
        );
        append(
            &c.support
                .join("local-otel/claude-code-effort")
                .join(format!("{:x}.jsonl", Sha256::digest(MALFORMED.as_bytes()))),
            "{malformed\n",
        );
        let scanner = E2ScanFixture::default();
        let mut index = ScanIndex::default();
        let mut accepted = crate::snapshots::claude_request_identity::AcceptedBuckets::for_test();
        for sweep in 0..2 {
            if sweep == 1 {
                // A packed-page comparison needs every family selected on
                // both sweeps. Stable local ownership no longer selects the
                // unchanged copies merely because their holder committed.
                if limit == 5 {
                    for session in [COPY, RESUMED, LOGINS, MALFORMED] {
                        append(&c.root.join(format!("{session}.jsonl")), "\n");
                    }
                }
                append(&a, &line(ROOT, "later", "2026-08-02T07:08:00Z", 6));
                c.evidence_for(
                    ROOT,
                    &[
                        api_login(ROOT, "shared", 10, '1', None),
                        api_login(ROOT, "parent", 20, '1', None),
                        api_login(ROOT, "switch", 25, '2', Some('8')),
                        api_for(ROOT, "side", 4, 40),
                        api_login(ROOT, "later", 6, '2', None),
                    ],
                    &[
                        trace_for(ROOT, "shared", ""),
                        trace_for(ROOT, "parent", ""),
                        trace_for(ROOT, "switch", ""),
                        trace_for(ROOT, "side", ""),
                        trace_for(ROOT, "later", ""),
                    ],
                );
            }
            for _ in 0..12 {
                let mut page = c.raw(&scanner, index, limit, true, &[]);
                page.enrich_with(&c, Some(&mut accepted));
                page.finish();
                index = c.reload(&mut page.index);
                if page.scan.census_complete {
                    break;
                }
            }
        }
    });
}

/// [money] Streaming the Claude local evidence (only the page's roots keep
/// rows; every root adds its cross-root answers as it is read) emits
/// exactly what a fold over every root's rows emits. Every enrichment of the
/// fixtures below runs both ways: bodies, contract-5 tags, persisted index,
/// holds and stats byte-equal, the money oracle equal, on non-terminal and
/// terminal passes.
#[test]
fn streamed_evidence_equals_whole_corpus() {
    // A request's API and trace rows under its own root are one owner; only
    // another root's claim makes it ambiguous (the original has both rows).
    let mut roots = crate::snapshots::claude_request_identity::RequestRootIndex::default();
    roots.add_root(0, ["original", "copied", "original"].into_iter());
    roots.add_root(1, ["copied"].into_iter());
    roots.finish();
    assert_eq!(roots.get("original"), Some(Some(0)));
    assert_eq!(roots.get("copied"), Some(None));
    assert_eq!(roots.get("absent"), None);

    let checks = streamed_checks(|| {
        five_root_sweep(false);
        five_root_sweep(true);
        // Existing fixtures, each enrichment now compared both ways:
        e2_pipeline_side_call_uses_trace_named_agent_and_counts_root_fallback();
        // An off-page trace-named subagent.
        e2_pipeline_trace_named_agent_on_another_page_is_not_published_on_root();
        // A queued, stale copy holder.
        copy_waits_for_queued_holder(true);
        // A completing census decision followed by ten unchanged passes.
        e2_pipeline_copy_census_completes_once_over_ten_unchanged_passes();
        // Retired and departed holders.
        e2_pipeline_resumed_copy_removal_stays_removed_after_its_proof_retires();
        e2_pipeline_recorded_removal_stands_when_its_holder_leaves_the_index();
        // Path twins.
        twins(false);
        // A page copy with no own rows (the foreign-owner branch).
        e2_pipeline_resumed_prefix_counts_removed_partial_dollars_and_own_turns();
    });
    assert!(
        // The evidence pass reads only the page's roots (no pending-family
        // scope), so no streamed read has another root's rows to drop.
        checks.non_terminal > 0 && checks.terminal > 0 && checks.carried > 0,
        "the arm must compare non-terminal and terminal passes that carry an account \
         forward: {checks:?}"
    );
    assert_eq!(
        checks.reread, 0,
        "no terminal pass rereads a pair: {checks:?}"
    );
}

fn twin(p: &Page) -> Page {
    Page {
        cache: p.cache.clone(),
        committed: p.committed.clone(),
        index: p.index.clone(),
        scan: p.scan.clone(),
        modes: p.modes,
        disposition: p.disposition.clone(),
        released: p.released,
        stats: p.stats.clone(),
        // A twin is an undelivered copy: only `ready`'s original earns receipts.
        delivered: None,
        upload_policy: p.upload_policy,
        cutoff_candidates: Vec::new(),
    }
}
fn api(request: &str, tokens: u64, cost: u64) -> crate::claude_local_otel::ClaudeLocalOtelEvidence {
    api_for(ROOT, request, tokens, cost)
}
fn api_for(
    session: &str,
    request: &str,
    tokens: u64,
    cost: u64,
) -> crate::claude_local_otel::ClaudeLocalOtelEvidence {
    let mut row = crate::claude_local_otel::ClaudeLocalOtelEvidence {
        capture_revision: "claude_api_request:v2".into(),
        session_id: session.into(),
        request_id: request.into(),
        client_request_id: format!("client-{request}"),
        observed_at: AT.into(),
        model: "claude-haiku-4-5".into(),
        effort: "high".into(),
        query_source: "user".into(),
        app_version: "2.1.309".into(),
        event_sequence: Some(cost + 1),
        cost_usd_micros: Some(cost),
        input_tokens: tokens,
        output_tokens: tokens,
        cache_read_tokens: 3,
        cache_creation_tokens: 7,
        cache_creation_5m_tokens: 5,
        cache_creation_1h_tokens: 2,
        request_count: 1,
        ..Default::default()
    };
    row.fingerprint = format!(
        "sha256:{:x}",
        Sha256::digest(serde_json::to_vec(&row).unwrap())
    );
    row
}
fn trace(request: &str, agent: &str) -> crate::claude_local_otel::ClaudeTraceOwnershipEvidence {
    trace_for(ROOT, request, agent)
}
fn trace_for(
    session: &str,
    request: &str,
    agent: &str,
) -> crate::claude_local_otel::ClaudeTraceOwnershipEvidence {
    let mut row = crate::claude_local_otel::ClaudeTraceOwnershipEvidence {
        capture_revision: "claude_llm_request_ownership:v1".into(),
        session_id: session.into(),
        request_id: request.into(),
        client_request_id: format!("client-{request}"),
        agent_id: agent.into(),
        observed_at: AT.into(),
        ..Default::default()
    };
    row.fingerprint = format!(
        "sha256:{:x}",
        Sha256::digest(serde_json::to_vec(&row).unwrap())
    );
    row
}
fn e2_progress() -> SnapshotUploadProgress {
    SnapshotUploadProgress::new(
        format!("{:064x}", 99),
        snapshot_quarantine_witness(SnapshotSource::ClaudeCode),
    )
}
fn request(
    items: &[impl std::borrow::Borrow<SnapshotItem>],
) -> SnapshotBatchRequest<&SnapshotItem> {
    request_under(
        SnapshotUploadPolicy::default(),
        &items
            .iter()
            .map(std::borrow::Borrow::borrow)
            .collect::<Vec<_>>(),
    )
}
fn request_under<'a>(
    upload_policy: SnapshotUploadPolicy,
    items: &[&'a SnapshotItem],
) -> SnapshotBatchRequest<&'a SnapshotItem> {
    SnapshotBatchRequest {
        schema_version: SNAPSHOT_SCHEMA_VERSION,
        source: SnapshotSource::ClaudeCode.api_slug().into(),
        machine_id: "a".repeat(64),
        collector_version: Some("0.1.synthetic".into()),
        snapshots: items.to_vec(),
        upload_policy,
        client_report: crate::client_report::ClientReport::empty(),
    }
}
fn upload(
    items: &[SnapshotItem],
    progress: &mut SnapshotUploadProgress,
    respond: impl FnMut(&[&SnapshotItem]) -> Result<crate::snapshot_client::SnapshotBatchResponse>,
) -> (
    Result<ResumableUploadResult>,
    Vec<Vec<u8>>,
    Vec<Vec<String>>,
) {
    upload_under(SnapshotUploadPolicy::default(), items, progress, respond)
}
fn upload_under(
    upload_policy: SnapshotUploadPolicy,
    items: &[SnapshotItem],
    progress: &mut SnapshotUploadProgress,
    respond: impl FnMut(&[&SnapshotItem]) -> Result<crate::snapshot_client::SnapshotBatchResponse>,
) -> (
    Result<ResumableUploadResult>,
    Vec<Vec<u8>>,
    Vec<Vec<String>>,
) {
    upload_source_under(
        SnapshotSource::ClaudeCode,
        upload_policy,
        items,
        progress,
        respond,
    )
}
pub(in crate::snapshot_sync) fn upload_source_under(
    source: SnapshotSource,
    upload_policy: SnapshotUploadPolicy,
    items: &[SnapshotItem],
    progress: &mut SnapshotUploadProgress,
    respond: impl FnMut(&[&SnapshotItem]) -> Result<crate::snapshot_client::SnapshotBatchResponse>,
) -> (
    Result<ResumableUploadResult>,
    Vec<Vec<u8>>,
    Vec<Vec<String>>,
) {
    upload_source_persisting(source, upload_policy, items, progress, respond, |_| Ok(()))
}
/// `upload_source_under` with the caller's progress persistence, as the
/// production pass passes its ledger save.
pub(in crate::snapshot_sync) fn upload_source_persisting(
    source: SnapshotSource,
    upload_policy: SnapshotUploadPolicy,
    items: &[SnapshotItem],
    progress: &mut SnapshotUploadProgress,
    mut respond: impl FnMut(&[&SnapshotItem]) -> Result<crate::snapshot_client::SnapshotBatchResponse>,
    persist: impl FnMut(&mut SnapshotUploadProgress) -> Result<()>,
) -> (
    Result<ResumableUploadResult>,
    Vec<Vec<u8>>,
    Vec<Vec<String>>,
) {
    let mut sent = Vec::new();
    let mut order = Vec::new();
    let mut accepted = 0;
    let result = upload_resumable_batches_with_literal_families(
        items,
        &unique_poison_scope(),
        progress,
        &mut accepted,
        |s| s.snapshot_fingerprint.as_str(),
        snapshot_upload_body_witness,
        |s| Some(s.source_session_id.as_str()),
        // The production main-upload class: patched and unpatched bodies
        // never share a request.
        snapshot_upload_batch_class,
        crate::snapshots::claude_request_money::request_owned_family_root,
        &mut InplaceRetryBudget::default(),
        |batch| {
            let mut wire = request_under(upload_policy, batch);
            wire.source = source.api_slug().into();
            validate_snapshot_batch_request(&wire)
                .expect("scan-generated fixture passes real wire preflight");
            sent.push(canonical(&wire));
            order.push(batch.iter().map(|s| s.source_session_id.clone()).collect());
            let response = respond(batch)?;
            response.validate_entity_ack(&wire)?;
            Ok(response)
        },
        persist,
    );
    (result, sent, order)
}
pub(in crate::snapshot_sync) fn ack(
    batch: &[&SnapshotItem],
) -> Result<crate::snapshot_client::SnapshotBatchResponse> {
    let mut response = entity_ack_response(0);
    // Head-CAS covers the whole declaring request (a cache patch, a saved
    // head or a telemetry-only body, `validate_entity_ack`): every accepted
    // entity gets a head, including telemetry-only bodies without cache
    // evidence.
    let head_cas = batch
        .iter()
        .any(|item| crate::snapshot_client::declares_head_cas(item));
    for item in batch {
        let mut reference = entity_ack_ref(&item.snapshot_fingerprint);
        reference.source_session_id = item.source_session_id.clone();
        reference.body_witness_version =
            crate::snapshot_client::snapshot_ack_body_witness_version(item).unwrap();
        reference.body_witness_digest = reference
            .body_witness_version
            .map(|_| snapshot_upload_body_witness(item));
        if head_cas {
            reference.head_etag = Some("e".repeat(64));
        }
        response.accepted_entities.push(reference);
        response.accepted += 1;
    }
    response.sessions_reconciled = response.accepted;
    Ok(response)
}
fn total(page: &Page) -> u64 {
    page.scan.snapshots.iter().map(|s| s.request_count).sum()
}
fn literal(page: &Page) {
    assert!(
        !page.scan.snapshots.is_empty(),
        "real scan must emit bodies"
    );
    assert!(page
        .scan
        .snapshots
        .iter()
        .all(crate::snapshots::claude_request_money::is_request_owned_literal));
    assert!(
        page.scan
            .snapshots
            .iter()
            .all(|item| item.claude_usage_occurrences.is_empty()
                && item.claude_usage_request_ids.is_empty()),
        "final E2 bodies release native inputs before upload and retry clones"
    );
    assert!(
        page.scan.snapshots.iter().all(|item| item
            .claude_money
            .as_deref()
            .map_or(true, e2::pipeline_test_observer::released_for_marks)),
        "final identity-tagged rows must not retain E2 fold storage for upload"
    );
}
/// Each indexed file still on disk: the body it last sent (snapshot
/// fingerprint and upload body witness), as the index stores it.
fn stored_bodies(
    index: &ScanIndex,
) -> std::collections::BTreeMap<String, (Option<String>, Option<String>)> {
    index
        .files
        .iter()
        .filter(|(key, _)| std::path::Path::new(key.as_str()).is_file())
        .map(|(key, entry)| {
            (
                key.clone(),
                (
                    entry.last_snapshot_fingerprint.clone(),
                    entry.last_upload_body_witness.clone(),
                ),
            )
        })
        .collect()
}
fn append(path: &Path, text: &str) {
    std::fs::OpenOptions::new()
        .append(true)
        .open(path)
        .unwrap()
        .write_all(text.as_bytes())
        .unwrap();
}
fn assert_mode(actual: (usize, usize, usize), expected: (usize, usize, usize)) {
    let expected = if crate::heap_layout_bound::layout_supported() {
        expected
    } else {
        (expected.0 + expected.1 + expected.2, 0, 0)
    };
    assert_eq!(
        actual,
        expected,
        "actual acquisition; layout_supported={}",
        crate::heap_layout_bound::layout_supported()
    );
}
/// Continue on the same committed route after discarding process state; a new
/// scanner must not publish the restored graph onto another fixture route.
fn cold_ready(c: &Corpus, prior: ScanIndex, limit: usize, sampled: bool) -> Page {
    let index = cold_restart(prior);
    let scanner = E2ScanFixture::default();
    scanner
        .on_committed_route(&crate::snapshots::e2_pipeline_scan_fixture::route_of(&index).unwrap());
    ready(c, &scanner, index, limit, sampled)
}

fn ready(
    corpus: &Corpus,
    scanner: &E2ScanFixture,
    index: ScanIndex,
    limit: usize,
    sampled: bool,
) -> Page {
    let mut p = corpus.raw(scanner, index, limit, sampled, &[]);
    p.enrich(corpus);
    deliver_page(p)
}
/// Upload `p`'s final bodies once and keep their exact ACKs (`delivered`).
fn deliver_page(mut p: Page) -> Page {
    let mut send = twin(&p);
    send.finish();
    let mut progress = e2_progress();
    let (result, _, _) = upload(&send.scan.snapshots, &mut progress, ack);
    assert_eq!(
        result.unwrap(),
        ResumableUploadResult::Completed,
        "real finalized bodies pass batching and entity ACK"
    );
    p.delivered = Some(std::mem::take(&mut progress.fresh_context_body_acks));
    p
}

/// [money] Cumulative acquisition modes and an independent cold read preserve all money fields.
/// The pre-birth line has no earlier holder of another session in its
/// folder, so it counts (flagged) on every route: none of them removes it.
#[test]
fn e2_pipeline_full_tail_unchanged_eviction_and_restart_are_cumulative() {
    with_e2(|| {
        let mut c = Corpus::new("e2-pipeline-modes");
        let path = c.root(ROOT, &line(ROOT, "copied", "2026-08-02T06:58:00Z", 10));
        let scanner = E2ScanFixture::default();
        let mut first = ready(&c, &scanner, ScanIndex::default(), 100, true);
        literal(&first);
        assert_mode(first.modes, (1, 0, 0));
        assert_eq!(total(&first), 1);
        first.finish();
        let prior = c.reload(&mut first.index);
        std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(line(ROOT, "r2", "2026-08-02T07:01:00Z", 20).as_bytes())
            .unwrap();
        let mut tail = ready(&c, &scanner, prior.clone(), 100, true);
        assert_mode(tail.modes, (0, 1, 0));
        literal(&tail);
        assert_eq!(total(&tail), 2, "the unproven copied line and r2");
        assert_eq!(tail.scan.snapshots[0].removed_request_count, Some(0));
        assert_eq!(
            tail.scan.snapshots[0]
                .removed_usage
                .as_ref()
                .unwrap()
                .input_tokens,
            0
        );
        assert_eq!(tail.scan.snapshots[0].input_tokens, 30);
        let full = ready(&c, &E2ScanFixture::default(), prior, 100, true);
        assert_mode(full.modes, (1, 0, 0));
        assert_eq!(
            canonical(&tail.scan.snapshots),
            canonical(&full.scan.snapshots)
        );
        // Independent physical input and support, with neither a prior index
        // nor a retained reduction. Reuse the corpus fixture and frozen bytes.
        let mut cold = Corpus::new("e2-pipeline-modes-independent-cold");
        let cold_path = cold.root(ROOT, &std::fs::read_to_string(&path).unwrap());
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            assert_ne!(
                std::fs::metadata(&path).unwrap().ino(),
                std::fs::metadata(&cold_path).unwrap().ino()
            );
        }
        let independent = ready(
            &cold,
            &E2ScanFixture::default(),
            ScanIndex::default(),
            100,
            true,
        );
        assert_mode(independent.modes, (1, 0, 0));
        assert_eq!(independent.scan.snapshots.len(), 1);
        let before = serde_json::to_value(&tail.scan.snapshots[0]).unwrap();
        let independent = serde_json::to_value(&independent.scan.snapshots[0]).unwrap();
        assert_eq!(
            before["source_session_id"],
            independent["source_session_id"]
        );
        for field in [
            "input_tokens",
            "output_tokens",
            "cache_read_tokens",
            "cache_creation_5m_tokens",
            "cache_creation_1h_tokens",
            "reasoning_output_tokens",
            "unattributed_total_tokens",
            "request_count",
            "cost",
            "usage_buckets",
            "model_usage",
            "removed_usage",
            "removed_request_count",
            "usage_accounting_contract",
            "telemetry_owned_complete",
        ] {
            // Option<&Value> compares presence as well as the full value:
            // an absent field must not equal an explicitly serialized null.
            assert_eq!(
                before.get(field),
                independent.get(field),
                "COLD mismatch: {field}"
            );
        }
        tail.finish();
        let prior = c.reload(&mut tail.index);
        // Unaccepted exact body remains due; a fresh sidecar is read even if
        // the transcript prefix and length are unchanged.
        c.evidence(&[api("copied", 10, 100), api("r2", 20, 200)], &[]);
        let unchanged = ready(&c, &scanner, prior.clone(), 100, true);
        assert_mode(unchanged.modes, (0, 0, 1));
        let oracle = ready(&c, &E2ScanFixture::default(), prior.clone(), 100, true);
        assert_eq!(
            canonical(&unchanged.scan.snapshots),
            canonical(&oracle.scan.snapshots)
        );
        assert_eq!(total(&unchanged), 2);
        assert_eq!(unchanged.scan.snapshots[0].removed_request_count, Some(0));
        scanner.evict(&prior);
        let evicted = ready(&c, &scanner, prior.clone(), 100, true);
        assert_mode(evicted.modes, (1, 0, 0));
        assert_eq!(
            canonical(&evicted.scan.snapshots),
            canonical(&oracle.scan.snapshots)
        );
        let oracle_bytes = canonical(&oracle.scan.snapshots);
        drop((first, full, tail, unchanged, evicted, oracle));
        let restarted = cold_ready(&c, prior, 100, true);
        assert_mode(restarted.modes, (1, 0, 0));
        assert_eq!(canonical(&restarted.scan.snapshots), oracle_bytes);
    });
}

fn mutation_case(kind: &str) {
    with_e2(|| {
        let mut c = Corpus::new(&format!("e2-pipeline-{kind}"));
        let contents = line(ROOT, "copied", "2026-08-02T06:58:00Z", 11)
            + &line(ROOT, "r1", AT, 10)
            + &line(ROOT, "r2", "2026-08-02T07:01:00Z", 20);
        let path = c.root(ROOT, &contents);
        let scanner = E2ScanFixture::default();
        let mut first = ready(&c, &scanner, ScanIndex::default(), 100, true);
        first.finish();
        let prior = c.reload(&mut first.index);
        let changed = match kind {
            "truncate" => {
                line(ROOT, "copied", "2026-08-02T06:58:00Z", 11) + &line(ROOT, "r1", AT, 10)
            }
            "same-size" => contents.replace("\"input_tokens\":20", "\"input_tokens\":30"),
            "inode" => contents.clone(),
            _ => unreachable!(),
        };
        if kind == "inode" {
            let tmp = path.with_extension("replacement");
            std::fs::write(&tmp, &changed).unwrap();
            std::fs::rename(tmp, &path).unwrap();
        } else {
            std::fs::write(&path, &changed).unwrap();
        }
        if kind == "same-size" {
            assert_eq!(contents.len(), changed.len());
        }
        let actual = ready(&c, &scanner, prior.clone(), 100, true);
        assert_mode(actual.modes, (1, 0, 0));
        literal(&actual);
        // No earlier holder of another session: the copied line counts.
        assert_eq!(actual.scan.snapshots[0].removed_request_count, Some(0));
        assert_eq!(
            actual.scan.snapshots[0]
                .removed_usage
                .as_ref()
                .unwrap()
                .input_tokens,
            0
        );
        let oracle = ready(&c, &E2ScanFixture::default(), prior, 100, true);
        assert_eq!(
            canonical(&actual.scan.snapshots),
            canonical(&oracle.scan.snapshots)
        );
        assert_eq!(total(&actual), if kind == "truncate" { 2 } else { 3 });
        assert_eq!(
            actual.scan.snapshots[0].input_tokens,
            if kind == "truncate" {
                21
            } else if kind == "same-size" {
                51
            } else {
                41
            }
        );
    });
}
#[test]
fn e2_pipeline_truncate_matches_full() {
    mutation_case("truncate");
}
#[test]
fn e2_pipeline_same_size_edit_matches_full() {
    mutation_case("same-size");
}
#[test]
fn e2_pipeline_inode_replacement_matches_full() {
    mutation_case("inode");
}

#[test]
fn e2_pipeline_page_boundary_matches_single_page_bodies() {
    with_e2(|| {
        let mut c = Corpus::new("e2-pipeline-pages");
        c.root(ROOT, &line(ROOT, "root", AT, 10));
        c.agent(0, &line(ROOT, "agent-0", AT, 11));
        c.agent(1, &line(ROOT, "agent-1", AT, 12));
        let scanner = E2ScanFixture::default();
        let full = ready(&c, &scanner, ScanIndex::default(), 100, true);
        literal(&full);
        assert_eq!(full.scan.snapshots.len(), 3);
        let mut index = ScanIndex::default();
        let mut observed = BTreeMap::new();
        for _ in 0..6 {
            let mut page = ready(&c, &scanner, index, 1, true);
            for item in &page.scan.snapshots {
                observed.insert(item.source_session_id.clone(), canonical(item));
            }
            page.finish();
            index = c.reload(&mut page.index);
            if page.scan.census_complete {
                break;
            }
        }
        let expected = full
            .scan
            .snapshots
            .iter()
            .map(|s| (s.source_session_id.clone(), canonical(s)))
            .collect::<BTreeMap<_, _>>();
        assert_eq!(
            observed, expected,
            "page boundaries cannot truncate cumulative money"
        );
    });
}

/// [money] A move keeps its birth through save and reload: the moved path
/// inherits the original's cutoff and counts its request once.
#[test]
fn e2_pipeline_birth_store_survives_save_reload_and_move() {
    with_e2(|| {
        let mut c = Corpus::new("e2-pipeline-move");
        let original = c.root(ROOT, &line(ROOT, "r1", AT, 10));
        let scanner = E2ScanFixture::default();
        let mut first = ready(&c, &scanner, ScanIndex::default(), 100, false);
        assert_eq!(total(&first), 1);
        first.finish();
        let before = birth_store_bytes(&first.index);
        let prior = c.reload(&mut first.index);
        assert_eq!(before, birth_store_bytes(&prior));
        c.write_at(
            &format!("moved/{ROOT}.jsonl"),
            &line(ROOT, "r1", AT, 10),
            "2026-08-02T07:01:00Z",
        );
        std::fs::remove_file(&original).unwrap();
        let moved_page = ready(&c, &scanner, prior, 100, false);
        assert_eq!(total(&moved_page), 1, "a move inherits the original cutoff");
    });
}

fn twins(reverse: bool) {
    with_e2(|| {
        let mut c = Corpus::new(if reverse {
            "e2-pipeline-twins-reverse"
        } else {
            "e2-pipeline-twins-forward"
        });
        let (old_dir, new_dir) = if reverse {
            ("z-original", "a-copy")
        } else {
            ("a-original", "z-copy")
        };
        c.write_at(
            &format!("{old_dir}/{ROOT}.jsonl"),
            &line(ROOT, "r1", AT, 10),
            "2026-08-02T07:00:00Z",
        );
        // The copy's own turns start after the copy proof cutoff: the
        // same-session page proof removes r1 when both twins are read.
        c.write_at(
            &format!("{new_dir}/{ROOT}.jsonl"),
            &(line(ROOT, "r1", AT, 10) + &line(ROOT, "r2", "2026-11-04T07:03:10Z", 20)),
            "2026-11-04T07:03:00Z",
        );
        let scanner = E2ScanFixture::default();
        let mut first = ready(&c, &scanner, ScanIndex::default(), 100, false);
        let paths = scanner.paths();
        assert_eq!(paths.len(), 2, "both real twin files were opened");
        assert!(
            paths[0].ends_with(format!(
                "{}/{ROOT}.jsonl",
                if reverse { new_dir } else { old_dir }
            )),
            "fixture must exercise the requested discovery order"
        );
        literal(&first);
        assert_eq!(
            total(&first),
            2,
            "opposite discovery orders count each request once on the first page"
        );
        assert_eq!(first.scan.snapshots.len(), 1);
        first.finish();
        let prior = c.reload(&mut first.index);
        // Unchanged settled twins are read again only by a change: the old
        // terminal family re-arm that re-read them on every complete census
        // is gone.
        let (repeated, consumed) =
            crate::snapshots::sampled_scan::transition_fixture::observe_consumed(|| {
                ready(&c, &scanner, prior, 100, false)
            });
        assert!(scanner.paths().is_empty(), "no twin is opened again");
        assert_eq!(consumed, 0, "the repeated page reads no transcript byte");
        assert!(
            repeated.scan.snapshots.is_empty(),
            "repeated page cannot add money"
        );
    });
}
#[test]
fn e2_pipeline_twins_original_discovered_first() {
    twins(false);
}
#[test]
fn e2_pipeline_twins_copy_discovered_first() {
    twins(true);
}

/// A response line that also calls `tools`, one `tool_use` block each.
fn tool_line(request: &str, at: &str, tokens: u64, tools: &[&str]) -> String {
    let mut turn: serde_json::Value =
        serde_json::from_str(&line(ROOT, request, at, tokens)).unwrap();
    turn["message"]["role"] = json!("assistant");
    turn["message"]["content"] = tools
        .iter()
        .enumerate()
        .map(|(n, name)| {
            json!({"type": "tool_use", "id": format!("toolu_{request}_{n}"),
                "name": name, "input": {}})
        })
        .collect();
    turn.to_string() + "\n"
}
fn tool_rows(rows: &[(&str, u64)]) -> Vec<(String, u64)> {
    rows.iter()
        .map(|(name, count)| (name.to_string(), *count))
        .collect()
}
/// The page's one literal body: its tool rows and truncation flag.
fn twin_tools(page: &Page) -> (Vec<(String, u64)>, bool) {
    literal(page);
    assert_eq!(page.scan.snapshots.len(), 1, "one body per session");
    let item = &page.scan.snapshots[0];
    let rows = item
        .tool_usage
        .as_deref()
        .expect("a Claude body lists tools");
    (
        rows.iter()
            .map(|row| (row.name.clone(), row.count))
            .collect(),
        item.tool_usage_truncated,
    )
}
/// Per-entity money fields (totals, cost, per-model rows and hourly
/// buckets) of two routes, which must match exactly.
fn assert_same_money(
    a: &crate::snapshots::sampled_scan::transition_fixture::RouteResult,
    b: &crate::snapshots::sampled_scan::transition_fixture::RouteResult,
    what: &str,
) {
    let mut differences = Vec::new();
    crate::snapshots::sampled_scan::transition_fixture::money_oracle::entity_differences(
        a,
        b,
        &mut differences,
    );
    assert!(
        differences.is_empty(),
        "{what}:\n{}",
        differences.join("\n")
    );
}
/// Path twins of `ROOT` (an original and its later copy) read cold on one
/// page in the requested discovery order: the one body's tools and money.
fn tool_twins(
    name: &str,
    reverse: bool,
    original: &str,
    copy: &str,
) -> (
    (Vec<(String, u64)>, bool),
    crate::snapshots::sampled_scan::transition_fixture::RouteResult,
) {
    let mut c = Corpus::new(&format!("{name}-{reverse}"));
    let (old_dir, new_dir) = if reverse {
        ("z-original", "a-copy")
    } else {
        ("a-original", "z-copy")
    };
    c.write_at(
        &format!("{old_dir}/{ROOT}.jsonl"),
        original,
        "2026-08-02T07:00:00Z",
    );
    c.write_at(
        &format!("{new_dir}/{ROOT}.jsonl"),
        copy,
        "2026-11-04T07:03:00Z",
    );
    let scanner = E2ScanFixture::default();
    let page = ready(&c, &scanner, ScanIndex::default(), 100, true);
    assert_mode(page.modes, (2, 0, 0));
    assert_eq!(total(&page), 2, "{name}: r1 counts once, plus r2");
    let paths = scanner.paths();
    assert_eq!(paths.len(), 2, "{name}: both twins are read");
    assert!(
        paths[0].ends_with(format!(
            "{}/{ROOT}.jsonl",
            if reverse { new_dir } else { old_dir }
        )),
        "{name}: fixture must exercise the requested discovery order"
    );
    (twin_tools(&page), sent_money(&page))
}

/// [regress] Tool usage is display data. One body per session sums every
/// path twin's money but kept only the first-read twin's tool counts, so the
/// discovery order decided `tool_usage`. Each tool now takes its highest
/// count over the twins: a turn only one twin holds is kept, a copied turn
/// counts once, and a superset twin adds its extra tool. Money is the same
/// in both orders.
#[test]
fn e2_pipeline_twin_tool_usage_is_independent_of_scan_order() {
    let (r2_at, r2_tokens) = ("2026-11-04T07:03:10Z", 20);
    for (name, original, copy, expected) in [
        (
            "e2-twin-tools-one-side",
            line(ROOT, "r1", AT, 10),
            line(ROOT, "r1", AT, 10) + &tool_line("r2", r2_at, r2_tokens, &["Read"]),
            tool_rows(&[("Read", 1)]),
        ),
        (
            "e2-twin-tools-copied",
            tool_line("r1", AT, 10, &["Read"]),
            tool_line("r1", AT, 10, &["Read"]) + &line(ROOT, "r2", r2_at, r2_tokens),
            tool_rows(&[("Read", 1)]),
        ),
        (
            "e2-twin-tools-superset",
            tool_line("r1", AT, 10, &["Read"]),
            tool_line("r1", AT, 10, &["Read"]) + &tool_line("r2", r2_at, r2_tokens, &["Bash"]),
            tool_rows(&[("Bash", 1), ("Read", 1)]),
        ),
    ] {
        with_e2(|| {
            let (forward, forward_money) = tool_twins(name, false, &original, &copy);
            let (reverse, reverse_money) = tool_twins(name, true, &original, &copy);
            assert_eq!(forward, (expected.clone(), false), "{name}: forward tools");
            assert_eq!(reverse, forward, "{name}: both orders send one tool list");
            assert_same_money(&forward_money, &reverse_money, name);
        });
    }
}

/// [regress] A tool turn appended to one settled twin, hinted first: the
/// Tail, a cold restart and a cold Full of the same bytes (which reads the
/// twin without the tool turn first) send the same tool rows and money.
#[test]
fn e2_pipeline_twin_tool_turn_tail_matches_cold_full() {
    use crate::snapshots::sampled_scan::transition_fixture::money_oracle;
    with_e2(|| {
        let seed = |c: &mut Corpus| {
            c.write_at(
                &format!("a/{ROOT}.jsonl"),
                &line(ROOT, "r1", AT, 10),
                "2026-08-02T07:00:00Z",
            );
            c.write_at(
                &format!("z/{ROOT}.jsonl"),
                &(line(ROOT, "r1", AT, 10) + &line(ROOT, "r2", "2026-11-04T07:03:10Z", 20)),
                "2026-11-04T07:03:00Z",
            )
        };
        let r3 = tool_line("r3", "2026-11-04T07:04:00Z", 30, &["Read"]);
        let mut c = Corpus::new("e2-twin-tools-tail");
        let grown = seed(&mut c);
        let scanner = E2ScanFixture::default();
        let first = ready(&c, &scanner, ScanIndex::default(), 100, true);
        assert_mode(first.modes, (2, 0, 0));
        assert_eq!(
            twin_tools(&first),
            (tool_rows(&[]), false),
            "no tool turn yet"
        );
        let prior = settle(&c, &ScanIndex::default(), first, &mut e2_progress());
        append(&grown, &r3);
        let mut warm = c.raw(
            &scanner,
            prior.clone(),
            100,
            true,
            std::slice::from_ref(&grown),
        );
        warm.enrich(&c);
        let warm = deliver_page(warm);
        if crate::heap_layout_bound::layout_supported() {
            assert_eq!(warm.modes.0, 0, "the growth reads Tail, not Full");
            assert!(warm.modes.1 > 0, "the grown twin reads Tail");
        }
        let expected = (tool_rows(&[("Read", 1)]), false);
        assert_eq!(twin_tools(&warm), expected, "tail tools");
        let warm_money = sent_money(&warm);
        drop(warm);
        // A restart restores the saved state, so its read mode is not pinned
        // here; the fresh corpus below is the cold Full.
        let restarted = cold_ready(&c, prior, 100, true);
        assert_eq!(twin_tools(&restarted), expected, "restart tools");

        let mut cold = Corpus::new("e2-twin-tools-tail-cold");
        append(&seed(&mut cold), &r3);
        let cold_scanner = E2ScanFixture::default();
        let full = ready(&cold, &cold_scanner, ScanIndex::default(), 100, true);
        assert_mode(full.modes, (2, 0, 0));
        assert!(
            cold_scanner.paths()[0].ends_with(format!("a/{ROOT}.jsonl")),
            "the cold Full reads the twin without the tool turn first"
        );
        assert_eq!(twin_tools(&full), expected, "cold Full keeps the tool turn");
        assert_eq!(total(&full), 3, "r1 counts once, plus r2 and r3");
        let full_money = sent_money(&full);
        money_oracle::assert_equivalent(&full_money, &warm_money);
        money_oracle::assert_equivalent(&full_money, &sent_money(&restarted));
    });
}

/// [regress] The identity byte cap measures the merged tool rows. A body
/// that fits with the carrier's own rows but not with the merged ones falls
/// back to its own rows: it is offered and exactly acknowledged, never held,
/// and its money is unchanged.
#[test]
fn e2_pipeline_twin_tool_merge_never_holds_a_fitting_body() {
    use crate::snapshots::claude_request_identity::{item_bytes, WireBudget};
    with_e2(|| {
        let names = (0..150)
            .map(|n| format!("NearCapTool{n:03}_{}", "x".repeat(80)))
            .collect::<Vec<_>>();
        let names = names.iter().map(String::as_str).collect::<Vec<_>>();
        let r1 = tool_line("r1", AT, 10, &["Read"]);
        let copy = r1.clone() + &tool_line("r2", "2026-11-04T07:03:10Z", 20, &names);
        let corpus = |name: &str| {
            let mut c = Corpus::new(name);
            c.write_at(&format!("a/{ROOT}.jsonl"), &r1, "2026-08-02T07:00:00Z");
            c.write_at(&format!("z/{ROOT}.jsonl"), &copy, "2026-11-04T07:03:00Z");
            c
        };
        let own = tool_rows(&[("Read", 1)]);

        let c = corpus("e2-twin-tools-cap-default");
        let scanner = E2ScanFixture::default();
        let merged = ready(&c, &scanner, ScanIndex::default(), 100, false);
        assert!(
            scanner.paths()[0].ends_with(format!("a/{ROOT}.jsonl")),
            "the carrier is the twin with only the Read turn"
        );
        let (rows, truncated) = twin_tools(&merged);
        assert_eq!(
            (rows.len(), truncated),
            (151, false),
            "every twin tool merged"
        );
        let item = &merged.scan.snapshots[0];
        let mut fallback = item.clone();
        fallback.tool_usage = Some(
            own.iter()
                .map(|(name, count)| crate::snapshots::SnapshotToolUsage {
                    name: name.clone(),
                    count: *count,
                })
                .collect(),
        );
        let (merged_bytes, own_bytes) = (item_bytes(item), item_bytes(&fallback));
        assert!(
            merged_bytes > own_bytes + 8_000,
            "{merged_bytes} vs {own_bytes}"
        );
        let merged_money = sent_money(&merged);
        drop(merged);

        let c = corpus("e2-twin-tools-cap-near");
        let mut page = c.raw(
            &E2ScanFixture::default(),
            ScanIndex::default(),
            100,
            false,
            &[],
        );
        page.enrich_with_budget(
            &c,
            None,
            WireBudget {
                max_item_bytes: own_bytes + (merged_bytes - own_bytes) / 2,
                reservation: None,
            },
        );
        assert!(
            page.disposition.request_owned_hold_reasons.is_empty(),
            "nothing is held: {:?}",
            page.disposition.request_owned_hold_reasons
        );
        assert_eq!(
            twin_tools(&page),
            (own.clone(), false),
            "own rows fall back"
        );
        assert_same_money(&merged_money, &sent_money(&page), "near cap");
        page.finish();
        assert_eq!(twin_tools(&page), (own, false), "the finished body");
        let item = page.scan.snapshots[0].clone();
        let mut progress = e2_progress();
        let (result, _, _) = upload(&page.scan.snapshots, &mut progress, ack);
        assert_eq!(result.unwrap(), ResumableUploadResult::Completed);
        assert_eq!(
            progress
                .accepted_body_witnesses
                .get(&item.snapshot_fingerprint),
            Some(&snapshot_upload_body_witness(&item)),
            "the offered body is exactly acknowledged"
        );
    });
}

/// A current Claude Code version. No writer version decides a copy: every
/// copied prefix takes request-id proof.
const UNLISTED_WRITER: &str = "2.1.316";
/// One page's bodies as finished and sent.
fn sent_money(page: &Page) -> crate::snapshots::sampled_scan::transition_fixture::RouteResult {
    let mut sent = twin(page);
    sent.finish();
    crate::snapshots::sampled_scan::transition_fixture::scan_money(
        SnapshotSource::ClaudeCode,
        &sent.index,
        &sent.scan,
    )
}

/// [regress] A resumed session whose earlier path is still on disk: an
/// unlisted writer's resume was read on one page with that path and its
/// copied prefix counted on both. A resume whose own turns start after the
/// cutoff counts each copied request once (old copied clocks included), in
/// both discovery orders and down a chain of resumes, through settle, tail,
/// restart and a cold read. That cold read gives the resumes other file
/// system births (one before the cutoff): the copy's own clock decides.
#[test]
fn e2_pipeline_unlisted_twin_resume_counts_copied_requests_once() {
    use crate::snapshots::sampled_scan::transition_fixture::money_oracle;
    for (reverse, chain) in [(false, false), (true, false), (false, true)] {
        with_e2(|| {
            let line = |request, at, tokens| line_by(ROOT, request, at, tokens, UNLISTED_WRITER);
            let (r1, r2) = (line("r1", AT, 10), line("r2", "2026-11-04T07:03:10Z", 20));
            // (folder, lines, stored birth, cold birth); r1 keeps its old clock.
            let mut files = vec![
                (
                    "a",
                    r1.clone(),
                    "2026-08-02T07:00:00Z",
                    "2026-08-02T07:00:00Z",
                ),
                (
                    "m",
                    r1.clone() + &r2,
                    "2026-11-04T07:03:00Z",
                    "2026-11-03T23:59:00Z",
                ),
            ];
            if chain {
                let r3 = line("r3", "2026-11-04T08:00:10Z", 30);
                files.push((
                    "z",
                    r1 + &r2 + &r3,
                    "2026-11-04T08:00:00Z",
                    "2026-11-04T07:30:00Z",
                ));
            }
            if reverse {
                // The resume's folder sorts first: it is discovered first.
                files[0].0 = "z";
            }
            let (counted, removed) = if chain { (3, 3) } else { (2, 1) };
            let name = format!("e2-pipeline-unlisted-twin-{reverse}-{chain}");
            let mut c = Corpus::new(&name);
            let mut latest = PathBuf::new();
            for (folder, text, birth, _) in &files {
                latest = c.write_at(&format!("{folder}/{ROOT}.jsonl"), text, birth);
            }
            let scanner = E2ScanFixture::default();
            e2::take_diag();
            let first = ready(&c, &scanner, ScanIndex::default(), 100, true);
            literal(&first);
            assert_eq!(scanner.paths().len(), files.len(), "every path is read");
            assert_eq!(first.scan.snapshots.len(), 1);
            assert_eq!(
                (total(&first), first.scan.snapshots[0].removed_request_count),
                (counted, Some(removed)),
                "{name}: each copied request counts once"
            );
            assert_eq!(copy_diag(&["copy_prefix_twin_page_removed"]), [0]);
            assert!(!first.index.claude_copy_removals.is_empty());
            let prior = settle(&c, &ScanIndex::default(), first, &mut e2_progress());
            append(&latest, &line("late", "2026-11-04T09:00:00Z", 40));
            let tail = ready(&c, &scanner, prior.clone(), 100, true);
            literal(&tail);
            assert_eq!(
                total(&tail),
                counted + 1,
                "{name}: the tail adds its own turn"
            );
            let tail_money = sent_money(&tail);
            drop(tail);
            let restarted = cold_ready(&c, prior, 100, true);
            let mut cold = Corpus::new(&format!("{name}-cold"));
            for (folder, _, _, birth) in &files {
                let relative = format!("{folder}/{ROOT}.jsonl");
                let text = std::fs::read_to_string(c.root.join(&relative)).unwrap();
                cold.write_at(&relative, &text, birth);
            }
            let cold = ready(
                &cold,
                &E2ScanFixture::default(),
                ScanIndex::default(),
                100,
                true,
            );
            let cold = sent_money(&cold);
            money_oracle::assert_equivalent(&cold, &tail_money);
            money_oracle::assert_equivalent(&cold, &sent_money(&restarted));
        });
    }
}

/// [money] A same-session accepted holder supersedes the old forward-only
/// cutoff. Growth declares and removes the earlier copied request.
#[test]
fn e2_pipeline_unlisted_twin_resume_before_cutoff_keeps_its_count() {
    with_e2(|| {
        let line = |request, at, tokens| line_by(ROOT, request, at, tokens, UNLISTED_WRITER);
        let mut c = Corpus::new("e2-pipeline-unlisted-twin-before-cutoff");
        let r1 = line("r1", AT, 10);
        c.write_at(&format!("a/{ROOT}.jsonl"), &r1, "2026-08-02T07:00:00Z");
        let copy = c.write_at(
            &format!("z/{ROOT}.jsonl"),
            &(r1 + &line("r2", "2026-11-03T07:03:10Z", 20)),
            "2026-11-03T07:03:00Z",
        );
        let scanner = E2ScanFixture::default();
        e2::take_diag();
        let first = ready(&c, &scanner, ScanIndex::default(), 100, true);
        literal(&first);
        assert_eq!(
            (total(&first), first.scan.snapshots[0].removed_request_count),
            (2, Some(1))
        );
        let prior = settle(&c, &ScanIndex::default(), first, &mut e2_progress());
        append(&copy, &line("r3", "2026-11-04T09:00:00Z", 30));
        let grown = ready(&c, &scanner, prior, 100, true);
        literal(&grown);
        assert_eq!(
            (total(&grown), grown.scan.snapshots[0].removed_request_count),
            (3, Some(1))
        );
        assert_eq!(copy_diag(&["copy_prefix_twin_page_removed"]), [0]);
    });
}

/// [money] No undercount with the holder off the page: a post-cutoff
/// unlisted writer's resume read without its earlier path (outside this
/// pass's scan roots) counts the copied request exactly once, from the
/// resume, and the page proof stays off. The same pair on one page counts it
/// once, from the holder, with equal totals. A session first published from
/// the resume alone then converges to the cold co-read once both are read.
#[test]
fn e2_pipeline_unlisted_twin_resume_counts_copied_request_once_with_holder_off_page() {
    use crate::snapshots::sampled_scan::transition_fixture::money_oracle;
    with_e2(|| {
        let line = |request, at, tokens| line_by(ROOT, request, at, tokens, UNLISTED_WRITER);
        let mut c = Corpus::new("e2-pipeline-unlisted-twin-holder-off-page");
        let projects = c.root.clone();
        let r1 = line("r1", AT, 10);
        c.write_at(&format!("a/{ROOT}.jsonl"), &r1, "2026-08-02T07:00:00Z");
        let scanner = E2ScanFixture::default();
        let holder = ready(&c, &scanner, ScanIndex::default(), 100, true);
        assert_eq!(total(&holder), 1);
        let prior = settle(&c, &ScanIndex::default(), holder, &mut e2_progress());
        let copy = c.write_at(
            &format!("z/{ROOT}.jsonl"),
            &(r1 + &line("r2", "2026-11-04T07:03:10Z", 20)),
            "2026-11-04T07:03:00Z",
        );
        // This pass scans only the resume's folder: its holder stays off the page.
        c.root = projects.join("z");
        e2::take_diag();
        let alone = ready(&c, &scanner, prior.clone(), 100, true);
        literal(&alone);
        let opened = scanner.paths();
        assert!(
            opened.len() == 1 && opened[0].ends_with(format!("z/{ROOT}.jsonl")),
            "only the resume is read: {opened:?}"
        );
        assert_eq!(total(&alone), 2, "r1 once (from the resume) and r2");
        assert_eq!(copy_diag(&["copy_prefix_twin_page_removed"]), [0]);
        c.root = projects;
        e2::take_diag();
        let together = ready(
            &c,
            &E2ScanFixture::default(),
            ScanIndex::default(),
            100,
            true,
        );
        literal(&together);
        assert_eq!(total(&together), 2, "r1 once (from the holder) and r2");
        assert_eq!(copy_diag(&["copy_prefix_twin_page_removed"]), [0]);
        assert!(!together.index.claude_copy_removals.is_empty());
        // Alone the resume restores and discloses r1, beside its holder it removes it
        // (removed_request_count, copy_unproven): compare counted totals only.
        let counted = |page: &Page| {
            let s = &page.scan.snapshots[0];
            [
                s.request_count,
                s.input_tokens,
                s.output_tokens,
                s.cache_read_tokens,
                s.cache_creation_5m_tokens,
                s.cache_creation_1h_tokens,
            ]
        };
        assert_eq!(counted(&alone), counted(&together));
        let prior = settle(&c, &prior, alone, &mut e2_progress());
        append(&copy, &line("r3", "2026-11-04T09:00:00Z", 30));
        let stored = ready(&c, &scanner, prior, 100, true);
        literal(&stored);
        assert_eq!(total(&stored), 3, "r1 once, r2, r3");
        let cold = ready(
            &c,
            &E2ScanFixture::default(),
            ScanIndex::default(),
            100,
            true,
        );
        money_oracle::assert_equivalent(&sent_money(&cold), &sent_money(&stored));
    });
}

/// Each walk meets both path twins, but a settled twin does not pull its
/// family into the page. Only a twin the page reads does; otherwise the
/// family is read again and one batch is sent on every walk.
#[test]
fn e2_pipeline_settled_twins_are_not_read_again() {
    with_e2(|| {
        let mut c = Corpus::new("e2-pipeline-twins-settled");
        c.write_at(
            &format!("a-original/{ROOT}.jsonl"),
            &line(ROOT, "r1", AT, 10),
            "2026-08-02T07:00:00Z",
        );
        c.write_at(
            &format!("z-copy/{ROOT}.jsonl"),
            &(line(ROOT, "r1", AT, 10) + &line(ROOT, "r2", "2026-08-02T07:03:10Z", 20)),
            "2026-08-02T07:03:00Z",
        );
        let scanner = E2ScanFixture::default();
        let mut index = ScanIndex::default();
        let mut pages = Vec::new();
        for _ in 0..4 {
            let mut page = c.raw(&scanner, index, 100, false, &[]);
            page.enrich(&c);
            page.finish();
            if !page.scan.snapshots.is_empty() {
                let mut progress = e2_progress();
                let (result, _, _) = upload(&page.scan.snapshots, &mut progress, ack);
                assert_eq!(result.unwrap(), ResumableUploadResult::Completed);
                page.index
                    .record_accepted_snapshot_fingerprints(&progress.accepted_fingerprints);
                accept_upload_context_acks_for_test(
                    &mut page.index,
                    &page.scan.snapshots,
                    &progress.fresh_context_body_acks,
                );
            }
            pages.push((
                page.scan.scanned_file_count,
                page.scan.snapshots.len(),
                page.scan.census_complete,
            ));
            index = c.reload(&mut page.index);
        }
        assert_eq!(pages[0].0, 2, "the first walk reads both twins: {pages:?}");
        assert_eq!(
            pages[2..]
                .iter()
                .map(|page| (page.0, page.1))
                .collect::<Vec<_>>(),
            [(0, 0), (0, 0)],
            "settled twins are not read again: {pages:?}"
        );
    });
}

#[test]
fn e2_pipeline_off_page_twin_hold_preserves_complete_history() {
    with_e2(|| {
        let mut c = Corpus::new("e2-pipeline-twin-hold");
        let original = c.write_at(
            &format!("a/{ROOT}.jsonl"),
            &line(ROOT, "r1", AT, 10),
            "2026-08-02T07:00:00Z",
        );
        // Own turns from the copy proof cutoff on: the page proof dedupes r1.
        let twin = c.write_at(
            &format!("z/{ROOT}.jsonl"),
            &(line(ROOT, "r1", AT, 10) + &line(ROOT, "r2", "2026-11-04T07:03:10Z", 20)),
            "2026-11-04T07:03:00Z",
        );
        let scanner = E2ScanFixture::default();
        let mut complete = ready(&c, &scanner, ScanIndex::default(), 100, false);
        literal(&complete);
        assert_eq!(total(&complete), 2);
        complete.finish();
        let mut progress = e2_progress();
        let (result, _, _) = upload(&complete.scan.snapshots, &mut progress, ack);
        assert_eq!(result.unwrap(), ResumableUploadResult::Completed);
        complete
            .index
            .record_accepted_snapshot_fingerprints(&progress.accepted_fingerprints);
        let prior = c.reload(&mut complete.index);
        std::fs::OpenOptions::new()
            .append(true)
            .open(&twin)
            .unwrap()
            .write_all(line(ROOT, "r3", "2026-11-04T07:04:00Z", 30).as_bytes())
            .unwrap();
        let mut page = c.raw(&scanner, prior, 1, false, std::slice::from_ref(&twin));
        page.enrich(&c);
        // The completed census dropped its walk, so this page lists both
        // twins again and gives its one census slot to the listed original
        // ahead of the hint. Settled and unchanged, the original reads
        // nothing and pulls no family (the old terminal family re-arm had
        // cleared its fingerprint, so it read both twins here). The grown
        // twin stays queued for a later page; nothing may publish before it.
        let mut deferred = 0;
        while page.scan.snapshots.is_empty() {
            assert!(
                scanner.paths().is_empty()
                    && page.disposition.request_owned_hold_reasons.is_empty(),
                "a deferring page opens and holds nothing: page={deferred} opened={} \
                 scanned={} holds={:?}",
                scanner.paths().len(),
                page.scan.scanned_file_count,
                page.disposition.request_owned_hold_reasons
            );
            deferred += 1;
            assert!(deferred <= 3, "the grown twin is read on a later page");
            page.finish();
            let next = c.reload(&mut page.index);
            page = c.raw(&scanner, next, 1, false, &[]);
            page.enrich(&c);
        }
        assert_eq!(
            scanner.paths().len(),
            2,
            "both twin paths must actually be opened (after {deferred} deferring pages)"
        );
        assert_eq!(
            total(&page),
            3,
            "a partial twin must never overwrite complete history"
        );
        assert!(original.is_file());
    });
}

/// [regress] A grown twin whose growth Full was paced still pulled its
/// unchanged twin into a forced-family Full on every listing; the pace then
/// deferred the grown twin, so the sibling was held as `absent_twin` each page.
/// While paced neither twin is read and nothing is held; once due, both read
/// together, the growth publishes and nothing is held.
#[test]
fn e2_pipeline_paced_twin_does_not_force_its_family() {
    use crate::snapshots::e2_pipeline_scan_fixture::{indexed_size, owe_claimed_growth};
    with_e2(|| {
        let mut c = Corpus::new("e2-pipeline-twin-paced");
        c.write_at(
            &format!("a/{ROOT}.jsonl"),
            &line(ROOT, "r1", AT, 10),
            "2026-08-02T07:00:00Z",
        );
        // Own turns from the copy proof cutoff on: the page proof dedupes r1.
        let twin = c.write_at(
            &format!("z/{ROOT}.jsonl"),
            &(line(ROOT, "r1", AT, 10) + &line(ROOT, "r2", "2026-11-04T07:03:10Z", 20)),
            "2026-11-04T07:03:00Z",
        );
        let scanner = E2ScanFixture::default();
        let mut index = ScanIndex::default();
        let mut reads = Vec::new();
        for _ in 0..3 {
            let mut page = c.raw(&scanner, index, 100, false, &[]);
            page.enrich(&c);
            page.finish();
            if !page.scan.snapshots.is_empty() {
                let mut progress = e2_progress();
                let (result, _, _) = upload(&page.scan.snapshots, &mut progress, ack);
                assert_eq!(result.unwrap(), ResumableUploadResult::Completed);
                page.index
                    .record_accepted_snapshot_fingerprints(&progress.accepted_fingerprints);
                accept_upload_context_acks_for_test(
                    &mut page.index,
                    &page.scan.snapshots,
                    &progress.fresh_context_body_acks,
                );
            }
            reads.push(page.scan.scanned_file_count);
            index = c.reload(&mut page.index);
        }
        assert_eq!(reads.last(), Some(&0), "both twins settled: {reads:?}");
        let indexed = indexed_size(&index, &twin);
        append(&twin, &line(ROOT, "r3", "2026-11-04T07:04:00Z", 30));
        for paced in [true, false] {
            let owed = owe_claimed_growth(&index, &c.base, &twin, paced);
            let mut page = c.raw(&scanner, owed, 100, false, std::slice::from_ref(&twin));
            page.enrich(&c);
            assert_eq!(
                page.disposition
                    .request_owned_hold_reasons
                    .get("absent_twin"),
                None,
                "paced={paced}: no twin is held off the page"
            );
            if paced {
                assert_eq!(
                    (scanner.paths().len(), page.scan.snapshots.len()),
                    (0, 0),
                    "a paced twin pulls no forced-family Full"
                );
                assert_eq!(
                    indexed_size(&page.index, &twin),
                    indexed,
                    "growth stays owed"
                );
            } else {
                assert_eq!(scanner.paths().len(), 2, "both twins read together");
                assert_eq!(total(&page), 3, "the due growth publishes");
            }
        }
    });
}

/// [money] An all-pre-birth path twin has no own turn, so nothing proves
/// locally owned earlier path proves the copy on the first page. After the
/// accepted original is deleted, the survivor keeps its stored body and, once it
/// changes, still counts r1 once and its own new turn.
#[test]
fn e2_pipeline_deleted_original_leaves_one_count_after_restart() {
    with_e2(|| {
        let mut c = Corpus::new("e2-pipeline-twin-delete");
        let original = c.write_at(
            &format!("a/{ROOT}.jsonl"),
            &line(ROOT, "r1", AT, 10),
            "2026-08-02T07:00:00Z",
        );
        let survivor = c.write_at(
            &format!("z/{ROOT}.jsonl"),
            &line(ROOT, "r1", AT, 10),
            "2026-08-02T07:03:00Z",
        );
        let scanner = E2ScanFixture::default();
        e2::take_diag();
        let mut first = ready(&c, &scanner, ScanIndex::default(), 100, false);
        assert_eq!(
            total(&first),
            1,
            "the locally owned earlier twin counts r1 once"
        );
        assert_eq!(copy_diag(&["copy_prefix_unproven"]), [0]);
        assert!(
            !first.index.claude_copy_removals.is_empty(),
            "the local removal is recorded"
        );
        first.finish();
        let prior = c.reload(&mut first.index);
        std::fs::remove_file(original).unwrap();
        let stored = stored_bodies(&prior);
        let mut left = ready(&c, &E2ScanFixture::default(), prior, 100, false);
        // The unchanged survivor is not read again
        // (latest wins); it re-emits on its next real change.
        assert!(
            left.scan.snapshots.is_empty(),
            "an unchanged survivor emits nothing new"
        );
        left.finish();
        assert_eq!(
            stored_bodies(&left.index),
            stored,
            "the stored body stays byte-identical"
        );
        append(&survivor, &line(ROOT, "r2", "2026-08-02T07:04:00Z", 20));
        let prior = c.reload(&mut left.index);
        let changed = ready(&c, &E2ScanFixture::default(), prior, 100, false);
        literal(&changed);
        assert_eq!(
            total(&changed),
            2,
            "the sole surviving path keeps known original money"
        );
    });
}

/// [money] A resumed branch whose original (another session in its folder)
/// was delivered on an earlier page removes exactly its copied request, by
/// request id, and keeps its own turn.
#[test]
fn e2_pipeline_one_branch_removes_copied_prefix_only() {
    with_e2(|| {
        let mut c = Corpus::new("e2-pipeline-branch");
        c.root(ROOT, &line(ROOT, "r1", AT, 10));
        let scanner = E2ScanFixture::default();
        let tuple = |s: &SnapshotItem| {
            (
                s.request_count,
                s.input_tokens,
                s.output_tokens,
                s.cache_read_tokens,
                s.cache_creation_5m_tokens,
                s.cache_creation_1h_tokens,
            )
        };
        let mut original = ready(&c, &scanner, ScanIndex::default(), 100, false);
        literal(&original);
        let root = body(&original, ROOT).expect("the original publishes");
        assert_eq!(tuple(root), (1, 10, 10, 3, 5, 2));
        assert_eq!(root.removed_request_count, Some(0));
        original.finish();
        let prior = c.reload(&mut original.index);
        c.write_at(
            &format!("{COPY}.jsonl"),
            &(line(COPY, "r1", AT, 10) + &line(COPY, "branch-own", "2026-08-02T07:03:10Z", 0)),
            "2026-08-02T07:03:00Z",
        );
        let p = ready(&c, &scanner, prior, 100, false);
        literal(&p);
        let copied = body(&p, COPY).expect("the branch publishes");
        assert_eq!(
            tuple(copied),
            (1, 0, 0, 3, 5, 2),
            "own branch response only (zero input/output)"
        );
        assert_eq!(
            copied.removed_request_count,
            Some(1),
            "copy_skipped must be positive for deliberate branch"
        );
        if let Some(root) = body(&p, ROOT) {
            assert_eq!(tuple(root), (1, 10, 10, 3, 5, 2));
            assert_eq!(root.removed_request_count, Some(0));
        }
        let removed = copied.removed_usage.as_ref().unwrap();
        assert_eq!(
            (
                removed.input_tokens,
                removed.output_tokens,
                removed.cache_read_tokens,
                removed.cache_creation_5m_tokens,
                removed.cache_creation_1h_tokens
            ),
            (10, 10, 3, 5, 2)
        );
    });
}

#[test]
fn e2_pipeline_side_call_uses_trace_named_agent_and_counts_root_fallback() {
    with_e2(|| {
        let mut c = Corpus::new("e2-pipeline-side-calls");
        c.root(ROOT, &line(ROOT, "root", AT, 10));
        c.agent(0, &line(ROOT, "agent", AT, 20));
        c.evidence(
            &[
                api("root", 10, 100),
                api("agent", 20, 200),
                api("side", 5, 50),
                api("fallback", 7, 70),
            ],
            &[trace("side", "000")],
        );
        let p = ready(
            &c,
            &E2ScanFixture::default(),
            ScanIndex::default(),
            100,
            false,
        );
        literal(&p);
        let root = p
            .scan
            .snapshots
            .iter()
            .find(|s| s.source_session_id == ROOT)
            .unwrap();
        let agent = p
            .scan
            .snapshots
            .iter()
            .find(|s| s.source_session_id == format!("{ROOT}_agent-000"))
            .unwrap();
        assert_eq!((root.request_count, root.input_tokens), (2, 17));
        assert_eq!((agent.request_count, agent.input_tokens), (2, 25));
        assert_eq!(
            e2::pipeline_test_observer::root_fallbacks(&p.scan.snapshots)
                + p.released.root_fallbacks,
            1,
            "exactly one side call used the counted root fallback"
        );
    });
}

#[test]
fn e2_pipeline_quiet_otel_only_change_replaces_estimate_without_count_growth() {
    with_e2(|| {
        let mut c = Corpus::new("e2-pipeline-quiet-otel");
        let path = c.root(ROOT, &line(ROOT, "root", AT, 10));
        let scanner = E2ScanFixture::default();
        let mut first = ready(&c, &scanner, ScanIndex::default(), 100, true);
        assert_eq!(total(&first), 1);
        assert_eq!(
            first.scan.snapshots[0].telemetry_owned_complete,
            Some(false)
        );
        first.finish();
        let mut progress = e2_progress();
        upload(&first.scan.snapshots, &mut progress, ack).0.unwrap();
        first
            .index
            .record_accepted_snapshot_fingerprints(&progress.accepted_fingerprints);
        let prior = c.reload(&mut first.index);
        let metadata = std::fs::metadata(&path).unwrap();
        c.evidence(&[api("root", 10, 100)], &[]);
        let after = ready(&c, &scanner, prior, 100, true);
        assert_eq!(
            std::fs::metadata(&path).unwrap().modified().unwrap(),
            metadata.modified().unwrap()
        );
        assert_mode(after.modes, (0, 0, 1));
        literal(&after);
        assert_eq!(total(&after), 1);
        assert_eq!(after.scan.snapshots[0].telemetry_owned_complete, Some(true));
        assert!(after.scan.snapshots[0]
            .model_usage
            .iter()
            .filter(|r| r.request_count > 0)
            .all(|r| r
                .selector_context
                .get("request_usage_origin")
                .is_some_and(|v| v == "telemetry_matched")));
        assert_eq!(
            after.scan.snapshots[0]
                .model_usage
                .iter()
                .map(|r| r.request_count)
                .sum::<u64>(),
            1
        );
        assert_eq!(after.scan.snapshots[0].input_tokens, 10);
        assert_ne!(
            after.scan.snapshots[0].snapshot_fingerprint,
            first.scan.snapshots[0].snapshot_fingerprint
        );
    });
}

#[test]
fn e2_pipeline_trace_named_agent_on_another_page_is_not_published_on_root() {
    with_e2(|| {
        let mut c = Corpus::new("e2-pipeline-side-other-page");
        let root = c.root(ROOT, &line(ROOT, "root", AT, 10));
        c.agent(0, &line(ROOT, "agent", AT, 20));
        c.evidence(
            &[api("root", 10, 100), api("agent", 20, 200)],
            &[trace("root", ""), trace("agent", "000")],
        );
        let scanner = E2ScanFixture::default();
        let mut baseline = ready(&c, &scanner, ScanIndex::default(), 100, false);
        baseline.finish();
        let mut baseline_progress = e2_progress();
        upload(&baseline.scan.snapshots, &mut baseline_progress, ack)
            .0
            .unwrap();
        assert_eq!(
            baseline_progress.accepted_fingerprints.len(),
            2,
            "baseline root and agent really received ACKs"
        );
        baseline
            .index
            .record_accepted_snapshot_fingerprints(&baseline_progress.accepted_fingerprints);
        let prior = c.reload(&mut baseline.index);
        c.evidence(
            &[
                api("root", 10, 100),
                api("agent", 20, 200),
                api("side", 5, 50),
            ],
            &[
                trace("root", ""),
                trace("agent", "000"),
                trace("side", "000"),
            ],
        );
        std::fs::OpenOptions::new()
            .append(true)
            .open(&root)
            .unwrap()
            .write_all(line(ROOT, "root2", "2026-08-02T07:01:00Z", 1).as_bytes())
            .unwrap();
        let mut p = c.raw(&scanner, prior, 1, false, std::slice::from_ref(&root));
        p.enrich(&c);
        if let Some(root_body) = p
            .scan
            .snapshots
            .iter()
            .find(|s| s.source_session_id == ROOT)
        {
            assert_eq!(
                root_body.input_tokens, 11,
                "trace-named side call must never fall back to root"
            );
        } else if scanner.paths().contains(&root) {
            assert!(crate::snapshots::e2_pipeline_scan_fixture::explicitly_held(&p.disposition, ROOT),
                "absent root must have an explicit hold; a partial family cannot silently cancel it");
        } else {
            // The one-file page read another member first: the root was not
            // read, so nothing about it was decided. It must still be due.
            assert_ne!(
                crate::snapshots::e2_pipeline_scan_fixture::indexed_size(&p.index, &root),
                Some(std::fs::metadata(&root).unwrap().len()),
                "an unread root keeps its old extent, so its append stays due"
            );
        }
        // An absent agent must stay due or be co-scheduled. Observe the next
        // real bounded pages; a named side call must eventually reach it.
        let mut items = p.scan.snapshots.clone();
        p.finish();
        let mut index = c.reload(&mut p.index);
        for _ in 0..6 {
            let mut next = ready(&c, &scanner, index, 1, false);
            items.extend(next.scan.snapshots.clone());
            next.finish();
            index = c.reload(&mut next.index);
        }
        assert!(items
            .iter()
            .filter(|s| s.source_session_id == ROOT)
            .all(|s| s.input_tokens == 11));
        assert!(
            items
                .iter()
                .any(|s| s.source_session_id == ROOT && s.input_tokens == 11),
            "the appended root must eventually publish, without the named side call"
        );
        assert!(items.iter().any(|s| s.source_session_id==format!("{ROOT}_agent-000") && s.input_tokens==25),"off-page named agent must eventually publish its side call");
    });
}

/// [`ready`] under a cycle with the cache mode off: as in production, the
/// upload seam drops the cache rows before delivery, so each ACK proves the
/// body the page keeps.
fn ready_without_cache(
    corpus: &Corpus,
    scanner: &E2ScanFixture,
    index: ScanIndex,
    limit: usize,
    sampled: bool,
) -> Page {
    let mut page = corpus.raw(scanner, index, limit, sampled, &[]);
    page.enrich(corpus);
    for snapshot in &mut page.scan.snapshots {
        prepare_snapshot_cache_for_upload(snapshot, &e2_progress(), false, false);
    }
    deliver_page(page)
}

fn retry_case(conflict: bool) {
    with_e2(|| {
        let mut c = Corpus::new(if conflict {
            "e2-pipeline-retry-conflict"
        } else {
            "e2-pipeline-retry-clean"
        });
        // An earlier session in the same folder holds the copied request; its
        // page is delivered first, so the root's copied prefix is removed by
        // request id on its first read and after the restart alike.
        c.write_at(
            &format!("{COPY}.jsonl"),
            &line(COPY, "copied", "2026-08-02T06:58:00Z", 11),
            "2026-08-02T06:57:00Z",
        );
        let scanner = E2ScanFixture::default();
        let mut holder = ready_without_cache(&c, &scanner, ScanIndex::default(), 100, false);
        assert_eq!(total(&holder), 1);
        holder.finish();
        let committed = c.reload(&mut holder.index);
        let prefix = line(ROOT, "copied", "2026-08-02T06:58:00Z", 11);
        let a = line(ROOT, "conflict", AT, 2);
        let b = a.replace("claude-haiku-4-5", "claude-sonnet-4-5");
        let conflict_lines = if conflict { a + &b } else { String::new() };
        c.root(
            ROOT,
            &(prefix + &conflict_lines + &line(ROOT, "own", AT, 20)),
        );
        c.agent(0, &line(ROOT, "agent", AT, 5));
        let mut p = ready_without_cache(&c, &scanner, committed.clone(), 100, false);
        literal(&p);
        let root = p
            .scan
            .snapshots
            .iter()
            .find(|s| s.source_session_id == ROOT)
            .expect("resolver-conflict root must reach literal emission with its disclosure");
        assert_eq!(root.removed_request_count, Some(1));
        assert_eq!(
            root.resolver_conflict_count,
            if conflict { Some(1) } else { None }
        );
        assert_eq!(root.telemetry_owned_complete, Some(false));
        let r = root.removed_usage.as_ref().unwrap();
        assert_eq!(
            (
                r.input_tokens,
                r.output_tokens,
                r.cache_read_tokens,
                r.cache_creation_5m_tokens,
                r.cache_creation_1h_tokens
            ),
            (11, 11, 3, 5, 2)
        );
        p.finish();
        let original = canonical(&p.scan.snapshots);
        let fingerprints = p.receipt();
        let mut progress = e2_progress();
        let (failed, first, order) = upload(&p.scan.snapshots, &mut progress, |_| {
            Err(anyhow!("synthetic connection reset before ACK"))
        });
        assert!(failed.is_err());
        assert!(progress.accepted_fingerprints.is_empty());
        assert_eq!(order.len(), 1);
        assert_eq!(order[0].len(), 2);
        assert_eq!(order[0][0], ROOT);
        let holds = LocalHoldSettlement::classify(
            SnapshotSource::ClaudeCode,
            &mut p.index,
            &mut p.scan,
            &p.disposition,
        );
        // Production transport-error seam: progress is durable first, then
        // only wholly settled files advance in the partial checkpoint.
        let index_path = crate::snapshots::e2_pipeline_scan_fixture::route_of(&p.index).unwrap();
        let progress_path = snapshot_upload_progress_path(&index_path);
        progress = route_fixture_progress(&p.index, &index_path, &progress_path, progress);
        progress.save(&progress_path).unwrap();
        checkpoint_partial_snapshot_index_with_audit_release(
            &p.index,
            &committed,
            &progress,
            &p.scan.snapshots,
            Some(&p.scan),
            &holds.held_fingerprints,
            &index_path,
            &progress_path,
            || Ok(()),
            Some(crate::snapshots::UnsettledUploadCause::UploadError),
            None,
            Default::default(),
        )
        .unwrap();
        let prior = ScanIndex::load(&index_path).unwrap();
        let mut progress = SnapshotUploadProgress::load_for_index(
            &prior,
            &index_path,
            &progress_path,
            &format!("{:064x}", 99),
            snapshot_quarantine_witness(SnapshotSource::ClaudeCode),
        )
        .unwrap();
        let mut restart = ready_without_cache(&c, &E2ScanFixture::default(), prior, 100, false);
        restart.finish();
        assert_eq!(
            canonical(&restart.scan.snapshots),
            original,
            "re-scan after restart retains canonical bytes"
        );
        assert_eq!(restart.receipt(), fingerprints);
        // Late telemetry changes the next scan without mutating this page.
        c.evidence(&[api("own", 20, 200), api("agent", 5, 50)], &[]);
        let mut late = ready_without_cache(
            &c,
            &E2ScanFixture::default(),
            restart.index.clone(),
            100,
            false,
        );
        late.finish();
        assert_ne!(
            late.receipt(),
            fingerprints,
            "fresh OTEL really changes the current body while the previously scanned page stays exact"
        );
        let (result, resent, _) = upload(&restart.scan.snapshots, &mut progress, |batch| {
            let mut response = ack(batch)?;
            let refused = response.accepted_entities.pop().unwrap();
            response.accepted -= 1;
            let mut refused = refused;
            refused.head_etag = None;
            response.conflict_entities.push(refused);
            Ok(response)
        });
        assert_eq!(
            result.unwrap(),
            ResumableUploadResult::Deferred {
                count: 1,
                isolated: 1,
                identity_503: 0
            }
        );
        assert_eq!(
            first, resent,
            "transport retry is byte-exact, including removals/conflict/completeness"
        );
        assert_eq!(
            progress.accepted_fingerprints.len(),
            1,
            "partial entity ACK never settles its sibling"
        );
        assert_eq!(progress.quarantined_fingerprints.len(), 1);
        // Accepted root and pending agent are the agreed entity-ACK split;
        // before that ACK the entire small family travelled in one batch.
        assert!(progress.accepted_fingerprints.contains(
            &restart
                .scan
                .snapshots
                .iter()
                .find(|s| s.source_session_id == ROOT)
                .unwrap()
                .snapshot_fingerprint
        ));
    });
}

#[test]
fn e2_pipeline_transport_restart_and_partial_ack_keep_exact_literal_fields() {
    retry_case(true);
}
#[test]
fn e2_pipeline_transport_restart_and_partial_ack_without_resolver_conflict() {
    retry_case(false);
}

#[test]
fn e2_pipeline_branch_copy_without_new_reply_keeps_original_totals_only() {
    with_e2(|| {
        let mut c = Corpus::new("e2-pipeline-branch-no-new-reply");
        c.root(ROOT, &line(ROOT, "original", AT, 10));
        let scanner = E2ScanFixture::default();
        let sum = |items: &[SnapshotItem]| {
            items.iter().fold([0_u64; 8], |mut sum, s| {
                for (target, n) in sum.iter_mut().zip([
                    s.request_count,
                    s.input_tokens,
                    s.output_tokens,
                    s.cache_read_tokens,
                    s.cache_creation_5m_tokens,
                    s.cache_creation_1h_tokens,
                    s.reasoning_output_tokens,
                    s.unattributed_total_tokens,
                ]) {
                    *target += n;
                }
                sum
            })
        };
        let mut original = ready(&c, &scanner, ScanIndex::default(), 100, false);
        assert_eq!(total(&original), 1);
        let original_totals = sum(&original.scan.snapshots);
        original.finish();
        let prior = c.reload(&mut original.index);
        c.write_at(
            &format!("{COPY}.jsonl"),
            &line(COPY, "original", AT, 10),
            "2026-08-02T07:03:00Z",
        );
        let branch = ready(&c, &scanner, prior, 100, false);
        literal(&branch);
        // The unchanged original is not re-emitted on the branch page (it
        // holds only the copy), so the money published is the original page
        // plus the branch page: the original's exactly once, the branch none.
        let branch_totals = sum(&branch.scan.snapshots);
        let totals: [u64; 8] = std::array::from_fn(|at| original_totals[at] + branch_totals[at]);
        let shape = branch
            .scan
            .snapshots
            .iter()
            .map(|s| {
                (
                    s.source_session_id == ROOT,
                    s.request_count,
                    s.removed_request_count,
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(
            totals,
            [1, 10, 10, 3, 5, 2, 0, 0],
            "a /branch containing only copied history cannot duplicate original money; \
             page (is_root, requests, removed) = {shape:?}"
        );
        assert!(
            branch
                .scan
                .snapshots
                .iter()
                .map(|s| s.removed_request_count.unwrap_or(0))
                .sum::<u64>()
                > 0,
            "deliberate /branch must expose copy_skipped > 0; page (is_root, requests, removed) = {shape:?}"
        );
    });
}

#[test]
fn e2_pipeline_orphan_branch_copy_counts_once_and_discloses() {
    with_e2(|| {
        let mut c = Corpus::new("e2-pipeline-branch-orphan");
        // The original was deleted before it was ever read: no indexed
        // earlier holder exists, so the all-copied branch is counted once
        // in its own session and disclosed, never dropped.
        let original = c.root(ROOT, &line(ROOT, "original", AT, 10));
        std::fs::remove_file(&original).unwrap();
        c.births.remove(&original);
        c.write_at(
            &format!("{COPY}.jsonl"),
            &line(COPY, "original", AT, 10),
            "2026-08-02T07:03:00Z",
        );
        let p = ready(
            &c,
            &E2ScanFixture::default(),
            ScanIndex::default(),
            100,
            false,
        );
        literal(&p);
        assert_eq!(p.scan.snapshots.len(), 1);
        let copy = &p.scan.snapshots[0];
        assert_eq!(copy.source_session_id, COPY);
        assert_eq!(
            (copy.request_count, copy.input_tokens, copy.output_tokens),
            (1, 10, 10),
            "an orphan copy is counted once"
        );
        assert_eq!(copy.removed_request_count, Some(0));
        assert!(
            e2::pipeline_test_observer::disclosed(&p.scan.snapshots) + p.released.disclosed > 0,
            "an orphan copy is disclosed"
        );
    });
}

/// [money] Restored same-session path twins, every line pre-birth: no own
/// turn or accepted session yet, but the earlier counted local body proves
/// the copy immediately. After the summed body is accepted it stays proven
/// regardless of the ACK carrier, discovery order or equal-birth tie break.
/// An unchanged page emits nothing; growth declares the prior removal.
fn restored_twins(reverse: bool, equal: bool) {
    restored_twins_pinned(reverse, equal, None);
}

/// `copy_key_first`: pin the equal-birth tie (the location key order of the
/// two paths) instead of leaving it to the scratch directory's hash.
fn restored_twins_pinned(reverse: bool, equal: bool, copy_key_first: Option<bool>) {
    with_e2(|| {
        let mut c = Corpus::new(&format!(
            "e2-pipeline-restored-{reverse}-{equal}-{copy_key_first:?}"
        ));
        let (a, b) = if reverse {
            ("z-original", "a-copy")
        } else {
            ("a-original", "z-copy")
        };
        let (a, b) = match copy_key_first {
            None => (a.to_string(), b.to_string()),
            Some(want) => {
                use crate::snapshots::claude_money_birth_store::location_key;
                let key = |dir: &str| {
                    location_key(&c.root.join(format!("{dir}/{ROOT}.jsonl")).to_string_lossy())
                };
                (0..256)
                    .map(|n| (format!("{a}-{n}"), format!("{b}-{n}")))
                    .find(|(a, b)| (key(b) < key(a)) == want)
                    .expect("both key orders occur among 256 suffixes")
            }
        };
        let (a, b) = (a.as_str(), b.as_str());
        c.write_at(
            &format!("{a}/{ROOT}.jsonl"),
            &line(ROOT, "r1", AT, 10),
            "2026-08-02T07:02:00Z",
        );
        let twin = c.write_at(
            &format!("{b}/{ROOT}.jsonl"),
            &line(ROOT, "r1", AT, 10),
            if equal {
                "2026-08-02T07:02:00Z"
            } else {
                "2026-08-02T07:03:00Z"
            },
        );
        let scanner = E2ScanFixture::default();
        e2::take_diag();
        let mut first = ready(&c, &scanner, ScanIndex::default(), 100, false);
        let opened = scanner.paths();
        assert_eq!(opened.len(), 2);
        assert!(
            opened[0].ends_with(format!("{}/{ROOT}.jsonl", if reverse { b } else { a })),
            "actual discovery order"
        );
        literal(&first);
        assert_eq!(
            total(&first),
            1,
            "all-prebirth restored twins count once from their earlier local owner"
        );
        // The emitted body carries the first discovered path's fold. When
        // that path is the removed copy, the counting twin's inline counter
        // leaves with its merged fold. Observe the sum of both decisions.
        assert_eq!(
            copy_diag(&["copy_prefix_unproven"]),
            [1],
            "the single counted request without an earlier owner is disclosed"
        );
        first.finish();
        let stored = stored_bodies(&first.index);
        let prior = c.reload(&mut first.index);
        let mut again = ready(&c, &scanner, prior, 100, false);
        // An unchanged repeated page reads and sends
        // nothing (latest wins); a real change re-emits the twin group.
        assert!(
            again.scan.snapshots.is_empty(),
            "an unchanged repeated page emits nothing new"
        );
        again.finish();
        assert_eq!(
            stored_bodies(&again.index),
            stored,
            "the stored body stays byte-identical"
        );
        append(&twin, &line(ROOT, "r2", "2026-08-02T07:04:00Z", 20));
        let prior = c.reload(&mut again.index);
        let changed = ready(&c, &scanner, prior, 100, false);
        literal(&changed);
        assert_eq!(
            total(&changed),
            2,
            "accepted same-session history counts once in every discovery/birth order"
        );
        assert_eq!(body(&changed, ROOT).unwrap().removed_request_count, Some(1));
    });
}
#[test]
fn e2_pipeline_restored_twins_earlier_first() {
    restored_twins(false, false);
}
#[test]
fn e2_pipeline_restored_twins_later_first() {
    restored_twins(true, false);
}
#[test]
fn e2_pipeline_restored_twins_equal_birth_forward() {
    restored_twins(false, true);
}
#[test]
fn e2_pipeline_restored_twins_equal_birth_reverse() {
    restored_twins(true, true);
}
/// [money] Equal births break the tie by location key: both orders count
/// every request exactly once, whichever path carries the session.
#[test]
fn e2_pipeline_restored_twins_equal_birth_reverse_pinned_ties() {
    restored_twins_pinned(true, true, Some(true));
    restored_twins_pinned(true, true, Some(false));
}

/// Path twins of `ROOT`: the original's and the copy's folder. The copy's
/// folder sorts first when the copy must be discovered first.
fn twin_dirs(copy_first: bool) -> (&'static str, &'static str) {
    if copy_first {
        ("z-original", "a-copy")
    } else {
        ("a-original", "z-copy")
    }
}
/// The original (born first) and its later copy, each with only `r1`,
/// written before either birth: every line of the copy is a copied request.
fn write_twin(c: &mut Corpus, dir: &str, copy: bool) -> PathBuf {
    c.write_at(
        &format!("{dir}/{ROOT}.jsonl"),
        &line(ROOT, "r1", AT, 10),
        if copy {
            "2026-08-02T07:03:00Z"
        } else {
            "2026-08-02T07:02:00Z"
        },
    )
}
/// The emitted body as the wire sends it, whole, minus its fingerprint, with
/// the corpus directory made relative: two corpora's bodies compare whole.
fn portable_body(page: &Page, base: &Path) -> serde_json::Value {
    let item = body(page, ROOT).expect("the twin session is emitted");
    let text = serde_json::to_string(item)
        .unwrap()
        .replace(&*base.to_string_lossy(), "<corpus>");
    let mut value: serde_json::Value = serde_json::from_str(&text).unwrap();
    // Both name the physical carrier file, not money.
    let object = value.as_object_mut().unwrap();
    object.remove("snapshot_fingerprint");
    object.remove("source_file_fingerprint");
    value
}
/// The copy's stored removal groups: (holder is the original, removed hashes).
fn twin_groups(index: &ScanIndex, copy: &Path, original: &Path) -> Vec<(bool, Vec<u64>)> {
    use crate::snapshots::claude_money_birth_store::location_key;
    let original = location_key(&original.to_string_lossy());
    index
        .claude_copy_removals
        .get(location_key(&copy.to_string_lossy()))
        .iter()
        .map(|(holder, hashes)| (*holder == original, hashes.to_vec()))
        .collect()
}
/// (request_count, removed_request_count, input_tokens, output_tokens)
fn twin_counts(page: &Page) -> (u64, Option<u64>, u64, u64) {
    let item = body(page, ROOT).expect("the twin session is emitted");
    (
        item.request_count,
        item.removed_request_count,
        item.input_tokens,
        item.output_tokens,
    )
}

/// The original-first order: the original alone is accepted, then its copy
/// appears and its copied request is removed under the accepted original.
/// Returns that page's whole body and the copy's stored groups.
fn original_accepted_first(copy_first: bool) -> (serde_json::Value, Vec<(bool, Vec<u64>)>) {
    let mut c = Corpus::new(&format!("e2-pipeline-original-first-{copy_first}"));
    let (original_dir, copy_dir) = twin_dirs(copy_first);
    let original = write_twin(&mut c, original_dir, false);
    let scanner = E2ScanFixture::default();
    let empty = ScanIndex::default();
    let alone = ready(&c, &scanner, empty.clone(), 100, false);
    assert_eq!(twin_counts(&alone).0, 1, "the original counts r1 once");
    let prior = settle(&c, &empty, alone, &mut e2_progress());
    let copy = write_twin(&mut c, copy_dir, true);
    let page = ready(&c, &scanner, prior.clone(), 100, false);
    literal(&page);
    assert_eq!(
        twin_counts(&page),
        (1, Some(1), 10, 10),
        "the accepted original removes the copy's r1"
    );
    let sent = portable_body(&page, &c.base);
    let settled = settle(&c, &prior, page, &mut e2_progress());
    let groups = twin_groups(&settled, &copy, &original);
    assert!(settled
        .files
        .keys()
        .all(|key| !settled.claude_copy_removals.pending(
            crate::snapshots::claude_money_birth_store::location_key(key)
        )));
    (sent, groups)
}

/// [money] Path twins, every line before the copy's birth. The copy is
/// decided while the original is not yet owned (its census is absent for
/// that decision only), so the first accepted body counts r1 at both
/// locations. The summed body's disclosure mark goes to the carrier, so
/// when the original carries it the copy has no mark of its own. The ACKed
/// save must still select the copy once; its ordinary correction read
/// removes r1 under the original, and the final body and groups equal the
/// original-first order. A repeated page reads and sends nothing.
fn unowned_original_twins(copy_first: bool, cold: bool) {
    use crate::snapshots::claude_money_birth_store::location_key;
    let (expected_body, expected_groups) = with_e2(|| original_accepted_first(copy_first));
    assert_eq!(
        expected_groups,
        vec![(
            true,
            vec![crate::snapshots::claude_request_census::claude_request_hash("r1")]
        )],
        "original-first: one group, r1 under the original"
    );
    with_e2(|| {
        let mut c = Corpus::new(&format!("e2-pipeline-unowned-original-{copy_first}-{cold}"));
        let (original_dir, copy_dir) = twin_dirs(copy_first);
        let original = write_twin(&mut c, original_dir, false);
        let copy = write_twin(&mut c, copy_dir, true);
        let original_key = original.to_string_lossy().into_owned();
        let copy_location = location_key(&copy.to_string_lossy());
        let scanner = E2ScanFixture::default();
        let empty = ScanIndex::default();
        let mut page = c.raw(&scanner, empty.clone(), 100, false, &[]);
        let opened = scanner.paths();
        assert_eq!(opened.len(), 2, "both twins are read on the first page");
        assert!(
            opened[0].ends_with(format!(
                "{}/{ROOT}.jsonl",
                if copy_first { copy_dir } else { original_dir }
            )),
            "actual discovery order"
        );
        let census = page
            .index
            .claude_request_census_for_test()
            .get(&original_key)
            .cloned()
            .expect("the page builds the original's census");
        page.index
            .claude_request_census_mut_for_test()
            .remove(&original_key);
        page.enrich(&c);
        page.index
            .claude_request_census_mut_for_test()
            .insert(original_key.clone(), census);
        let page = deliver_page(page);
        literal(&page);
        assert_eq!(
            twin_counts(&page).0,
            2,
            "premise: an unowned original leaves the copy's r1 counted too"
        );
        assert_eq!(twin_counts(&page).2, 20);
        let prior = settle(&c, &empty, page, &mut e2_progress());
        if !copy_first {
            assert_eq!(
                prior.claude_money_birth_store.money_marks(copy_location),
                0,
                "premise: the original carries the body, the copy has no mark"
            );
        }
        assert!(twin_groups(&prior, &copy, &original).is_empty());
        assert!(
            prior.claude_copy_removals.pending(copy_location),
            "the ACKed save selects the counted copy"
        );
        assert!(!prior
            .claude_copy_removals
            .pending(location_key(&original_key)));
        // A cold restart closes the persisted route, so it takes the prior itself.
        let (prior, corrected) = if cold {
            let restored = cold_restart(prior);
            let cold_scanner = E2ScanFixture::default();
            cold_scanner.on_committed_route(
                &crate::snapshots::e2_pipeline_scan_fixture::route_of(&restored).unwrap(),
            );
            let corrected = ready(&c, &cold_scanner, restored.clone(), 100, false);
            (restored, corrected)
        } else {
            let corrected = ready(&c, &scanner, prior.clone(), 100, false);
            assert!(
                scanner.paths().contains(&copy),
                "the correction reads the marked copy"
            );
            (prior, corrected)
        };
        literal(&corrected);
        assert_eq!(
            twin_counts(&corrected),
            (1, Some(1), 10, 10),
            "the correction removes the copy's r1 under the original"
        );
        assert_eq!(
            portable_body(&corrected, &c.base),
            expected_body,
            "the corrected body equals the original-first body"
        );
        let settled = settle(&c, &prior, corrected, &mut e2_progress());
        assert_eq!(twin_groups(&settled, &copy, &original), expected_groups);
        assert!(
            !settled.claude_copy_removals.pending(copy_location),
            "one correction settles the copy"
        );
        drop(prior);
        let again = if cold {
            cold_ready(&c, settled, 100, false)
        } else {
            ready(&c, &scanner, settled, 100, false)
        };
        assert!(
            again.scan.snapshots.is_empty(),
            "the settled twins are not read or sent again"
        );
    });
}
#[test]
fn e2_pipeline_unowned_original_twin_copy_is_redecided() {
    unowned_original_twins(false, false);
}
#[test]
fn e2_pipeline_unowned_original_twin_copy_is_redecided_after_cold_restart() {
    unowned_original_twins(false, true);
}
#[test]
fn e2_pipeline_unowned_original_twin_copy_discovered_first_is_redecided() {
    unowned_original_twins(true, false);
}

// Input-only usage makes the dominance fixtures' expected sums explicit.
fn uncopied_rows(rows: &[(&str, u64)]) -> String {
    rows.iter()
        .map(|(id, tokens)| {
            let mut row: serde_json::Value =
                serde_json::from_str(&line(ROOT, id, AT, *tokens)).unwrap();
            row["message"]["usage"] = json!({"input_tokens":tokens,"output_tokens":0});
            row.to_string() + "\n"
        })
        .collect()
}

fn uncopied_pair(name: &str, a_first: bool, a: &str, b: &str) -> (Corpus, [PathBuf; 2]) {
    use crate::snapshots::claude_money_birth_store::location_key;
    let mut c = Corpus::new(&format!("e2-pipeline-uncopied-{name}-{a_first}"));
    // Fixed suffixes, ordered by the actual full-path key rather than by name.
    let mut paths =
        ["a-original", "z-copy"].map(|dir| c.root.join(dir).join(format!("{ROOT}.jsonl")));
    paths.sort_by_key(|path| location_key(&path.to_string_lossy()));
    if !a_first {
        paths.swap(0, 1);
    }
    assert_eq!(
        location_key(&paths[0].to_string_lossy()) < location_key(&paths[1].to_string_lossy()),
        a_first
    );
    let birth = "2026-08-02T07:00:00Z";
    assert!(nanos(birth) < nanos(AT));
    assert!(nanos(AT) < nanos("2026-11-04T00:00:00Z"));
    for (path, text) in paths.iter().zip([a, b]) {
        let relative = path
            .strip_prefix(&c.root)
            .unwrap()
            .to_string_lossy()
            .into_owned();
        c.write_at(&relative, text, birth);
    }
    (c, paths)
}

#[test]
fn e2_pipeline_uncopied_t_equal() {
    // Expected RED on main: equal clones count twice (83 input, 7 requests).
    for a_first in [true, false] {
        for grow_a in [true, false] {
            with_e2(|| {
                let a = uncopied_rows(&[("r1", 10), ("r2", 20), ("r3", 5)]);
                let b = a.clone() + &uncopied_rows(&[("r4", 13)]);
                let (c, paths) = uncopied_pair("equal", a_first, &a, &b);
                let scanner = E2ScanFixture::default();
                e2::take_diag();
                let mut first = ready(&c, &scanner, ScanIndex::default(), 100, false);
                literal(&first);
                assert_eq!(
                    (body(&first, ROOT).unwrap().input_tokens, total(&first)),
                    (48, 4)
                );
                assert_eq!(copy_diag(&["copy_prefix_twin_page_removed"]), [3]);
                first.finish();
                let stored = stored_bodies(&first.index);
                let prior = c.reload(&mut first.index);
                let mut again = ready(&c, &E2ScanFixture::default(), prior, 100, false);
                assert!(
                    again.scan.snapshots.is_empty(),
                    "reload repeat emits nothing"
                );
                again.finish();
                assert_eq!(stored_bodies(&again.index), stored);
                append(
                    &paths[usize::from(!grow_a)],
                    &uncopied_rows(&[("growth", 17)]),
                );
                let prior = c.reload(&mut again.index);
                e2::take_diag();
                let grown = ready(&c, &E2ScanFixture::default(), prior, 100, false);
                literal(&grown);
                assert_eq!(
                    (body(&grown, ROOT).unwrap().input_tokens, total(&grown)),
                    (65, 5)
                );
                assert_eq!(
                    copy_diag(&[
                        "copy_prefix_twin_page_removed",
                        "copy_prefix_families_corrected"
                    ]),
                    [3, 1]
                );
            });
        }
    }
}

fn uncopied_numeric_case(name: &str, a: &[(&str, u64)], b: &[(&str, u64)], input: u64, drops: u64) {
    for a_first in [true, false] {
        with_e2(|| {
            let (c, _) = uncopied_pair(name, a_first, &uncopied_rows(a), &uncopied_rows(b));
            e2::take_diag();
            let page = ready(
                &c,
                &E2ScanFixture::default(),
                ScanIndex::default(),
                100,
                false,
            );
            literal(&page);
            let result = body(&page, ROOT).unwrap();
            assert_eq!(result.input_tokens, input);
            assert_eq!(result.removed_request_count.unwrap_or(0), drops);
            assert_eq!(
                copy_diag(&["copy_prefix_twin_page_removed", "twin_overcount_kept"]),
                [drops, 0]
            );
        });
    }
}

#[test]
fn e2_pipeline_uncopied_t_zero() {
    // Guard: a zero occurrence cannot keep R or remove any of B's usage.
    uncopied_numeric_case(
        "zero",
        &[("R", 0), ("S", 1)],
        &[("R", 10), ("Q", 13)],
        24,
        0,
    );
}

#[test]
fn e2_pipeline_uncopied_t_partial() {
    // Expected RED on main: partial R also counts (28 input); B must keep R.
    uncopied_numeric_case("partial", &[("R", 5)], &[("R", 10), ("Q", 13)], 23, 1);
}

#[test]
fn e2_pipeline_uncopied_t_disjoint() {
    // Guard: different request ids remain independent.
    uncopied_numeric_case("disjoint", &[("P", 5)], &[("Q", 13)], 18, 0);
}

#[test]
fn e2_pipeline_uncopied_t_markers() {
    // Expected RED on main only for the new per-id diagnostic; totals are a guard.
    for a_first in [true, false] {
        with_e2(|| {
            let marker = |org: &str| {
                json!({"type":"attachment","sessionId":ROOT,
                "attachment":{"type":"credential_org","organizationUuid":org}})
                .to_string()
                    + "\n"
            };
            let a = marker("11111111-1111-4111-8111-111111111111") + &uncopied_rows(&[("R", 10)]);
            let b = marker("22222222-2222-4222-8222-222222222222") + &uncopied_rows(&[("R", 10)]);
            let (c, _) = uncopied_pair("markers", a_first, &a, &b);
            e2::take_diag();
            let page = ready(
                &c,
                &E2ScanFixture::capturing_identity(),
                ScanIndex::default(),
                100,
                false,
            );
            literal(&page);
            assert_eq!(
                (body(&page, ROOT).unwrap().input_tokens, total(&page)),
                (20, 2)
            );
            assert_eq!(
                copy_diag(&["copy_prefix_twin_page_removed", "twin_overcount_kept"]),
                [0, 1]
            );
        });
    }
}

#[test]
fn e2_pipeline_uncopied_t_untimed() {
    // Guard: a dominated occurrence with no provider timestamp is never dropped.
    for a_first in [true, false] {
        with_e2(|| {
            let mut a: serde_json::Value =
                serde_json::from_str(&uncopied_rows(&[("R", 5)])).unwrap();
            a.as_object_mut().unwrap().remove("timestamp");
            // Give the untimed response a bucket without giving it a provider time.
            let clock = json!({"type":"user","sessionId":ROOT,"timestamp":AT,
                "message":{"role":"user","content":[]}})
            .to_string()
                + "\n";
            let (c, _) = uncopied_pair(
                "untimed",
                a_first,
                &(clock + &a.to_string() + "\n"),
                &uncopied_rows(&[("R", 10)]),
            );
            let mut page = c.raw(
                &E2ScanFixture::default(),
                ScanIndex::default(),
                100,
                false,
                &[],
            );
            assert_eq!(
                page.scan
                    .snapshots
                    .iter()
                    .map(|item| item.input_tokens)
                    .sum::<u64>(),
                15
            );
            assert_eq!(
                total(&page),
                2,
                "both occurrences count before the decision"
            );
            // The target R has no own timestamp (the fallback bucket places its
            // usage); the occurrence timestamp is private to the parser.
            e2::take_diag();
            page.enrich(&c);
            literal(&page);
            assert_eq!(copy_diag(&["copy_prefix_twin_page_removed"]), [0]);
            assert_eq!(
                (body(&page, ROOT).unwrap().input_tokens, total(&page)),
                (15, 2)
            );
            assert_eq!(
                body(&page, ROOT)
                    .unwrap()
                    .removed_request_count
                    .unwrap_or(0),
                0
            );
        });
    }
}

#[test]
fn e2_pipeline_uncopied_t_ambiguous() {
    // Guard: neither an ambiguous keeper nor an ambiguous target proves a drop.
    for a_first in [true, false] {
        for ambiguous_larger in [true, false] {
            with_e2(|| {
                let tokens = if ambiguous_larger { 10 } else { 5 };
                let mut second: serde_json::Value =
                    serde_json::from_str(&uncopied_rows(&[("R", tokens)])).unwrap();
                second["message"]["id"] = json!("msg-R-second");
                let a = uncopied_rows(&[("R", tokens)]) + &second.to_string() + "\n";
                let b = uncopied_rows(&[("R", if ambiguous_larger { 5 } else { 10 })]);
                let (c, _) = uncopied_pair("ambiguous", a_first, &a, &b);
                let scanner = E2ScanFixture::default();
                let mut page = c.raw(&scanner, ScanIndex::default(), 100, false, &[]);
                assert!(
                    page.scan.snapshots.iter().any(|item| item
                        .claude_money
                        .as_deref()
                        .is_some_and(|fold| fold.is_ambiguous("R"))),
                    "fixture parsed an ambiguous request"
                );
                e2::take_diag();
                page.enrich(&c);
                assert_eq!(
                    (body(&page, ROOT).unwrap().input_tokens, total(&page)),
                    (if ambiguous_larger { 25 } else { 20 }, 3)
                );
                assert_eq!(
                    body(&page, ROOT)
                        .unwrap()
                        .removed_request_count
                        .unwrap_or(0),
                    0
                );
                assert_eq!(copy_diag(&["copy_prefix_twin_page_removed"]), [0]);
            });
        }
    }
}

#[test]
fn e2_pipeline_uncopied_t_incomparable() {
    // Expected RED on main only for the new per-id diagnostic; totals are a guard.
    for a_first in [true, false] {
        with_e2(|| {
            let a = uncopied_rows(&[("R", 10)]);
            let mut b: serde_json::Value =
                serde_json::from_str(&uncopied_rows(&[("R", 5)])).unwrap();
            b["message"]["usage"]["output_tokens"] = json!(10);
            let (c, _) = uncopied_pair("incomparable", a_first, &a, &(b.to_string() + "\n"));
            e2::take_diag();
            let page = ready(
                &c,
                &E2ScanFixture::default(),
                ScanIndex::default(),
                100,
                false,
            );
            let result = body(&page, ROOT).unwrap();
            assert_eq!(
                (result.input_tokens, result.output_tokens, total(&page)),
                (15, 10, 2)
            );
            assert_eq!(
                copy_diag(&["copy_prefix_twin_page_removed", "twin_overcount_kept"]),
                [0, 1]
            );
        });
    }
}

#[test]
fn e2_pipeline_uncopied_t_chain() {
    // Expected RED on main: three comparable occurrences count three times.
    for a_first in [true, false] {
        for strongest_a in [true, false] {
            with_e2(|| {
                let (mut c, _) = uncopied_pair(
                    "chain",
                    a_first,
                    &uncopied_rows(&[("R", if strongest_a { 20 } else { 5 })]),
                    &uncopied_rows(&[("R", if strongest_a { 5 } else { 20 })]),
                );
                c.write_at(
                    &format!("middle/{ROOT}.jsonl"),
                    &uncopied_rows(&[("R", 10)]),
                    "2026-08-02T07:00:00Z",
                );
                e2::take_diag();
                let page = ready(
                    &c,
                    &E2ScanFixture::default(),
                    ScanIndex::default(),
                    100,
                    false,
                );
                assert_eq!(
                    (body(&page, ROOT).unwrap().input_tokens, total(&page)),
                    (20, 1)
                );
                assert_eq!(copy_diag(&["copy_prefix_twin_page_removed"]), [2]);
            });
        }
    }
}

#[test]
fn e2_pipeline_uncopied_guard_absent_complete() {
    // Guard: accepted residual B1; id inclusion does not prove usage dominance.
    for a_first in [true, false] {
        with_e2(|| {
            let (c, paths) = uncopied_pair(
                "absent-complete",
                a_first,
                &uncopied_rows(&[("R", 10)]),
                &uncopied_rows(&[("R", 5), ("Q", 13)]),
            );
            let scanner = E2ScanFixture::default();
            let mut page = c.raw(&scanner, ScanIndex::default(), 100, false, &[]);
            let fingerprint = page.index.files[&paths[1].to_string_lossy().into_owned()]
                .source_file_fingerprint
                .clone();
            page.scan.snapshots.retain(|item| {
                item.source_file_fingerprint.as_deref() == Some(fingerprint.as_str())
            });
            assert_eq!(
                page.scan.snapshots.len(),
                1,
                "only partial B is on the page"
            );
            e2::take_diag();
            page.enrich(&c);
            let result =
                body(&page, ROOT).expect("absent complete A is considered redundant by ids");
            assert_eq!((result.input_tokens, result.request_count), (18, 2));
            assert_eq!(
                copy_diag(&["copy_prefix_twin_page_removed", "twin_redundant"]),
                [0, 1]
            );
            assert!(paths[0].is_file(), "complete A remains live but absent");
        });
    }
}

#[test]
fn e2_pipeline_uncopied_guard_carried_accounts() {
    // Expected RED on main (22/4 vs 12/3); guards accepted residual account drift after dedup.
    // Equal native None markers can carry different accounts; the copy-order keeper wins.
    for a_first in [true, false] {
        with_e2(|| {
            let (c, _) = uncopied_pair(
                "carried",
                a_first,
                &(line(ROOT, "P", AT, 1) + &line(ROOT, "R", AT, 10)),
                &(line(ROOT, "Q", AT, 1) + &line(ROOT, "R", AT, 10)),
            );
            c.evidence(
                &[
                    api_login(ROOT, "P", 1, '1', Some('8')),
                    api_login(ROOT, "Q", 1, '2', Some('9')),
                ],
                &[trace_for(ROOT, "P", ""), trace_for(ROOT, "Q", "")],
            );
            let scanner = E2ScanFixture::capturing_identity();
            let mut page = c.raw(&scanner, ScanIndex::default(), 100, false, &[]);
            let mut accepted =
                crate::snapshots::claude_request_identity::AcceptedBuckets::for_test();
            e2::take_diag();
            page.enrich_with(&c, Some(&mut accepted));
            let result = body(&page, ROOT).unwrap();
            assert_eq!((result.input_tokens, result.request_count), (12, 3));
            assert_eq!(
                org_shares(result),
                BTreeMap::from([
                    ("8".repeat(64), if a_first { 2 } else { 1 }),
                    ("9".repeat(64), if a_first { 1 } else { 2 })
                ])
            );
            assert_eq!(
                copy_diag(&["copy_prefix_twin_page_removed", "twin_overcount_kept"]),
                [1, 0]
            );
        });
    }
}

/// [money] A summed body's COPY mark never lets its counting carrier drop r1.
#[test]
fn equal_birth_carrier_never_drops_its_counted_request() {
    use crate::snapshots::claude_money_birth_store::location_key;
    use crate::snapshots::claude_request_census::claude_request_hash;
    use crate::snapshots::sampled_scan::transition_fixture::with_scan_clock;

    with_e2(|| {
        let copied_at = "2026-11-03T07:00:10Z";
        let born_at = "2026-11-03T07:02:00Z";
        let own_at = "2026-11-03T07:04:00Z";
        assert!(nanos(copied_at) + 2_000_000_000 < nanos(born_at));
        assert!(nanos(born_at) < nanos(own_at));
        assert!(nanos(own_at) < nanos("2026-11-04T00:00:00Z"));
        let r1 = line(ROOT, "r1", copied_at, 10);
        let r1_hash = claude_request_hash("r1");
        for carrier_first in [true, false] {
            let mut c = Corpus::new(&format!("e2-pipeline-counting-carrier-{carrier_first}"));
            // Sort actual full-path hashes: a unique scratch root must not
            // choose which equal-birth tie order this arm exercises.
            let mut paths = ["home-a", "home-b"]
                .map(|folder| c.root.join(folder).join(format!("{ROOT}.jsonl")));
            paths.sort_by_key(|path| location_key(&path.to_string_lossy()));
            let [carrier, other] = if carrier_first {
                paths
            } else {
                let [a, b] = paths;
                [b, a]
            };
            let carrier_key = location_key(&carrier.to_string_lossy());
            let other_key = location_key(&other.to_string_lossy());
            assert_ne!(carrier_key, other_key);
            assert_eq!(carrier_key < other_key, carrier_first);
            let carrier_relative = carrier
                .strip_prefix(&c.root)
                .unwrap()
                .to_string_lossy()
                .into_owned();
            let other_relative = other
                .strip_prefix(&c.root)
                .unwrap()
                .to_string_lossy()
                .into_owned();
            c.write_at(&carrier_relative, &r1, born_at);
            let scanner = E2ScanFixture::default();
            let committed = ScanIndex::default();
            let seed = ready(&c, &scanner, committed.clone(), 100, false);
            assert_eq!(
                scanner.paths(),
                vec![carrier.clone()],
                "C is discovered first"
            );
            eprintln!(
                "counted carrier stage=seed carrier_first={carrier_first} bodies={}",
                seed.scan.snapshots.len()
            );
            literal(&seed);
            assert_eq!(total(&seed), 1);
            // Complete upload settlement records acceptance and exact ACK
            // stamps. Reload clears the runtime context; restore it to inspect
            // the durable receipt under the destination that earned it.
            let mut prior = settle(&c, &committed, seed, &mut e2_progress());
            prior.activate_upload_context("e2-synthetic-destination".into());
            assert!(upload_context_receipt_earned_for_test(&prior, &carrier));

            c.write_at(&other_relative, &r1, born_at);
            if !carrier_first {
                // The ordinary proof creates the earlier-holder order. Seed
                // the saved O -> C decision for the reverse order; stored
                // removals retain their holder independently of today's tie.
                prior.claude_copy_removals.store(
                    other_key,
                    BTreeMap::from([(carrier_key, BTreeSet::from([r1_hash]))]),
                );
            }
            let twins = ready(&c, &scanner, prior.clone(), 100, false);
            eprintln!(
                "counted carrier stage=twins carrier_first={carrier_first} bodies={}",
                twins.scan.snapshots.len()
            );
            literal(&twins);
            assert_eq!(total(&twins), 1);
            assert_eq!(body(&twins, ROOT).unwrap().removed_request_count, Some(1));
            let accepted_body = snapshot_upload_body_witness(body(&twins, ROOT).unwrap());
            let prior = settle(&c, &prior, twins, &mut e2_progress());

            // Refresh the ACK carrier with blank JSONL so unchanged usage
            // acquires the summed body's COPY mark before the own turn grows.
            append(&carrier, "\n");
            let refreshed_at = crate::scan_clock::utc_seconds();
            let refreshed = with_scan_clock(refreshed_at, || {
                ready(&c, &scanner, prior.clone(), 100, false)
            });
            eprintln!(
                "counted carrier stage=refreshed carrier_first={carrier_first} bodies={}",
                refreshed.scan.snapshots.len()
            );
            literal(&refreshed);
            assert_eq!(
                snapshot_upload_body_witness(body(&refreshed, ROOT).unwrap()),
                accepted_body,
                "carrier refresh changes no accepted body"
            );
            let mut prior = settle(&c, &prior, refreshed, &mut e2_progress());
            prior.activate_upload_context("e2-synthetic-destination".into());
            let store = &prior.claude_money_birth_store;
            for path in [&carrier, &other] {
                let key = path.to_string_lossy();
                assert!(prior.files.contains_key(key.as_ref()));
                assert_eq!(store.observed_birth(ROOT, &key), Some(nanos(born_at)));
                assert_eq!(store.effective_cutoff(ROOT, &key), Some(nanos(born_at)));
            }
            assert_ne!(store.money_marks(carrier_key) & e2::money_mark::COPY, 0);
            assert!(upload_context_receipt_earned_for_test(&prior, &carrier));
            assert!(prior.claude_copy_removals.get(carrier_key).is_empty());
            assert!(prior
                .claude_copy_removals
                .get(other_key)
                .iter()
                .any(|(holder, hashes)| *holder == carrier_key
                    && hashes.binary_search(&r1_hash).is_ok()));

            append(&carrier, &line(ROOT, "r2", own_at, 20));
            let grown = with_scan_clock(refreshed_at + 6 * 60 * 60, || {
                ready(&c, &scanner, prior.clone(), 100, false)
            });
            eprintln!(
                "counted carrier stage=grown carrier_first={carrier_first} bodies={} growth_pacing={:?}",
                grown.scan.snapshots.len(),
                crate::snapshots::e2_pipeline_scan_fixture::growth_diagnostics_for_test(&grown.index, &carrier),
            );
            literal(&grown);
            let root = body(&grown, ROOT).expect("growth emits ROOT");
            assert_eq!(
                (root.request_count, root.removed_request_count),
                (2, Some(1)),
                "equal-birth carrier growth must retain r1: carrier_first={carrier_first}"
            );
            assert_eq!(total(&grown), 2);
            let settled = settle(&c, &prior, grown, &mut e2_progress());
            assert!(
                [carrier_key, other_key].iter().any(|&location| !settled
                    .claude_copy_removals
                    .get(location)
                    .iter()
                    .any(|(_, hashes)| hashes.binary_search(&r1_hash).is_ok())),
                "r1 must not be removed at every location: carrier_first={carrier_first}"
            );
        }
    });
}

#[test]
fn e2_pipeline_deletion_reload_then_later_move_keeps_birth() {
    with_e2(|| {
        let mut c = Corpus::new("e2-pipeline-delayed-move");
        let old = c.root(ROOT, &line(ROOT, "r1", AT, 10));
        let scanner = E2ScanFixture::default();
        let mut first = ready(&c, &scanner, ScanIndex::default(), 100, false);
        first.finish();
        let prior = c.reload(&mut first.index);
        std::fs::remove_file(old).unwrap();
        let mut absent = ready(&c, &scanner, prior, 100, false);
        absent.finish();
        let prior = c.reload(&mut absent.index);
        c.write_at(
            &format!("new-location/{ROOT}.jsonl"),
            &line(ROOT, "r1", AT, 10),
            "2026-08-02T07:03:00Z",
        );
        let moved = ready(&c, &E2ScanFixture::default(), prior, 100, false);
        literal(&moved);
        assert_eq!(
            total(&moved),
            1,
            "lineage survives a real deletion scan and durable reload"
        );
        assert_eq!(moved.scan.snapshots[0].removed_request_count, Some(0));
    });
}

/// [regress] First-group byte admission must publish and acknowledge the complete twin history.
#[test]
fn e2_pipeline_first_twin_group_above_byte_budget_preserves_complete_history() {
    with_e2(|| {
        let mut c = Corpus::new("e2-pipeline-twin-byte-hold");
        c.write_at(
            &format!("a/{ROOT}.jsonl"),
            &line(ROOT, "r1", AT, 10),
            "2026-08-02T07:00:00Z",
        );
        // Own turns from the copy proof cutoff on: the page proof dedupes r1.
        c.write_at(
            &format!("z/{ROOT}.jsonl"),
            &(line(ROOT, "r1", AT, 10) + &line(ROOT, "r2", "2026-11-04T07:03:10Z", 20)),
            "2026-11-04T07:03:00Z",
        );
        let scanner = E2ScanFixture::default();
        let mut progress = e2_progress();
        // Production Completed settlement of one ordinary page, then reload.
        let settle = |c: &Corpus,
                      committed: &ScanIndex,
                      mut page: Page,
                      progress: &mut SnapshotUploadProgress| {
            page.finish();
            let sent = page.scan.snapshots.clone();
            assert_eq!(
                upload(&sent, progress, ack).0.unwrap(),
                ResumableUploadResult::Completed
            );
            for item in &sent {
                assert_eq!(
                    page.delivered
                        .as_ref()
                        .expect("ready records exact ACKs")
                        .get(&item.snapshot_fingerprint),
                    Some(&snapshot_upload_body_witness(item)),
                    "exact body ACK precedes settlement"
                );
            }
            let holds = LocalHoldSettlement::classify(
                SnapshotSource::ClaudeCode,
                &mut page.index,
                &mut page.scan,
                &page.disposition,
            );
            let mut settled = settle_completed_upload(page.index, committed, progress, &holds);
            settle_index_after_upload(&mut settled.index, committed, progress);
            accept_upload_context_acks_for_test(
                &mut settled.index,
                &sent,
                &progress.fresh_context_body_acks,
            );
            c.reload(&mut settled.index)
        };
        let old = ScanIndex::default();
        let first = ready(&c, &scanner, old.clone(), 100, false);
        literal(&first);
        assert_eq!(total(&first), 2);
        let prior = settle(&c, &old, first, &mut progress);
        assert_eq!(progress.accepted_fingerprints.len(), 1);
        // A fresh index's first page records the identity contract, which
        // re-arms every family file for one re-read. Consume that one-time
        // re-read on an ordinary page, so the byte-limited page below has no
        // reason to read the twins except the owed adoption.
        let warm = ready(&c, &scanner, prior.clone(), 100, false);
        let mut prior = settle(&c, &prior, warm, &mut progress);
        let before = prior.current_snapshot_fingerprints();
        assert_eq!(
            before.len(),
            1,
            "admission starts from one complete accepted family body"
        );
        prior.activate_effective_upload_body_witness_revision(3);
        for key in prior.files.keys().cloned().collect::<Vec<_>>() {
            assert!(
                prior.re_owe_effective_upload_body_witness_revision(&key, 2),
                "existing production re-owe keeps this family due"
            );
        }
        let committed = prior.clone();
        let admitted =
            crate::snapshots::e2_pipeline_scan_fixture::with_history_byte_limit(1, || {
                ready(&c, &scanner, prior, 1, false)
            });
        literal(&admitted);
        assert_eq!(
            total(&admitted),
            2,
            "the first group emits both owned requests"
        );
        assert_eq!(
            admitted
                .scan
                .snapshots
                .iter()
                .fold((0, 0, 0, 0, 0), |sum, item| (
                    sum.0 + item.input_tokens,
                    sum.1 + item.output_tokens,
                    sum.2 + item.cache_read_tokens,
                    sum.3 + item.cache_creation_5m_tokens,
                    sum.4 + item.cache_creation_1h_tokens,
                )),
            (30, 30, 6, 10, 4)
        );
        assert_eq!(
            scanner.paths().len(),
            2,
            "both twins are read despite the page byte target"
        );
        let restored = settle(&c, &committed, admitted, &mut progress);
        assert_eq!(
            restored.current_snapshot_fingerprints(),
            before,
            "complete accepted history survives first-group admission and reload"
        );
        assert_eq!(progress.accepted_fingerprints.len(), 1);
        assert!(restored
            .files
            .values()
            .all(|entry| entry.effective_upload_body_witness_revision == 3));
    });
}

// ---- gate-ON copy proofs, delays, side-call holds, conflict carrier ----

const LATE: &str = "3338a80a-f36e-4cbc-a5bb-50fc66430ba5";

/// Production Completed settlement of one page (holds included), then reload.
fn settle(
    c: &Corpus,
    committed: &ScanIndex,
    page: Page,
    progress: &mut SnapshotUploadProgress,
) -> ScanIndex {
    settle_in(c, committed, page, progress, "scan-index.json")
}
fn settle_in(
    c: &Corpus,
    committed: &ScanIndex,
    mut page: Page,
    progress: &mut SnapshotUploadProgress,
    index_name: &str,
) -> ScanIndex {
    page.finish();
    let sent = page.scan.snapshots.clone();
    upload(&sent, progress, ack).0.unwrap();
    let holds = LocalHoldSettlement::classify(
        SnapshotSource::ClaudeCode,
        &mut page.index,
        &mut page.scan,
        &page.disposition,
    );
    let mut settled = settle_completed_upload(page.index, committed, progress, &holds);
    settle_index_after_upload(&mut settled.index, committed, progress);
    accept_upload_context_acks_for_test(
        &mut settled.index,
        &sent,
        &progress.fresh_context_body_acks,
    );
    c.reload_in(&mut settled.index, index_name)
}

fn body<'a>(page: &'a Page, session: &str) -> Option<&'a SnapshotItem> {
    page.scan
        .snapshots
        .iter()
        .find(|s| s.source_session_id == session)
}
/// The session's items on the page are withheld: none is a literal body,
/// and the page quarantines them (delayed, never settled, never counted).
fn assert_withheld(page: &Page, session: &str, why: &str) {
    let items = page
        .scan
        .snapshots
        .iter()
        .filter(|s| s.source_session_id == session)
        .collect::<Vec<_>>();
    assert!(!items.is_empty(), "{why}: the held items stay on the page");
    assert!(
        items
            .iter()
            .all(|s| !crate::snapshots::claude_request_money::is_request_owned_literal(s)),
        "{why}: no body publishes"
    );
    let held = page
        .disposition
        .quarantined_fingerprints(&page.scan.snapshots);
    assert!(
        items.iter().all(|s| held.contains(&s.snapshot_fingerprint)),
        "{why}: the session is held"
    );
}
/// An earlier twin rewritten IN PLACE
/// (same inode, size kept) no longer holds H. Its stale identity cannot
/// remove H from the later twin: H counts once, from the twin.
fn rewritten_original(reverse: bool) {
    with_e2(|| {
        let mut c = Corpus::new(&format!("e2-pipeline-rewritten-original-{reverse}"));
        let (old_dir, new_dir) = if reverse {
            ("z-original", "a-copy")
        } else {
            ("a-original", "z-copy")
        };
        let original = c.write_at(
            &format!("{old_dir}/{ROOT}.jsonl"),
            &line(ROOT, "h1", AT, 10),
            "2026-08-02T07:00:00Z",
        );
        // Own turns from the copy proof cutoff on: the page proof removes h1
        // only while the original still holds it.
        c.write_at(
            &format!("{new_dir}/{ROOT}.jsonl"),
            &(line(ROOT, "h1", AT, 10) + &line(ROOT, "r2", "2026-11-04T07:03:10Z", 20)),
            "2026-11-04T07:03:00Z",
        );
        let scanner = E2ScanFixture::default();
        let mut progress = e2_progress();
        let old = ScanIndex::default();
        let first = ready(&c, &scanner, old.clone(), 100, false);
        assert_eq!(total(&first), 2, "h1 once, r2 once");
        let mut prior = settle(&c, &old, first, &mut progress);
        // Exercise Local proof after loading older state without receiver rows.
        // Exact accepted hashes instead survive a semantic no-op rewrite.
        prior.upload_context_proof.request_contributions.clear();
        let prior = c.reload(&mut prior);
        let inode = |path: &Path| {
            use std::os::unix::fs::MetadataExt;
            std::fs::metadata(path).unwrap().ino()
        };
        let before = (
            inode(&original),
            std::fs::metadata(&original).unwrap().len(),
        );
        // Same length id, same inode: an in-place rewrite replacing h1 by u1.
        std::fs::OpenOptions::new()
            .write(true)
            .open(&original)
            .unwrap()
            .write_all(line(ROOT, "u1", AT, 10).as_bytes())
            .unwrap();
        std::fs::File::options()
            .write(true)
            .open(&original)
            .unwrap()
            .set_modified(std::time::SystemTime::now() + std::time::Duration::from_secs(5))
            .unwrap();
        assert_eq!(
            (
                inode(&original),
                std::fs::metadata(&original).unwrap().len()
            ),
            before,
            "fixture keeps the inode and the size"
        );
        let page = ready(&c, &E2ScanFixture::default(), prior, 100, false);
        literal(&page);
        assert_eq!(
            total(&page),
            3,
            "u1 from the original, h1 and r2 from the twin: nothing dropped"
        );
        assert_eq!(page.scan.snapshots[0].removed_request_count, Some(0));
    });
}
#[test]
fn e2_pipeline_inplace_rewritten_original_cannot_remove_its_twin_copy() {
    rewritten_original(false);
}
#[test]
fn e2_pipeline_inplace_rewritten_original_cannot_remove_its_twin_copy_reverse() {
    rewritten_original(true);
}

/// Restored same-session histories H1
/// and H1+H2, every line pre-birth: the union counts, H1 once, H2 once, on
/// the first page in either discovery order and through settlement. H2, the
/// later history's first response its twin lacks, is after the copy proof
/// cutoff, so the same-session page proof removes H1 from it.
fn overlapping_restored(reverse: bool) {
    with_e2(|| {
        let mut c = Corpus::new(&format!("e2-pipeline-overlap-restored-{reverse}"));
        let (a, b) = if reverse {
            ("z-original", "a-copy")
        } else {
            ("a-original", "z-copy")
        };
        c.write_at(
            &format!("{a}/{ROOT}.jsonl"),
            &line(ROOT, "h1", AT, 10),
            "2026-08-02T07:02:00Z",
        );
        c.write_at(
            &format!("{b}/{ROOT}.jsonl"),
            &(line(ROOT, "h1", AT, 10) + &line(ROOT, "h2", "2026-11-04T07:00:20Z", 20)),
            "2026-11-04T07:03:00Z",
        );
        let scanner = E2ScanFixture::default();
        let mut progress = e2_progress();
        let old = ScanIndex::default();
        let first = ready(&c, &scanner, old.clone(), 100, false);
        let opened = scanner.paths();
        assert_eq!(opened.len(), 2);
        assert!(
            opened[0].ends_with(format!("{}/{ROOT}.jsonl", if reverse { b } else { a })),
            "actual discovery order"
        );
        literal(&first);
        assert_eq!(total(&first), 2, "the union of both histories, once");
        assert_eq!(first.scan.snapshots[0].input_tokens, 30);
        assert_eq!(first.scan.snapshots[0].removed_request_count, Some(1));
        let prior = settle(&c, &old, first, &mut progress);
        // Settled and unchanged: a restart reads and re-sends nothing (the old
        // terminal family re-arm re-read both histories).
        let (again, consumed) =
            crate::snapshots::sampled_scan::transition_fixture::observe_consumed(|| {
                ready(&c, &E2ScanFixture::default(), prior, 100, false)
            });
        assert_eq!(consumed, 0, "settled: the restart reads no transcript byte");
        assert!(
            again.scan.snapshots.is_empty(),
            "settled: nothing is re-sent"
        );
    });
}
#[test]
fn e2_pipeline_overlapping_restored_histories_count_their_union_once() {
    overlapping_restored(false);
}
#[test]
fn e2_pipeline_overlapping_restored_histories_count_their_union_once_reverse() {
    overlapping_restored(true);
}

/// An all-copied /branch is skipped on the request ids its
/// earlier other-session holder has, whatever version wrote the lines.
fn branch_by(version: &str) {
    with_e2(|| {
        let mut c = Corpus::new(&format!("e2-pipeline-branch-by-{version}"));
        c.root(ROOT, &line_by(ROOT, "original", AT, 10, version));
        let scanner = E2ScanFixture::default();
        let mut original = ready(&c, &scanner, ScanIndex::default(), 100, false);
        assert_eq!(total(&original), 1);
        original.finish();
        let prior = c.reload(&mut original.index);
        c.write_at(
            &format!("{COPY}.jsonl"),
            &line_by(COPY, "original", AT, 10, version),
            "2026-08-02T07:03:00Z",
        );
        let branch = ready(&c, &scanner, prior, 100, false);
        literal(&branch);
        let copy = body(&branch, COPY).expect("the branch publishes its (empty) body");
        assert_eq!(
            (copy.request_count, copy.removed_request_count),
            (0, Some(1)),
            "{version}: the copy never counts the original's request again"
        );
        assert!(body(&branch, ROOT).is_none(), "the original is unchanged");
    });
}
#[test]
fn e2_pipeline_branch_written_outside_the_writer_allowlist_is_skipped_by_request_ids() {
    branch_by("2.0.99");
}
#[test]
fn e2_pipeline_branch_written_by_the_current_claude_code_is_skipped() {
    // `claude --version` observed on 2026-10-26: 2.1.310 (Claude Code).
    branch_by("2.1.310");
}

/// A /branch read before its original on a fresh index
/// counts immediately; after the original commits, the marked correction
/// removes it. Both discovery orders.
fn branch_before_original(copy_first: bool) {
    with_e2(|| {
        let original = if copy_first { LATE } else { ROOT };
        let mut c = Corpus::new(&format!("e2-pipeline-branch-fresh-{copy_first}"));
        c.root(original, &line(original, "original", AT, 10));
        c.write_at(
            &format!("{COPY}.jsonl"),
            &line(COPY, "original", AT, 10),
            "2026-08-02T07:03:00Z",
        );
        let scanner = E2ScanFixture::default();
        let mut progress = e2_progress();
        let old = ScanIndex::default();
        let mut first = c.raw(&scanner, old.clone(), 1, false, &[]);
        first.enrich(&c);
        let opened = scanner.paths();
        assert_eq!(opened.len(), 1, "one file per page");
        let read_first = if copy_first { COPY } else { original };
        assert!(opened[0].ends_with(format!("{read_first}.jsonl")));
        literal(&first);
        assert_eq!(total(&first), 1);
        if copy_first {
            assert_eq!(body(&first, COPY).unwrap().removed_request_count, Some(0));
        }
        let mut prior = settle(&c, &old, first, &mut progress);
        let mut copy_body = None;
        let mut original_requests = if copy_first { 0 } else { 1 };
        for _ in 0..3 {
            let page = ready(&c, &E2ScanFixture::default(), prior.clone(), 100, false);
            if let Some(found) = body(&page, original) {
                if crate::snapshots::claude_request_money::is_request_owned_literal(found) {
                    original_requests = found.request_count;
                }
            }
            if let Some(found) = body(&page, COPY) {
                assert!(
                    crate::snapshots::claude_request_money::is_request_owned_literal(found),
                    "decided once the original is indexed"
                );
                copy_body = Some((found.request_count, found.removed_request_count));
            }
            prior = settle(&c, &prior, page, &mut progress);
            if copy_body.is_some() {
                break;
            }
        }
        assert_eq!(original_requests, 1, "the original counts once");
        assert_eq!(
            copy_body,
            Some((0, Some(1))),
            "the copy is skipped, never counted twice"
        );
    });
}
#[test]
fn e2_pipeline_branch_read_before_its_original_waits_instead_of_counting() {
    branch_before_original(true);
}
#[test]
fn e2_pipeline_branch_read_after_its_original_on_a_fresh_index_is_skipped() {
    branch_before_original(false);
}

/// An indexed original rewritten in place to drop H, then a new all-pre-birth
/// branch holding H, read before the original's next page: the original's
/// accepted body still owns H until the replacement commits. The marked
/// branch then restores H, which counts once from the branch.
#[test]
fn e2_pipeline_branch_waits_for_an_original_modified_since_its_read() {
    with_e2(|| {
        let mut c = Corpus::new("e2-pipeline-branch-stale-holder");
        let original = c.root(LATE, &line(LATE, "h", AT, 10));
        let mut progress = e2_progress();
        let old = ScanIndex::default();
        let first = ready(&c, &E2ScanFixture::default(), old.clone(), 100, false);
        assert_eq!(total(&first), 1);
        let mut prior = settle(&c, &old, first, &mut progress);
        // Keep the Local-only stale-holder control separate from receiver proof.
        prior.upload_context_proof.request_contributions.clear();
        prior = c.reload(&mut prior);
        // Same length: h becomes u in place; the clock moves on.
        std::fs::write(&original, line(LATE, "u", AT, 10)).unwrap();
        std::fs::File::options()
            .write(true)
            .open(&original)
            .unwrap()
            .set_modified(std::time::SystemTime::now() + std::time::Duration::from_secs(5))
            .unwrap();
        c.write_at(
            &format!("{COPY}.jsonl"),
            &line(COPY, "h", AT, 10),
            "2026-08-02T07:03:00Z",
        );
        let scanner = E2ScanFixture::default();
        let mut page = c.raw(&scanner, prior.clone(), 1, false, &[]);
        page.enrich(&c);
        let opened = scanner.paths();
        assert_eq!(opened.len(), 1, "one file per page");
        assert!(
            opened[0].ends_with(format!("{COPY}.jsonl")),
            "fixture reads the branch before the modified original"
        );
        literal(&page);
        assert_eq!(
            body(&page, COPY).map(|copy| (copy.request_count, copy.removed_request_count)),
            Some((0, Some(1))),
            "the accepted original still owns h until its replacement commits"
        );
        prior = settle(&c, &prior, page, &mut progress);
        let mut original_body = None;
        let mut copy_body = None;
        for _ in 0..3 {
            let page = ready(&c, &E2ScanFixture::default(), prior.clone(), 100, false);
            for (session, slot) in [(LATE, &mut original_body), (COPY, &mut copy_body)] {
                if let Some(found) = body(&page, session) {
                    if crate::snapshots::claude_request_money::is_request_owned_literal(found) {
                        *slot = Some((found.request_count, found.removed_request_count));
                    }
                }
            }
            prior = settle(&c, &prior, page, &mut progress);
            if copy_body.is_some() {
                break;
            }
        }
        assert_eq!(original_body.map(|(count, _)| count), Some(1), "u only");
        assert_eq!(
            copy_body,
            Some((1, Some(0))),
            "h counts once, from the branch: nothing dropped"
        );
    });
}

/// Owner rule: holding a session withholds its upload only; its scan
/// state stays evidence. All-copied main files of four sessions share
/// request ids (the Linux probe shape: every root a cross-session copy
/// candidate), read one per page. Each file counts unproven requests or
/// removes them against an earlier local owner, so every session publishes
/// within two traversal passes, each request counts exactly once, and
/// nothing is re-read after.
#[test]
fn e2_pipeline_held_copies_never_wait_on_each_other() {
    with_e2(|| {
        const A: &str = "3338a80a-f36e-4cbc-a5bb-50fc66430ba5";
        const B: &str = "4338a80a-f36e-4cbc-a5bb-50fc66430ba5";
        const C: &str = "5338a80a-f36e-4cbc-a5bb-50fc66430ba5";
        const D: &str = "6338a80a-f36e-4cbc-a5bb-50fc66430ba5";
        let mut c = Corpus::new("e2-pipeline-held-cycle");
        // Every line predates its file's birth; the (birth, location) order
        // decides who holds a shared id first: x in A, y in C.
        for (session, requests, birth) in [
            (A, &["x", "a"][..], "2026-08-02T07:03:00Z"),
            (B, &["x", "b"][..], "2026-08-02T07:04:00Z"),
            (C, &["x", "y", "c"][..], "2026-08-02T07:05:00Z"),
            (D, &["y", "d"][..], "2026-08-02T07:06:00Z"),
        ] {
            let contents = requests
                .iter()
                .map(|request| line(session, request, AT, 10))
                .collect::<String>();
            c.write_at(&format!("{session}.jsonl"), &contents, birth);
        }
        let mut progress = e2_progress();
        let mut prior = ScanIndex::default();
        let mut published = BTreeMap::<&str, (u64, Option<u64>)>::new();
        let mut reads = BTreeMap::<PathBuf, usize>::new();
        let mut held = 0;
        let mut pages = 0;
        while published.len() < 4 {
            assert!(
                pages < 12,
                "every session publishes: {published:?} after {pages} pages \
                 ({held} holds, reads {reads:?})"
            );
            let scanner = E2ScanFixture::default();
            let mut page = c.raw(&scanner, prior.clone(), 1, false, &[]);
            page.enrich(&c);
            pages += 1;
            for path in scanner.paths() {
                *reads.entry(path).or_default() += 1;
            }
            let quarantined = page
                .disposition
                .quarantined_fingerprints(&page.scan.snapshots);
            for session in [A, B, C, D] {
                let Some(found) = body(&page, session) else {
                    continue;
                };
                if quarantined.contains(&found.snapshot_fingerprint) {
                    held += 1;
                    continue;
                }
                assert!(
                    crate::snapshots::claude_request_money::is_request_owned_literal(found),
                    "{session}: a decided session publishes its literal body"
                );
                assert!(
                    published
                        .insert(session, (found.request_count, found.removed_request_count))
                        .is_none(),
                    "{session}: published once"
                );
            }
            prior = settle(&c, &prior, page, &mut progress);
        }
        assert_eq!(held, 0, "local ownership never waits: {published:?}");
        assert!(
            reads.values().all(|&count| count <= 2),
            "settled within two traversal passes: no file read more than twice, {reads:?}"
        );
        assert_eq!(
            published,
            BTreeMap::from([
                (A, (2, Some(0))),
                (B, (1, Some(1))),
                (C, (2, Some(1))),
                (D, (1, Some(1))),
            ]),
            "x counts in A and y in C, once; every other id in its own file"
        );
        // A clean follow-up may read a file once more; it never changes a
        // published body, and the sync after it reads nothing.
        for follow_up in 0.. {
            assert!(follow_up < 2, "a settled corpus is not re-read every sync");
            let mut page = c.raw(&E2ScanFixture::default(), prior.clone(), 100, false, &[]);
            page.enrich(&c);
            if page.scan.scanned_file_count == 0 {
                break;
            }
            for session in [A, B, C, D] {
                if let Some(found) = body(&page, session) {
                    assert_eq!(
                        Some(&(found.request_count, found.removed_request_count)),
                        published.get(session),
                        "{session}: a follow-up read decides the same"
                    );
                }
            }
            prior = settle(&c, &prior, page, &mut progress);
        }
    });
}

/// The `fork-context-ref` line `/branch` (Claude Code 2.1.309+) writes into
/// the new session, naming the session it copied.
fn fork_ref(session: &str, parent: &str) -> String {
    json!({"type":"fork-context-ref", "sessionId":session, "agentId":"fork-agent",
        "contextLength":1, "parentSessionId":parent, "parentLastUuid":"parent-last",
        "timestamp":"2026-08-02T07:03:00Z"})
    .to_string()
        + "\n"
}

/// PR C (a): the /branch of a session untouched for over 35 days, whose
/// census record is retired (it keeps no request ids). `named` writes the
/// branch's `fork-context-ref` line naming `parent`. Returns the branch body
/// (requests, removed) and the page's disclosed count.
fn branch_of_retired(name: &str, named: Option<&str>) -> ((u64, Option<u64>), u64) {
    with_e2(|| {
        let mut c = Corpus::new(name);
        c.root(ROOT, &line(ROOT, "original", AT, 10));
        let scanner = E2ScanFixture::default();
        let mut progress = e2_progress();
        let old = ScanIndex::default();
        let original = ready(&c, &scanner, old.clone(), 100, false);
        assert_eq!(total(&original), 1, "the original counts its request");
        let mut prior = settle(&c, &old, original, &mut progress);
        e2::pipeline_test_observer::retire_census(&mut prior, &format!("{ROOT}.jsonl"));
        let fork = named
            .map(|parent| fork_ref(COPY, parent))
            .unwrap_or_default();
        c.write_at(
            &format!("{COPY}.jsonl"),
            &(fork + &line(COPY, "original", AT, 10)),
            "2026-08-02T07:03:00Z",
        );
        let branch = ready(&c, &E2ScanFixture::default(), prior, 100, false);
        literal(&branch);
        assert!(body(&branch, ROOT).is_none(), "the original is unchanged");
        let copy = body(&branch, COPY).expect("the branch publishes its body");
        (
            (copy.request_count, copy.removed_request_count),
            e2::pipeline_test_observer::disclosed(&branch.scan.snapshots),
        )
    })
}
#[test]
fn e2_pipeline_branch_of_a_retired_original_named_by_its_fork_line_is_skipped() {
    assert_eq!(
        branch_of_retired("e2-pipeline-retired-named", Some(ROOT)),
        ((0, Some(1)), 0),
        "the still-indexed original the fork line names proves the copy: never counted twice"
    );
}
#[test]
fn e2_pipeline_branch_of_a_retired_original_without_a_fork_line_counts_and_discloses() {
    // No durable per-request store: without the name, the retired original
    // proves nothing, so the copy counts once more and is disclosed.
    assert_eq!(
        branch_of_retired("e2-pipeline-retired-unnamed", None),
        ((1, Some(0)), 1)
    );
}
#[test]
fn e2_pipeline_branch_naming_an_unindexed_session_counts_and_discloses() {
    // The fork line names a session that is not indexed: no proof.
    assert_eq!(
        branch_of_retired("e2-pipeline-retired-unindexed", Some(LATE)),
        ((1, Some(0)), 1)
    );
}

/// [money] The copy-only resume `COPY` repeats requests its original `ROOT`
/// holds. A complete terminal 36 days after both were last written keeps
/// every request id (a record lives while its file is indexed), so a later
/// re-read of the copy still proves its copies against the original instead
/// of counting them again (as an older release's retired original would:
/// `e2_pipeline_branch_of_a_retired_original_without_a_fork_line_counts_and_discloses`).
#[test]
fn e2_pipeline_aged_original_sharing_ids_with_its_copy_keeps_the_copy_proven() {
    with_e2(|| {
        let mut c = Corpus::new("e2-pipeline-aged-original-kept");
        let second = "2026-08-02T07:00:20Z";
        c.root(
            ROOT,
            &(line(ROOT, "first", AT, 10) + &line(ROOT, "second", second, 10)),
        );
        let scanner = E2ScanFixture::default();
        let mut progress = e2_progress();
        let old = ScanIndex::default();
        let original = ready(&c, &scanner, old.clone(), 100, false);
        assert_eq!(total(&original), 2, "the original counts its requests");
        let prior = settle(&c, &old, original, &mut progress);
        let copy = c.write_at(
            &format!("{COPY}.jsonl"),
            &line(COPY, "first", AT, 10),
            "2026-08-02T07:03:00Z",
        );
        let branch = ready(&c, &E2ScanFixture::default(), prior.clone(), 100, false);
        literal(&branch);
        let found = body(&branch, COPY).expect("the copy publishes its body");
        assert_eq!(
            (found.request_count, found.removed_request_count),
            (0, Some(1))
        );
        let mut prior = settle(&c, &prior, branch, &mut progress);

        // A complete terminal 36 days after both files were last written.
        let window = (OffsetDateTime::now_utc() + TimeDuration::days(36))
            .format(&Rfc3339)
            .unwrap();
        let keys = prior.files.keys().cloned().collect::<BTreeSet<_>>();
        // The terminal reads 0 transcript bytes: transcript I/O is denied
        // and no transcript is opened.
        let opens = crate::snapshots::all_transcript_opens_for_test();
        crate::snapshots::with_transcript_io_denied(|| {
            crate::snapshots::claude_request_census::settle_claude_request_census_terminal(
                &mut prior,
                &BTreeSet::new(),
                &window,
            )
        });
        assert_eq!(crate::snapshots::all_transcript_opens_for_test(), opens);
        let census = prior.claude_request_census_for_test();
        let record = |session: &str| {
            let name = format!("{session}.jsonl");
            let key = keys
                .iter()
                .find(|key| key.ends_with(&name))
                .expect("an indexed file");
            census.record_for_test(key).expect("a census record")
        };
        assert_eq!(
            record(ROOT).retired_for_test(),
            None,
            "the original keeps its ids"
        );
        assert_eq!(record(ROOT).request_hashes_for_test().len(), 2);
        assert!(record(ROOT).proves_scan());
        assert_eq!(
            record(COPY).retired_for_test(),
            None,
            "the copy keeps its id"
        );

        // The copy is re-read with a second copied request: both stay proven.
        std::fs::write(
            &copy,
            line(COPY, "first", AT, 10) + &line(COPY, "second", second, 10),
        )
        .unwrap();
        let reread = ready(&c, &E2ScanFixture::default(), prior, 100, false);
        literal(&reread);
        let found = body(&reread, COPY).expect("the re-read copy publishes its body");
        assert_eq!(
            (found.request_count, found.removed_request_count),
            (0, Some(2)),
            "the kept original still proves every copied request"
        );
        assert_eq!(
            e2::pipeline_test_observer::disclosed(&reread.scan.snapshots),
            0
        );
    });
}

/// PR C (c) and (d): the copy is read while its holder `LATE`, changed
/// since its last read, is still queued by the traversal. `stale_record`:
/// the holder keeps a census record of its old content (rewritten in place
/// without the request); else it has none (indexed, record lost) and grew.
/// The copy decides immediately from existing positive proof. Committing
/// the holder's re-read marks a correction, so each request counts once.
fn copy_waits_for_queued_holder(stale_record: bool) {
    with_e2(|| {
        let mut c = Corpus::new(&format!("e2-pipeline-queued-holder-{stale_record}"));
        let original = c.root(LATE, &line(LATE, "original", AT, 10));
        let scanner = E2ScanFixture::default();
        let mut progress = e2_progress();
        let old = ScanIndex::default();
        let first = ready(&c, &scanner, old.clone(), 100, false);
        let mut prior = settle(&c, &old, first, &mut progress);
        let expected_original = if stale_record {
            std::fs::write(&original, line(LATE, "rewritten", AT, 100)).unwrap();
            1
        } else {
            e2::pipeline_test_observer::forget_census(&mut prior, &format!("{LATE}.jsonl"));
            let grown = line(LATE, "original", AT, 10) + &line(LATE, "more", AT, 20);
            std::fs::write(&original, grown).unwrap();
            2
        };
        c.write_at(
            &format!("{COPY}.jsonl"),
            &line(COPY, "original", AT, 10),
            "2026-08-02T07:03:00Z",
        );
        let scanner = E2ScanFixture::default();
        let mut held = c.raw(&scanner, prior.clone(), 1, false, &[]);
        held.enrich(&c);
        let opened = scanner.paths();
        assert_eq!(opened.len(), 1, "one file per page");
        assert!(
            opened[0].ends_with(format!("{COPY}.jsonl")),
            "the copy is read while its changed holder is still queued"
        );
        literal(&held);
        let first_copy = body(&held, COPY).unwrap();
        let first_decision = (first_copy.request_count, first_copy.removed_request_count);
        assert_eq!(
            first_decision,
            if stale_record {
                (0, Some(1))
            } else {
                (1, Some(0))
            },
            "positive accepted census removes immediately; missing census counts immediately"
        );
        prior = settle(&c, &prior, held, &mut progress);
        let (mut copy_body, mut original_requests) = (Some(first_decision), None);
        for _ in 0..4 {
            let page = ready(&c, &E2ScanFixture::default(), prior.clone(), 100, false);
            if let Some(found) = body(&page, LATE) {
                literal(&page);
                original_requests = Some(found.request_count);
            }
            if let Some(found) = body(&page, COPY) {
                literal(&page);
                copy_body = Some((found.request_count, found.removed_request_count));
            }
            prior = settle(&c, &prior, page, &mut progress);
            // The holder's save marks a later correction; its own page is
            // not evidence that the copy has consumed that mark yet.
            if original_requests.is_some()
                && copy_body
                    == Some(if stale_record {
                        (1, Some(0))
                    } else {
                        (0, Some(1))
                    })
            {
                break;
            }
        }
        assert_eq!(original_requests, Some(expected_original));
        assert_eq!(
            copy_body,
            Some(if stale_record {
                (1, Some(0))
            } else {
                (0, Some(1))
            }),
            "the copy's request counts exactly once: in the copy only when the \
             re-read holder no longer holds it"
        );
    });
}
#[test]
fn e2_pipeline_copy_waits_for_a_queued_stale_holder() {
    copy_waits_for_queued_holder(true);
}
#[test]
fn e2_pipeline_copy_waits_for_a_queued_indexed_holder_without_a_census_record() {
    copy_waits_for_queued_holder(false);
}

/// A file whose every response conflicts keeps
/// a zero-usage carrier that publishes its conflict disclosure through the
/// literal, ACK and restart path, over an accepted prior body.
fn conflict_only(subagent: bool, sampled: bool) {
    with_e2(|| {
        let mut c = Corpus::new(&format!("e2-pipeline-conflict-only-{subagent}"));
        let session = if subagent {
            format!("{ROOT}_agent-000")
        } else {
            ROOT.to_owned()
        };
        let a = line(ROOT, "conflict", AT, 2);
        let b = a.replace("claude-haiku-4-5", "claude-sonnet-4-5");
        let path = if subagent {
            c.root(ROOT, &line(ROOT, "root-own", AT, 5));
            c.agent(0, &a)
        } else {
            c.root(ROOT, &a)
        };
        let scanner = E2ScanFixture::default();
        let mut progress = e2_progress();
        let old = ScanIndex::default();
        let accepted = ready(&c, &scanner, old.clone(), 100, sampled);
        let prior_body = body(&accepted, &session).expect("accepted prior body");
        assert_eq!(prior_body.request_count, 1);
        let prior = settle(&c, &old, accepted, &mut progress);
        // A later revision makes its only response a resolver conflict.
        std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(b.as_bytes())
            .unwrap();
        let mut conflicted = ready(&c, &E2ScanFixture::default(), prior.clone(), 100, sampled);
        let carrier = body(&conflicted, &session).expect("conflict-only file keeps a carrier");
        assert!(crate::snapshots::claude_request_money::is_request_owned_literal(carrier));
        assert_eq!(carrier.request_count, 0, "no invented tokens");
        assert_eq!(
            (carrier.input_tokens, carrier.output_tokens),
            (0, 0),
            "no invented tokens"
        );
        assert_eq!(carrier.resolver_conflict_count, Some(1));
        conflicted.finish();
        let bytes = canonical(&conflicted.scan.snapshots);
        // A crash before the ACK: discard the page's uncommitted native state.
        drop(conflicted);
        let mut restart = cold_ready(&c, prior, 100, sampled);
        restart.finish();
        if !sampled {
            assert!(
                restart.scan.snapshots.is_empty(),
                "a recent growth Full is paced"
            );
            let mut due = c.reload(&mut restart.index);
            crate::snapshots::e2_pipeline_scan_fixture::expire_claimed_growth_for_test(
                &mut due, &path,
            );
            drop(restart);
            restart = cold_ready(&c, due, 100, false);
            restart.finish();
        }
        assert_eq!(
            canonical(&restart.scan.snapshots),
            bytes,
            "restart re-derives the same carrier bytes"
        );
        let (result, _, _) = upload(&restart.scan.snapshots, &mut progress, ack);
        assert_eq!(result.unwrap(), ResumableUploadResult::Completed);
    });
}
#[test]
fn e2_pipeline_root_conflict_only_file_publishes_its_disclosure() {
    conflict_only(false, true);
}
#[test]
fn e2_pipeline_subagent_conflict_only_file_publishes_its_disclosure() {
    conflict_only(true, true);
}

#[test]
fn e2_pipeline_unsampled_conflict_carrier_resumes_after_growth_claim_expires() {
    for subagent in [false, true] {
        conflict_only(subagent, false);
    }
}

// Shared helpers above remain the real scan/evidence/finish/upload callers.
// Keep the CI test filter stable while its base-compatible transplant stays
// independent of the Tail implementation used by this build.
pub(in crate::snapshot_sync) mod money_equivalence_tests {
    include!("claude_tail_money_tests.rs");
    mod resident_wave_money_tests {
        include!("resident_wave_money_tests.rs");
    }
    #[cfg(unix)]
    mod root_twin_scope_tests {
        include!("root_twin_scope_tests.rs");
    }
    #[cfg(unix)]
    mod subagent_twin_tail_tests {
        include!("subagent_twin_tail_tests.rs");
    }
    #[cfg(unix)]
    mod lease_touch_oracle_tests {
        include!("lease_touch_oracle_tests.rs");
    }
    pub(in crate::snapshot_sync) mod copy_prefix_route_tests {
        include!("copy_prefix_route_tests.rs");
    }
    mod copy_route_oracle_tests {
        include!("copy_route_oracle_tests.rs");
    }
    #[cfg(unix)]
    mod codex_legacy_fork_tests {
        include!("../snapshots/codex_legacy_fork_tests.rs");
    }
    #[cfg(unix)]
    mod codex_creator_slot_oracle_tests {
        include!("../snapshots/sampled_scan/codex_creator_slot_oracle_tests.rs");
    }
    #[cfg(unix)]
    mod codex_login_identity_oracle_tests {
        include!("../snapshots/sampled_scan/codex_login_identity_oracle_tests.rs");
    }
}

pub(in crate::snapshot_sync) mod reject_isolation_tests {
    include!("reject_isolation_tests.rs");
}

// V2-only fixtures must not enter the cross-build harness transplanted to v1.
mod state_v2_money_tests {
    include!("state_v2_money_tests.rs");
}

mod evidence_chunk_tests;

#[cfg(unix)]
mod claude_tail_oracle_tests;

#[cfg(unix)]
mod codex_tail_oracle_tests;

#[cfg(unix)]
pub(in crate::snapshot_sync) use codex_tail_oracle_tests::{
    assert_joined_ack, assert_joined_post, revert_archives,
};

#[test]
fn e2_page_never_creates_ledger_or_diagnostics() {
    with_e2(|| {
        let mut corpus = Corpus::new("e2-without-p1");
        corpus.root(ROOT, &line(ROOT, "req-real", AT, 10));
        corpus.evidence(&[api("req-real", 10, 100)], &[]);
        let scanner = E2ScanFixture::default();
        let mut page = corpus.raw(&scanner, ScanIndex::default(), 16, true, &[]);
        page.enrich(&corpus);
        page.finish();
        literal(&page);
        assert_eq!(total(&page), 1);
        assert!(!corpus.support.join("claude-request-ledger").exists());
        assert!(!corpus
            .support
            .join(".claude-request-money-run.json")
            .exists());
        assert!(!corpus.support.join("diagnostics").exists());
    });
}

// Copy-family fix: resumed
// files of any Claude Code version, with turns of their own after the
// copied prefix (the demo 2026-08-12 shape).
const THIRD: &str = "4338a80a-f36e-4cbc-a5bb-50fc66430ba5";
const OLD_WRITER: &str = "2.1.222";
const RESUME_WRITER: &str = "2.1.229";
fn file(session: &str) -> String {
    format!("{session}.jsonl")
}
/// Lines `(request, clock, writer)` of one resumed file, all under `session`.
fn resumed(session: &str, lines: &[(&str, &str, &str)]) -> String {
    lines
        .iter()
        .map(|(request, at, writer)| line_by(session, request, at, 10, writer))
        .collect()
}
const A: (&str, &str, &str) = ("a", "2026-08-02T07:00:10Z", OLD_WRITER);
const B: (&str, &str, &str) = ("b", "2026-08-02T07:00:20Z", OLD_WRITER);
const C: (&str, &str, &str) = ("c", "2026-08-02T07:03:10Z", RESUME_WRITER);
const D: (&str, &str, &str) = ("d", "2026-08-02T07:06:10Z", RESUME_WRITER);
/// The page's `e2` diagnostics for these keys (test-only tally).
fn copy_diag(keys: &[&str]) -> Vec<u64> {
    let diag = e2::take_diag();
    keys.iter()
        .map(|key| diag.get(key).copied().unwrap_or(0))
        .collect()
}
const PREFIX_KEYS: [&str; 5] = [
    "copy_prefix_unproven",
    "copy_prefix_unproven_files",
    "copy_prefix_unproven_cost_micros",
    "copy_removal_reused",
    "copy_removal_stored",
];

/// The original (2 requests), its resume (copies a, b; own c) and the
/// resume of that (copies a, b, c; own d), each read after the previous
/// file settled. Returns the settled index.
/// A checked released-format value (pre-dedupe bodies, accepted-share ledgers, held
/// scan-index state), captured once from the released copy path; see
/// `snapshots/fixtures/README.md`. `name` is `<fixture>.<value>`.
fn released(name: &str) -> serde_json::Value {
    static FIXTURE: std::sync::OnceLock<serde_json::Value> = std::sync::OnceLock::new();
    let fixture = FIXTURE.get_or_init(|| {
        serde_json::from_str(include_str!(
            "../snapshots/fixtures/claude_released_copy_prefix.json"
        ))
        .unwrap()
    });
    let mut value = fixture[name].clone();
    assert!(!value.is_null(), "released fixture {name}");
    // A released ledger's LRU stamp is decoded and dropped, never written.
    let sessions = value
        .as_object_mut()
        .into_iter()
        .flat_map(|map| map.values_mut());
    for session in sessions.filter_map(serde_json::Value::as_object_mut) {
        if session.contains_key("key_epoch") {
            session.remove("last_ack");
        }
    }
    value
}
/// A body's serialized form without its source-file fingerprint: a hash of
/// the corpus path and clock, the one field another corpus legitimately changes.
fn without_file_fingerprint(body: &impl Serialize) -> serde_json::Value {
    let mut body = serde_json::to_value(body).unwrap();
    body.as_object_mut()
        .unwrap()
        .remove("source_file_fingerprint")
        .expect("bodies carry a source file fingerprint");
    body
}
/// [`without_file_fingerprint`] without cache rows either: the released
/// fixture predates Claude cache rows.
fn without_file_fingerprint_or_cache(body: &impl Serialize) -> serde_json::Value {
    let mut body = without_file_fingerprint(body);
    body.as_object_mut().unwrap().remove("cache_observations");
    body
}
/// The five token counters of a serialized body.
fn body_tokens(body: &serde_json::Value) -> [u64; 5] {
    [
        "input_tokens",
        "output_tokens",
        "cache_read_tokens",
        "cache_creation_5m_tokens",
        "cache_creation_1h_tokens",
    ]
    .map(|field| body[field].as_u64().unwrap())
}
fn demo_family(c: &mut Corpus, progress: &mut SnapshotUploadProgress) -> ScanIndex {
    c.root(ROOT, &resumed(ROOT, &[A, B]));
    let old = ScanIndex::default();
    let original = ready(c, &E2ScanFixture::default(), old.clone(), 100, false);
    assert_eq!(total(&original), 2, "the original counts its own requests");
    let prior = settle(c, &old, original, progress);
    e2::take_diag();
    c.write_at(
        &file(COPY),
        &resumed(COPY, &[A, B, C]),
        "2026-08-02T07:03:00Z",
    );
    let first = ready(c, &E2ScanFixture::default(), prior.clone(), 100, false);
    literal(&first);
    let copy = body(&first, COPY).expect("the resume publishes its body");
    assert_eq!(
        (copy.request_count, copy.removed_request_count),
        (1, Some(2)),
        "the resume counts only its own turn; its copied prefix is removed by request ids"
    );
    assert_eq!(
        copy_diag(&PREFIX_KEYS),
        [0, 0, 0, 0, 2],
        "proven, so stored and never flagged"
    );
    let prior = settle(c, &prior, first, progress);
    c.write_at(
        &file(THIRD),
        &resumed(THIRD, &[A, B, C, D]),
        "2026-08-02T07:06:00Z",
    );
    let second = ready(c, &E2ScanFixture::default(), prior.clone(), 100, false);
    literal(&second);
    let third = body(&second, THIRD).expect("the second resume publishes its body");
    assert_eq!(
        (third.request_count, third.removed_request_count),
        (1, Some(3))
    );
    assert_eq!(copy_diag(&PREFIX_KEYS), [0, 0, 0, 0, 3]);
    settle(c, &prior, second, progress)
}

#[test]
fn e2_pipeline_resumed_prefix_counts_removed_partial_dollars_and_own_turns() {
    with_e2(|| {
        let mut c = Corpus::new("e2-copy-switch-counts");
        c.root(ROOT, &resumed(ROOT, &[A, B]));
        let old = ScanIndex::default();
        let original = ready(&c, &E2ScanFixture::default(), old.clone(), 100, false);
        let prior = settle(&c, &old, original, &mut e2_progress());
        c.write_at(
            &file(COPY),
            &resumed(COPY, &[A, B, C]),
            "2026-08-02T07:03:00Z",
        );
        c.evidence_for(
            COPY,
            &[
                api_for(COPY, "a", 10, 100),
                api_for(COPY, "b", 10, 200),
                api_for(COPY, "c", 10, 400),
            ],
            &[],
        );
        e2::take_diag();
        let on = ready(&c, &E2ScanFixture::default(), prior.clone(), 100, false);
        assert_eq!(body(&on, COPY).unwrap().removed_request_count, Some(2));
        assert_eq!(
            copy_diag(&[
                "copy_prefix_removed_priced_requests",
                "copy_prefix_removed_cost_micros",
                "copy_prefix_own_requests",
                "copy_prefix_families_corrected"
            ]),
            [2, 300, 1, 1]
        );
    });
}

#[test]
fn corrected_family_counter_excludes_history_vetoed_literals() {
    with_e2(|| {
        let mut c = Corpus::new("e2-copy-counter-history-veto");
        let mut prior = demo_family(&mut c, &mut e2_progress());
        prior.activate_effective_upload_body_witness_revision(3);
        let path = c.root.join(file(THIRD));
        assert!(
            prior.re_owe_effective_upload_body_witness_revision(path.to_string_lossy().as_ref(), 2)
        );
        // Read the owed member through the normal scanner, then use the
        // production late telemetry hold. This isolates the counter's final
        // emission decision from candidate-admission and page-budget rules.
        let scanner = E2ScanFixture::default();
        let mut page = c.raw(&scanner, prior, 100, false, &[]);
        assert!(
            scanner.paths().contains(&path),
            "the owed member was actually read"
        );
        page.scan
            .snapshots
            .retain(|item| item.source_session_id == THIRD);
        assert_eq!(
            page.scan.snapshots.len(),
            1,
            "actual native read of the held member"
        );
        assert_eq!(
            page.index.hold_claude_history_for_unread_telemetry(),
            1,
            "one permitted owed member is now held by the production emission seam"
        );
        e2::take_diag();
        page.enrich(&c);
        assert_eq!(
            page.released.removed_requests, 3,
            "the literal actually removed its proven prefix"
        );
        assert_eq!(copy_diag(&["copy_prefix_families_corrected"]), [0]);
        assert!(
            body(&page, THIRD).is_none(),
            "history-held literal is vetoed"
        );
        page.finish();
        assert!(
            body(&page, THIRD).is_none(),
            "finalization cannot restore the vetoed literal"
        );
    });
}

#[test]
fn e2_pipeline_resumed_old_writer_family_counts_each_request_once() {
    with_e2(|| {
        let mut c = Corpus::new("e2-pipeline-copy-family-demo");
        let mut progress = e2_progress();
        let settled = demo_family(&mut c, &mut progress);
        // a, b by the original; c, d by the resume that wrote each: 4 requests
        // across 2 + 1 + 1 counted, never a copy twice.
        assert!(
            !settled.claude_copy_removals.is_empty(),
            "the decisions survive save and reload"
        );
    });
}

#[test]
fn e2_pipeline_resumed_copy_removal_stays_removed_after_its_proof_retires() {
    with_e2(|| {
        let mut c = Corpus::new("e2-pipeline-copy-family-retired");
        let mut progress = e2_progress();
        let mut prior = demo_family(&mut c, &mut progress);
        // Both holders' census records retire (35 idle days): their id lists
        // are gone. The latest resume then gets a new own turn and is re-read.
        e2::pipeline_test_observer::retire_census(&mut prior, &file(ROOT));
        e2::pipeline_test_observer::retire_census(&mut prior, &file(COPY));
        append(
            &c.root.join(file(THIRD)),
            &line_by(THIRD, "e", "2026-08-02T07:06:20Z", 10, RESUME_WRITER),
        );
        e2::take_diag();
        let page = ready(&c, &E2ScanFixture::default(), prior, 100, false);
        literal(&page);
        let third = body(&page, THIRD).expect("the grown resume publishes");
        assert_eq!(
            (third.request_count, third.removed_request_count),
            (2, Some(3)),
            "its own turns count; the stored removal keeps the copies removed"
        );
        assert_eq!(
            e2::pipeline_test_observer::disclosed(&page.scan.snapshots),
            0
        );
        assert_eq!(
            copy_diag(&PREFIX_KEYS),
            [0, 0, 0, 3, 0],
            "reused, never flagged or re-added"
        );
    });
}

#[test]
fn e2_pipeline_stored_copy_removal_is_dropped_when_its_holder_no_longer_holds_it() {
    with_e2(|| {
        let mut c = Corpus::new("e2-pipeline-copy-family-disproven");
        let mut progress = e2_progress();
        let prior = demo_family(&mut c, &mut progress);
        // The original is rewritten without request a (replaced, not
        // appended) and read again: its current census lacks a.
        c.write_at(&file(ROOT), &resumed(ROOT, &[B]), "2026-08-02T07:00:00Z");
        let rewrite = ready(&c, &E2ScanFixture::default(), prior.clone(), 100, false);
        assert_eq!(body(&rewrite, ROOT).map(|s| s.request_count), Some(1));
        let mut prior = settle(&c, &prior, rewrite, &mut progress);
        // Commit the marked corrections before retiring their new holder proof.
        let repair = ready(&c, &E2ScanFixture::default(), prior.clone(), 100, false);
        let fallback = body(&repair, COPY).expect("the marked intermediate holder restores a");
        assert_eq!(
            (fallback.request_count, fallback.removed_request_count),
            (2, Some(1))
        );
        prior = settle(&c, &prior, repair, &mut progress);
        // The first resume's id list retires; the second resume grows.
        e2::pipeline_test_observer::retire_census(&mut prior, &file(COPY));
        append(
            &c.root.join(file(THIRD)),
            &line_by(THIRD, "e", "2026-08-02T07:06:20Z", 10, RESUME_WRITER),
        );
        e2::take_diag();
        let page = ready(&c, &E2ScanFixture::default(), prior, 100, false);
        literal(&page);
        let third = body(&page, THIRD).expect("the grown resume publishes");
        // The changed original re-arms COPY too. Its corrected body owns a;
        // THIRD keeps a removed under that holder even after its census retires.
        assert_eq!(
            (third.request_count, third.removed_request_count),
            (2, Some(3))
        );
        assert_eq!(
            third.input_tokens + third.removed_usage.as_ref().unwrap().input_tokens,
            50
        );
        assert_eq!(copy_diag(&PREFIX_KEYS), [0, 0, 0, 2, 0]);
    });
}

#[test]
fn e2_pipeline_resumed_copy_without_proof_or_stored_removal_counts_flagged() {
    for missing in [false, true] {
        with_e2(|| {
            let mut c = Corpus::new("e2-pipeline-copy-family-unproven");
            let mut progress = e2_progress();
            c.root(ROOT, &resumed(ROOT, &[A, B]));
            let old = ScanIndex::default();
            let original = ready(&c, &E2ScanFixture::default(), old.clone(), 100, false);
            let mut prior = settle(&c, &old, original, &mut progress);
            // The holder's id list aged out before the resume was ever decided.
            if missing {
                e2::pipeline_test_observer::forget_census(&mut prior, &file(ROOT));
            } else {
                e2::pipeline_test_observer::retire_census(&mut prior, &file(ROOT));
            }
            c.write_at(
                &file(COPY),
                &(fork_ref(COPY, ROOT) + &resumed(COPY, &[A, B, C])),
                "2026-08-02T07:03:00Z",
            );
            c.evidence_for(COPY, &[api_for(COPY, "a", 10, 250)], &[]);
            e2::take_diag();
            let page = ready(&c, &E2ScanFixture::default(), prior, 100, false);
            literal(&page);
            let copy = body(&page, COPY).expect("never held: the resume publishes");
            assert_eq!(
                (copy.request_count, copy.removed_request_count),
                (3, Some(0)),
                "unproven copies are emitted (counted), never dropped and never held"
            );
            assert_eq!(
                e2::pipeline_test_observer::disclosed(&page.scan.snapshots),
                2
            );
            // Exactly the copied prefix is flagged (a, b), with the reported cost
            // of the one matched to priced telemetry; the own turn c never.
            assert_eq!(copy_diag(&PREFIX_KEYS), [2, 1, 250, 0, 0]);
            assert!(
                page.index.claude_copy_removals.is_empty(),
                "nothing proven, nothing stored"
            );
        });
    }
}

/// [money] Regression test: resumed main files counted their copied requests twice.
/// The shape: a resumed main file of any writer version, own turns in
/// later hours and its holder in an earlier accepted member. Its re-read of
/// the same bytes removes exactly the copied requests; every token counter is
/// conserved (kept + removed = the released body), the own turns
/// keep their money, and an unrelated session's body is unchanged. Scheduling
/// the paced re-read is the `claude_copy_prefix_reread` tests' concern.
#[test]
fn e2_pipeline_audit_shaped_resume_reread_removes_exactly_its_copies() {
    with_e2(|| {
        const OTHER: &str = "8338a80a-f36e-4cbc-a5bb-50fc66430ba5";
        let mut c = Corpus::new("e2-pipeline-audit-shape");
        c.root(ROOT, &resumed(ROOT, &[A, B]));
        let old = ScanIndex::default();
        let page = ready(&c, &E2ScanFixture::default(), old.clone(), 100, false);
        let prior = settle(&c, &old, page, &mut e2_progress());
        let late = ("d-late", "2026-08-02T08:10:00Z", RESUME_WRITER);
        c.write_at(
            &file(COPY),
            &resumed(COPY, &[A, B, C, late]),
            "2026-08-02T07:03:00Z",
        );
        c.write_at(
            &file(OTHER),
            &resumed(OTHER, &[("u1", "2026-08-02T07:30:10Z", RESUME_WRITER)]),
            "2026-08-02T07:30:00Z",
        );
        let accepted = released("audit.copy");
        assert_eq!(
            (
                &accepted["request_count"],
                &accepted["removed_request_count"]
            ),
            (&json!(4), &json!(0)),
            "the released body accepted the copied prefix"
        );
        let on = ready(&c, &E2ScanFixture::default(), prior.clone(), 100, false);
        let copy = body(&on, COPY).unwrap();
        assert_eq!(
            (copy.request_count, copy.removed_request_count),
            (2, Some(2)),
            "only the copied requests are removed"
        );
        let removed = copy.removed_usage.expect("removed usage is counted");
        let kept = body_tokens(&serde_json::to_value(copy).unwrap());
        let gone = [
            removed.input_tokens,
            removed.output_tokens,
            removed.cache_read_tokens,
            removed.cache_creation_5m_tokens,
            removed.cache_creation_1h_tokens,
        ];
        assert_eq!(
            std::array::from_fn::<u64, 5, _>(|n| kept[n] + gone[n]),
            body_tokens(&accepted),
            "kept + removed tokens = the accepted released body, per counter"
        );
        assert_eq!(
            copy.output_tokens, 20,
            "the two own turns keep their tokens"
        );
        // The released body predates counted request positions.
        let mut other = body(&on, OTHER).unwrap().clone();
        crate::snapshots::clear_counted_request_positions(&mut other);
        assert_eq!(
            canonical(&without_file_fingerprint_or_cache(&other)),
            canonical(&without_file_fingerprint_or_cache(&released("audit.other"))),
            "unrelated body unchanged"
        );
    });
}

#[test]
fn e2_pipeline_file_without_copied_prefix_stores_and_flags_nothing() {
    with_e2(|| {
        let mut c = Corpus::new("e2-pipeline-copy-family-none");
        c.root(ROOT, &resumed(ROOT, &[A, B]));
        e2::take_diag();
        let page = ready(
            &c,
            &E2ScanFixture::default(),
            ScanIndex::default(),
            100,
            false,
        );
        literal(&page);
        let original = body(&page, ROOT).unwrap();
        assert_eq!(original.request_count, 2);
        assert_eq!(copy_diag(&PREFIX_KEYS), [0; 5]);
        assert!(page.index.claude_copy_removals.is_empty());
    });
}

/// A copy decision completes even when a deadline-bearing census walk would
/// time out. The unchanged copy is read once and stays unmarked for ten passes.
#[test]
fn e2_pipeline_copy_census_completes_once_over_ten_unchanged_passes() {
    for sampled in [false, true] {
        with_e2(|| {
            let mut c = Corpus::new("e2-pipeline-copy-census-completes");
            c.root(ROOT, &resumed(ROOT, &[A, B]));
            let mut progress = e2_progress();
            let scanner = E2ScanFixture::default();
            let old = ScanIndex::default();
            let original = ready(&c, &scanner, old.clone(), 100, sampled);
            let mut prior = settle(&c, &old, original, &mut progress);
            let path = c.write_at(
                &file(COPY),
                &resumed(COPY, &[A, B, C]),
                "2026-08-02T07:03:00Z",
            );
            let location =
                crate::snapshots::claude_money_birth_store::location_key(&path.to_string_lossy());
            let mut reads = 0;
            for pass in 0..=10 {
                let mut page = c.raw(&scanner, prior.clone(), 100, sampled, &[]);
                reads += usize::from(scanner.paths().contains(&path));
                crate::snapshots::claude_request_census::with_walk_deadline_for_test(|| {
                    page.enrich(&c);
                });
                if pass == 0 {
                    let copy = body(&page, COPY).expect("the copy is decided on its first pass");
                    assert!(crate::snapshots::claude_request_money::is_request_owned_literal(copy));
                    assert_eq!(
                        (copy.request_count, copy.removed_request_count),
                        (1, Some(2))
                    );
                } else {
                    assert!(body(&page, COPY).is_none(), "unchanged copy on pass {pass}");
                }
                assert!(!page.index.claude_copy_removals.pending(location));
                prior = settle(&c, &prior, page, &mut progress);
                assert!(!prior.claude_copy_removals.pending(location));
            }
            assert_eq!(reads, 1, "one decision read, then ten unchanged passes");
        });
    }
}

#[test]
fn e2_pipeline_lossy_holder_hits_prove_but_absences_are_flagged() {
    with_e2(|| {
        let mut c = Corpus::new("e2-pipeline-lossy-positive");
        c.root(ROOT, &resumed(ROOT, &[A, B]));
        let old = ScanIndex::default();
        let original = ready(&c, &E2ScanFixture::default(), old.clone(), 100, false);
        let mut prior = settle(&c, &old, original, &mut e2_progress());
        e2::pipeline_test_observer::lossy_census(&mut prior, &file(ROOT), &["a"]);
        c.write_at(
            &file(COPY),
            &resumed(COPY, &[A, B, C]),
            "2026-08-02T07:03:00Z",
        );
        e2::take_diag();
        let page = ready(&c, &E2ScanFixture::default(), prior, 100, false);
        let copy = body(&page, COPY).unwrap();
        assert_eq!(
            (copy.request_count, copy.removed_request_count),
            (2, Some(1))
        );
        assert_eq!(
            copy_diag(&["copy_prefix_unproven", "copy_removal_stored"]),
            [1, 1]
        );
    });
}

#[test]
fn e2_pipeline_lossy_absence_never_invalidates_a_stored_removal() {
    with_e2(|| {
        let mut c = Corpus::new("e2-pipeline-lossy-stored");
        let mut prior = demo_family(&mut c, &mut e2_progress());
        e2::pipeline_test_observer::lossy_census(&mut prior, &file(ROOT), &["b"]);
        e2::pipeline_test_observer::retire_census(&mut prior, &file(COPY));
        append(
            &c.root.join(file(THIRD)),
            &line_by(THIRD, "e", "2026-08-02T07:06:20Z", 10, RESUME_WRITER),
        );
        e2::take_diag();
        let page = ready(&c, &E2ScanFixture::default(), prior, 100, false);
        let third = body(&page, THIRD).unwrap();
        assert_eq!(
            (third.request_count, third.removed_request_count),
            (2, Some(3))
        );
        assert_eq!(
            copy_diag(&["copy_prefix_unproven", "copy_removal_reused"]),
            [0, 2]
        );
    });
}

/// [money] An accepted copy whose saved removal metadata is lost (absent or
/// damaged) is decided by the request-id holder proof like any other copy:
/// while the census still proves the holder, the prefix stays removed; once
/// nothing proves it, the prefix is counted and flagged as unproven, and a
/// damaged record is also flagged as lost metadata. Own turns publish
/// without delay.
#[test]
fn e2_pipeline_lost_removal_metadata_decides_by_holder_proof() {
    for missing in [false, true] {
        for retired in [false, true] {
            with_e2(|| {
                let mut c = Corpus::new("e2-pipeline-removal-metadata-lost");
                let mut prior = demo_family(&mut c, &mut e2_progress());
                if retired {
                    e2::pipeline_test_observer::retire_census(&mut prior, &file(ROOT));
                    e2::pipeline_test_observer::retire_census(&mut prior, &file(COPY));
                }
                let mut encoded = serde_json::to_value(&prior).unwrap();
                if missing {
                    encoded
                        .as_object_mut()
                        .unwrap()
                        .remove("claude_copy_removals");
                } else {
                    encoded["claude_copy_removals"] = json!("damaged");
                }
                prior = serde_json::from_value(encoded).unwrap();
                prior = c.reload(&mut prior); // both native and streaming decode
                append(
                    &c.root.join(file(THIRD)),
                    &line_by(THIRD, "e", "2026-08-02T07:06:20Z", 10, RESUME_WRITER),
                );
                e2::take_diag();
                let page = ready(&c, &E2ScanFixture::default(), prior, 100, false);
                let third = body(&page, THIRD).expect("own turns always publish");
                let case = format!("missing {missing} retired {retired}");
                if retired {
                    // No proof left: the prefix counts and is flagged.
                    assert_eq!(
                        (third.request_count, third.removed_request_count),
                        (5, Some(0)),
                        "{case}"
                    );
                    assert_eq!(
                        copy_diag(&["copy_prefix_unproven", "copy_removal_metadata_lost"]),
                        [3, if missing { 0 } else { 3 }],
                        "{case}: counted prefix is flagged"
                    );
                } else {
                    // The census still proves the holder: the removal stays.
                    assert_eq!(
                        (third.request_count, third.removed_request_count),
                        (2, Some(3)),
                        "{case}"
                    );
                    assert_eq!(
                        copy_diag(&["copy_prefix_unproven", "copy_removal_metadata_lost"]),
                        [0, 0],
                        "{case}: nothing flagged"
                    );
                }
            });
        }
    }
}

#[test]
fn e2_pipeline_copy_unproven_wire_is_capability_gated_and_partitions_own_rows() {
    for sampled in [false, true] {
        with_e2(|| {
            let mut c = Corpus::new("e2-pipeline-copy-wire-gate");
            let scanner = E2ScanFixture::default();
            c.root(ROOT, &resumed(ROOT, &[A, B]));
            let old = ScanIndex::default();
            let original = ready(&c, &scanner, old.clone(), 100, sampled);
            let mut prior = settle(&c, &old, original, &mut e2_progress());
            e2::pipeline_test_observer::retire_census(&mut prior, &file(ROOT));
            c.write_at(
                &file(COPY),
                &resumed(COPY, &[A, B, C]),
                "2026-08-02T07:03:00Z",
            );
            // Same bucket/model/account: the prefix must not contaminate own rows,
            // including shared telemetry placement memo entries.
            c.evidence_for(
                COPY,
                &[api_for(COPY, "a", 10, 250), api_for(COPY, "c", 10, 400)],
                &[],
            );
            let off = ready(&c, &scanner, prior.clone(), 100, sampled);
            let off_body = body(&off, COPY).unwrap();
            let legacy = serde_json::to_value(off_body).unwrap();
            assert!(legacy.get("copy_unproven_counts").is_none());
            assert!(off_body
                .usage_buckets
                .iter()
                .flat_map(|b| &b.model_usage)
                .all(|r| !r.copy_unproven));
            assert!(!serde_json::to_string(&legacy)
                .unwrap()
                .contains("copy_unproven"));
            let again = ready(&c, &scanner, prior.clone(), 100, sampled);
            assert_eq!(
                canonical(off_body),
                canonical(body(&again, COPY).unwrap()),
                "gate-off unchanged input preserves complete body bytes"
            );
            assert_eq!(
                off_body.snapshot_fingerprint,
                body(&again, COPY).unwrap().snapshot_fingerprint
            );
            prior.copy_unproven_enabled = true;
            e2::take_diag();
            let on = ready(&c, &scanner, prior, 100, sampled);
            let on_body = body(&on, COPY).unwrap();
            assert_eq!(
                (on_body.request_count, on_body.input_tokens, &on_body.cost),
                (
                    off_body.request_count,
                    off_body.input_tokens,
                    &off_body.cost
                )
            );
            assert_eq!(
                on_body.copy_unproven_counts,
                Some(crate::snapshots::CopyUnprovenCounts {
                    rows: 2,
                    requests: 2
                })
            );
            let rows = on_body
                .usage_buckets
                .iter()
                .flat_map(|b| &b.model_usage)
                .collect::<Vec<_>>();
            assert_eq!(
                rows.iter()
                    .filter(|r| r.copy_unproven)
                    .map(|r| r.request_count)
                    .sum::<u64>(),
                2
            );
            assert_eq!(
                rows.iter()
                    .filter(|r| !r.copy_unproven)
                    .map(|r| r.request_count)
                    .sum::<u64>(),
                1
            );
            assert!(rows
                .iter()
                .all(|r| !r.selector_context.contains_key("__ottto_copy_unproven")));
            assert_ne!(
                crate::snapshots::snapshot_semantic_component_hashes(
                    SnapshotSource::ClaudeCode,
                    on_body
                ),
                crate::snapshots::snapshot_semantic_component_hashes(
                    SnapshotSource::ClaudeCode,
                    off_body
                )
            );
            assert_eq!(
                copy_diag(&[
                    "copy_prefix_unproven_rows",
                    "copy_prefix_unproven",
                    "copy_prefix_unproven_cost_micros"
                ]),
                [2, 2, 250]
            );
        });
    }
}

#[test]
fn e2_pipeline_proven_prefix_markers_never_lend_identity_to_retained_requests() {
    // Full proof, partial proof, an emitted prefix's own marker, and id-less
    // prefix usage all pass through production identity reconciliation.
    for (partial, retained_marker, idless) in [
        (false, false, false),
        (true, false, false),
        (true, true, false),
        (true, false, true),
    ] {
        with_e2(|| {
            let mut c = Corpus::new("e2-pipeline-copy-marker-exclusion");
            let scanner = E2ScanFixture::capturing_identity();
            c.root(ROOT, &resumed(ROOT, &[A]));
            let old = ScanIndex::default();
            let page = ready(&c, &scanner, old.clone(), 100, false);
            let prior = settle(&c, &old, page, &mut e2_progress());
            let org_a = "11111111-1111-4111-8111-111111111111";
            let org_b = "22222222-2222-4222-8222-222222222222";
            let marker = |org: &str| {
                json!({"type":"attachment", "sessionId":COPY,
                "attachment":{"type":"credential_org","organizationUuid":org}})
                .to_string()
                    + "\n"
            };
            // A real terminal org change carries a new session_context.
            // Blank context proves a switch without asserting email identity.
            let switched_b = || {
                json!({"type":"attachment", "sessionId":COPY,
                "attachment":{"type":"session_context", "context":{}}})
                .to_string()
                    + "\n"
                    + &marker(org_b)
            };
            let mut text = marker(org_a) + &resumed(COPY, &[A]);
            if partial {
                if retained_marker {
                    text += &switched_b();
                }
                let mut b: serde_json::Value =
                    serde_json::from_str(&line_by(COPY, B.0, B.1, 10, RESUME_WRITER)).unwrap();
                if idless {
                    b.as_object_mut().unwrap().remove("requestId");
                }
                text += &(b.to_string() + "\n");
            }
            text += &resumed(COPY, &[C]);
            // A later own marker stays authoritative only from its own turn.
            text += &switched_b();
            text += &line_by(COPY, "later", "2026-08-02T07:03:20Z", 10, RESUME_WRITER);
            c.write_at(&file(COPY), &text, "2026-08-02T07:03:00Z");
            let page = ready(&c, &scanner, prior, 100, false);
            let copy = body(&page, COPY).expect("retained usage publishes");
            assert_eq!(
                (copy.request_count, copy.removed_request_count),
                (if partial { 3 } else { 2 }, Some(1))
            );
            let a = ottto_core::billing_identity_hash("anthropic", "organization", org_a).unwrap();
            let b = ottto_core::billing_identity_hash("anthropic", "organization", org_b).unwrap();
            let shares = org_shares(copy);
            assert!(
                !shares.contains_key(&a),
                "removed marker cannot lend account identity"
            );
            assert_eq!(shares.get(&b), Some(&if retained_marker { 3 } else { 1 }));
            assert_eq!(copy.input_tokens, if partial { 30 } else { 20 });
        });
    }
}

#[test]
fn e2_pipeline_zero_usage_prefix_responses_neither_lend_markers_nor_hold_own_turns() {
    for zero_before_proven in [false, true] {
        with_e2(|| {
            let mut c = Corpus::new("e2-pipeline-copy-marker-zero-usage");
            let scanner = E2ScanFixture::capturing_identity();
            c.root(ROOT, &resumed(ROOT, &[A]));
            let old = ScanIndex::default();
            let page = ready(&c, &scanner, old.clone(), 100, false);
            let prior = settle(&c, &old, page, &mut e2_progress());
            let org = "11111111-1111-4111-8111-111111111111";
            let marker = json!({"type":"attachment", "sessionId":COPY,
                "attachment":{"type":"credential_org","organizationUuid":org}})
            .to_string()
                + "\n";
            let mut zero: serde_json::Value =
                serde_json::from_str(&line_by(COPY, "zero", B.1, 0, RESUME_WRITER)).unwrap();
            if zero_before_proven {
                zero["timestamp"] = json!("2026-08-02T07:00:05Z");
            }
            zero["message"]["usage"] = json!({"input_tokens":0,"output_tokens":0});
            let zero = zero.to_string() + "\n";
            let text = marker
                + &if zero_before_proven {
                    zero + &resumed(COPY, &[A, C])
                } else {
                    resumed(COPY, &[A]) + &zero + &resumed(COPY, &[C])
                };
            c.write_at(&file(COPY), &text, "2026-08-02T07:03:00Z");
            e2::take_diag();
            let page = ready(&c, &scanner, prior, 100, false);
            let copy = body(&page, COPY).expect("zero-usage prefix never withholds own turns");
            assert_eq!(
                (copy.request_count, copy.removed_request_count),
                (1, Some(1))
            );
            let org = ottto_core::billing_identity_hash("anthropic", "organization", org).unwrap();
            assert!(
                copy.request_evidence
                    .iter()
                    .all(|e| e.provider_workspace_hash.as_ref() != Some(&org)),
                "the removed marker cannot lend identity across a zero-usage response"
            );
            assert_eq!(copy_diag(&["copy_prefix_unproven"]), [0]);
        });
    }
}

#[test]
fn e2_pipeline_rewritten_prefix_clears_retry_debt_but_preserves_recorded_removals() {
    for empty in [false, true] {
        with_e2(|| {
            use crate::snapshots::claude_money_birth_store::location_key;
            let mut c = Corpus::new("e2-pipeline-rewritten-prefix-debt");
            let scanner = E2ScanFixture::default();
            let mut progress = e2_progress();
            let mut prior = demo_family(&mut c, &mut progress);
            let key = location_key(&c.root.join(file(THIRD)).to_string_lossy());
            let recorded = prior.claude_copy_removals.get(key).to_vec();
            assert_eq!(
                recorded
                    .iter()
                    .map(|(_, hashes)| hashes.len())
                    .sum::<usize>(),
                3
            );
            c.write_at(
                &file(THIRD),
                &resumed(
                    THIRD,
                    &[
                        A,
                        B,
                        C,
                        ("unresolved", "2026-08-02T07:05:00Z", RESUME_WRITER),
                        D,
                    ],
                ),
                "2026-08-02T07:06:00Z",
            );
            let decided = ready(&c, &scanner, prior.clone(), 100, false);
            assert_eq!(
                body(&decided, THIRD).map(|b| (b.request_count, b.removed_request_count)),
                Some((2, Some(3)))
            );
            prior = settle(&c, &prior, decided, &mut progress);
            // Ownership reconciliation can mark a decided copy for another read.
            prior.claude_copy_removals.mark(key);
            assert!(prior.claude_copy_removals.pending(key));
            c.write_at(
                &file(THIRD),
                &if empty {
                    String::new()
                } else {
                    resumed(THIRD, &[D])
                },
                "2026-08-02T07:06:00Z",
            );
            let rewritten = ready(&c, &scanner, prior.clone(), 100, false);
            assert_eq!(
                body(&rewritten, THIRD).map(|b| (b.request_count, b.removed_request_count)),
                if empty { None } else { Some((1, Some(0))) }
            );
            assert!(!rewritten.index.claude_copy_removals.pending(key));
            assert_eq!(
                rewritten.index.claude_copy_removals.get(key),
                recorded.as_slice()
            );
            prior = settle(&c, &prior, rewritten, &mut progress);
            assert!(!prior.claude_copy_removals.pending(key));
            assert_eq!(prior.claude_copy_removals.get(key), recorded.as_slice());
            let quiet = ready(&c, &scanner, prior, 100, false);
            assert!(
                body(&quiet, THIRD).is_none(),
                "resolved debt cannot force indefinite reads after ACK/restart"
            );
        });
    }
}

/// Requests of `item` per organization hash its identity names.
fn org_shares(item: &impl Serialize) -> BTreeMap<String, u64> {
    let item = serde_json::to_value(item).unwrap();
    let org = |row: &serde_json::Value| {
        let at = usize::try_from(row["evidence_ref"].as_u64()?).ok()?;
        item["request_evidence"][at]["provider_workspace_hash"]
            .as_str()
            .map(str::to_owned)
    };
    let mut shares = BTreeMap::<String, u64>::new();
    for row in item["model_usage"].as_array().into_iter().flatten() {
        let parts = row["identity_parts"].as_array();
        for part in parts.map_or(std::slice::from_ref(row), Vec::as_slice) {
            if let Some(org) = org(part) {
                *shares.entry(org).or_default() += part["request_count"].as_u64().unwrap();
            }
        }
    }
    shares
}

/// One `identity_cap` counter; the group and zero counters are
/// omitted from the serialized counts.
fn identity_count(counts: &serde_json::Value, key: &str) -> u64 {
    counts["identity_cap"][key].as_u64().unwrap_or(0)
}

/// [money] Five copy-derived identity fixtures in accepted-share protection mode.
/// In fixture 4, the tombstoned row on an unhealthy root stays definite (no refusal, marker or second tombstone). The
/// released body froze an own turn's org a copied prefix marker lent (X).
/// Copy-prefix dedupe tombstones that row once, counted, and sends it
/// untagged with no refusal or marker (today's attribution), while a later
/// row its own marker proves (B) keeps its accepted identity. A later own
/// marker in the invalidated row tags it fresh. Money never changes.
#[test]
fn e2_pipeline_upgrade_invalidates_identity_a_copied_marker_lent() {
    with_e2(|| {
        use crate::snapshots::claude_request_identity::{take_identity_counts, AcceptedBuckets};
        let mut c = Corpus::new("e2-pipeline-copy-derived-identity");
        let scanner = E2ScanFixture::capturing_identity();
        c.root(ROOT, &resumed(ROOT, &[A]));
        let old = ScanIndex::default();
        let page = ready(&c, &scanner, old.clone(), 100, false);
        let prior = settle(&c, &old, page, &mut e2_progress());
        let [org_x, org_b] = [
            "11111111-1111-4111-8111-111111111111",
            "22222222-2222-4222-8222-222222222222",
        ];
        let marker = |org: &str| {
            json!({"type":"attachment", "sessionId":COPY,
            "attachment":{"type":"credential_org","organizationUuid":org}})
            .to_string()
                + "\n"
        };
        // A trusted org change needs a changed session_context digest.
        let switched = |org: &str, email: &str| {
            json!({"type":"attachment", "sessionId":COPY,
            "attachment":{"type":"session_context", "context":{"userEmail":email}}})
            .to_string()
                + "\n"
                + &marker(org)
        };
        let mut text = marker(org_x)
            + &resumed(COPY, &[A, C])
            + &switched(org_b, "")
            + &line_by(COPY, "own", "2026-08-02T08:10:00Z", 10, RESUME_WRITER);
        c.write_at(&file(COPY), &text, "2026-08-02T07:03:00Z");
        let [x, b] = [org_x, org_b].map(|org| {
            ottto_core::billing_identity_hash("anthropic", "organization", org).unwrap()
        });
        let stored = released("identity.copy");
        assert_eq!(
            [&x, &b].map(|org| org_shares(&stored).get(org).copied()),
            [Some(2), Some(1)]
        );
        assert!(
            !stored.to_string().contains("copy_invalidated"),
            "the released body has no X-B1 flag"
        );
        let mut ledger = AcceptedBuckets::for_test();
        let ack = |ledger: &mut AcceptedBuckets, item: &SnapshotItem| {
            ledger.record(&serde_json::to_value(item).unwrap());
        };
        ledger.record(&serde_json::to_value(&stored).unwrap());
        assert_eq!(
            serde_json::to_value(&ledger).unwrap(),
            released("identity.ledger.retained-false"),
            "the released body yields the released ledger"
        );
        // The 07:00 row X lent, the 08:00 row B proves, and money per row.
        let rows = |item: &SnapshotItem| {
            item.usage_buckets
                .iter()
                .map(|bucket| {
                    let row = &bucket.model_usage[0];
                    let tagged = row.evidence_ref.is_some() || row.identity_parts.is_some();
                    (
                        bucket.bucket_start.clone(),
                        row.request_count,
                        row.input_tokens,
                        row.cost_usd.clone(),
                        tagged,
                    )
                })
                .collect::<Vec<_>>()
        };
        let today_item = {
            let mut page = c.raw(&scanner, prior.clone(), 100, false, &[]);
            page.enrich_with(&c, Some(&mut AcceptedBuckets::for_test()));
            body(&page, COPY).unwrap().clone()
        };
        let today = rows(&today_item);
        assert_eq!(
            today.iter().map(|row| row.4).collect::<Vec<_>>(),
            [false, true]
        );
        let pass = |c: &Corpus, ledger: &mut AcceptedBuckets| {
            let mut page = c.raw(&scanner, prior.clone(), 100, false, &[]);
            take_identity_counts();
            page.enrich_with(c, Some(ledger));
            let copy = body(&page, COPY).expect("the own turns publish").clone();
            let counts = serde_json::to_value(take_identity_counts()).unwrap();
            assert_eq!(copy.request_identity_refusals, 0, "never a refusal");
            assert_eq!(identity_count(&counts, "accepted_share_changed"), 0);
            (
                copy,
                identity_count(&counts, "copy_derived_proof_invalidated"),
            )
        };
        for once in [1, 0] {
            let (copy, invalidated) = pass(&c, &mut ledger);
            assert_eq!(invalidated, once, "one tombstone per copy-derived row");
            let got = rows(&copy);
            assert_eq!(got[0], today[0], "the X row moves to today's attribution");
            assert_eq!(
                (&got[1].0, got[1].1, got[1].2, &got[1].3),
                (&today[1].0, today[1].1, today[1].2, &today[1].3)
            );
            assert!(got[1].4, "the row B proves keeps its accepted identity");
            assert_eq!(org_shares(&copy).get(&x), None);
        }
        // Fixture 4: one sidecar of the pair makes the root unhealthy
        // (all accounts Unknown). Only the row B proves keeps protection.
        let effort = c
            .support
            .join("local-otel/claude-code-effort")
            .join(format!("{:x}.jsonl", Sha256::digest(COPY.as_bytes())));
        std::fs::create_dir_all(effort.parent().unwrap()).unwrap();
        std::fs::write(&effort, "").unwrap();
        let saved = serde_json::to_vec(&ledger).unwrap();
        let mut page = c.raw(&scanner, prior.clone(), 100, false, &[]);
        take_identity_counts();
        page.enrich_with(&c, Some(&mut ledger));
        let counts = serde_json::to_value(take_identity_counts()).unwrap();
        assert_eq!(
            body(&page, COPY).and_then(|copy| copy.telemetry_owned_complete),
            Some(false),
            "the half pair leaves the root unproven"
        );
        assert_eq!(identity_count(&counts, "copy_derived_proof_invalidated"), 0);
        assert_eq!(
            identity_count(&counts, "copy_derived_skipped_evidence_unavailable"),
            0
        );
        assert_eq!(
            serde_json::to_vec(&ledger).unwrap(),
            saved,
            "no second tombstone"
        );
        let copy = body(&page, COPY).unwrap();
        assert!(crate::snapshots::claude_request_money::is_request_owned_literal(copy));
        let got = rows(copy);
        assert_eq!(
            (&got[0].0, got[0].1, got[0].2, &got[0].3, got[0].4),
            (&today[0].0, today[0].1, today[0].2, &today[0].3, false),
            "the tombstoned row: same money, untagged, no marker"
        );
        assert_eq!(copy.request_identity_refusals, 1, "only B's row refuses");
        std::fs::remove_file(&effort).unwrap();
        // The invalidated row reads as never accepted: own evidence tags it fresh.
        let (copy, _) = pass(&c, &mut ledger);
        ack(&mut ledger, &copy);
        text += &switched(org_b, "");
        text += &line_by(COPY, "own-early", "2026-08-02T07:05:00Z", 10, RESUME_WRITER);
        c.write_at(&file(COPY), &text, "2026-08-02T07:03:00Z");
        let (copy, invalidated) = pass(&c, &mut ledger);
        assert_eq!(invalidated, 0);
        let row = &copy.usage_buckets[0].model_usage[0];
        assert!(row.identity_parts.is_some(), "fresh own tags");
        assert_eq!(org_shares(&copy).get(&x), None);
        // A copied marker never lent B's row, so its later change is an ordinary
        // accepted-share change.
        text += &switched(
            "33333333-3333-4333-8333-333333333333",
            "late@example.invalid",
        );
        text += &line_by(COPY, "own-late", "2026-08-02T08:20:00Z", 10, RESUME_WRITER);
        c.write_at(&file(COPY), &text, "2026-08-02T07:03:00Z");
        let mut page = c.raw(&scanner, prior.clone(), 100, false, &[]);
        take_identity_counts();
        page.enrich_with(&c, Some(&mut ledger));
        let counts = serde_json::to_value(take_identity_counts()).unwrap();
        assert_eq!(identity_count(&counts, "accepted_share_changed"), 1);
        assert_eq!(identity_count(&counts, "copy_derived_proof_invalidated"), 0);
        assert_eq!(body(&page, COPY).unwrap().request_identity_refusals, 1);
    });
}

/// [money] Money shard B1 (2026-10-31): path twins of one resumed session
/// sum into the first item's body, so a copied-marker loan recorded only by a
/// later twin (its own later turn) must reach the copy-derived selection too.
/// Copy-prefix dedupe tombstones every released row X lent, whichever twin
/// lent it. Each twin's folder holds its own accepted origin of request a,
/// another session delivered before the twins are read (a copied prefix is
/// proven only by such a holder in the copy's folder).
#[test]
fn e2_pipeline_copy_derived_rows_of_a_later_path_twin_are_invalidated() {
    with_e2(|| {
        use crate::snapshots::claude_request_identity::{take_identity_counts, AcceptedBuckets};
        let mut c = Corpus::new("e2-pipeline-copy-derived-twins");
        let scanner = E2ScanFixture::capturing_identity();
        for (folder, origin) in [("a-first", ROOT), ("z-twin", THIRD)] {
            c.write_at(
                &format!("{folder}/{origin}.jsonl"),
                &resumed(origin, &[A]),
                "2026-08-02T07:00:00Z",
            );
        }
        let old = ScanIndex::default();
        let page = ready(&c, &scanner, old.clone(), 100, false);
        let prior = settle(&c, &old, page, &mut e2_progress());
        let org_x = "11111111-1111-4111-8111-111111111111";
        let x = ottto_core::billing_identity_hash("anthropic", "organization", org_x).unwrap();
        let text = json!({"type":"attachment", "sessionId":COPY, "attachment":{
            "type":"credential_org", "organizationUuid":org_x}})
        .to_string()
            + "\n"
            + &resumed(COPY, &[A, C]);
        // The later twin alone holds an own turn in a later hour.
        c.write_at(
            &format!("a-first/{COPY}.jsonl"),
            &text,
            "2026-08-02T07:03:00Z",
        );
        let later = text + &line_by(COPY, "own-late", "2026-08-02T09:10:00Z", 10, RESUME_WRITER);
        c.write_at(
            &format!("z-twin/{COPY}.jsonl"),
            &later,
            "2026-08-02T07:03:00Z",
        );
        let stored = released("twins.copy");
        let buckets = stored["usage_buckets"].as_array().unwrap();
        assert_eq!(buckets.len(), 2, "both twins' hours are summed");
        assert!(
            buckets.iter().all(|bucket| bucket["model_usage"]
                .as_array()
                .unwrap()
                .iter()
                .any(|row| !row["evidence_ref"].is_null() || !row["identity_parts"].is_null())),
            "the released body froze both hours under X"
        );
        assert!(org_shares(&stored).contains_key(&x));
        let mut ledger = AcceptedBuckets::for_test();
        ledger.record(&stored);
        assert_eq!(
            serde_json::to_value(&ledger).unwrap(),
            released("twins.ledger.retained-false"),
            "the released body yields the released ledger"
        );
        let mut page = c.raw(&scanner, prior.clone(), 100, false, &[]);
        take_identity_counts();
        page.enrich_with(&c, Some(&mut ledger));
        let paths = scanner.paths();
        assert!(paths
            .iter()
            .any(|path| path.ends_with(format!("z-twin/{COPY}.jsonl"))));
        let counts = serde_json::to_value(take_identity_counts()).unwrap();
        let copy = body(&page, COPY).expect("the own turns publish");
        assert_eq!(
            identity_count(&counts, "copy_derived_proof_invalidated"),
            2,
            "one tombstone per X row, the later twin's hour included"
        );
        assert_eq!(copy.request_identity_refusals, 0, "never a refusal");
        assert_eq!(org_shares(copy).get(&x), None);
    });
}

/// [regress] A row frozen from the corrected
/// (deduped) body holds the lent request's own share beside an own-proved
/// copy of the lent org. A later own change there keeps accepted-share protection;
/// it is never read as copy-derived.
#[test]
fn e2_pipeline_corrected_body_freeze_is_not_copy_derived() {
    with_e2(|| {
        use crate::snapshots::claude_request_identity::{take_identity_counts, AcceptedBuckets};
        let mut c = Corpus::new("e2-pipeline-corrected-freeze");
        let scanner = E2ScanFixture::capturing_identity();
        c.root(ROOT, &resumed(ROOT, &[A]));
        let old = ScanIndex::default();
        let page = ready(&c, &scanner, old.clone(), 100, false);
        let prior = settle(&c, &old, page, &mut e2_progress());
        let marker = |org: &str| {
            json!({"type":"attachment", "sessionId":COPY,
            "attachment":{"type":"credential_org","organizationUuid":org}})
            .to_string()
                + "\n"
        };
        let org_x = "11111111-1111-4111-8111-111111111111";
        // The copied marker lent X to C; an own marker proves X in C's row.
        let mut text = marker(org_x)
            + &resumed(COPY, &[A, C])
            + &marker(org_x)
            + &line_by(COPY, "own-x", "2026-08-02T07:30:00Z", 10, RESUME_WRITER);
        c.write_at(&file(COPY), &text, "2026-08-02T07:03:00Z");
        let corrected = ready(&c, &scanner, prior.clone(), 100, false);
        let stored = body(&corrected, COPY).unwrap();
        assert!(
            stored.usage_buckets[0].model_usage[0]
                .identity_parts
                .is_some(),
            "{{C, X}}"
        );
        let mut ledger = AcceptedBuckets::for_test();
        ledger.record(&serde_json::to_value(stored).unwrap());
        text += &(json!({"type":"attachment", "sessionId":COPY,
            "attachment":{"type":"session_context", "context":{}}})
        .to_string()
            + "\n");
        text += &marker("22222222-2222-4222-8222-222222222222");
        text += &line_by(COPY, "own-b", "2026-08-02T07:40:00Z", 10, RESUME_WRITER);
        c.write_at(&file(COPY), &text, "2026-08-02T07:03:00Z");
        let mut page = c.raw(&scanner, prior.clone(), 100, false, &[]);
        take_identity_counts();
        page.enrich_with(&c, Some(&mut ledger));
        let counts = serde_json::to_value(take_identity_counts()).unwrap();
        assert_eq!(identity_count(&counts, "accepted_share_changed"), 1);
        assert_eq!(identity_count(&counts, "copy_derived_proof_invalidated"), 0);
        assert_eq!(
            identity_count(&counts, "copy_derived_mixed_not_invalidated"),
            1
        );
        assert_eq!(body(&page, COPY).unwrap().request_identity_refusals, 1);
    });
}

/// [money] A row frozen {X} by a copied marker is not tombstoned while this
/// pass cannot read the session's own evidence (a partial telemetry sidecar
/// pair).
/// Accepted-share protection stays and is counted. Money and account stay unchanged.
/// The unhealthy root's no-fallback branch leaves every
/// loan unread, so the row is skipped, never tombstoned.
#[test]
fn e2_pipeline_copy_derived_row_is_kept_while_own_evidence_is_unreadable() {
    with_e2(|| {
        use crate::snapshots::claude_request_identity::{take_identity_counts, AcceptedBuckets};
        let mut c = Corpus::new("e2-pipeline-copy-derived-unread");
        let scanner = E2ScanFixture::capturing_identity();
        c.root(ROOT, &resumed(ROOT, &[A]));
        let old = ScanIndex::default();
        let page = ready(&c, &scanner, old.clone(), 100, false);
        let prior = settle(&c, &old, page, &mut e2_progress());
        let b = ottto_core::billing_identity_hash(
            "anthropic",
            "organization",
            "22222222-2222-4222-8222-222222222222",
        )
        .unwrap();
        let marker = json!({"type":"attachment", "sessionId":COPY, "attachment":{
            "type":"credential_org", "organizationUuid":"11111111-1111-4111-8111-111111111111"}});
        c.write_at(
            &file(COPY),
            &(marker.to_string() + "\n" + &resumed(COPY, &[A, C])),
            "2026-08-02T07:03:00Z",
        );
        let stored = released("unread.copy");
        let mut ledger = AcceptedBuckets::for_test();
        ledger.record(&stored);
        // One sidecar of the pair: this root's telemetry read is incomplete.
        let effort = c
            .support
            .join("local-otel/claude-code-effort")
            .join(format!("{:x}.jsonl", Sha256::digest(COPY.as_bytes())));
        std::fs::create_dir_all(effort.parent().unwrap()).unwrap();
        std::fs::write(&effort, "").unwrap();
        let saved = serde_json::to_vec(&ledger).unwrap();
        let mut page = c.raw(&scanner, prior.clone(), 100, false, &[]);
        take_identity_counts();
        page.enrich_with(&c, Some(&mut ledger));
        let counts = serde_json::to_value(take_identity_counts()).unwrap();
        // The half pair leaves the root's evidence unavailable.
        assert_eq!(
            identity_count(&counts, "copy_derived_skipped_evidence_unavailable"),
            1
        );
        assert_eq!(identity_count(&counts, "copy_derived_proof_invalidated"), 0);
        assert_eq!(serde_json::to_vec(&ledger).unwrap(), saved, "no tombstone");
        if let Some(copy) = body(&page, COPY) {
            assert!(copy.request_identity_refusals > 0, "protection kept");
            assert_eq!(
                (copy.request_count, copy.removed_request_count),
                (1, Some(1))
            );
            assert_eq!(org_shares(copy).get(&b), None);
        } else {
            // Held for unread telemetry: no upload carries this session, so
            // the stored body stays byte-for-byte the last ACKed one.
            page.finish();
            let (result, sent, order) = upload(&page.scan.snapshots, &mut e2_progress(), ack);
            result.unwrap();
            assert!(order.iter().flatten().all(|session| session != COPY));
            assert!(sent
                .iter()
                .all(|wire| !String::from_utf8_lossy(wire).contains(COPY)));
        }
    });
}

/// Declared copied-prefix removals publish through the accepted bucket
/// reconciliation without holding the whole session.
#[test]
fn e2_pipeline_declared_prefix_removal_over_accepted_buckets_publishes() {
    for accepted in [false, true] {
        with_e2(|| {
            let mut c = Corpus::new("e2-pipeline-accepted-prefix-hold");
            c.root(ROOT, &resumed(ROOT, &[A, B]));
            // Tagged, so the stored body's buckets enter the accepted-share hints.
            let scanner = E2ScanFixture::capturing_identity();
            let mut progress = e2_progress();
            let old = ScanIndex::default();
            let original = ready(&c, &scanner, old.clone(), 100, false);
            let mut prior = settle(&c, &old, original, &mut progress);
            let marker = json!({"type":"attachment", "sessionId":COPY, "attachment":{
                "type":"credential_org", "organizationUuid":"11111111-1111-4111-8111-111111111111"}});
            c.write_at(
                &file(COPY),
                &(marker.to_string() + "\n" + &resumed(COPY, &[A, B, C])),
                "2026-08-02T07:03:00Z",
            );
            let mut ledger = crate::snapshots::claude_request_identity::AcceptedBuckets::for_test();
            if accepted {
                let stored = released("accepted-hold.copy");
                assert_eq!(
                    stored["request_count"], 3,
                    "the released body stored the prefix with the own turn"
                );
                ledger.record(&stored);
                assert_eq!(
                    serde_json::to_value(&ledger).unwrap(),
                    released("accepted-hold.ledger")
                );
                assert!(ledger.may_have_accepted(
                    COPY,
                    stored["usage_buckets"][0]["bucket_start"].as_str().unwrap()
                ));
            }
            let mut expected = serde_json::to_value(&ledger).unwrap();
            if accepted {
                let sessions = expected.as_object_mut().unwrap();
                assert_eq!(sessions.len(), 1, "one accepted copy session");
                let session = sessions.values_mut().next().unwrap();
                assert_eq!(session["shares"].as_array().unwrap().len(), 1);
                // The declared replacement invalidates this old copy-derived
                // share. Every other accepted-ledger field stays identical.
                session["shares"] = json!([]);
            }
            let mut page = c.raw(&scanner, prior.clone(), 100, false, &[]);
            page.enrich_with(&c, Some(&mut ledger));
            let copy = body(&page, COPY)
                .expect("declared removals publish without an accepted-prefix hold");
            assert_eq!(
                (copy.request_count, copy.removed_request_count),
                (1, Some(2))
            );
            assert_eq!(
                copy.input_tokens + copy.removed_usage.as_ref().unwrap().input_tokens,
                30
            );
            prior = settle(&c, &prior, page, &mut progress);
            let quiet = ready(&c, &scanner, prior, 100, false);
            assert!(body(&quiet, COPY).is_none());
            assert_eq!(serde_json::to_value(&ledger).unwrap(), expected);
        });
    }
}

/// An empty removal store is not written, and its restart is not
/// lost metadata; damaged metadata is lost, and survives the restart.
#[test]
fn e2_pipeline_empty_removal_store_restart_is_not_lost_metadata_but_damage_is() {
    for damaged in [false, true] {
        with_e2(|| {
            let mut c = Corpus::new("e2-pipeline-empty-removal-store");
            c.root(ROOT, &resumed(ROOT, &[A, B]));
            let old = ScanIndex::default();
            let original = ready(&c, &E2ScanFixture::default(), old.clone(), 100, false);
            let prior = settle(&c, &old, original, &mut e2_progress());
            let mut encoded = serde_json::to_value(&prior).unwrap();
            assert!(
                encoded.get("claude_copy_removals").is_none(),
                "an empty store is not written"
            );
            if damaged {
                encoded["claude_copy_removals"] = json!("damaged");
            }
            let mut prior: ScanIndex = serde_json::from_value(encoded).unwrap();
            prior = c.reload(&mut prior); // both native and streaming decode
            assert_eq!(prior.claude_copy_removals.metadata_lost(), damaged);
            let written = serde_json::to_value(&prior)
                .unwrap()
                .get("claude_copy_removals")
                .is_some();
            assert_eq!(written, damaged, "only damage is written back");
        });
    }
}

/// Holders whose transcripts left the index cannot disprove a
/// recorded removal. The resumed file's re-read keeps its copies removed,
/// counted, and the decision stays recorded.
#[test]
fn e2_pipeline_recorded_removal_stands_when_its_holder_leaves_the_index() {
    with_e2(|| {
        use crate::snapshots::claude_money_birth_store::location_key;
        let mut c = Corpus::new("e2-pipeline-copy-holder-absent");
        let mut progress = e2_progress();
        let mut prior = demo_family(&mut c, &mut progress);
        for holder in [ROOT, COPY] {
            std::fs::remove_file(c.root.join(file(holder))).unwrap();
            e2::pipeline_test_observer::forget_file(&mut prior, &file(holder));
        }
        let key = location_key(&c.root.join(file(THIRD)).to_string_lossy());
        let recorded = prior.claude_copy_removals.get(key).to_vec();
        assert_eq!(
            recorded
                .iter()
                .map(|(_, hashes)| hashes.len())
                .sum::<usize>(),
            3
        );
        append(
            &c.root.join(file(THIRD)),
            &line_by(THIRD, "e", "2026-08-02T07:06:20Z", 10, RESUME_WRITER),
        );
        e2::take_diag();
        let page = ready(&c, &E2ScanFixture::default(), prior.clone(), 100, false);
        literal(&page);
        let third = body(&page, THIRD).expect("the grown resume publishes");
        assert_eq!(
            (third.request_count, third.removed_request_count),
            (2, Some(3)),
            "holder absence never re-adds a recorded copy"
        );
        assert_eq!(
            copy_diag(&[
                "copy_removal_holder_absent_kept",
                "copy_prefix_unproven",
                "copy_removal_reused"
            ]),
            [3, 0, 3]
        );
        let settled = settle(&c, &prior, page, &mut progress);
        assert_eq!(settled.claude_copy_removals.get(key), recorded.as_slice());
    });
}

mod desktop_depth_tests;
mod late_member_side_calls_tests {
    include!("late_member_side_calls_tests.rs");
}

mod copied_session_file_tests;

// ---- Recency tiers: Claude copy holders read in tiers ----

/// The fixture's census end; tier bounds and file ages count back from it.
const TIER_CENSUS: &str = "2026-08-02T08:00:00Z";
const OLD_AT: &str = "2026-07-02T07:00:10Z";

fn census_minus(days: u64) -> u64 {
    crate::snapshots::rfc3339_unix_seconds(TIER_CENSUS).unwrap() - days * 86_400
}

fn tier_bounds() -> Vec<u64> {
    [1, 3, 7, 14, 30].map(census_minus).to_vec()
}

/// Write `contents` born at `birth`, last modified `days` before the census.
fn write_aged(c: &mut Corpus, relative: &str, contents: &str, birth: &str, days: u64) -> PathBuf {
    let path = c.write_at(relative, contents, birth);
    std::fs::File::options()
        .write(true)
        .open(&path)
        .unwrap()
        .set_modified(std::time::UNIX_EPOCH + std::time::Duration::from_secs(census_minus(days)))
        .unwrap();
    path
}

/// How a tiered first read is broken or answered.
#[derive(Clone, Copy, Default)]
struct TierRun {
    /// The first upload of the page that reads this file is lost before any
    /// reply: nothing commits, the ledger keeps the send pending and the
    /// next pass reads and settles it again.
    lost_upload_of: Option<&'static str>,
    /// A daemon restart from the saved store right after that loss.
    restart_on_loss: bool,
    /// The server answers this session `unchanged` (`usage_identical`).
    not_stored: Option<&'static str>,
    /// This file is removed after the first page.
    removed: Option<&'static str>,
    /// Files per page (zero: one).
    page_files: usize,
    /// The tiers come from this destination's saved tier state, as prepare
    /// and finish keep it, instead of `tiers`.
    destination: Option<&'static str>,
    /// This file (same path, birth and mtime) appears only once the first
    /// read has completed, so a later pass reads it.
    late: Option<&'static str>,
}

struct TieredRead {
    index: ScanIndex,
    scan: SourceScanResult,
    /// Each page's tier bound and the files it read.
    pages: Vec<(Option<u64>, Vec<PathBuf>)>,
    /// The server's latest accepted body per session after each page.
    stored: Vec<BTreeMap<String, SnapshotItem>>,
    /// With a `destination`, before each page: its tier days, the tier
    /// Claude finished itself and the `tier_ready_cutoff` it would report.
    claims: Vec<(u64, Option<u64>, Option<String>)>,
}

/// One first read to its end, `page_files` per page, each page uploaded,
/// settled and reloaded as the daemon does. Each bound in `tiers` gates the
/// read until the settled index finishes the tier (as finish records it),
/// then the next applies. The census completing ends the import and so its
/// tiers, as bootstrap completion does; four more passes follow. The server
/// keeps each session's latest accepted body, recorded from its reply.
fn tiered_read(c: &Corpus, tiers: &[u64], run: TierRun) -> TieredRead {
    tiered_read_from(c, tiers, run, ScanIndex::default())
}

/// `tiered_read` from a committed index `start` (an earlier read's), to a
/// destination whose server holds nothing yet.
fn tiered_read_from(c: &Corpus, tiers: &[u64], run: TierRun, start: ScanIndex) -> TieredRead {
    let scanner = E2ScanFixture::default();
    let hidden = c.base.join("late-file");
    if let Some(relative) = run.late {
        std::fs::rename(c.root.join(relative), &hidden).unwrap();
    }
    let claude = SnapshotSource::ClaudeCode;
    let state = || crate::backfill::load_backfill_state(&c.support);
    let bound = |destination: &str| {
        state()
            .first_read_tier(destination, claude)
            .map(|(_, bound)| bound)
    };
    let mut tiers = tiers.iter().copied();
    let mut cutoff = match run.destination {
        Some(destination) => {
            crate::backfill::record_first_census(
                &c.support,
                claude,
                destination,
                TIER_CENSUS,
                true,
            )
            .unwrap();
            bound(destination)
        }
        None => tiers.next(),
    };
    let mut claims = Vec::new();
    let mut committed = start;
    let mut progress = e2_progress();
    let mut latest = BTreeMap::new();
    let mut pages = Vec::new();
    let mut stored = Vec::new();
    let mut last = None;
    let mut lost = false;
    let mut completed = false;
    let mut quiet = 0;
    for n in 0..64 {
        if let Some(destination) = run.destination {
            let state = state();
            let tier = &state.first_read_tiers[destination];
            claims.push((
                tier.days,
                tier.finished.get(claude.api_slug()).copied(),
                state.first_read_cutoffs(destination, claude.api_slug()).1,
            ));
        }
        let mut index = committed.clone();
        index.first_read_tier_cutoff = cutoff;
        let mut page = ready(c, &scanner, index, run.page_files.max(1), true);
        let paths = scanner.paths();
        pages.push((cutoff, paths.clone()));
        if n == 0 {
            if let Some(relative) = run.removed {
                std::fs::remove_file(c.root.join(relative)).unwrap();
            }
        }
        if !lost
            && run
                .lost_upload_of
                .is_some_and(|file| paths.iter().any(|path| path.ends_with(file)))
        {
            lost = true;
            page.finish();
            let (result, _, _) = upload(&page.scan.snapshots, &mut progress, |_| {
                Err(anyhow!("synthetic connection reset before any reply"))
            });
            assert!(result.is_err());
            stored.push(latest.clone());
            drop(page);
            if run.restart_on_loss && n > 0 {
                committed = cold_restart(committed);
            }
            continue;
        }
        let complete = page.scan.census_complete;
        let sent = {
            let mut sent = twin(&page);
            sent.finish();
            sent.scan
        };
        let (settled, accepted) =
            settle_answering(c, &committed, page, &mut progress, run.not_stored);
        committed = settled;
        for item in accepted {
            latest.insert(item.source_session_id.clone(), item);
        }
        stored.push(latest.clone());
        last = Some(sent);
        committed.first_read_tier_cutoff = cutoff;
        if complete {
            if !completed {
                if let Some(relative) = run.late {
                    std::fs::rename(&hidden, c.root.join(relative)).unwrap();
                }
            }
            completed = true;
            cutoff = None;
        } else if cutoff.is_some()
            && committed.first_read_tier_finished(SnapshotSource::ClaudeCode, |_| None)
        {
            cutoff = match run.destination {
                Some(destination) => {
                    crate::backfill::record_first_read_tier_pass(
                        &c.support,
                        claude,
                        destination,
                        &[claude],
                    )
                    .unwrap();
                    bound(destination)
                }
                None => tiers.next(),
            };
        }
        committed.first_read_tier_cutoff = None;
        // A holder's save may mark a copy's correction for a later pass, so
        // a few passes follow the census.
        if completed {
            quiet += 1;
            if quiet > 4 {
                break;
            }
        }
    }
    let mut scan = last.expect("a page was sent");
    assert!(completed, "first read finished: {pages:?}");
    let mut bodies = BTreeSet::new();
    scan.snapshots = latest
        .into_values()
        .filter(|item| bodies.insert(item.snapshot_fingerprint.clone()))
        .collect();
    TieredRead {
        index: committed,
        scan,
        pages,
        stored,
        claims,
    }
}

/// `settle`, with `not_stored`'s bodies answered `unchanged`
/// (`usage_identical`). Returns the settled index and the bodies the server
/// accepted.
fn settle_answering(
    c: &Corpus,
    committed: &ScanIndex,
    mut page: Page,
    progress: &mut SnapshotUploadProgress,
    not_stored: Option<&str>,
) -> (ScanIndex, Vec<SnapshotItem>) {
    page.finish();
    let sent = page.scan.snapshots.clone();
    let mut stored = BTreeSet::new();
    upload(&sent, progress, |batch| {
        let mut response = ack(batch)?;
        let (unchanged, accepted) = std::mem::take(&mut response.accepted_entities)
            .into_iter()
            .partition::<Vec<_>, _>(|entity| Some(entity.source_session_id.as_str()) == not_stored);
        stored.extend(
            accepted
                .iter()
                .map(|entity| entity.snapshot_fingerprint.clone()),
        );
        response.accepted_entities = accepted;
        for mut entity in unchanged {
            entity.unchanged_basis = Some("usage_identical".into());
            response.unchanged_entities.push(entity);
        }
        Ok(response)
    })
    .0
    .unwrap();
    let holds = LocalHoldSettlement::classify(
        SnapshotSource::ClaudeCode,
        &mut page.index,
        &mut page.scan,
        &page.disposition,
    );
    let mut settled = settle_completed_upload(page.index, committed, progress, &holds);
    settle_index_after_upload(&mut settled.index, committed, progress);
    // The production order after save selection, with the claim cutoff's
    // corrections.
    finish_selected_settlement(
        &mut settled.index,
        SelectedSettlementInputs {
            scan: &page.scan,
            committed_index: committed,
            progress,
            candidates: &[],
            cutoff_candidates: &page.cutoff_candidates,
            transport_fully_settled: settled.fully_settled,
            body_drains: Default::default(),
            audit_release: None,
        },
    );
    accept_upload_context_acks_for_test(
        &mut settled.index,
        &sent,
        &progress.fresh_context_body_acks,
    );
    let accepted = sent
        .into_iter()
        .filter(|item| stored.contains(&item.snapshot_fingerprint))
        .collect();
    (c.reload_in(&mut settled.index, "scan-index.json"), accepted)
}

/// The tier bound of the page that read `file`.
fn read_under(read: &TieredRead, file: &str) -> Option<Option<u64>> {
    read.pages
        .iter()
        .find(|(_, paths)| paths.iter().any(|path| path.ends_with(file)))
        .map(|(cutoff, _)| *cutoff)
}

/// The final state of a tiered read equals the untiered read's (after the
/// existing reconcile), in money, receipts, ownership and placement.
fn assert_tiered_equals_untiered(name: &str, untiered: &TieredRead, tiered: &TieredRead) {
    use crate::snapshots::sampled_scan::transition_fixture::{money_oracle, scan_money};
    let requests = |read: &TieredRead| {
        read.scan
            .snapshots
            .iter()
            .map(|item| (item.source_session_id.clone(), item.request_count))
            .collect::<BTreeMap<_, _>>()
    };
    assert_eq!(
        requests(untiered),
        requests(tiered),
        "{name}: requests per session; untiered pages {:?}; tiered pages {:?}",
        untiered.pages,
        tiered.pages
    );
    let buckets = |read: &TieredRead| {
        read.scan
            .snapshots
            .iter()
            .map(|item| {
                (
                    item.source_session_id.clone(),
                    serde_json::to_value(&item.usage_buckets).unwrap(),
                )
            })
            .collect::<BTreeMap<_, _>>()
    };
    assert_eq!(
        buckets(untiered),
        buckets(tiered),
        "{name}: accepted buckets per session"
    );
    assert_eq!(
        e2::pipeline_test_observer::durable_ownership(&untiered.index),
        e2::pipeline_test_observer::durable_ownership(&tiered.index),
        "{name}: durable copy ownership and upload eligibility per file"
    );
    let source = SnapshotSource::ClaudeCode;
    let cold = scan_money(source, &untiered.index, &untiered.scan);
    let other = scan_money(source, &tiered.index, &tiered.scan);
    money_oracle::assert_equivalent(&cold, &other);
    money_oracle::assert_no_smaller_reemit(name, &cold, &other, &cold, false);
}

/// A holder (20 days old) and its copy (new) in one folder: the copy's own
/// line and the copied one, born after the copied line.
fn holder_and_copy(c: &mut Corpus, copy_folder: &str) {
    write_aged(
        c,
        &format!("{ROOT}.jsonl"),
        &line(ROOT, "original", OLD_AT, 10),
        "2026-07-02T07:00:00Z",
        20,
    );
    c.write_at(
        &format!("{copy_folder}{COPY}.jsonl"),
        &(line(COPY, "original", OLD_AT, 10) + &line(COPY, "own", AT, 20)),
        "2026-08-02T07:00:00Z",
    );
}

/// [money] The copy is read first in the 1-day tier with its holder unread:
/// it counts and discloses the copied prefix, which pulls the 20-day holder
/// into the same tier; once the holder is accepted the save-time re-decide
/// removes the prefix from the copy. The final state equals the untiered read.
#[test]
fn e2_tier_pulls_the_copy_holder_into_tier_one() {
    with_e2(|| {
        let mut c = Corpus::new("e2-tier-holder-pulled");
        holder_and_copy(&mut c, "");
        let untiered = tiered_read(&c, &[], TierRun::default());
        let tiered = tiered_read(&c, &tier_bounds(), TierRun::default());
        let copy = format!("{COPY}.jsonl");
        let holder = format!("{ROOT}.jsonl");
        let page_of = |file: &str| {
            tiered
                .pages
                .iter()
                .position(|(_, paths)| paths.iter().any(|path| path.ends_with(file)))
        };
        assert!(
            page_of(&copy) < page_of(&holder),
            "the copy is read before its holder: {:?}",
            tiered.pages
        );
        assert_eq!(
            read_under(&tiered, &holder),
            Some(Some(tier_bounds()[0])),
            "the holder is pulled into the 1-day tier: {:?}",
            tiered.pages
        );
        assert_tiered_equals_untiered("holder-pulled", &untiered, &tiered);
    });
}

/// [money] A chain of two holders (40 and 20 days old) and a new copy of the
/// copy, in one folder: the new copy pulls both; the final state equals the
/// untiered read.
#[test]
fn e2_tier_pulls_a_chain_of_two_holders() {
    with_e2(|| {
        let mut c = Corpus::new("e2-tier-holder-chain");
        let first = line(ROOT, "r1", "2026-06-20T07:00:10Z", 10);
        write_aged(&mut c, &format!("{ROOT}.jsonl"), &first, "2026-06-20T07:00:00Z", 40);
        let second = line(COPY, "r1", "2026-06-20T07:00:10Z", 10)
            + &line(COPY, "r2", OLD_AT, 20);
        write_aged(&mut c, &format!("{COPY}.jsonl"), &second, "2026-07-02T07:00:00Z", 20);
        c.write_at(
            &format!("{THIRD}.jsonl"),
            &(line(THIRD, "r1", "2026-06-20T07:00:10Z", 10)
                + &line(THIRD, "r2", OLD_AT, 20)
                + &line(THIRD, "r3", AT, 30)),
            "2026-08-02T07:00:00Z",
        );
        let untiered = tiered_read(&c, &[], TierRun::default());
        let tiered = tiered_read(&c, &tier_bounds(), TierRun::default());
        for holder in [ROOT, COPY] {
            assert_eq!(
                read_under(&tiered, &format!("{holder}.jsonl")),
                Some(Some(tier_bounds()[0])),
                "{holder} is pulled into the 1-day tier: {:?}",
                tiered.pages
            );
        }
        assert_tiered_equals_untiered("holder-chain", &untiered, &tiered);
    });
}

/// [money] The holder is listed, then removed before any read: the copy
/// counts the copied request once and discloses it (`copy_unproven` route),
/// the removed holder takes its removal route and the tiers still finish.
/// The final state equals an untiered read of the copy alone (same files).
#[test]
fn e2_tier_holder_gone_keeps_the_copy_count_and_finishes() {
    with_e2(|| {
        let mut c = Corpus::new("e2-tier-holder-gone");
        holder_and_copy(&mut c, "");
        let removed = Box::leak(format!("{ROOT}.jsonl").into_boxed_str());
        let tiered = tiered_read(
            &c,
            &tier_bounds(),
            TierRun {
                removed: Some(removed),
                ..TierRun::default()
            },
        );
        assert!(
            e2::pipeline_test_observer::disclosed(&tiered.scan.snapshots) > 0,
            "the copy discloses its unproven prefix"
        );
        let untiered = tiered_read(&c, &[], TierRun::default());
        assert_tiered_equals_untiered("holder-gone", &untiered, &tiered);
    });
}

/// [money] The holder's body is answered `unchanged` (`usage_identical`, no
/// stored body) in both reads: the final state equals the untiered read.
#[test]
fn e2_tier_not_stored_holder_matches_untiered() {
    with_e2(|| {
        let mut c = Corpus::new("e2-tier-holder-not-stored");
        holder_and_copy(&mut c, "");
        let run = TierRun {
            not_stored: Some(ROOT),
            ..TierRun::default()
        };
        let untiered = tiered_read(&c, &[], run);
        let tiered = tiered_read(&c, &tier_bounds(), run);
        assert_tiered_equals_untiered("holder-not-stored", &untiered, &tiered);
    });
}

/// [money] A `/branch` fork in another folder, its `fork-context-ref` line
/// naming the parent: the parent is not pulled; it is read in its own
/// (30-day) tier, after the fork. The final state equals the untiered read.
#[test]
fn e2_tier_fork_parent_in_another_folder_settles_by_redecide() {
    with_e2(|| {
        let mut c = Corpus::new("e2-tier-fork-parent");
        write_aged(
            &mut c,
            &format!("{ROOT}.jsonl"),
            &line(ROOT, "original", OLD_AT, 10),
            "2026-07-02T07:00:00Z",
            20,
        );
        c.write_at(
            &format!("fork/{COPY}.jsonl"),
            &(fork_ref(COPY, ROOT)
                + &line(COPY, "original", OLD_AT, 10)
                + &line(COPY, "own", AT, 20)),
            "2026-08-02T07:00:00Z",
        );
        let untiered = tiered_read(&c, &[], TierRun::default());
        let tiered = tiered_read(&c, &tier_bounds(), TierRun::default());
        assert_eq!(
            read_under(&tiered, &format!("{ROOT}.jsonl")),
            Some(Some(tier_bounds()[4])),
            "the parent waits for its own tier: {:?}",
            tiered.pages
        );
        assert_tiered_equals_untiered("fork-parent", &untiered, &tiered);
    });
}

/// [money] The upload of the page that reads the pulled holder fails before
/// any reply (the ledger keeps it pending), and the daemon restarts from the
/// saved store before the next pass, which reads and settles it again. The
/// final state equals the untiered read.
#[test]
fn e2_tier_pending_retry_and_restart_match_untiered() {
    with_e2(|| {
        let mut c = Corpus::new("e2-tier-retry-restart");
        holder_and_copy(&mut c, "");
        let untiered = tiered_read(&c, &[], TierRun::default());
        let holder: &'static str = Box::leak(format!("{ROOT}.jsonl").into_boxed_str());
        let tiered = tiered_read(
            &c,
            &tier_bounds(),
            TierRun {
                lost_upload_of: Some(holder),
                restart_on_loss: true,
                ..TierRun::default()
            },
        );
        assert!(
            tiered
                .pages
                .iter()
                .filter(|(_, paths)| paths.iter().any(|path| path.ends_with(holder)))
                .count()
                >= 2,
            "the holder is read again after the loss: {:?}",
            tiered.pages
        );
        assert_tiered_equals_untiered("retry-restart", &untiered, &tiered);
    });
}

/// [money] The upload of the copy's own first page fails before any reply:
/// nothing commits and the next pass reads the copy again. The final state
/// equals the untiered read.
#[test]
fn e2_tier_lost_upload_on_the_copy_page_matches_untiered() {
    with_e2(|| {
        let mut c = Corpus::new("e2-tier-lost-copy-page");
        holder_and_copy(&mut c, "");
        let untiered = tiered_read(&c, &[], TierRun::default());
        let copy: &'static str = Box::leak(format!("{COPY}.jsonl").into_boxed_str());
        let tiered = tiered_read(
            &c,
            &tier_bounds(),
            TierRun {
                lost_upload_of: Some(copy),
                ..TierRun::default()
            },
        );
        assert_tiered_equals_untiered("lost-copy-page", &untiered, &tiered);
    });
}

/// [money] Pages of two files. Untiered, the holder and its copy share the
/// first page, so the copy's first body already removes the copied prefix.
/// Tiered, the copy is read alone in the 1-day tier and its first body
/// counts and discloses the prefix (pinned: the one difference). The page
/// that reads the pulled holder re-reads the copy, so the server never holds
/// the holder beside an uncorrected copy. The final state equals the
/// untiered read.
#[test]
fn e2_tier_holder_page_rereads_its_copy() {
    with_e2(|| {
        let mut c = Corpus::new("e2-tier-holder-page-copy");
        holder_and_copy(&mut c, "");
        let run = TierRun {
            page_files: 2,
            ..TierRun::default()
        };
        let untiered = tiered_read(&c, &[], run);
        let tiered = tiered_read(&c, &tier_bounds(), run);
        let removed = |read: &TieredRead, at: usize| {
            read.stored[at]
                .get(COPY)
                .map(|copy| copy.removed_request_count)
        };
        let first_with = |read: &TieredRead, session: &str| {
            (0..read.stored.len())
                .find(|&at| read.stored[at].contains_key(session))
                .expect("stored")
        };
        assert_eq!(
            removed(&untiered, first_with(&untiered, COPY)),
            Some(Some(1)),
            "untiered: the copy's first body removes the prefix: {:?}",
            untiered.pages
        );
        assert_eq!(
            removed(&tiered, first_with(&tiered, COPY)),
            Some(Some(0)),
            "tiered: the copy's first body counts and discloses it: {:?}",
            tiered.pages
        );
        let holder_page = first_with(&tiered, ROOT);
        for at in holder_page..tiered.stored.len() {
            assert_eq!(
                removed(&tiered, at),
                Some(Some(1)),
                "after the holder's page the copy is corrected: {:?}",
                tiered.pages
            );
        }
        assert_tiered_equals_untiered("holder-page-copy", &untiered, &tiered);
    });
}

/// [money] A chain whose middle holder sits in another folder: the new copy
/// pulls the 40-day holder of its folder; the middle one (20 days, another
/// folder) waits for its own tier. The final state equals the untiered read.
#[test]
fn e2_tier_chain_with_its_middle_holder_in_another_folder() {
    with_e2(|| {
        let mut c = Corpus::new("e2-tier-chain-middle-elsewhere");
        let first = line(ROOT, "r1", "2026-06-20T07:00:10Z", 10);
        write_aged(&mut c, &format!("{ROOT}.jsonl"), &first, "2026-06-20T07:00:00Z", 40);
        let second = line(COPY, "r1", "2026-06-20T07:00:10Z", 10)
            + &line(COPY, "r2", OLD_AT, 20);
        write_aged(&mut c, &format!("mid/{COPY}.jsonl"), &second, "2026-07-02T07:00:00Z", 20);
        c.write_at(
            &format!("{THIRD}.jsonl"),
            &(line(THIRD, "r1", "2026-06-20T07:00:10Z", 10)
                + &line(THIRD, "r2", OLD_AT, 20)
                + &line(THIRD, "r3", AT, 30)),
            "2026-08-02T07:00:00Z",
        );
        let untiered = tiered_read(&c, &[], TierRun::default());
        let tiered = tiered_read(&c, &tier_bounds(), TierRun::default());
        assert_eq!(
            read_under(&tiered, &format!("{ROOT}.jsonl")),
            Some(Some(tier_bounds()[0])),
            "the folder's holder is pulled: {:?}",
            tiered.pages
        );
        assert_tiered_equals_untiered("chain-middle-elsewhere", &untiered, &tiered);
    });
}

/// [money] The pulled holder has a path twin (same session, 20 days old) in
/// another folder: the twin is admitted with the holder's family, so both
/// are read in the 1-day tier. The final state equals the untiered read.
#[test]
fn e2_tier_pulled_holder_brings_its_path_twin() {
    with_e2(|| {
        let mut c = Corpus::new("e2-tier-pulled-holder-twin");
        holder_and_copy(&mut c, "");
        write_aged(
            &mut c,
            &format!("x/{ROOT}.jsonl"),
            &line(ROOT, "original", OLD_AT, 10),
            "2026-07-02T07:00:00Z",
            20,
        );
        let untiered = tiered_read(&c, &[], TierRun::default());
        let tiered = tiered_read(&c, &tier_bounds(), TierRun::default());
        assert_eq!(
            read_under(&tiered, &format!("x/{ROOT}.jsonl")),
            Some(Some(tier_bounds()[0])),
            "the twin comes with the pulled holder's family: {:?}",
            tiered.pages
        );
        assert_tiered_equals_untiered("pulled-holder-twin", &untiered, &tiered);
    });
}

/// A claim cutoff between the holder's line (`OLD_AT`) and its copy's own
/// line (`AT`).
const SWITCH_CUTOFF: &str = "2026-07-15T00:00:00Z";

/// When a body's session activity ended, as the claim cutoff reads it.
fn activity_ended(item: &SnapshotItem) -> Option<u64> {
    [
        &item.source_last_activity_at,
        &item.source_ended_at,
        &item.source_started_at,
    ]
    .into_iter()
    .flatten()
    .filter_map(|at| crate::snapshots::rfc3339_unix_seconds(at))
    .max()
}

/// Claim completion for `destination`: `policy` with `cutoff`, for `user`,
/// recorded before its bootstrap.
fn claim(c: &Corpus, policy: &str, cutoff: Option<&str>, user: &str, destination: &str) {
    crate::backfill::apply_claim_backfill_policy_for_destination(
        &c.support,
        Some(policy),
        cutoff,
        user,
        Some(destination),
    )
    .unwrap();
}

/// The server's latest accepted body of `session` once the read ends.
fn latest_of<'a>(read: &'a TieredRead, session: &str) -> Option<&'a SnapshotItem> {
    read.stored.last().and_then(|stored| stored.get(session))
}

fn page_of(read: &TieredRead, file: &str) -> Option<usize> {
    read.pages
        .iter()
        .position(|(_, paths)| paths.iter().any(|path| path.ends_with(file)))
}

/// The three placements of the holder and its copy, each with the tiers
/// that keep it: (a) one two-file page, under one tier wide enough for both
/// (the 1-day tier reads the copy alone and pulls its holder onto a later
/// page); (b) the holder read first; (c) the copy read first.
fn placements() -> [(&'static str, TierRun, Vec<u64>); 3] {
    let holder: &'static str = Box::leak(format!("{ROOT}.jsonl").into_boxed_str());
    let copy: &'static str = Box::leak(format!("{COPY}.jsonl").into_boxed_str());
    [
        (
            "same-page",
            TierRun {
                page_files: 2,
                ..TierRun::default()
            },
            vec![census_minus(30)],
        ),
        (
            "holder-first",
            TierRun {
                late: Some(copy),
                ..TierRun::default()
            },
            tier_bounds(),
        ),
        (
            "copy-first",
            TierRun {
                late: Some(holder),
                ..TierRun::default()
            },
            tier_bounds(),
        ),
    ]
}

/// `read` read the holder and its copy in `placement`.
fn assert_placed(name: &str, placement: &str, read: &TieredRead) {
    let holder = page_of(read, &format!("{ROOT}.jsonl"));
    let copy = page_of(read, &format!("{COPY}.jsonl"));
    let placed = match placement {
        "same-page" => holder == copy,
        "holder-first" => holder < copy,
        "copy-first" => copy < holder,
        other => panic!("unknown placement {other}"),
    };
    assert!(
        holder.is_some() && copy.is_some() && placed,
        "{name}: {placement}: {:?}",
        read.pages
    );
}

/// A cold restart from a read's saved store (`saved`, the route's last
/// index handle), then one more pass: settled, it opens no file and sends
/// nothing.
fn assert_settled_after_restart(name: &str, c: &Corpus, saved: ScanIndex) {
    let index = cold_restart(saved);
    let scanner = E2ScanFixture::default();
    scanner
        .on_committed_route(&crate::snapshots::e2_pipeline_scan_fixture::route_of(&index).unwrap());
    let page = ready(c, &scanner, index, 100, true);
    assert!(
        scanner.paths().is_empty(),
        "{name}: a settled pass after a restart opens no file: {:?}",
        scanner.paths()
    );
    assert!(
        page.scan.snapshots.is_empty(),
        "{name}: and sends nothing"
    );
}

/// The one answer under a `from` cutoff: the holder (its session ended
/// before the cutoff) never reaches the server, its accepted rows or accepted
/// origin, and the copy counts its `own` requests only: the copied one is
/// removed, not disclosed.
fn assert_copied_prefix_counts_nowhere(name: &str, c: &Corpus, read: &TieredRead, own: u64) {
    use crate::snapshots::claude_money_birth_store::location_key;
    let holder = c
        .root
        .join(format!("{ROOT}.jsonl"))
        .to_string_lossy()
        .into_owned();
    for stored in &read.stored {
        assert!(
            !stored.contains_key(ROOT),
            "{name}: the holder never reaches the server: {:?}",
            read.pages
        );
    }
    assert!(
        !crate::snapshots::e2_pipeline_scan_fixture::accepted_file_for_test(&read.index, &holder),
        "{name}: the holder is no accepted origin"
    );
    assert!(
        !read
            .index
            .upload_context_proof
            .request_contributions
            .values()
            .flat_map(|slot| slot.rows.iter())
            .any(|(loc, _)| *loc == location_key(&holder)),
        "{name}: the holder has no accepted rows"
    );
    let copy = latest_of(read, COPY).unwrap_or_else(|| panic!("{name}: the copy is stored"));
    assert_eq!(
        (copy.request_count, copy.removed_request_count),
        (own, Some(1)),
        "{name}: the copy counts its own requests and removes the copied one: {:?}",
        read.pages
    );
    assert_eq!(
        e2::pipeline_test_observer::disclosed(std::slice::from_ref(copy)),
        0,
        "{name}: nothing is disclosed"
    );
}

/// [money] A real account switch. Destination A reads the history tiered
/// from its own tier state, and the history grows. A claim then binds
/// destination B through the claim policy, for another user, with B recorded
/// before its bootstrap: `from` with a cutoff between the holder's line and
/// its copy's own line, the same `from` claim followed by a same-user `full`
/// one (which keeps the cutoff), or `full`. B's first import then runs
/// untiered and tiered from the same saved state, through the claim cutoff
/// and the finish settlement with its corrections. The final states are
/// equal. Under the cutoff no session that ended before it reaches B and the
/// copied request counts nowhere; under `full` the holder counts it. B's
/// tiers start at 1 day with no claim, and B never claims a tier it did not
/// finish; A's tier state stays A's.
#[test]
fn e2_tier_fresh_destination_after_account_switch_matches_untiered() {
    for (policy, then_full) in [("from", false), ("from-then-full", true), ("full", false)] {
        with_e2(|| {
            let mut c = Corpus::new(&format!("e2-tier-account-switch-{policy}"));
            holder_and_copy(&mut c, "");
            // In its own folder, so no folder pull brings it into tier 1.
            write_aged(
                &mut c,
                &format!("old/{THIRD}.jsonl"),
                &line(THIRD, "t1", "2026-06-20T07:00:10Z", 5),
                "2026-06-20T07:00:00Z",
                40,
            );
            let (a, b) = ("destination-a", "destination-b");
            let claude = SnapshotSource::ClaudeCode.api_slug();
            let state = || crate::backfill::load_backfill_state(&c.support);
            claim(&c, "full", None, "user-a", a);
            tiered_read(
                &c,
                &[],
                TierRun {
                    destination: Some(a),
                    ..TierRun::default()
                },
            );
            let a_tier = state().first_read_tiers[a].clone();
            assert!(
                a_tier.finished.contains_key(claude),
                "{policy}: A finished tiers itself"
            );
            assert!(state().first_read_cutoffs(a, claude).1.is_some());
            append(
                &c.root.join(format!("{COPY}.jsonl")),
                &line(COPY, "after-switch", "2026-08-02T07:40:00Z", 40),
            );
            let cutoff = (policy != "full").then_some(SWITCH_CUTOFF);
            claim(&c, policy.split('-').next().unwrap(), cutoff, "user-b", b);
            if then_full {
                claim(&c, "full", None, "user-b", b);
            }
            assert_eq!(
                state().backfill_cutoff_at.as_deref(),
                cutoff,
                "{policy}: a same-user full claim keeps the cutoff"
            );
            let path = crate::backfill::backfill_state_path(&c.support);
            let start = std::fs::read(&path).unwrap();
            let untiered = tiered_read(&c, &[], TierRun::default());
            std::fs::write(&path, &start).unwrap();
            let tiered = tiered_read(
                &c,
                &[],
                TierRun {
                    destination: Some(b),
                    ..TierRun::default()
                },
            );
            assert_tiered_equals_untiered(&format!("account-switch-{policy}"), &untiered, &tiered);
            for (run, read) in [("untiered", &untiered), ("tiered", &tiered)] {
                let name = format!("{policy}-{run}");
                match cutoff {
                    Some(cutoff) => {
                        assert_copied_prefix_counts_nowhere(&name, &c, read, 2);
                        let cutoff = crate::snapshots::rfc3339_unix_seconds(cutoff).unwrap();
                        for stored in &read.stored {
                            assert!(
                                !stored.contains_key(THIRD),
                                "{name}: sessions that ended before the cutoff stay off B"
                            );
                            for item in stored.values() {
                                assert!(
                                    activity_ended(item).is_some_and(|ended| ended >= cutoff),
                                    "{name}: {} ended before the cutoff",
                                    item.source_session_id
                                );
                            }
                        }
                    }
                    None => {
                        let copy = latest_of(read, COPY).unwrap();
                        assert_eq!(
                            (
                                latest_of(read, ROOT).map(|holder| holder.request_count),
                                copy.request_count,
                                copy.removed_request_count
                            ),
                            (Some(1), 2, Some(1)),
                            "{name}: the holder counts the copied request"
                        );
                    }
                }
            }
            assert_eq!(
                tiered.claims.first(),
                Some(&(1, None, None)),
                "{policy}: B starts at 1 day with nothing finished and no claim"
            );
            for (_, finished, claimed) in &tiered.claims {
                match (finished, claimed) {
                    (_, None) => {}
                    (Some(days), Some(claimed)) => assert!(
                        crate::snapshots::rfc3339_unix_seconds(claimed).unwrap()
                            >= census_minus(*days),
                        "{policy}: B claims no wider than it finished: {:?}",
                        tiered.claims
                    ),
                    (None, Some(_)) => {
                        panic!("{policy}: a claim B did not earn: {:?}", tiered.claims)
                    }
                }
            }
            assert!(
                tiered.claims.iter().any(|(_, finished, _)| finished.is_some()),
                "{policy}: B finished a tier itself: {:?} {:?}",
                tiered.claims,
                tiered.pages
            );
            let after = state();
            assert_eq!(after.first_read_tiers[a], a_tier, "{policy}: A's tier state is A's");
            assert!(after.first_read_tiers.contains_key(b));
        });
    }
}

/// [money] Placement (a), under a `from` cutoff: the holder and its copy on
/// one page (two-file pages; the tiered read under one tier wide enough for
/// both). The holder's page body proves the copied request; finish drops the
/// holder, and the emptied holder keeps proving it. Tiered and untiered reads
/// give the one answer, and a pass after a cold restart reads nothing.
#[test]
fn e2_tier_switch_holder_and_copy_on_one_page_count_the_prefix_nowhere() {
    with_e2(|| {
        let mut c = Corpus::new("e2-tier-switch-same-page");
        holder_and_copy(&mut c, "");
        claim(&c, "from", Some(SWITCH_CUTOFF), "user-b", "destination-b");
        let [(placement, run, tiers), ..] = placements();
        let untiered = tiered_read(&c, &[], run);
        let tiered = tiered_read(&c, &tiers, run);
        for (name, read) in [("same-page-untiered", &untiered), ("same-page-tiered", &tiered)] {
            assert_placed(name, placement, read);
            assert_copied_prefix_counts_nowhere(name, &c, read, 1);
        }
        assert_tiered_equals_untiered("switch-same-page", &untiered, &tiered);
        drop(untiered);
        assert_settled_after_restart("same-page-tiered", &c, tiered.index);
    });
}

/// [money] Placement (b), under a `from` cutoff: the holder is read and
/// emptied by the cutoff in an earlier pass; the copy appears and is read
/// later. The emptied holder (last written before the cutoff) proves the
/// copied request. Tiered and untiered reads give the one answer, and a pass
/// after a cold restart reads nothing.
#[test]
fn e2_tier_switch_holder_emptied_before_its_copy_counts_the_prefix_nowhere() {
    with_e2(|| {
        let mut c = Corpus::new("e2-tier-switch-holder-first");
        holder_and_copy(&mut c, "");
        claim(&c, "from", Some(SWITCH_CUTOFF), "user-b", "destination-b");
        let [_, (placement, run, tiers), _] = placements();
        let untiered = tiered_read(&c, &[], run);
        let tiered = tiered_read(&c, &tiers, run);
        for (name, read) in [("holder-first-untiered", &untiered), ("holder-first-tiered", &tiered)] {
            assert_placed(name, placement, read);
            assert_copied_prefix_counts_nowhere(name, &c, read, 1);
        }
        assert_tiered_equals_untiered("switch-holder-first", &untiered, &tiered);
        drop(untiered);
        assert_settled_after_restart("holder-first-tiered", &c, tiered.index);
    });
}

/// [money] Placement (c), under a `from` cutoff: the copy is read first and
/// counts the copied request (disclosed) before the holder is read; the
/// holder appears and is read later, and the cutoff empties it. The save-time
/// re-decide marks the copy, whose next read removes the request. Tiered and
/// untiered reads give the one answer, and a pass after a cold restart reads
/// nothing.
#[test]
fn e2_tier_switch_holder_read_after_its_copy_counts_the_prefix_nowhere() {
    with_e2(|| {
        let mut c = Corpus::new("e2-tier-switch-copy-first");
        holder_and_copy(&mut c, "");
        claim(&c, "from", Some(SWITCH_CUTOFF), "user-b", "destination-b");
        let [_, _, (placement, run, tiers)] = placements();
        let untiered = tiered_read(&c, &[], run);
        let tiered = tiered_read(&c, &tiers, run);
        for (name, read) in [("copy-first-untiered", &untiered), ("copy-first-tiered", &tiered)] {
            assert_placed(name, placement, read);
            let (at, first) = read
                .stored
                .iter()
                .enumerate()
                .find_map(|(at, stored)| stored.get(COPY).map(|copy| (at, copy)))
                .unwrap_or_else(|| panic!("{name}: the copy is stored"));
            assert!(
                Some(at) < page_of(read, &format!("{ROOT}.jsonl")),
                "{name}: the copy's first body is stored before the holder is read: {:?}",
                read.pages
            );
            assert_eq!(
                first.request_count, 2,
                "{name}: before the holder is read the copy counts the copied request"
            );
            assert!(
                e2::pipeline_test_observer::disclosed(std::slice::from_ref(first)) > 0,
                "{name}: and discloses it"
            );
            assert_copied_prefix_counts_nowhere(name, &c, read, 1);
        }
        assert_tiered_equals_untiered("switch-copy-first", &untiered, &tiered);
        drop(untiered);
        assert_settled_after_restart("copy-first-tiered", &c, tiered.index);
    });
}

/// [money] A touched holder: its session ended before the `from` cutoff, but
/// its file was last written after it, so nothing local shows that finish
/// empties the history. It owns nothing: in each placement, tiered or not,
/// every stored body of the copy counts the copied request and discloses it,
/// from the first.
#[test]
fn e2_tier_switch_touched_holder_leaves_the_copy_counting() {
    for (placement, run, tiers) in placements() {
        with_e2(|| {
            let mut c = Corpus::new(&format!("e2-tier-switch-touched-{placement}"));
            holder_and_copy(&mut c, "");
            write_aged(
                &mut c,
                &format!("{ROOT}.jsonl"),
                &line(ROOT, "original", OLD_AT, 10),
                "2026-07-02T07:00:00Z",
                13,
            );
            claim(&c, "from", Some(SWITCH_CUTOFF), "user-b", "destination-b");
            let untiered = tiered_read(&c, &[], run);
            let tiered = tiered_read(&c, &tiers, run);
            for (mode, read) in [("untiered", &untiered), ("tiered", &tiered)] {
                let name = format!("touched-{placement}-{mode}");
                assert_placed(&name, placement, read);
                assert_copy_counts_and_discloses(&name, read);
            }
            assert_tiered_equals_untiered(&format!("touched-{placement}"), &untiered, &tiered);
        });
    }
}

/// The holder never reaches the server, and every stored body of the copy
/// counts the copied request with its own and discloses it.
fn assert_copy_counts_and_discloses(name: &str, read: &TieredRead) {
    assert!(latest_of(read, COPY).is_some(), "{name}: the copy is stored");
    for stored in &read.stored {
        assert!(
            !stored.contains_key(ROOT),
            "{name}: the holder never reaches the server: {:?}",
            read.pages
        );
        if let Some(copy) = stored.get(COPY) {
            assert_eq!(
                copy.request_count, 2,
                "{name}: the copy counts the copied request: {:?}",
                read.pages
            );
            assert!(
                e2::pipeline_test_observer::disclosed(std::slice::from_ref(copy)) > 0,
                "{name}: and discloses it"
            );
        }
    }
}

/// [money] Path twins under a `from` cutoff: one session in two folders,
/// both written and ended before the cutoff, with the copy beside one. Finish
/// empties both. A holder whose session has another location proves nothing
/// under the cutoff (that location's body may carry its requests and be
/// refused), so the copy counts the copied request and discloses it, tiered
/// or not.
#[test]
fn e2_tier_switch_holder_with_a_path_twin_leaves_the_copy_counting() {
    with_e2(|| {
        let mut c = Corpus::new("e2-tier-switch-twin-holder");
        for folder in ["a", "b"] {
            write_aged(
                &mut c,
                &format!("{folder}/{ROOT}.jsonl"),
                &line(ROOT, "original", OLD_AT, 10),
                "2026-07-02T07:00:00Z",
                20,
            );
        }
        c.write_at(
            &format!("b/{COPY}.jsonl"),
            &(line(COPY, "original", OLD_AT, 10) + &line(COPY, "own", AT, 20)),
            "2026-08-02T07:00:00Z",
        );
        claim(&c, "from", Some(SWITCH_CUTOFF), "user-b", "destination-b");
        let untiered = tiered_read(&c, &[], TierRun::default());
        let tiered = tiered_read(&c, &tier_bounds(), TierRun::default());
        for (name, read) in [("twin-untiered", &untiered), ("twin-tiered", &tiered)] {
            assert_copy_counts_and_discloses(name, read);
        }
        assert_tiered_equals_untiered("switch-twin-holder", &untiered, &tiered);
    });
}

/// [money] A holder that ended and was last written before a `from` cutoff,
/// read and emptied, whose root the birth store then forgets (absent past its
/// retention). Nothing records its location as the session's only one, so it
/// proves nothing: the copy, read later, counts the copied request and
/// discloses it.
#[test]
fn e2_tier_switch_holder_without_a_birth_observation_leaves_the_copy_counting() {
    with_e2(|| {
        let mut c = Corpus::new("e2-tier-switch-unobserved-holder");
        write_aged(
            &mut c,
            &format!("{ROOT}.jsonl"),
            &line(ROOT, "original", OLD_AT, 10),
            "2026-07-02T07:00:00Z",
            20,
        );
        claim(&c, "from", Some(SWITCH_CUTOFF), "user-b", "destination-b");
        let read = tiered_read(&c, &[], TierRun::default());
        let mut prior = read.index;
        let births = &mut prior.claude_money_birth_store;
        assert!(
            births.observations(ROOT).next().is_some(),
            "the read observed the holder"
        );
        births.prune(1, Vec::<(&str, &str)>::new());
        births.prune(u64::MAX, Vec::<(&str, &str)>::new());
        assert!(
            births.observations(ROOT).next().is_none(),
            "the store forgot the holder's root"
        );
        c.write_at(
            &format!("{COPY}.jsonl"),
            &(line(COPY, "original", OLD_AT, 10) + &line(COPY, "own", AT, 20)),
            "2026-08-02T07:00:00Z",
        );
        let after = tiered_read_from(&c, &[], TierRun::default(), prior);
        assert_copy_counts_and_discloses("unobserved-holder", &after);
    });
}

/// [money] A /branch names its parent in a `fork-context-ref` line, and the
/// parent's census is retired, so no request id matches. Under a `from`
/// cutoff the parent ended before the cutoff and finish emptied it: the
/// named-parent fallback takes no cutoff ownership, so the branch counts the
/// copied request and discloses it.
#[test]
fn e2_tier_switch_named_emptied_parent_leaves_the_branch_counting() {
    with_e2(|| {
        let mut c = Corpus::new("e2-tier-switch-named-parent");
        write_aged(
            &mut c,
            &format!("{ROOT}.jsonl"),
            &line(ROOT, "original", OLD_AT, 10),
            "2026-07-02T07:00:00Z",
            20,
        );
        claim(&c, "from", Some(SWITCH_CUTOFF), "user-b", "destination-b");
        let read = tiered_read(&c, &[], TierRun::default());
        assert!(
            read.stored.iter().all(|stored| !stored.contains_key(ROOT)),
            "finish empties the parent: {:?}",
            read.pages
        );
        let mut prior = read.index;
        e2::pipeline_test_observer::retire_census(&mut prior, &format!("{ROOT}.jsonl"));
        c.write_at(
            &format!("{COPY}.jsonl"),
            &(fork_ref(COPY, ROOT) + &line(COPY, "original", OLD_AT, 10)),
            "2026-08-02T07:03:00Z",
        );
        let branch = tiered_read_from(&c, &[], TierRun::default(), prior);
        let copy = latest_of(&branch, COPY)
            .unwrap_or_else(|| panic!("the branch is stored: {:?}", branch.pages));
        assert_eq!(
            (copy.request_count, copy.removed_request_count),
            (1, Some(0)),
            "the branch keeps its copied request counted"
        );
        assert!(
            e2::pipeline_test_observer::disclosed(std::slice::from_ref(copy)) > 0,
            "and discloses it"
        );
    });
}

/// [money] The clock row, under a `from` cutoff: the holder's transcript
/// ends before the cutoff, but its matched API event was observed after it.
/// Finish keeps and uploads the holder on the emitted session clock, so the
/// holder owns the copied request and it counts once, on the holder.
#[test]
fn e2_tier_switch_holder_kept_by_its_api_event_counts_once() {
    with_e2(|| {
        let mut c = Corpus::new("e2-tier-switch-clock");
        holder_and_copy(&mut c, "");
        let mut row = api_for(ROOT, "original", 10, 100);
        row.observed_at = "2026-07-20T07:00:10Z".into();
        row.fingerprint = String::new();
        row.fingerprint = format!(
            "sha256:{:x}",
            Sha256::digest(serde_json::to_vec(&row).unwrap())
        );
        c.evidence(&[row], &[]);
        claim(&c, "from", Some(SWITCH_CUTOFF), "user-b", "destination-b");
        let untiered = tiered_read(&c, &[], TierRun::default());
        let tiered = tiered_read(&c, &tier_bounds(), TierRun::default());
        let cutoff = crate::snapshots::rfc3339_unix_seconds(SWITCH_CUTOFF).unwrap();
        for (name, read) in [("clock-untiered", &untiered), ("clock-tiered", &tiered)] {
            let holder = latest_of(read, ROOT)
                .unwrap_or_else(|| panic!("{name}: finish keeps the holder: {:?}", read.pages));
            assert!(
                activity_ended(holder).is_some_and(|ended| ended >= cutoff),
                "{name}: the holder ends on its API event's clock"
            );
            let copy = latest_of(read, COPY).unwrap();
            assert_eq!(
                (holder.request_count, copy.request_count, copy.removed_request_count),
                (1, 1, Some(1)),
                "{name}: the copied request counts once, on the holder"
            );
        }
        assert_tiered_equals_untiered("switch-clock", &untiered, &tiered);
    });
}

/// [money] Acceptance, under a `from` cutoff: the emptied holder never
/// reaches the server, its accepted rows or accepted origin, while it owns
/// the copied request. A later claim by another user clears the cutoff; that
/// destination's replay of the same index uploads the holder, and the copy,
/// read again, removes the request the holder now counts: counted once.
#[test]
fn e2_tier_switch_emptied_holder_is_never_accepted_and_a_cleared_cutoff_counts_once() {
    with_e2(|| {
        let mut c = Corpus::new("e2-tier-switch-acceptance");
        holder_and_copy(&mut c, "");
        claim(&c, "from", Some(SWITCH_CUTOFF), "user-b", "destination-b");
        let first = tiered_read(&c, &tier_bounds(), TierRun::default());
        assert_copied_prefix_counts_nowhere("acceptance-from", &c, &first, 1);
        claim(&c, "full", None, "user-c", "destination-c");
        assert_eq!(
            crate::backfill::load_backfill_state(&c.support).backfill_cutoff_at,
            None,
            "another user's claim clears the cutoff"
        );
        let mut start = first.index.clone();
        assert!(start.prepare_historical_replay("destination-c".into()));
        let replay = tiered_read_from(&c, &[], TierRun::default(), start);
        let holder = latest_of(&replay, ROOT)
            .unwrap_or_else(|| panic!("the holder uploads: {:?}", replay.pages));
        let copy = latest_of(&replay, COPY).unwrap();
        assert_eq!(
            (holder.request_count, copy.request_count, copy.removed_request_count),
            (1, 1, Some(1)),
            "the copied request counts once, on the holder"
        );
    });
}

/// [money] A deleted holder proves nothing: under a `from` cutoff its copy
/// counts the copied request (disclosed), the same whether the holder shared
/// the copy's page, was read and emptied first, or was never read.
#[test]
fn e2_tier_switch_deleted_holder_leaves_the_copy_counting() {
    with_e2(|| {
        let mut c = Corpus::new("e2-tier-switch-holder-deleted");
        claim(&c, "from", Some(SWITCH_CUTOFF), "user-b", "destination-b");
        let removed: &'static str = Box::leak(format!("{ROOT}.jsonl").into_boxed_str());
        let copy: &'static str = Box::leak(format!("{COPY}.jsonl").into_boxed_str());
        let mut reads = Vec::new();
        for (name, tiers, run) in [
            (
                "same-page",
                Vec::new(),
                TierRun {
                    page_files: 2,
                    removed: Some(removed),
                    ..TierRun::default()
                },
            ),
            (
                "holder-first",
                Vec::new(),
                TierRun {
                    removed: Some(removed),
                    late: Some(copy),
                    ..TierRun::default()
                },
            ),
            (
                "copy-first",
                tier_bounds(),
                TierRun {
                    removed: Some(removed),
                    ..TierRun::default()
                },
            ),
        ] {
            holder_and_copy(&mut c, "");
            let read = tiered_read(&c, &tiers, run);
            let body = latest_of(&read, COPY)
                .unwrap_or_else(|| panic!("{name}: the copy is stored"))
                .clone();
            assert_eq!(
                body.request_count, 2,
                "{name}: the copy counts the copied request: {:?}",
                read.pages
            );
            assert!(
                e2::pipeline_test_observer::disclosed(std::slice::from_ref(&body)) > 0,
                "{name}: and discloses it"
            );
            reads.push((name, body));
        }
        let fields = |body: &SnapshotItem| {
            (
                body.request_count,
                body.removed_request_count,
                serde_json::to_value(&body.usage_buckets).unwrap(),
            )
        };
        for (name, body) in &reads[1..] {
            assert_eq!(fields(body), fields(&reads[0].1), "{name}: same as same-page");
        }
    });
}

/// [money] Path twins (one session in two folders, the old one 20 days
/// back): the new twin admits its family whole, so both are read in the
/// 1-day tier and twin ownership is unchanged. The final state equals the
/// untiered read.
#[test]
fn e2_tier_path_twins_are_read_together() {
    with_e2(|| {
        let mut c = Corpus::new("e2-tier-path-twins");
        let r1 = line_by(ROOT, "r1", OLD_AT, 10, UNLISTED_WRITER);
        write_aged(&mut c, &format!("a/{ROOT}.jsonl"), &r1, "2026-07-02T07:00:00Z", 20);
        c.write_at(
            &format!("z/{ROOT}.jsonl"),
            &(r1 + &line_by(ROOT, "r2", AT, 20, UNLISTED_WRITER)),
            "2026-08-02T07:00:00Z",
        );
        let untiered = tiered_read(&c, &[], TierRun::default());
        let tiered = tiered_read(&c, &tier_bounds(), TierRun::default());
        assert_eq!(
            read_under(&tiered, &format!("a/{ROOT}.jsonl")),
            Some(Some(tier_bounds()[0])),
            "the old twin is admitted with its family: {:?}",
            tiered.pages
        );
        assert_tiered_equals_untiered("path-twins", &untiered, &tiered);
    });
}
