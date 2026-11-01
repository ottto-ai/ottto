//! Publication, durable authority and the native retired-holder recovery seam.
use super::*;
use crate::snapshots::claude_request_census::{self as census, ClaudeRequestCensusShape};
use crate::snapshots::e2_pipeline_scan_fixture::{self as fixture, E2ScanFixture};
use crate::snapshots::sampled_scan::transition_fixture::{money_oracle, scan_money};

fn publish(home: &Path, support: &Path, replace: bool) -> Request {
    super::super::run(
        &home.join("scope.json"),
        support,
        &home.join("scan-index.json"),
        true,
        replace,
        BACKFILL_WINDOW_DAYS,
    )
    .unwrap();
    bounded_json(&support.join("snapshots").join(REQUEST)).unwrap()
}

const SCAN_AT: &str = "2026-08-02T08:00:00Z";
const ORGS: [&str; 2] = [
    "11111111-1111-4111-8111-111111111111",
    "22222222-2222-4222-8222-222222222222",
];

/// Small birth-ordered chain: retired origin, live copy, two retired holders,
/// live all-copy partner, retired final resume. All holders have a live partner.
struct ProofChain {
    home: PathBuf,
    root: PathBuf,
    support: PathBuf,
    paths: Vec<PathBuf>,
    births: BTreeMap<PathBuf, i128>,
}
impl ProofChain {
    fn new(name: &str) -> Self {
        let home = crate::test_scratch::canonical_private_dir(name);
        let root = home.join("project");
        let support = home.join("support");
        fs::create_dir_all(&root).unwrap();
        fixture::write_exclusions(&support, &[]);
        let mut paths = Vec::new();
        let mut births = BTreeMap::new();
        let counts = [2, 3, 4, 5, 5, 6];
        for (slot, count) in counts.into_iter().enumerate() {
            let session = format!("bbbbbbbb-cccc-4ddd-8eee-{slot:012x}");
            let path = root.join(format!("{session}.jsonl"));
            let mut text = String::new();
            for request in 0..count {
                // Keep the final own request untagged as an evidence-gap control.
                let attachment = if request == 5 {
                    json!({"type":"session_context", "context":{}})
                } else {
                    json!({"type":"credential_org", "organizationUuid":ORGS[request % 2]})
                };
                text += &(json!({"type":"attachment", "sessionId":session,
                    "attachment":{"type":"session_context", "context":{}}})
                .to_string()
                    + "\n");
                text += &(json!({"type":"attachment", "sessionId":session,
                    "attachment":attachment})
                .to_string()
                    + "\n");
                let day = if request < 2 {
                    1
                } else if request == 5 {
                    6
                } else {
                    request
                };
                text += &(json!({"type":"assistant", "sessionId":session,
                    "version":"2.1.229", "timestamp":format!("2026-06-{day:02}T07:00:10Z"),
                    "requestId":format!("request-{request}"),
                    "message":{"id":format!("message-{request}"), "model":"claude-haiku-4-5",
                        "usage":{"input_tokens":10 + request, "output_tokens":1}}})
                .to_string()
                    + "\n");
            }
            fs::write(&path, text).unwrap();
            let birth_day = if slot == 0 { 1 } else { slot + 1 };
            let birth = time::OffsetDateTime::parse(
                &format!("2026-06-{birth_day:02}T07:00:00Z"),
                &time::format_description::well_known::Rfc3339,
            )
            .unwrap()
            .unix_timestamp_nanos();
            births.insert(path.clone(), birth);
            fs::File::open(&path)
                .unwrap()
                .set_modified(
                    UNIX_EPOCH
                        + std::time::Duration::from_secs(
                            rfc3339_unix_seconds("2026-06-15T00:00:00Z").unwrap(),
                        ),
                )
                .unwrap();
            paths.push(path);
        }
        // One real sidecar-only API call, retained in the first session.
        let session = paths[0].file_stem().unwrap().to_str().unwrap();
        let mut side = crate::snapshots::tests::complete_api_row(session, "side-call", 1, 7, 2, 0);
        side.client_request_id = "side-client".into();
        side.observed_at = "2026-06-01T07:00:30Z".into();
        side.app_version = "2.1.229".into();
        side.effort.clear();
        side.speed.clear();
        side.cost_usd_micros = Some(1);
        side.account_identifier_hash = Some("b".repeat(64));
        let mut api = vec![side.clone()];
        for request in 0..2 {
            let mut row = side.clone();
            row.request_id = format!("request-{request}");
            row.client_request_id = format!("client-{request}");
            row.observed_at = "2026-06-01T07:00:10Z".into();
            row.input_tokens = 10 + request;
            row.output_tokens = 1;
            row.event_sequence = Some(request + 2);
            row.account_identifier_hash = Some(if request == 0 { "a" } else { "b" }.repeat(64));
            api.push(row);
        }
        let mut traces = Vec::new();
        for row in &mut api {
            row.fingerprint.clear();
            row.fingerprint = format!(
                "sha256:{:x}",
                Sha256::digest(serde_json::to_vec(&row).unwrap())
            );
            let mut trace =
                crate::snapshots::tests::complete_trace_row(session, &row.request_id, "");
            trace.client_request_id = row.client_request_id.clone();
            trace.observed_at = row.observed_at.clone();
            trace.fingerprint.clear();
            trace.fingerprint = format!(
                "sha256:{:x}",
                Sha256::digest(serde_json::to_vec(&trace).unwrap())
            );
            traces.push(trace);
        }
        for (directory, rows) in [
            (
                "claude-code-effort",
                api.iter()
                    .map(|row| serde_json::to_string(row).unwrap() + "\n")
                    .collect::<String>(),
            ),
            (
                "claude-code-trace-ownership",
                traces
                    .iter()
                    .map(|row| serde_json::to_string(row).unwrap() + "\n")
                    .collect::<String>(),
            ),
        ] {
            let sidecar = support
                .join("local-otel")
                .join(directory)
                .join(format!("{:x}.jsonl", Sha256::digest(session.as_bytes())));
            fs::create_dir_all(sidecar.parent().unwrap()).unwrap();
            fs::write(sidecar, rows).unwrap();
        }
        fs::write(home.join("scope.json"), serde_json::to_vec(&paths).unwrap()).unwrap();
        Self {
            home,
            root,
            support,
            paths,
            births,
        }
    }

    fn raw(&self, mut index: ScanIndex) -> (ScanIndex, SourceScanResult) {
        index.activate_effective_upload_body_witness_revision(3);
        index.adopt_effective_upload_body_witness_revision_monotonically();
        index.activate_upload_context("proof-recovery-context".into());
        index.load_claude_reemission_exclusions(&self.support);
        let (index, scan, _) = E2ScanFixture::capturing_identity().scan(
            std::slice::from_ref(&self.root),
            &self.support,
            index,
            MAX_BACKFILL_FILES_PER_SOURCE,
            false,
            &self.births,
            &[],
        );
        (index, scan)
    }

    fn enrich(&self, index: &mut ScanIndex, scan: &mut SourceScanResult) {
        let (disposition, _, _) =
            crate::snapshot_sync::apply_claude_local_evidence_to_scan(&self.support, scan, index);
        assert!(disposition.quarantined_source_session_ids.is_empty());
        apply_upload_policy(
            SnapshotSource::ClaudeCode,
            &mut scan.snapshots,
            SnapshotUploadPolicy::default(),
        );
    }

    fn accept(&self, index: &mut ScanIndex, scan: &mut SourceScanResult) {
        finalize_scan_after_policy(SnapshotSource::ClaudeCode, scan, index);
        index.record_accepted_snapshot_fingerprints(
            &scan
                .snapshots
                .iter()
                .map(|item| item.snapshot_fingerprint.clone())
                .collect(),
        );
        let acks = fixture::exact_acks_for_test(&scan.snapshots);
        fixture::accept_upload_context_acks_for_test(index, &scan.snapshots, &acks);
        index.save(&self.home.join("scan-index.json")).unwrap();
    }

    fn retire(&self, index: &mut ScanIndex, slots: &[usize]) {
        for slot in slots {
            let key = local_index_key(&self.paths[*slot]);
            let mut record = index
                .claude_request_census_for_test()
                .record_for_test(&key)
                .unwrap()
                .clone();
            record.retire();
            index
                .claude_request_census_mut_for_test()
                .insert_for_test(&key, record);
        }
    }

    fn residue(&self) -> (ScanIndex, Vec<SnapshotItem>) {
        let (mut index, raw) = self.raw(ScanIndex::default());
        self.retire(&mut index, &[0, 2, 3, 5]);
        // The existing decision retry expires unresolved prefixes on pass three.
        // Reuse the native parse as a RAM re-derivation would; do not invent folds.
        let mut scan = raw.clone();
        for _ in 0..3 {
            scan = raw.clone();
            self.enrich(&mut index, &mut scan);
        }
        self.accept(&mut index, &mut scan);
        let items = scan.snapshots;
        assert!(items.iter().map(|item| item.request_count).sum::<u64>() > 7);
        (index, items)
    }

    fn prepare(&self, index: &mut ScanIndex) -> Vec<PathBuf> {
        index.activate_effective_upload_body_witness_revision(3);
        super::super::prepare(
            index,
            &self.support,
            std::slice::from_ref(&self.root),
            SCAN_AT,
            BACKFILL_WINDOW_DAYS,
        )
        .unwrap()
    }
}
impl Drop for ProofChain {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.home);
    }
}

/// [regress] Authorized recovery rebuilds unchanged retired proof once;
/// legacy requests never grant revival, and a non-Full revival still owes Full.
#[test]
fn retired_unchanged_holder_authorized_reread_removes_prefix_once() {
    with_max_gated_claude_revision(3, || {
        let chain = ProofChain::new("copy-prefix-retired-regression");
        let (mut index, _) = chain.residue();
        let request = publish(&chain.home, &chain.support, false);
        let request_path = chain.support.join("snapshots").join(REQUEST);
        let bytes = fs::read(&request_path).unwrap();
        assert!(run(&chain.home.join("scope.json"), &chain.support, true).is_err());
        assert!(super::super::run(
            &chain.home.join("scope.json"),
            &chain.support,
            &chain.home.join("scan-index.json"),
            false,
            true,
            BACKFILL_WINDOW_DAYS,
        )
        .is_err());
        assert_eq!(fs::read(&request_path).unwrap(), bytes);
        assert_eq!(chain.prepare(&mut index).len(), 6);
        assert_eq!(index.copy_prefix_last_accepted_nonce, request.nonce);
        let (mut index, mut recovered) = chain.raw(index);
        for slot in [0, 2, 3, 5] {
            let record = index
                .claude_request_census_for_test()
                .record_for_test(&local_index_key(&chain.paths[slot]))
                .unwrap();
            assert_eq!(
                record.retired_for_test(),
                None,
                "proof survives same-page terminal overlap"
            );
        }
        chain.enrich(&mut index, &mut recovered);
        let copy = recovered
            .snapshots
            .iter()
            .find(|s| s.source_session_id == chain.paths[1].file_stem().unwrap().to_str().unwrap())
            .unwrap();
        assert_eq!(
            (copy.request_count, copy.removed_request_count),
            (1, Some(2))
        );
        chain.accept(&mut index, &mut recovered);
        let mut index = ScanIndex::load(&chain.home.join("scan-index.json")).unwrap();
        assert!(chain.prepare(&mut index).is_empty());
        assert!(index.copy_prefix_recovery_scope.is_empty());
        let temp = chain.support.join("same-request.json");
        fs::write(&temp, serde_json::to_vec(&request).unwrap()).unwrap();
        fs::rename(temp, &request_path).unwrap();
        assert!(chain.prepare(&mut index).is_empty());
        let (_, quiet) = chain.raw(index.clone());
        assert_eq!(
            quiet.scanned_file_count, 0,
            "same nonce does not schedule another read"
        );

        // A fresh legacy publication remains one-shot and confers no authority.
        let mut legacy = request;
        legacy.nonce = None;
        fs::write(&request_path, serde_json::to_vec(&legacy).unwrap()).unwrap();
        assert!(chain.prepare(&mut index).is_empty());
        assert!(index.copy_prefix_recovery_scope.is_empty());

        let bytes = fs::read(&request_path).unwrap();
        let mut reader = fs::File::open(&request_path).unwrap();
        let replacement = publish(&chain.home, &chain.support, true);
        let mut old_bytes = Vec::new();
        reader.read_to_end(&mut old_bytes).unwrap();
        assert_eq!(
            old_bytes, bytes,
            "replacement preserves the old reader's whole request"
        );
        assert_ne!(replacement.nonce, index.copy_prefix_last_accepted_nonce);
        assert_eq!(
            chain.prepare(&mut index).len(),
            6,
            "new nonce re-arms settled members"
        );
        chain.retire(&mut index, &[0]);
        let path = &chain.paths[0];
        let key = local_index_key(path);
        let fingerprint = index.files[&key].source_file_fingerprint.clone();
        // A complete but non-Full itemless parse is identity-incomplete; the
        // prepared recovery scope authorizes its revival.
        let accepted_recovery_member = index.copy_prefix_recovery_scope.contains(path);
        census::record_claude_request_census(
            &mut index,
            census::ClaudeRequestCensusParse {
                path,
                index_key: &key,
                source_file_fingerprint: &fingerprint,
                census_window_end: SCAN_AT,
                complete: true,
                lossy: false,
                source_verified: false,
                unchanged_source: false,
                itemless_request_hashes: vec![census::claude_request_hash("request-0")],
                opened_birth: None,
                modified_unix_seconds: rfc3339_unix_seconds("2026-06-15T00:00:00Z").unwrap(),
                accepted_recovery_member,
            },
            &[],
        );
        let record = index
            .claude_request_census_for_test()
            .record_for_test(&key)
            .unwrap();
        assert_eq!(record.retired_for_test(), None);
        assert!(record.unverified_for_test());
        assert_eq!(
            record.shape_for_test(),
            ClaudeRequestCensusShape::IdentityIncomplete
        );
        assert!(record.identity_incomplete_hold());
        index.files.get_mut(&key).unwrap().scan_identity_version =
            Some(LOCAL_SCAN_INDEX_IDENTITY_VERSION.into());
        assert!(sampled_audit::awaits_hold_deadline_restoration(
            &index, &key
        ));
    });
}

/// [money] A six-session chain restores totals and placement to cold Full,
/// including a mid-session account switch, a side call and an evidence gap.
#[test]
fn copy_prefix_proof_recovery_totals_and_placement() {
    with_max_gated_claude_revision(3, || {
        let chain = ProofChain::new("copy-prefix-recovery-money");
        let (mut cold_index, mut cold) = chain.raw(ScanIndex::default());
        chain.enrich(&mut cold_index, &mut cold);
        chain.accept(&mut cold_index, &mut cold);
        let cold_route = scan_money(SnapshotSource::ClaudeCode, &cold_index, &cold);
        let (mut index, prior) = chain.residue();
        publish(&chain.home, &chain.support, false);
        chain.prepare(&mut index);
        index.save(&chain.home.join("scan-index.json")).unwrap();
        let mut index = ScanIndex::load(&chain.home.join("scan-index.json")).unwrap();
        assert!(index.copy_prefix_recovery_scope.is_empty());
        index = state_v2::money_test_support::roundtrip(&index, &chain.home.join("nonce.sqlite"));
        assert!(index.copy_prefix_recovery_scope.is_empty());
        assert_eq!(
            chain.prepare(&mut index).len(),
            6,
            "accepted nonce survives restart while debt remains"
        );
        let (mut index, mut recovered) = chain.raw(index);
        chain.enrich(&mut index, &mut recovered);
        chain.accept(&mut index, &mut recovered);
        // Compare the destination's complete replacement state, including
        // unchanged bodies whose exact receipt makes finalization a no-op.
        let mut delivered = prior
            .into_iter()
            .map(|s| (s.source_session_id.clone(), s))
            .collect::<BTreeMap<_, _>>();
        for item in std::mem::take(&mut recovered.snapshots) {
            delivered.insert(item.source_session_id.clone(), item);
        }
        recovered.snapshots = delivered.into_values().collect();
        let restored_route = scan_money(SnapshotSource::ClaudeCode, &index, &recovered);
        money_oracle::assert_equivalent(&cold_route, &restored_route);
        let rows = cold_route
            .snapshots
            .values()
            .flat_map(|s| s["usage_buckets"].as_array().unwrap())
            .flat_map(|b| b["model_usage"].as_array().unwrap())
            .collect::<Vec<_>>();
        assert!(
            rows.iter()
                .any(|r| !r["evidence_ref"].is_null() || !r["identity_parts"].is_null()),
            "positive tagged-row control"
        );
        let accounts = rows
            .iter()
            .flat_map(|row| {
                row["identity_parts"]
                    .as_array()
                    .map(Vec::as_slice)
                    .unwrap_or(std::slice::from_ref(*row))
            })
            .filter_map(|part| part["account_identifier_hash"].as_str())
            .collect::<BTreeSet<_>>();
        assert!(
            accounts.contains("a".repeat(64).as_str())
                && accounts.contains("b".repeat(64).as_str()),
            "two-account control"
        );
        assert!(
            rows.iter()
                .any(|row| row["evidence_ref"].is_null() && row["identity_parts"].is_null()),
            "evidence-gap control"
        );
        assert_eq!(
            cold.snapshots.iter().map(|s| s.request_count).sum::<u64>(),
            7,
            "six owned requests plus one side call"
        );
        assert!(chain.prepare(&mut index).is_empty());
    });
}
