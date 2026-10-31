// Lead B condition b: synthetic v1 custody -> composed rows -> mapper hydrate
// -> real scan, identity qualification, finalization and upload encoding.
use super::money_equivalence_tests::{
    compare_claude_uploads, corpus, finish_claude_pages, grow, input_clock, receipt_with_output,
};
use super::*;
use serde_json::Value;

fn tagged_api(
    request: &str,
    tokens: u64,
    account: Option<&str>,
) -> crate::claude_local_otel::ClaudeLocalOtelEvidence {
    use crate::claude_local_otel::{
        ClaudeIdentityAttributeEvidence as Attribute, ClaudeIdentityAttributeOrigin as Origin,
        ClaudeIdentityDisposition as Disposition, ClaudeRequestIdentityEvidence,
    };
    let mut row = api(request, tokens, tokens * 10);
    row.account_identity_checked = true;
    row.account_identifier_hash = account.map(str::to_owned);
    row.request_identity = Some(ClaudeRequestIdentityEvidence {
        identity_hash_scheme: "provider-sha256:v1".into(),
        account: Attribute {
            // None models a present but invalid login attribute.
            origin: Origin::LogRecord,
            disposition: if account.is_some() {
                Disposition::Complete
            } else {
                Disposition::Invalid
            },
            resource_hash: None,
            log_record_hash: account.map(str::to_owned),
        },
        organization: Attribute {
            origin: Origin::Missing,
            disposition: Disposition::Missing,
            resource_hash: None,
            log_record_hash: None,
        },
        disposition: if account.is_some() {
            Disposition::Missing
        } else {
            Disposition::Invalid
        },
    });
    row.fingerprint.clear();
    row.fingerprint = format!(
        "sha256:{:x}",
        Sha256::digest(serde_json::to_vec(&row).unwrap())
    );
    row
}

fn add_class(index: &mut ScanIndex, path: &Path, class: &str) {
    let key = path.to_str().unwrap();
    let mut raw = serde_json::to_value(&*index).unwrap();
    match class {
        "census_keep" => {
            // The retained old copy shares exact request hashes with the live
            // member. This is #920's keep evidence, including its old window.
            let record = raw["claude_request_census"][key].clone();
            assert!(
                record.is_object(),
                "warm scan must create real census custody"
            );
            let mut old = record;
            old["w"] = json!(0);
            raw["claude_request_census"]["/synthetic/aged-copy"] = old;
        }
        "pending" => {
            let shaped: Value = serde_json::from_str(include_str!(
                "../../tests/fixtures/scan_index/real-shaped-v1.json"
            ))
            .unwrap();
            for field in [
                "claude_account_family_pending",
                "claude_usage_family_pending",
            ] {
                let mut pending = shaped["logical"][field]["synthetic-family"].clone();
                assert!(pending.is_object(), "pending fixture must be present");
                for member_field in ["members", "member_request_id_hashes", "member_occurrences"] {
                    // IndexMut would insert null for absent optional maps,
                    // which the v1 decoder correctly refuses as a non-map.
                    if let Some(members) =
                        pending.get_mut(member_field).and_then(Value::as_object_mut)
                    {
                        let value = members.remove("synthetic-file").unwrap();
                        members.insert(key.into(), value);
                    }
                }
                if let Some(windows) = pending
                    .get_mut("previous_windows")
                    .and_then(Value::as_array_mut)
                {
                    for window in windows {
                        let members = window["members"].as_object_mut().unwrap();
                        let value = members.remove("synthetic-file").unwrap();
                        members.insert(key.into(), value);
                    }
                }
                raw[field] = json!({ROOT: pending});
            }
        }
        "proved_rows" | "authority_quarantine" => {
            raw["claude_account_family_witnesses"] = json!({ROOT: {
                "account_identifier_hash":"a".repeat(64), "evidence_request_count":1,
                "members":{key:1}, "member_request_id_fingerprints":{key:"b".repeat(64)}
            }});
            raw["claude_usage_family_witnesses"] = json!({ROOT:{
                "evidence_fingerprint":"c".repeat(64),
                "member_request_id_fingerprints":{key:"b".repeat(64)},
                "member_occurrence_fingerprints":{key:"d".repeat(64)},
                "assigned_request_id_fingerprints":{ROOT:"e".repeat(64)},
                "legacy_excluded_request_id_hashes":{key:["f".repeat(64)]},
                "legacy_exclusion_evidence_fingerprint":"1".repeat(64), "legacy_owner_roots":[ROOT]
            }});
            if class == "authority_quarantine" {
                raw["claude_usage_authority_quarantine"] = json!({ROOT:{
                    "contract":"claude_usage_authority_quarantine:v2",
                    "proven_witness_fingerprint":"c".repeat(64),
                    "member_source_file_fingerprints":{key:raw["files"][key]["source_file_fingerprint"]},
                    "failed_reconstruction_count":2,"disposition":"unproven_terminal",
                    "retry_after_unix_seconds":u64::MAX,
                    "proof_correction":{"proof_witness_fingerprint":"2".repeat(64),"owed_member_ids":[ROOT]}
                }});
            }
        }
        "snapshot_quarantine" => {
            let mut record =
                crate::snapshots::snapshot_quarantine_record(SnapshotSource::ClaudeCode);
            record.retry_after_unix_seconds = u64::MAX;
            record.failed_reconstruction_count = 3;
            record.disposition = crate::snapshots::SnapshotQuarantineDisposition::UnprovenTerminal;
            raw["quarantined_snapshot_fingerprints"] = json!({"8".repeat(64):record});
        }
        "accepted_ack" => {
            let fp = "3".repeat(64);
            raw["accepted_snapshot_fingerprints"] = json!([fp]);
            raw["accepted_snapshot_fingerprint_ledger_version"] = json!(1);
            raw["accepted_rebuild_incidence"] = json!({key:[fp]});
            raw["upload_ack_retirement_handoff"] = json!({
                "destination_namespace_hash":"4".repeat(64), "committed_generation":index.generation,
                "bodies":{fp:"5".repeat(64)}, "pending_bodies":{"6".repeat(64):"7".repeat(64)}
            });
        }
        "copy_removal" => {
            let births = &mut index.claude_money_birth_store;
            let from = "/synthetic/moved-away";
            births.record_observation(COPY, from, nanos("2026-08-01T07:00:00Z"));
            births.record_observation(COPY, key, nanos(AT));
            assert!(births.record_proven_move(
                COPY,
                crate::snapshots::claude_money_birth_store::location_key(from),
                key
            ));
            births.set_money_rule_version(1);
            births.set_money_marks(key, 1 | 2 | 4);
            return;
        }
        "identity" | "identity_inheritance" => {}
        _ => panic!("uncovered money class {class}"),
    }
    *index = serde_json::from_value(raw).unwrap();
}

fn condition_b(class: &str) {
    with_e2(|| {
        let mut c = corpus(&format!("v2-condition-b-{class}"));
        if class == "identity" {
            crate::snapshots::write_claude_reemission_list_for_test(&c.support, &[ROOT]);
        }
        let path = c.root(ROOT, &line(ROOT, "r1", AT, 10));
        input_clock(&path);
        c.evidence(
            &[tagged_api("r1", 10, Some(&"a".repeat(64)))],
            &[trace("r1", "")],
        );
        let mut warm = c.raw(
            &E2ScanFixture::with_identity_capture(class.starts_with("identity")),
            ScanIndex::default(),
            100,
            false,
            &[],
        );
        warm.enrich(&c);
        warm.finish();
        assert!(!warm.scan.snapshots.is_empty(), "warm fixture must emit");
        let mut prior = warm.index;
        add_class(&mut prior, &path, class);
        // Decode both arms from the same v1 bytes, dropping identical runtime
        // flags. Only the candidate passes through composed populate/hydrate.
        let mut v1: ScanIndex =
            serde_json::from_slice(&serde_json::to_vec(&prior).unwrap()).unwrap();
        let v2 =
            crate::snapshots::state_v2_money_roundtrip(&v1, &c.base.canonicalize().unwrap().join("money.v2.sqlite.import"));
        v1.generation = v2.generation;
        assert_eq!(canonical(&v1), canonical(&v2), "all custody and join keys");
        grow(&path, "r2", 20);
        c.evidence(
            &[
                tagged_api("r1", 10, Some(&"a".repeat(64))),
                tagged_api("r2", 20, None),
            ],
            &[trace("r1", ""), trace("r2", "")],
        );
        let mut pages = [v1.clone(), v1, v2].map(|prior| {
            c.raw(
                &E2ScanFixture::with_identity_capture(class.starts_with("identity")),
                prior,
                100,
                false,
                &[],
            )
        });
        finish_claude_pages(&c, &mut pages);
        for candidate in &pages[1..] {
            assert_eq!(
                candidate.receipt(),
                pages[0].receipt(),
                "session, fingerprint and body join keys"
            );
            assert_eq!(
                canonical(&candidate.scan.snapshots),
                canonical(&pages[0].scan.snapshots),
                "identity tags/refusals and money"
            );
            assert_eq!(
                candidate.disposition, pages[0].disposition,
                "authority refusal"
            );
        }
        if matches!(class, "identity" | "identity_inheritance") {
            assert!(
                pages[0]
                    .scan
                    .snapshots
                    .iter()
                    .any(|item| !item.request_evidence.is_empty()),
                "tagged r1 must survive"
            );
        }
        if class == "identity" {
            assert!(
                pages[0]
                    .scan
                    .snapshots
                    .iter()
                    .any(|item| item.request_identity_refusals > 0),
                "invalid r2 must disclose its refusal"
            );
        }
        if class == "identity_inheritance" {
            // Preserve coverage of the original E2 path too: its invalid
            // login inherits r1's account rather than emitting a refusal.
            assert!(pages[0]
                .scan
                .snapshots
                .iter()
                .all(|item| item.request_identity_refusals == 0));
        }
        if pages[0].scan.snapshots.is_empty() {
            assert!(
                matches!(class, "proved_rows" | "authority_quarantine"),
                "unexpected empty money fixture {class}"
            );
            assert!(
                pages[0].disposition.quarantined_entity_count() > 0,
                "empty fixture must have a named refusal"
            );
            // A held family has no upload request in either arm.
            for page in &pages {
                let (result, sent, _) = upload(&page.scan.snapshots, &mut e2_progress(), |_| {
                    panic!("held family POST")
                });
                assert_eq!(result.unwrap(), ResumableUploadResult::Completed);
                assert!(sent.is_empty());
            }
        } else {
            let body = compare_claude_uploads(&pages);
            receipt_with_output(
                &format!("v2-{class}"),
                &[body],
                "OTTTO_STATE_V2_MONEY_EQUIVALENCE_OUTPUT",
                "STATE_V2_MONEY_EQUIVALENCE",
            );
            // Receiver UNCHANGED is a distinct settlement: compare the real
            // POST and retained progress without pretending it was a stored ACK.
            let unchanged = pages.each_ref().map(|page| {
                let mut progress = e2_progress();
                progress
                    .accepted_identity_buckets
                    .bind_test_key(Some([0x42; 32]));
                let (result, sent, _) = upload(&page.scan.snapshots, &mut progress, |batch| {
                    let mut response = ack(batch)?;
                    response.unchanged_entities = std::mem::take(&mut response.accepted_entities);
                    for entity in &mut response.unchanged_entities {
                        entity.unchanged_basis = Some("usage_identical".into());
                    }
                    Ok(response)
                });
                assert_eq!(result.unwrap(), ResumableUploadResult::Completed);
                assert!(!sent.is_empty());
                assert!(
                    progress.accepted_identity_buckets.is_empty(),
                    "UNCHANGED must not invent accepted shares"
                );
                (sent, serde_json::to_vec(&progress).unwrap())
            });
            assert_eq!(unchanged[0], unchanged[1]);
            assert_eq!(unchanged[0], unchanged[2]);
            // Persisted exact-body ACKs must still suppress a subsequent POST.
            let mut accepted = e2_progress();
            let (result, sent, _) = upload(&pages[0].scan.snapshots, &mut accepted, ack);
            assert_eq!(result.unwrap(), ResumableUploadResult::Completed);
            assert!(!sent.is_empty());
            let bytes = serde_json::to_vec(&accepted).unwrap();
            for page in &pages {
                let mut restored: SnapshotUploadProgress = serde_json::from_slice(&bytes).unwrap();
                let (result, sent, _) = upload(&page.scan.snapshots, &mut restored, |_| {
                    panic!("unchanged exact body POST")
                });
                assert_eq!(result.unwrap(), ResumableUploadResult::Completed);
                assert!(sent.is_empty());
            }
        }
    });
}

macro_rules! classes {
    ($($test:ident => $class:literal),+ $(,)?) => {$(#[doc = "[money] Preserve the next upload and ACK custody for this persisted money class."] #[test] fn $test() { condition_b($class); })+};
}
classes! {
    v2_census_and_920_keep_emit_identical_next_body => "census_keep",
    v2_account_and_usage_pending_emit_identical_next_body => "pending",
    v2_option_ii_proved_rows_emit_identical_body_or_refusal => "proved_rows",
    v2_authority_quarantine_preserves_refusal_and_join_keys => "authority_quarantine",
    v2_accepted_ledger_and_ack_handoff_preserve_no_post => "accepted_ack",
    v2_snapshot_quarantine_preserves_terminal_refusal => "snapshot_quarantine",
    v2_e2_copy_removal_and_rule_marks_preserve_next_body => "copy_removal",
    v2_909_identity_tags_and_refusals_preserve_next_body => "identity",
    v2_e2_invalid_identity_inheritance_preserves_next_body => "identity_inheritance",
}

/// [money] v2 accepted identity buckets and ack receipt preserve identical next upload.
#[test]
fn v2_accepted_identity_buckets_and_ack_receipt_preserve_identical_next_upload() {
    with_e2(|| {
        let mut c = corpus("v2-accepted-identity-buckets");
        // #909 deliberately retains uniform markerless E2 bodies in D1's
        // existing wire shape. An own captured marker exercises identity rows.
        let marker = json!({"type":"attachment", "sessionId":ROOT,
            "attachment":{"type":"credential_org",
                "organizationUuid":"11111111-1111-4111-8111-111111111111"}});
        let path = c.root(
            ROOT,
            &(marker.to_string() + "\n" + &line(ROOT, "r1", AT, 10)),
        );
        input_clock(&path);
        c.evidence(
            &[tagged_api("r1", 10, Some(&"a".repeat(64)))],
            &[trace("r1", "")],
        );
        let mut warm = c.raw(
            &E2ScanFixture::with_identity_capture(true),
            ScanIndex::default(),
            100,
            false,
            &[],
        );
        warm.enrich(&c);
        warm.finish();
        assert!(
            warm.scan
                .snapshots
                .iter()
                .any(|item| !item.request_evidence.is_empty()),
            "fixture must carry real identity tags"
        );
        let mut progress = e2_progress();
        progress
            .accepted_identity_buckets
            .bind_test_key(Some([0x42; 32]));
        let (result, sent, _) = upload(&warm.scan.snapshots, &mut progress, ack);
        assert_eq!(result.unwrap(), ResumableUploadResult::Completed);
        assert!(!sent.is_empty());
        assert!(!progress.accepted_identity_buckets.is_empty());
        let bytes = serde_json::to_vec(&progress).unwrap();
        let progress_path = c.base.join("claude_code-upload-progress.json");
        ottto_core::write_owner_only_file_atomic(&progress_path, &bytes).unwrap();
        let recovery = crate::snapshots::ProgressRecovery::synthetic(
            &c.base.join("index"),
            &"a".repeat(64),
            warm.index.generation,
        );
        recovery.adopt_synthetic(Some(&bytes));
        let v2 = crate::snapshots::state_v2_money_roundtrip(
            &warm.index,
            &c.base.canonicalize().unwrap().join("accepted.v2.sqlite.import"),
        );
        recovery.recover(&progress_path).unwrap();
        assert_eq!(
            std::fs::read(&progress_path).unwrap(),
            bytes,
            "import/ACK handoff must leave external progress byte-unchanged"
        );
        let mut v1: ScanIndex =
            serde_json::from_slice(&serde_json::to_vec(&warm.index).unwrap()).unwrap();
        v1.generation = v2.generation;
        grow(&path, "r2", 20);
        // A changed/new authority must not erase the previously accepted share.
        c.evidence(
            &[
                tagged_api("r1", 10, Some(&"a".repeat(64))),
                tagged_api("r2", 20, Some(&"b".repeat(64))),
            ],
            &[trace("r1", ""), trace("r2", "")],
        );
        let mut pages = [v1.clone(), v1, v2].map(|prior| {
            c.raw(
                &E2ScanFixture::with_identity_capture(true),
                prior,
                100,
                false,
                &[],
            )
        });
        let mut bodies = Vec::new();
        for page in &mut pages {
            let mut restored: SnapshotUploadProgress = serde_json::from_slice(&bytes).unwrap();
            restored
                .accepted_identity_buckets
                .bind_test_key(Some([0x42; 32]));
            assert_eq!(
                restored.accepted_identity_buckets,
                progress.accepted_identity_buckets
            );
            page.enrich_with_accepted(&c, Some(&restored.accepted_identity_buckets));
            page.finish();
            let (result, sent, _) = upload(&page.scan.snapshots, &mut restored, ack);
            assert_eq!(result.unwrap(), ResumableUploadResult::Completed);
            assert!(!sent.is_empty(), "changed body must reach next POST");
            bodies.push(sent);
        }
        assert_eq!(bodies[0], bodies[1]);
        assert_eq!(
            bodies[0], bodies[2],
            "accepted share priority, identity parts/refusals, body bytes and joins"
        );
        assert_eq!(std::fs::read(&progress_path).unwrap(), bytes);
    });
}
