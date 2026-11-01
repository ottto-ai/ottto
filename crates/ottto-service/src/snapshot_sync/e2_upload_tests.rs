// E2 upload path: request-owned families, literal batch errors, retry bytes.
// Included into `snapshot_sync::tests`; uses its helpers.

#[derive(Clone, Serialize)]
struct FamilyItem {
    fingerprint: String,
    session: String,
    payload: String,
    #[serde(skip)]
    root: Option<String>,
    #[serde(skip)]
    class: bool,
}

fn family_member(root: &str, agent: Option<usize>, payload: usize) -> FamilyItem {
    let session = match agent {
        Some(agent) => format!("{root}_agent-{agent:03}"),
        None => root.to_owned(),
    };
    FamilyItem {
        fingerprint: format!("{:064x}", fingerprint_seed(&session)),
        session,
        payload: "x".repeat(payload),
        root: Some(root.to_owned()),
        class: false,
    }
}

fn plain_item(ordinal: u64) -> FamilyItem {
    FamilyItem {
        fingerprint: format!("{ordinal:064x}"),
        session: format!("plain-{ordinal}"),
        payload: String::new(),
        root: None,
        class: false,
    }
}

fn fingerprint_seed(session: &str) -> u128 {
    // Deterministic, order-independent of the session's position: a family's
    // pending order (by fingerprint) must not decide its batch order.
    use sha2::Digest;
    let digest = sha2::Sha256::digest(session.as_bytes());
    u128::from_be_bytes(digest[..16].try_into().unwrap())
}

fn family(root: &str, members: usize, payload: usize) -> Vec<FamilyItem> {
    (0..members)
        .map(|n| family_member(root, n.checked_sub(1), payload))
        .collect()
}

fn upload_families(
    items: &[FamilyItem],
    progress: &mut SnapshotUploadProgress,
    mut respond: impl FnMut(&[FamilyItem]) -> Result<crate::snapshot_client::SnapshotBatchResponse>,
) -> (Result<ResumableUploadResult>, Vec<Vec<String>>) {
    let mut batches = Vec::new();
    let mut accepted = 0;
    let result = upload_resumable_batches_with_literal_families(
        items,
        &unique_poison_scope(),
        progress,
        &mut accepted,
        |item| item.fingerprint.as_str(),
        |item| item.fingerprint.clone(),
        |item| Some(item.session.as_str()),
        |item| item.class,
        |item| item.root.as_deref(),
        no_history_group,
        &mut InplaceRetryBudget::default(),
        |batch| {
            batches.push(batch.iter().map(|item| item.session.clone()).collect());
            respond(&batch)
        },
        |_| Ok(()),
    );
    (result, batches)
}

fn accept_all(batch: &[FamilyItem]) -> Result<crate::snapshot_client::SnapshotBatchResponse> {
    Ok(accepted_batch(batch.len()))
}

#[test]
fn e2_family_of_49_50_51_bodies_uploads_root_first_and_never_refuses() {
    for members in [49, 50, 51, 120] {
        let items = family("root-a", members, 0);
        let (result, batches) = upload_families(&items, &mut test_upload_progress(), accept_all);
        assert_eq!(
            result.unwrap(),
            ResumableUploadResult::Completed,
            "{members}"
        );
        let sizes = batches.iter().map(Vec::len).collect::<Vec<_>>();
        let expected = match members {
            49 => vec![49],
            50 => vec![50],
            51 => vec![50, 1],
            _ => vec![50, 50, 20],
        };
        assert_eq!(sizes, expected, "{members} bodies");
        assert_eq!(batches[0][0], "root-a", "root first");
        let flat = batches.concat();
        let mut agents = flat[1..].to_vec();
        agents.sort();
        assert_eq!(flat[1..], agents[..], "agents follow in session order");
    }
}

#[test]
fn e2_family_that_fits_stays_whole_beside_plain_bodies() {
    // 30 plain bodies first (fingerprint order), then the 30-body family must
    // not straddle a batch: it moves whole to the next one.
    let mut items = (0..30).map(plain_item).collect::<Vec<_>>();
    items.extend(family("root-b", 30, 0));
    let (result, batches) = upload_families(&items, &mut test_upload_progress(), accept_all);
    assert_eq!(result.unwrap(), ResumableUploadResult::Completed);
    assert_eq!(
        batches.iter().map(Vec::len).collect::<Vec<_>>(),
        vec![30, 30]
    );
    assert!(batches[1]
        .iter()
        .all(|session| session.starts_with("root-b")));
}

#[test]
fn e2_family_byte_boundary_is_one_batch_at_two_mib_and_split_above() {
    let probe = family("root-c", 2, 0);
    let base = probe
        .iter()
        .map(|item| serde_json::to_vec(item).unwrap().len() + 1)
        .sum::<usize>();
    let fill = SNAPSHOT_BATCH_MAX_BYTES - 2 - base;
    let mut exact = probe.clone();
    exact[0].payload = "x".repeat(fill / 2);
    exact[1].payload = "x".repeat(fill - fill / 2);
    let bytes = 2 + exact
        .iter()
        .map(|item| serde_json::to_vec(item).unwrap().len() + 1)
        .sum::<usize>();
    assert_eq!(bytes, SNAPSHOT_BATCH_MAX_BYTES);
    let (result, batches) = upload_families(&exact, &mut test_upload_progress(), accept_all);
    assert_eq!(result.unwrap(), ResumableUploadResult::Completed);
    assert_eq!(batches.len(), 1, "exactly 2 MiB fits one batch");
    let mut over = exact;
    over[1].payload.push('x');
    let (result, batches) = upload_families(&over, &mut test_upload_progress(), accept_all);
    assert_eq!(result.unwrap(), ResumableUploadResult::Completed);
    assert_eq!(
        batches,
        vec![
            vec!["root-c".to_owned()],
            vec!["root-c_agent-000".to_owned()]
        ]
    );
}

#[test]
fn e2_gate_off_batches_equal_the_plain_packer() {
    // No literal family: the family-aware packer is the plain packer.
    let items = (0..120).rev().map(plain_item).collect::<Vec<_>>();
    let (result, batches) = upload_families(&items, &mut test_upload_progress(), accept_all);
    assert_eq!(result.unwrap(), ResumableUploadResult::Completed);
    let mut plain = Vec::new();
    let mut accepted = 0;
    upload_resumable_batches_with_body_witness_partitioned(
        &items,
        &unique_poison_scope(),
        &mut test_upload_progress(),
        &mut accepted,
        |item| item.fingerprint.as_str(),
        |item| item.fingerprint.clone(),
        |item| Some(item.session.as_str()),
        |item| item.class,
        &mut InplaceRetryBudget::default(),
        |batch| {
            plain.push(
                batch
                    .iter()
                    .map(|item| item.session.clone())
                    .collect::<Vec<_>>(),
            );
            Ok(accepted_batch(batch.len()))
        },
        |_| Ok(()),
    )
    .unwrap();
    assert_eq!(batches, plain);
    assert_eq!(
        batches.iter().map(Vec::len).collect::<Vec<_>>(),
        vec![50, 50, 20]
    );
}

#[test]
fn e2_malformed_literal_is_isolated_and_siblings_settle() {
    let items = family("root-d", 3, 0);
    let poison = items[1].fingerprint.clone();
    let mut progress = test_upload_progress();
    let (result, batches) = upload_families(&items, &mut progress, |batch| {
        if let Some(position) = batch.iter().position(|item| item.fingerprint == poison) {
            return Err(anyhow::Error::new(SnapshotBatchPreflightRejected {
                reason: format!("snapshot[{position}] violates the wire contract"),
            }));
        }
        Ok(accepted_batch(batch.len()))
    });
    assert_eq!(result.unwrap(), ResumableUploadResult::Completed);
    assert_eq!(batches.len(), 2, "one failed attempt, one sibling retry");
    assert_eq!(batches[1].len(), 2);
    for item in &items {
        assert_eq!(
            progress.accepted_fingerprints.contains(&item.fingerprint),
            item.fingerprint != poison,
        );
    }
    assert!(progress.quarantined_fingerprints.contains_key(&poison));
}

#[test]
fn e2_literal_batch_validation_error_splits_instead_of_stalling() {
    // A whole-batch 422 naming the snapshots list: the existing splitter
    // isolates the bad body; healthy families and plain bodies settle.
    let mut items = family("root-e", 4, 0);
    items.push(plain_item(7));
    let poison = items[2].fingerprint.clone();
    let mut progress = test_upload_progress();
    let (result, _) = upload_families(&items, &mut progress, |batch| {
        if batch.iter().any(|item| item.fingerprint == poison) {
            return Err(anyhow::Error::new(BatchRejected {
                status: 422,
                body_excerpt: Some(r#"{"detail":[{"loc":["body","snapshots",0]}]}"#.into()),
            }));
        }
        Ok(accepted_batch(batch.len()))
    });
    assert!(result.is_err(), "the poison body is reported, not hidden");
    for item in &items {
        assert_eq!(
            progress.accepted_fingerprints.contains(&item.fingerprint),
            item.fingerprint != poison,
            "{}",
            item.session
        );
    }
}

#[test]
fn e2_partial_entity_ack_settles_only_acknowledged_members() {
    let items = family("root-f", 2, 0);
    let (root, agent) = (items[0].fingerprint.clone(), items[1].fingerprint.clone());
    let mut progress = test_upload_progress();
    let (result, batches) = upload_families(&items, &mut progress, |_| {
        Ok(entity_ack_batch(
            std::slice::from_ref(&root),
            &[],
            std::slice::from_ref(&agent),
        ))
    });
    assert_eq!(batches.len(), 1, "the family travels together");
    assert_eq!(
        result.unwrap(),
        ResumableUploadResult::Deferred { count: 1 }
    );
    assert!(progress.accepted_fingerprints.contains(&root));
    assert!(!progress.accepted_fingerprints.contains(&agent));
    assert!(
        progress.quarantined_fingerprints.contains_key(&agent),
        "the conflicted member waits for its bounded retry, never dropped"
    );
}

#[test]
fn e2_transient_failure_resends_the_exact_literal_bytes() {
    // The retry copy keeps every literal member, so the resend's bytes,
    // fingerprint and body witness equal the first attempt's.
    let mut item = crate::snapshots::cache_adapter_tests::cache_fixture_item();
    item.cache_observations = None;
    item.cache_base_head_etag = None;
    item.usage_accounting_contract = Some(crate::snapshots::REQUEST_OWNED_USAGE_CONTRACT.into());
    item.removed_request_count = Some(3);
    item.removed_usage = Some(crate::snapshots::ClaudeRemovedUsage {
        input_tokens: 11,
        output_tokens: 7,
        cache_read_tokens: 5,
        cache_creation_5m_tokens: 3,
        cache_creation_1h_tokens: 2,
        unattributed_total_tokens: 1,
        reasoning_output_tokens: 4,
    });
    item.telemetry_owned_complete = Some(false);
    item.snapshot_fingerprint =
        crate::snapshots::snapshot_fingerprint(SnapshotSource::ClaudeCode, &item);
    let copy = retry_ordinary_owned(&item).expect("ordinary owned item has a retry copy");
    assert_eq!(
        serde_json::to_vec(&copy).unwrap(),
        serde_json::to_vec(&item).unwrap()
    );
    assert_eq!(copy.snapshot_fingerprint, item.snapshot_fingerprint);
    assert_eq!(
        snapshot_upload_body_witness(&copy),
        snapshot_upload_body_witness(&item)
    );

    let items = vec![item];
    let mut sent = Vec::new();
    let mut progress = test_upload_progress();
    for attempt in 0..2 {
        let mut accepted = 0;
        let result = upload_resumable_batches_with_literal_families(
            &items,
            &unique_poison_scope(),
            &mut progress,
            &mut accepted,
            |item| item.snapshot_fingerprint.as_str(),
            snapshot_upload_body_witness,
            |item| Some(item.source_session_id.as_str()),
            |_| false,
            crate::snapshots::claude_request_money::request_owned_family_root,
            crate::snapshots::history_segments::history_group,
            &mut InplaceRetryBudget::default(),
            |batch| {
                sent.push(serde_json::to_vec(&batch).unwrap());
                if attempt == 0 {
                    Err(anyhow!("transient transport failure"))
                } else {
                    Ok(accepted_batch(batch.len()))
                }
            },
            |_| Ok(()),
        );
        assert_eq!(result.is_ok(), attempt == 1);
    }
    assert_eq!(sent.len(), 2);
    assert_eq!(sent[0], sent[1], "identical bytes on the resend");
}
