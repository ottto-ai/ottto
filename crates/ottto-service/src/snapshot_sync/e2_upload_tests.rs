// `e2` upload path: request-owned families, literal batch errors, retry bytes.
// Included into `snapshot_sync::tests`; uses its helpers.

#[derive(Clone, Serialize)]
struct FamilyItem {
    fingerprint: String,
    session: String,
    payload: String,
    #[serde(skip)]
    root: Option<String>,
    /// Main-upload batch class: 0 ordinary, 1 cache-patched, 2 legacy.
    #[serde(skip)]
    class: u8,
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
        class: 0,
    }
}

fn plain_item(ordinal: u64) -> FamilyItem {
    FamilyItem {
        fingerprint: format!("{ordinal:064x}"),
        session: format!("plain-{ordinal}"),
        payload: String::new(),
        root: None,
        class: 0,
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
    upload_resumable_batches_with_literal_families(
        &items,
        &unique_poison_scope(),
        &mut test_upload_progress(),
        &mut accepted,
        |item| item.fingerprint.as_str(),
        |item| item.fingerprint.clone(),
        |item| Some(item.session.as_str()),
        |item| item.class,
        |_| None,
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
fn e2_literal_batch_validation_error_holds_entity_and_settles_siblings() {
    // Validated entity-local locations hold the bad body durably;
    // healthy family members and plain bodies still settle on their own ACKs.
    let mut items = family("root-e", 4, 0);
    items.push(plain_item(7));
    let poison = items[2].fingerprint.clone();
    let mut progress = test_upload_progress();
    let (result, _) = upload_families(&items, &mut progress, |batch| {
        if let Some(index) = batch.iter().position(|item| item.fingerprint == poison) {
            return Err(anyhow::Error::new(BatchRejected::from_response(
                422,
                serde_json::json!({"errors":[{"loc":["body","snapshots",index]}]})
                    .to_string()
                    .as_bytes(),
                batch.len(),
            )));
        }
        Ok(accepted_batch(batch.len()))
    });
    assert_eq!(
        result.unwrap(),
        ResumableUploadResult::Deferred { count: 1 }
    );
    assert!(progress.quarantined_fingerprints.contains_key(&poison));
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
            |_| 0,
            crate::snapshots::claude_request_money::request_owned_family_root,
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

/// [format] A server that still advertises the retired recorded-login
/// capability is ignored: its hint decodes as before, and request evidence
/// keeps its existing wire bytes.
#[test]
fn sole_login_hint_token_is_ignored() {
    let mut raw = serde_json::json!({
        "source": SnapshotSource::ClaudeCode.api_slug(),
        "server_time": "2026-10-24T00:00:00Z",
        "last_data_at": null,
        "record_count_15m": 0,
        "record_count_24h": 0,
        "local_usage_reconciliation_enabled": true,
        "backfill_window_days": 30,
        "recommended_scan_after": "2026-10-24T00:05:00Z",
    });
    assert!(crate::snapshot_client::decode_activity_hint(raw.clone()).is_ok());
    raw["session_request_sole_login_witness_contract"] =
        "session_request_sole_login_witness:v1".into();
    assert!(crate::snapshot_client::decode_activity_hint(raw).is_ok());
    let entry = crate::snapshots::SnapshotRequestEvidence {
        identity_basis: "transcript_org".to_string(),
        provider_workspace_hash: Some("d".repeat(64)),
        account_source: None,
    };
    assert_eq!(
        serde_json::to_value(&entry).unwrap(),
        serde_json::json!({
            "identity_basis": "transcript_org",
            "provider_workspace_hash": "d".repeat(64),
        })
    );
}

/// The client declares head CAS for a whole request when one body in it
/// carries a cache patch. A synthetic server with that rule: under CAS, an
/// unpatched body of a session the server already holds conflicts.
fn cas_server(
    batch: &[FamilyItem],
    held: &BTreeSet<String>,
    seen: &mut Vec<(u8, Vec<String>)>,
) -> Result<crate::snapshot_client::SnapshotBatchResponse> {
    let class = batch[0].class;
    assert!(
        batch.iter().all(|item| item.class == class),
        "a request is class-pure"
    );
    seen.push((
        class,
        batch.iter().map(|item| item.session.clone()).collect(),
    ));
    let cas = batch.iter().any(|item| item.class != 0);
    let (conflicted, accepted): (Vec<&FamilyItem>, Vec<&FamilyItem>) = batch
        .iter()
        .partition(|item| cas && item.class == 0 && held.contains(&item.session));
    let ids = |items: Vec<&FamilyItem>| {
        items
            .into_iter()
            .map(|item| item.fingerprint.clone())
            .collect::<Vec<_>>()
    };
    Ok(entity_ack_batch(&ids(accepted), &[], &ids(conflicted)))
}

fn with_class(mut item: FamilyItem, class: u8) -> FamilyItem {
    item.class = class;
    item
}

/// [money] M2: a literal family whose root and members differ in patch class
/// (patched root with unpatched members, and the reverse) is cut into
/// class-pure groups that stay contiguous and root first. Each group settles
/// by its own ACKs, and no unpatched member is sent under CAS.
#[test]
fn e2_mixed_class_family_is_class_pure_root_first_in_both_directions() {
    for root_class in [1u8, 0] {
        let member_class = 1 - root_class;
        let mut family = family("root-m", 4, 0);
        family[0].class = root_class;
        family[2].class = member_class;
        family[3].class = member_class;
        let mut items = vec![
            with_class(plain_item(1), 1),
            with_class(plain_item(2), 0),
            with_class(plain_item(3), 1),
        ];
        items.extend(family.iter().cloned());
        // Every session already has a server head: CAS on an unpatched,
        // base-less body would conflict.
        let held = items.iter().map(|item| item.session.clone()).collect();
        let mut seen = Vec::new();
        let mut progress = test_upload_progress();
        let (result, batches) = upload_families(&items, &mut progress, |batch| {
            cas_server(batch, &held, &mut seen)
        });
        assert_eq!(
            result.unwrap(),
            ResumableUploadResult::Completed,
            "root class {root_class}"
        );
        for item in &items {
            assert!(
                progress.accepted_fingerprints.contains(&item.fingerprint),
                "{}",
                item.session
            );
        }
        // Family groups: contiguous, root first, members in session order.
        let flat = batches.concat();
        let first = flat.iter().position(|s| s == "root-m").unwrap();
        assert_eq!(
            flat[first..first + 4],
            family
                .iter()
                .map(|item| item.session.clone())
                .collect::<Vec<_>>()[..],
            "family contiguous and root first"
        );
        // The family's own groups follow its root's class run; singles are
        // grouped by class, ordinary first.
        let classes = seen.iter().map(|(class, _)| *class).collect::<Vec<_>>();
        let expected = if root_class == 1 {
            vec![0, 1, 0]
        } else {
            vec![0, 1]
        };
        assert_eq!(classes, expected, "root class {root_class}: {seen:?}");
        let single_runs = seen
            .iter()
            .filter(|(_, sessions)| sessions.iter().any(|s| s.starts_with("plain-")))
            .count();
        assert_eq!(single_runs, 2, "one run per class for single bodies");
    }
}

/// [money] Before the split, one patched sibling made the whole request CAS
/// and the unpatched, base-less siblings conflicted. The same page under the
/// production class now sends two class-pure requests and conflicts nothing.
#[test]
fn e2_mixed_page_no_longer_sends_unpatched_bodies_under_cas() {
    let items = vec![
        with_class(plain_item(1), 1),
        with_class(plain_item(2), 0),
        with_class(plain_item(3), 0),
    ];
    let held = items
        .iter()
        .map(|item| item.session.clone())
        .collect::<BTreeSet<_>>();
    // The previous single class: one CAS request; unpatched bodies conflict.
    let mut accepted = 0;
    let mut progress = test_upload_progress();
    let result = upload_resumable_batches_with_literal_families(
        &items,
        &unique_poison_scope(),
        &mut progress,
        &mut accepted,
        |item| item.fingerprint.as_str(),
        |item| item.fingerprint.clone(),
        |item| Some(item.session.as_str()),
        |_| 0,
        |_| None,
        &mut InplaceRetryBudget::default(),
        |batch| {
            let cas = batch.iter().any(|item| item.class != 0);
            let (conflicted, accepted): (Vec<_>, Vec<_>) = batch
                .iter()
                .partition(|item| cas && item.class == 0 && held.contains(&item.session));
            let ids = |items: Vec<&FamilyItem>| {
                items
                    .into_iter()
                    .map(|item| item.fingerprint.clone())
                    .collect::<Vec<_>>()
            };
            Ok(entity_ack_batch(&ids(accepted), &[], &ids(conflicted)))
        },
        |_| Ok(()),
    );
    assert_eq!(
        result.unwrap(),
        ResumableUploadResult::Deferred { count: 2 }
    );
    // The production class: no conflicts.
    let mut seen = Vec::new();
    let mut progress = test_upload_progress();
    let (result, batches) = upload_families(&items, &mut progress, |batch| {
        cas_server(batch, &held, &mut seen)
    });
    assert_eq!(result.unwrap(), ResumableUploadResult::Completed);
    assert_eq!(
        batches,
        vec![
            vec!["plain-2".to_owned(), "plain-3".to_owned()],
            vec!["plain-1".to_owned()]
        ]
    );
}

/// E2: a single-class page (Pi, an all-patched page, or all ordinary) is
/// packed exactly as before the class split: same requests, same order.
#[test]
fn e2_single_class_pages_keep_the_previous_batches() {
    for class in [0u8, 1, 2] {
        let mut items = (0..60).rev().map(plain_item).collect::<Vec<_>>();
        items.extend(family("root-s", 5, 0));
        items.extend(family("root-t", 3, 0));
        for item in &mut items {
            item.class = class;
        }
        let (result, batches) = upload_families(&items, &mut test_upload_progress(), accept_all);
        assert_eq!(result.unwrap(), ResumableUploadResult::Completed);
        let mut previous = Vec::new();
        let mut accepted = 0;
        upload_resumable_batches_with_literal_families(
            &items,
            &unique_poison_scope(),
            &mut test_upload_progress(),
            &mut accepted,
            |item| item.fingerprint.as_str(),
            |item| item.fingerprint.clone(),
            |item| Some(item.session.as_str()),
            |_| 0,
            |item| item.root.as_deref(),
            &mut InplaceRetryBudget::default(),
            |batch| {
                previous.push(
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
        assert_eq!(batches, previous, "class {class}");
    }
}

/// [money] R3x: the first class request checkpoints; the second is unsent,
/// loses its ACK after the server stored it, or its checkpoint save fails.
/// After a restart from the saved ledger only unsettled bodies are re-sent;
/// a replay of a stored body is an exact repeat (unchanged), so nothing is
/// stored or credited twice. Both class orders: ordinary before patched, and
/// patched before legacy.
#[test]
fn e2_class_request_lost_after_a_checkpoint_resends_only_unsettled_bodies() {
    for (first, second) in [(0u8, 1u8), (1, 2)] {
        for (lost, save_fails) in [(second, false), (first, false), (second, true)] {
            let items = vec![
                with_class(plain_item(1), second),
                with_class(plain_item(2), first),
                with_class(plain_item(3), second),
                with_class(plain_item(4), first),
            ];
            let root = crate::test_scratch::ScratchDir::new("e2-class-lost");
            let path = root.join("progress.json");
            let mut progress = test_upload_progress();
            progress.save(&path).unwrap();
            // The server stores each new body once; a stored body is unchanged.
            let stored = std::cell::RefCell::new(BTreeMap::<String, usize>::new());
            let serve = |batch: &[FamilyItem]| {
                let mut stored = stored.borrow_mut();
                let (mut accepted, mut unchanged) = (Vec::new(), Vec::new());
                for item in batch {
                    if stored.contains_key(&item.fingerprint) {
                        unchanged.push(item.fingerprint.clone());
                    } else {
                        stored.insert(item.fingerprint.clone(), 1);
                        accepted.push(item.fingerprint.clone());
                    }
                }
                entity_ack_batch(&accepted, &unchanged, &[])
            };
            let mut accepted = 0;
            let mut sent = Vec::new();
            let result = upload_resumable_batches_with_literal_families(
                &items,
                &unique_poison_scope(),
                &mut progress,
                &mut accepted,
                |item| item.fingerprint.as_str(),
                |item| item.fingerprint.clone(),
                |item| Some(item.session.as_str()),
                |item| item.class,
                |_| None,
                &mut InplaceRetryBudget::default(),
                |batch| {
                    sent.push(batch[0].class);
                    let response = serve(&batch);
                    if batch[0].class == lost && !save_fails {
                        return Err(anyhow!("synthetic lost reply"));
                    }
                    Ok(response)
                },
                |state| {
                    let saving_lost = items
                        .iter()
                        .filter(|item| item.class == lost)
                        .all(|item| state.accepted_fingerprints.contains(&item.fingerprint));
                    if save_fails && saving_lost {
                        return Err(anyhow!("synthetic save failure"));
                    }
                    state.save(&path)
                },
            );
            let case = format!("{first}->{second} lost {lost} save_fails {save_fails}");
            assert!(result.is_err(), "{case}");
            let expected_sent = if lost == first {
                vec![first]
            } else {
                vec![first, second]
            };
            assert_eq!(sent, expected_sent, "{case}: lower class first");
            let mut restarted = SnapshotUploadProgress::load(
                &path,
                &format!("{:064x}", 99),
                snapshot_quarantine_witness(SnapshotSource::Codex),
            )
            .unwrap();
            for item in &items {
                assert_eq!(
                    restarted.accepted_fingerprints.contains(&item.fingerprint),
                    lost == second && item.class == first,
                    "{case}: {}",
                    item.session
                );
            }
            let mut resent = Vec::new();
            let (result, _) = upload_families(&items, &mut restarted, |batch| {
                resent.extend(batch.iter().map(|item| item.session.clone()));
                Ok(serve(batch))
            });
            assert_eq!(result.unwrap(), ResumableUploadResult::Completed, "{case}");
            let mut expected = items
                .iter()
                .filter(|item| lost == first || item.class == second)
                .map(|item| item.session.clone())
                .collect::<Vec<_>>();
            expected.sort();
            resent.sort();
            assert_eq!(resent, expected, "{case}: only unsettled bodies, once");
            assert!(
                stored.borrow().values().all(|count| *count == 1),
                "{case}: no body stored twice"
            );
            assert_eq!(stored.borrow().len(), items.len(), "{case}");
            for item in &items {
                assert!(restarted.accepted_fingerprints.contains(&item.fingerprint));
            }
            // A repeat pass sends no POST.
            let (result, batches) = upload_families(&items, &mut restarted, |_| {
                panic!("a settled page sends no POST")
            });
            assert_eq!(result.unwrap(), ResumableUploadResult::Completed);
            assert!(batches.is_empty());
        }
    }
}
