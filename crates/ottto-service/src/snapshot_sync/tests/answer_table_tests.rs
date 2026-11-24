// One row per kind of answer to a snapshot page, at the page and the pass
// seam: what the page or the pass returns, and the whole upload ledger it
// leaves, compared as one serialized value, in memory and as last handed to
// the save callback (the callback is a test double: no file is written).
// Bodies are the synthetic fingerprint strings of `test_fingerprints`; every
// answer is a typed response or error built here and fed through the upload
// callback, so no server runs and "posts" counts callback attempts. The retry
// clock and the in-place resend clock are pinned, so every timer is exact.
//
// "held(n, D, t)" is a quarantine record with reconstruction count n,
// disposition D (RP = RetryPending, UT = UnprovenTerminal) and retry time t;
// "6h" is `quarantine_retry_after`, "probe" is `conflict_probe_after`.
//
// One page, `attempt_snapshot_page`:
//  1. accepted, head          -> settled 0/0; accepted body, head saved
//  2. accepted, no head       -> settled 0/0; accepted body, saved head dropped
//  3. unchanged, no basis     -> settled 0/0; accepted body, saved head kept
//  4. unchanged usage_identical  -> settled 0/0; held(4, UT, 0), nothing accepted
//  5. unchanged dominated_by_head, head -> as 4, and the head is saved
//  6. unchanged for a refused stale body still owed -> held(1, RP, 6h), refusal kept
//  7. permanent, known reason -> settled 0/0; held(4, UT, 0) + refusal, no re-offer
//  8. permanent original_pair_candidate_unproved -> refusal `other`, re-offer in 24 h
//  9. permanent `other`       -> refusal `other`, classified (never re-offered)
// 10. retryable accepted_log_stale_older_mixed -> settled 1/1; held(1, RP, 6h)
// 11. retryable usage-decrease hold -> settled 1/0; held(1, RP, 6h)
// 12. conflict, new challenge -> settled 1/1; held(1, RP, now), challenge saved
// 13. conflict, same challenge answered again -> held(1, RP, probe), attempt counted
// 14. conflict on a contract re-arm -> held(3, RP, 6h), its claim kept
// 15. mixed page (accepted, unchanged, two retryable, permanent, conflict)
//     -> settled 3/2 and each entity's row as in 1, 3, 10, 11, 9 and the probe of 13
// 16. ACK omits a sent entity, validator in the callback -> its error; nothing saved
// 17. the same ACK with no validator -> the page settles what it names; the
//     omitted body gets no row (the page trusts its callback's validation)
// 18. disabled                -> Disabled(reason); nothing saved
// 19. no ACK contract         -> SnapshotAckRejected; nothing saved
// 20. unsupported ACK contract -> SnapshotAckRejected; nothing saved
// 21. the page's own save fails -> SnapshotLocalStateRejected; the ledger in
//     memory keeps the ACK (no rollback), nothing durable
//
// One pass, the page loop (`upload_resumable_batches_with_body_witness`):
// 22. local preflight names item 0 -> held(1, RP, 6h); sibling resent, accepted; Completed
// 23. local preflight on held bodies at count 2 and 3 -> held(3, RP, 6h) and
//     held(4, UT, 0): the fourth failure is terminal; Completed
// 24. validation 422 naming item 0 -> held(1, RP, 6h); sibling accepted; Deferred 1/0/0
// 25. ACK body witness refused for item 0 -> as 24
// 26. identity-unavailable 503 naming item 0 -> held(1, RP, now + Retry-After);
//     sibling accepted; Deferred 1/1/1
// 27. identity-unavailable 503 naming the whole page -> both held; Deferred 2/2/2
// 28. plain shed with a long Retry-After -> Shed(Retry-After); nothing saved
// 29. 413 on a single item     -> that error; nothing saved
// 30. 504 deadline             -> split in two, both accepted; Completed
// 31. fast 500                 -> one in-place resend, both accepted; Completed
// 32. transport outage         -> that error; nothing saved here (outage
//     custody is written by the caller, not by this loop)
// 33. permanent refusal        -> held(4, UT, 0) + refusal; Rejected 1
// 34. disabled                 -> Disabled(reason); nothing saved
//
// Not pinned here: an unchanged answer to a current-context re-offer (it needs
// the source pass's receipt candidates, which this seam does not build), and
// the freshness walk's `usage_identical` note across a restart (process-only
// state read inside the snapshots module).
use super::*;
use crate::snapshot_client::{
    SnapshotBatchResponse, SnapshotConflictRescan, SnapshotEntityRef, SnapshotEntityRejection,
};
use crate::snapshot_sync::progress_rows::HeadConflictChallenge;
use crate::snapshot_sync::reason_reoffer::{RefusalReoffer, REOFFER_INTERVAL_SECONDS};
use crate::upload_receipts::RejectedUsageReason;
use serde_json::Value;

const NOW: u64 = 1_800_000_000;
const RP: SnapshotQuarantineDisposition = SnapshotQuarantineDisposition::RetryPending;
const UT: SnapshotQuarantineDisposition = SnapshotQuarantineDisposition::UnprovenTerminal;
const MIXED: &str = "accepted_log_stale_older_mixed";
const HOLD: &str = "usage_decrease_held_for_review";
const TOO_BIG: &str = "body_exceeds_max_bytes";

type Seed = fn(&mut SnapshotUploadProgress, &[String]);
type Answer = Result<SnapshotBatchResponse>;

fn ledger(progress: &SnapshotUploadProgress) -> Value {
    serde_json::to_value(progress).unwrap()
}

fn witness(fingerprint: &str) -> String {
    format!("body-{fingerprint}")
}

fn hex(digit: char) -> String {
    digit.to_string().repeat(64)
}

/// The saved-head and challenge key of `entity_ack_ref`'s session.
fn session_key(fingerprint: &str) -> String {
    cache_session_key(&format!("session-{fingerprint}"))
}

fn head(fingerprint: &str) -> SnapshotEntityRef {
    SnapshotEntityRef {
        head_etag: Some(hex('e')),
        ..entity_ack_ref(fingerprint)
    }
}

fn unstored(fingerprint: &str, basis: &str) -> SnapshotEntityRef {
    SnapshotEntityRef {
        unchanged_basis: Some(basis.into()),
        ..entity_ack_ref(fingerprint)
    }
}

fn refusal(fingerprint: &str, reason: &str, permanent: bool) -> SnapshotEntityRejection {
    SnapshotEntityRejection {
        source_session_id: format!("session-{fingerprint}"),
        snapshot_fingerprint: fingerprint.into(),
        reason: reason.into(),
        detail: String::new(),
        permanent,
        occurrence_count: 1,
    }
}

fn answer(
    accepted: Vec<SnapshotEntityRef>,
    unchanged: Vec<SnapshotEntityRef>,
    rejected: Vec<SnapshotEntityRejection>,
    conflict: Vec<SnapshotEntityRef>,
) -> SnapshotBatchResponse {
    let count = (accepted.len() + unchanged.len()) as u64;
    SnapshotBatchResponse {
        accepted_entities: accepted,
        unchanged_entities: unchanged,
        rejected_entities: rejected,
        conflict_entities: conflict,
        ..entity_ack_response(count)
    }
}

fn accepted(entity: SnapshotEntityRef) -> Answer {
    Ok(answer(vec![entity], vec![], vec![], vec![]))
}

fn unchanged(entity: SnapshotEntityRef) -> Answer {
    Ok(answer(vec![], vec![entity], vec![], vec![]))
}

fn rejected(fingerprint: &str, reason: &str, permanent: bool) -> Answer {
    let refusal = refusal(fingerprint, reason, permanent);
    Ok(answer(vec![], vec![], vec![refusal], vec![]))
}

fn disabled() -> Answer {
    Ok(SnapshotBatchResponse {
        disabled: true,
        disabled_reason: Some("paused".into()),
        ..entity_ack_response(0)
    })
}

fn contract(version: Option<&str>, fingerprint: &str) -> Answer {
    Ok(SnapshotBatchResponse {
        entity_ack_contract: version.map(Into::into),
        ..answer(vec![entity_ack_ref(fingerprint)], vec![], vec![], vec![])
    })
}

/// A conflict on `fingerprint` carrying a head challenge over the refused
/// body's revision, as the network boundary binds it.
fn challenged(fingerprint: &str, answered: bool) -> Answer {
    let entity = SnapshotEntityRef {
        head_challenge: Some(hex('c')),
        ..entity_ack_ref(fingerprint)
    };
    let mut response = answer(vec![], vec![], vec![], vec![entity]);
    response.conflict_rescans.insert(
        fingerprint.into(),
        SnapshotConflictRescan {
            revision_v2_hash: hex('d'),
            answered,
        },
    );
    Ok(response)
}

fn challenge(attempts: u32, last_answer: u64) -> HeadConflictChallenge {
    HeadConflictChallenge {
        challenge: hex('c'),
        stale_revision_v2_hash: hex('d'),
        answer_attempts: attempts,
        last_answer_unix: last_answer,
    }
}

fn accept(progress: &mut SnapshotUploadProgress, fingerprint: &str) {
    progress.accepted_fingerprints.insert(fingerprint.into());
    progress
        .accepted_body_witnesses
        .insert(fingerprint.into(), witness(fingerprint));
}

fn held(
    progress: &mut SnapshotUploadProgress,
    fingerprint: &str,
    count: u8,
    disposition: SnapshotQuarantineDisposition,
    retry_after: u64,
    claims: Option<u16>,
) {
    let record = SnapshotQuarantineRecord {
        reconstruction_contract: crate::snapshots::terminal_contract_retry::current_contract(),
        contract_retry_claims: claims,
        witness: progress.active_quarantine_witness.clone().unwrap(),
        retry_after_unix_seconds: retry_after,
        upload_body_witness: Some(witness(fingerprint)),
        failed_reconstruction_count: count,
        disposition,
    };
    progress
        .quarantined_fingerprints
        .insert(fingerprint.into(), record);
}

/// A retryable hold with the ordinary 6 h timer.
fn held_6h(progress: &mut SnapshotUploadProgress, fingerprint: &str) {
    held(
        progress,
        fingerprint,
        1,
        RP,
        quarantine_retry_after(fingerprint),
        None,
    );
}

fn refused(
    progress: &mut SnapshotUploadProgress,
    fingerprint: &str,
    reason: RejectedUsageReason,
    reoffer: Option<RefusalReoffer>,
) {
    held(progress, fingerprint, 4, UT, 0, None);
    progress.permanent_rejections.insert(
        fingerprint.into(),
        PermanentSnapshotRejection {
            body_witness: witness(fingerprint),
            reason,
            reoffer,
            exposure: Some(crate::snapshot_sync::stale_owed::Exposure::new(NOW)),
            revisions: BTreeMap::new(),
        },
    );
}

#[derive(Debug, PartialEq)]
enum Page {
    Settled(usize, usize),
    Disabled(Option<String>),
    AckRejected(&'static str),
    LocalState(&'static str),
    Failed(String),
}

struct PageRow {
    name: &'static str,
    items: usize,
    seed: Seed,
    answer: fn(&[&String]) -> Answer,
    persist_fails: bool,
    outcome: Page,
    /// The ledger after the page, applied to a copy of the seeded one.
    want: Seed,
}

impl PageRow {
    /// One body, nothing seeded, a working save.
    fn new(
        name: &'static str,
        answer: fn(&[&String]) -> Answer,
        outcome: Page,
        want: Seed,
    ) -> Self {
        Self {
            name,
            items: 1,
            seed: |_, _| {},
            answer,
            persist_fails: false,
            outcome,
            want,
        }
    }

    fn seed(self, seed: Seed) -> Self {
        Self { seed, ..self }
    }

    fn items(self, items: usize) -> Self {
        Self { items, ..self }
    }
}

fn run_page(row: &PageRow) {
    let items = test_fingerprints(row.items);
    let mut progress = test_upload_progress();
    (row.seed)(&mut progress, &items);
    let before = ledger(&progress);
    let mut want = progress.clone();
    (row.want)(&mut want, &items);
    let indices = (0..items.len()).collect::<Vec<_>>();
    let mut saves = Vec::new();
    let mut answer = row.answer;
    let result = attempt_snapshot_page(
        &items,
        &indices,
        &unique_poison_scope(),
        &mut progress,
        &mut 0,
        &|item: &String| item.as_str(),
        &|item: &String| witness(item),
        &|item: &String| Some(item.as_str()),
        &mut answer,
        &mut |state: &mut SnapshotUploadProgress| {
            saves.push(ledger(state));
            if row.persist_fails {
                Err(anyhow!("synthetic progress save failure"))
            } else {
                Ok(())
            }
        },
    );
    let observed = match result {
        Ok(SnapshotPageOutcome::Settled {
            conflicted,
            isolated,
        }) => Page::Settled(conflicted, isolated),
        Ok(SnapshotPageOutcome::Disabled(reason)) => Page::Disabled(reason),
        Err(error) => match (
            error.downcast_ref::<SnapshotAckRejected>(),
            error.downcast_ref::<SnapshotLocalStateRejected>(),
        ) {
            (Some(rejected), _) => Page::AckRejected(rejected.reason),
            (None, Some(local)) => Page::LocalState(local.operation),
            (None, None) => Page::Failed(error.to_string()),
        },
    };
    let name = row.name;
    assert_eq!(observed, row.outcome, "{name}: outcome");
    // One settlement save per answered page; no row seeds a due retry, so
    // the pacing save never runs.
    let saved = matches!(row.outcome, Page::Settled(..)) || row.persist_fails;
    assert_eq!(saves.len(), usize::from(saved), "{name}: saves");
    assert_eq!(ledger(&progress), ledger(&want), "{name}: ledger in memory");
    // What the page last handed to the save callback, also when that save
    // then fails; a page that saves nothing leaves the seeded ledger.
    let handed = saves.last().unwrap_or(&before);
    assert_eq!(handed, &ledger(&want), "{name}: last save argument");
}

/// Rows 1 to 21. A permanent refusal counts a poison loss in the client report.
#[test]
#[serial(client_report)]
fn every_page_answer_stores_its_exact_ledger_rows() {
    let _clock = crate::snapshot_sync::tests::permanent_finish_pipeline_tests::prior_index_lifetime_tests::Guard::new(false, None, Some(NOW));
    let saved_head: Seed = |p, f| {
        p.accepted_cache_heads.insert(session_key(&f[0]), hex('a'));
    };
    let rows = [
        PageRow::new(
            "1 accepted, head",
            |b| accepted(head(b[0])),
            Page::Settled(0, 0),
            |p, f| {
                accept(p, &f[0]);
                p.accepted_cache_heads.insert(session_key(&f[0]), hex('e'));
            },
        ),
        PageRow::new(
            "2 accepted, no head",
            |b| accepted(entity_ack_ref(b[0])),
            Page::Settled(0, 0),
            |p, f| {
                accept(p, &f[0]);
                p.accepted_cache_heads.remove(&session_key(&f[0]));
            },
        )
        .seed(saved_head),
        PageRow::new(
            "3 unchanged, no basis",
            |b| unchanged(entity_ack_ref(b[0])),
            Page::Settled(0, 0),
            |p, f| accept(p, &f[0]),
        )
        .seed(saved_head),
        PageRow::new(
            "4 unchanged usage_identical",
            |b| unchanged(unstored(b[0], "usage_identical")),
            Page::Settled(0, 0),
            |p, f| held(p, &f[0], 4, UT, 0, None),
        ),
        PageRow::new(
            "5 unchanged dominated_by_head",
            |b| {
                unchanged(SnapshotEntityRef {
                    head_etag: Some(hex('e')),
                    ..unstored(b[0], "dominated_by_head")
                })
            },
            Page::Settled(0, 0),
            |p, f| {
                held(p, &f[0], 4, UT, 0, None);
                p.accepted_cache_heads.insert(session_key(&f[0]), hex('e'));
            },
        ),
        PageRow::new(
            "6 unchanged for an owed stale body",
            |b| unchanged(unstored(b[0], "usage_identical")),
            Page::Settled(0, 0),
            |p, f| held_6h(p, &f[0]),
        )
        .seed(|p, f| {
            // A fresh stale refusal without exposure still owes an answer.
            let refusal = PermanentSnapshotRejection {
                body_witness: witness(&f[0]),
                reason: RejectedUsageReason::AcceptedLogStaleOlderUpload,
                reoffer: None,
                exposure: None,
                revisions: BTreeMap::new(),
            };
            p.permanent_rejections.insert(f[0].clone(), refusal);
        }),
        PageRow::new(
            "7 permanent, known reason",
            |b| rejected(b[0], TOO_BIG, true),
            Page::Settled(0, 0),
            |p, f| refused(p, &f[0], RejectedUsageReason::BodyExceedsMaxBytes, None),
        ),
        PageRow::new(
            "8 permanent original_pair_candidate_unproved",
            |b| rejected(b[0], "original_pair_candidate_unproved", true),
            Page::Settled(0, 0),
            |p, f| {
                let retry_after_unix_seconds = NOW + REOFFER_INTERVAL_SECONDS;
                let reoffer = RefusalReoffer::OriginalPair {
                    retry_after_unix_seconds,
                };
                refused(p, &f[0], RejectedUsageReason::Other, Some(reoffer));
            },
        ),
        PageRow::new(
            "9 permanent other",
            |b| rejected(b[0], "other", true),
            Page::Settled(0, 0),
            |p, f| {
                refused(
                    p,
                    &f[0],
                    RejectedUsageReason::Other,
                    Some(RefusalReoffer::Classified),
                )
            },
        ),
        PageRow::new(
            "10 retryable stale mixed",
            |b| rejected(b[0], MIXED, false),
            Page::Settled(1, 1),
            |p, f| held_6h(p, &f[0]),
        ),
        PageRow::new(
            "11 retryable usage-decrease hold",
            |b| rejected(b[0], HOLD, false),
            Page::Settled(1, 0),
            |p, f| held_6h(p, &f[0]),
        ),
        PageRow::new(
            "12 conflict, new challenge",
            |b| challenged(b[0], false),
            Page::Settled(1, 1),
            |p, f| {
                held(p, &f[0], 1, RP, NOW, None);
                p.head_conflict_challenges
                    .insert(session_key(&f[0]), challenge(0, 0));
            },
        ),
        PageRow::new(
            "13 conflict, same challenge answered again",
            |b| challenged(b[0], true),
            Page::Settled(1, 1),
            |p, f| {
                held(p, &f[0], 1, RP, conflict_probe_after(&f[0], NOW), None);
                p.head_conflict_challenges
                    .insert(session_key(&f[0]), challenge(1, NOW));
            },
        )
        .seed(|p, f| {
            p.head_conflict_challenges
                .insert(session_key(&f[0]), challenge(0, 0));
        }),
        PageRow::new(
            "14 conflict on a contract re-arm",
            |b| Ok(answer(vec![], vec![], vec![], vec![entity_ack_ref(b[0])])),
            Page::Settled(1, 1),
            |p, f| held(p, &f[0], 3, RP, quarantine_retry_after(&f[0]), Some(1)),
        )
        .seed(|p, f| held(p, &f[0], 3, RP, 0, Some(1))),
        // conflicted = 1 conflict + 2 retryable; isolated = 1 conflict + the
        // one ordinary retryable reason. Each entity's row is its own row's.
        PageRow::new(
            "15 mixed page",
            |b| {
                Ok(answer(
                    vec![entity_ack_ref(b[0])],
                    vec![entity_ack_ref(b[1])],
                    vec![
                        refusal(b[2], MIXED, false),
                        refusal(b[3], HOLD, false),
                        refusal(b[4], "other", true),
                    ],
                    vec![entity_ack_ref(b[5])],
                ))
            },
            Page::Settled(3, 2),
            |p, f| {
                accept(p, &f[0]);
                accept(p, &f[1]);
                held_6h(p, &f[2]);
                held_6h(p, &f[3]);
                refused(
                    p,
                    &f[4],
                    RejectedUsageReason::Other,
                    Some(RefusalReoffer::Classified),
                );
                held(p, &f[5], 1, RP, conflict_probe_after(&f[5], NOW), None);
            },
        )
        .items(6),
        PageRow::new(
            "16 ACK omits a sent entity, validated",
            |b| {
                let response = accepted(entity_ack_ref(b[0]))?;
                let sent = b.iter().map(|f| (format!("session-{f}"), f.to_string()));
                let sent = sent.collect::<Vec<_>>();
                response.validate_entity_ack_identities(
                    sent.iter()
                        .map(|(session, f)| (session.as_str(), f.as_str())),
                )?;
                Ok(response)
            },
            Page::Failed("snapshot ACK does not cover the request exactly".into()),
            |_, _| {},
        )
        .items(2),
        PageRow::new(
            "17 ACK omits a sent entity, unvalidated",
            |b| accepted(entity_ack_ref(b[0])),
            Page::Settled(0, 0),
            |p, f| accept(p, &f[0]),
        )
        .items(2),
        PageRow::new(
            "18 disabled",
            |_| disabled(),
            Page::Disabled(Some("paused".into())),
            |_, _| {},
        ),
        PageRow::new(
            "19 no ACK contract",
            |b| contract(None, b[0]),
            Page::AckRejected("snapshot response lacks the entity ACK contract"),
            |_, _| {},
        ),
        PageRow::new(
            "20 unsupported ACK contract",
            |b| contract(Some("entity_ack:v0"), b[0]),
            Page::AckRejected("snapshot response uses an unsupported entity ACK contract"),
            |_, _| {},
        ),
        PageRow {
            persist_fails: true,
            ..PageRow::new(
                "21 the page's own save fails",
                |b| accepted(entity_ack_ref(b[0])),
                Page::LocalState("save upload checkpoint"),
                |p, f| accept(p, &f[0]),
            )
        },
    ];
    assert_eq!(rows.len(), 21);
    for row in &rows {
        run_page(row);
    }
}

#[derive(Debug, PartialEq)]
enum Pass {
    Done(ResumableUploadResult),
    Failed(std::result::Result<UploadFailureDiagnostics, String>),
}

struct PassRow {
    name: &'static str,
    items: usize,
    seed: Seed,
    /// Answers each POST by its zero-based attempt number.
    answer: fn(usize, &[&String]) -> Answer,
    /// Each POST's items, by index into the input.
    posts: Vec<Vec<usize>>,
    waits: usize,
    saves: usize,
    outcome: Pass,
    want: Seed,
}

impl PassRow {
    /// Two bodies, nothing seeded, one POST, nothing saved or stored.
    fn new(name: &'static str, answer: fn(usize, &[&String]) -> Answer, outcome: Pass) -> Self {
        Self {
            name,
            items: 2,
            seed: |_, _| {},
            answer,
            posts: vec![vec![0, 1]],
            waits: 0,
            saves: 0,
            outcome,
            want: |_, _| {},
        }
    }

    /// The POSTs and in-place waits it made, the saves and the ledger after.
    fn then(self, posts: Vec<Vec<usize>>, waits: usize, saves: usize, want: Seed) -> Self {
        Self {
            posts,
            waits,
            saves,
            want,
            ..self
        }
    }
}

fn run_pass(row: &PassRow) {
    let items = test_fingerprints(row.items);
    let mut progress = test_upload_progress();
    (row.seed)(&mut progress, &items);
    let before = ledger(&progress);
    let mut want = progress.clone();
    (row.want)(&mut want, &items);
    let mut posts = Vec::new();
    let mut saves = Vec::new();
    let (result, waits) = with_inplace_retry_test_clock(Some(Duration::ZERO), || {
        upload_resumable_batches_with_body_witness(
            &items,
            &unique_poison_scope(),
            &mut progress,
            &mut 0,
            String::as_str,
            |item: &String| witness(item),
            |batch: &[&String]| {
                let sent = batch
                    .iter()
                    .map(|fp| items.iter().position(|item| item == *fp));
                posts.push(sent.map(Option::unwrap).collect::<Vec<_>>());
                (row.answer)(posts.len() - 1, batch)
            },
            |state: &mut SnapshotUploadProgress| {
                saves.push(ledger(state));
                Ok(())
            },
        )
    });
    let observed = match result {
        Ok(done) => Pass::Done(done),
        Err(error) => Pass::Failed(
            error
                .downcast_ref::<UploadFailureDiagnostics>()
                .cloned()
                .ok_or_else(|| error.to_string()),
        ),
    };
    let name = row.name;
    assert_eq!(observed, row.outcome, "{name}: outcome");
    assert_eq!(posts, row.posts, "{name}: posts");
    assert_eq!(waits.len(), row.waits, "{name}: in-place waits");
    assert_eq!(saves.len(), row.saves, "{name}: saves");
    assert_eq!(ledger(&progress), ledger(&want), "{name}: ledger in memory");
    assert_eq!(
        saves.last().unwrap_or(&before),
        &ledger(&want),
        "{name}: last save argument"
    );
}

/// The first POST fails with `error`; every later one is accepted.
fn fail_first(attempt: usize, batch: &[&String], error: fn() -> anyhow::Error) -> Answer {
    if attempt == 0 {
        Err(error())
    } else {
        Ok(accept_fingerprints(batch))
    }
}

fn preflight() -> anyhow::Error {
    anyhow::Error::new(SnapshotBatchPreflightRejected {
        reason: "snapshot[0] exceeds the item wire byte limit".into(),
    })
}

fn validation() -> anyhow::Error {
    anyhow::Error::new(BatchRejected {
        status: 422,
        snapshot_indexes: Some(vec![0]),
    })
}

/// The ACK validator's shape: the typed rejection, naming its items.
fn witness_refused() -> anyhow::Error {
    let reason = "snapshot ACK lacks exact durable context curve body witness proof";
    anyhow::Error::new(SnapshotAckRejected { reason }).context(RefusedSnapshotIndexes(vec![0]))
}

/// At the honoured maximum Retry-After the jitter is capped away, so the
/// identity deferral's deadline is exactly `NOW + 1_800`.
fn identity_shed(named: Vec<usize>) -> anyhow::Error {
    anyhow::Error::new(UploadShed {
        status: 503,
        retry_after: Some(crate::snapshot_client::MAX_HONOURED_RETRY_AFTER),
        code: Some(crate::snapshot_client::UploadShedCode::OriginalIdentityUnavailable),
    })
    .context(ShedSnapshotIndexes(named))
}

fn plain_shed() -> anyhow::Error {
    anyhow::Error::new(UploadShed {
        status: 503,
        retry_after: Some(Duration::from_secs(60)),
        code: None,
    })
}

const UPLOAD: &str = "local snapshot upload";

fn batch_http(status: u16) -> UploadFailureDiagnostics {
    UploadFailureDiagnostics::for_http_test(UPLOAD, "snapshot_batch", status, false)
}

fn outage() -> UploadFailureDiagnostics {
    let family = "transport_connection";
    UploadFailureDiagnostics::for_test(UPLOAD, "snapshot_batch", family, true, false)
}

/// Item 0 held once until `retry_after`; item 1 accepted.
fn first_held(progress: &mut SnapshotUploadProgress, f: &[String], retry_after: u64) {
    held(progress, &f[0], 1, RP, retry_after, None);
    accept(progress, &f[1]);
}

/// Rows 22 to 34. Sheds, local preflight holds and refusals record client reports.
#[test]
#[serial(client_report)]
fn every_pass_answer_stores_its_exact_ledger_rows() {
    let _clock = crate::snapshot_sync::tests::permanent_finish_pipeline_tests::prior_index_lifetime_tests::Guard::new(false, None, Some(NOW));
    let honoured = crate::snapshot_client::MAX_HONOURED_RETRY_AFTER;
    assert_eq!(honoured.as_secs(), 1_800);
    let completed = || Pass::Done(ResumableUploadResult::Completed);
    let deferred = |count, isolated, identity_503| {
        Pass::Done(ResumableUploadResult::Deferred {
            count,
            isolated,
            identity_503,
        })
    };
    let both_accepted: Seed = |p, f| {
        accept(p, &f[0]);
        accept(p, &f[1]);
    };
    let resent = || vec![vec![0, 1], vec![1]];
    let rows = [
        PassRow::new(
            "22 local preflight",
            |n, b| fail_first(n, b, preflight),
            completed(),
        )
        .then(resent(), 0, 2, |p, f| {
            first_held(p, f, quarantine_retry_after(&f[0]))
        }),
        PassRow {
            seed: |p, f| {
                for (fingerprint, count) in [(&f[0], 2), (&f[1], 3)] {
                    held(p, fingerprint, count, RP, 0, None);
                    p.active_quarantine_retries.insert(fingerprint.clone());
                }
            },
            ..PassRow::new(
                "23 local preflight at count 2 and 3",
                |_, _| Err(preflight()),
                completed(),
            )
        }
        .then(resent(), 0, 2, |p, f| {
            held(p, &f[0], 3, RP, quarantine_retry_after(&f[0]), None);
            held(p, &f[1], 4, UT, 0, None);
        }),
        PassRow::new(
            "24 validation 422 naming item 0",
            |n, b| fail_first(n, b, validation),
            deferred(1, 0, 0),
        )
        .then(resent(), 0, 2, |p, f| {
            first_held(p, f, quarantine_retry_after(&f[0]))
        }),
        PassRow::new(
            "25 ACK witness refused for item 0",
            |n, b| fail_first(n, b, witness_refused),
            deferred(1, 0, 0),
        )
        .then(resent(), 0, 2, |p, f| {
            first_held(p, f, quarantine_retry_after(&f[0]))
        }),
        PassRow::new(
            "26 identity 503 naming item 0",
            |n, b| fail_first(n, b, || identity_shed(vec![0])),
            deferred(1, 1, 1),
        )
        .then(resent(), 0, 2, |p, f| first_held(p, f, NOW + 1_800)),
        PassRow::new(
            "27 identity 503 naming the page",
            |_, _| Err(identity_shed(vec![0, 1])),
            deferred(2, 2, 2),
        )
        .then(vec![vec![0, 1]], 0, 1, |p, f| {
            held(p, &f[0], 1, RP, NOW + 1_800, None);
            held(p, &f[1], 1, RP, NOW + 1_800, None);
        }),
        PassRow::new(
            "28 plain shed",
            |_, _| Err(plain_shed()),
            Pass::Done(ResumableUploadResult::Shed {
                retry_after: Some(Duration::from_secs(60)),
            }),
        ),
        PassRow {
            items: 1,
            posts: vec![vec![0]],
            ..PassRow::new(
                "29 413 on a single item",
                |_, _| Err(anyhow::Error::new(batch_http(413))),
                Pass::Failed(Ok(batch_http(413))),
            )
        },
        PassRow::new(
            "30 504 deadline",
            |n, b| fail_first(n, b, || anyhow::Error::new(batch_http(504))),
            completed(),
        )
        .then(vec![vec![0, 1], vec![0], vec![1]], 0, 2, both_accepted),
        PassRow::new(
            "31 fast 500",
            |n, b| fail_first(n, b, || anyhow::Error::new(batch_http(500))),
            completed(),
        )
        .then(vec![vec![0, 1], vec![0, 1]], 1, 1, both_accepted),
        PassRow::new(
            "32 transport outage",
            |_, _| Err(anyhow::Error::new(outage())),
            Pass::Failed(Ok(outage())),
        ),
        PassRow {
            items: 1,
            ..PassRow::new(
                "33 permanent refusal",
                |_, b| rejected(b[0], TOO_BIG, true),
                Pass::Done(ResumableUploadResult::Rejected { count: 1 }),
            )
        }
        .then(vec![vec![0]], 0, 1, |p, f| {
            refused(p, &f[0], RejectedUsageReason::BodyExceedsMaxBytes, None)
        }),
        PassRow::new(
            "34 disabled",
            |_, _| disabled(),
            Pass::Done(ResumableUploadResult::Disabled(Some("paused".into()))),
        ),
    ];
    assert_eq!(rows.len(), 13);
    for row in &rows {
        run_pass(row);
    }
}
