//! Guards on what a read may upload: workspace-wide answers, and one series
//! seen through two logins.

use super::all_logins::{grant_key, slot_login, ScopedReader, SECOND_WORKSPACE};
use super::*;

/// One valid day carrying `users` at `location`.
fn payload_with_users(location: &str, users: Value) -> Value {
    let mut payload = json!({
        "results": [
            {
                "date": "2026-07-26",
                "totals": {"text_total_tokens": 20},
                "models": [{"model": "gpt-fixture", "text_total_tokens": 20}],
                "clients": [{
                    "client_id": "CODEX_WEB",
                    "text_total_tokens": 20,
                    "models": [
                        {"model": "gpt-fixture", "text_total_tokens": 15},
                        {"model": "!!!", "text_total_tokens": 5}
                    ]
                }]
            },
            {"totals": {"text_total_tokens": 1}},
            {"date": "2026-01-01", "totals": {"text_total_tokens": 1}}
        ]
    });
    let target = match location {
        "totals" => &mut payload["results"][0]["totals"],
        "client" => &mut payload["results"][0]["clients"][0],
        "client model" => &mut payload["results"][0]["clients"][0]["models"][0],
        "unknown model" => &mut payload["results"][0]["clients"][0]["models"][1],
        "day model" => &mut payload["results"][0]["models"][0],
        "day without a date" => &mut payload["results"][1]["totals"],
        "day outside the window" => &mut payload["results"][2]["totals"],
        other => panic!("unknown location {other}"),
    };
    target["users"] = users;
    payload
}

/// [money] A `users` count above one anywhere in the answer refuses the
/// whole read as a shape failure; one, zero, absent or malformed does not.
#[test]
fn a_count_above_one_user_anywhere_refuses_the_whole_answer() {
    let locations = [
        "totals",
        "client",
        "client model",
        "unknown model",
        "day model",
        "day without a date",
        "day outside the window",
    ];
    for location in locations {
        let collector = collector("workspace-wide");
        enabled(&collector);
        let reader = StaticReader::new(payload_with_users(location, json!(2)));
        let cycle = collect_one(
            &collector,
            &runtime(),
            &login(),
            &reader,
            &ForbiddenTransport,
            now(),
        );
        assert_eq!(reader.calls.get(), 1, "{location}");
        assert_eq!(cycle.outcome, CycleOutcome::Failed, "{location}");
        assert_eq!(
            cycle.accounts[0].reason,
            Some("workspace_wide_answer"),
            "{location}"
        );
        let grant = collector.grants().load().expect("load").expect("grant");
        let state = collector.state.load(&state_identity(&grant, false));
        assert_eq!(state.shape_failures, 1, "{location}");
        assert_eq!(
            grant.last_error_category.as_deref(),
            Some("workspace_wide_answer")
        );
    }

    // Totals of one user still refuse a model row of two.
    let mut mixed = payload_with_users("totals", json!(1));
    mixed["results"][0]["clients"][0]["models"][0]["users"] = json!(2);
    assert!(max_user_count(&mixed) > 1.0);

    for users in [json!(0), json!(1), json!("2"), json!(null), json!([2])] {
        for location in locations {
            assert!(
                max_user_count(&payload_with_users(location, users.clone())) <= 1.0,
                "{location}: {users}"
            );
        }
        let collector = collector("one-user");
        enabled(&collector);
        let transport = RecordingTransport::default();
        let cycle = collect_one(
            &collector,
            &runtime(),
            &login(),
            &StaticReader::new(payload_with_users("client", users.clone())),
            &transport,
            now(),
        );
        assert_eq!(cycle.outcome, CycleOutcome::Uploaded, "{users}");
    }
    assert!(max_user_count(&poisoned_payload()) <= 1.0);
}

/// [regress] No digest for a series that cannot identify an account; the
/// digest covers the window too.
#[test]
fn only_a_nonzero_series_has_a_digest() {
    let (start, end) = collection_window(now());
    let rows = normalize_provider_window(&poisoned_payload(), &start, &end)
        .expect("normalize")
        .rows;
    assert!(series_digest(&[], &start, &end).is_none());
    let zero = rows
        .iter()
        .map(|row| DailyReferenceRow {
            credits_used: row.credits_used.as_ref().map(|_| "0".to_string()),
            uncached_input_tokens: row.uncached_input_tokens.map(|_| 0),
            cached_input_tokens: row.cached_input_tokens.map(|_| 0),
            output_tokens: row.output_tokens.map(|_| 0),
            total_tokens: row.total_tokens.map(|_| 0),
            thread_count: row.thread_count.map(|_| 0),
            turn_count: row.turn_count.map(|_| 0),
            ..row.clone()
        })
        .collect::<Vec<_>>();
    assert!(series_digest(&zero, &start, &end).is_none());
    let digest = series_digest(&rows, &start, &end).expect("digest");
    assert_eq!(series_digest(&rows, &start, &end), Some(digest.clone()));
    assert_ne!(
        series_digest(&rows, &start, "2026-07-27"),
        Some(digest.clone())
    );
    assert_ne!(series_digest(&rows[1..], &start, &end), Some(digest));
}

/// Acknowledges every batch; `superseded` marks every row superseded, and
/// `failing` fails uploads for one opaque account.
#[derive(Default)]
struct AckingTransport {
    superseded: Cell<bool>,
    failing: RefCell<Option<String>>,
    batches: RefCell<Vec<Value>>,
}

impl DailyReferenceTransport for AckingTransport {
    fn is_configured(&self) -> bool {
        true
    }

    fn send_batch(&self, batch: &Value) -> Result<Value, UploadError> {
        if self.failing.borrow().as_deref() == batch["account_fingerprint"].as_str() {
            return Err(UploadError::Unavailable("fixture".to_string()));
        }
        self.batches.borrow_mut().push(batch.clone());
        let mut ack = ack_for(batch);
        if self.superseded.get() {
            ack["stored_row_count"] = json!(0);
            ack["superseded_row_count"] = ack["accepted_row_count"].clone();
        }
        Ok(ack)
    }
}

impl AckingTransport {
    /// Opaque accounts that uploaded, in order, once per read.
    fn uploaders(&self) -> Vec<String> {
        let mut uploaders = Vec::new();
        for batch in self.batches.borrow().iter() {
            let account = batch["account_fingerprint"]
                .as_str()
                .expect("fingerprint")
                .to_string();
            if uploaders.last() != Some(&account) {
                uploaders.push(account);
            }
        }
        uploaders
    }
}

fn reasons(cycle: &Cycle) -> Vec<(usize, Option<&'static str>)> {
    cycle
        .accounts
        .iter()
        .map(|account| (account.ordinal, account.reason))
        .collect()
}

/// [money] Two logins returning one series: the first full current proof
/// stands for both, the second is not uploaded, nothing is read again before
/// the cadence, and over two days each login is read only at its 6 h band.
#[test]
fn an_identical_series_is_uploaded_once_and_read_only_at_cadence() {
    let collector = collector("identical-series");
    enabled(&collector);
    let key = grant_key(&collector);
    let discovery = discovered(&collector, vec![login(), slot_login(SECOND_WORKSPACE)]);
    let reader = StaticReader::new(poisoned_payload());
    let transport = AckingTransport::default();
    let first = collector.run_tick(&runtime(), &discovery, &reader, &transport, &now);
    assert_eq!(first.outcome, CycleOutcome::Uploaded);
    assert_eq!(
        reasons(&first),
        vec![(1, Some("ok")), (2, Some("identical_series"))]
    );
    assert_eq!(transport.uploaders(), vec![opaque_key(&key, ACCOUNT_SCOPE)]);
    let grant = collector.grants().load().expect("load").expect("grant");
    let suppressed = collector.state.load(&state_identity_for_account(
        &grant,
        &opaque_key(&key, SECOND_WORKSPACE),
        false,
    ));
    assert_eq!(suppressed.last_success_epoch_seconds, 0, "not a success");
    assert!(suppressed.proof.is_none());

    let soon = now() + TimeDuration::minutes(30);
    let quiet = collector.run_tick(
        &runtime(),
        &discovery,
        &ForbiddenReader,
        &ForbiddenTransport,
        &move || soon,
    );
    assert_eq!(quiet.outcome, CycleOutcome::Noop);

    // Every 30 minutes for two days: each login is read only at its 6 h
    // band, suppressed or not.
    let mut tick_at = now();
    let mut suppressed_reads = 0;
    for _ in 0..96 {
        tick_at += TimeDuration::minutes(30);
        let at = tick_at;
        let cycle = collector.run_tick(&runtime(), &discovery, &reader, &transport, &move || at);
        suppressed_reads += cycle
            .accounts
            .iter()
            .filter(|account| account.reason == Some("identical_series"))
            .count();
    }
    let reads = reader.calls.get();
    assert!((16..=18).contains(&reads), "two logins read {reads} times");
    assert!(suppressed_reads > 0);
}

/// [money] A receipt with superseded rows is a success without a proof, so
/// a second login with the same series is uploaded.
#[test]
fn a_superseded_receipt_proves_nothing_for_another_login() {
    let collector = collector("superseded-receipt");
    enabled(&collector);
    let key = grant_key(&collector);
    let discovery = discovered(&collector, vec![login(), slot_login(SECOND_WORKSPACE)]);
    let transport = AckingTransport::default();
    transport.superseded.set(true);
    let cycle = collector.run_tick(
        &runtime(),
        &discovery,
        &StaticReader::new(poisoned_payload()),
        &transport,
        &now,
    );
    assert_eq!(reasons(&cycle), vec![(1, Some("ok")), (2, Some("ok"))]);
    assert_eq!(
        transport.uploaders(),
        vec![
            opaque_key(&key, ACCOUNT_SCOPE),
            opaque_key(&key, SECOND_WORKSPACE)
        ]
    );
    let grant = collector.grants().load().expect("load").expect("grant");
    let first = collector.state.load(&state_identity_for_account(
        &grant,
        &opaque_key(&key, ACCOUNT_SCOPE),
        false,
    ));
    assert!(first.last_success_epoch_seconds > 0);
    assert!(first.proof.is_none());
}

/// What one owner case changes before the later tick.
type OwnerChange = fn(&Collector, &[u8]);

/// [money] Suppression rests only on a current proof from an eligible owner:
/// a newer failed read, an excluded or absent owner, or an older epoch all
/// let the other login upload.
#[test]
fn only_a_current_proof_from_an_eligible_owner_suppresses() {
    let later = now() + TimeDuration::hours(7);
    let owner_cases: [(&str, OwnerChange); 4] = [
        ("newer read failed", |_, _| {}),
        ("owner excluded", |collector, key| {
            collector
                .grants()
                .set_account_excluded(&opaque_key(key, ACCOUNT_SCOPE), true)
                .expect("exclude");
        }),
        ("owner absent", |_, _| {}),
        ("older epoch", |collector, _| {
            let local = collector.grants().load().expect("load").expect("grant");
            collector
                .grants()
                .bind_backend_grant(&grant_response(&local, "enabled", 2), INSTALLATION_ID)
                .expect("rebind");
        }),
    ];
    for (case, change) in owner_cases {
        let collector = collector("eligible-owner");
        enabled(&collector);
        let key = grant_key(&collector);
        let both = discovered(&collector, vec![login(), slot_login(SECOND_WORKSPACE)]);
        let reader = StaticReader::new(poisoned_payload());
        let transport = AckingTransport::default();
        collector.run_tick(&runtime(), &both, &reader, &transport, &now);
        assert_eq!(transport.uploaders().len(), 1, "{case}: owner proved");

        change(&collector, &key);
        transport.batches.borrow_mut().clear();
        let discovery = match case {
            "newer read failed" => {
                // The owner reads again first and its upload fails.
                *transport.failing.borrow_mut() = Some(opaque_key(&key, ACCOUNT_SCOPE));
                let owner_only = discovered(&collector, vec![login()]);
                collector.run_tick(&runtime(), &owner_only, &reader, &transport, &move || later);
                both
            }
            "owner absent" => discovered(&collector, vec![slot_login(SECOND_WORKSPACE)]),
            // The other login reads first under the new epoch.
            "older epoch" => discovered(&collector, vec![slot_login(SECOND_WORKSPACE), login()]),
            _ => both,
        };
        let after = later + TimeDuration::minutes(1);
        collector.run_tick(&runtime(), &discovery, &reader, &transport, &move || after);
        assert!(
            transport
                .uploaders()
                .contains(&opaque_key(&key, SECOND_WORKSPACE)),
            "{case}: the other login uploaded"
        );
    }
}

/// [money] Different recent days are different series: both upload.
#[test]
fn an_equal_prefix_with_different_recent_days_uploads_both() {
    let collector = collector("equal-prefix");
    enabled(&collector);
    let discovery = discovered(&collector, vec![login(), slot_login(SECOND_WORKSPACE)]);
    let transport = AckingTransport::default();
    let cycle = collector.run_tick(
        &runtime(),
        &discovery,
        &ScopedReader::distinct(),
        &transport,
        &now,
    );
    assert_eq!(reasons(&cycle), vec![(1, Some("ok")), (2, Some("ok"))]);
    assert_eq!(transport.uploaders().len(), 2);
}

/// [money] A failed admission save while another login holds a proof makes
/// no request, so nothing can replace that proof.
#[test]
fn a_failed_admission_save_never_replaces_a_proof() {
    let collector = collector("admission-proof");
    enabled(&collector);
    let key = grant_key(&collector);
    let discovery = discovered(&collector, vec![login(), slot_login(SECOND_WORKSPACE)]);
    let transport = AckingTransport::default();
    collector.run_tick(
        &runtime(),
        &discovery,
        &StaticReader::new(poisoned_payload()),
        &transport,
        &now,
    );
    let grant = collector.grants().load().expect("load").expect("grant");
    let owner = state_identity_for_account(&grant, &opaque_key(&key, ACCOUNT_SCOPE), false);
    let proof = collector.state.load(&owner).proof.expect("owner proof");

    // The state file cannot be replaced: every admission save fails.
    let saved = fs::read(collector.state_path()).expect("state bytes");
    fs::remove_file(collector.state_path()).expect("remove state");
    fs::create_dir(collector.state_path()).expect("state path as a directory");
    let later = now() + TimeDuration::hours(7);
    let cycle = collector.run_tick(
        &runtime(),
        &discovery,
        &ForbiddenReader,
        &ForbiddenTransport,
        &move || later,
    );
    fs::remove_dir(collector.state_path()).expect("remove directory");
    fs::write(collector.state_path(), saved).expect("restore state");
    assert_eq!(
        reasons(&cycle),
        vec![(1, Some("state_unwritable")), (2, Some("state_unwritable"))]
    );
    assert_eq!(collector.state.load(&owner).proof, Some(proof));
}
