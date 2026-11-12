//! Every login: discovery, the tick loop, per-account state and status.

use super::accounts::{
    auth, expected_identity, expired, home_with, jwt, live, CapturingReader, USER, WORKSPACE,
};
use super::*;
use crate::agent_status::DailyReferenceHome;
use crate::provider_daily_reference::logins::{discover, LoginHomeKind, LoginSkip};
use ottto_core::CodexHomeTrust;

const SECOND_USER: &str = "user-second-fixture-private";
const SECOND_WORKSPACE: &str = "acct-second-fixture-private";
const SLOT_ID: &str = "slot-fixture-private";

fn grant_key(collector: &Collector) -> Vec<u8> {
    collector.grants().hmac_key().expect("key").expect("grant")
}

fn default_home(home: PathBuf) -> DailyReferenceHome {
    DailyReferenceHome {
        slot_id: None,
        home,
        trust: CodexHomeTrust::ProviderDefault,
        registered_pair: None,
    }
}

/// A registered slot home; `pair` is the (user, workspace) it was registered
/// with.
fn slot_home(home: PathBuf, slot_id: &str, pair: Option<(&str, &str)>) -> DailyReferenceHome {
    DailyReferenceHome {
        slot_id: Some(slot_id.to_string()),
        home,
        trust: CodexHomeTrust::Managed,
        registered_pair: pair.map(|(user, workspace)| {
            let identity = expected_identity(user, workspace);
            (
                identity.account_identifier_hash,
                identity.provider_workspace_hash,
            )
        }),
    }
}

/// An identified sign-in for `user` in `workspace`, with an agreeing id token.
fn signed_in(user: &str, workspace: &str) -> Value {
    auth(
        &jwt(Some(user), Some(workspace), live()),
        Some(&jwt(Some(user), Some(workspace), expired())),
        workspace,
    )
}

/// A live sign-in whose token names no user, so it proves no pair.
fn unidentified(workspace: &str) -> Value {
    auth(&jwt(None, Some(workspace), live()), None, workspace)
}

fn slot_login(scope: &str) -> CodexLogin {
    let mut login = login_with_scope(scope);
    login.home_kind = LoginHomeKind::Slot {
        slot_id: SLOT_ID.to_string(),
    };
    login
}

/// Every file under `root` and its bytes, to prove a read wrote nothing.
fn tree(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    let mut files = BTreeMap::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(&directory).expect("read dir") {
            let path = entry.expect("entry").path();
            if path.is_dir() {
                pending.push(path);
            } else {
                files.insert(path.clone(), fs::read(&path).expect("read file"));
            }
        }
    }
    files
}

/// A reader that answers from a queue, then with a fixed payload.
struct QueuedReader {
    answers: RefCell<VecDeque<Result<Value, ProviderReadError>>>,
    payload: Value,
    calls: Cell<usize>,
}

impl QueuedReader {
    fn new(answers: Vec<Result<Value, ProviderReadError>>) -> Self {
        Self {
            answers: RefCell::new(answers.into()),
            payload: poisoned_payload(),
            calls: Cell::new(0),
        }
    }
}

impl ProviderDailyUsageReader for QueuedReader {
    fn fetch_window(
        &self,
        _credential: &CodexCredential,
        _start: &str,
        _end: &str,
    ) -> Result<Value, ProviderReadError> {
        self.calls.set(self.calls.get() + 1);
        self.answers
            .borrow_mut()
            .pop_front()
            .unwrap_or_else(|| Ok(self.payload.clone()))
    }
}

/// [behaviour] One login per opaque account, identified first, then the
/// default home, then the slot; slots are used only while their token proves
/// the registered pair; an absent default home is not a skip. Discovery never
/// writes.
#[test]
fn discovery_selects_one_login_per_account_and_proves_every_slot() {
    let collector = collector("discovery-priority");
    enabled(&collector);
    let key = grant_key(&collector);
    let scratch = crate::test_scratch::ScratchDir::canonical("pdr-discovery");
    let fingerprint = |scope: &str| opaque_key(&key, scope);
    type Case<'a> = (
        &'a str,
        Option<Value>,
        Option<Value>,
        Option<(&'a str, &'a str)>,
        Vec<&'a str>,
        Vec<(&'a str, u32)>,
    );
    let cases: Vec<Case> = vec![
        (
            "both identified: the default home wins",
            Some(signed_in(USER, WORKSPACE)),
            Some(signed_in(USER, WORKSPACE)),
            Some((USER, WORKSPACE)),
            vec!["default"],
            vec![("shared_workspace_skipped", 1)],
        ),
        (
            "only the slot identified: the slot wins",
            Some(unidentified(WORKSPACE)),
            Some(signed_in(USER, WORKSPACE)),
            Some((USER, WORKSPACE)),
            vec!["slot"],
            vec![("shared_workspace_skipped", 1)],
        ),
        (
            "two users in one workspace: one read",
            Some(signed_in(USER, WORKSPACE)),
            Some(signed_in(SECOND_USER, WORKSPACE)),
            Some((SECOND_USER, WORKSPACE)),
            vec!["default"],
            vec![("shared_workspace_skipped", 1)],
        ),
        (
            "two accounts: both read in home order",
            Some(signed_in(USER, WORKSPACE)),
            Some(signed_in(SECOND_USER, SECOND_WORKSPACE)),
            Some((SECOND_USER, SECOND_WORKSPACE)),
            vec!["default", "slot"],
            vec![],
        ),
        (
            "slot signed in to another account",
            Some(signed_in(USER, WORKSPACE)),
            Some(signed_in(USER, SECOND_WORKSPACE)),
            Some((SECOND_USER, SECOND_WORKSPACE)),
            vec!["default"],
            vec![("slot_identity_mismatch", 1)],
        ),
        (
            "slot token proves no pair",
            Some(signed_in(USER, WORKSPACE)),
            Some(unidentified(SECOND_WORKSPACE)),
            Some((SECOND_USER, SECOND_WORKSPACE)),
            vec!["default"],
            vec![("slot_identity_unprovable", 1)],
        ),
        (
            "slot without a registered pair",
            Some(signed_in(USER, WORKSPACE)),
            Some(signed_in(SECOND_USER, SECOND_WORKSPACE)),
            None,
            vec!["default"],
            vec![("slot_identity_unprovable", 1)],
        ),
        (
            "no default sign-in: not a skip",
            None,
            Some(signed_in(SECOND_USER, SECOND_WORKSPACE)),
            Some((SECOND_USER, SECOND_WORKSPACE)),
            vec!["slot"],
            vec![],
        ),
    ];
    for (index, (case, default_auth, slot_auth, pair, kinds, skipped)) in
        cases.into_iter().enumerate()
    {
        let default_dir = home_with(
            &scratch,
            &format!("default-{index}"),
            default_auth.as_ref(),
            0o600,
        );
        let slot_dir = home_with(
            &scratch,
            &format!("slot-{index}"),
            slot_auth.as_ref(),
            0o600,
        );
        let before = tree(&scratch);
        let discovery = discover(
            vec![
                default_home(default_dir),
                slot_home(slot_dir, SLOT_ID, pair),
            ],
            true,
            &key,
            unix_seconds(now()),
        );
        assert_eq!(tree(&scratch), before, "{case}: discovery wrote nothing");
        assert_eq!(
            discovery
                .logins
                .iter()
                .map(|login| login.home_kind.label())
                .collect::<Vec<_>>(),
            kinds,
            "{case}"
        );
        assert_eq!(
            discovery.skipped,
            skipped
                .into_iter()
                .map(|(reason, count)| (reason.to_string(), count))
                .collect::<BTreeMap<_, _>>(),
            "{case}"
        );
        // The compatibility fields always describe the default home's login,
        // also when a slot with the same account was selected for the read.
        let expected_default = match default_auth {
            Some(_) => logins::DefaultHomeState {
                state: "ok".to_string(),
                fingerprint: Some(fingerprint(WORKSPACE)),
            },
            None => logins::DefaultHomeState {
                state: LoginSkip::Absent.reason().to_string(),
                fingerprint: None,
            },
        };
        assert_eq!(discovery.default_home, expected_default, "{case}");
        assert!(discovery.complete, "{case}");
    }

    // An unsafe default home is counted; an incomplete registry is carried.
    let unsafe_dir = home_with(
        &scratch,
        "default-unsafe",
        Some(&signed_in(USER, WORKSPACE)),
        0o644,
    );
    let discovery = discover(
        vec![default_home(unsafe_dir)],
        false,
        &key,
        unix_seconds(now()),
    );
    assert!(discovery.logins.is_empty());
    assert!(!discovery.complete);
    assert_eq!(
        discovery.skipped.get("sign_in_unreadable").copied(),
        Some(1)
    );
}

/// [money] The A1-C1 slot half: a registered slot with a live access token
/// and an expired id token is discovered, read once with its own credential,
/// and uploaded with its identity; status then reports its success.
#[test]
fn a_slot_login_with_an_expired_id_token_uploads_identified_batches() {
    let collector = collector("slot-expired-id-token");
    enabled(&collector);
    let key = grant_key(&collector);
    let scratch = crate::test_scratch::ScratchDir::canonical("pdr-slot-upload");
    let access = jwt(Some(SECOND_USER), Some(SECOND_WORKSPACE), live());
    let slot_dir = home_with(
        &scratch,
        "slot",
        Some(&auth(
            &access,
            Some(&jwt(Some(SECOND_USER), Some(SECOND_WORKSPACE), expired())),
            SECOND_WORKSPACE,
        )),
        0o600,
    );
    let discovery = discover(
        vec![
            default_home(scratch.join("no-default")),
            slot_home(slot_dir, SLOT_ID, Some((SECOND_USER, SECOND_WORKSPACE))),
        ],
        true,
        &key,
        unix_seconds(now()),
    );
    assert!(discovery.skipped.is_empty(), "no skip reason");
    let reader = CapturingReader {
        payload: poisoned_payload(),
        ..CapturingReader::default()
    };
    let transport = RecordingTransport::default();
    let cycle = collector.run_tick(&runtime(), &discovery, &reader, &transport, &now);
    assert_eq!(cycle.outcome, CycleOutcome::Uploaded);
    assert_eq!(
        *reader.headers.borrow(),
        vec![(access, Some(SECOND_WORKSPACE.to_string()))]
    );
    let identity =
        serde_json::to_value(expected_identity(SECOND_USER, SECOND_WORKSPACE)).expect("identity");
    let batches = transport.batches.borrow();
    assert!(!batches.is_empty());
    for batch in batches.iter() {
        assert_eq!(batch["account_identity"], identity);
        assert_eq!(
            batch["account_fingerprint"],
            json!(opaque_key(&key, SECOND_WORKSPACE))
        );
    }
    let status = status_with_live_binding(
        collector.grants(),
        collector_status(collector.grants(), false),
        Some(INSTALLATION_ID),
    );
    assert_eq!(status.reason_code, "enabled");
    assert_eq!(status.current_account_fingerprint, None);
    assert_eq!(
        status.accounts,
        vec![CollectorAccountStatusV1 {
            ordinal: 1,
            home_kind: "slot".to_string(),
            reason: "ok".to_string(),
            last_success_at: Some(timestamp(now())),
        }]
    );
}

/// [money] Two accounts: each read once per cadence under its own
/// attribution, and a later tick inside the cadence reads neither.
#[test]
fn every_login_is_read_once_per_cadence_under_its_own_attribution() {
    let collector = collector("two-logins");
    enabled(&collector);
    let key = grant_key(&collector);
    let discovery = discovered(&collector, vec![login(), slot_login(SECOND_WORKSPACE)]);
    let reader = StaticReader::new(poisoned_payload());
    let transport = RecordingTransport::default();
    let cycle = collector.run_tick(&runtime(), &discovery, &reader, &transport, &now);
    assert_eq!(cycle.outcome, CycleOutcome::Uploaded);
    assert_eq!(reader.calls.get(), 2);
    assert_eq!(
        cycle
            .accounts
            .iter()
            .map(|account| (account.ordinal, account.home_kind, account.reason))
            .collect::<Vec<_>>(),
        vec![(1, "default", Some("ok")), (2, "slot", Some("ok"))]
    );
    let fingerprints = transport
        .batches
        .borrow()
        .iter()
        .map(|batch| {
            batch["account_fingerprint"]
                .as_str()
                .expect("fingerprint")
                .to_string()
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(
        fingerprints,
        [ACCOUNT_SCOPE, SECOND_WORKSPACE]
            .into_iter()
            .map(|scope| opaque_key(&key, scope))
            .collect::<BTreeSet<_>>()
    );
    assert!(cycle
        .diagnostics
        .iter()
        .all(|diagnostic| diagnostic.message.starts_with("login ")));

    let later = now() + TimeDuration::hours(1);
    let quiet = collector.run_tick(
        &runtime(),
        &discovery,
        &ForbiddenReader,
        &ForbiddenTransport,
        &move || later,
    );
    assert_eq!(quiet.outcome, CycleOutcome::Noop);
    assert!(quiet.diagnostics.is_empty());
}

/// [behaviour] A 429 counts on that login and ends the tick; the next tick
/// reads the login that waited.
#[test]
fn a_rate_limit_stops_the_tick_and_the_next_tick_reads_the_next_login() {
    let collector = collector("rate-limit-stop");
    enabled(&collector);
    let discovery = discovered(&collector, vec![login(), slot_login(SECOND_WORKSPACE)]);
    let reader = QueuedReader::new(vec![Err(ProviderReadError::RateLimited)]);
    let transport = RecordingTransport::default();
    let cycle = collector.run_tick(&runtime(), &discovery, &reader, &transport, &now);
    assert_eq!(reader.calls.get(), 1);
    assert_eq!(cycle.outcome, CycleOutcome::Failed);
    assert_eq!(
        cycle
            .accounts
            .iter()
            .map(|account| account.reason)
            .collect::<Vec<_>>(),
        vec![Some("rate_limited")]
    );

    let later = now() + TimeDuration::minutes(30);
    let next = collector.run_tick(&runtime(), &discovery, &reader, &transport, &move || later);
    assert_eq!(reader.calls.get(), 2, "only the login that waited is read");
    assert_eq!(next.outcome, CycleOutcome::Uploaded);
    assert_eq!(
        next.accounts
            .iter()
            .map(|account| (account.ordinal, account.reason))
            .collect::<Vec<_>>(),
        vec![(2, Some("ok")), (1, None)]
    );
}

/// [behaviour] Refusals that hold for the whole grant end the tick; refusals
/// of one account let the next login proceed.
#[test]
fn grant_wide_refusals_stop_the_tick_and_account_refusals_continue() {
    for (error, calls, reason) in [
        (UploadError::NotAdmitted(403), 1, "upload_refused"),
        (UploadError::GrantEpochConflict, 1, "upload_refused"),
        (UploadError::ContractRejected(422), 2, "upload_refused"),
        (
            UploadError::Unavailable("fixture".to_string()),
            2,
            "upload_failed",
        ),
        (UploadError::AccountExcluded, 2, "excluded"),
    ] {
        let collector = collector("refusal-scope");
        enabled(&collector);
        let discovery = discovered(&collector, vec![login(), slot_login(SECOND_WORKSPACE)]);
        let reader = StaticReader::new(poisoned_payload());
        let transport = RejectingTransport::new(error.clone());
        let cycle = collector.run_tick(&runtime(), &discovery, &reader, &transport, &now);
        assert_eq!(transport.calls.get(), calls, "{error:?}");
        assert!(
            cycle
                .accounts
                .iter()
                .all(|account| account.reason == Some(reason)),
            "{error:?}"
        );
    }
}

/// [behaviour] An attempt time that cannot be saved makes no request: the
/// account is skipped as `state_unwritable` and the next login is evaluated.
#[test]
fn a_failed_admission_save_makes_no_request() {
    let collector = collector("admission-save");
    enabled(&collector);
    fs::create_dir_all(collector.state_path()).expect("state path as a directory");
    let discovery = discovered(&collector, vec![login(), slot_login(SECOND_WORKSPACE)]);
    let cycle = collector.run_tick(
        &runtime(),
        &discovery,
        &ForbiddenReader,
        &ForbiddenTransport,
        &now,
    );
    assert_eq!(cycle.outcome, CycleOutcome::Deferred);
    assert_eq!(
        cycle
            .accounts
            .iter()
            .map(|account| account.reason)
            .collect::<Vec<_>>(),
        vec![Some("state_unwritable"), Some("state_unwritable")]
    );
}

/// [money] A2 per login: with the clock passing UTC midnight between two
/// logins, each read's `coverage_end` is the last complete day at its own
/// `collected_at`.
#[test]
fn the_clock_passing_midnight_between_logins_keeps_each_read_whole() {
    let collector = collector("midnight-between-logins");
    enabled(&collector);
    let discovery = discovered(&collector, vec![login(), slot_login(SECOND_WORKSPACE)]);
    let instants = RefCell::new(VecDeque::from(
        [
            "2026-07-27T23:59:58Z",
            "2026-07-27T23:59:59Z",
            "2026-07-28T00:00:01Z",
        ]
        .map(|instant| OffsetDateTime::parse(instant, &Rfc3339).expect("instant")),
    ));
    let last = Cell::new(now());
    let clock = || {
        if let Some(next) = instants.borrow_mut().pop_front() {
            last.set(next);
        }
        last.get()
    };
    let reader = StaticReader::new(json!({"results": [{"date": "2026-07-20"}]}));
    let transport = RecordingTransport::default();
    let cycle = collector.run_tick(&runtime(), &discovery, &reader, &transport, &clock);
    assert_eq!(cycle.outcome, CycleOutcome::Uploaded);
    let batches = transport.batches.borrow();
    let ends = batches
        .iter()
        .map(|batch| {
            let collected = OffsetDateTime::parse(
                batch["collected_at"].as_str().expect("collected_at"),
                &Rfc3339,
            )
            .expect("rfc3339");
            assert_eq!(
                batch["coverage_end"],
                json!(date_string(collected - TimeDuration::days(1)))
            );
            batch["coverage_end"]
                .as_str()
                .expect("coverage_end")
                .to_string()
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(ends.len(), 2, "each login kept its own day");
}

/// A transport that replaces the consent epoch while it answers.
struct EpochReplacingTransport {
    grants: GrantStore,
    calls: Cell<usize>,
}

impl DailyReferenceTransport for EpochReplacingTransport {
    fn is_configured(&self) -> bool {
        true
    }

    fn send_batch(&self, _batch: &Value) -> Result<Value, UploadError> {
        self.calls.set(self.calls.get() + 1);
        let local = self.grants.load().expect("load").expect("grant");
        self.grants
            .bind_backend_grant(&grant_response(&local, "enabled", 2), INSTALLATION_ID)
            .expect("rebind at a newer epoch");
        Err(UploadError::AccountExcluded)
    }
}

/// [money] An answer to the old epoch never writes health or an exclusion to
/// the epoch that replaced it, and the rest of the tick stops unrecorded.
#[test]
fn an_epoch_replaced_during_an_upload_is_never_written_to() {
    let collector = collector("epoch-replaced");
    enabled(&collector);
    let discovery = discovered(&collector, vec![login(), slot_login(SECOND_WORKSPACE)]);
    let transport = EpochReplacingTransport {
        grants: GrantStore::new(collector.grants().path()),
        calls: Cell::new(0),
    };
    let reader = StaticReader::new(poisoned_payload());
    let cycle = collector.run_tick(&runtime(), &discovery, &reader, &transport, &now);
    assert_eq!(transport.calls.get(), 1);
    assert_eq!(reader.calls.get(), 1, "the second login is not read");
    assert_eq!(
        cycle
            .accounts
            .iter()
            .map(|account| account.reason)
            .collect::<Vec<_>>(),
        vec![Some("excluded"), Some("consent_changed")]
    );
    let grant = collector.grants().load().expect("load").expect("grant");
    assert_eq!(
        grant
            .backend_binding
            .as_ref()
            .map(|binding| binding.grant_version),
        Some(2)
    );
    assert_eq!(grant.last_error_category, None);
    let fingerprint = collector
        .grants()
        .account_fingerprint_for(ACCOUNT_SCOPE)
        .expect("derive")
        .expect("grant");
    assert!(!collector
        .grants()
        .account_is_excluded(&fingerprint)
        .expect("read"));
    assert_eq!(collector.state.load_file().discovery, None);
}

/// A reader that turns the local off-switch on while it answers.
struct SwitchingOffReader {
    sentinel: PathBuf,
    calls: Cell<usize>,
}

impl ProviderDailyUsageReader for SwitchingOffReader {
    fn fetch_window(
        &self,
        _credential: &CodexCredential,
        _start: &str,
        _end: &str,
    ) -> Result<Value, ProviderReadError> {
        self.calls.set(self.calls.get() + 1);
        fs::write(&self.sentinel, b"disabled\n").expect("write sentinel");
        Ok(poisoned_payload())
    }
}

/// [behaviour] The off-switch between logins stops the tick before the next
/// read and retires local state.
#[test]
fn the_off_switch_between_logins_stops_the_tick_and_retires_state() {
    let collector = collector("off-switch-between-logins");
    enabled(&collector);
    let discovery = discovered(&collector, vec![login(), slot_login(SECOND_WORKSPACE)]);
    let reader = SwitchingOffReader {
        sentinel: collector.sentinel.clone(),
        calls: Cell::new(0),
    };
    let transport = RecordingTransport::default();
    let cycle = collector.run_tick(&runtime(), &discovery, &reader, &transport, &now);
    assert_eq!(reader.calls.get(), 1);
    assert_eq!(
        cycle.accounts.last().map(|account| account.reason),
        Some(Some("network_disabled"))
    );
    assert!(!collector.state_path().is_file());
}

/// [money] A v1 grant reads only the login it covers and sends no identity.
#[test]
fn a_v1_grant_reads_only_the_covered_login() {
    let collector = collector("v1-covered-only");
    enabled(&collector);
    super::accounts::set_disclosure(&collector, DISCLOSURE_VERSION_V1);
    let mut covered = login();
    covered.identity = Some(expected_identity(USER, WORKSPACE));
    let discovery = discovered(&collector, vec![covered, slot_login(SECOND_WORKSPACE)]);
    let reader = StaticReader::new(poisoned_payload());
    let transport = RecordingTransport::default();
    let cycle = collector.run_tick(&runtime(), &discovery, &reader, &transport, &now);
    assert_eq!(reader.calls.get(), 1);
    assert_eq!(
        cycle
            .accounts
            .iter()
            .map(|account| account.reason)
            .collect::<Vec<_>>(),
        vec![Some("ok"), Some("not_covered_by_v1_consent")]
    );
    assert!(transport
        .batches
        .borrow()
        .iter()
        .all(|batch| batch.get("account_identity").is_none()));
}

/// [behaviour] Status reads the latest discovery, never a credential:
/// pending before a tick and after the binding changes, every account with
/// its own reason, the default home in the compatibility fields, and no
/// identifier in `accounts[]`.
#[test]
fn status_reports_every_discovered_account_from_state_only() {
    let collector = collector("status-accounts");
    enabled(&collector);
    let status = || {
        status_with_live_binding(
            collector.grants(),
            collector_status(collector.grants(), false),
            Some(INSTALLATION_ID),
        )
    };
    let pending = status();
    assert_eq!(pending.reason_code, "discovery_pending");
    assert!(pending.provider_read_permitted);
    assert!(pending.accounts.is_empty());

    // An excluded default home and a collecting slot: still Enabled.
    let default_fingerprint = collector
        .grants()
        .account_fingerprint_for(ACCOUNT_SCOPE)
        .expect("derive")
        .expect("grant");
    collector
        .grants()
        .set_account_excluded(&default_fingerprint, true)
        .expect("exclude");
    let discovery = discovered(&collector, vec![login(), slot_login(SECOND_WORKSPACE)]);
    let reader = StaticReader::new(poisoned_payload());
    let transport = RecordingTransport::default();
    collector.run_tick(&runtime(), &discovery, &reader, &transport, &now);
    let reported = status();
    assert_eq!(reported.runtime_state, RuntimeState::Enabled);
    assert_eq!(reported.reason_code, "enabled");
    assert!(reported.provider_read_permitted);
    assert_eq!(
        reported.current_account_fingerprint.as_deref(),
        Some(default_fingerprint.as_str())
    );
    assert!(reported.current_account_excluded);
    assert_eq!(
        reported
            .accounts
            .iter()
            .map(|account| (
                account.ordinal,
                account.home_kind.as_str(),
                account.reason.as_str()
            ))
            .collect::<Vec<_>>(),
        vec![(1, "default", "excluded"), (2, "slot", "ok")]
    );
    let encoded = serde_json::to_string(&reported.accounts).expect("accounts json");
    let identity = expected_identity(USER, WORKSPACE);
    for forbidden in [
        "hmac-sha256",
        SLOT_ID,
        GRANT_ID,
        ACCOUNT_SCOPE,
        SECOND_WORKSPACE,
        identity.account_identifier_hash.as_str(),
        identity.provider_workspace_hash.as_str(),
    ] {
        assert!(!encoded.contains(forbidden), "{forbidden}");
    }

    // Every live account excluded.
    collector
        .grants()
        .set_account_excluded(&opaque_key(&grant_key(&collector), SECOND_WORKSPACE), true)
        .expect("exclude slot");
    let all_excluded = status();
    assert_eq!(all_excluded.runtime_state, RuntimeState::AccountExcluded);
    assert!(!all_excluded.provider_read_permitted);

    // No usable login: nothing is read and the status says so.
    let mut nobody = discovered(&collector, Vec::new());
    nobody
        .skipped
        .insert(LoginSkip::Expired.reason().to_string(), 1);
    let later = now() + TimeDuration::days(1);
    let deferred = collector.run_tick(
        &runtime(),
        &nobody,
        &ForbiddenReader,
        &ForbiddenTransport,
        &move || later,
    );
    assert_eq!(deferred.outcome, CycleOutcome::Deferred);
    let empty = status();
    assert_eq!(empty.reason_code, "no_live_codex_login");
    assert!(!empty.provider_read_permitted);

    // A new binding has not been discovered yet.
    let local = collector.grants().load().expect("load").expect("grant");
    collector
        .grants()
        .bind_backend_grant(&grant_response(&local, "enabled", 2), INSTALLATION_ID)
        .expect("rebind");
    assert_eq!(status().reason_code, "discovery_pending");
}

/// [regress] Entries unseen for a week are dropped only after a complete
/// discovery; an incomplete one keeps them.
#[test]
fn state_entries_are_pruned_only_after_a_complete_discovery() {
    let collector = collector("state-prune");
    let binding = StateBinding {
        grant_id: GRANT_ID.to_string(),
        grant_version: 1,
    };
    let entry = |identity: &str, day: &str| CollectorState {
        schema_version: STATE_FILE_SCHEMA_VERSION,
        identity: identity.to_string(),
        last_seen_day: Some(day.to_string()),
        ..CollectorState::default()
    };
    collector
        .state
        .save(&entry("entry-old", "2026-07-19"))
        .expect("save old");
    collector
        .state
        .save(&entry("entry-week", "2026-07-20"))
        .expect("save week");
    let summary = |complete: bool| DiscoverySummary {
        binding: binding.clone(),
        complete,
        accounts: Vec::new(),
        skipped: BTreeMap::new(),
        default_home: logins::DefaultHomeState::default(),
    };
    collector
        .state
        .record_tick(summary(false), &[], "2026-07-27")
        .expect("incomplete");
    assert_eq!(collector.state.load_file().entries.len(), 2);
    collector
        .state
        .record_tick(summary(true), &[], "2026-07-27")
        .expect("complete");
    assert_eq!(
        collector
            .state
            .load_file()
            .entries
            .keys()
            .cloned()
            .collect::<Vec<_>>(),
        vec!["entry-week".to_string()]
    );
}
