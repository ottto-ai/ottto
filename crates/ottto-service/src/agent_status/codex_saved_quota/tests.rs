//! Tests for saved Codex quota per home and the schedule that refreshes it.

use super::*;
use ottto_protocol::AgentQuotaWindowFreshness;

/// Canonical: the credential reader refuses symlinked path components
/// (macOS `$TMPDIR` sits under the `/var` symlink).
fn scratch(label: &str) -> PathBuf {
    crate::test_scratch::private_dir(&format!("ottto-codex-saved-quota-{label}"))
        .canonicalize()
        .expect("canonical scratch dir")
}

fn probe(account: &str, workspace: &str, observed_at: &str) -> CodexUsageProbe {
    CodexUsageProbe {
        quota_windows: vec![AgentQuotaWindow {
            name: "primary".to_string(),
            freshness: AgentQuotaWindowFreshness::Fresh,
            observed_at: Some(observed_at.to_string()),
            used_percent: Some(42),
            ..Default::default()
        }],
        credit_balances: vec![AgentCreditBalance {
            name: "credits".to_string(),
            freshness: AgentQuotaWindowFreshness::Fresh,
            observed_at: Some(observed_at.to_string()),
            remaining: ottto_protocol::CreditAmount::whole(7),
            ..Default::default()
        }],
        account: Some(AgentAccountStatus {
            login_state: AgentLoginState::SignedIn,
            email: Some("never-saved".to_string()),
            plan_type: Some("pro".to_string()),
            ..unsupported_account("openai")
        }),
        provider_account_absent: false,
        identity: None,
        saved_identity: Some(CodexIdentityHashes {
            account_identifier_hash: account.to_string(),
            workspace_identifier_hash: workspace.to_string(),
            superseded_account_identifier_hash: Some("old-account".to_string()),
            superseded_organization_identifier_hash: None,
        }),
        credential_read_failed: false,
        response_completed_at: Some(observed_at.to_string()),
        reset_credit_detail_summary: Some("Codex reset details: count 2.".to_string()),
        rate_limit_pool_summary: None,
    }
}

fn served_error(root: &Path, home: &Path, now: u64) -> Option<String> {
    serve_saved_at(root, home, CodexHomeTrust::Managed, now)
        .err()
        .map(|failure| failure.message)
}

fn rfc3339(at: u64) -> String {
    OffsetDateTime::from_unix_timestamp(at as i64)
        .unwrap()
        .format(&Rfc3339)
        .unwrap()
}

/// A home whose `auth.json` names no decodable binding, so only the auth
/// file witness can keep a reading.
fn opaque_home(root: &Path) -> PathBuf {
    let home = root.join("home");
    crate::test_scratch::create_private_dir(&home).unwrap();
    write_opaque_auth(&home, "first");
    home
}

fn write_opaque_auth(home: &Path, token: &str) {
    use std::os::unix::fs::PermissionsExt;
    let auth = home.join("auth.json");
    std::fs::write(
        &auth,
        serde_json::json!({"tokens": {"access_token": token}}).to_string(),
    )
    .unwrap();
    std::fs::set_permissions(&auth, std::fs::Permissions::from_mode(0o600)).unwrap();
}

fn saved_with(attempt_at: u64, login: LoginMark) -> SavedCodexQuota {
    SavedCodexQuota {
        last_attempt_at_epoch_seconds: attempt_at,
        last_attempt_login: login,
        ..SavedCodexQuota::new(Path::new("/unused"))
    }
}

fn mark(binding: Option<&str>, modified_secs: u64) -> LoginMark {
    LoginMark {
        binding: binding.map(str::to_string),
        named: binding.map(str::to_string),
        auth: Some(AuthWitness {
            modified_secs,
            modified_nanos: 0,
            len: 10,
        }),
    }
}

#[test]
fn a_changed_login_is_read_again_after_a_minute_only() {
    let saved = saved_with(10_000, mark(Some("a:w"), 1));
    let other_account = mark(Some("b:w"), 2);
    assert!(!scheduled_read_due(
        Some(&saved),
        &other_account,
        false,
        10_000 + 59
    ));
    assert!(scheduled_read_due(
        Some(&saved),
        &other_account,
        false,
        10_000 + 60
    ));
    // A token rewrite for the same account (Codex refreshing it) is not a
    // new login: the interval holds.
    let rewritten = mark(Some("a:w"), 2);
    assert!(!scheduled_read_due(
        Some(&saved),
        &rewritten,
        false,
        10_000 + 600
    ));
    // Without a claimed account on either side, a rewritten file is not
    // a new login (every read rewrites it): the interval holds.
    let opaque = saved_with(10_000, mark(None, 1));
    assert!(!scheduled_read_due(
        Some(&opaque),
        &mark(None, 2),
        false,
        10_000 + 600
    ));
    // Nor is a credential that stops naming its account (an expired
    // token), or starts to.
    assert!(!scheduled_read_due(
        Some(&saved),
        &mark(None, 1),
        false,
        10_000 + 600
    ));
    assert!(!scheduled_read_due(
        Some(&opaque),
        &mark(Some("a:w"), 2),
        false,
        10_000 + 600
    ));
    // A credential written into a signed-out home is.
    assert!(scheduled_read_due(
        Some(&saved_with(10_000, LoginMark::default())),
        &mark(None, 2),
        false,
        10_000 + 60
    ));
    // A signed-out home (no auth file before or after) keeps the interval.
    let signed_out = saved_with(10_000, LoginMark::default());
    assert!(!scheduled_read_due(
        Some(&signed_out),
        &LoginMark::default(),
        false,
        10_000 + 600
    ));
}

#[test]
fn saved_reading_round_trips_without_the_email() {
    use std::os::unix::fs::PermissionsExt;
    let root = scratch("round-trip");
    let home = root.join("home");
    crate::test_scratch::create_private_dir(&home).unwrap();
    // A saved identity is served only while the credential names it.
    sign_in_home_with_id_token_lifetime(&home, "u1", "w", 3_600);
    let account = ottto_core::billing_identity_hash("openai", "account", "u1").unwrap();
    let workspace = ottto_core::billing_identity_hash("openai", "workspace", "w").unwrap();
    let now = current_unix_seconds();
    let read = read_and_save_at(
        &root,
        &home,
        CodexHomeTrust::Managed,
        now,
        |_, _| true,
        || Ok(probe(&account, &workspace, &rfc3339(now))),
    );
    assert!(matches!(read, Some(Ok(_))));
    let path = saved_path(&root, &home);
    let mode = std::fs::metadata(&path).unwrap().permissions().mode();
    assert_eq!(mode & 0o077, 0, "owner-only: {mode:o}");
    let body = std::fs::read_to_string(&path).unwrap();
    assert!(!body.contains("never-saved"), "no email on disk");
    assert!(
        !body.contains(home.to_str().unwrap()),
        "no home path on disk"
    );

    let served = serve_saved_at(&root, &home, CodexHomeTrust::Managed, now + 60).unwrap();
    let original = probe(&account, &workspace, &rfc3339(now));
    assert_eq!(served.quota_windows, original.quota_windows);
    assert_eq!(served.credit_balances, original.credit_balances);
    assert_eq!(served.saved_identity, original.saved_identity);
    assert!(served.identity.is_none(), "a saved reading has no raw ids");
    assert_eq!(served.response_completed_at, original.response_completed_at);
    assert_eq!(
        served.reset_credit_detail_summary,
        original.reset_credit_detail_summary
    );
    let account = served.account.expect("provider account");
    assert_eq!(account.plan_type.as_deref(), Some("pro"));
    assert!(account.email.is_none());

    // A reading is fresh for two unused intervals, then labelled stale
    // (still naming its account), then not served at all. A slot whose
    // reading is stale shows no limits.
    let u = UNUSED_REFRESH_SECONDS;
    let slot_status = |served: &CodexUsageProbe, at: u64| {
        let mut snapshot = crate::agent_status::base_snapshot(
            SourceKind::Codex,
            ottto_protocol::AgentStatusState::Available,
            ottto_protocol::AgentStatusCollectionMethod::CommandProbe,
            rfc3339(at),
            rfc3339(at),
        );
        let identity = served.saved_identity.clone().unwrap();
        snapshot.account = Some(AgentAccountStatus {
            login_state: AgentLoginState::SignedIn,
            account_identifier_hash: Some(identity.account_identifier_hash),
            organization_identifier_hash: Some(identity.workspace_identifier_hash),
            ..unsupported_account("openai")
        });
        snapshot.quota_windows = served.quota_windows.clone();
        crate::agent_status::codex_collection_status_from_snapshot(&snapshot)
    };
    let fresh = serve_saved_at(&root, &home, CodexHomeTrust::Managed, now + 2 * u).unwrap();
    assert_eq!(
        fresh.quota_windows[0].freshness,
        AgentQuotaWindowFreshness::Fresh
    );
    assert!(slot_status(&fresh, now + 2 * u).quota_snapshot.is_some());
    let stale = serve_saved_at(&root, &home, CodexHomeTrust::Managed, now + 2 * u + 1).unwrap();
    assert_eq!(
        stale.quota_windows[0].freshness,
        AgentQuotaWindowFreshness::Stale
    );
    assert_eq!(stale.saved_identity, original.saved_identity);
    let status = slot_status(&stale, now + 2 * u + 1);
    assert_eq!(
        status.state,
        ottto_protocol::CodexAccountSlotCollectionStateV1::ProviderUnavailable
    );
    assert!(status.quota_snapshot.is_none());
    assert_eq!(
        served_error(&root, &home, now + 7 * 3_600),
        Some(CODEX_QUOTA_NOT_READ_YET.to_string())
    );
    // A reading between one and two unused intervals old never stands for
    // another account: once the credential names another login (here with
    // an expired access token, so no live one), nothing is served and a
    // launch gets no binding.
    let saved = read_saved_at(&root, &home);
    sign_in_home_with_lifetimes(&home, "u2", "w", -60, -60);
    let switched = login_mark(&home, CodexHomeTrust::Managed);
    assert_eq!(held_binding(saved.as_ref(), &switched), None);
    assert_eq!(
        served_error(&root, &home, now + u + u / 2),
        Some(CODEX_QUOTA_NOT_READ_YET.to_string())
    );
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn a_failed_read_is_served_as_that_failure_and_keeps_the_reading() {
    let root = scratch("failure");
    let home = opaque_home(&root);
    let now = current_unix_seconds();
    let _ = read_and_save_at(
        &root,
        &home,
        CodexHomeTrust::Managed,
        now,
        |_, _| true,
        || Ok(probe("account-a", "workspace-a", &rfc3339(now))),
    );
    let failure = "Codex app-server quota read timed out.".to_string();
    let _ = read_and_save_at(
        &root,
        &home,
        CodexHomeTrust::Managed,
        now,
        |_, _| true,
        || Err(failure.clone()),
    );
    let saved = read_saved_at(&root, &home).unwrap();
    assert!(saved.reading.is_some(), "the last good reading is kept");
    let failed_at = saved.last_failure.as_ref().unwrap().at_epoch_seconds;
    // Served later with the failed read's own time, not as a new failure.
    assert_eq!(
        serve_saved_at(&root, &home, CodexHomeTrust::Managed, now + 600).err(),
        Some(CodexQuotaFailure {
            message: failure,
            at_epoch_seconds: failed_at,
        })
    );
    // Not past the last-known cap.
    assert_eq!(
        served_error(&root, &home, failed_at + 7 * 3_600),
        Some(CODEX_QUOTA_NOT_READ_YET.to_string())
    );
    // Never for another login.
    write_opaque_auth(&home, "a-different-and-longer-login");
    assert_eq!(
        served_error(&root, &home, now),
        Some(CODEX_QUOTA_NOT_READ_YET.to_string())
    );
    let _ = std::fs::remove_dir_all(root);
}

/// The whole schedule over four homes: a home tied to a session or a
/// running process is read every 5 minutes, the others at the unused
/// interval, and a removed slot is no longer read; its sessions then
/// count for the default home.
#[test]
fn a_schedule_round_reads_homes_in_use_every_five_minutes_and_drops_removed_ones() {
    let root = scratch("round");
    let homes = ["default", "busy", "process", "idle"].map(|name| {
        let home = root.join(name);
        crate::test_scratch::create_private_dir(&home).unwrap();
        write_opaque_auth(&home, name);
        home
    });
    let slot = |index: usize| CodexHomeSlot {
        slot_id: format!("slot-{index}"),
        ownership: if index == 0 {
            CodexAccountSlotOwnershipV1::Default
        } else {
            CodexAccountSlotOwnershipV1::Managed
        },
        home: homes[index].clone(),
        registered_binding: None,
    };
    let reads = Mutex::new(Vec::<String>::new());
    // A little ahead of the clock, so every attempt is stamped `at`.
    let start = current_unix_seconds() + 30;
    let round = |slots: &[usize], at: u64| {
        reads.lock().unwrap().clear();
        let running = BTreeMap::from([(homes[2].clone(), at - 60)]);
        let sessions = [session(Some(("busy", "w")), at - 60)];
        let scheduled = scheduled_homes_from(
            &root,
            slots.iter().map(|index| slot(*index)).collect(),
            &running,
            at,
        );
        scheduled_round_for(
            &root,
            scheduled,
            &sessions,
            at,
            || true,
            |home| {
                let name = home.home.file_name().unwrap().to_str().unwrap().to_string();
                reads.lock().unwrap().push(name.clone());
                Ok(probe(&name, "w", &rfc3339(at)))
            },
        );
        let mut read = reads.lock().unwrap().clone();
        read.sort();
        read
    };
    let u = UNUSED_REFRESH_SECONDS;
    let all = [0, 1, 2, 3];
    assert_eq!(round(&all, start), ["busy", "default", "idle", "process"]);
    assert!(round(&all, start + 5 * 60 - 1).is_empty());
    assert_eq!(round(&all, start + 5 * 60), ["busy", "process"]);
    assert_eq!(round(&all, start + 10 * 60), ["busy", "process"]);
    assert_eq!(
        round(&all, start + u),
        ["busy", "default", "idle", "process"]
    );
    // "busy" is removed: never read again, and its session now counts for
    // the default home, which is read at the in-use interval.
    assert_eq!(
        round(&[0, 2, 3], start + u + 5 * 60),
        ["default", "process"]
    );
    assert!(round(&[0, 2, 3], start + u + 9 * 60).is_empty());
    let _ = std::fs::remove_dir_all(root);
}

/// A read that rewrites a credential naming no account, before or after
/// (no account id, no current id_token): the rewrite is the read's own,
/// so the reading is kept and the next read waits the full interval. A
/// credential that names no account carries none: the reading's account
/// is not served under it.
#[test]
fn a_read_that_rewrites_an_unnamed_credential_keeps_its_reading() {
    let root = scratch("unnamed-rewrite");
    let _pinned = ReadsFinishAtTriggerClock::pin(&root);
    let home = opaque_home(&root);
    let now = current_unix_seconds();
    let before = login_mark(&home, CodexHomeTrust::Managed);
    assert_eq!(before.binding, None);
    let result = read_and_save_at(
        &root,
        &home,
        CodexHomeTrust::Managed,
        now,
        |_, _| true,
        || {
            write_opaque_auth(&home, "token-refreshed-by-the-read");
            Ok(probe("account-a", "workspace-a", &rfc3339(now)))
        },
    );
    assert!(matches!(result, Some(Ok(_))));
    let after = login_mark(&home, CodexHomeTrust::Managed);
    assert_eq!(after.binding, None);
    assert_ne!(after, before, "the read rewrote auth.json");
    let saved = read_saved_at(&root, &home).unwrap();
    assert!(saved.reading.is_some(), "the reading is kept");
    assert_eq!(saved.last_attempt_login, after);
    assert!(serve_saved_at(&root, &home, CodexHomeTrust::Managed, now).is_err());
    for in_use in [true, false] {
        let interval = refresh_interval_seconds(in_use);
        assert!(!scheduled_read_due(Some(&saved), &after, in_use, now + 61));
        assert!(!scheduled_read_due(
            Some(&saved),
            &after,
            in_use,
            now + interval - 1
        ));
        assert!(scheduled_read_due(
            Some(&saved),
            &after,
            in_use,
            now + interval
        ));
    }
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn an_unwritable_saved_file_still_spaces_the_reads() {
    let root = scratch("unwritable");
    let _pinned = ReadsFinishAtTriggerClock::pin(&root);
    let home = opaque_home(&root);
    // The state directory is a file: every saved write fails.
    std::fs::write(root.join("codex-quota"), b"").unwrap();
    let now = current_unix_seconds();
    let reads = std::cell::Cell::new(0);
    let read = || {
        reads.set(reads.get() + 1);
        Ok(probe("account-a", "workspace-a", &rfc3339(now)))
    };
    let due = |saved: Option<&SavedCodexQuota>, now: u64| {
        scheduled_read_due(
            saved,
            &login_mark(&home, CodexHomeTrust::Managed),
            false,
            now,
        )
    };
    assert!(read_and_save_at(&root, &home, CodexHomeTrust::Managed, now, due, read).is_some());
    assert!(read_saved_at(&root, &home).is_none(), "nothing was written");
    // Later ticks inside the interval do not read again.
    let u = UNUSED_REFRESH_SECONDS;
    for tick in [15, 60, u - 60] {
        assert!(
            read_and_save_at(&root, &home, CodexHomeTrust::Managed, now + tick, due, read)
                .is_none()
        );
    }
    assert!(read_and_save_at(
        &root,
        &home,
        CodexHomeTrust::Managed,
        now + u + 1,
        due,
        read
    )
    .is_some());
    assert_eq!(reads.get(), 2);
    let explicit =
        |saved: Option<&SavedCodexQuota>, now: u64| explicit_refresh_allowed(saved, now);
    assert!(read_and_save_at(
        &root,
        &home,
        CodexHomeTrust::Managed,
        now + u + 30,
        explicit,
        read
    )
    .is_none());
    assert_eq!(reads.get(), 2);
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn a_read_that_panics_still_counts_as_an_attempt() {
    let root = scratch("panic");
    let home = opaque_home(&root);
    let now = current_unix_seconds();
    let result = read_and_save_at(
        &root,
        &home,
        CodexHomeTrust::Managed,
        now,
        |_, _| true,
        || panic!("a parser bug"),
    );
    assert!(matches!(result, Some(Err(message)) if message == CODEX_QUOTA_READ_PANICKED));
    let saved = saved_with_attempt(&root, &home).expect("attempt recorded");
    assert!(saved.last_attempt_at_epoch_seconds >= now);
    let login = login_mark(&home, CodexHomeTrust::Managed);
    assert!(!scheduled_read_due(Some(&saved), &login, true, now + 15));
    assert!(scheduled_read_due(
        Some(&saved),
        &login,
        true,
        saved.last_attempt_at_epoch_seconds + IN_USE_REFRESH_SECONDS
    ));
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn oversized_or_foreign_saved_files_are_ignored() {
    let root = scratch("bounds");
    let home = opaque_home(&root);
    let now = current_unix_seconds();
    let _ = read_and_save_at(
        &root,
        &home,
        CodexHomeTrust::Managed,
        now,
        |_, _| true,
        || {
            let mut probe = probe("account-a", "workspace-a", &rfc3339(now));
            probe.quota_windows = vec![probe.quota_windows[0].clone(); 100];
            probe.reset_credit_detail_summary = Some("x".repeat(10_000));
            Ok(probe)
        },
    );
    let saved = read_saved_at(&root, &home).unwrap();
    let reading = saved.reading.unwrap();
    assert_eq!(reading.quota_windows.len(), SAVED_METERS_MAX);
    assert_eq!(
        reading.reset_credit_detail_summary.unwrap().chars().count(),
        SAVED_TEXT_MAX_CHARS
    );
    // Another home's file is never served for this one.
    let other = root.join("other");
    crate::test_scratch::create_private_dir(&other).unwrap();
    std::fs::create_dir_all(saved_path(&root, &other).parent().unwrap()).unwrap();
    std::fs::copy(saved_path(&root, &home), saved_path(&root, &other)).unwrap();
    assert!(read_saved_at(&root, &other).is_none());
    // A file over the size bound is ignored.
    std::fs::write(
        saved_path(&root, &home),
        vec![b' '; SAVED_QUOTA_MAX_BYTES as usize + 1],
    )
    .unwrap();
    assert!(read_saved_at(&root, &home).is_none());
    let _ = std::fs::remove_dir_all(root);
}

fn session(binding: Option<(&str, &str)>, at: u64) -> ActiveSession {
    serde_json::from_value(serde_json::json!({
        "source_session_id": format!("s-{at}"),
        "source_last_activity_at": rfc3339(at),
        "account_identifier_hash": binding.map(|(a, _)| a),
        "organization_identifier_hash": binding.map(|(_, w)| w),
    }))
    .unwrap()
}

/// A round tells when the next home is due: the in-use or unused interval
/// after its read, and a minute after the last read once the login
/// switched; that next round reads it.
#[test]
fn a_round_tells_when_the_next_home_is_due() {
    let fixture = SameLoginFixture::new("next-due", &[("default", true, "u1", "w")]);
    let u = UNUSED_REFRESH_SECONDS;
    let start = current_unix_seconds() + 30;
    assert_eq!(
        fixture.planned_round(start, true),
        (vec!["default".to_string()], Some(start + 5 * 60))
    );
    assert_eq!(
        fixture.planned_round(start + 10, false),
        (Vec::new(), Some(start + u))
    );
    fixture.sign_in("default", "u2", "w");
    assert_eq!(
        fixture.planned_round(start + 20, false),
        (Vec::new(), Some(start + 60))
    );
    assert_eq!(
        fixture.planned_round(start + 60, false),
        (vec!["default".to_string()], Some(start + 60 + u))
    );
}

/// Set a file's modification time an hour back, as an unchanged file has.
fn settle(path: &Path) {
    std::fs::File::options()
        .write(true)
        .open(path)
        .unwrap()
        .set_modified(SystemTime::now() - Duration::from_secs(3_600))
        .unwrap();
}

/// The schedule keeps a credential's login while `auth.json` is unchanged
/// and its tokens live; a rewrite, a permission change or a token expiry
/// derives it again, and a file written just now is not kept.
#[test]
fn a_planned_login_is_kept_only_while_its_credential_is_unchanged() {
    let root = scratch("planned-login");
    let home = root.join("home");
    crate::test_scratch::create_private_dir(&home).unwrap();
    let auth = home.join("auth.json");
    let trust = CodexHomeTrust::Managed;
    let now = current_unix_seconds();
    sign_in_home_with_id_token_lifetime(&home, "u1", "w", 3_600);
    settle(&auth);
    let first = planned_login_mark(&home, trust, now);
    assert!(first.binding.is_some());
    assert_eq!(first, login_mark(&home, trust));
    let derived = planned_derives();
    assert_eq!(planned_login_mark(&home, trust, now), first);
    assert_eq!(planned_derives(), derived, "kept");
    // Past the id token's expiry: kept (the access token names the login).
    planned_login_mark(&home, trust, now + 3_600 + 1);
    assert_eq!(planned_derives(), derived, "kept past the id token");
    // Past the access token's expiry: derived again.
    planned_login_mark(&home, trust, now + 30 * 86_400 + 1);
    assert_eq!(planned_derives(), derived + 1);

    // Another account, the same length: derived again, and the new one,
    // even right after the write.
    sign_in_home_with_id_token_lifetime(&home, "u2", "w", 3_600);
    let second = planned_login_mark(&home, trust, now);
    assert_ne!(second.binding, first.binding);
    assert_eq!(second, login_mark(&home, trust));
    let derived = planned_derives();
    planned_login_mark(&home, trust, now);
    assert_eq!(planned_derives(), derived + 1, "a fresh file is not kept");

    // A permission change the credential reader refuses.
    settle(&auth);
    let settled = planned_login_mark(&home, trust, now);
    assert_eq!(settled.binding, second.binding);
    assert_eq!(settled, login_mark(&home, trust));
    let derived = planned_derives();
    planned_login_mark(&home, trust, now);
    assert_eq!(planned_derives(), derived, "kept");
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&auth, std::fs::Permissions::from_mode(0o644)).unwrap();
    }
    let refused = planned_login_mark(&home, trust, now);
    assert_eq!(refused, login_mark(&home, trust));
    assert_eq!(refused.binding, None);

    // A directory above the home that turns group-writable: the reader
    // refuses the whole chain, and so does the kept login.
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&auth, std::fs::Permissions::from_mode(0o600)).unwrap();
        settle(&auth);
        let kept = planned_login_mark(&home, trust, now);
        assert!(kept.binding.is_some());
        assert_eq!(kept, login_mark(&home, trust));
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o770)).unwrap();
        let unsafe_parent = planned_login_mark(&home, trust, now);
        assert_eq!(unsafe_parent, login_mark(&home, trust));
        assert_eq!(unsafe_parent.binding, None);
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let _ = std::fs::remove_dir_all(root);
}

/// The schedule keeps a saved file while it is unchanged; a write here,
/// or any rewrite of the file, is seen at once.
#[test]
fn a_planned_saved_file_is_kept_only_while_unchanged() {
    let root = scratch("planned-saved");
    let home = root.join("home");
    let now = current_unix_seconds();
    let saved = |attempt_at: u64| SavedCodexQuota {
        last_attempt_at_epoch_seconds: attempt_at,
        ..SavedCodexQuota::new(&home)
    };
    write_saved_at(&root, &home, &saved(1_000_000));
    let path = saved_path(&root, &home);
    settle(&path);
    assert_eq!(planned_saved(&root, &home, now), Some(saved(1_000_000)));
    let derived = planned_derives();
    assert_eq!(planned_saved(&root, &home, now), Some(saved(1_000_000)));
    assert_eq!(planned_derives(), derived, "kept");

    write_saved_at(&root, &home, &saved(2_000_000));
    assert_eq!(planned_saved(&root, &home, now), Some(saved(2_000_000)));

    // Rewritten in place by someone else, the same size.
    settle(&path);
    assert_eq!(planned_saved(&root, &home, now), Some(saved(2_000_000)));
    let body = std::fs::read_to_string(&path).unwrap().replace(
        "\"last_attempt_at_epoch_seconds\":2000000",
        "\"last_attempt_at_epoch_seconds\":3000000",
    );
    std::fs::write(&path, body).unwrap();
    assert_eq!(planned_saved(&root, &home, now), Some(saved(3_000_000)));
    let _ = std::fs::remove_dir_all(root);
}

thread_local! {
    static PLANNED_DERIVES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Planning values derived from the files on this thread.
pub(super) fn note_planned_derive() {
    PLANNED_DERIVES.with(|count| count.set(count.get() + 1));
}

fn planned_derives() -> usize {
    PLANNED_DERIVES.with(std::cell::Cell::get)
}

/// Support dirs whose reads finish at the trigger's clock.
fn pinned_support_dirs() -> MutexGuard<'static, BTreeSet<PathBuf>> {
    static PINNED: OnceLock<Mutex<BTreeSet<PathBuf>>> = OnceLock::new();
    PINNED
        .get_or_init(Default::default)
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
}

pub(super) fn reads_finish_at_trigger_clock(support_dir: &Path) -> bool {
    pinned_support_dirs().contains(support_dir)
}

/// Reads under a support dir finish at the trigger's clock while this
/// lives, so a read that crosses a wall-clock second cannot shift the
/// schedule a test checks to the second.
struct ReadsFinishAtTriggerClock(PathBuf);

impl ReadsFinishAtTriggerClock {
    fn pin(support_dir: &Path) -> Self {
        pinned_support_dirs().insert(support_dir.to_path_buf());
        Self(support_dir.to_path_buf())
    }
}

impl Drop for ReadsFinishAtTriggerClock {
    fn drop(&mut self) {
        pinned_support_dirs().remove(&self.0);
    }
}

/// Write a credential that names `user` in `workspace`, with an id token
/// that expires `id_token_lifetime` seconds from now (in the past when
/// negative) and an access token that lives 30 days.
fn sign_in_home_with_id_token_lifetime(
    home: &Path,
    user: &str,
    workspace: &str,
    id_token_lifetime: i64,
) {
    sign_in_home_with_lifetimes(home, user, workspace, id_token_lifetime, 30 * 86_400);
}

fn sign_in_home_with_lifetimes(
    home: &Path,
    user: &str,
    workspace: &str,
    id_token_lifetime: i64,
    access_token_lifetime: i64,
) {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use std::os::unix::fs::PermissionsExt;
    let jwt = |user: &str, workspace: &str, lifetime: i64| {
        let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"RS256","typ":"JWT"}"#);
        let payload = URL_SAFE_NO_PAD.encode(
            serde_json::json!({
                "iss": "https://auth.openai.com",
                "aud": "synthetic-client",
                "exp": OffsetDateTime::now_utc().unix_timestamp() + lifetime,
                "https://api.openai.com/auth": {
                    "chatgpt_user_id": user,
                    "chatgpt_account_id": workspace,
                    "chatgpt_plan_type": "pro"
                }
            })
            .to_string(),
        );
        format!("{header}.{payload}.synthetic-signature")
    };
    let auth = home.join("auth.json");
    std::fs::write(
        &auth,
        serde_json::json!({
            "tokens": {
                "access_token": jwt(user, workspace, access_token_lifetime),
                "id_token": jwt(user, workspace, id_token_lifetime),
            },
            "account_id": workspace,
        })
        .to_string(),
    )
    .unwrap();
    std::fs::set_permissions(&auth, std::fs::Permissions::from_mode(0o600)).unwrap();
}

/// A provider reading validated for `user` in `workspace`.
fn bound_probe(user: &str, workspace: &str, observed_at: u64) -> CodexUsageProbe {
    probe(
        &ottto_core::billing_identity_hash("openai", "account", user).unwrap(),
        &ottto_core::billing_identity_hash("openai", "workspace", workspace).unwrap(),
        &rfc3339(observed_at),
    )
}

/// Homes on the schedule with fake provider reads that answer for each
/// home's current login, and count. Reads finish at the round's clock.
struct SameLoginFixture {
    root: PathBuf,
    /// (name, ownership, home)
    homes: Vec<(&'static str, CodexAccountSlotOwnershipV1, PathBuf)>,
    logins: Mutex<BTreeMap<PathBuf, (String, String)>>,
    failing: Mutex<BTreeSet<&'static str>>,
    /// What a failing read answers (a timeout unless a test sets it).
    failure: Mutex<String>,
    reads: Mutex<Vec<String>>,
}

impl SameLoginFixture {
    fn new(label: &str, homes: &[(&'static str, bool, &str, &str)]) -> Self {
        let root = scratch(label);
        pinned_support_dirs().insert(root.clone());
        let fixture = Self {
            homes: homes
                .iter()
                .map(|(name, default, _, _)| {
                    let home = root.join(name);
                    crate::test_scratch::create_private_dir(&home).unwrap();
                    let ownership = if *default {
                        CodexAccountSlotOwnershipV1::Default
                    } else {
                        CodexAccountSlotOwnershipV1::Managed
                    };
                    (*name, ownership, home)
                })
                .collect(),
            root,
            logins: Mutex::default(),
            failing: Mutex::default(),
            failure: Mutex::new("Codex app-server quota read timed out.".to_string()),
            reads: Mutex::default(),
        };
        for (name, _, user, workspace) in homes {
            fixture.sign_in(name, user, workspace);
        }
        fixture
    }

    fn home(&self, name: &str) -> &PathBuf {
        &self
            .homes
            .iter()
            .find(|(own, _, _)| *own == name)
            .unwrap()
            .2
    }

    fn trust(&self, name: &str) -> CodexHomeTrust {
        match self
            .homes
            .iter()
            .find(|(own, _, _)| *own == name)
            .unwrap()
            .1
        {
            CodexAccountSlotOwnershipV1::Default => CodexHomeTrust::ProviderDefault,
            CodexAccountSlotOwnershipV1::Managed => CodexHomeTrust::Managed,
        }
    }

    fn sign_in(&self, name: &str, user: &str, workspace: &str) {
        self.sign_in_with_id_token_lifetime(name, user, workspace, 30 * 86_400);
    }

    fn sign_in_with_id_token_lifetime(
        &self,
        name: &str,
        user: &str,
        workspace: &str,
        id_token_lifetime: i64,
    ) {
        let home = self.home(name).clone();
        sign_in_home_with_id_token_lifetime(&home, user, workspace, id_token_lifetime);
        self.logins
            .lock()
            .unwrap()
            .insert(home, (user.to_string(), workspace.to_string()));
    }

    fn scheduled(&self, except: &[&str], at: u64) -> Vec<ScheduledHome> {
        let slots = self
            .homes
            .iter()
            .filter(|(name, _, _)| !except.contains(name))
            .map(|(name, ownership, home)| CodexHomeSlot {
                slot_id: name.to_string(),
                ownership: *ownership,
                home: home.clone(),
                registered_binding: None,
            })
            .collect();
        scheduled_homes_from(&self.root, slots, &BTreeMap::new(), at)
    }

    fn read(&self, home: &ScheduledHome, at: u64) -> Result<CodexUsageProbe, String> {
        let name = self
            .homes
            .iter()
            .find(|(_, _, own)| own == &home.home)
            .unwrap()
            .0;
        self.reads.lock().unwrap().push(name.to_string());
        if self.failing.lock().unwrap().contains(name) {
            return Err(self.failure.lock().unwrap().clone());
        }
        let (user, workspace) = self.logins.lock().unwrap()[&home.home].clone();
        Ok(bound_probe(&user, &workspace, at))
    }

    fn taken_reads(&self) -> Vec<String> {
        let mut reads = std::mem::take(&mut *self.reads.lock().unwrap());
        reads.sort();
        reads
    }

    /// One scheduler round at `at`; `in_use` adds a recent session that
    /// counts for the default home.
    fn round(&self, at: u64, in_use: bool, except: &[&str]) -> Vec<String> {
        let sessions = if in_use {
            vec![session(None, at - 60)]
        } else {
            Vec::new()
        };
        scheduled_round_for(
            &self.root,
            self.scheduled(except, at),
            &sessions,
            at,
            || true,
            |home| self.read(home, at),
        );
        self.taken_reads()
    }

    /// [`Self::round`], with when the next home is due.
    fn planned_round(&self, at: u64, in_use: bool) -> (Vec<String>, Option<u64>) {
        let sessions = if in_use {
            vec![session(None, at - 60)]
        } else {
            Vec::new()
        };
        let round = scheduled_round_for(
            &self.root,
            self.scheduled(&[], at),
            &sessions,
            at,
            || true,
            |home| self.read(home, at),
        );
        let reads = self.taken_reads();
        assert_eq!(round.read, reads.len());
        (reads, round.next_due_at)
    }

    fn refresh(&self, at: u64) -> (CodexExplicitRefresh, Vec<String>) {
        let outcome = refresh_homes_now(&self.root, self.scheduled(&[], at), at, |home| {
            self.read(home, at)
        });
        (outcome, self.taken_reads())
    }

    /// When the reading served for `name` was read, or its failure.
    fn served_at(&self, name: &str, at: u64) -> Result<String, String> {
        serve_saved_at(&self.root, self.home(name), self.trust(name), at)
            .map(|probe| probe.response_completed_at.unwrap())
            .map_err(|failure| failure.message)
    }

    fn served(&self, name: &str, at: u64) -> CodexUsageProbe {
        serve_saved_at(&self.root, self.home(name), self.trust(name), at).unwrap()
    }
}

impl Drop for SameLoginFixture {
    fn drop(&mut self) {
        pinned_support_dirs().remove(&self.root);
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

/// The default home and a managed slot signed into the same account and
/// workspace share one read: the default home reads at 5 minutes while
/// either is in use and at the unused interval otherwise, the slot is
/// read by itself once a day, and its status serves the default home's
/// reading.
#[test]
fn homes_with_the_same_login_are_read_once_and_share_the_reading() {
    let fixture = SameLoginFixture::new(
        "same-login",
        &[
            ("default", true, "user-a", "workspace-a"),
            ("twin", false, "user-a", "workspace-a"),
            ("other", false, "user-b", "workspace-a"),
        ],
    );
    let u = UNUSED_REFRESH_SECONDS;
    let start = current_unix_seconds();
    // Nothing read yet: nothing is known to be shared.
    assert_eq!(
        fixture.round(start, false, &[]),
        ["default", "other", "twin"]
    );
    // In use: the default home reads at 5 minutes, for both.
    assert!(fixture.round(start + 5 * 60 - 1, true, &[]).is_empty());
    assert_eq!(fixture.round(start + 5 * 60, true, &[]), ["default"]);
    assert_eq!(fixture.round(start + 10 * 60, true, &[]), ["default"]);
    // The slot's card shows the default home's newer reading: windows,
    // credits and reset details.
    let served = fixture.served("twin", start + 10 * 60);
    let expected = bound_probe("user-a", "workspace-a", start + 10 * 60);
    assert_eq!(served.response_completed_at, expected.response_completed_at);
    assert_eq!(served.quota_windows, expected.quota_windows);
    assert_eq!(served.credit_balances, expected.credit_balances);
    assert_eq!(
        served.reset_credit_detail_summary,
        expected.reset_credit_detail_summary
    );
    assert_eq!(served.saved_identity, expected.saved_identity);
    // Not in use: the unused interval since the default home's last read;
    // the other account keeps its own.
    assert_eq!(fixture.round(start + u, false, &[]), ["other"]);
    assert!(fixture
        .round(start + 10 * 60 + u - 1, false, &[])
        .is_empty());
    assert_eq!(fixture.round(start + 10 * 60 + u, false, &[]), ["default"]);
    // The slot only would be in use (a running Codex there): the shared
    // read is at 5 minutes again (the other account is left out of this
    // round, whatever its own interval), and the slot, last read by
    // itself 45 minutes ago, checks its own login at the unused interval.
    let busy_round = |at: u64| {
        let mut homes = fixture.scheduled(&["other"], at);
        for home in &mut homes {
            if &home.home == fixture.home("twin") {
                home.process_seen_at = Some(at - 60);
            }
        }
        scheduled_round_for(
            &fixture.root,
            homes,
            &[],
            at,
            || true,
            |home| fixture.read(home, at),
        );
        fixture.taken_reads()
    };
    let busy = start + 10 * 60 + u + 5 * 60;
    assert_eq!(busy_round(busy), ["default", "twin"]);
    // While it stays in use: its own read every 30 minutes, not sooner.
    assert!(!busy_round(busy + u - 60).contains(&"twin".to_string()));
    assert!(busy_round(busy + u).contains(&"twin".to_string()));

    // Keep-alive: once nothing runs there, the slot reads by itself once
    // a day after its last own read, not before.
    let day = busy + u + SAME_LOGIN_KEEPALIVE_SECONDS;
    assert!(!fixture
        .round(day - 60, false, &[])
        .contains(&"twin".to_string()));
    assert!(fixture.round(day, false, &[]).contains(&"twin".to_string()));
    assert!(!fixture
        .round(day + u, false, &[])
        .contains(&"twin".to_string()));
}

/// The same account in another workspace is another quota: both homes
/// keep their own schedule and their own readings.
#[test]
fn the_same_account_in_another_workspace_is_read_on_its_own() {
    let fixture = SameLoginFixture::new(
        "same-account-other-workspace",
        &[
            ("default", true, "user-a", "workspace-a"),
            ("slot", false, "user-a", "workspace-b"),
        ],
    );
    let u = UNUSED_REFRESH_SECONDS;
    let start = current_unix_seconds();
    assert_eq!(fixture.round(start, false, &[]), ["default", "slot"]);
    assert_eq!(fixture.round(start + 5 * 60, true, &[]), ["default"]);
    assert_eq!(fixture.round(start + u, false, &[]), ["slot"]);
    assert_eq!(
        fixture.served("slot", start + u).saved_identity,
        bound_probe("user-a", "workspace-b", start).saved_identity
    );
    let (refresh, reads) = fixture.refresh(start + u + 2 * 60);
    assert_eq!((refresh.read, refresh.rate_limited), (2, 0));
    assert_eq!(reads, ["default", "slot"]);
}

/// The slot's id token expired an hour after its own read, while its
/// access token lives: it still names the login it read, so it stays
/// shared, is served the default home's fresh reading, and is read by
/// itself only for the keep-alive.
#[test]
fn a_twin_whose_id_token_expired_stays_shared_until_its_keepalive() {
    let fixture = SameLoginFixture::new(
        "same-login-expired-id-token",
        &[
            ("default", true, "user-a", "workspace-a"),
            ("twin", false, "user-a", "workspace-a"),
        ],
    );
    fixture.sign_in_with_id_token_lifetime("twin", "user-a", "workspace-a", -60);
    assert!(login_mark(fixture.home("twin"), fixture.trust("twin"))
        .binding
        .is_some());
    let u = UNUSED_REFRESH_SECONDS;
    let start = current_unix_seconds();
    assert_eq!(fixture.round(start, false, &[]), ["default", "twin"]);
    assert_eq!(fixture.round(start + 5 * 60, true, &[]), ["default"]);
    assert!(fixture.round(start + u, false, &[]).is_empty());
    assert_eq!(fixture.round(start + 5 * 60 + u, false, &[]), ["default"]);
    let later = start + 5 * 60 + 2 * u;
    assert_eq!(fixture.round(later, false, &[]), ["default"]);
    // Fresh, although the slot's own reading is older than the stale
    // threshold.
    let served = fixture.served("twin", later);
    assert_eq!(served.response_completed_at, Some(rfc3339(later)));
    assert!(served
        .quota_windows
        .iter()
        .all(|window| window.freshness == AgentQuotaWindowFreshness::Fresh));

    let day = start + SAME_LOGIN_KEEPALIVE_SECONDS;
    assert!(!fixture
        .round(day - 60, false, &[])
        .contains(&"twin".to_string()));
    assert!(fixture.round(day, false, &[]).contains(&"twin".to_string()));
}

/// The slot's `auth.json` is rewritten after its read and names no live
/// login (its access token expired): it may hold another one now, so it is
/// never served the default home's reading, and it is back on its own
/// schedule.
#[test]
fn a_rewritten_credential_that_names_no_login_ends_the_sharing() {
    let fixture = SameLoginFixture::new(
        "same-login-rewritten-unnamed",
        &[
            ("default", true, "user-a", "workspace-a"),
            ("twin", false, "user-a", "workspace-a"),
        ],
    );
    fixture.sign_in_with_id_token_lifetime("twin", "user-a", "workspace-a", -60);
    let start = current_unix_seconds();
    assert_eq!(fixture.round(start, false, &[]), ["default", "twin"]);
    assert_eq!(fixture.round(start + 5 * 60, true, &[]), ["default"]);
    assert_eq!(
        fixture.served_at("twin", start + 5 * 60 + 10),
        Ok(rfc3339(start + 5 * 60))
    );

    sign_in_home_with_lifetimes(fixture.home("twin"), "user-a", "workspace-a", -60, -60);
    std::fs::File::options()
        .write(true)
        .open(fixture.home("twin").join("auth.json"))
        .unwrap()
        .set_modified(UNIX_EPOCH + std::time::Duration::from_secs(1_000_000))
        .unwrap();
    assert_eq!(
        fixture.served_at("twin", start + 5 * 60 + 30),
        Err(CODEX_QUOTA_NOT_READ_YET.to_string())
    );
    let u = UNUSED_REFRESH_SECONDS;
    assert!(fixture.round(start + u - 1, false, &[]).is_empty());
    assert_eq!(fixture.round(start + u, false, &[]), ["twin"]);
    assert_eq!(fixture.served_at("twin", start + u), Ok(rfc3339(start + u)));
}

/// When the default home signs into another account, the slot no longer
/// shares its readings: at once it serves its own saved copy, and it is
/// back on its own schedule; the default home's new login is read after a
/// minute. No provider call is needed to notice.
#[test]
fn a_home_that_switches_account_stops_sharing_at_once() {
    let fixture = SameLoginFixture::new(
        "same-login-switch",
        &[
            ("default", true, "user-a", "workspace-a"),
            ("twin", false, "user-a", "workspace-a"),
        ],
    );
    let start = current_unix_seconds();
    assert_eq!(fixture.round(start, false, &[]), ["default", "twin"]);
    assert_eq!(fixture.round(start + 5 * 60, true, &[]), ["default"]);
    assert_eq!(
        fixture.served_at("twin", start + 5 * 60 + 10),
        Ok(rfc3339(start + 5 * 60))
    );

    let switched = start + 5 * 60 + 30;
    fixture.sign_in("default", "user-c", "workspace-c");
    assert_eq!(fixture.served_at("twin", switched), Ok(rfc3339(start)));
    assert_eq!(
        fixture.served_at("default", switched),
        Err(CODEX_QUOTA_NOT_READ_YET.to_string())
    );
    assert_eq!(fixture.round(switched + 61, true, &[]), ["default"]);
    // The slot is read on its own unused interval again, not once a day.
    let u = UNUSED_REFRESH_SECONDS;
    assert!(fixture.round(start + u - 1, false, &[]).is_empty());
    assert_eq!(fixture.round(start + u, false, &[]), ["twin"]);
    assert_eq!(fixture.served_at("twin", start + u), Ok(rfc3339(start + u)));
}

/// A failed read of the home that reads for both ends the sharing: the
/// other home reads on its own schedule and serves its own reading,
/// never the failed home's older one.
#[test]
fn a_failed_shared_read_puts_the_other_home_back_on_its_own_schedule() {
    let fixture = SameLoginFixture::new(
        "same-login-failure",
        &[
            ("default", true, "user-a", "workspace-a"),
            ("twin", false, "user-a", "workspace-a"),
        ],
    );
    let start = current_unix_seconds();
    assert_eq!(fixture.round(start, false, &[]), ["default", "twin"]);
    assert_eq!(fixture.round(start + 5 * 60, true, &[]), ["default"]);
    fixture.failing.lock().unwrap().insert("default");
    assert_eq!(fixture.round(start + 10 * 60, true, &[]), ["default"]);
    assert_eq!(
        fixture.served_at("default", start + 10 * 60),
        Err("Codex app-server quota read timed out.".to_string())
    );
    assert_eq!(
        fixture.served_at("twin", start + 10 * 60),
        Ok(rfc3339(start))
    );
    let u = UNUSED_REFRESH_SECONDS;
    assert_eq!(fixture.round(start + u, true, &[]), ["default", "twin"]);
    // A later good read of the default home shares again.
    fixture.failing.lock().unwrap().clear();
    assert_eq!(fixture.round(start + u + 5 * 60, true, &[]), ["default"]);
    let later = start + 5 * 60 + 2 * u;
    assert_eq!(fixture.round(later, false, &[]), ["default"]);
    assert_eq!(fixture.served_at("twin", later), Ok(rfc3339(later)));
}

/// The keep-alive read of the other home fails (its login died there):
/// that failure is what its card shows, and it reads on its own schedule.
#[test]
fn a_failed_keepalive_read_is_served_and_not_hidden_by_the_shared_reading() {
    let fixture = SameLoginFixture::new(
        "same-login-keepalive-failure",
        &[
            ("default", true, "user-a", "workspace-a"),
            ("twin", false, "user-a", "workspace-a"),
        ],
    );
    let start = current_unix_seconds();
    assert_eq!(fixture.round(start, false, &[]), ["default", "twin"]);
    fixture.failing.lock().unwrap().insert("twin");
    let day = start + SAME_LOGIN_KEEPALIVE_SECONDS;
    assert_eq!(fixture.round(day, true, &[]), ["default", "twin"]);
    assert_eq!(
        fixture.served_at("twin", day + 60),
        Err("Codex app-server quota read timed out.".to_string())
    );
    assert_eq!(fixture.round(day + 5 * 60, true, &[]), ["default"]);
    // Its failed read is retried at the unused interval, not before.
    let u = UNUSED_REFRESH_SECONDS;
    assert_eq!(fixture.round(day + u - 1, true, &[]), ["default"]);
    assert_eq!(fixture.round(day + u, true, &[]), ["twin"]);
}

/// The twin's own read finds its refresh token spent (a dead login): that
/// is what its card shows, never the reader's fresh reading, and it reads
/// on its own schedule from then on.
#[test]
fn a_dead_login_on_the_twin_is_served_and_leaves_the_shared_reading() {
    let fixture = SameLoginFixture::new(
        "same-login-dead-twin",
        &[
            ("default", true, "user-a", "workspace-a"),
            ("twin", false, "user-a", "workspace-a"),
        ],
    );
    let start = current_unix_seconds();
    assert_eq!(fixture.round(start, false, &[]), ["default", "twin"]);
    let dead = format!(
        "{}Codex app-server quota RPC failed with code -32603.",
        crate::agent_status::CODEX_NO_ACCOUNT_FAILURE_PREFIX
    );
    *fixture.failure.lock().unwrap() = dead.clone();
    fixture.failing.lock().unwrap().insert("twin");
    let day = start + SAME_LOGIN_KEEPALIVE_SECONDS;
    assert_eq!(fixture.round(day, true, &[]), ["default", "twin"]);
    assert_eq!(fixture.served_at("twin", day + 60), Err(dead));
    assert_eq!(fixture.round(day + 5 * 60, true, &[]), ["default"]);
    let u = UNUSED_REFRESH_SECONDS;
    assert_eq!(fixture.round(day + u - 1, true, &[]), ["default"]);
    assert_eq!(fixture.round(day + u, true, &[]), ["twin"]);
}

/// An explicit refresh reads homes that hold the same login once, with
/// the same once-a-minute limit.
#[test]
fn an_explicit_refresh_reads_a_shared_login_once() {
    let fixture = SameLoginFixture::new(
        "same-login-refresh",
        &[
            ("default", true, "user-a", "workspace-a"),
            ("twin", false, "user-a", "workspace-a"),
            ("other", false, "user-b", "workspace-a"),
        ],
    );
    let start = current_unix_seconds();
    assert_eq!(
        fixture.round(start, false, &[]),
        ["default", "other", "twin"]
    );
    let (first, reads) = fixture.refresh(start + 2 * 60);
    assert_eq!((first.read, first.rate_limited), (2, 0));
    assert_eq!(reads, ["default", "other"]);
    let (second, reads) = fixture.refresh(start + 2 * 60 + 30);
    assert_eq!((second.read, second.rate_limited), (0, 2));
    assert!(reads.is_empty());
    assert_eq!(
        fixture.served_at("twin", start + 2 * 60 + 30),
        Ok(rfc3339(start + 2 * 60))
    );
}

/// A home with a running daemon sign-in is left off the schedule (as
/// `scheduled_homes` does): the other home reads alone on its own
/// schedule, and the signing-in home is never served the other home's
/// reading for a login it no longer holds.
#[test]
fn a_sign_in_on_one_home_ends_the_sharing_for_both() {
    let fixture = SameLoginFixture::new(
        "same-login-sign-in",
        &[
            ("default", true, "user-a", "workspace-a"),
            ("twin", false, "user-a", "workspace-a"),
        ],
    );
    let start = current_unix_seconds();
    assert_eq!(fixture.round(start, false, &[]), ["default", "twin"]);
    assert_eq!(fixture.round(start + 5 * 60, true, &[]), ["default"]);

    // A sign-in runs in the default home: the slot reads alone.
    let u = UNUSED_REFRESH_SECONDS;
    assert!(fixture.round(start + u - 1, true, &["default"]).is_empty());
    assert_eq!(fixture.round(start + u, true, &["default"]), ["twin"]);
    assert_eq!(fixture.round(start + 2 * u, true, &["default"]), ["twin"]);

    // A sign-in runs in the slot and writes another account, before and
    // after the next round: never the default home's reading.
    let shared = start + 2 * u + 60;
    assert_eq!(fixture.round(shared, true, &[]), ["default"]);
    assert_eq!(fixture.served_at("twin", shared), Ok(rfc3339(shared)));
    fixture.sign_in("twin", "user-d", "workspace-d");
    assert_eq!(
        fixture.served_at("twin", shared),
        Err(CODEX_QUOTA_NOT_READ_YET.to_string())
    );
    assert_eq!(fixture.round(shared + 5 * 60, true, &["twin"]), ["default"]);
    assert_eq!(
        fixture.served_at("twin", shared + 5 * 60),
        Err(CODEX_QUOTA_NOT_READ_YET.to_string())
    );
}
