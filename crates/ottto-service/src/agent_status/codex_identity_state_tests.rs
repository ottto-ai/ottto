use super::*;

/// Change one fixed answer of the synthetic app-server.
#[cfg(unix)]
fn answer_synthetic_codex_app_server(root: &Path, from: &str, to: &str) {
    use std::os::unix::fs::PermissionsExt;

    let executable = root.join("codex");
    let script = std::fs::read_to_string(&executable).expect("fake Codex");
    assert!(script.contains(from), "the fixture answers {from}");
    std::fs::write(&executable, script.replace(from, to)).expect("fake Codex answer");
    std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o755))
        .expect("fake Codex mode");
}

fn slot_codes(status: &CodexAccountSlotCollectionStatusV1) -> Vec<&str> {
    status
        .diagnostics
        .iter()
        .map(|diagnostic| diagnostic.code.as_str())
        .collect()
}

#[cfg(unix)]
fn collect_default(home: &Path, quota_read: CodexQuotaRead) -> CodexSlotCandidate {
    collect_codex_home_candidate(
        default_codex_slot(home),
        "2026-08-26T00:00:00Z",
        "2026-08-26T00:15:00Z",
        quota_read,
    )
}

/// A signed-in login whose limits were simply not read yet is still being
/// checked (`unverified`), not a login whose identity check failed.
#[cfg(unix)]
fn assert_pending(candidate: &CodexSlotCandidate, snapshot_code: &str) {
    assert!(candidate
        .snapshot
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.code == snapshot_code));
    assert_eq!(
        candidate.status.state,
        CodexAccountSlotCollectionStateV1::Unverified,
        "{snapshot_code}"
    );
    assert!(candidate.status.diagnostics.is_empty());
    assert!(candidate.binding.is_none());
    assert!(candidate.status.account_identifier_hash.is_none());
    assert!(candidate.status.workspace_identifier_hash.is_none());
    assert!(candidate.status.quota_snapshot.is_none());
}

#[cfg(unix)]
#[test]
#[serial]
fn codex_login_not_read_yet_is_pending_not_identity_unknown() {
    let (root, home, _guards) = synthetic_default_codex_install("pending-not-read");
    let before = codex_app_server_runs();

    let unread = collect_default(&home, CodexQuotaRead::Saved);
    assert_pending(&unread, "codex_quota_not_read_yet");
    let annotated = annotate_codex_accounts_status(empty_codex_accounts_status());
    assert_eq!(
        annotated.default_slot.collection.state,
        CodexAccountSlotCollectionStateV1::Unverified
    );
    mac_admits_codex_accounts_status(&annotated).expect("a pending login decodes on the Mac");
    assert_eq!(codex_app_server_runs(), before);

    // Once read, the same login is fresh, exactly as before.
    let fresh = collect_default(&home, CodexQuotaRead::Provider);
    assert_eq!(fresh.status.state, CodexAccountSlotCollectionStateV1::Fresh);
    assert!(fresh.binding.is_some());

    let _ = std::fs::remove_dir_all(root);
}

#[cfg(unix)]
#[test]
#[serial]
fn codex_login_with_background_refresh_off_is_pending_not_identity_unknown() {
    use std::os::unix::fs::PermissionsExt;

    let (root, home, _guards) = synthetic_default_codex_install("pending-refresh-off");
    let support = root.join("support");
    std::fs::set_permissions(&support, std::fs::Permissions::from_mode(0o700))
        .expect("private support dir");
    codex_saved_quota::forget_running_homes();
    ottto_core::FileCodexAccountSlotSettingsStore::default()
        .set_quota_refresh_consent(1, false)
        .expect("turn off");

    let unread = collect_default(&home, CodexQuotaRead::Saved);
    assert_pending(&unread, "codex_quota_background_refresh_off");
    let annotated = annotate_codex_accounts_status(empty_codex_accounts_status());
    assert_eq!(
        annotated.default_slot.collection.state,
        CodexAccountSlotCollectionStateV1::Unverified
    );
    mac_admits_codex_accounts_status(&annotated).expect("a pending login decodes on the Mac");

    let _ = std::fs::remove_dir_all(root);
}

/// Each identity check the provider read can fail keeps `identity_unknown`
/// and names that check on the slot row: a code only, never the compared
/// emails or plans. The saved copy of that read says the same.
#[cfg(unix)]
#[test]
#[serial]
fn codex_identity_rejection_names_the_failed_check() {
    let account_answer = r#""email":"synthetic-account","planType":"pro"}"#;
    let limits_answer = r#""limitId":"synthetic-limit","planType":"pro""#;
    let reasons = [
        "codex_identity_email_mismatch",
        "codex_identity_plan_mismatch_account_read",
        "codex_identity_plan_mismatch_rate_limits",
    ];
    for (label, from, to, reason) in [
        (
            "email",
            account_answer,
            r#""email":"other-account","planType":"pro"}"#,
            reasons[0],
        ),
        (
            "plan-account",
            account_answer,
            r#""email":"synthetic-account","planType":"plus"}"#,
            reasons[1],
        ),
        (
            "plan-limits",
            limits_answer,
            r#""limitId":"synthetic-limit","planType":"plus""#,
            reasons[2],
        ),
    ] {
        let (root, home, _guards) = synthetic_default_codex_install(&format!("reject-{label}"));
        answer_synthetic_codex_app_server(&root, from, to);

        for quota_read in [CodexQuotaRead::Provider, CodexQuotaRead::Saved] {
            let rejected = collect_default(&home, quota_read);
            assert_eq!(
                rejected.status.state,
                CodexAccountSlotCollectionStateV1::IdentityUnknown,
                "{label}"
            );
            assert!(rejected.binding.is_none(), "{label}");
            assert!(rejected.status.account_identifier_hash.is_none());
            assert!(rejected.status.quota_snapshot.is_none());
            let codes = slot_codes(&rejected.status);
            // The first code is the one clients read; it is unchanged.
            assert_eq!(codes.first(), Some(&"codex_identity_unknown"), "{label}");
            assert_eq!(
                codes
                    .iter()
                    .filter(|code| reasons.contains(code))
                    .collect::<Vec<_>>(),
                vec![&reason],
                "{label}: {codes:?}"
            );
            let row = serde_json::to_string(&rejected.status.diagnostics).expect("slot JSON");
            for value in ["synthetic-account", "other-account", "plus"] {
                assert!(!row.contains(value), "{label}: {value} in {row}");
            }
        }
        let annotated = annotate_codex_accounts_status(empty_codex_accounts_status());
        assert_eq!(
            annotated.default_slot.collection.state,
            CodexAccountSlotCollectionStateV1::IdentityUnknown
        );
        mac_admits_codex_accounts_status(&annotated)
            .unwrap_or_else(|error| panic!("{label} decodes on the Mac: {error}"));

        let _ = std::fs::remove_dir_all(root);
    }
}

/// A valid identity keeps today's accepted state, and a pending login beside
/// it changes nothing about the accepted account's row: same state, hashes
/// and reading.
#[cfg(unix)]
#[test]
#[serial]
fn codex_valid_identity_and_accepted_rows_are_unchanged() {
    use std::os::unix::fs::PermissionsExt;

    let (root, home, _guards) = synthetic_default_codex_install("identity-valid");
    let managed_home = root.join("managed-home");
    std::fs::create_dir(&managed_home).expect("managed home");
    std::fs::set_permissions(&managed_home, std::fs::Permissions::from_mode(0o700))
        .expect("managed home mode");
    std::fs::copy(home.join("auth.json"), managed_home.join("auth.json")).expect("managed auth");
    std::fs::set_permissions(
        managed_home.join("auth.json"),
        std::fs::Permissions::from_mode(0o600),
    )
    .expect("managed auth mode");
    // Before any reading exists, so no saved reading is shared with it.
    let pending = collect_codex_home_candidate(
        CodexHomeSlot {
            slot_id: "codex_slot_pending".to_string(),
            ownership: CodexAccountSlotOwnershipV1::Managed,
            home: managed_home,
            registered_binding: None,
        },
        "2026-08-26T00:00:00Z",
        "2026-08-26T00:15:00Z",
        CodexQuotaRead::Saved,
    );
    assert_pending(&pending, "codex_quota_not_read_yet");

    let fresh = collect_default(&home, CodexQuotaRead::Provider);
    assert_eq!(fresh.status.state, CodexAccountSlotCollectionStateV1::Fresh);
    assert!(fresh.binding.is_some());
    assert!(fresh.status.diagnostics.is_empty());
    assert!(fresh
        .snapshot
        .diagnostics
        .iter()
        .all(|diagnostic| !diagnostic.code.starts_with("codex_identity_")));

    let (account, workspace) = fresh.binding.clone().expect("accepted binding");
    let alone = codex_accounts_status_for(std::slice::from_ref(&fresh));
    let candidates = [fresh, pending];
    let together = codex_accounts_status_for(&candidates);
    mac_admits_codex_accounts_status(&together).expect("both rows decode on the Mac");
    assert_eq!(
        together.default_slot.collection,
        alone.default_slot.collection
    );
    assert_eq!(
        together.managed_slots[0].collection.state,
        CodexAccountSlotCollectionStateV1::Unverified
    );
    let accepted = &together.default_slot.collection;
    assert_eq!(accepted.state, CodexAccountSlotCollectionStateV1::Fresh);
    assert_eq!(accepted.account_identifier_hash, Some(account));
    assert_eq!(accepted.workspace_identifier_hash, Some(workspace));
    assert!(accepted.quota_snapshot.is_some());

    let _ = std::fs::remove_dir_all(root);
}
