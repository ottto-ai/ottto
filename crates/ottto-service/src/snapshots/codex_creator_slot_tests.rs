//! Codex sessions named from their own creator record: rows recording no login
//! mode are named by the single registered slot their creator pair matches,
//! when that slot's saved login is a subscription login.

use super::tests::{manifest_index_entry, valid_v6_batch_request};
use super::*;
use crate::codex_scan_diagnostics::{
    CREATOR_API_KEY as API_KEY, CREATOR_MODE_UNREADABLE as MODE_UNREADABLE,
    CREATOR_MULTI_MATCH as MULTI_MATCH, CREATOR_NAMED as NAMED,
    CREATOR_NOT_FORCED_CHATGPT as NOT_FORCED, CREATOR_NO_MATCH as NO_MATCH,
};

const HOME_A: &str = "/synthetic/codex-slot-a";

fn slot(account: &str, cause: usize) -> (String, String, usize) {
    (account.into(), format!("{account}-workspace"), cause)
}

fn creator(account: Option<&str>, disposition: Option<&'static str>) -> SessionAccountEvidence {
    SessionAccountEvidence {
        provider: "openai",
        account_identifier_hash: account.map(str::to_string),
        provider_workspace_hash: account.map(|account| format!("{account}-workspace")),
        identity_hash_scheme: "provider-sha256:v1",
        evidence_source: "codex_creator_header:v1",
        identity_disposition: disposition,
        source_created_at: None,
    }
}

/// Binds one Codex session found in slot A's home, created per `evidence`,
/// whose rows and buckets record `modes`. Returns the session's account, its
/// retained binding and the scan's creator counts.
fn bind(
    evidence: SessionAccountEvidence,
    slots: &[(String, String, usize)],
    (row_mode, bucket_mode): (Option<&str>, Option<&str>),
    cached: Option<&str>,
) -> (Option<String>, Option<SessionAccountBinding>, [u64; 6]) {
    let key = sha256_hex(&["session_owner:v1", "machine", "creator-session"]);
    let home = crate::agent_status::CodexHomeBinding {
        home: PathBuf::from(HOME_A),
        account_identifier_hash: "slot-a".into(),
        workspace_identifier_hash: "slot-a-workspace".into(),
        auth_modified_at: UNIX_EPOCH,
    };
    let mut index = ScanIndex::default();
    let mut item = valid_v6_batch_request().snapshots.remove(0);
    item.source_session_id = "creator-session".into();
    item.source_started_at = Some("2026-10-05T00:00:00Z".into());
    item.source_file_fingerprint = Some("creator-file".into());
    for row in &mut item.model_usage {
        row.auth_mode = row_mode.map(str::to_string);
    }
    for bucket in &mut item.usage_buckets {
        for row in &mut bucket.model_usage {
            row.auth_mode = bucket_mode.map(str::to_string);
        }
    }
    item.session_account_evidence = Some(evidence.clone());
    let mut entry = manifest_index_entry(None);
    entry.source_file_fingerprint = "creator-file".into();
    let path = Path::new(HOME_A).join("sessions/rollout.jsonl");
    index.files.insert(local_index_key(&path), entry);
    if let Some(cached) = cached {
        let owner = SessionAccountBinding {
            account_identifier_hash: cached.into(),
            workspace_identifier_hash: None,
        };
        index.session_account_bindings.insert(key.clone(), owner);
    }
    let mut counts = [0; 6];
    let deferred = index.bind_session_accounts_with_mixed(
        SnapshotSource::Codex,
        "machine",
        std::slice::from_mut(&mut item),
        std::slice::from_ref(&home),
        (slots, &mut counts),
        &Default::default(),
    );
    assert!(deferred.is_empty());
    assert_eq!(
        item.session_account_evidence,
        Some(evidence),
        "sent unchanged"
    );
    assert!(
        item.model_usage
            .iter()
            .all(|row| row.auth_mode.as_deref() == row_mode),
        "no login mode is written onto rows"
    );
    let binding = index.session_account_bindings.get(&key).cloned();
    (exact_session_account_hash(&item), binding, counts)
}

fn counted(cause: usize) -> [u64; 6] {
    let mut counts = [0; 6];
    counts[cause] = 1;
    counts
}

/// [regress] Codex rollouts record no login mode, so no Codex session was
/// named. One whose creator pair matches its single registered subscription
/// slot is now named by that slot and counted.
#[test]
fn codex_creator_pair_names_its_single_subscription_slot() {
    let slots = [slot("slot-a", NAMED), slot("slot-b", NAMED)];
    let named = bind(creator(Some("slot-a"), None), &slots, (None, None), None);
    let owner = SessionAccountBinding {
        account_identifier_hash: "slot-a".into(),
        workspace_identifier_hash: Some("slot-a-workspace".into()),
    };
    assert_eq!(named, (Some("slot-a".into()), Some(owner), counted(NAMED)));
}

/// D185: a session found in slot A's home whose creator pair matches slot B
/// is named B, never A.
#[test]
fn codex_creator_pair_names_its_slot_never_the_home_it_was_found_in() {
    let slots = [slot("slot-a", NAMED), slot("slot-b", NAMED)];
    let named = bind(creator(Some("slot-b"), None), &slots, (None, None), None);
    let owner = SessionAccountBinding {
        account_identifier_hash: "slot-b".into(),
        workspace_identifier_hash: Some("slot-b-workspace".into()),
    };
    assert_eq!(named, (Some("slot-b".into()), Some(owner), counted(NAMED)));
}

/// One control per refusal cause, the slot login causes read from synthetic
/// slot homes. Every refusal names nothing (never the home), and only slot
/// decisions are counted. A null stored key is no key; rows proving OAuth keep
/// today's home owner; an owner of the creator's account stands.
#[cfg(unix)]
#[test]
fn codex_creator_slot_refusals_name_nothing_and_count_their_cause() {
    use std::os::unix::fs::PermissionsExt;
    let forced = "cli_auth_credentials_store = \"file\"\nforced_login_method = \"chatgpt\"\n";
    let login = |label: &str, config: &str, auth: serde_json::Value, env_api_key: bool| {
        let home = crate::test_scratch::ScratchDir::canonical(&format!("codex-slot-{label}"));
        for (name, body) in [
            ("config.toml", config.to_string()),
            ("auth.json", auth.to_string()),
        ] {
            std::fs::write(home.join(name), body).expect("slot fixture");
            let mode = std::fs::Permissions::from_mode(0o600);
            std::fs::set_permissions(home.join(name), mode).expect("slot fixture mode");
        }
        crate::agent_status::codex_slot_login_cause(&home, env_api_key)
    };
    let chatgpt = serde_json::json!({"auth_mode": "chatgpt", "OPENAI_API_KEY": null,
        "tokens": {"access_token": "synthetic-token"}});
    let stored = serde_json::json!({"auth_mode": "chatgpt", "OPENAI_API_KEY": "synthetic"});
    let null_key = login("null-key", forced, chatgpt.clone(), false);
    let stored_key = login("stored-key", forced, stored, false);
    let env_key = login("env-key", forced, chatgpt.clone(), true);
    let api_mode = login(
        "api-mode",
        forced,
        serde_json::json!({"auth_mode": "apikey"}),
        false,
    );
    let not_forced = login("not-forced", "", chatgpt, false);
    let with_b = |cause| [slot("slot-a", NAMED), slot("slot-b", cause)];
    let (a_c, b_b) = (
        [slot("slot-a", NAMED), slot("slot-c", NAMED)],
        [slot("slot-b", NAMED), slot("slot-b", NAMED)],
    );
    for (label, slots, cause) in [
        ("null key", with_b(null_key), NAMED),
        ("stored key", with_b(stored_key), API_KEY),
        ("env key", with_b(env_key), API_KEY),
        ("api mode", with_b(api_mode), MODE_UNREADABLE),
        ("not forced", with_b(not_forced), NOT_FORCED),
        ("no match", a_c, NO_MATCH),
        ("multi match", b_b, MULTI_MATCH),
    ] {
        let (named, _, counts) = bind(creator(Some("slot-b"), None), &slots, (None, None), None);
        let expected = (cause == NAMED).then_some("slot-b");
        assert_eq!(
            (named.as_deref(), counts),
            (expected, counted(cause)),
            "{label}"
        );
    }
    // Controls the slot never decides: nothing is counted.
    let (a, b, none) = (Some("slot-a"), Some("slot-b"), (None, None));
    let (oauth, api, mixed) = (
        (Some("oauth"), Some("oauth")),
        (Some("api_key"), Some("api_key")),
        (Some("oauth"), None),
    );
    for (label, slots, account, modes, cached, expected) in [
        ("negative", with_b(NAMED), None, none, None, None),
        ("api rows", with_b(NAMED), b, api, None, None),
        ("mixed rows", with_b(NAMED), b, mixed, None, None),
        ("oauth rows", with_b(NAMED), b, oauth, None, a),
        ("retained", with_b(API_KEY), b, none, b, b),
        ("other owner", with_b(NAMED), b, none, a, None),
    ] {
        let evidence = creator(account, account.is_none().then_some("missing"));
        let (named, _, counts) = bind(evidence, &slots, modes, cached);
        assert_eq!((named.as_deref(), counts), (expected, [0; 6]), "{label}");
    }
}
