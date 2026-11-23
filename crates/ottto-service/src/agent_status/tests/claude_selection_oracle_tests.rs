//! Full synthetic receipts at the existing Claude selection boundaries.
//! These exercise decision helpers, not a second implementation of collection.
//! Provider-success completion clocks and composed fallback selection belong
//! at the collection boundary.
use super::*;
use serde_json::json;
use sha2::{Digest, Sha256};

const CAPTURED: &str = "2026-08-05T01:05:00Z";
const EXPIRES: &str = "2026-08-05T01:10:00Z";

fn binding(account: &str, organization: &str) -> ClaudeStrongBinding {
    ClaudeStrongBinding::new(account, organization).unwrap()
}

// Literal expected wire data, independent of the decision/projection helpers.
// Keep required nulls and optional field absence exactly as on the wire.
fn window(account: &str, organization: &str, name: &str, percent: u8) -> Value {
    json!({
        "name": name, "scope": "account", "status": "ok", "freshness": "fresh",
        "observed_at": "2026-08-05T01:00:00Z",
        "account_identifier_hash": account, "organization_identifier_hash": organization,
        "window_seconds": 18000, "resets_at": "2026-08-05T05:00:00Z",
        "quota": null, "remaining": null, "used_percent": percent, "left_percent": 100-percent
    })
}

fn credit(account: &str, organization: &str) -> Value {
    json!({
        "name": "Usage credits", "status": "ok", "freshness": "fresh",
        "unit": "credits", "account_identifier_hash": account,
        "organization_identifier_hash": organization, "remaining": "7.890001",
        "used": "2.109999", "quota": 10, "updated_at": "2026-08-05T01:00:00Z"
    })
}

fn full_snapshot(account: &str, organization: &str, percent: u8) -> Value {
    let mut scoped = window(account, organization, "weekly_sonnet", 56);
    scoped["scope"] = json!("model");
    scoped["model"] = json!("claude-sonnet");
    json!({
        "source": "claude_code", "status": "available", "collection_method": "cli_json",
        "captured_at": CAPTURED, "expires_at": EXPIRES,
        "account": {
            "login_state": "signed_in", "provider": "anthropic", "auth_method": "oauth",
            "email": "synthetic@example.invalid", "account_id": "synthetic-account",
            "organization_id": "synthetic-organization", "organization_label": "Synthetic",
            "plan_type": "max", "subscription_product": "claude_max_20x",
            "billing_channel": "subscription", "account_identifier_hash": account,
            "organization_identifier_hash": organization, "billing_identity_evidence": "provider_account_id",
            "billing_identity_confidence": "high", "confidence": "high"
        },
        "quota_windows": [window(account, organization, "session", percent),
            window(account, organization, "weekly", 34), scoped],
        "credit_balances": [credit(account, organization)],
        "capabilities": [], "plan_observations": [], "diagnostics": []
    })
}

fn candidate(
    slot: &str,
    account: &str,
    organization: &str,
    tier: u8,
    percent: u8,
) -> ClaudeSnapshotCandidate {
    ClaudeSnapshotCandidate {
        slot_id: slot.to_string(),
        slot_class: if slot == "default" {
            ClaudeSnapshotSlotClass::Default
        } else {
            ClaudeSnapshotSlotClass::Registered
        },
        binding: binding(account, organization),
        quality: ClaudeSnapshotQuality {
            tier,
            provider_observed_at: "2026-08-05T01:00:00Z".to_string(),
        },
        snapshot: serde_json::from_value(full_snapshot(account, organization, percent)).unwrap(),
    }
}

fn candidate_inputs(candidates: &[ClaudeSnapshotCandidate]) -> Value {
    json!(candidates.iter().map(|c| json!({
        "slot_id": c.slot_id, "class": format!("{:?}", c.slot_class),
        "account": c.binding.account_identifier_hash, "organization": c.binding.organization_identifier_hash,
        "tier": c.quality.tier, "provider_observed_at": c.quality.provider_observed_at,
        "snapshot": c.snapshot
    })).collect::<Vec<_>>())
}

fn snapshot_views(snapshots: &[AgentStatusSnapshot]) -> Value {
    json!({"local": snapshots, "backend": snapshots.iter().cloned()
        .map(AgentStatusSnapshot::redacted_for_backend).collect::<Vec<_>>()})
}

fn expected_views(snapshots: Vec<Value>) -> Value {
    json!({"local": snapshots, "backend": snapshots})
}

fn selection_rows(
    candidates: &[ClaudeSnapshotCandidate],
    selection: &ClaudeSnapshotSelection,
) -> Value {
    // Preserve source order; maps become rows because bindings are compound keys.
    json!({
        "winners": selection.winning_by_binding.iter().map(|(b,i)| json!([
            b.account_identifier_hash,b.organization_identifier_hash,i])).collect::<Vec<_>>(),
        "anchors": selection.preferred_anchor_by_binding.iter().map(|(b,i)| json!([
            b.account_identifier_hash,b.organization_identifier_hash,i])).collect::<Vec<_>>(),
        "dispositions": candidates.iter().enumerate().map(|(i,c)|
            format!("{:?}",claude_snapshot_candidate_disposition(i,c,selection))).collect::<Vec<_>>()
    })
}

pub(super) fn emit(name: &str, inputs: Value, actual: Value, expected: Value) {
    assert_eq!(actual, expected, "{name}: complete receipt");
    let root = std::env::var_os("OTTTO_MONEY_EQUIVALENCE_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| std::env::temp_dir().join("ottto-claude-selection-oracle"));
    fs::create_dir_all(&root).unwrap();
    let inputs = serde_json::to_vec(&inputs).unwrap();
    fs::write(root.join(format!("{name}.inputs")), &inputs).unwrap();
    let bytes = serde_json::to_vec(&json!({"kind":"plain_json_v1","value":actual})).unwrap();
    let digest = format!("{:x}", Sha256::digest(&bytes));
    if let Some(out) = std::env::var_os("OTTTO_MONEY_EQUIVALENCE_OUTPUT") {
        let out = PathBuf::from(out);
        fs::create_dir_all(&out).unwrap();
        fs::write(out.join(format!("{name}.inputs")), &inputs).unwrap();
        for suffix in ["json", "cross-build.json"] {
            fs::write(out.join(format!("{name}.{suffix}")), &bytes).unwrap();
        }
        for suffix in ["sha256", "cross-build.sha256"] {
            fs::write(out.join(format!("{name}.{suffix}")), &digest).unwrap();
        }
    }
    println!(
        "MONEY_EQUIVALENCE {name} VERIFIED bytes={} sha256={digest} cross_build_sha256={digest}",
        bytes.len()
    );
}

fn status(account: &str, organization: &str, state: &str) -> ClaudeConfigSlotCollectionStatusV1 {
    serde_json::from_value(json!({
        "state":state,"account_identifier_hash":account,"organization_identifier_hash":organization,
        "observed_at":CAPTURED,"has_account_windows":false,"has_scoped_limits":false,
        "has_credit_balances":false,"diagnostics":[]
    }))
    .unwrap()
}

fn plan(account: &str, organization: Option<&str>) -> AgentStatusPlanObservation {
    serde_json::from_value(json!({"account_identifier_hash":account,
        "organization_identifier_hash":organization,"observed_at":CAPTURED,
        "provider":"anthropic","auth_mode":"oauth","billing_channel":"subscription",
        "subscription_product":"claude_max_20x","confidence":"high","is_current":true}))
    .unwrap()
}

// Every changed hook is restored on unwind. HOME also redirects the existing
// effective-user-home guard; these fixtures never acquire a credential.
pub(super) struct OAuthGuard {
    _environment: Vec<EnvVarGuard>,
    responder: Option<ClaudeOAuthTestResponder>,
    before_send: Option<fn()>,
    forbidden: bool,
    pub(super) calls: usize,
    callers: BTreeMap<String, claude_credit_pools::ClaudeCallerBinding>,
    passes: (usize, BTreeSet<String>),
    transient_failures: Vec<ClaudeBindingTime>,
    rate_limit_holds: Vec<ClaudeBindingTime>,
    explicit_attempts: Vec<ClaudeBindingTime>,
    explicit_request: ClaudeExplicitRefreshRequest,
}

impl OAuthGuard {
    pub(super) fn new(name: &str) -> Self {
        use std::sync::atomic::Ordering::SeqCst;
        let root = std::env::var_os("OTTTO_MONEY_EQUIVALENCE_ROOT")
            .map(PathBuf::from)
            .unwrap_or_else(|| std::env::temp_dir().join("ottto-claude-selection-oracle"))
            .join(name);
        if root.exists() {
            fs::remove_dir_all(&root).unwrap();
        }
        let home = root.join("home");
        let support = root.join("support");
        let bin = root.join("bin");
        for dir in [&home, &support, &bin] {
            fs::create_dir_all(dir).unwrap();
        }
        Self {
            _environment: vec![
                EnvVarGuard::set_os("HOME", home.into_os_string()),
                EnvVarGuard::set_os("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", support.into_os_string()),
                EnvVarGuard::set_os("PATH", bin.into_os_string()),
            ],
            responder: CLAUDE_OAUTH_TEST_RESPONSE.lock().unwrap().take(),
            before_send: CLAUDE_OAUTH_BEFORE_SEND_HOOK.lock().unwrap().take(),
            forbidden: CLAUDE_OAUTH_PROVIDER_CALLS_FORBIDDEN.swap(true, SeqCst),
            calls: CLAUDE_OAUTH_PROVIDER_CALLS.load(SeqCst),
            callers: std::mem::take(&mut *CLAUDE_OAUTH_CALLER_BINDINGS.lock().unwrap()),
            passes: std::mem::take(&mut *CLAUDE_OAUTH_PASS_CALLERS.lock().unwrap()),
            transient_failures: std::mem::take(&mut claude_transient_failures()),
            rate_limit_holds: std::mem::take(&mut claude_rate_limit_holds()),
            explicit_attempts: std::mem::take(&mut claude_explicit_refresh_attempts()),
            explicit_request: std::mem::replace(
                &mut claude_explicit_refresh_request(),
                ClaudeExplicitRefreshRequest {
                    at: 0,
                    trigger: crate::provider_calls::Trigger::ExplicitRefresh,
                },
            ),
        }
    }
}

impl Drop for OAuthGuard {
    fn drop(&mut self) {
        use std::sync::atomic::Ordering::SeqCst;
        *CLAUDE_OAUTH_TEST_RESPONSE
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = self.responder;
        *CLAUDE_OAUTH_BEFORE_SEND_HOOK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = self.before_send;
        *CLAUDE_OAUTH_CALLER_BINDINGS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = std::mem::take(&mut self.callers);
        *CLAUDE_OAUTH_PASS_CALLERS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = std::mem::take(&mut self.passes);
        *claude_transient_failures() = std::mem::take(&mut self.transient_failures);
        *claude_rate_limit_holds() = std::mem::take(&mut self.rate_limit_holds);
        *claude_explicit_refresh_attempts() = std::mem::take(&mut self.explicit_attempts);
        std::mem::swap(
            &mut *claude_explicit_refresh_request(),
            &mut self.explicit_request,
        );
        CLAUDE_OAUTH_PROVIDER_CALLS_FORBIDDEN.store(self.forbidden, SeqCst);
        CLAUDE_OAUTH_PROVIDER_CALLS.store(self.calls, SeqCst);
    }
}

fn usage_value(usage: &ClaudeOAuthUsage) -> Value {
    json!({"windows":usage.windows,"credits":usage.credit_balances,
        "account_weekly_not_offered":usage.account_weekly_not_offered,"account_session_not_offered":usage.account_session_not_offered})
}

pub(super) fn outcome_value(outcome: &ClaudeOAuthUsageOutcome) -> Value {
    json!({"result":match &outcome.result {Ok(usage)=>json!({"ok":usage_value(usage)}),Err(error)=>json!({"error":error})},
        "diagnostics":outcome.diagnostics})
}

fn expected_plan(account: &str, organization: &str) -> Value {
    json!({"account_identifier_hash":account,"organization_identifier_hash":organization,
        "observed_at":CAPTURED,"provider":"anthropic","auth_mode":"oauth","billing_channel":"subscription",
        "subscription_product":"claude_max_20x","confidence":"high","billing_identity_confidence":"unknown","is_current":true})
}

fn desktop_pair(account: &str, organization: &str) -> ClaudeDesktopPairObservation {
    ClaudeDesktopPairObservation {
        binding: binding(account, organization),
        observation: plan(account, Some(organization)),
    }
}

fn expected_desktop(observations: Vec<Value>, only: bool) -> Value {
    json!({"source":"claude_code","status":"available","collection_method":"command_probe","captured_at":CAPTURED,"expires_at":EXPIRES,
        "quota_windows":[{"name":"usage","scope":"source","status":"unsupported","freshness":"unsupported",
            "window_seconds":null,"resets_at":null,"quota":null,"remaining":null,"used_percent":null,"left_percent":null}],
        "credit_balances":[],"plan_observations":observations,
        "capabilities":[{"capability":"desktop_identity","status":"supported","detail":"Read display-safe Claude Desktop account/organization session-folder metadata."},
            {"capability":"quota_windows","status":"unsupported","detail":"Claude Desktop session folders carry no usage limits; a Claude Code login for the account is needed to show them."}],
        "diagnostics":[{"code":"claude_desktop_profile_detected","severity":"info","message":"Claude Desktop Code account/session bucket metadata was detected."},
            if only {json!({"code":"claude_desktop_only_no_cli_login","severity":"info","message":"No Claude Code login on this Mac can be uploaded; Claude Desktop account/organization folders are reported without limits."})}
            else {json!({"code":"claude_desktop_uncovered_pairs","severity":"info","message":"Claude Desktop account/organization folders that no uploaded Claude Code login covers are reported without limits."})}]})
}

mod money_equivalence_tests {
    use super::*;

    /// [money] Default-only selection and the complete local/upload boundary.
    #[test]
    fn s01_default_only_full_row() {
        let candidates = vec![candidate("default", "account-a", "org-x", 4, 12)];
        let inputs = candidate_inputs(&candidates);
        let selected = select_claude_snapshot_candidates(&candidates, &BTreeMap::new());
        let decisions = selection_rows(&candidates, &selected);
        let uploaded = claude_uploaded_candidate_snapshot(
            candidates.into_iter().next().unwrap(),
            &BTreeMap::new(),
            &BTreeMap::new(),
            &BTreeMap::new(),
            &BTreeSet::new(),
        );
        let mut expected = full_snapshot("account-a", "org-x", 12);
        expected["account"]["claude_anchor_durability"] = json!("default_only");
        emit(
            "claude_status_s01_default_only",
            inputs,
            json!({"selection":decisions,"snapshots":snapshot_views(&[uploaded])}),
            json!({"selection":{"winners":[["account-a","org-x",0]],"anchors":[],"dispositions":["Upload"]},
                "snapshots":expected_views(vec![expected])}),
        );
    }

    /// [money] Equal meter quality uses the lexical registered anchor.
    #[test]
    fn s02_lexical_anchor() {
        let candidates = vec![
            candidate("default", "account-a", "org-x", 4, 12),
            candidate("claude_slot_b", "account-a", "org-x", 4, 12),
            candidate("claude_slot_a", "account-a", "org-x", 4, 12),
        ];
        let selected = select_claude_snapshot_candidates(&candidates, &BTreeMap::new());
        emit(
            "claude_status_s02_lexical_tie",
            candidate_inputs(&candidates),
            json!({"selection":selection_rows(&candidates,&selected),"snapshots":snapshot_views(&candidates.iter().map(|c|c.snapshot.clone()).collect::<Vec<_>>())}),
            json!({"selection":{"winners":[["account-a","org-x",2]],"anchors":[["account-a","org-x",2]],
                "dispositions":["ShadowDefault","DuplicateRegistered","Upload"]},
                "snapshots":expected_views(vec![full_snapshot("account-a","org-x",12);3])}),
        );
    }

    /// [money] A working weak-meter anchor beats a dead complete-meter login.
    #[test]
    fn s03_health_first_canonical() {
        let mut live = status("account-a", "org-x", "fresh");
        live.access_expires_at = Some("2099-01-01T00:00:00Z".to_string());
        let mut dead = status("account-a", "org-x", "needs_login");
        dead.has_account_windows = true;
        dead.has_scoped_limits = true;
        dead.access_expires_at = Some("2000-01-01T00:00:00Z".to_string());
        let states = BTreeMap::from([
            ("claude_slot_a".to_string(), dead),
            ("claude_slot_b".to_string(), live),
        ]);
        let canonical = canonical_registered_anchors(states.keys().cloned(), &states);
        let candidates = vec![
            candidate("claude_slot_a", "account-a", "org-x", 4, 12),
            candidate("claude_slot_b", "account-a", "org-x", 3, 23),
        ];
        let selected = select_claude_snapshot_candidates(&candidates, &canonical);
        emit(
            "claude_status_s03_health_first",
            json!({"states":states,"candidates":candidate_inputs(&candidates)}),
            json!({"selection":selection_rows(&candidates,&selected),"states":states}),
            json!({"selection":{"winners":[["account-a","org-x",1]],"anchors":[["account-a","org-x",1]],
                "dispositions":["DuplicateRegistered","Upload"]},"states":{
                "claude_slot_a":{"state":"needs_login","account_identifier_hash":"account-a","organization_identifier_hash":"org-x",
                    "observed_at":CAPTURED,"access_expires_at":"2000-01-01T00:00:00Z","has_account_windows":true,"has_scoped_limits":true,"has_credit_balances":false,"diagnostics":[]},
                "claude_slot_b":{"state":"fresh","account_identifier_hash":"account-a","organization_identifier_hash":"org-x",
                    "observed_at":CAPTURED,"access_expires_at":"2099-01-01T00:00:00Z","has_account_windows":false,"has_scoped_limits":false,"has_credit_balances":false,"diagnostics":[]}}}),
        );
    }

    /// [money] A better default carries only its exact anchor's closed receipt.
    #[test]
    fn s04_better_default_closed_receipt() {
        let mut anchor = status("account-a", "org-x", "needs_login");
        anchor.quota_check_diagnostics = vec![serde_json::from_value(json!({
            "code":"claude_slot_worker_needs_login","severity":"warning",
            "message":"This local Claude login needs sign-in.",
            "observed_at":"2026-08-05T00:59:00Z","account_identifier_hash":"account-a",
            "organization_identifier_hash":"org-x"
        }))
        .unwrap()];
        let states = BTreeMap::from([("claude_slot_a".to_string(), anchor)]);
        let canonical =
            BTreeMap::from([(binding("account-a", "org-x"), "claude_slot_a".to_string())]);
        let health = canonical_anchor_health(&canonical, &states);
        let candidates = vec![
            candidate("default", "account-a", "org-x", 4, 12),
            candidate("claude_slot_a", "account-a", "org-x", 1, 23),
        ];
        let input = json!({"states":states,"candidates":candidate_inputs(&candidates)});
        let selected = select_claude_snapshot_candidates(&candidates, &canonical);
        let decisions = selection_rows(&candidates, &selected);
        let uploaded = claude_uploaded_candidate_snapshot(
            candidates.into_iter().next().unwrap(),
            &health,
            &canonical,
            &states,
            &BTreeSet::new(),
        );
        let mut expected = full_snapshot("account-a", "org-x", 12);
        expected["account"]["claude_anchor_durability"] = json!("anchored");
        expected["account"]["claude_anchor_health"] = json!("reconnect_required");
        // The receipt's closed vocabulary supplies its text; it keeps the original clock.
        expected["diagnostics"] = json!([{
            "code":"claude_slot_worker_needs_login","severity":"warning",
            "message":"The local worker returned this upkeep outcome; no quota provider check, vendor-command attempt, or current limits observation is implied.","observed_at":"2026-08-05T00:59:00Z",
            "account_identifier_hash":"account-a","organization_identifier_hash":"org-x"
        }]);
        emit(
            "claude_status_s04_anchor_receipt",
            input,
            json!({"selection":decisions,"snapshots":snapshot_views(&[uploaded])}),
            json!({"selection":{"winners":[["account-a","org-x",0]],"anchors":[["account-a","org-x",1]],
                "dispositions":["Upload","PreserveRegisteredAnchor"]},"snapshots":expected_views(vec![expected])}),
        );
    }

    /// [money] Neither shared account nor shared organization merges exact pairs.
    #[test]
    fn s05_three_exact_pairs() {
        let candidates = vec![
            candidate("claude_slot_a", "account-a", "org-x", 4, 12),
            candidate("claude_slot_b", "account-a", "org-y", 4, 23),
            candidate("claude_slot_c", "account-b", "org-x", 4, 45),
        ];
        let selected = select_claude_snapshot_candidates(&candidates, &BTreeMap::new());
        emit(
            "claude_status_s05_exact_pairs",
            candidate_inputs(&candidates),
            json!({"selection":selection_rows(&candidates,&selected),"snapshots":snapshot_views(&candidates.iter().map(|c|c.snapshot.clone()).collect::<Vec<_>>())}),
            json!({"selection":{"winners":[["account-a","org-x",0],["account-a","org-y",1],["account-b","org-x",2]],
                "anchors":[["account-a","org-x",0],["account-a","org-y",1],["account-b","org-x",2]],"dispositions":["Upload","Upload","Upload"]},
                "snapshots":expected_views(vec![full_snapshot("account-a","org-x",12),full_snapshot("account-a","org-y",23),full_snapshot("account-b","org-x",45)])}),
        );
    }

    /// [money] Unknown registry ownership withholds a winner without substituting a degraded row.
    #[test]
    fn s06_unknown_registry_withholds() {
        let states = BTreeMap::from([(
            "claude_slot_a".to_string(),
            status("account-a", "org-x", "provider_unavailable"),
        )]);
        let candidates = vec![candidate("default", "account-a", "org-x", 4, 12)];
        let selected = select_claude_snapshot_candidates(&candidates, &BTreeMap::new());
        let owned = claude_registered_owned_bindings(false, &[], &BTreeMap::new(), &states);
        let withheld = claude_default_upload_withheld(&candidates[0], &owned, &BTreeMap::new());
        let witnesses = degraded_claude_slot_snapshots(
            &states,
            &BTreeMap::new(),
            &selected.winning_by_binding.keys().cloned().collect(),
            CAPTURED,
            EXPIRES,
        );
        let positive_control = degraded_claude_slot_snapshots(
            &states,
            &BTreeMap::new(),
            &BTreeSet::new(),
            CAPTURED,
            EXPIRES,
        );
        let expected_degraded = json!({
            "source":"claude_code","status":"degraded","collection_method":"cli_json",
            "captured_at":CAPTURED,"expires_at":EXPIRES,
            "account":{"login_state":"unknown","provider":"anthropic","auth_method":"oauth",
                "email":null,"account_id":null,"organization_id":null,"organization_label":null,
                "plan_type":null,"subscription_product":null,"billing_channel":"subscription",
                "account_identifier_hash":"account-a","organization_identifier_hash":"org-x",
                "billing_identity_evidence":"provider_account_id","billing_identity_confidence":"high","confidence":"high",
                "claude_quota_access_state":"temporarily_unavailable","claude_anchor_durability":"default_only"},
            "quota_windows":[],"credit_balances":[],"plan_observations":[],
            "capabilities":[{"capability":"claude_quota_access_state_v1","status":"supported",
                "detail":"This daemon reports exact-slot Claude quota access state for strongly bound accounts."}],
            "diagnostics":[
                {"code":"claude_quota_temporarily_unavailable","severity":"warning",
                    "message":"Full Claude quota collection is temporarily unavailable for this registered account and will retry automatically.",
                    "account_identifier_hash":"account-a","organization_identifier_hash":"org-x"},
                {"code":"claude_slot_collection_provider_unavailable","severity":"warning",
                    "message":"The exact registered slot reported this local collection state.",
                    "account_identifier_hash":"account-a","organization_identifier_hash":"org-x"}]
        });
        emit(
            "claude_status_s06_slot_owned_without_anchor",
            json!({"states":states,"candidates":candidate_inputs(&candidates)}),
            json!({"withheld":withheld,"reason":if withheld {Some("slot_owned_without_anchor")} else {None},
                "uploads":snapshot_views(&witnesses),"positive_control":snapshot_views(&positive_control),
                "metered_control":snapshot_views(&[candidates[0].snapshot.clone()]),"saved":states}),
            json!({"withheld":true,"reason":"slot_owned_without_anchor","uploads":expected_views(vec![]),
                "positive_control":expected_views(vec![expected_degraded]),
                "metered_control":expected_views(vec![full_snapshot("account-a","org-x",12)]),"saved":{
                    "claude_slot_a":{"state":"provider_unavailable","account_identifier_hash":"account-a","organization_identifier_hash":"org-x",
                        "observed_at":CAPTURED,"has_account_windows":false,"has_scoped_limits":false,"has_credit_balances":false,"diagnostics":[]}}}),
        );
    }

    /// [money] Failure bounds and known removal differ from an unreadable registry.
    #[test]
    fn s07_failure_bound_and_ownership() {
        let now = Instant::now();
        let previous = BTreeMap::from([(
            "claude_slot_a".to_string(),
            status("account-a", "org-x", "fresh"),
        )]);
        let stale = claude_stale_saved_slot_states(&previous);
        let removed = claude_registered_owned_bindings(true, &[], &BTreeMap::new(), &previous);
        let retained = claude_registered_owned_bindings(
            true,
            &["claude_slot_a".to_string()],
            &BTreeMap::new(),
            &previous,
        );
        let default = candidate("default", "account-a", "org-x", 4, 12);
        emit(
            "claude_status_s07_failure_bounds",
            json!({"previous":previous,"elapsed_seconds":[0,3599,3600],"passes":[5,6]}),
            json!({"bound":[claude_settings_failure_outlasted(now,5,now),claude_settings_failure_outlasted(now,6,now),
                claude_settings_failure_outlasted(now-Duration::from_secs(3599),5,now),claude_settings_failure_outlasted(now-Duration::from_secs(3600),1,now)],
                "removed_withheld":claude_default_upload_withheld(&default,&removed,&BTreeMap::new()),
                "registered_withheld":claude_default_upload_withheld(&default,&retained,&BTreeMap::new()),"stale":stale}),
            json!({"bound":[false,true,false,true],"removed_withheld":false,"registered_withheld":true,"stale":{
                "claude_slot_a":{"state":"probe_failed","account_identifier_hash":"account-a","organization_identifier_hash":"org-x",
                    "observed_at":CAPTURED,"has_account_windows":false,"has_scoped_limits":false,"has_credit_balances":false,"diagnostics":[]}}}),
        );
    }

    /// [money] Candidate exact and organization-less claims survive owned siblings.
    #[test]
    fn s08_plan_composition() {
        let mut c = candidate("default", "account-a", "org-x", 4, 12);
        c.snapshot.plan_observations = vec![
            plan("account-a", Some("org-x")),
            plan("account-a", None),
            plan("account-a", Some("org-y")),
            plan("account-b", Some("org-x")),
            plan("account-b", None),
            plan("account-b", Some("org-y")),
        ];
        let local = c.snapshot.clone();
        let owned = BTreeSet::from([binding("account-a", "org-y"), binding("account-b", "org-x")]);
        let uploaded = claude_uploaded_candidate_snapshot(
            c,
            &BTreeMap::new(),
            &BTreeMap::new(),
            &BTreeMap::new(),
            &owned,
        );
        let p = |a: &str, o: Option<&str>| {
            let mut value = json!({"account_identifier_hash":a,"observed_at":CAPTURED,"provider":"anthropic","auth_mode":"oauth",
                "billing_channel":"subscription","subscription_product":"claude_max_20x","confidence":"high","billing_identity_confidence":"unknown","is_current":true});
            if let Some(o) = o {
                value["organization_identifier_hash"] = json!(o);
            }
            value
        };
        let mut expected_local = full_snapshot("account-a", "org-x", 12);
        expected_local["plan_observations"] = json!([
            p("account-a", Some("org-x")),
            p("account-a", None),
            p("account-a", Some("org-y")),
            p("account-b", Some("org-x")),
            p("account-b", None),
            p("account-b", Some("org-y"))
        ]);
        let mut expected_upload = full_snapshot("account-a", "org-x", 12);
        expected_upload["account"]["claude_anchor_durability"] = json!("default_only");
        expected_upload["plan_observations"] = json!([
            p("account-a", Some("org-x")),
            p("account-a", None),
            p("account-b", Some("org-y"))
        ]);
        emit(
            "claude_status_s08_plan_ownership",
            json!({"default":local,"owned":[["account-a","org-y"],["account-b","org-x"]]}),
            json!({"local":snapshot_views(&[local]),"upload":snapshot_views(&[uploaded])}),
            json!({"local":expected_views(vec![expected_local]),"upload":expected_views(vec![expected_upload])}),
        );
    }

    /// [money] A deferred default serves exact cached meters with their original clocks.
    #[test]
    #[serial]
    fn s09_deferred_cache_absent_stale_fresh() {
        let guard = OAuthGuard::new("deferred");
        let caller = ClaudeOAuthUsageCaller::DefaultDeferredToSlot;
        for (variant, observed) in [
            ("absent", None),
            ("stale", Some(2800)),
            ("fresh", Some(10000)),
        ] {
            let cache = observed.map(|observed| ClaudeOAuthUsageCache {
                schema_version: 4,
                account_identifier_hash: "account-a".to_string(),
                organization_identifier_hash: "org-x".to_string(),
                observed_at_epoch_seconds: observed,
                next_refresh_after_epoch_seconds: observed + 300,
                windows: serde_json::from_value(
                    full_snapshot("account-a", "org-x", 12)["quota_windows"].clone(),
                )
                .unwrap(),
                credit_balances: serde_json::from_value(json!([credit("account-a", "org-x")]))
                    .unwrap(),
                account_weekly_not_offered: false,
                account_session_not_offered: false,
            });
            if let Some(cache) = &cache {
                write_claude_oauth_usage_cache(cache).unwrap();
            }
            let result = collect_claude_oauth_usage_with_credential(
                "account-a",
                "org-x",
                Some("synthetic-never-sent".to_string()),
                Some("2099-01-01T00:00:00Z".to_string()),
                &caller,
                || 10000,
            );
            let deferred = json!({"code":"claude_oauth_usage_deferred_to_registered_slot","severity":"info",
                "message":"This Claude account's quota is read through its registered account slot; the default Claude Code login made no provider request.",
                "account_identifier_hash":"account-a","organization_identifier_hash":"org-x"});
            let expected = if variant == "absent" {
                json!({"result":{"error":"Claude OAuth usage for this account is read by its registered account slot."},"diagnostics":[deferred]})
            } else {
                let mut windows = full_snapshot("account-a", "org-x", 12)["quota_windows"]
                    .as_array()
                    .unwrap()
                    .clone();
                for w in &mut windows {
                    w["observed_at"] = json!(if variant == "stale" {
                        "1970-01-01T00:46:40Z"
                    } else {
                        "1970-01-01T02:46:40Z"
                    });
                    if variant == "stale" {
                        w["status"] = json!("unknown");
                        w["freshness"] = json!("stale");
                    }
                }
                let mut balance = credit("account-a", "org-x");
                if variant == "stale" {
                    balance["freshness"] = json!("stale");
                }
                json!({"result":{"ok":{"windows":windows,"credits":[balance],
                    "account_weekly_not_offered":false,"account_session_not_offered":false}},
                    "diagnostics":[deferred,{"code":"claude_oauth_usage_cache_reused","severity":"info",
                        "message":"A locally cached quota reading kept by the registered account slot was reused; no provider check was made.",
                        "observed_at":"1970-01-01T02:46:40Z","account_identifier_hash":"account-a","organization_identifier_hash":"org-x"}]})
            };
            emit(
                &format!("claude_status_s09_deferred_{variant}"),
                json!({"cache":cache,"clock":10000,"caller":"deferred_default"}),
                json!({"outcome":outcome_value(&result),"provider_calls":CLAUDE_OAUTH_PROVIDER_CALLS.load(std::sync::atomic::Ordering::SeqCst)-guard.calls}),
                json!({"outcome":expected,"provider_calls":0}),
            );
        }
    }

    /// [money] Each managed-anchor deferral precondition is independently necessary.
    #[test]
    #[serial]
    fn s10_deferral_exclusions() {
        let _guard = OAuthGuard::new("deferral-exclusions");
        use ottto_protocol::ClaudeConfigSlotRelationshipV1 as Relationship;
        let base = single_caller_slot(
            "claude_slot_a",
            ClaudeConfigSlotOwnership::Managed,
            ClaudeConfigSlotCollectionStateV1::Fresh,
            Some(Relationship::CanonicalAnchor),
        );
        for variant in [
            "managed",
            "external",
            "unproven",
            "not_fresh",
            "needs_login",
            "noncanonical",
            "changed",
            "missing",
            "suppressed",
            "auth_held",
        ] {
            let mut slot = base.clone();
            match variant {
                "external" => slot.ownership = ClaudeConfigSlotOwnership::External,
                "unproven" => slot.collection.organization_identifier_hash = None,
                "not_fresh" => {
                    slot.collection.state = ClaudeConfigSlotCollectionStateV1::ProviderUnavailable
                }
                "needs_login" => {
                    slot.collection.state = ClaudeConfigSlotCollectionStateV1::NeedsLogin
                }
                "noncanonical" => {
                    slot.collection.relationship = Some(Relationship::DuplicateAnchor)
                }
                _ => {}
            }
            let accounts = if variant == "external" {
                single_caller_accounts_status(vec![], vec![slot])
            } else {
                single_caller_accounts_status(vec![slot], vec![])
            };
            let current = if variant == "missing" {
                None
            } else {
                Some(binding(
                    if variant == "changed" {
                        "other-account"
                    } else {
                        "account-g"
                    },
                    "organization-g",
                ))
            };
            let owned = claude_slot_owned_usage_bindings(
                &accounts,
                |_| current.clone(),
                |_| variant == "suppressed",
                |_, _| variant == "auth_held",
            );
            let rows = owned
                .iter()
                .map(|b| json!([b.account_identifier_hash, b.organization_identifier_hash]))
                .collect::<Vec<_>>();
            emit(
                &format!("claude_status_s10_{variant}"),
                json!({"accounts":accounts,"current":current.map(|b|json!([b.account_identifier_hash,b.organization_identifier_hash])),
                "suppressed":variant=="suppressed","auth_held":variant=="auth_held"}),
                json!({"deferred":rows}),
                json!({"deferred":if variant=="managed" {json!([["account-g","organization-g"]])} else {json!([])}}),
            );
        }
    }

    /// [money] Exact-pair attempt exclusion and the existing caller-run state boundaries.
    #[test]
    #[serial]
    fn s11_attempt_and_caller_runs() {
        let _guard = OAuthGuard::new("attempts");
        let first = try_claude_oauth_collection_attempt("account-a", "org-x").unwrap();
        let contended = try_claude_oauth_collection_attempt("account-a", "org-x").is_none();
        let other_org = try_claude_oauth_collection_attempt("account-a", "org-y").is_some();
        drop(first);
        let released = try_claude_oauth_collection_attempt("account-a", "org-x").is_some();
        let mut callers = BTreeMap::new();
        let mut since = Vec::new();
        for now in [10000, 10300, 12000, 11999] {
            since.push(claude_credit_pools::claude_observe_caller_binding(
                &mut callers,
                "default",
                "pair-a",
                now,
            ));
        }
        claude_credit_pools::claude_end_caller_binding(&mut callers, "default");
        since.push(claude_credit_pools::claude_observe_caller_binding(
            &mut callers,
            "default",
            "pair-a",
            12001,
        ));
        callers.clear();
        since.push(claude_credit_pools::claude_observe_caller_binding(
            &mut callers,
            "default",
            "pair-a",
            12002,
        ));
        let caller = ClaudeOAuthUsageCaller::Default;
        let outer = ClaudeOAuthCollectionPass::begin();
        let inner = ClaudeOAuthCollectionPass::begin();
        claude_oauth_pass_reached_collector(&caller);
        claude_credit_pools::claude_observe_caller_binding(
            &mut CLAUDE_OAUTH_CALLER_BINDINGS.lock().unwrap(),
            &caller.breaker_key(),
            "pair-a",
            10000,
        );
        drop(inner);
        let during = CLAUDE_OAUTH_CALLER_BINDINGS
            .lock()
            .unwrap()
            .contains_key(&caller.breaker_key());
        drop(outer);
        let after = CLAUDE_OAUTH_CALLER_BINDINGS
            .lock()
            .unwrap()
            .contains_key(&caller.breaker_key());
        let skipped = ClaudeOAuthCollectionPass::begin();
        drop(skipped);
        let swept = CLAUDE_OAUTH_CALLER_BINDINGS.lock().unwrap().is_empty();
        emit(
            "claude_status_s11_attempt_runs",
            json!({"pairs":[["account-a","org-x"],["account-a","org-y"]],"clocks":[10000,10300,12000,11999,12001,12002]}),
            json!({"contended":contended,"other_org":other_org,"released":released,"since":since,"overlap":[during,after,swept]}),
            json!({"contended":true,"other_org":true,"released":true,"since":[10000,10000,12000,11999,12001,12002],"overlap":[true,true,true]}),
        );
    }

    /// [money] Full equal payloads collide by registered home count, not distinct pair count.
    #[test]
    fn s13_collision_home_count() {
        for (variant, candidates, expected) in [
            (
                "one_registered",
                vec![
                    candidate("default", "account-a", "org-x", 4, 12),
                    candidate("claude_slot_a", "account-b", "org-y", 4, 12),
                ],
                vec!["default"],
            ),
            (
                "two_registered",
                vec![
                    candidate("default", "account-a", "org-x", 4, 12),
                    candidate("claude_slot_a", "account-b", "org-y", 4, 12),
                    candidate("claude_slot_b", "account-b", "org-y", 4, 12),
                ],
                vec!["claude_slot_a", "claude_slot_b", "default"],
            ),
            (
                "same_pair",
                vec![
                    candidate("default", "account-a", "org-x", 4, 12),
                    candidate("claude_slot_a", "account-a", "org-x", 4, 12),
                ],
                vec![],
            ),
            (
                "incomplete",
                vec![
                    candidate("default", "account-a", "org-x", 3, 12),
                    candidate("claude_slot_a", "account-b", "org-y", 4, 12),
                ],
                vec![],
            ),
        ] {
            let values = candidates
                .iter()
                .map(|c| c.snapshot.clone())
                .collect::<Vec<_>>();
            let snapshots = candidates
                .iter()
                .map(|c| {
                    full_snapshot(
                        &c.binding.account_identifier_hash,
                        &c.binding.organization_identifier_hash,
                        12,
                    )
                })
                .collect();
            emit(
                &format!("claude_status_s13_{variant}"),
                candidate_inputs(&candidates),
                json!({"quarantined":claude_cross_binding_meter_collisions(&candidates),"snapshots":snapshot_views(&values)}),
                json!({"quarantined":expected,"snapshots":expected_views(snapshots)}),
            );
        }
    }

    /// [money] Retained stale collisions clear both meter vectors and every availability flag.
    #[test]
    fn s14_stale_collision_quarantine() {
        let current = candidate("claude_slot_b", "account-b", "org-y", 4, 12);
        let stale = json!({"state":"provider_unavailable","account_identifier_hash":"account-a","organization_identifier_hash":"org-x",
            "observed_at":CAPTURED,"last_full_quota_read_at":"2026-08-05T01:00:00Z","has_account_windows":true,
            "has_scoped_limits":true,"has_credit_balances":true,"diagnostics":[],"quota_snapshot":{
                "state":"stale","captured_at":CAPTURED,"observed_at":"2026-08-05T01:00:00Z",
                "quota_windows":full_snapshot("account-a","org-x",12)["quota_windows"],
                "credit_balances":[credit("account-a","org-x")]}});
        let mut states = BTreeMap::from([(
            "default".to_string(),
            serde_json::from_value(stale.clone()).unwrap(),
        )]);
        let collisions = claude_stale_cross_binding_meter_collisions(&[current], &states);
        quarantine_claude_cross_account_meters(states.get_mut("default").unwrap());
        let no_survivor = claude_stale_cross_binding_meter_collisions(
            &[],
            &BTreeMap::from([(
                "default".to_string(),
                serde_json::from_value(stale.clone()).unwrap(),
            )]),
        );
        emit(
            "claude_status_s14_stale_quarantine",
            json!({"stale":stale,"current":full_snapshot("account-b","org-y",12)}),
            json!({"collisions":collisions,"no_survivor":no_survivor,"states":states}),
            json!({"collisions":["default"],"no_survivor":[],"states":{"default":{
                "state":"identity_mismatch","account_identifier_hash":"account-a","organization_identifier_hash":"org-x","observed_at":CAPTURED,
                "has_account_windows":false,"has_scoped_limits":false,"has_credit_balances":false,
                "diagnostics":[{"code":"identity_mismatch","message":"Limits matched another account and were hidden. Reconnect this Claude login."}]}}}),
        );
    }

    /// [money] Another caller's success preserves this caller's exact auth hold.
    #[test]
    #[serial]
    fn s12_independent_auth_holds() {
        let _guard = OAuthGuard::new("caller-holds");
        let caller = ClaudeOAuthUsageCaller::Default;
        let diagnostics = record_claude_oauth_usage_auth_failure(
            &caller,
            401,
            "account-a",
            "org-x",
            "synthetic-config",
            10000,
            None,
        );
        clear_claude_oauth_usage_breaker_after_success(
            &ClaudeOAuthUsageCaller::RegisteredSlot("claude_slot_b".to_string()),
            "account-a",
            "org-x",
            "synthetic-config",
            10001,
        );
        let kept =
            read_claude_oauth_usage_breaker("account-a", "org-x", "synthetic-config").unwrap();
        let held = claude_oauth_usage_caller_auth_hold(&kept, &caller, 10001, None).is_some();
        let other_held = claude_oauth_usage_caller_auth_hold(
            &kept,
            &ClaudeOAuthUsageCaller::RegisteredSlot("claude_slot_b".to_string()),
            10001,
            None,
        )
        .is_some();
        clear_claude_oauth_usage_breaker_after_success(
            &caller,
            "account-a",
            "org-x",
            "synthetic-config",
            10002,
        );
        emit(
            "claude_status_s12_independent_holds",
            json!({"account":"account-a","organization":"org-x","config":"synthetic-config","status":401,"clocks":[10000,10001,10002]}),
            json!({"diagnostics":diagnostics,"breaker":kept,"held":held,"other_held":other_held,
                "cleared":read_claude_oauth_usage_breaker("account-a","org-x","synthetic-config")}),
            json!({"diagnostics":[{"code":"claude_oauth_usage_auth_rejected","severity":"warning",
                "message":"The Claude OAuth usage endpoint rejected the default Claude Code login credential with HTTP 401 at 1970-01-01T02:46:40Z; that credential is not retried until 1970-01-01T03:01:40Z.",
                "observed_at":"1970-01-01T02:46:40Z"}],
                "breaker":{"schema_version":1,"account_identifier_hash":"account-a","organization_identifier_hash":"org-x","config_fingerprint":"synthetic-config",
                    "auth_failures":0,"shape_failures":0,"rate_limit_failures":0,"opened_at_epoch_seconds":0,"reopen_after_epoch_seconds":0,"opened_by":"",
                    "auth_callers":{"default":{"consecutive_failures":1,"last_status":401,"last_failure_at_epoch_seconds":10000,"backoff_until_epoch_seconds":10900}},
                    "last_auth_failure":{"caller":"default","status":401,"at_epoch_seconds":10000}},"held":true,"other_held":false,"cleared":null}),
        );
    }

    /// [money] Real HTTP error arms retain meters and distinguish caller and binding holds.
    #[test]
    #[serial]
    fn s12_error_responses_keep_exact_cached_readings() {
        use std::sync::atomic::Ordering::SeqCst;
        let diagnostic = |code: &str, message: &str| {
            json!({
                "code":code,"severity":"info","message":message,
                "observed_at":"1970-01-01T02:46:40Z",
                "account_identifier_hash":"account-a","organization_identifier_hash":"org-x"
            })
        };
        let mut expected_windows = full_snapshot("account-a", "org-x", 12)["quota_windows"]
            .as_array()
            .unwrap()
            .clone();
        for window in &mut expected_windows {
            window["observed_at"] = json!("1970-01-01T00:46:40Z");
            window["status"] = json!("unknown");
            window["freshness"] = json!("stale");
        }
        let mut expected_credit = credit("account-a", "org-x");
        expected_credit["freshness"] = json!("stale");
        let expected_usage = json!({"windows":expected_windows,"credits":[expected_credit],
            "account_weekly_not_offered":false,"account_session_not_offered":false});
        let failed = diagnostic("claude_oauth_usage_check_failed",
            "The latest Claude OAuth quota request failed; any served readings remain locally cached evidence.");
        for variant in ["auth_other_caller", "transient", "rate_limited"] {
            let guard = OAuthGuard::new(variant);
            let cache_value = json!({"schema_version":4,"account_identifier_hash":"account-a",
                "organization_identifier_hash":"org-x","observed_at_epoch_seconds":2800,
                "next_refresh_after_epoch_seconds":3100,
                "windows":full_snapshot("account-a","org-x",12)["quota_windows"],
                "credit_balances":[credit("account-a","org-x")]});
            let cache: ClaudeOAuthUsageCache = serde_json::from_value(cache_value.clone()).unwrap();
            write_claude_oauth_usage_cache(&cache).unwrap();
            let responder: ClaudeOAuthTestResponder = match variant {
                "auth_other_caller" => |_| Err(401),
                "transient" => |_| Err(503),
                "rate_limited" => |_| Err(429),
                _ => unreachable!(),
            };
            *CLAUDE_OAUTH_TEST_RESPONSE.lock().unwrap() = Some(responder);
            CLAUDE_OAUTH_PROVIDER_CALLS_FORBIDDEN.store(false, SeqCst);
            let first = collect_claude_oauth_usage_with_credential(
                "account-a",
                "org-x",
                Some("synthetic-never-sent".to_string()),
                Some("2099-01-01T00:00:00Z".to_string()),
                &ClaudeOAuthUsageCaller::Default,
                || 10000,
            );
            // A different credential can still request after the default's
            // 401. Success completion belongs to the collection-clock corpus;
            // here a 503 proves that this request reaches the real error arm.
            let second_caller = if variant == "auth_other_caller" {
                *CLAUDE_OAUTH_TEST_RESPONSE.lock().unwrap() = Some(|_| Err(503));
                ClaudeOAuthUsageCaller::RegisteredSlot("claude_slot_b".to_string())
            } else {
                ClaudeOAuthUsageCaller::Default
            };
            let second = collect_claude_oauth_usage_with_credential(
                "account-a",
                "org-x",
                Some("synthetic-never-sent".to_string()),
                Some("2099-01-01T00:00:00Z".to_string()),
                &second_caller,
                || 10000,
            );
            let mut expected_cache = cache_value.clone();
            let (first_diagnostics, second_diagnostics, calls) = match variant {
                "auth_other_caller" => (json!([
                    {"code":"claude_oauth_usage_auth_rejected","severity":"warning",
                        "message":"The Claude OAuth usage endpoint rejected the default Claude Code login credential with HTTP 401 at 1970-01-01T02:46:40Z; that credential is not retried until 1970-01-01T03:01:40Z.",
                        "observed_at":"1970-01-01T02:46:40Z","account_identifier_hash":"account-a","organization_identifier_hash":"org-x"},
                    failed]), json!([failed]), 2),
                "transient" => (json!([failed]), json!([diagnostic("claude_oauth_usage_check_suppressed",
                    "The latest Claude OAuth quota request failed moments ago; no provider request was made, and any served readings are last-known local readings.")]), 1),
                "rate_limited" => {
                    expected_cache["next_refresh_after_epoch_seconds"] = json!(10300);
                    let mut limited = diagnostic("claude_oauth_usage_rate_limited",
                        "Claude asked Ottto to wait until 02:51 UTC before the next saved-resets read.");
                    limited["retry_after"] = json!("1970-01-01T02:51:40Z");
                    let mut reused = diagnostic("claude_oauth_usage_cache_reused",
                        "Locally cached quota evidence was reused; no provider check was made.");
                    reused["retry_after"] = json!("1970-01-01T02:51:40Z");
                    (json!([diagnostic("claude_oauth_usage_check_failed",
                        "The latest Claude OAuth quota request failed with rate limiting; any served readings remain locally cached evidence."), limited]), json!([reused]), 1)
                }
                _ => unreachable!(),
            };
            emit(
                &format!("claude_status_s12_{variant}"),
                json!({"cache":cache_value,"read_schedule":{},"clock":10000,"first_caller":"default",
                    "second_caller":if variant=="auth_other_caller" {"registered_slot"} else {"default"},
                    "responses":if variant=="auth_other_caller" {vec![401,503]} else if variant=="transient" {vec![503]} else {vec![429]}}),
                json!({"outcomes":[outcome_value(&first),outcome_value(&second)],
                    "cache":read_claude_oauth_usage_cache("account-a","org-x"),
                    "provider_calls":CLAUDE_OAUTH_PROVIDER_CALLS.load(SeqCst)-guard.calls}),
                json!({"outcomes":[{"result":{"ok":expected_usage},"diagnostics":first_diagnostics},
                    {"result":{"ok":expected_usage},"diagnostics":second_diagnostics}],
                    "cache":expected_cache,"provider_calls":calls}),
            );
        }
    }

    /// [money] Source completeness and exact statusLine conversion use existing seams.
    #[test]
    fn s17_source_completeness_inputs() {
        let body = json!({"five_hour":null,"seven_day":null,"limits":[{"kind":"weekly_sonnet","group":"weekly","scope":{"model":"sonnet"}}]});
        let cache = ClaudeStatusLineRateLimitCache {
            schema_version: CLAUDE_STATUSLINE_RATE_LIMIT_CACHE_SCHEMA_VERSION,
            observed_under_account_identifier_hash: "account-a".to_string(),
            observed_under_organization_identifier_hash: Some("org-x".to_string()),
            observed_under_account_method: "config_dir".to_string(),
            observed_at_epoch_seconds: 10000,
            windows: vec![
                ClaudeStatusLineRateLimitWindow {
                    name: "five_hour".to_string(),
                    used_percent: 12,
                    resets_at_epoch_seconds: 20000,
                },
                ClaudeStatusLineRateLimitWindow {
                    name: "unknown".to_string(),
                    used_percent: 34,
                    resets_at_epoch_seconds: 20000,
                },
                ClaudeStatusLineRateLimitWindow {
                    name: "seven_day".to_string(),
                    used_percent: 34,
                    resets_at_epoch_seconds: 9000,
                },
            ],
        };
        let mut expected = window("account-a", "org-x", "session", 12);
        expected["observed_at"] = json!("1970-01-01T02:46:40Z");
        expected["resets_at"] = json!("1970-01-01T05:33:20Z");
        let mut snapshot = candidate("default", "account-a", "org-x", 4, 12).snapshot;
        snapshot.quota_windows.pop();
        let partial = claude_snapshot_candidate_rank(&snapshot).unwrap().tier;
        snapshot.quota_windows[1].model = Some("claude-sonnet".to_string());
        let complete = claude_snapshot_candidate_rank(&snapshot).unwrap().tier;
        emit(
            "claude_status_s17_source_inputs",
            json!({"oauth":body,"statusline":cache,"now":10000}),
            json!({"weekly_not_offered":claude_oauth_account_weekly_not_offered(&body),"session_not_offered":claude_oauth_account_session_not_offered(&body),
                "absent_flags":[claude_oauth_account_weekly_not_offered(&json!({})),claude_oauth_account_session_not_offered(&json!({}))],
                "windows":claude_statusline_quota_windows_from_cache(cache,10000),"quality_tiers":[partial,complete]}),
            json!({"weekly_not_offered":true,"session_not_offered":true,"absent_flags":[false,false],"windows":[expected],"quality_tiers":[3,4]}),
        );
    }

    /// [money] Percentage replacement preserves complete identity, money and period coverage.
    #[test]
    fn s18_exact_statusline_replacement() {
        for variant in [
            "newer",
            "older",
            "equal",
            "future",
            "other_account",
            "other_org",
            "weak_account",
            "weak_org",
            "scope",
            "model",
            "group",
            "limit_id",
            "duration",
            "invalid_reset",
            "ended_reset",
            "rollover",
            "invalid_rollover",
            "tolerance",
            "money_limit",
            "money_used",
            "money_remaining",
            "quota",
            "remaining",
            "start_conflict",
        ] {
            let mut older = window("account-a", "org-x", "session", 12);
            older["observed_at"] = json!("2026-08-05T01:00:00Z");
            older["started_at"] = json!("2026-08-05T00:00:00Z");
            older["started_at_basis"] = json!("assumed_duration");
            let mut newer = window("account-a", "org-x", "session", 46);
            newer["observed_at"] = json!("2026-08-05T01:01:00Z");
            match variant {
                "older" => newer["observed_at"] = json!("2026-08-05T00:59:00Z"),
                "equal" => newer["observed_at"] = json!("2026-08-05T01:00:00Z"),
                "future" => {
                    // Isolate the future-observation guard: the reset, derived
                    // start and increasing observations otherwise permit replacement.
                    older["observed_at"] = json!("2099-01-01T00:00:00Z");
                    older["started_at"] = json!("2099-01-01T00:00:00Z");
                    older["resets_at"] = json!("2099-01-01T05:00:00Z");
                    newer["observed_at"] = json!("2099-01-01T00:01:00Z");
                    newer["resets_at"] = json!("2099-01-01T05:00:00Z");
                }
                "other_account" => newer["account_identifier_hash"] = json!("account-b"),
                "other_org" => newer["organization_identifier_hash"] = json!("org-y"),
                "weak_account" => {
                    newer
                        .as_object_mut()
                        .unwrap()
                        .remove("account_identifier_hash");
                }
                "weak_org" => {
                    newer
                        .as_object_mut()
                        .unwrap()
                        .remove("organization_identifier_hash");
                }
                "scope" => newer["scope"] = json!("model"),
                "model" => newer["model"] = json!("claude-sonnet"),
                "group" => newer["group"] = json!("other"),
                "limit_id" => newer["limit_id"] = json!("other"),
                "duration" => newer["window_seconds"] = json!(21600),
                "invalid_reset" => newer["resets_at"] = json!("invalid"),
                "ended_reset" => {
                    // Isolate new_reset <= new_time: the matching cycle and
                    // derived start otherwise permit the increasing observation.
                    older["observed_at"] = json!("2026-08-05T00:59:00Z");
                    older["started_at"] = json!("2026-08-04T20:00:00Z");
                    older["resets_at"] = json!("2026-08-05T01:00:00Z");
                    newer["resets_at"] = json!("2026-08-05T01:00:00Z");
                }
                "rollover" => {
                    newer["observed_at"] = json!("2026-08-05T05:01:00Z");
                    newer["resets_at"] = json!("2026-08-05T10:00:00Z");
                }
                "invalid_rollover" => newer["resets_at"] = json!("2026-08-05T10:00:00Z"),
                "tolerance" => older["resets_at"] = json!("2026-08-05T05:00:00.123456Z"),
                "money_limit" => older["limit_cents"] = json!(2500),
                "money_used" => older["used_cents"] = json!(600),
                "money_remaining" => older["remaining_cents"] = json!(1900),
                "quota" => older["quota"] = json!(100),
                "remaining" => older["remaining"] = json!(80),
                "start_conflict" => older["started_at"] = json!("2026-08-05T00:00:05Z"),
                _ => {}
            }
            let replace = matches!(variant, "newer" | "rollover" | "tolerance");
            let mut before = full_snapshot("account-a", "org-x", 12);
            before["quota_windows"][0] = older.clone();
            let mut snapshot: AgentStatusSnapshot = serde_json::from_value(before.clone()).unwrap();
            let replaced = prefer_newer_exact_claude_statusline_windows(
                &mut snapshot.quota_windows,
                vec![serde_json::from_value(newer.clone()).unwrap()],
            );
            let mut expected = before.clone();
            if replace {
                let mut chosen = newer.clone();
                chosen["started_at"] = json!(if variant == "rollover" {
                    "2026-08-05T05:00:00Z"
                } else {
                    "2026-08-05T00:00:00Z"
                });
                chosen["started_at_basis"] = json!("assumed_duration");
                expected["quota_windows"][0] = chosen;
            }
            emit(
                &format!("claude_status_s18_{variant}"),
                json!({"oauth":before,"statusline":newer}),
                json!({"replaced":replaced,"snapshots":snapshot_views(&[snapshot])}),
                json!({"replaced":replace,"snapshots":expected_views(vec![expected])}),
            );
        }
    }

    /// [money] Carrier and setup choose actual eligible rows before later append boundaries.
    #[test]
    fn s21_carrier_setup_degraded_desktop() {
        let a = candidate("claude_slot_b", "account-a", "org-x", 4, 12).snapshot;
        let b = candidate("claude_slot_a", "account-b", "org-y", 4, 23).snapshot;
        let uploads = vec![a.clone(), b.clone()];
        let uploaded = vec![
            ("claude_slot_b".to_string(), binding("account-a", "org-x")),
            ("claude_slot_a".to_string(), binding("account-b", "org-y")),
        ];
        let default = binding("account-a", "org-x");
        let carrier = claude_runtime_defaults_carrier(&uploads, &uploaded, true, Some(&default));
        let lexical = claude_runtime_defaults_carrier(&uploads, &uploaded, true, None);
        let absent = claude_runtime_defaults_carrier(&uploads, &uploaded, false, Some(&default));
        let none = claude_runtime_defaults_carrier(&[], &[], true, Some(&default));
        let state = status("account-a", "org-x", "needs_login");
        let degraded = degraded_claude_slot_snapshot(
            &state,
            ClaudeAccountAnchorDurabilityV1::DefaultOnly,
            None,
            CAPTURED,
            EXPIRES,
        )
        .unwrap();
        let desktop = ClaudeDesktopPairs {
            pairs: vec![
                desktop_pair("account-a", "org-x"),
                desktop_pair("account-b", "org-y"),
            ],
            duplicate_sessions: vec![],
        };
        let only = claude_desktop_pairs_snapshot(&desktop, &[], CAPTURED, EXPIRES).unwrap();
        let uncovered = claude_desktop_pairs_snapshot(&desktop, &[a], CAPTURED, EXPIRES).unwrap();
        let all_covered = claude_desktop_pairs_snapshot(&desktop, &uploads, CAPTURED, EXPIRES);
        let mut expected_degraded = full_snapshot("account-a", "org-x", 12);
        expected_degraded["status"] = json!("degraded");
        expected_degraded["quota_windows"] = json!([]);
        expected_degraded["credit_balances"] = json!([]);
        for field in [
            "email",
            "account_id",
            "organization_id",
            "organization_label",
            "plan_type",
            "subscription_product",
        ] {
            expected_degraded["account"][field] = Value::Null;
        }
        expected_degraded["account"]["login_state"] = json!("signed_out");
        expected_degraded["account"]["claude_quota_access_state"] = json!("reconnect_required");
        expected_degraded["account"]["claude_anchor_durability"] = json!("default_only");
        expected_degraded["capabilities"] = json!([{"capability":"claude_quota_access_state_v1","status":"supported",
            "detail":"This daemon reports exact-slot Claude quota access state for strongly bound accounts."}]);
        expected_degraded["diagnostics"] = json!([
            {"code":"claude_quota_reconnect_required","severity":"warning","message":"This registered Claude account requires customer-owned official Claude Code login before full quota collection can resume.",
                "account_identifier_hash":"account-a","organization_identifier_hash":"org-x"},
            {"code":"claude_slot_collection_needs_login","severity":"warning","message":"The exact registered slot reported this local collection state.",
                "account_identifier_hash":"account-a","organization_identifier_hash":"org-x"}]);
        emit(
            "claude_status_s21_carriers",
            json!({"uploads":uploads,"degraded_state":state,
            "desktop":[expected_plan("account-a","org-x"),expected_plan("account-b","org-y")]}),
            json!({"carriers":[carrier,lexical,absent,none],"setup":[claude_setup_snapshot_index(&uploads,Some(&default),false),
                claude_setup_snapshot_index(std::slice::from_ref(&only),None,true),claude_setup_snapshot_index(std::slice::from_ref(&degraded),Some(&default),false)],
                "degraded":snapshot_views(&[degraded]),"desktop_only":snapshot_views(&[only]),"uncovered":snapshot_views(&[uncovered]),"covered":all_covered}),
            json!({"carriers":[0,1,null,null],"setup":[0,0,0],"degraded":expected_views(vec![expected_degraded]),
                "desktop_only":expected_views(vec![expected_desktop(vec![expected_plan("account-a","org-x"),expected_plan("account-b","org-y")],true)]),
                "uncovered":expected_views(vec![expected_desktop(vec![expected_plan("account-b","org-y")],false)]),"covered":null}),
        );
    }

    /// [money] Existing collection, observation and upload limits retain exact omission outcomes.
    #[test]
    #[serial]
    fn s24_existing_boundaries() {
        let _guard = OAuthGuard::new("boundaries");
        use ottto_protocol::ClaudeConfigSlotRelationshipV1 as Relationship;
        let descriptors = (0..11)
            .map(|n| {
                single_caller_slot(
                    &format!("claude_slot_{n:02}"),
                    ClaudeConfigSlotOwnership::Managed,
                    ClaudeConfigSlotCollectionStateV1::Fresh,
                    Some(Relationship::CanonicalAnchor),
                )
            })
            .collect::<Vec<_>>();
        let (collected, overflow) = bounded_claude_custom_descriptors(descriptors.clone());
        let desktop = ClaudeDesktopPairs {
            pairs: (0..22)
                .map(|n| desktop_pair(&format!("account-{n:02}"), "org-x"))
                .collect(),
            duplicate_sessions: vec![],
        };
        let only = claude_desktop_pairs_snapshot(&desktop, &[], CAPTURED, EXPIRES).unwrap();
        let expected_observations = (0..20)
            .map(|n| expected_plan(&format!("account-{n:02}"), "org-x"))
            .collect();
        let mut expected_only = expected_desktop(expected_observations, true);
        expected_only["diagnostics"].as_array_mut().unwrap().push(json!({"code":"claude_desktop_pairs_truncated","severity":"warning",
            "message":"2 Claude Desktop folder pair(s) and 0 duplicate-session reading(s) were left out to stay within the upload limit; the newest were kept."}));
        let mut full = vec![candidate("default", "account-a", "org-x", 4, 12).snapshot; 10];
        append_claude_desktop_pairs_snapshot(&mut full, &desktop, CAPTURED, EXPIRES);
        let mut room = vec![candidate("default", "account-a", "org-x", 4, 12).snapshot; 9];
        append_claude_desktop_pairs_snapshot(&mut room, &desktop, CAPTURED, EXPIRES);
        let mut expected_room = vec![full_snapshot("account-a", "org-x", 12); 9];
        let mut appended = expected_only.clone();
        appended["diagnostics"][1] = json!({"code":"claude_desktop_uncovered_pairs","severity":"info",
            "message":"Claude Desktop account/organization folders that no uploaded Claude Code login covers are reported without limits."});
        expected_room.push(appended);

        let mut duplicate_a = desktop_pair("account-a", "org-x");
        duplicate_a.observation.source_session_id = Some("synthetic-duplicate-a".to_string());
        let mut duplicate_b = duplicate_a.clone();
        duplicate_b.observation.source_session_id = Some("synthetic-duplicate-b".to_string());
        let duplicate_desktop = ClaudeDesktopPairs {
            pairs: (0..18)
                .map(|n| desktop_pair(&format!("account-{n:02}"), "org-x"))
                .chain([desktop_pair("account-a", "org-x")])
                .collect(),
            duplicate_sessions: vec![duplicate_a, duplicate_b],
        };
        // Nineteen pairs leave one duplicate cell, preserving session order.
        let duplicate_row =
            claude_desktop_pairs_snapshot(&duplicate_desktop, &[], CAPTURED, EXPIRES).unwrap();
        let mut observations = (0..18)
            .map(|n| expected_plan(&format!("account-{n:02}"), "org-x"))
            .collect::<Vec<_>>();
        observations.push(expected_plan("account-a", "org-x"));
        let mut duplicate_expected = expected_plan("account-a", "org-x");
        duplicate_expected["source_session_id"] = json!("synthetic-duplicate-a");
        observations.push(duplicate_expected);
        let mut expected_duplicates = expected_desktop(observations, true);
        expected_duplicates["diagnostics"].as_array_mut().unwrap().push(json!({"code":"claude_desktop_pairs_truncated","severity":"warning",
            "message":"0 Claude Desktop folder pair(s) and 1 duplicate-session reading(s) were left out to stay within the upload limit; the newest were kept."}));
        let unresolved = derive_unresolved_claude_accounts(
            &candidate("default", "account-a", "org-x", 4, 12).snapshot,
            &desktop,
            &[],
            &BTreeMap::new(),
            OffsetDateTime::parse(CAPTURED, &Rfc3339).unwrap(),
        );
        let expected_ids = [
            "claude-unresolved-a1c5b932557d4466",
            "claude-unresolved-fd442fbdcf07b41c",
            "claude-unresolved-f8a92ddfc7050119",
            "claude-unresolved-bc202852b7fa01ad",
            "claude-unresolved-e644d770664083b3",
            "claude-unresolved-e18d14f2ea171f01",
            "claude-unresolved-3516fad695a6de89",
            "claude-unresolved-f3bb56dec4e80f34",
            "claude-unresolved-53a1ecc9cc3ab97e",
            "claude-unresolved-dd5b03842a4287d5",
            "claude-unresolved-cad8be3bf9c65c55",
            "claude-unresolved-875e5f4c8ecc85e7",
            "claude-unresolved-79a4106c89e2bf2e",
            "claude-unresolved-53bc87e15c9f30bf",
            "claude-unresolved-1b94ad45c1656f8d",
            "claude-unresolved-082f5f49b03c4063",
            "claude-unresolved-d57321961f5a6a9a",
            "claude-unresolved-3e7b8b8e3467bab0",
            "claude-unresolved-db197b12f5bf2ec6",
            "claude-unresolved-50bb7a6826778561",
        ];
        let expected_unresolved = expected_ids.iter().enumerate().map(|(n, id)| json!({
            "unresolved_id":id,"account_identifier_hash":format!("account-{n:02}"),
            "organization_identifier_hash":"org-x","observed_at":CAPTURED,"evidence":["desktop_session"]
        })).collect::<Vec<_>>();
        emit(
            "claude_status_s24_boundaries",
            json!({"descriptors":descriptors,"desktop":(0..22).map(|n|expected_plan(&format!("account-{n:02}"),"org-x")).collect::<Vec<_>>(),"upload_counts":[9,10],"duplicates":[expected_plan("account-a","org-x"),"synthetic-duplicate-a","synthetic-duplicate-b"],"unresolved_now":CAPTURED}),
            json!({"collected":collected.iter().map(|d|&d.slot_id).collect::<Vec<_>>(),"overflow":overflow.iter().map(|d|&d.slot_id).collect::<Vec<_>>(),
                "desktop":snapshot_views(&[only]),"full":snapshot_views(&full),"room":snapshot_views(&room),"duplicates":snapshot_views(&[duplicate_row]),"unresolved":unresolved}),
            json!({"collected":["claude_slot_00","claude_slot_01","claude_slot_02","claude_slot_03","claude_slot_04","claude_slot_05","claude_slot_06","claude_slot_07","claude_slot_08"],
                "overflow":["claude_slot_09","claude_slot_10"],"desktop":expected_views(vec![expected_only]),
                "full":expected_views(vec![full_snapshot("account-a","org-x",12);10]),"room":expected_views(expected_room),"duplicates":expected_views(vec![expected_duplicates]),"unresolved":expected_unresolved}),
        );
    }

    /// [money] Config-dir ownership differs from current session-store acceptance.
    #[test]
    fn s19_attribution_methods() {
        for (variant, sample, method, current, expected) in [
            ("same_config", "account-a", "config_dir", "account-a", None),
            (
                "different_config",
                "account-b",
                "config_dir",
                "account-a",
                Some("claude_statusline_cache_credential_replaced"),
            ),
            (
                "different_session_store",
                "account-b",
                "session_store",
                "account-a",
                None,
            ),
            (
                "empty_sample",
                "",
                "session_store",
                "account-a",
                Some("claude_statusline_cache_account_unknown"),
            ),
            (
                "empty_current",
                "account-a",
                "config_dir",
                "",
                Some("claude_statusline_cache_account_unknown"),
            ),
            (
                "unknown",
                "account-a",
                "unknown",
                "account-a",
                Some("claude_statusline_cache_account_unknown"),
            ),
            (
                "ambiguous",
                "account-a",
                "ambiguous",
                "account-a",
                Some("claude_statusline_cache_multiple_accounts"),
            ),
            (
                "legacy_method",
                "account-a",
                "",
                "account-a",
                Some("claude_statusline_cache_account_unknown"),
            ),
        ] {
            let result = claude_statusline_attribution_failure(
                sample,
                method,
                current,
                &["account-a".to_string(), "account-b".to_string()],
            );
            emit(
                &format!("claude_status_s19_{variant}"),
                json!({"sample":sample,"method":method,"current":current,"observable":["account-a","account-b"]}),
                json!({"failure":result.as_ref().map(ClaudeStatusLineUnattributable::code),"control":snapshot_views(&[candidate("default","account-a","org-x",4,12).snapshot])}),
                json!({"failure":expected,"control":expected_views(vec![full_snapshot("account-a","org-x",12)])}),
            );
        }
    }
}
