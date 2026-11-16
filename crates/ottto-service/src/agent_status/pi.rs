//! Pi status, configured model routes, and local identity evidence.
//! Called through the agent-status facade by status and session consumers.
//! Keeps Pi collection and route interpretation in their existing order.

use crate::agent_status::append_current_plan_observation;
use crate::agent_status::base_snapshot;
use crate::agent_status::billing_identity_evidence_for;
use crate::agent_status::billing_identity_hash;
use crate::agent_status::command_output_text;
use crate::agent_status::first_json_string;
use crate::agent_status::fs;
use crate::agent_status::home_dir;
use crate::agent_status::home_path;
use crate::agent_status::looks_like_safe_model_id;
use crate::agent_status::normalize_plan_type;
use crate::agent_status::not_installed_snapshot;
use crate::agent_status::parse_yes_no;
use crate::agent_status::run_command_capture;
use crate::agent_status::strip_secret_json;
use crate::agent_status::supported_capability;
use crate::agent_status::unsupported_account;
use crate::agent_status::unsupported_capability;
use crate::agent_status::unsupported_context;
use crate::agent_status::unsupported_quota_window;
use crate::agent_status::AgentAccountStatus;
use crate::agent_status::AgentAvailableModelStatus;
use crate::agent_status::AgentDiagnosticSeverity;
use crate::agent_status::AgentLoginState;
use crate::agent_status::AgentModelStatus;
use crate::agent_status::AgentStatusCollectionMethod;
use crate::agent_status::AgentStatusConfidence;
use crate::agent_status::AgentStatusDiagnostic;
use crate::agent_status::AgentStatusPlanObservation;
use crate::agent_status::AgentStatusSnapshot;
use crate::agent_status::AgentStatusState;
use crate::agent_status::BTreeSet;
use crate::agent_status::BillingIdentityHints;
use crate::agent_status::CommandOutput;
use crate::agent_status::Path;
use crate::agent_status::PathBuf;
use crate::agent_status::PiModelRoute;
use crate::agent_status::PiRouteClassification;
use crate::agent_status::SourceKind;
use crate::agent_status::Value;
use crate::agent_status::COMMAND_TIMEOUT;
use crate::agent_status::MAX_AVAILABLE_MODELS;
use crate::agent_status::URL_SAFE_NO_PAD;
use base64::Engine as _;

pub(super) fn collect_pi_status(captured_at: String, expires_at: String) -> AgentStatusSnapshot {
    if !crate::agent_configs::detection::source_present_locally(&SourceKind::Pi) {
        return not_installed_snapshot(SourceKind::Pi, "pi", captured_at, expires_at);
    }
    let mut snapshot = base_snapshot(
        SourceKind::Pi,
        AgentStatusState::Available,
        AgentStatusCollectionMethod::CommandProbe,
        captured_at,
        expires_at,
    );
    snapshot.account = Some(AgentAccountStatus {
        login_state: AgentLoginState::Unknown,
        provider: None,
        email: read_pi_safe_auth_metadata()
            .and_then(|metadata| first_json_string(&metadata, &["email"])),
        confidence: AgentStatusConfidence::Low,
        ..unsupported_account("")
    });
    let settings = read_pi_agent_settings();
    let auth = read_pi_agent_auth();
    let list_models = if settings.is_none() {
        Some(run_command_capture(
            "pi",
            &["--list-models"],
            COMMAND_TIMEOUT,
        ))
    } else {
        None
    };
    snapshot.model = Some(collect_pi_model_status(
        settings.as_ref(),
        list_models.as_ref(),
        auth.as_ref(),
    ));
    if settings.is_some() {
        snapshot.collection_method = AgentStatusCollectionMethod::ConfigFile;
        snapshot.diagnostics.push(AgentStatusDiagnostic::source(
            "pi_agent_settings_detected",
            AgentDiagnosticSeverity::Info,
            "Pi model route read from Pi's agent settings.json.",
        ));
    }
    snapshot.quota_windows = vec![unsupported_quota_window("usage")];
    snapshot.context = Some(unsupported_context(
        "pi_cli_v1",
        "pi_active_context_not_collected",
        None,
    ));
    snapshot.capabilities = vec![
        supported_capability(
            "model_list",
            "Collected from Pi's agent settings.json enabledModels, falling back to pi --list-models.",
        ),
        unsupported_capability(
            "account_plan",
            "Pi does not publish display-safe plan metadata in v1.",
        ),
        unsupported_capability(
            "quota_windows",
            "Pi does not publish display-safe quota-window metadata in v1.",
        ),
        unsupported_capability(
            "active_context",
            "Pi does not publish active context metadata in v1.",
        ),
    ];
    append_pi_route_plan_observations(&mut snapshot);
    append_current_plan_observation(&mut snapshot);
    snapshot
}

pub(super) fn append_pi_route_plan_observations(snapshot: &mut AgentStatusSnapshot) {
    let Some(model) = &snapshot.model else {
        return;
    };
    let observed_at = snapshot.captured_at.clone();
    for detail in model.available_model_details.iter().take(20) {
        if detail.subscription_product.is_none()
            && detail.account_identifier_hash.is_none()
            && detail.organization_identifier_hash.is_none()
            && detail.credential_fingerprint_hash.is_none()
        {
            continue;
        }
        snapshot.plan_observations.push(AgentStatusPlanObservation {
            desktop_recent_at: None,
            observed_at: Some(observed_at.clone()),
            evidence_method: Some("pi_route_metadata".to_string()),
            source_session_id: None,
            provider: detail.provider.clone(),
            billing_provider: detail.billing_provider.clone(),
            model_provider: detail.model_provider.clone(),
            billing_channel: detail.billing_channel.clone(),
            auth_mode: detail.auth_mode.clone(),
            gateway_provider: detail.gateway_provider.clone(),
            subscription_product: detail.subscription_product.clone(),
            plan_type: None,
            account_label: None,
            account_id: None,
            organization_label: None,
            organization_id: None,
            account_identifier_hash: detail.account_identifier_hash.clone(),
            organization_identifier_hash: detail.organization_identifier_hash.clone(),
            superseded_account_identifier_hash: None,
            superseded_organization_identifier_hash: None,
            credential_fingerprint_hash: detail.credential_fingerprint_hash.clone(),
            billing_identity_evidence: detail.billing_identity_evidence.clone(),
            billing_identity_confidence: detail.billing_identity_confidence.clone(),
            confidence: if detail.billing_identity_confidence == AgentStatusConfidence::Unknown {
                AgentStatusConfidence::Low
            } else {
                detail.billing_identity_confidence.clone()
            },
            is_current: Some(true),
        });
    }
}

pub(crate) fn read_pi_smoke_routes() -> Vec<PiModelRoute> {
    if let Some(settings) = read_pi_agent_settings() {
        if let Some(route) = collect_default_pi_smoke_route_from_settings(&settings) {
            return vec![route];
        }
    }
    Vec::new()
}

pub(super) fn collect_pi_model_status(
    settings: Option<&Value>,
    list_models: Option<&CommandOutput>,
    auth: Option<&Value>,
) -> AgentModelStatus {
    if let Some(settings) = settings {
        let status = collect_pi_model_status_from_settings(settings, auth);
        if !status.available_models.is_empty() || status.default_model.is_some() {
            return status;
        }
    }
    if let Some(output) = list_models {
        return collect_pi_model_status_from_output(output, auth);
    }
    AgentModelStatus {
        active_model: None,
        default_model: None,
        provider: None,
        available_models: Vec::new(),
        available_model_details: Vec::new(),
        context_window_tokens: None,
    }
}

pub(super) fn collect_pi_model_status_from_settings(
    settings: &Value,
    auth: Option<&Value>,
) -> AgentModelStatus {
    let default_provider = first_json_string(
        settings,
        &["defaultProvider", "default_provider", "provider"],
    );
    let default_model = first_json_string(settings, &["defaultModel", "default_model", "model"]);
    let default_thinking = first_json_string(
        settings,
        &[
            "defaultThinkingLevel",
            "default_thinking_level",
            "thinkingLevel",
        ],
    );
    let mut routes = Vec::new();
    let mut seen = BTreeSet::new();
    if let Some(enabled_models) = settings
        .get("enabledModels")
        .or_else(|| settings.get("enabled_models"))
    {
        collect_pi_enabled_model_routes(
            enabled_models,
            default_provider.as_deref(),
            default_thinking.as_deref(),
            &mut seen,
            &mut routes,
        );
    }
    if let (Some(provider), Some(model)) = (default_provider.as_deref(), default_model.as_deref()) {
        push_pi_model_route(
            provider,
            model,
            default_thinking.as_deref(),
            &mut seen,
            &mut routes,
        );
    }
    let details: Vec<AgentAvailableModelStatus> = routes
        .iter()
        .map(|route| {
            let identity = pi_identity_hints_for_route(auth, route);
            pi_model_detail_from_route(route, None, None, None, None, Some(&identity))
        })
        .collect();
    let providers: BTreeSet<&str> = details
        .iter()
        .filter_map(|detail| detail.provider.as_deref())
        .collect();
    AgentModelStatus {
        active_model: default_model.clone(),
        default_model,
        provider: match providers.len() {
            0 => default_provider,
            1 => providers
                .iter()
                .next()
                .map(|provider| (*provider).to_string()),
            _ => Some("multi_provider".to_string()),
        },
        available_models: details
            .iter()
            .map(|detail| detail.id.clone())
            .take(MAX_AVAILABLE_MODELS)
            .collect(),
        available_model_details: details.into_iter().take(MAX_AVAILABLE_MODELS).collect(),
        context_window_tokens: None,
    }
}

#[cfg(test)]
pub(super) fn collect_pi_routes_from_settings(settings: &Value) -> Vec<PiModelRoute> {
    let default_provider = first_json_string(
        settings,
        &["defaultProvider", "default_provider", "provider"],
    );
    let default_model = first_json_string(settings, &["defaultModel", "default_model", "model"]);
    let default_thinking = first_json_string(
        settings,
        &[
            "defaultThinkingLevel",
            "default_thinking_level",
            "thinkingLevel",
        ],
    );
    let mut routes = Vec::new();
    let mut seen = BTreeSet::new();
    if let Some(enabled_models) = settings
        .get("enabledModels")
        .or_else(|| settings.get("enabled_models"))
    {
        collect_pi_enabled_model_routes(
            enabled_models,
            default_provider.as_deref(),
            default_thinking.as_deref(),
            &mut seen,
            &mut routes,
        );
    }
    if let (Some(provider), Some(model)) = (default_provider.as_deref(), default_model.as_deref()) {
        push_pi_model_route(
            provider,
            model,
            default_thinking.as_deref(),
            &mut seen,
            &mut routes,
        );
    }
    routes
}

pub(super) fn collect_default_pi_smoke_route_from_settings(
    settings: &Value,
) -> Option<PiModelRoute> {
    let default_provider = first_json_string(
        settings,
        &["defaultProvider", "default_provider", "provider"],
    );
    let default_model = first_json_string(settings, &["defaultModel", "default_model", "model"]);
    let default_thinking = first_json_string(
        settings,
        &[
            "defaultThinkingLevel",
            "default_thinking_level",
            "thinkingLevel",
        ],
    );
    let provider = default_provider.as_deref()?;
    let model = default_model.as_deref()?;
    PiModelRoute::new(provider, model, default_thinking.as_deref())
}

pub(super) fn collect_pi_enabled_model_routes(
    value: &Value,
    default_provider: Option<&str>,
    default_thinking: Option<&str>,
    seen: &mut BTreeSet<(Option<String>, String)>,
    routes: &mut Vec<PiModelRoute>,
) {
    match value {
        Value::Array(items) => {
            for item in items {
                collect_pi_enabled_model_routes(
                    item,
                    default_provider,
                    default_thinking,
                    seen,
                    routes,
                );
            }
        }
        Value::Object(map) => {
            if let Some(enabled) = map.get("enabled").and_then(Value::as_bool) {
                if !enabled {
                    return;
                }
            }
            let provider = first_json_string(
                value,
                &["provider", "defaultProvider", "provider_id", "providerId"],
            )
            .or_else(|| default_provider.map(ToString::to_string));
            let model = first_json_string(value, &["model", "id", "model_id", "modelId", "name"]);
            if let (Some(provider), Some(model)) = (provider.as_deref(), model.as_deref()) {
                let thinking = first_json_string(
                    value,
                    &["thinkingLevel", "thinking_level", "defaultThinkingLevel"],
                )
                .or_else(|| default_thinking.map(ToString::to_string));
                push_pi_model_route(provider, model, thinking.as_deref(), seen, routes);
                return;
            }
            for nested in map.values() {
                collect_pi_enabled_model_routes(
                    nested,
                    default_provider,
                    default_thinking,
                    seen,
                    routes,
                );
            }
        }
        Value::String(route) => {
            if let Some((provider, model, route_thinking)) =
                parse_pi_route_string(route, default_provider)
            {
                let thinking = route_thinking.as_deref().or(default_thinking);
                push_pi_model_route(&provider, &model, thinking, seen, routes);
            }
        }
        _ => {}
    }
}

pub(super) fn parse_pi_route_string(
    route: &str,
    default_provider: Option<&str>,
) -> Option<(String, String, Option<String>)> {
    let trimmed = route.trim();
    if trimmed.is_empty() {
        return None;
    }

    let (route_body, thinking_level) = parse_pi_route_thinking_suffix(trimmed);
    for separator in ["/", ":"] {
        if let Some((provider, model)) = route_body.split_once(separator) {
            if looks_like_safe_model_id(model) && !provider.trim().is_empty() {
                return Some((
                    provider.trim().to_string(),
                    model.trim().to_string(),
                    thinking_level,
                ));
            }
        }
    }
    default_provider
        .filter(|_| looks_like_safe_model_id(route_body))
        .map(|provider| (provider.to_string(), route_body.to_string(), thinking_level))
}

pub(super) fn parse_pi_route_thinking_suffix(route: &str) -> (&str, Option<String>) {
    let Some((body, suffix)) = route.rsplit_once(':') else {
        return (route, None);
    };
    let suffix = suffix.trim();
    if !body.contains('/') || !looks_like_pi_thinking_level(suffix) {
        return (route, None);
    }
    (body.trim(), Some(suffix.to_ascii_lowercase()))
}

pub(super) fn looks_like_pi_thinking_level(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "none" | "off" | "low" | "medium" | "high" | "xhigh"
    )
}

pub(super) fn push_pi_model_route(
    provider: &str,
    model: &str,
    thinking_level: Option<&str>,
    seen: &mut BTreeSet<(Option<String>, String)>,
    routes: &mut Vec<PiModelRoute>,
) {
    let Some(route) = PiModelRoute::new(provider, model, thinking_level) else {
        return;
    };
    let key = (Some(route.provider.clone()), route.model.clone());
    if !seen.insert(key) {
        return;
    }
    routes.push(route);
}

pub(super) fn pi_model_detail_from_route(
    route: &PiModelRoute,
    context_window_tokens: Option<u64>,
    max_output_tokens: Option<u64>,
    supports_thinking: Option<bool>,
    supports_images: Option<bool>,
    billing_identity: Option<&BillingIdentityHints>,
) -> AgentAvailableModelStatus {
    let identity = billing_identity.cloned().unwrap_or_default();
    AgentAvailableModelStatus {
        id: route.model.clone(),
        provider: Some(route.provider.clone()),
        model_provider: route.classification.model_provider.clone(),
        billing_provider: route.classification.billing_provider.clone(),
        billing_channel: route.classification.billing_channel.clone(),
        auth_mode: route.classification.auth_mode.clone(),
        gateway_provider: route.classification.gateway_provider.clone(),
        subscription_product: route.classification.subscription_product.clone(),
        source_category: route.classification.source_category.clone(),
        account_identifier_hash: identity.account_identifier_hash,
        organization_identifier_hash: identity.organization_identifier_hash,
        credential_fingerprint_hash: identity.credential_fingerprint_hash,
        billing_identity_evidence: identity.billing_identity_evidence,
        billing_identity_confidence: identity.billing_identity_confidence,
        context_window_tokens,
        max_output_tokens,
        supports_thinking: supports_thinking.or_else(|| {
            route
                .thinking_level
                .as_deref()
                .map(|value| value != "none" && value != "off")
        }),
        supports_images,
    }
}

pub(super) fn collect_pi_model_status_from_output(
    output: &CommandOutput,
    auth: Option<&Value>,
) -> AgentModelStatus {
    let mut details = Vec::new();
    let mut seen = BTreeSet::new();
    if output.command_found && output.success {
        let text = command_output_text(output);
        let mut in_table = false;
        for line in text.lines() {
            if line.split_whitespace().eq([
                "provider", "model", "context", "max-out", "thinking", "images",
            ]) {
                in_table = true;
                continue;
            }
            if !in_table {
                continue;
            }
            let Some(detail) = parse_pi_model_table_line(line, auth) else {
                continue;
            };
            if seen.insert((detail.provider.clone(), detail.id.clone())) {
                details.push(detail);
            }
            if details.len() >= MAX_AVAILABLE_MODELS {
                break;
            }
        }
    }
    let available_models = details.iter().map(|detail| detail.id.clone()).collect();
    let providers: BTreeSet<&str> = details
        .iter()
        .filter_map(|detail| detail.provider.as_deref())
        .collect();
    AgentModelStatus {
        active_model: None,
        default_model: None,
        provider: match providers.len() {
            0 => None,
            1 => providers
                .iter()
                .next()
                .map(|provider| (*provider).to_string()),
            _ => Some("multi_provider".to_string()),
        },
        available_models,
        available_model_details: details,
        context_window_tokens: None,
    }
}

pub(super) fn parse_pi_model_table_line(
    line: &str,
    auth: Option<&Value>,
) -> Option<AgentAvailableModelStatus> {
    let mut parts = line.split_whitespace();
    let provider = parts.next()?;
    let model = parts.next()?;
    if provider == "provider" || model == "model" {
        return None;
    }
    let context = parse_pi_token_count(parts.next()?)?;
    let max_output = parse_pi_token_count(parts.next()?)?;
    let thinking = parse_yes_no(parts.next()?)?;
    let images = parse_yes_no(parts.next()?)?;
    if parts.next().is_some() || !looks_like_safe_model_id(model) {
        return None;
    }
    let route = PiModelRoute::new(provider, model, None)?;
    let identity = pi_identity_hints_for_route(auth, &route);
    Some(pi_model_detail_from_route(
        &route,
        Some(context),
        Some(max_output),
        Some(thinking),
        Some(images),
        Some(&identity),
    ))
}

pub(super) fn parse_pi_token_count(value: &str) -> Option<u64> {
    let trimmed = value.trim().replace(',', "");
    if trimmed.is_empty() {
        return None;
    }
    let (number, multiplier) = match trimmed.chars().last()? {
        'K' | 'k' => (&trimmed[..trimmed.len() - 1], 1_000_f64),
        'M' | 'm' => (&trimmed[..trimmed.len() - 1], 1_000_000_f64),
        _ => (trimmed.as_str(), 1_f64),
    };
    number
        .parse::<f64>()
        .ok()
        .map(|value| (value * multiplier).round() as u64)
}

pub(super) fn pi_route_classification(provider: &str, model: &str) -> PiRouteClassification {
    let provider = normalize_pi_provider(provider);
    let model_key = model.to_ascii_lowercase();
    match provider.as_str() {
        "openai-codex" => PiRouteClassification {
            model_provider: Some("openai".to_string()),
            billing_provider: Some("openai".to_string()),
            billing_channel: Some("subscription".to_string()),
            auth_mode: Some("oauth".to_string()),
            gateway_provider: None,
            subscription_product: Some("chatgpt".to_string()),
            source_category: Some("chatgpt_openai_subscription".to_string()),
        },
        "openai" => PiRouteClassification {
            model_provider: Some("openai".to_string()),
            billing_provider: Some("openai".to_string()),
            billing_channel: Some("direct_api".to_string()),
            auth_mode: Some("api_key".to_string()),
            gateway_provider: None,
            subscription_product: None,
            source_category: Some("openai_api_key".to_string()),
        },
        "google-vertex" => PiRouteClassification {
            model_provider: Some("google".to_string()),
            billing_provider: Some("google".to_string()),
            billing_channel: Some("google_vertex".to_string()),
            auth_mode: Some("service_account".to_string()),
            gateway_provider: None,
            subscription_product: None,
            source_category: Some("google_cloud_vertex".to_string()),
        },
        "google" | "google-gemini" => PiRouteClassification {
            model_provider: Some("google".to_string()),
            billing_provider: Some("google".to_string()),
            billing_channel: Some("direct_api".to_string()),
            auth_mode: Some("api_key".to_string()),
            gateway_provider: None,
            subscription_product: None,
            source_category: Some("google_gemini_api_key".to_string()),
        },
        "amazon-bedrock" | "aws-bedrock" => {
            let model_provider = infer_pi_model_provider_from_model(&model_key)
                .unwrap_or_else(|| "amazon".to_string());
            PiRouteClassification {
                model_provider: Some(model_provider.clone()),
                billing_provider: Some(model_provider),
                billing_channel: Some("amazon_bedrock".to_string()),
                auth_mode: Some("service_account".to_string()),
                gateway_provider: None,
                subscription_product: None,
                source_category: Some("aws_bedrock".to_string()),
            }
        }
        "azure-openai-responses" | "azure-openai" => PiRouteClassification {
            model_provider: Some("openai".to_string()),
            billing_provider: Some("openai".to_string()),
            billing_channel: Some("azure_openai".to_string()),
            auth_mode: Some("api_key".to_string()),
            gateway_provider: None,
            subscription_product: None,
            source_category: Some("azure_openai".to_string()),
        },
        "cloudflare-ai-gateway" | "cloudflare-workers-ai" => {
            gateway_classification("cloudflare", &model_key)
        }
        "openrouter" => gateway_classification("openrouter", &model_key),
        "vercel-ai-gateway" => gateway_classification("vercel_ai_gateway", &model_key),
        "github-copilot" => PiRouteClassification {
            model_provider: infer_pi_model_provider_from_model(&model_key),
            billing_provider: Some("github".to_string()),
            billing_channel: Some("subscription".to_string()),
            auth_mode: Some("oauth".to_string()),
            gateway_provider: None,
            subscription_product: Some("github_copilot".to_string()),
            source_category: Some("unknown".to_string()),
        },
        "anthropic" | "claude" | "claude-code" => PiRouteClassification {
            model_provider: Some("anthropic".to_string()),
            billing_provider: Some("anthropic".to_string()),
            billing_channel: Some("subscription".to_string()),
            auth_mode: Some("oauth".to_string()),
            gateway_provider: None,
            subscription_product: Some("claude".to_string()),
            source_category: Some("unknown".to_string()),
        },
        other => PiRouteClassification {
            model_provider: infer_pi_model_provider_from_model(&model_key),
            billing_provider: Some(other.to_string()),
            billing_channel: Some("direct_api".to_string()),
            auth_mode: Some("api_key".to_string()),
            gateway_provider: None,
            subscription_product: None,
            source_category: Some("unknown".to_string()),
        },
    }
}

pub(super) fn gateway_classification(
    gateway_provider: &str,
    model_key: &str,
) -> PiRouteClassification {
    PiRouteClassification {
        model_provider: infer_pi_model_provider_from_model(model_key),
        billing_provider: Some(gateway_provider.to_string()),
        billing_channel: Some("gateway".to_string()),
        auth_mode: Some("api_key".to_string()),
        gateway_provider: Some(gateway_provider.to_string()),
        subscription_product: None,
        source_category: Some("gateway".to_string()),
    }
}

pub(super) fn normalize_pi_provider(provider: &str) -> String {
    provider
        .trim()
        .to_ascii_lowercase()
        .replace('_', " ")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join("-")
}

pub(super) fn infer_pi_model_provider_from_model(model_key: &str) -> Option<String> {
    let model_key = model_key.trim().to_ascii_lowercase();
    if model_key.is_empty() {
        return None;
    }
    if model_key.contains("anthropic.") || model_key.contains("claude") {
        return Some("anthropic".to_string());
    }
    if model_key.starts_with("openai.")
        || model_key.starts_with("gpt-")
        || model_key.starts_with("o1")
        || model_key.starts_with("o3")
        || model_key.starts_with("o4")
    {
        return Some("openai".to_string());
    }
    if model_key.starts_with("google.")
        || model_key.starts_with("gemini")
        || model_key.contains(".gemini")
    {
        return Some("google".to_string());
    }
    if model_key.starts_with("meta.") || model_key.contains("llama") {
        return Some("meta".to_string());
    }
    if model_key.starts_with("mistral.") || model_key.contains("mistral") {
        return Some("mistral".to_string());
    }
    if model_key.starts_with("xai.") || model_key.contains("grok") {
        return Some("xai".to_string());
    }
    if let Some((prefix, _)) = model_key.split_once('.') {
        if !matches!(prefix, "global" | "us" | "eu" | "apac") {
            return Some(prefix.to_string());
        }
    }
    None
}

pub(super) fn read_pi_safe_auth_metadata() -> Option<Value> {
    for path in [
        pi_agent_auth_path(),
        home_path(".pi/auth.json"),
        home_path(".pi/profile.json"),
        home_path(".pi/config.json"),
    ] {
        if let Ok(body) = fs::read_to_string(path) {
            if let Ok(json) = serde_json::from_str::<Value>(&body) {
                return Some(strip_secret_json(json));
            }
        }
    }
    None
}

pub(crate) fn read_pi_agent_auth() -> Option<Value> {
    let body = fs::read_to_string(pi_agent_auth_path()).ok()?;
    serde_json::from_str::<Value>(&body).ok()
}

pub(super) fn read_pi_agent_settings() -> Option<Value> {
    let body = fs::read_to_string(pi_agent_settings_path()).ok()?;
    serde_json::from_str::<Value>(&body)
        .ok()
        .map(strip_secret_json)
}

/// Pi's agent directory, resolved as Pi itself does: a non-empty
/// `PI_CODING_AGENT_DIR`, taken as written (no trim) with a leading `~`
/// expanded against `home`, else `~/.pi/agent`. The scanner, the status
/// reader and the Verify census all use this one rule.
pub(crate) fn pi_agent_dir(home: &Path) -> PathBuf {
    pi_agent_dir_from(home, std::env::var_os("PI_CODING_AGENT_DIR"))
}

/// Where Pi writes its sessions: `sessions` under its agent directory.
pub(crate) fn pi_sessions_dir(home: &Path) -> PathBuf {
    pi_agent_dir(home).join("sessions")
}

pub(super) fn pi_agent_dir_from(home: &Path, value: Option<std::ffi::OsString>) -> PathBuf {
    match value.filter(|value| !value.is_empty()).map(PathBuf::from) {
        Some(dir) => match dir.strip_prefix("~") {
            Ok(rest) if rest.as_os_str().is_empty() => home.to_path_buf(),
            Ok(rest) => home.join(rest),
            Err(_) => dir,
        },
        None => home.join(".pi").join("agent"),
    }
}

pub(super) fn pi_agent_auth_path() -> PathBuf {
    pi_agent_dir(&home_dir()).join("auth.json")
}

pub(super) fn pi_agent_settings_path() -> PathBuf {
    pi_agent_dir(&home_dir()).join("settings.json")
}

pub(super) fn pi_auth_entry<'a>(auth: &'a Value, provider: &str) -> Option<&'a Value> {
    let Value::Object(map) = auth else {
        return None;
    };
    let provider_lower = provider.trim().to_ascii_lowercase();
    let mut aliases = vec![provider_lower.clone(), provider_lower.replace('-', "_")];
    aliases.push(
        match provider_lower.as_str() {
            "openai-codex" | "openai_codex" => "openai",
            "google-vertex" | "google_vertex" | "vertex" => "google",
            "anthropic-api" | "anthropic_api" => "anthropic",
            other => other,
        }
        .to_string(),
    );
    aliases.iter().find_map(|alias| map.get(alias.as_str()))
}

pub(super) fn jwt_claims(token: &str) -> Option<Value> {
    let payload = token.split('.').nth(1)?;
    let decoded = URL_SAFE_NO_PAD.decode(payload).ok()?;
    serde_json::from_slice(&decoded).ok()
}

pub(super) fn openai_codex_account_id_from_auth_entry(entry: &Value) -> Option<String> {
    first_json_string(
        entry,
        &[
            "accountId",
            "account_id",
            "chatgpt_account_id",
            "chatgptAccountId",
        ],
    )
    .or_else(|| {
        for key in [
            "accessToken",
            "access_token",
            "idToken",
            "id_token",
            "token",
        ] {
            let token = first_json_string(entry, &[key])?;
            let claims = jwt_claims(&token)?;
            let auth_claim = claims.get("https://api.openai.com/auth");
            if let Some(account_id) = auth_claim.and_then(|value| {
                first_json_string(value, &["chatgpt_account_id", "chatgpt_user_id", "user_id"])
            }) {
                return Some(account_id);
            }
            if let Some(subject) = first_json_string(&claims, &["sub"]) {
                return Some(subject);
            }
        }
        None
    })
}

pub(crate) fn pi_identity_hints_for_route(
    auth: Option<&Value>,
    route: &PiModelRoute,
) -> BillingIdentityHints {
    let Some(entry) = auth.and_then(|auth| pi_auth_entry(auth, &route.provider)) else {
        return BillingIdentityHints::default();
    };
    let provider_for_hash = route
        .classification
        .billing_provider
        .as_deref()
        .unwrap_or(route.provider.as_str());
    let auth_type = first_json_string(entry, &["type", "auth_type", "authType", "auth_method"])
        .map(normalize_plan_type);

    let mut account_identifier_hash = None;
    let mut organization_identifier_hash = None;
    let mut credential_fingerprint_hash = None;
    let mut evidence = None;

    if route.provider.eq_ignore_ascii_case("openai-codex")
        || route.provider.eq_ignore_ascii_case("openai_codex")
    {
        account_identifier_hash = openai_codex_account_id_from_auth_entry(entry)
            .as_deref()
            .and_then(|value| billing_identity_hash("openai", "account", value));
    }

    if matches!(
        route.classification.billing_channel.as_deref(),
        Some("google_vertex")
    ) {
        organization_identifier_hash = first_json_string(
            entry,
            &[
                "projectId",
                "project_id",
                "quota_project_id",
                "quotaProjectId",
                "billing_project",
            ],
        )
        .as_deref()
        .and_then(|value| billing_identity_hash("google_vertex", "project", value));
        credential_fingerprint_hash = first_json_string(
            entry,
            &[
                "client_email",
                "clientEmail",
                "service_account",
                "serviceAccount",
            ],
        )
        .as_deref()
        .and_then(|value| billing_identity_hash("google_vertex", "service_account", value));
        if organization_identifier_hash.is_some() {
            evidence = Some("cloud_project_id".to_string());
        }
    }

    if route.classification.auth_mode.as_deref() == Some("api_key")
        || auth_type.as_deref() == Some("api_key")
    {
        credential_fingerprint_hash = first_json_string(
            entry,
            &[
                "key",
                "api_key",
                "apiKey",
                "access_key",
                "accessKey",
                "secret_access_key",
                "secretAccessKey",
            ],
        )
        .as_deref()
        .and_then(|value| billing_identity_hash(provider_for_hash, "credential", value));
    }

    if evidence.is_none() {
        evidence = billing_identity_evidence_for(
            &account_identifier_hash,
            &organization_identifier_hash,
            &credential_fingerprint_hash,
        );
    }
    let billing_identity_confidence = if evidence.is_some() {
        AgentStatusConfidence::High
    } else {
        AgentStatusConfidence::Unknown
    };
    BillingIdentityHints {
        account_identifier_hash,
        organization_identifier_hash,
        credential_fingerprint_hash,
        billing_identity_evidence: evidence,
        billing_identity_confidence,
    }
}
