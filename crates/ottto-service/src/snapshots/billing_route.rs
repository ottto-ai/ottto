//! Per-session billing route annotation (`session_billing_route:v1`).
//!
//! Annotation only: a route never feeds pricing, placement, identity, upload
//! eligibility or any money field. The wire object sits outside every
//! semantic component, the content hash and the upload body witness, so it
//! starts no upload of its own and rides on the session's ordinary uploads.
//!
//! Latches live in this process's memory only; nothing is persisted, so no
//! release ever reads, refuses or must preserve them. The server keeps the
//! first known route it accepted for a session and counts, never applies, a
//! later different one.
//!
//! Claude Code: the login evaluator's result is frozen once per process, when
//! a session's request is first observed live (it ended after this process
//! started), and it never names a route by itself. Only live requests are
//! classified: after a restart a session latches again from its next request,
//! never from today's login applied to earlier requests. OAuth needs that session's own Desktop request or a request whose
//! own telemetry row named a valid account; an API key needs a native
//! `req_`/`msg_` id pair. A cloud message or request id (`msg_bdrk_`,
//! `msg_vrtx_`) or a cloud-shaped model on any owned request vetoes both, so
//! the session stays unknown whatever its model. Residuals, disclosed: a
//! gateway that forwards native-looking ids can satisfy either conjunction,
//! and a same-session account does not prove who paid for the first request;
//! the annotation is not fail-closed for every proxy.
//! Codex and Pi read the auth and provider recorded on the session's own rows
//! (Pi through an allowlist). The first known route never changes; later
//! routes only join `routes_seen`. Every other case is unknown with a closed
//! reason, and unknown never means zero cost or permission to hold usage.

use super::scan::lines::selectors::claude_cloud_id_provider;
use super::*;

/// The exact receiver capability. Missing/null/unknown keeps the object off.
pub(crate) const SESSION_BILLING_ROUTE_CONTRACT: &str = "session_billing_route:v1";

/// Whether this build latches and annotates routes. Off, no route state, clock
/// or classification work runs.
pub(crate) const PRODUCER_ENABLED: bool = false;

/// Shared route vocabulary. Values never name an account, payer or price.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BillingRoute {
    /// Native provider API billing.
    DirectApi,
    /// Provider plan.
    Subscription,
    /// AWS Bedrock, Mantle included. Not produced for Claude Code in v1.
    AmazonBedrock,
    /// Google Cloud Vertex. Not produced for Claude Code in v1.
    GoogleVertex,
}

/// Closed reasons, present only while `first_route` is null.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum UnknownRouteReason {
    #[serde(rename = "3p_classifier_pending")]
    ThirdPartyClassifierPending,
    #[serde(rename = "proxy_endpoint")]
    ProxyEndpoint,
    #[serde(rename = "mode_unknown")]
    ModeUnknown,
    #[serde(rename = "first_request_snapshot_missing")]
    FirstRequestSnapshotMissing,
    #[serde(rename = "unsupported_provider_auth")]
    UnsupportedProviderAuth,
    #[serde(rename = "signal_conflict")]
    SignalConflict,
    #[serde(rename = "missing_evidence")]
    MissingEvidence,
    #[serde(rename = "uncorroborated_snapshot")]
    UncorroboratedSnapshot,
}

/// What set a known `first_route`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteSource {
    /// Claude Code: the frozen login evaluator result plus that session's
    /// own corroborating request evidence; never the evaluator alone.
    EvaluatorSnapshot,
    PiProviderAuth,
    CodexAuthSnapshot,
}

/// The Claude Code login evaluator's result for the default login, reduced
/// to what route classification may use. No credential, key or URL is kept.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum LoginCandidate {
    /// A usable OAuth login and no visible alternative authentication.
    Oauth,
    /// An API key, auth token or key helper aimed at the native endpoint.
    ApiKey,
    /// Visible Bedrock or Vertex selection.
    ThirdPartyPending,
    /// A visible non-native `ANTHROPIC_BASE_URL`.
    ProxyEndpoint,
    /// Interactive and print-mode evaluation disagree.
    ModeUnknown,
    /// A visible route v1 does not classify (for example Foundry).
    Unsupported,
    /// Neither a usable OAuth login nor an alternative authentication.
    NoUsableLogin,
}

/// The `session_billing_route` wire object: exactly four members.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SessionBillingRoute {
    pub first_route: Option<BillingRoute>,
    /// Sorted unique known routes; empty while `first_route` is null.
    pub routes_seen: Vec<BillingRoute>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unknown_reason: Option<UnknownRouteReason>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_route_source: Option<RouteSource>,
}

/// The per-session latch, in this process's memory only, keyed by
/// destination, source, machine and session. Never persisted or uploaded as
/// is.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct SessionBillingRouteFact {
    /// Claude Code: the login evaluator result frozen at the session's first
    /// live request in this process. Never retaken.
    pub(crate) login: Option<LoginCandidate>,
    pub(crate) first_route: Option<BillingRoute>,
    pub(crate) first_route_source: Option<RouteSource>,
    pub(crate) routes_seen: BTreeSet<BillingRoute>,
    pub(crate) unknown_reason: Option<UnknownRouteReason>,
    /// A later request contradicted the first route. Recorded, never
    /// corrected.
    pub(crate) conflict_after_latch: bool,
}

impl SessionBillingRouteFact {
    pub(crate) fn wire(&self) -> SessionBillingRoute {
        match self.first_route {
            Some(route) => SessionBillingRoute {
                first_route: Some(route),
                routes_seen: self
                    .routes_seen
                    .iter()
                    .copied()
                    .chain(std::iter::once(route))
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect(),
                unknown_reason: None,
                first_route_source: self.first_route_source,
            },
            None => SessionBillingRoute {
                first_route: None,
                routes_seen: Vec::new(),
                unknown_reason: Some(
                    self.unknown_reason
                        .unwrap_or(UnknownRouteReason::MissingEvidence),
                ),
                first_route_source: None,
            },
        }
    }
}

/// One owned Claude request's route evidence, from fields the response book
/// already retains.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct ClaudeRouteRequest {
    /// `requestId` `req_*` with a plain `message.id` `msg_*`.
    pub(crate) native_ids: bool,
    /// A third-party-shaped model or message id.
    pub(crate) third_party: bool,
    /// Every record of the request carried entrypoint `claude-desktop`.
    pub(crate) desktop: bool,
    /// When the request ended.
    pub(crate) ended_unix: Option<u64>,
}

/// A Claude item's route evidence, captured before its native request inputs
/// are released. Local only; never serialized.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct ClaudeRouteEvidence {
    /// Owned billable requests in transcript order.
    pub(crate) requests: Vec<ClaudeRouteRequest>,
    /// One of this session's own requests joined a telemetry row, by its
    /// provider request id, that named a valid account.
    pub(crate) telemetry_account: bool,
}

crate::heap_layout_bound::no_heap!(true;
    BillingRoute: DirectApi | Subscription | AmazonBedrock | GoogleVertex,
    UnknownRouteReason: ThirdPartyClassifierPending | ProxyEndpoint | ModeUnknown | FirstRequestSnapshotMissing | UnsupportedProviderAuth | SignalConflict | MissingEvidence | UncorroboratedSnapshot,
    RouteSource: EvaluatorSnapshot | PiProviderAuth | CodexAuthSnapshot,
    LoginCandidate: Oauth | ApiKey | ThirdPartyPending | ProxyEndpoint | ModeUnknown | Unsupported | NoUsableLogin,
    ClaudeRouteRequest { native_ids, third_party, desktop, ended_unix },
);
crate::heap_layout_bound::fields!(SessionBillingRouteFact; login, first_route, first_route_source, routes_seen, unknown_reason, conflict_after_latch);
crate::heap_layout_bound::fields!(SessionBillingRoute; first_route, routes_seen, unknown_reason, first_route_source);
crate::heap_layout_bound::fields!(ClaudeRouteEvidence; requests, telemetry_account);

/// Third-party-shaped Claude model names: Bedrock inference profiles and
/// ARNs, Mantle ids and Vertex `@date` versions. A conservative veto only;
/// a shape never names a cloud route.
pub(crate) fn claude_third_party_model(model: &str) -> bool {
    let model = model.trim().to_ascii_lowercase();
    if model.starts_with("arn:aws:bedrock:") || model.starts_with("anthropic.claude") {
        return true;
    }
    if ["us.", "eu.", "apac.", "global."].iter().any(|prefix| {
        model
            .strip_prefix(prefix)
            .is_some_and(|rest| rest.starts_with("anthropic.claude"))
    }) {
        return true;
    }
    // Vertex: `claude-<name>@YYYYMMDD`.
    model.starts_with("claude-")
        && model
            .rsplit_once('@')
            .is_some_and(|(_, date)| date.len() == 8 && date.bytes().all(|b| b.is_ascii_digit()))
}

/// The request ids a Claude response key carries: `(native pair, cloud id)`.
/// Keys are `p<US>message<US>request`, `m<US>message` or `r<US>request`.
pub(crate) fn claude_key_route_ids(key: &str) -> (bool, bool) {
    let mut parts = key.split('\u{1f}');
    let kind = parts.next().unwrap_or_default();
    let (message, request) = match kind {
        "p" => (parts.next(), parts.next()),
        "m" => (parts.next(), None),
        "r" => (None, parts.next()),
        _ => (None, None),
    };
    let cloud = |id: &str| claude_cloud_id_provider(id).is_some();
    let third_party = message.is_some_and(cloud) || request.is_some_and(cloud);
    let native = !third_party
        && message.is_some_and(|id| id.starts_with("msg_"))
        && request.is_some_and(|id| id.starts_with("req_"));
    (native, third_party)
}

/// Capture `item`'s Claude route evidence from its native request inputs,
/// once, before those inputs are released. Requests copied before the
/// session's first own request and synthetic records are not its own.
pub(crate) fn capture_claude_route_evidence(item: &mut SnapshotItem) {
    if item.claude_route_evidence.is_some() || item.claude_usage_occurrences.is_empty() {
        return;
    }
    let own_from = item
        .first_own_request_at
        .as_deref()
        .and_then(rfc3339_unix_seconds);
    let mut owned = item
        .claude_usage_occurrences
        .values()
        .filter(|occurrence| occurrence.model.as_deref() != Some("<synthetic>"))
        .filter_map(|occurrence| {
            let at = occurrence
                .timestamp
                .as_deref()
                .and_then(rfc3339_unix_seconds);
            if let (Some(from), Some(at)) = (own_from, at)
                && at < from
            {
                return None;
            }
            Some((occurrence.sequence, at, occurrence))
        })
        .collect::<Vec<_>>();
    owned.sort_by_key(|(sequence, _, _)| *sequence);
    let evidence = ClaudeRouteEvidence {
        telemetry_account: owned
            .iter()
            .any(|(_, _, occurrence)| occurrence.route_telemetry_account),
        requests: owned
            .iter()
            .map(|(_, at, occurrence)| ClaudeRouteRequest {
                native_ids: occurrence.route_native_ids,
                third_party: occurrence.route_third_party_id
                    || occurrence
                        .model
                        .as_deref()
                        .is_some_and(claude_third_party_model),
                desktop: occurrence.desktop_request,
                ended_unix: *at,
            })
            .collect(),
    };
    item.claude_route_evidence = Some(Box::new(evidence));
}

/// One request's route, or why it has none.
fn classify_claude_request(
    login: Option<LoginCandidate>,
    request: ClaudeRouteRequest,
    telemetry_account: bool,
) -> Result<BillingRoute, UnknownRouteReason> {
    use UnknownRouteReason as R;
    if request.third_party {
        return Err(R::SignalConflict);
    }
    match login {
        None => Err(R::FirstRequestSnapshotMissing),
        Some(LoginCandidate::ThirdPartyPending) => Err(R::ThirdPartyClassifierPending),
        Some(LoginCandidate::ProxyEndpoint) => Err(R::ProxyEndpoint),
        Some(LoginCandidate::ModeUnknown) => Err(R::ModeUnknown),
        Some(LoginCandidate::Unsupported) => Err(R::UnsupportedProviderAuth),
        Some(LoginCandidate::NoUsableLogin) => Err(R::MissingEvidence),
        Some(LoginCandidate::Oauth) if request.desktop || telemetry_account => {
            Ok(BillingRoute::Subscription)
        }
        Some(LoginCandidate::ApiKey) if request.native_ids => Ok(BillingRoute::DirectApi),
        Some(LoginCandidate::Oauth | LoginCandidate::ApiKey) => Err(R::UncorroboratedSnapshot),
    }
}

/// Classified requests in source order, with the source that names them.
struct Classified {
    requests: Vec<Result<BillingRoute, UnknownRouteReason>>,
    /// Any request vetoes a new latch (third-party evidence).
    veto: bool,
    source: RouteSource,
}

/// Fold one pass's classified requests into the latch. A null first route
/// becomes known once, from the first classified request in source order,
/// unless any request vetoes it; a known one never changes. Later known
/// routes only join `routes_seen`.
fn fold(fact: &mut SessionBillingRouteFact, classified: Classified) {
    let known = || {
        classified
            .requests
            .iter()
            .filter_map(|r| r.as_ref().ok().copied())
    };
    if let Some(first) = fact.first_route {
        fact.routes_seen.extend(known());
        fact.routes_seen.insert(first);
        // Third-party evidence after the latch is recorded, never corrected.
        // A different known route is a mixed session, not a conflict.
        fact.conflict_after_latch |= classified.veto;
        return;
    }
    if classified.veto {
        fact.unknown_reason = Some(UnknownRouteReason::SignalConflict);
        return;
    }
    match classified.requests.iter().find_map(|r| r.as_ref().ok()) {
        Some(&first) => {
            fact.first_route = Some(first);
            fact.first_route_source = Some(classified.source);
            fact.unknown_reason = None;
            fact.routes_seen = known().collect();
        }
        None => {
            fact.unknown_reason = Some(
                classified
                    .requests
                    .first()
                    .and_then(|r| r.err())
                    .unwrap_or(UnknownRouteReason::MissingEvidence),
            );
        }
    }
}

/// Positive routes come only from live requests; third-party evidence on any
/// owned request vetoes.
fn classify_claude(
    fact: &SessionBillingRouteFact,
    evidence: &ClaudeRouteEvidence,
    context: &RouteContext,
) -> Classified {
    Classified {
        requests: evidence
            .requests
            .iter()
            .filter(|request| context.live(request))
            .map(|request| {
                classify_claude_request(fact.login, *request, evidence.telemetry_account)
            })
            .collect(),
        veto: evidence.requests.iter().any(|request| request.third_party),
        source: RouteSource::EvaluatorSnapshot,
    }
}

/// Every model row of an item in source order: hour buckets as emitted
/// (earliest first), then the session rows.
fn rows(item: &SnapshotItem) -> impl Iterator<Item = &SnapshotModelUsage> {
    item.usage_buckets
        .iter()
        .flat_map(|bucket| bucket.model_usage.iter())
        .chain(item.model_usage.iter())
}

/// Codex: the auth mode recorded on the session's own rows. Explicit
/// `chatgpt` is the plan; an explicit API key is native API billing only
/// beside the built-in `openai` provider. Everything else stays unknown.
fn classify_codex_row(row: &SnapshotModelUsage) -> Result<BillingRoute, UnknownRouteReason> {
    use UnknownRouteReason as R;
    let provider = row.model_provider.as_deref().map(str::trim);
    match row.auth_mode.as_deref().map(str::trim) {
        Some("chatgpt") => Ok(BillingRoute::Subscription),
        Some("apikey" | "api_key") => match provider {
            Some("openai") => Ok(BillingRoute::DirectApi),
            Some(_) => Err(R::ProxyEndpoint),
            None => Err(R::MissingEvidence),
        },
        None => Err(R::MissingEvidence),
        Some(_) => Err(R::UnsupportedProviderAuth),
    }
}

/// Pi: only allowlisted cloud provider + explicit recorded auth pairs. The
/// provider name alone never names a route.
fn classify_pi_row(row: &SnapshotModelUsage) -> Result<BillingRoute, UnknownRouteReason> {
    let provider = row
        .model_provider
        .as_deref()
        .map(|provider| provider.trim().to_ascii_lowercase());
    let auth = row.auth_mode.as_deref().map(str::trim);
    match (provider.as_deref(), auth) {
        (Some("google-vertex"), Some("service_account")) => Ok(BillingRoute::GoogleVertex),
        (Some("amazon-bedrock" | "aws-bedrock"), Some("service_account")) => {
            Ok(BillingRoute::AmazonBedrock)
        }
        _ => Err(UnknownRouteReason::UnsupportedProviderAuth),
    }
}

/// Codex and Pi: each billable row in source order.
fn classify_rows(
    item: &SnapshotItem,
    classify: fn(&SnapshotModelUsage) -> Result<BillingRoute, UnknownRouteReason>,
    source: RouteSource,
) -> Classified {
    Classified {
        requests: rows(item)
            .filter(|row| row.request_count > 0)
            .map(classify)
            .collect(),
        veto: false,
        source,
    }
}

/// Inputs for one pass's route latches.
#[derive(Debug, Clone, Copy)]
pub(crate) struct RouteContext {
    /// Also put the object on the wire (the receiver advertised the contract).
    pub(crate) emit: bool,
    pub(crate) process_started_unix: u64,
    /// The latest Claude Code default-login evaluation.
    pub(crate) claude_login: Option<LoginCandidate>,
}

impl RouteContext {
    /// Observed live: the request ended after this process started. Anything
    /// earlier is history and never meets today's login.
    fn live(&self, request: &ClaudeRouteRequest) -> bool {
        request
            .ended_unix
            .is_some_and(|ended| ended >= self.process_started_unix)
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

#[derive(Debug, Default)]
pub(crate) struct RouteState {
    claude_login: Option<LoginCandidate>,
    process_started_unix: Option<u64>,
    /// The process's latches; empty while the producer is off.
    latches: BTreeMap<String, SessionBillingRouteFact>,
}

impl RouteState {
    fn process_started_unix(&mut self) -> u64 {
        *self.process_started_unix.get_or_insert_with(unix_now)
    }
}

process_state! {
    fn with_route_state: RouteState = RouteState {
        claude_login: None,
        process_started_unix: None,
        latches: BTreeMap::new(),
    }; clear_poison: true
}

/// Publish the latest Claude Code default-login evaluation. Its first call
/// also fixes the process start for the live rule; a later start only makes
/// more requests history (fail closed).
pub(crate) fn publish_claude_login(candidate: LoginCandidate) {
    with_route_state(|state| {
        state.process_started_unix();
        state.claude_login = Some(candidate);
    });
}

/// The latch key: destination, source, machine and session. Never an account
/// or a path.
pub(crate) fn route_key(
    destination: &str,
    source: SnapshotSource,
    machine_id: &str,
    session_id: &str,
) -> String {
    sha256_hex(&[
        "session_billing_route:v1",
        destination,
        source.api_slug(),
        machine_id,
        session_id,
    ])
}

/// Latch this pass's items and, when the receiver advertised `contract`,
/// attach the wire object. Producer off, nothing runs.
pub(crate) fn annotate_session_billing_routes(
    destination: &str,
    source: SnapshotSource,
    machine_id: &str,
    snapshots: &mut [SnapshotItem],
    contract: Option<&str>,
) {
    if !PRODUCER_ENABLED {
        return;
    }
    with_route_state(|state| {
        let context = RouteContext {
            emit: contract == Some(SESSION_BILLING_ROUTE_CONTRACT),
            process_started_unix: state.process_started_unix(),
            claude_login: state.claude_login,
        };
        apply_session_billing_routes(
            &mut state.latches,
            destination,
            source,
            machine_id,
            snapshots,
            &context,
        );
    });
}

/// Fold `snapshots` into `latches`. Touches no money field, row, hash, upload
/// decision or persisted state. A session with no billable request gets no
/// latch; a Claude session gets one only at its first live request.
pub(crate) fn apply_session_billing_routes(
    latches: &mut BTreeMap<String, SessionBillingRouteFact>,
    destination: &str,
    source: SnapshotSource,
    machine_id: &str,
    snapshots: &mut [SnapshotItem],
    context: &RouteContext,
) {
    for item in snapshots {
        if source == SnapshotSource::ClaudeCode {
            capture_claude_route_evidence(item);
        }
        let key = route_key(destination, source, machine_id, &item.source_session_id);
        let evidence = item.claude_route_evidence.as_deref();
        let billable = match source {
            SnapshotSource::ClaudeCode => evidence.is_some_and(|e| !e.requests.is_empty()),
            SnapshotSource::Codex | SnapshotSource::Pi => {
                rows(item).any(|row| row.request_count > 0)
            }
        };
        if billable && !latches.contains_key(&key) {
            let start = match source {
                SnapshotSource::ClaudeCode => context
                    .claude_login
                    .filter(|_| {
                        evidence.is_some_and(|e| e.requests.iter().any(|r| context.live(r)))
                    })
                    .map(|login| SessionBillingRouteFact {
                        login: Some(login),
                        ..SessionBillingRouteFact::default()
                    }),
                SnapshotSource::Codex | SnapshotSource::Pi => {
                    Some(SessionBillingRouteFact::default())
                }
            };
            if let Some(fact) = start {
                latches.insert(key.clone(), fact);
            }
        }
        let wire = match latches.get_mut(&key) {
            Some(fact) => {
                let classified = match source {
                    SnapshotSource::ClaudeCode => {
                        evidence.map(|evidence| classify_claude(fact, evidence, context))
                    }
                    SnapshotSource::Codex => Some(classify_rows(
                        item,
                        classify_codex_row,
                        RouteSource::CodexAuthSnapshot,
                    )),
                    SnapshotSource::Pi => Some(classify_rows(
                        item,
                        classify_pi_row,
                        RouteSource::PiProviderAuth,
                    )),
                };
                if let Some(classified) = classified {
                    fold(fact, classified);
                }
                fact.wire()
            }
            // Billable Claude history with no live request yet.
            None => SessionBillingRouteFact {
                unknown_reason: Some(if billable {
                    UnknownRouteReason::FirstRequestSnapshotMissing
                } else {
                    UnknownRouteReason::MissingEvidence
                }),
                ..SessionBillingRouteFact::default()
            }
            .wire(),
        };
        if context.emit {
            item.session_billing_route = Some(wire);
        }
    }
}

#[cfg(test)]
mod tests;
