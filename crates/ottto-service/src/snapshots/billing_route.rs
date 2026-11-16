//! Per-session billing route annotation (`session_billing_route:v1`).
//!
//! Annotation only: a route never feeds pricing, placement, identity, upload
//! eligibility or any money field. The wire object sits outside every
//! semantic component, the content hash and the upload body witness, so it
//! starts no upload of its own and rides on the session's ordinary uploads.
//!
//! Claude Code latches live in this process's memory only; nothing is
//! persisted, so no release ever reads, refuses or must preserve them. Codex
//! and Pi hold no latch: each pass derives the route from the session's own
//! rows in time order (hour buckets).
//!
//! Claude Code: only the session's first own response (in sequence order,
//! never filtered away) names the first route, and only when all of these
//! hold: every physical line of the file decoded and no response, resolved or
//! not, precedes that one (it is the file's response 0); the session's
//! earliest stamped line of any kind, inherited and invalid fork lines
//! included, is strictly after this process started; that
//! response carries a request id, is not synthetic, and has a complete clock
//! whose request start (its preceding prompt or tool-result record) and end
//! are strictly after this process started; and the published login
//! evaluator result last changed at or before that start and was observed at
//! or after that end. An evaluation not yet observed after the end defers the
//! session (no object until a later pass); any other missing, unstamped or
//! unproven input is `first_request_snapshot_missing` with nothing latched,
//! and a later request never stands in. The evaluator never names a route by
//! itself: OAuth needs that session's own Desktop request or a request whose
//! own telemetry row named a valid account; an API key needs a native
//! `req_`/`msg_` id pair. A cloud message or request id (`msg_bdrk_`,
//! `msg_vrtx_`) or a cloud-shaped model on any owned request vetoes both.
//! Later requests, under the same clock and evaluator rule, only join
//! `routes_seen`. Residuals, disclosed: a gateway that forwards native-looking
//! ids can satisfy either conjunction; a same-session account does not prove
//! who paid for the first request; a login switched and switched back between
//! two status refreshes is not seen. The annotation is not fail-closed for
//! every proxy.
//! A known first route never becomes a different known route: Claude Code
//! keeps it in its latch; for Codex and Pi a second route arriving in the
//! first route's hour turns it to `signal_conflict`. Later proven routes only
//! join `routes_seen`. Every other case is unknown with a closed reason, and
//! unknown never means zero cost or permission to hold usage.

use super::scan::lines::selectors::claude_cloud_id_provider;
use super::*;

/// The exact receiver capability. Missing/null/unknown keeps the object off.
pub(crate) const SESSION_BILLING_ROUTE_CONTRACT: &str = "session_billing_route:v1";

/// Whether this build latches and annotates routes. Off, no route state, clock
/// or classification work runs.
pub(crate) const PRODUCER_ENABLED: bool = false;

#[cfg(test)]
thread_local! {
    static TEST_PRODUCER: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// The producer gate on the parse path: [`PRODUCER_ENABLED`], or a test that
/// parses real transcripts with the producer on for its own thread.
pub(crate) fn producer_on() -> bool {
    #[cfg(test)]
    if TEST_PRODUCER.with(std::cell::Cell::get) {
        return true;
    }
    PRODUCER_ENABLED
}

/// Run `f` with the parse-path producer on for this thread.
#[cfg(test)]
pub(crate) fn with_test_producer<T>(f: impl FnOnce() -> T) -> T {
    TEST_PRODUCER.with(|on| on.set(true));
    let out = f();
    TEST_PRODUCER.with(|on| on.set(false));
    out
}

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
    /// Sorted unique known routes; empty while `first_route` is null (the
    /// receiver refuses routes beside an unknown first route).
    pub routes_seen: Vec<BillingRoute>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unknown_reason: Option<UnknownRouteReason>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_route_source: Option<RouteSource>,
}

/// A session's route state. Claude Code keeps one per live session in this
/// process's memory; Codex and Pi build one per pass. Never persisted.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct SessionBillingRouteFact {
    pub(crate) first_route: Option<BillingRoute>,
    pub(crate) first_route_source: Option<RouteSource>,
    pub(crate) routes_seen: BTreeSet<BillingRoute>,
    pub(crate) unknown_reason: Option<UnknownRouteReason>,
}

impl SessionBillingRouteFact {
    fn unknown(reason: UnknownRouteReason) -> Self {
        Self {
            unknown_reason: Some(reason),
            ..Self::default()
        }
    }

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
/// already retains. Times are unix nanoseconds.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct ClaudeRouteRequest {
    /// `requestId` `req_*` with a plain `message.id` `msg_*`.
    pub(crate) native_ids: bool,
    /// A third-party-shaped model or message id.
    pub(crate) third_party: bool,
    /// Every record of the request carried entrypoint `claude-desktop`.
    pub(crate) desktop: bool,
    /// Every record of the response was stamped, so `ended_ns` is its end.
    pub(crate) clock_complete: bool,
    /// No later than the request started: its preceding prompt or
    /// tool-result record.
    pub(crate) started_ns: Option<i64>,
    /// When the request ended.
    pub(crate) ended_ns: Option<i64>,
}

/// A Claude item's route evidence. Local only; never serialized.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct ClaudeRouteEvidence {
    /// The session's earliest stamped line of any kind, inherited and invalid
    /// fork lines included (`claude_line_clocks`), set when the item is
    /// built.
    pub(crate) first_line_ns: Option<i64>,
    /// The route proof is invalid: a physical line of the file failed to
    /// decode, or a response (resolved or not) precedes the first own one.
    pub(crate) proof_invalid: bool,
    /// The session has an own billable response.
    pub(crate) billable: bool,
    /// The session's first own response (`first_own_sequence`); `None` when it
    /// carries no request id or is synthetic.
    pub(crate) first: Option<ClaudeRouteRequest>,
    /// Owned non-synthetic requests after the first, in sequence order.
    pub(crate) later: Vec<ClaudeRouteRequest>,
    /// Any owned request carried a third-party model or id.
    pub(crate) third_party: bool,
    /// One of this session's own requests joined a telemetry row, by its
    /// provider request id, that named a valid account.
    pub(crate) telemetry_account: bool,
}

crate::heap_layout_bound::no_heap!(true;
    BillingRoute: DirectApi | Subscription | AmazonBedrock | GoogleVertex,
    UnknownRouteReason: ThirdPartyClassifierPending | ProxyEndpoint | ModeUnknown | FirstRequestSnapshotMissing | UnsupportedProviderAuth | SignalConflict | MissingEvidence | UncorroboratedSnapshot,
    RouteSource: EvaluatorSnapshot | PiProviderAuth | CodexAuthSnapshot,
    LoginCandidate: Oauth | ApiKey | ThirdPartyPending | ProxyEndpoint | ModeUnknown | Unsupported | NoUsableLogin,
    ClaudeRouteRequest { native_ids, third_party, desktop, clock_complete, started_ns, ended_ns },
    ClaudeLogin { candidate, changed_ns, observed_ns },
);
crate::heap_layout_bound::fields!(SessionBillingRouteFact; first_route, first_route_source, routes_seen, unknown_reason);
crate::heap_layout_bound::fields!(SessionBillingRoute; first_route, routes_seen, unknown_reason, first_route_source);
crate::heap_layout_bound::fields!(ClaudeRouteEvidence; first_line_ns, proof_invalid, billable, first, later, third_party, telemetry_account);

/// An RFC 3339 time as unix nanoseconds; `None` when unreadable or outside
/// `i64`.
pub(crate) fn unix_nanos(value: &str) -> Option<i64> {
    super::rfc3339_unix_nanos(value).and_then(|nanos| i64::try_from(nanos).ok())
}

fn now_unix_nanos() -> i64 {
    i64::try_from(OffsetDateTime::now_utc().unix_timestamp_nanos()).unwrap_or(i64::MAX)
}

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

/// Producer on, a Claude item's evidence box holding the all-line start
/// witness; `None` (nothing allocated) otherwise.
pub(crate) fn start_witness(
    source: SnapshotSource,
    line_clocks: Option<(i128, i128)>,
) -> Option<Box<ClaudeRouteEvidence>> {
    (producer_on() && source == SnapshotSource::ClaudeCode).then(|| {
        Box::new(ClaudeRouteEvidence {
            first_line_ns: line_clocks.and_then(|(first, _)| i64::try_from(first).ok()),
            ..ClaudeRouteEvidence::default()
        })
    })
}

/// Invalidate the route proof of `items`, whose file has a physical line that
/// failed to decode: it may have held the session's first response or its
/// earliest timestamp. Only evidence boxes (producer on) are touched.
pub(crate) fn invalidate_route_proof(items: &mut [SnapshotItem]) {
    for evidence in items
        .iter_mut()
        .filter_map(|item| item.claude_route_evidence.as_deref_mut())
    {
        evidence.proof_invalid = true;
    }
}

/// Capture `item`'s Claude route evidence from its native request inputs,
/// while they are retained, keeping the start witness. Responses before the
/// first own one are copies, not the session's own.
pub(crate) fn capture_claude_route_evidence(item: &mut SnapshotItem) {
    if item.claude_usage_occurrences.is_empty() {
        return;
    }
    let first_own = item.claude_file_birth.first_own_sequence();
    let mut owned = item
        .claude_usage_occurrences
        .values()
        .filter(|occurrence| first_own.is_some_and(|first| occurrence.sequence >= first))
        .collect::<Vec<_>>();
    owned.sort_by_key(|occurrence| occurrence.sequence);
    fn synthetic(occurrence: &ClaudeTranscriptUsageOccurrence) -> bool {
        occurrence.model.as_deref() == Some("<synthetic>")
    }
    fn request(occurrence: &ClaudeTranscriptUsageOccurrence) -> ClaudeRouteRequest {
        ClaudeRouteRequest {
            native_ids: occurrence.route_native_ids,
            third_party: occurrence.route_third_party_id
                || occurrence
                    .model
                    .as_deref()
                    .is_some_and(claude_third_party_model),
            desktop: occurrence.desktop_request,
            clock_complete: occurrence.event_clock_complete,
            started_ns: occurrence.route_started_ns,
            ended_ns: occurrence.timestamp.as_deref().and_then(unix_nanos),
        }
    }
    // The first own response with no request id has no occurrence.
    let first_kept = owned
        .first()
        .copied()
        .filter(|occurrence| Some(occurrence.sequence) == first_own);
    let real = owned
        .iter()
        .copied()
        .filter(|occurrence| !synthetic(occurrence));
    let witness = item.claude_route_evidence.as_deref();
    let evidence = ClaudeRouteEvidence {
        first_line_ns: witness.and_then(|evidence| evidence.first_line_ns),
        // Sequences count every response, resolved or not, from the file's
        // first: any before the first own one leaves the proof invalid.
        proof_invalid: witness.is_some_and(|evidence| evidence.proof_invalid)
            || first_own != Some(0),
        billable: real.clone().next().is_some() || (first_own.is_some() && first_kept.is_none()),
        first: first_kept
            .filter(|occurrence| !synthetic(occurrence))
            .map(request),
        later: real
            .clone()
            .filter(|occurrence| Some(occurrence.sequence) != first_own)
            .map(request)
            .collect(),
        third_party: real
            .clone()
            .any(|occurrence| request(occurrence).third_party),
        telemetry_account: owned
            .iter()
            .any(|occurrence| occurrence.route_telemetry_account),
    };
    item.claude_route_evidence = Some(Box::new(evidence));
}

/// The published Claude Code default-login evaluation and the span it is
/// proven for. Times are unix nanoseconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ClaudeLogin {
    pub(crate) candidate: LoginCandidate,
    /// No earlier than the candidate took its current value: the end of the
    /// evaluation that first saw it.
    pub(crate) changed_ns: i64,
    /// No later than the candidate was last seen: the start of the latest
    /// evaluation that saw it.
    pub(crate) observed_ns: i64,
}

/// One request's route or why it has none; `None` defers it until a status
/// refresh covers its end.
fn classify_claude_request(
    login: Option<ClaudeLogin>,
    request: ClaudeRouteRequest,
    telemetry_account: bool,
) -> Option<Result<BillingRoute, UnknownRouteReason>> {
    use UnknownRouteReason as R;
    if request.third_party {
        return Some(Err(R::SignalConflict));
    }
    let login = login?;
    if request
        .ended_ns
        .is_none_or(|ended| login.observed_ns < ended)
    {
        return None;
    }
    // The evaluator may have changed after the request started: no snapshot
    // proven for this request exists.
    if request
        .started_ns
        .is_none_or(|started| login.changed_ns > started)
    {
        return Some(Err(R::FirstRequestSnapshotMissing));
    }
    Some(match login.candidate {
        LoginCandidate::ThirdPartyPending => Err(R::ThirdPartyClassifierPending),
        LoginCandidate::ProxyEndpoint => Err(R::ProxyEndpoint),
        LoginCandidate::ModeUnknown => Err(R::ModeUnknown),
        LoginCandidate::Unsupported => Err(R::UnsupportedProviderAuth),
        LoginCandidate::NoUsableLogin => Err(R::MissingEvidence),
        LoginCandidate::Oauth if request.desktop || telemetry_account => {
            Ok(BillingRoute::Subscription)
        }
        LoginCandidate::ApiKey if request.native_ids => Ok(BillingRoute::DirectApi),
        LoginCandidate::Oauth | LoginCandidate::ApiKey => Err(R::UncorroboratedSnapshot),
    })
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

/// Codex and Pi: the route from the item's own rows, so no latch is kept.
/// Rows carry no request time and sort by row key within an hour, so time
/// order is the hour buckets (emitted from a map keyed by bucket start): the
/// first route is the one known route of the earliest bucket that has one,
/// and two different known routes there are `signal_conflict`. Rows that
/// grow later can only add hours after it or a second route to it, so the
/// first route never becomes a different known route. Without buckets the
/// session rows stand in as one group.
fn rows_route(
    item: &SnapshotItem,
    classify: fn(&SnapshotModelUsage) -> Result<BillingRoute, UnknownRouteReason>,
    source: RouteSource,
) -> SessionBillingRoute {
    let billable = |rows: &[SnapshotModelUsage]| {
        rows.iter()
            .filter(|row| row.request_count > 0)
            .map(classify)
            .collect::<Vec<_>>()
    };
    let mut hours = item
        .usage_buckets
        .iter()
        .map(|bucket| billable(&bucket.model_usage))
        .collect::<Vec<_>>();
    if hours.is_empty() {
        hours.push(billable(&item.model_usage));
    }
    let known = |rows: &[Result<BillingRoute, UnknownRouteReason>]| {
        rows.iter()
            .filter_map(|row| row.as_ref().ok().copied())
            .collect::<BTreeSet<_>>()
    };
    let mut fact = SessionBillingRouteFact::unknown(UnknownRouteReason::MissingEvidence);
    match hours
        .iter()
        .map(|rows| known(rows))
        .find(|routes| !routes.is_empty())
    {
        Some(first) if first.len() == 1 => {
            fact.first_route = first.first().copied();
            fact.first_route_source = Some(source);
            fact.unknown_reason = None;
            fact.routes_seen = rows(item)
                .filter(|row| row.request_count > 0)
                .filter_map(|row| classify(row).ok())
                .collect();
        }
        Some(_) => fact.unknown_reason = Some(UnknownRouteReason::SignalConflict),
        None => {
            if let Some(reason) = hours.iter().flatten().find_map(|row| row.err()) {
                fact.unknown_reason = Some(reason);
            }
        }
    }
    fact.wire()
}

/// Inputs for one pass's route annotation.
#[derive(Debug, Clone, Copy)]
pub(crate) struct RouteContext {
    /// Also put the object on the wire (the receiver advertised the contract).
    pub(crate) emit: bool,
    /// Unix nanoseconds.
    pub(crate) process_started_ns: i64,
    /// The latest Claude Code default-login evaluation.
    pub(crate) claude_login: Option<ClaudeLogin>,
}

impl RouteContext {
    /// Observed live: ended strictly after this process started. A request
    /// ending at or before the start, or unstamped, is history.
    fn live(&self, ended_ns: Option<i64>) -> bool {
        ended_ns.is_some_and(|ended| ended > self.process_started_ns)
    }
}

/// Claude Code latches of this process, for one destination at a time.
#[derive(Debug, Default)]
pub(crate) struct RouteState {
    claude_login: Option<ClaudeLogin>,
    process_started_ns: Option<i64>,
    /// The destination `latches` belong to.
    destination: String,
    /// Sessions whose first own request this process saw live; empty while
    /// the producer is off.
    latches: BTreeMap<String, SessionBillingRouteFact>,
}

impl RouteState {
    fn process_started_ns(&mut self) -> i64 {
        *self.process_started_ns.get_or_insert_with(now_unix_nanos)
    }

    /// One pass's annotation against this state.
    fn annotate(
        &mut self,
        destination: &str,
        source: SnapshotSource,
        machine_id: &str,
        snapshots: &mut [SnapshotItem],
        contract: Option<&str>,
    ) {
        let context = RouteContext {
            emit: contract == Some(SESSION_BILLING_ROUTE_CONTRACT),
            process_started_ns: self.process_started_ns(),
            claude_login: self.claude_login,
        };
        // One destination at a time, as the source manifests: a machine that
        // moved never returns to the old binding, so its latches go.
        if self.destination != destination {
            self.latches.clear();
            self.destination = destination.to_string();
        }
        apply_session_billing_routes(
            &mut self.latches,
            destination,
            source,
            machine_id,
            snapshots,
            &context,
        );
    }
}

/// The published login after an evaluation read from `read_started_ns` to
/// `read_ended_ns`. An unchanged candidate extends the proven span; a changed
/// one starts a new span at the read's end. An evaluation that started before
/// the published one was last observed is ignored.
fn next_login(
    previous: Option<ClaudeLogin>,
    candidate: LoginCandidate,
    read_started_ns: i64,
    read_ended_ns: i64,
) -> ClaudeLogin {
    match previous {
        Some(previous) if read_started_ns < previous.observed_ns => previous,
        Some(previous) if previous.candidate == candidate => ClaudeLogin {
            observed_ns: read_started_ns,
            ..previous
        },
        _ => ClaudeLogin {
            candidate,
            changed_ns: read_ended_ns,
            observed_ns: read_started_ns,
        },
    }
}

process_state! {
    fn with_route_state: RouteState = RouteState {
        claude_login: None,
        process_started_ns: None,
        destination: String::new(),
        latches: BTreeMap::new(),
    }; clear_poison: true
}

/// Publish a Claude Code default-login evaluation whose inputs were read
/// from `read_started_ns` on. The first call also fixes the process start for
/// the live rule (a later start only makes more requests history).
pub(crate) fn publish_claude_login(candidate: LoginCandidate, read_started_ns: i64) {
    let read_ended_ns = now_unix_nanos();
    with_route_state(|state| {
        state.process_started_ns();
        state.claude_login = Some(next_login(
            state.claude_login,
            candidate,
            read_started_ns,
            read_ended_ns,
        ));
    });
}

/// The start stamp a login evaluation passes to [`publish_claude_login`];
/// `None` (no clock read) while the producer is off.
pub(crate) fn login_read_started() -> Option<i64> {
    PRODUCER_ENABLED.then(now_unix_nanos)
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

/// Annotate this pass's items and, when the receiver advertised `contract`,
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
        state.annotate(destination, source, machine_id, snapshots, contract);
    });
}

/// Annotate `snapshots`. Touches no money field, row, hash, upload decision
/// or persisted state. Only a Claude Code session whose first own request was
/// live gets a latch; a deferred first request leaves the item without the
/// object for this pass.
pub(crate) fn apply_session_billing_routes(
    latches: &mut BTreeMap<String, SessionBillingRouteFact>,
    destination: &str,
    source: SnapshotSource,
    machine_id: &str,
    snapshots: &mut [SnapshotItem],
    context: &RouteContext,
) {
    for item in snapshots {
        let wire = match source {
            SnapshotSource::ClaudeCode => {
                capture_claude_route_evidence(item);
                let key = route_key(destination, source, machine_id, &item.source_session_id);
                claude_route(latches, key, item, context)
            }
            SnapshotSource::Codex => Some(rows_route(
                item,
                classify_codex_row,
                RouteSource::CodexAuthSnapshot,
            )),
            SnapshotSource::Pi => Some(rows_route(
                item,
                classify_pi_row,
                RouteSource::PiProviderAuth,
            )),
        };
        if context.emit {
            item.session_billing_route = wire.map(Box::new);
        }
    }
}

/// One Claude Code item's route; `None` while the evaluation for its first
/// request waits for a status refresh.
fn claude_route(
    latches: &mut BTreeMap<String, SessionBillingRouteFact>,
    key: String,
    item: &SnapshotItem,
    context: &RouteContext,
) -> Option<SessionBillingRoute> {
    use UnknownRouteReason as R;
    let Some(evidence) = item
        .claude_route_evidence
        .as_deref()
        .filter(|evidence| evidence.billable)
    else {
        return Some(SessionBillingRouteFact::unknown(R::MissingEvidence).wire());
    };
    // A complete clock seen live, then the evaluator proven to span it.
    let classify = |request: &ClaudeRouteRequest| {
        if !(request.clock_complete
            && context.live(request.started_ns)
            && context.live(request.ended_ns))
        {
            return Some(Err(R::FirstRequestSnapshotMissing));
        }
        classify_claude_request(context.claude_login, *request, evidence.telemetry_account)
    };
    let later = || evidence.later.iter().filter_map(|r| classify(r)?.ok());
    if let Some(fact) = latches.get_mut(&key) {
        fact.routes_seen.extend(later());
        return Some(fact.wire());
    }
    let first = match evidence.first {
        Some(first) if !evidence.proof_invalid && context.live(evidence.first_line_ns) => first,
        _ => return Some(SessionBillingRouteFact::unknown(R::FirstRequestSnapshotMissing).wire()),
    };
    let route = match classify(&first)? {
        _ if evidence.third_party => Err(R::SignalConflict),
        result => result,
    };
    let fact = match route {
        Ok(route) => SessionBillingRouteFact {
            first_route: Some(route),
            first_route_source: Some(RouteSource::EvaluatorSnapshot),
            routes_seen: later().chain(std::iter::once(route)).collect(),
            unknown_reason: None,
        },
        Err(reason) => return Some(SessionBillingRouteFact::unknown(reason).wire()),
    };
    let wire = fact.wire();
    latches.insert(key, fact);
    Some(wire)
}

#[cfg(test)]
mod tests;
