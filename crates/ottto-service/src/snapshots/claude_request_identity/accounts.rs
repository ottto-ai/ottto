//! Request accounts: the bounded native marker runs that partition a
//! file's counted requests by account, their reconcile across a scan's
//! items, and the root accounts sessions retain or inherit.

use super::{
    classify_ref, organization_hash, request_occurrence_facts, spanless_first_sequence,
    wire_login_is_valid, AccountPartition, AccountRun, AuthorityKey, CarryCounts, IdentityRef,
    OrgMarker, OrgMarkers, Refusal, RequestAccounts, ScanEvidence, MAX_AUTHORITY_KEYS,
    TELEMETRY_LOGIN, TRANSCRIPT_ORG,
};
use crate::claude_local_otel::ClaudeIdentityDisposition;
use crate::snapshots::{
    snapshot_fingerprint, AccountSource, ScanIndex, SnapshotItem, SnapshotSource,
};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// The carry rule, within one transcript in native order: a gap (a request with no
/// telemetry row) takes the account the latest earlier request's own
/// telemetry named, marked `carried_forward`; gaps before the first such
/// request take it, marked `carried_backward`. Only own telemetry seeds, never
/// a fill (marker, start, bound, retained, root) or a copied request. A row
/// naming no valid account blocks the carry on both sides.
struct Carry<'o> {
    /// The normal read holds every request of this transcript.
    complete: bool,
    /// An own (non-copy) request was seen: later gaps carry or stay Unknown.
    seen_own: bool,
    /// Invalid telemetry prevents old markers/start/bindings from crossing it.
    blocked: bool,
    /// The latest own telemetry account, never a fill-derived key.
    seed: Option<(u64, Arc<AuthorityKey>)>,
    first: Option<Arc<AuthorityKey>>,
    /// Gaps before the first seed; the first `closed` were cut off by a block.
    /// 8 bytes per request, at most 512 KiB (native 65,536 cap).
    pending: Vec<&'o mut crate::snapshots::ClaudeTranscriptUsageOccurrence>,
    closed: usize,
    counts: CarryCounts,
}

impl Carry<'_> {
    fn new(complete: bool) -> Self {
        Self {
            complete,
            seen_own: false,
            blocked: false,
            seed: None,
            first: None,
            pending: Vec::new(),
            closed: 0,
            counts: CarryCounts::default(),
        }
    }

    /// The marked twin of an own key, sharing the item's key cap.
    fn marked(
        keys: &mut Vec<Arc<AuthorityKey>>,
        own: &AuthorityKey,
        source: AccountSource,
        over_cap: &mut bool,
    ) -> AccountPartition {
        let key = AuthorityKey {
            account_source: Some(source),
            ..own.clone()
        };
        if let Some(known) = keys.iter().find(|known| ***known == key) {
            return Some(Arc::clone(known));
        }
        if keys.len() >= MAX_AUTHORITY_KEYS {
            *over_cap = true;
            return None;
        }
        let key = Arc::new(key);
        keys.push(Arc::clone(&key));
        Some(key)
    }

    /// A request whose own telemetry named `own`: always a whole observed
    /// pair (telemetry org, or a login with no org at all), so it seeds.
    fn own(&mut self, sequence: u64, own: &Arc<AuthorityKey>, copy: bool) {
        if copy {
            return;
        }
        // Backward fill reaches only the first own request's account.
        let first = !self.seen_own;
        self.seen_own = true;
        let next = self.complete.then(|| Arc::clone(own));
        if next.is_some() {
            self.blocked = false;
        }
        self.seed = next.map(|next| {
            if first {
                self.first = Some(Arc::clone(&next));
            }
            (sequence, next)
        });
    }

    /// Own telemetry naming no valid account: no carry across it.
    fn block(&mut self, requests: u64) {
        self.counts.blocked_no_account |= requests > 0;
        self.blocked = true;
        self.seed = None;
        if !self.seen_own {
            self.closed = self.pending.len();
        }
    }

    /// The forward carry for a gap.
    fn forward(
        &mut self,
        gap: bool,
        keys: &mut Vec<Arc<AuthorityKey>>,
    ) -> Option<(u64, AccountPartition)> {
        let (position, own) = self.seed.as_ref().filter(|_| gap)?;
        // Only keys actually used by gaps consume the shared authority cap.
        Self::marked(
            keys,
            own,
            AccountSource::CarriedForward,
            &mut self.counts.keys_over_cap,
        )
        .map(|key| (*position, Some(key)))
    }

    /// Notes a request placed without own evidence; returns whether it
    /// waits for backward fill (a gap before any own request, still Unknown).
    fn placed(&mut self, gap: bool, account: &AccountPartition, requests: u64) -> bool {
        match account {
            // Before own evidence a non-gap keeps its (absent) fill.
            Some(_) => false,
            None if !self.seen_own && !gap => false,
            None if !self.seen_own && self.complete => true,
            None => {
                self.counts.no_seed |= requests > 0;
                false
            }
        }
    }

    /// Backward fill once the walk is done: the first seed's marked twin, or
    /// Unknown (noted) when there is none or a block cut the gap off.
    fn finish(
        mut self,
        keys: &mut Vec<Arc<AuthorityKey>>,
        mut place: impl FnMut(&mut crate::snapshots::ClaudeTranscriptUsageOccurrence, AccountPartition),
    ) -> CarryCounts {
        let backward = self
            .first
            .take()
            .filter(|_| self.pending.len() > self.closed)
            .and_then(|first| {
                Self::marked(
                    keys,
                    &first,
                    AccountSource::CarriedBackward,
                    &mut self.counts.keys_over_cap,
                )
            });
        for (index, occurrence) in self.pending.into_iter().enumerate() {
            let requests = occurrence.usage.request_count;
            match backward.clone().filter(|_| index >= self.closed) {
                Some(account) => place(occurrence, Some(account)),
                None => self.counts.no_seed |= requests > 0,
            }
        }
        self.counts
    }
}

/// One account policy for `e2`. Never use a later marker for an earlier request.
/// A conflict fills missing shares; trusted own/earlier org runs stay intact.
/// Subagents are assigned their root's starting account at page finalization.
/// From `trust_from` every valid org line governs (rule 8: the request's own
/// time); earlier requests keep the terminal trust rule.
pub(crate) fn request_accounts(
    markers: Option<&OrgMarkers>,
    bound: Option<&str>,
    first_sequence: Option<u64>,
    subagent: bool,
    excluded: &[u64],
    trust_from: Option<u64>,
) -> RequestAccounts {
    let bound = bound.filter(|hash| wire_login_is_valid(hash)).map(|login| {
        Arc::new(AuthorityKey {
            login: Some(login.to_owned()),
            org: None,
            basis: TELEMETRY_LOGIN,
            account_source: None,
        })
    });
    let mut accounts = RequestAccounts {
        starting: bound.clone(),
        fallback: bound.clone(),
        bound,
        subagent,
        trust_from,
        ..Default::default()
    };
    if subagent {
        return accounts;
    }
    let Some(markers) = markers else {
        // Unknown here is provisional until existing account evidence runs.
        return accounts;
    };
    let Some(first) = first_sequence else {
        return accounts;
    };
    // Only `e2` can exclude a request. Marker timestamps never decide identity.
    let own_marker = |marker: &&OrgMarker| excluded.binary_search(&marker.position).is_err();
    // Positions where one request carries two different orgs (R3-N2).
    let mut contradicted = Vec::new();
    // A refused org line still governing at `trust_from` starts a run there
    // with its org; a real line at `trust_from` needs none (no R3-N2).
    let mut refused: Option<&str> = None;
    for marker in markers.entries.iter().filter(own_marker) {
        if let Some(from) = trust_from.filter(|from| marker.position >= *from) {
            if let Some(org) = refused.take().filter(|_| marker.position > from) {
                push_org_run(&mut accounts, from, org, true);
            }
        }
        let Some(org) = marker.org.as_deref().filter(|_| {
            marker.terminal_trusted
                || trust_from.is_some_and(|from| marker.position >= from)
                || accounts
                    .runs
                    .iter()
                    .rev()
                    .find_map(|run| run.account.as_ref())
                    .map_or(true, |key| key.org.as_deref() == marker.org.as_deref())
        }) else {
            accounts.conflict = true;
            refused = marker.org.as_deref();
            if accounts
                .runs
                .last()
                .map_or(true, |run| run.position != marker.position)
            {
                accounts.runs.push(AccountRun {
                    position: marker.position,
                    account: None,
                    copied: None,
                    split: false,
                });
            }
            continue;
        };
        refused = None;
        if let Some(previous) = accounts.runs.last() {
            if previous.position == marker.position {
                if previous.account.as_ref().and_then(|key| key.org.as_deref()) != Some(org) {
                    accounts.conflict = true;
                    contradicted.push(marker.position);
                }
                continue;
            }
        }
        push_org_run(&mut accounts, marker.position, org, false);
    }
    if let Some((from, org)) = trust_from.zip(refused) {
        push_org_run(&mut accounts, from, org, true);
    }
    // Derive the first own request's start from the accepted own stream,
    // preserving the first observation of a conflicting same-position pair.
    if let Some(key) = accounts
        .runs
        .iter()
        .rev()
        .filter(|run| run.position <= first)
        .find_map(|run| run.account.as_ref())
    {
        accounts.starting = Some(key.clone());
    }
    accounts.fallback = accounts.starting.clone();
    // R3-N2 (QUOTA): a later request carrying two different orgs is never
    // guessed: it goes to the starting (or bound) account, counted as a
    // conflict above. A pair at the session start is the start itself.
    for run in &mut accounts.runs {
        if run.position > first && contradicted.contains(&run.position) {
            run.account = accounts.starting.clone();
        }
    }
    if accounts
        .runs
        .iter()
        .filter_map(|run| run.account.as_ref())
        .collect::<BTreeSet<_>>()
        .len()
        > MAX_AUTHORITY_KEYS
    {
        accounts.conflict = true;
    }
    accounts.mixed = accounts
        .runs
        .iter()
        .any(|run| run.account.is_some() && run.account != accounts.starting);
    // Keep bounded runs through native copy adjudication so the first
    // retained request can establish the real start even under a conflict.
    accounts
}

/// A run for `org` at `position`, sharing the start's or an earlier run's key.
fn push_org_run(accounts: &mut RequestAccounts, position: u64, org: &str, split: bool) {
    let key = accounts
        .starting
        .as_ref()
        .filter(|key| key.org.as_deref() == Some(org))
        .cloned()
        .or_else(|| {
            accounts.runs.iter().find_map(|run| {
                run.account
                    .as_ref()
                    .filter(|key| key.org.as_deref() == Some(org))
                    .cloned()
            })
        })
        .unwrap_or_else(|| {
            Arc::new(AuthorityKey {
                login: None,
                org: Some(org.to_owned()),
                basis: TRANSCRIPT_ORG,
                account_source: None,
            })
        });
    accounts.runs.push(AccountRun {
        position,
        account: Some(key),
        copied: None,
        split,
    });
}

impl RequestAccounts {
    pub(crate) fn account(&self, sequence: u64) -> AccountPartition {
        if self.unhealthy_no_fallback {
            return None;
        }
        if self.subagent {
            return self.starting.clone().or_else(|| {
                (!self.root_fallback_pending)
                    .then(|| self.fallback.clone())
                    .flatten()
            });
        }
        let end = self.runs.partition_point(|run| run.position <= sequence);
        self.runs[..end]
            .iter()
            .rev()
            .find_map(|run| run.account.clone())
            .or_else(|| self.starting.clone())
            .or_else(|| {
                (!self.root_fallback_pending)
                    .then(|| self.fallback.clone())
                    .flatten()
            })
    }
    pub(crate) fn observe(&mut self, sequence: u64, copied: bool) {
        let next = self.runs.partition_point(|run| run.copied.is_some());
        for run in self.runs[next..]
            .iter_mut()
            .take_while(|run| run.position <= sequence)
        {
            run.copied = Some((sequence, copied));
        }
        if !copied {
            self.first_retained.get_or_insert(sequence);
        }
    }
    /// The governing native marker run; `e2` uses its own skipped ranges to
    /// stage inherited usage until its copy decision is final.
    pub(crate) fn copied_marker_position(&self, sequence: u64) -> Option<u64> {
        let end = self.runs.partition_point(|run| run.position <= sequence);
        let runs = &self.runs[..end];
        // Keep every marker boundary, even a provisionally rejected flip:
        // removing its copied predecessor can make that marker authoritative.
        runs.iter()
            .rev()
            .find(|run| run.account.is_some())
            .filter(|run| matches!(run.copied, Some((_, true))))?;
        runs.last().map(|run| run.position)
    }

    /// The money owner has decided individual copies. Exclude only markers
    /// on still-removed/held requests; an emitted unproven prefix keeps its
    /// own markers. Build beside the original so its grains can be moved.
    pub(crate) fn after_copy_decision(
        &self,
        markers: Option<&OrgMarkers>,
        skipped: &[(u64, u64)],
        first_retained: Option<u64>,
    ) -> Option<Self> {
        if self.subagent {
            return None;
        }
        let excluded = self
            .runs
            .iter()
            .filter(|run| {
                let Some((response, true)) = run.copied else {
                    return false;
                };
                let at = skipped.partition_point(|(_, end)| *end <= response);
                skipped.get(at).is_some_and(|(start, _)| *start <= response)
            })
            .map(|run| run.position)
            .collect::<Vec<_>>();
        if excluded.is_empty() {
            return None;
        }
        let mut own = request_accounts(
            markers,
            self.bound.as_ref().and_then(|key| key.login.as_deref()),
            first_retained.or(self.first_retained),
            false,
            &excluded,
            self.trust_from,
        );
        own.first_retained = first_retained.or(self.first_retained);
        Some(own)
    }
}

/// Own exact telemetry uses the existing request classifier, with the same
/// standing as an own credential_org. Only missing evidence is filled: by a
/// marker or the `Carry` rule, else (before own evidence) the start/binding;
/// every such fill is counted.
/// A family whose strict sidecar read failed this page inherits nothing: its
/// requests stay Unknown.
pub(crate) fn reconcile_request_accounts(items: &mut [SnapshotItem], evidence: &ScanEvidence<'_>) {
    use crate::snapshots::claude_request_money::e2::{place_request_identity, IdentityCaller};
    for item in items {
        let Some(mut fold) = item.claude_money.take() else {
            continue;
        };
        let Some(mut accounts) = fold.accounts.take() else {
            item.claude_money = Some(fold);
            continue;
        };
        if accounts.reconciled {
            fold.accounts = Some(accounts);
            item.claude_money = Some(fold);
            continue;
        }
        let root = crate::snapshots::claude_snapshot_family_root_ref(item);
        if evidence.unhealthy_roots.contains(root) {
            // The classifier refuses every request here (IncompleteEvidence).
            // A retained, creator, start or earlier-request account is not
            // evidence for requests whose own proof could not be read: collapse
            // the partitions in place so tokens, costs, side calls and id-less
            // shares survive with no account. Durable bindings are untouched.
            fold.entity.repartition(None);
            accounts.unhealthy_no_fallback = true;
            // A discard keeps the trace-discard account hold: nothing to admit.
            accounts.unhealthy_cleared_account = (!evidence.trace_discarded_roots.contains(root))
                .then(|| crate::snapshots::exact_session_account_hash(item))
                .flatten();
            accounts.starting = None;
            accounts.fallback = None;
            accounts.reconciled = true;
            fold.accounts = Some(accounts);
            item.claude_money = Some(fold);
            // Emission carries the account owner's uniform row login to rows
            // that bypass final identity grouping (non-subscription or mixed
            // billing). That login came from this unreadable pair too.
            if crate::snapshots::set_claude_account_hash(item, None) {
                item.snapshot_fingerprint = snapshot_fingerprint(SnapshotSource::ClaudeCode, item);
            }
            continue;
        }
        let native = accounts.clone();
        // Existing account-owner qualification remains a fallback for a
        // markerless file, never an override of a request's own telemetry.
        if !accounts.subagent
            && accounts.starting.is_none()
            && !accounts.mixed
            && item.claude_org_markers.is_none()
            && item.claude_usage_request_ids.iter().all(|request| {
                !evidence.invalid_logins.contains(&(
                    crate::snapshots::claude_snapshot_family_root_ref(item),
                    request.as_str(),
                ))
            })
        {
            if let Some(login) = crate::snapshots::exact_session_account_hash(item) {
                let key = Some(Arc::new(AuthorityKey {
                    login: Some(login),
                    org: None,
                    basis: TELEMETRY_LOGIN,
                    account_source: None,
                }));
                accounts.starting = key.clone();
                accounts.fallback = key.clone();
                if accounts.bound.is_none() {
                    accounts.bound = key;
                }
            }
        }
        // Existing occurrence storage owns these requests. The temporary sort
        // is 16 bytes per resolved request, at most 1 MiB (native 65,536 cap).
        // Carry covers identified occurrences, not census cardinality.
        // Zero-usage responses have ids but no counted row; counts can also
        // include responses without a usable id. Proven copies no longer
        // count. Check before draining the occurrence map.
        let mut carry = Carry::new(
            item.claude_usage_occurrences
                .keys()
                .eq(item.claude_usage_request_ids.iter())
                && item
                    .claude_usage_occurrences
                    .values()
                    .filter(|occurrence| {
                        !fold.is_skipped(occurrence.sequence) && !occurrence.usage.is_zero()
                    })
                    .map(|occurrence| occurrence.usage.request_count)
                    .try_fold(0_u64, u64::checked_add)
                    .is_some_and(|requests| requests <= item.request_count),
        );
        let spanless_first = spanless_first_sequence(item, &fold);
        let mut occurrences = std::mem::take(&mut item.claude_usage_occurrences);
        let mut requests = occurrences.iter_mut().collect::<Vec<_>>();
        requests.sort_unstable_by_key(|(_, occurrence)| occurrence.sequence);
        let first_retained = requests
            .iter()
            .find(|(_, occurrence)| {
                !fold.is_skipped(occurrence.sequence) && !occurrence.usage.is_zero()
            })
            .map(|(_, occurrence)| occurrence.sequence);
        let mut keys: Vec<Arc<AuthorityKey>> = Vec::new();
        // Recompute local clocks at their final accounts. Id-less records do
        // not prove an exact request identity and cannot decide current login.
        for grain in fold.entity.grains.values_mut() {
            grain.last_own_at = None;
        }
        for (request, occurrence) in requests {
            if fold.is_skipped(occurrence.sequence) || occurrence.usage.is_zero() {
                continue;
            }
            let sequence = occurrence.sequence;
            let root = crate::snapshots::claude_snapshot_family_root_ref(item);
            let telemetry = evidence
                .requests
                .get(&(root, request.as_str()))
                .and_then(|row| *row);
            let identity = request_occurrence_facts(item, request, occurrence, spanless_first)
                .map(|facts| classify_ref(evidence, &facts));
            let copy = fold.unproven_copy(occurrence);
            // A gap has no telemetry row and no other stream's owner.
            let gap = !copy
                && !evidence.requests.contains_key(&(root, request.as_str()))
                && !matches!(
                    identity,
                    Some(IdentityRef::Refused(
                        Refusal::ForeignOwner | Refusal::ConflictingDuplicate
                    ))
                );
            let read = matches!(
                identity,
                Some(IdentityRef::Tagged(_) | IdentityRef::Missing)
            );
            let own = match identity {
                Some(IdentityRef::Tagged(key)) if telemetry.is_some() && key.login.is_some() => {
                    let found = keys.iter().find(|known| key.matches(known));
                    match found {
                        Some(known) => Some(Arc::clone(known)),
                        None if keys.len() < MAX_AUTHORITY_KEYS => {
                            let own = Arc::new(key.to_key());
                            keys.push(Arc::clone(&own));
                            Some(own)
                        }
                        None => {
                            // Preserve the verdict for the existing grouping
                            // cap allocator; valid overflow is not missing data.
                            fold.entity.identity_over_cap = true;
                            accounts.conflict = true;
                            None
                        }
                    }
                }
                _ => None,
            };
            let marker_end = native.runs.partition_point(|run| run.position <= sequence);
            let marker = native.runs[..marker_end]
                .iter()
                .rev()
                .find(|run| run.account.is_some());
            let own_marker = marker.filter(|run| run.position == sequence && !run.split);
            // Absence of a paired trace is not a contradiction of an own org.
            // Keep the existing strong-org guards; only genuinely conflicting
            // telemetry is disclosed, never used to relocate an own org run.
            let contradicted =
                matches!(evidence.requests.get(&(root, request.as_str())), Some(None))
                    || telemetry.is_some_and(|row| {
                        row.request_identity.as_ref().is_some_and(|identity| {
                            matches!(
                                identity.disposition,
                                ClaudeIdentityDisposition::Conflict
                                    | ClaudeIdentityDisposition::Invalid
                            ) || (identity.account.disposition
                                != ClaudeIdentityDisposition::Missing
                                && evidence.invalid_logins.contains(&(root, request.as_str())))
                                || match organization_hash(identity) {
                                    Err(()) => true,
                                    Ok(Some(org)) => own_marker
                                        .and_then(|run| run.account.as_ref())
                                        .and_then(|key| key.org.as_deref())
                                        .is_some_and(|own| own != org),
                                    Ok(None) => false,
                                }
                        })
                    });
            accounts.conflict |= contradicted;
            let preserve_org = contradicted && own_marker.is_some();
            let refused = contradicted && own.is_none() && own_marker.is_none();
            let mut backward = false;
            // Present but invalid/no-account telemetry blocks both directions,
            // including the contradictory/refused arm. Reuse valid_login's
            // normalized verdict, never guess from a marker or binding.
            let blocked = evidence.invalid_logins.contains(&(root, request.as_str()))
                || matches!(evidence.requests.get(&(root, request.as_str())), Some(None));
            if blocked {
                carry.block(occurrence.usage.request_count);
            }
            // The classifier's refusal for an owner the scope names but could
            // not read: no marker, carry, start or binding fills it.
            let unreadable_owner = matches!(
                identity,
                Some(IdentityRef::Refused(Refusal::IncompleteEvidence))
            ) && evidence.owner_unreadable(root, request.as_str());
            let account = if blocked || unreadable_owner {
                carry.counts.blocked_no_account |= unreadable_owner;
                None
            } else if preserve_org {
                own_marker.and_then(|run| run.account.clone())
            } else if let Some(own) = own {
                carry.own(sequence, &own, copy);
                let account = Some(own);
                // The first retained request establishes the actual start;
                // a durable binding only fills a request with no own evidence.
                if !accounts.subagent && first_retained == Some(sequence) {
                    accounts.starting = account.clone();
                    accounts.fallback = account.clone();
                }
                account
            } else if refused {
                accounts.conflict = true;
                accounts.fallback.clone().or_else(|| accounts.bound.clone())
            } else {
                let carried = carry.forward(gap, &mut keys);
                let account = match (marker, carried.as_ref()) {
                    _ if carry.blocked => None,
                    (Some(marker), Some((position, account))) if marker.position < *position => {
                        account.clone()
                    }
                    (Some(marker), _) => marker.account.clone(),
                    (_, Some((_, account))) => account.clone(),
                    // After own evidence only a carry or marker places a gap.
                    _ if carry.seen_own => None,
                    _ => accounts
                        .starting
                        .clone()
                        .or_else(|| accounts.fallback.clone())
                        .or_else(|| accounts.bound.clone()),
                };
                backward = !blocked && carry.placed(gap, &account, occurrence.usage.request_count);
                account
            };
            // Own evidence for the lent account itself ends the loan.
            if let std::collections::btree_map::Entry::Occupied(mut lent) =
                accounts.copied_marker_lent.entry(sequence)
            {
                if account.as_ref() == Some(&lent.get().lent) {
                    lent.remove();
                } else {
                    lent.get_mut().read = read;
                }
            }
            place_request_identity(
                &mut fold,
                occurrence,
                telemetry,
                native.account(sequence),
                account,
                IdentityCaller::Request,
            );
            if backward {
                carry.pending.push(occurrence);
            }
        }
        accounts.carried = carry.finish(&mut keys, |occurrence, account| {
            place_request_identity(
                &mut fold,
                occurrence,
                None,
                None,
                account,
                IdentityCaller::Carry,
            );
        });
        item.claude_usage_occurrences = occurrences;
        accounts.reconciled = true;
        fold.accounts = Some(accounts);
        item.claude_money = Some(fold);
    }
}

/// The account this page cleared from `item` for
/// a non-discard unhealthy read. If it was the bound owner's, main would have
/// uploaded the body, so it uploads Unknown now instead of being held.
pub(crate) fn unhealthy_cleared_account(item: &SnapshotItem) -> Option<&str> {
    item.claude_money
        .as_deref()?
        .accounts
        .as_deref()?
        .unhealthy_cleared_account
        .as_deref()
}

/// Read retained creator bindings using the same machine/session key as the
/// account owner. No transcript read, new index field, or current-login guess.
pub(crate) fn retain_root_accounts(items: &mut [SnapshotItem], index: &ScanIndex, machine: &str) {
    for item in items {
        if item
            .claude_money
            .as_deref()
            .and_then(|fold| fold.accounts.as_deref())
            .is_none()
        {
            continue;
        }
        let root = crate::snapshots::claude_snapshot_family_root_ref(item);
        let key = crate::snapshots::sha256_hex(&["session_owner:v1", machine, root]);
        let retained = index
            .session_account_bindings
            .get(&key)
            .filter(|binding| wire_login_is_valid(&binding.account_identifier_hash))
            .map(|binding| {
                Arc::new(AuthorityKey {
                    login: Some(binding.account_identifier_hash.clone()),
                    org: None,
                    basis: TELEMETRY_LOGIN,
                    account_source: None,
                })
            });
        let fold = item.claude_money.as_deref_mut().expect("checked fold");
        let accounts = fold.accounts.as_deref_mut().expect("checked accounts");
        if accounts.subagent {
            accounts.retained_root = retained;
        } else if retained.is_some() {
            // A native markerless file may not yet carry its persisted creator
            // binding. Fill only missing shares, never a later own-org run.
            if accounts.bound.is_none() {
                accounts.bound = retained.clone();
            }
            if accounts.starting.is_none() {
                accounts.starting = retained.clone();
                accounts.fallback = retained.clone();
                fold.entity.inherit_missing(retained);
            }
        }
    }
}

/// Root placement is fixed before summing path twins. A missing/Unknown root
/// stays Unknown; a subagent's own marker can never manufacture a root account.
pub(crate) fn inherit_root_accounts(items: &mut [SnapshotItem], settled: bool) {
    // Select the root's earliest native start, independently of page/map order.
    // Contradictory observations at the same start use the retained binding.
    struct Root {
        first: i128,
        starting: AccountPartition,
        bound: AccountPartition,
        conflict: bool,
        known: bool,
        // Kind of the original start evidence, retained through fallback.
        org_start: bool,
        start_conflict: bool,
        bound_conflict: bool,
    }
    let mut roots = BTreeMap::<String, Root>::new();
    for item in items.iter() {
        let Some(accounts) = item
            .claude_money
            .as_deref()
            .and_then(|fold| fold.accounts.as_deref())
        else {
            continue;
        };
        // An unhealthy family lends no start to its children or twins.
        if accounts.subagent || accounts.unhealthy_no_fallback {
            continue;
        }
        let first = item
            .source_started_at
            .as_deref()
            .and_then(crate::snapshots::rfc3339_unix_nanos)
            .unwrap_or(i128::MAX);
        let candidate = Root {
            first,
            starting: accounts.starting.clone(),
            bound: accounts.bound.clone(),
            conflict: accounts.conflict,
            known: accounts.starting.is_some(),
            org_start: accounts
                .starting
                .as_ref()
                .is_some_and(|key| key.org.is_some()),
            start_conflict: false,
            bound_conflict: false,
        };
        match roots.entry(item.source_session_id.clone()) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(candidate);
            }
            std::collections::btree_map::Entry::Occupied(mut entry) => {
                let root = entry.get_mut();
                let any_conflict = root.conflict || candidate.conflict;
                if candidate.known && (!root.known || first < root.first) {
                    *root = candidate;
                } else if first == root.first {
                    if root.bound.is_some()
                        && candidate.bound.is_some()
                        && root.bound != candidate.bound
                    {
                        root.bound_conflict = true;
                    }
                    if root.bound_conflict {
                        root.bound = None;
                    } else if root.bound.is_none() {
                        root.bound = candidate.bound.clone();
                    }
                    if root.known && candidate.known && root.starting != candidate.starting {
                        if root.org_start != candidate.org_start {
                            // Different kinds do not contradict each other.
                            if candidate.org_start {
                                root.starting = candidate.starting.clone();
                                root.org_start = true;
                                root.start_conflict = false;
                            }
                        } else {
                            root.start_conflict = true;
                            root.conflict = true;
                        }
                    }
                    // A fallback is only as strong as the current binding.
                    // A later contradictory binding invalidates it too.
                    if root.start_conflict {
                        root.starting = root.bound.clone();
                    }
                }
                root.conflict |= any_conflict;
            }
        }
    }
    for item in items {
        let root = crate::snapshots::claude_snapshot_family_root_ref(item).to_owned();
        let Some(fold) = item.claude_money.as_deref_mut() else {
            continue;
        };
        let Some(accounts) = fold.accounts.as_deref_mut() else {
            continue;
        };
        // Reconciliation's new Unknown decisions are final for this file.
        // A blanket root/start fill must not restore an invalid account or
        // turn an explicitly seedless gap into unmarked per-request proof.
        if accounts.unhealthy_no_fallback
            || (accounts.reconciled
                && (accounts.carried.blocked_no_account || accounts.carried.no_seed))
        {
            continue;
        }
        if accounts.subagent {
            accounts.starting = match roots.get(&root) {
                Some(root) => root.starting.clone(),
                None => accounts.retained_root.clone(),
            };
            accounts.fallback = accounts.starting.clone();
            if settled || accounts.reconciled {
                // Own request logins survive; only missing shares inherit the fallback account.
                fold.entity.inherit_missing(accounts.fallback.clone());
            } else {
                fold.entity.repartition(accounts.fallback.clone());
            }
        } else if let Some(root) = roots.get(&root) {
            accounts.fallback = root.starting.clone();
            // The side-call pass lends the root start without remapping
            // this file's native grains. Keep account(sequence) aligned with
            // those grains until the final missing-share fill is applied.
            accounts.root_fallback_pending = !settled && accounts.starting.is_none();
            if root.conflict {
                accounts.conflict = true;
            }
            if settled {
                // Markerless twins inherit the resolved session start, not a
                // provisional Unknown partition from their native file.
                fold.entity.inherit_missing(accounts.fallback.clone());
            }
        }
    }
}
