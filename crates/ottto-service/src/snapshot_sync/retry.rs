//! In-place resend budgets and their test clock share one source page.
use super::UploadFailureDiagnostics;
use super::UploadShed;
use std::time::{Duration, Instant};

use super::continuation;
#[cfg(test)]
use super::tests;
use super::BTreeMap;
use super::CadenceConfig;
use super::Digest;
use super::Mutex;
use super::OffsetDateTime;
use super::OnceLock;
use super::PlatformGates;
use super::Result;
use super::Rfc3339;
use super::Sha256;
use super::SnapshotSource;
use super::SourceCadence;
use super::SNAPSHOT_SYNC_INTERVAL;

// A short, explicitly transient batch failure is resent in place rather than
// abandoning the page and marking the bounded sweep unsettled: a 429/503 whose
// Retry-After is at most 5 s (cursor allocation and shared-lock timeouts send
// 1 s) or a fast 500/502. The wait holds the sync lock, so each source page
// gets at most two resends and 10 s of waiting, shared by its cache-head
// bootstrap stages and its main upload. A failure that took 15 s or longer is
// overload and is never resent; the identity deferral, recognized by its code,
// keeps its backoff whatever its Retry-After.
pub(super) const SNAPSHOT_INPLACE_RETRY_LIMIT: usize = 2;

const SNAPSHOT_INPLACE_RETRY_MAX_WAIT: Duration = Duration::from_secs(5);

pub(super) const SNAPSHOT_INPLACE_RETRY_WAIT_BUDGET: Duration = Duration::from_secs(10);

const SNAPSHOT_INPLACE_RETRY_FAST_FAILURE: Duration = Duration::from_secs(15);

const SNAPSHOT_INPLACE_RETRY_SERVER_ERROR_WAIT: Duration = Duration::from_secs(2);

const SNAPSHOT_INPLACE_RETRY_MIN_WAIT: Duration = Duration::from_millis(250);

/// Hard ceiling on how long a source may go unscanned on cadence grounds alone.
///
/// The cost tiers are allowed to stretch a quiet source out to here and no
/// further: neither the filesystem watcher nor a server directive can suppress
/// a scan, because a watcher that silently stops delivering events would
/// otherwise stop collection with every health signal green.
pub(super) const MAX_CYCLE_INTERVAL: Duration = Duration::from_secs(30 * 60);

/// How long the loop is willing to sit inside one wait before re-deciding.
/// Filesystem events shorten a wait to the next tier boundary; they never
/// shorten it below the floor, which is what makes a 2-second debounce incapable
/// of producing a per-event upload.
pub(super) const CADENCE_WAIT_SLICE: Duration = Duration::from_secs(30);

/// Per-source adaptive cadence state.
static SOURCE_CADENCES: OnceLock<Mutex<BTreeMap<&'static str, SourceCadence>>> = OnceLock::new();

pub(super) fn source_cadences() -> &'static Mutex<BTreeMap<&'static str, SourceCadence>> {
    SOURCE_CADENCES.get_or_init(|| Mutex::new(BTreeMap::new()))
}

pub(super) fn with_source_cadence<T>(
    source: SnapshotSource,
    apply: impl FnOnce(&mut SourceCadence) -> T,
) -> Option<T> {
    let power = continuation::MacPlatformSignals::default().power();
    with_source_cadence_state(source, |cadence| {
        cadence.set_power_stretch(continuation::session_power_stretch(power));
        apply(cadence)
    })
}

// Collection observations must not refresh power inputs or change scheduling.
pub(super) fn with_source_cadence_state<T>(
    source: SnapshotSource,
    apply: impl FnOnce(&mut SourceCadence) -> T,
) -> Option<T> {
    let mut cadences = source_cadences().lock().ok()?;
    let cadence = cadences
        .entry(source.api_slug())
        .or_insert_with(|| SourceCadence::new(CadenceConfig::cost_first(SNAPSHOT_SYNC_INTERVAL)));
    Some(apply(cadence))
}

pub(crate) fn start_collection_health(source: SnapshotSource) {
    // A small-route shed may predate the first offered scan of this run.
    let deadline = source_upload_deadlines()
        .lock()
        .ok()
        .and_then(|deadlines| deadlines.get(source.api_slug()).copied());
    with_source_cadence_state(source, |cadence| {
        let pulse = cadence
            .collection
            .get_or_insert_with(crate::collection_health::Pulse::start);
        if let Some(deadline) = deadline {
            pulse.defer(deadline);
        }
    });
}

pub(crate) fn reset_collection_health(source: SnapshotSource) {
    let Ok(mut cadences) = source_cadences().lock() else {
        return;
    };
    if let Some(cadence) = cadences.get_mut(source.api_slug()) {
        cadence.collection = None;
    }
}

pub(crate) fn collection_health(
    source: SnapshotSource,
    applicable: bool,
    wall: &str,
) -> Option<ottto_protocol::SourceCollectionHealth> {
    let mut cadences = source_cadences().lock().ok()?;
    let cadence = cadences.get_mut(source.api_slug())?;
    if !applicable {
        cadence.collection = None;
    }
    cadence
        .collection
        .as_ref()
        .map(|pulse| pulse.project(cadence.ordinary_interval(), wall))
}

/// The negotiated wait for one source: `clamp(directive, floor, ceiling)`.
///
/// The tier arithmetic — including the server's requested minimum interval — lives
/// in [`SourceCadence`], anchored to the last scan. That anchoring is load-bearing:
/// a *relative* directive re-read on every cycle would push its own deadline
/// forward forever and the scan would never run again, silently, on a healthy
/// machine. All that remains here is the ceiling, which bounds a directive that
/// would otherwise silence a source for a day.
pub(super) fn negotiated_wait(cadence: &SourceCadence, now: Instant) -> Duration {
    cadence
        .next_scan_after(now)
        .clamp(Duration::ZERO, MAX_CYCLE_INTERVAL)
}

/// When `source`'s paced scan may run; `None` without one or under backoff.
pub(super) fn source_paced_due(source: SnapshotSource) -> Option<Instant> {
    source_upload_backoff_remaining(source)
        .is_none()
        .then(|| with_source_cadence(source, |cadence| cadence.paced_scan_due()).flatten())
        .flatten()
}

/// The earliest paced scan across sources, for the cycle's wake time.
pub(super) fn paced_scan_due() -> Option<Instant> {
    [
        SnapshotSource::ClaudeCode,
        SnapshotSource::Codex,
        SnapshotSource::Pi,
    ]
    .into_iter()
    .filter_map(|source| {
        let paced = with_source_cadence(source, |cadence| cadence.paced_scan_due()).flatten()?;
        let deadlines = source_upload_deadlines().lock().ok()?;
        Some(
            deadlines
                .get(source.api_slug())
                .map_or(paced, |due| paced.max(*due)),
        )
    })
    .min()
}

pub(super) fn source_cadence_wait(source: SnapshotSource) -> Option<Duration> {
    let now = crate::scan_clock::now();
    let wait = with_source_cadence(source, |cadence| negotiated_wait(cadence, now))
        .unwrap_or(Duration::ZERO);
    (!wait.is_zero()).then_some(wait)
}

/// Fold the server's `recommended_scan_after` into the source's cadence as a
/// minimum interval between scans.
///
/// An unparsable value leaves the previous directive alone rather than inventing
/// one, and a value in the past means "no minimum", not a negative wait.
pub(super) fn record_server_scan_directive(source: SnapshotSource, recommended_scan_after: &str) {
    let Ok(recommended) = OffsetDateTime::parse(recommended_scan_after, &Rfc3339) else {
        return;
    };
    let delay = recommended - OffsetDateTime::now_utc();
    let requested = if delay.is_negative() {
        Duration::ZERO
    } else {
        Duration::from_secs(delay.whole_seconds().unsigned_abs()).min(MAX_CYCLE_INTERVAL)
    };
    with_source_cadence(source, |cadence| {
        cadence.set_server_min_interval(Some(requested))
    });
}

#[cfg(test)]
pub(super) fn clear_cadence_state_for_test() {
    if let Ok(mut cadences) = source_cadences().lock() {
        cadences.clear();
    }
}

/// Base of the local backoff ladder for missing headers and repeated sheds.
pub(super) const SHED_BACKOFF_BASE: Duration = Duration::from_secs(30);

/// Uniform random in `[0, span]`, from the OS entropy source already used for
/// token material. Jitter that is not random is not jitter.
pub(super) fn uniform_duration(span: Duration) -> Duration {
    #[cfg(test)]
    if let Some(sample) =
        tests::permanent_finish_pipeline_tests::once_credit_oracle_tests::backoff_sample_for_test(
            span,
        )
    {
        return sample;
    }
    if span.is_zero() {
        return Duration::ZERO;
    }
    let mut bytes = [0u8; 8];
    if getrandom::fill(&mut bytes).is_err() {
        // Entropy is not available. Half the span is a poor sample but a correct
        // wait; refusing to wait would be the actual bug.
        return span / 2;
    }
    let fraction = u64::from_le_bytes(bytes) as f64 / u64::MAX as f64;
    Duration::from_secs_f64(span.as_secs_f64() * fraction)
}

/// The wait after a shed request.
///
/// With a server-supplied `Retry-After`, wait `Retry-After × uniform(1.0, 1.2)`.
/// The jitter is one-sided on purpose: the whole fleet was told the same number,
/// so obeying it exactly re-synchronises every machine onto the same instant —
/// which is how a shed becomes a thundering herd — but jittering *below* it
/// returns before the server said it would be ready, which is the overload the
/// shed was protecting against. Never early, sometimes late.
///
/// Without a `Retry-After`, full jitter over an exponential ladder: `random(0,
/// min(cap, base·2^n))`, which is the form that actually decorrelates retries,
/// not the "exponential plus a little noise" form.
///
/// The result is capped like a parsed `Retry-After` is, so the upper jitter
/// cannot push a wait past the longest silence the freshness promise tolerates.
pub(crate) fn shed_backoff(retry_after: Option<Duration>) -> Duration {
    match retry_after {
        Some(retry_after) => (retry_after + uniform_duration(retry_after.mul_f64(0.2)))
            .min(crate::snapshot_client::MAX_HONOURED_RETRY_AFTER),
        None => full_jitter_backoff(0),
    }
}

/// `random(0, min(cap, base·2^attempt))` — full jitter, capped.
pub(crate) fn full_jitter_backoff(attempt: u32) -> Duration {
    let ceiling = SHED_BACKOFF_BASE
        .saturating_mul(1u32 << attempt.min(6))
        .min(crate::snapshot_client::MAX_HONOURED_RETRY_AFTER);
    uniform_duration(ceiling)
}

/// A deterministic per-machine offset inside `interval`.
///
/// Cycle phase is otherwise set by install or restart time, so any fleet-wide
/// event — a deploy, a shed, a network partition healing — re-aligns every
/// machine onto the same tick and keeps them aligned. The offset is derived from
/// the client id so it is stable across restarts (a random offset would
/// re-scatter on every launch, which is worse for the freshness promise than
/// being predictable).
pub(super) fn cadence_phase_offset(client_id: &str, interval: Duration) -> Duration {
    let seconds = interval.as_secs();
    if seconds == 0 {
        return Duration::ZERO;
    }
    let mut digest = Sha256::new();
    digest.update(b"ottto.cadence.phase:v1");
    digest.update(client_id.as_bytes());
    let hash = digest.finalize();
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&hash[..8]);
    Duration::from_secs(u64::from_be_bytes(bytes) % seconds)
}

/// Consecutive sheds per source, so persistent refusal climbs the ladder.
///
/// Without it every shed draws from `random(0, 30s)`, which the five-minute cycle
/// has already outlived by the next tick — a ladder that never leaves its first
/// rung is not backoff, it is a rounding error on the normal cadence. Reset by any
/// completed upload.
static SOURCE_SHED_STREAKS: OnceLock<Mutex<BTreeMap<&'static str, u32>>> = OnceLock::new();

pub(super) fn source_shed_streaks() -> &'static Mutex<BTreeMap<&'static str, u32>> {
    SOURCE_SHED_STREAKS.get_or_init(|| Mutex::new(BTreeMap::new()))
}

/// Count this shed and return the wait to honour.
pub(super) fn note_shed_and_backoff(
    source: SnapshotSource,
    retry_after: Option<Duration>,
) -> Duration {
    let attempt = match source_shed_streaks().lock() {
        Ok(mut streaks) => {
            let streak = streaks.entry(source.api_slug()).or_insert(0);
            let attempt = *streak;
            *streak = streak.saturating_add(1);
            attempt
        }
        Err(_) => 0,
    };
    match retry_after {
        // The server's time is always the floor; repeated sheds also draw
        // from the existing ladder to ease sustained refusal.
        Some(retry_after) if attempt > 0 => {
            shed_backoff(Some(retry_after)).max(full_jitter_backoff(attempt))
        }
        Some(retry_after) => shed_backoff(Some(retry_after)),
        None => full_jitter_backoff(attempt),
    }
}

pub(super) fn clear_shed_streak(source: SnapshotSource) {
    if let Ok(mut streaks) = source_shed_streaks().lock() {
        streaks.remove(source.api_slug());
    }
}

/// Per-source "do not upload before" deadlines, set by an honoured shed.
static SOURCE_UPLOAD_DEADLINES: OnceLock<Mutex<BTreeMap<&'static str, Instant>>> = OnceLock::new();

pub(super) fn source_upload_deadlines() -> &'static Mutex<BTreeMap<&'static str, Instant>> {
    SOURCE_UPLOAD_DEADLINES.get_or_init(|| Mutex::new(BTreeMap::new()))
}

pub(super) fn defer_source_uploads(source: SnapshotSource, retry_after: Duration) {
    let deadline = source_upload_deadlines().lock().ok().map(|mut deadlines| {
        let deadline = crate::scan_clock::now() + retry_after;
        *deadlines
            .entry(source.api_slug())
            .and_modify(|existing| *existing = (*existing).max(deadline))
            .or_insert(deadline)
    });
    // Release the deadline lock before the collector lock. All shed routes latch here.
    if let Some(deadline) = deadline {
        with_source_cadence_state(source, |cadence| {
            if let Some(pulse) = cadence.collection.as_mut() {
                pulse.defer(deadline);
            }
        });
    }
}

/// Small-route errors keep their typed diagnostics while sharing source backoff.
/// Terminal reports and heartbeats still send during an existing batch backoff.
pub(crate) fn small_source_upload<T>(
    source: SnapshotSource,
    send: impl FnOnce() -> Result<T>,
) -> Result<T> {
    send().inspect_err(|error| {
        if let Some(shed) = error.downcast_ref::<UploadShed>() {
            defer_source_uploads(source, note_shed_and_backoff(source, shed.retry_after));
        }
    })
}

/// Remaining backoff for `source`, or `None` when it may upload now.
pub(super) fn source_upload_backoff_remaining(source: SnapshotSource) -> Option<Duration> {
    let mut deadlines = source_upload_deadlines().lock().ok()?;
    let deadline = *deadlines.get(source.api_slug())?;
    let now = crate::scan_clock::now();
    if deadline <= now {
        deadlines.remove(source.api_slug());
        return None;
    }
    Some(deadline - now)
}

#[cfg(test)]
pub(super) fn clear_source_upload_deadlines_for_test() {
    if let Ok(mut deadlines) = source_upload_deadlines().lock() {
        deadlines.clear();
    }
    if let Ok(mut streaks) = source_shed_streaks().lock() {
        streaks.clear();
    }
}
/// The wait before resending a failed batch in place, with the HTTP status
/// that earned it, or `None` when the failure keeps its existing path. The
/// wait is never earlier than the server's own `Retry-After`.
fn transient_inplace_retry_wait(error: &anyhow::Error) -> Option<(u16, Duration)> {
    let (status, base) = if let Some(shed) = error.downcast_ref::<UploadShed>() {
        // The identity deferral waits on the identity, not on this request:
        // excluded by its code before any admission, even with a short
        // Retry-After.
        if shed.is_original_identity_unavailable() {
            return None;
        }
        // No Retry-After keeps the jittered ladder; a long one is not worth
        // holding the sync lock for.
        let retry_after = shed
            .retry_after
            .filter(|wait| *wait <= SNAPSHOT_INPLACE_RETRY_MAX_WAIT)?;
        (shed.status, retry_after)
    } else {
        let status = error
            .downcast_ref::<UploadFailureDiagnostics>()?
            .transient_batch_status()?;
        (status, SNAPSHOT_INPLACE_RETRY_SERVER_ERROR_WAIT)
    };
    let base = base.max(SNAPSHOT_INPLACE_RETRY_MIN_WAIT);
    let wait = (base + uniform_duration(base.mul_f64(0.2))).min(SNAPSHOT_INPLACE_RETRY_MAX_WAIT);
    Some((status, wait))
}

/// In-place resends spent by one source page: every batch of its cache-head
/// bootstrap stages and of its main upload draws on the same budget.
#[derive(Default)]
pub(super) struct InplaceRetryBudget {
    pub(super) resends: usize,
    pub(super) waited: Duration,
}

impl InplaceRetryBudget {
    pub(super) fn admit(
        &self,
        error: &anyhow::Error,
        failed_after: Duration,
    ) -> Option<(u16, Duration)> {
        if self.resends >= SNAPSHOT_INPLACE_RETRY_LIMIT
            || failed_after >= SNAPSHOT_INPLACE_RETRY_FAST_FAILURE
        {
            return None;
        }
        transient_inplace_retry_wait(error)
            .filter(|(_, wait)| self.waited + *wait <= SNAPSHOT_INPLACE_RETRY_WAIT_BUDGET)
    }
}

pub(super) fn inplace_retry_failed_after(started: Instant) -> Duration {
    #[cfg(test)]
    if let Some(failed_after) = INPLACE_RETRY_TEST_CLOCK
        .with(|clock| clock.borrow().as_ref().and_then(|clock| clock.failed_after))
    {
        return failed_after;
    }
    started.elapsed()
}

pub(super) fn inplace_retry_sleep(wait: Duration) {
    #[cfg(test)]
    if INPLACE_RETRY_TEST_CLOCK.with(|clock| match clock.borrow_mut().as_mut() {
        Some(clock) => {
            clock.waits.push(wait);
            true
        }
        None => false,
    }) {
        return;
    }
    std::thread::sleep(wait);
}

/// Test-only stand-in for the in-place resend clock: it records every wait
/// instead of sleeping and may override how long a failed POST took.
#[cfg(test)]
struct InplaceRetryTestClock {
    failed_after: Option<Duration>,
    waits: Vec<Duration>,
}

#[cfg(test)]
thread_local! {
    static INPLACE_RETRY_TEST_CLOCK: std::cell::RefCell<Option<InplaceRetryTestClock>> =
        const { std::cell::RefCell::new(None) };
}

/// Run `body` with this thread's in-place resend clock replaced. Returns the
/// result and every wait the uploader asked for, in order.
#[cfg(test)]
pub(super) fn with_inplace_retry_test_clock<R>(
    failed_after: Option<Duration>,
    body: impl FnOnce() -> R,
) -> (R, Vec<Duration>) {
    INPLACE_RETRY_TEST_CLOCK.with(|clock| {
        *clock.borrow_mut() = Some(InplaceRetryTestClock {
            failed_after,
            waits: Vec::new(),
        });
    });
    let result = body();
    let waits = INPLACE_RETRY_TEST_CLOCK
        .with(|clock| clock.borrow_mut().take())
        .map(|clock| clock.waits)
        .unwrap_or_default();
    (result, waits)
}
