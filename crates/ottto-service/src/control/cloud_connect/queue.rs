//! The in-memory sign queue between the service and the Mac app: at most four live requests, each
//! taken by one verified signer connection, and the app's answer handed back to the caller that
//! queued it. Nothing here is persisted; a restart drops every request.

use serde::Serialize;
use std::collections::VecDeque;
use std::sync::Condvar;
use std::sync::Mutex;
use std::sync::MutexGuard;
use std::time::Duration;
use std::time::Instant;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

/// Requests the app has not answered yet, across every attempt.
pub const MAX_LIVE_SIGN_REQUESTS: usize = 4;

/// A queued request wakes the app unless a hello arrived this recently.
const HELLO_FRESH_FOR: Duration = Duration::from_secs(3);

/// An answered or expired request stays this long past its expiry for its caller to collect.
const KEEP_AFTER_EXPIRY_SECONDS: i64 = 60;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignKind {
    /// A silent device-key signature over a server challenge.
    DeviceProof,
    /// The user's Touch ID approval of `approval_id` for `attempt_id`.
    Approval {
        attempt_id: String,
        approval_id: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignOutcome {
    /// A DER P-256 signature over the request's payload bytes.
    Signed(Vec<u8>),
    Declined,
    BiometricUnavailable,
    AppUnavailable,
    /// Expired before the app answered, or no longer known.
    Expired,
    /// A newer approval for the same attempt replaced it.
    Superseded,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignQueueError {
    /// No signer channel on this Mac.
    SignerUnavailable,
    /// Already four live requests.
    Full,
    /// The expiry is not in the future.
    AlreadyExpired,
    /// Too many distinct native approvals were offered in the last minute.
    ApprovalRateLimited,
}

/// A request handed to a signer connection by `cloud_sign_poll`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(super) struct PolledSignRequest {
    pub(super) request_id: String,
    pub(super) kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) attempt_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) approval_id: Option<String>,
    pub(super) payload_b64: String,
    pub(super) expires_at: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum AnswerRefused {
    /// Unknown, answered, expired, superseded, or taken by another connection.
    NotLive,
}

/// What `enqueue` did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Queued {
    pub(super) request_id: String,
    /// No signer connection said hello in the last few seconds.
    pub(super) wake_app: bool,
}

#[derive(Default)]
pub struct SignQueue {
    state: Mutex<QueueState>,
    answered: Condvar,
}

#[derive(Default)]
struct QueueState {
    next_id: u64,
    requests: Vec<QueuedRequest>,
    last_hello: Option<Instant>,
    approval_offers: VecDeque<Instant>,
}

struct QueuedRequest {
    id: String,
    kind: SignKind,
    payload: Vec<u8>,
    expires_at: i64,
    taken_by: Option<u64>,
    outcome: Option<SignOutcome>,
}

impl SignQueue {
    fn lock(&self) -> MutexGuard<'_, QueueState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Queues `payload` for the app to sign until `expires_at` (Unix seconds). One request per
    /// approval id: queuing the same approval again returns the live request, and a new approval
    /// for the same attempt supersedes the old one.
    pub(super) fn enqueue(
        &self,
        kind: SignKind,
        payload: Vec<u8>,
        expires_at: i64,
    ) -> Result<Queued, SignQueueError> {
        let now = unix_now();
        let mut state = self.lock();
        state.settle(now);
        if let SignKind::Approval {
            attempt_id,
            approval_id,
        } = &kind
        {
            if let Some(live) = state.requests.iter().find(|request| {
                matches!(&request.kind, SignKind::Approval { approval_id: live, .. } if live == approval_id)
            }) {
                return Ok(Queued {
                    request_id: live.id.clone(),
                    wake_app: false,
                });
            }
            for request in state.requests.iter_mut().filter(|request| {
                request.outcome.is_none()
                    && matches!(&request.kind, SignKind::Approval { attempt_id: live, .. } if live == attempt_id)
            }) {
                request.outcome = Some(SignOutcome::Superseded);
            }
            self.answered.notify_all();
        }
        if expires_at <= now {
            return Err(SignQueueError::AlreadyExpired);
        }
        if state
            .requests
            .iter()
            .filter(|request| request.outcome.is_none())
            .count()
            >= MAX_LIVE_SIGN_REQUESTS
        {
            return Err(SignQueueError::Full);
        }
        if matches!(kind, SignKind::Approval { .. }) {
            state
                .approval_offers
                .retain(|offer| offer.elapsed() < Duration::from_secs(60));
            if state.approval_offers.len() >= MAX_LIVE_SIGN_REQUESTS {
                return Err(SignQueueError::ApprovalRateLimited);
            }
            state.approval_offers.push_back(Instant::now());
        }
        state.next_id += 1;
        let request_id = format!("sign_{}", state.next_id);
        state.requests.push(QueuedRequest {
            id: request_id.clone(),
            kind,
            payload,
            expires_at,
            taken_by: None,
            outcome: None,
        });
        let wake_app = state
            .last_hello
            .is_none_or(|hello| hello.elapsed() >= HELLO_FRESH_FOR);
        Ok(Queued {
            request_id,
            wake_app,
        })
    }

    /// Waits up to `timeout` for the app's answer and takes it. `None` when the request is still
    /// live at the timeout; it stays queued until the caller cancels it or it expires.
    pub fn wait(&self, request_id: &str, timeout: Duration) -> Option<SignOutcome> {
        let deadline = Instant::now() + timeout;
        let mut state = self.lock();
        loop {
            let now = unix_now();
            state.settle(now);
            let Some(index) = state
                .requests
                .iter()
                .position(|request| request.id == request_id)
            else {
                return Some(SignOutcome::Expired);
            };
            if state.requests[index].outcome.is_some() {
                return state.requests.remove(index).outcome;
            }
            let until_expiry = Duration::from_secs(
                u64::try_from(state.requests[index].expires_at - now).unwrap_or(0),
            );
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return None;
            }
            state = self
                .answered
                .wait_timeout(
                    state,
                    left.min(until_expiry.max(Duration::from_millis(100))),
                )
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .0;
        }
    }

    /// Retains a native answer for readback and identical R5 retries.
    pub(super) fn approval_outcome(&self, request_id: &str) -> Option<SignOutcome> {
        let state = self.lock();
        state
            .requests
            .iter()
            .find(|request| request.id == request_id)?
            .outcome
            .clone()
    }

    pub(super) fn cancel_attempt(&self, attempt_id: &str) {
        self.lock().requests.retain(|request| {
            !matches!(&request.kind, SignKind::Approval { attempt_id: id, .. } if id == attempt_id)
        });
    }

    /// Drops a request its caller no longer waits for.
    pub fn cancel(&self, request_id: &str) {
        self.lock()
            .requests
            .retain(|request| request.id != request_id);
    }

    /// A verified hello on a signer connection: the app's loop is running.
    pub(super) fn record_hello(&self) {
        self.lock().last_hello = Some(Instant::now());
    }

    /// Hands every live request no other connection holds to `connection`.
    pub(super) fn poll(&self, connection: u64) -> Vec<PolledSignRequest> {
        let mut state = self.lock();
        state.settle(unix_now());
        state
            .requests
            .iter_mut()
            .filter(|request| {
                request.outcome.is_none()
                    && request.taken_by.is_none_or(|taken| taken == connection)
            })
            .map(|request| {
                request.taken_by = Some(connection);
                let (kind, attempt_id, approval_id) = match &request.kind {
                    SignKind::DeviceProof => ("device_proof", None, None),
                    SignKind::Approval {
                        attempt_id,
                        approval_id,
                    } => (
                        "approval",
                        Some(attempt_id.clone()),
                        Some(approval_id.clone()),
                    ),
                };
                PolledSignRequest {
                    request_id: request.id.clone(),
                    kind,
                    attempt_id,
                    approval_id,
                    payload_b64: super::wire::encode_base64url(&request.payload),
                    expires_at: request.expires_at,
                }
            })
            .collect()
    }

    /// Records the app's answer: only for a live request the same connection polled.
    pub(super) fn answer(
        &self,
        connection: u64,
        request_id: &str,
        outcome: SignOutcome,
    ) -> Result<(), AnswerRefused> {
        let mut state = self.lock();
        state.settle(unix_now());
        let request = state
            .requests
            .iter_mut()
            .find(|request| {
                request.id == request_id
                    && request.outcome.is_none()
                    && request.taken_by == Some(connection)
            })
            .ok_or(AnswerRefused::NotLive)?;
        request.outcome = Some(outcome);
        self.answered.notify_all();
        Ok(())
    }

    /// A signer connection ended: its unanswered requests go back to the queue for the app's next
    /// verified connection.
    pub(super) fn release(&self, connection: u64) {
        for request in self
            .lock()
            .requests
            .iter_mut()
            .filter(|request| request.taken_by == Some(connection) && request.outcome.is_none())
        {
            request.taken_by = None;
        }
    }
}

impl QueueState {
    /// Expires unanswered requests past their expiry and forgets requests well past it.
    fn settle(&mut self, now: i64) {
        for request in self
            .requests
            .iter_mut()
            .filter(|request| request.outcome.is_none() && request.expires_at <= now)
        {
            request.outcome = Some(SignOutcome::Expired);
        }
        self.requests
            .retain(|request| request.expires_at + KEEP_AFTER_EXPIRY_SECONDS > now);
    }
}

pub(super) fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| {
            i64::try_from(elapsed.as_secs()).unwrap_or(i64::MAX)
        })
}
