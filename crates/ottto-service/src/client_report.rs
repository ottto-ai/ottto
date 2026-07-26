//! Daemon-side loss accounting, reported on every snapshot batch.
//!
//! Without it, "the collector uploaded nothing because nothing changed" and
//! "the collector dropped what changed" are indistinguishable server-side, so
//! every daemon-side drop is unfalsifiable. The shape is Sentry's client-report
//! triple `{reason, category, quantity}`.
//!
//! Two disciplines are deliberate:
//!
//! * **Every reason is emitted on every batch, including the zeros.** A counter
//!   that only appears when it is non-zero cannot distinguish "healthy" from
//!   "not reporting"; an explicit `0` can.
//! * **Counters are reported before they are cleared.** [`take`] reads without
//!   clearing and [`commit`] subtracts exactly what the server acknowledged, so
//!   a failed upload re-reports its losses on the next batch instead of
//!   erasing them.

use serde::Serialize;
use std::sync::atomic::{AtomicU64, Ordering};

/// Bump when the reported shape changes so the server can branch on it.
pub const CLIENT_REPORT_SCHEMA_VERSION: u16 = 1;

/// What was lost. The set is closed: a new loss path adds a variant here (and
/// therefore a row on the wire) rather than hiding inside an existing one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ClientReportReason {
    /// A bounded local queue dropped work it could not hold.
    QueueOverflow,
    /// An upload was shed by the server (429/503) and backed off.
    RatelimitBackoff,
    /// An upload failed at the transport layer.
    NetworkError,
    /// An entity the server rejected permanently, so the daemon stopped
    /// retrying it.
    Poisoned,
}

impl ClientReportReason {
    pub const ALL: [Self; 4] = [
        Self::QueueOverflow,
        Self::RatelimitBackoff,
        Self::NetworkError,
        Self::Poisoned,
    ];

    pub fn reason(self) -> &'static str {
        match self {
            Self::QueueOverflow => "queue_overflow",
            Self::RatelimitBackoff => "ratelimit_backoff",
            Self::NetworkError => "network_error",
            Self::Poisoned => "poisoned",
        }
    }

    /// The unit the quantity counts. Per-entity losses count snapshot items;
    /// transport losses count whole batch attempts.
    pub fn category(self) -> &'static str {
        match self {
            Self::QueueOverflow | Self::Poisoned => "snapshot_item",
            Self::RatelimitBackoff | Self::NetworkError => "snapshot_batch",
        }
    }

    fn slot(self) -> &'static AtomicU64 {
        match self {
            Self::QueueOverflow => &QUEUE_OVERFLOW,
            Self::RatelimitBackoff => &RATELIMIT_BACKOFF,
            Self::NetworkError => &NETWORK_ERROR,
            Self::Poisoned => &POISONED,
        }
    }
}

static QUEUE_OVERFLOW: AtomicU64 = AtomicU64::new(0);
static RATELIMIT_BACKOFF: AtomicU64 = AtomicU64::new(0);
static NETWORK_ERROR: AtomicU64 = AtomicU64::new(0);
static POISONED: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ClientReportEntry {
    pub reason: &'static str,
    pub category: &'static str,
    pub quantity: u64,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ClientReport {
    pub schema_version: u16,
    pub entries: Vec<ClientReportEntry>,
}

impl ClientReport {
    /// A report with every reason at zero. Used by offline reproductions (the
    /// snapshot audit) whose output must not vary with the live process's
    /// loss history.
    pub fn empty() -> Self {
        Self {
            schema_version: CLIENT_REPORT_SCHEMA_VERSION,
            entries: ClientReportReason::ALL
                .iter()
                .map(|reason| ClientReportEntry {
                    reason: reason.reason(),
                    category: reason.category(),
                    quantity: 0,
                })
                .collect(),
        }
    }

    pub fn quantity(&self, reason: ClientReportReason) -> u64 {
        self.entries
            .iter()
            .find(|entry| entry.reason == reason.reason())
            .map(|entry| entry.quantity)
            .unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.entries.iter().all(|entry| entry.quantity == 0)
    }
}

/// Record `quantity` losses for `reason`.
pub fn record(reason: ClientReportReason, quantity: u64) {
    if quantity == 0 {
        return;
    }
    reason.slot().fetch_add(quantity, Ordering::Relaxed);
}

/// Read the current counters without clearing them.
pub fn take() -> ClientReport {
    ClientReport {
        schema_version: CLIENT_REPORT_SCHEMA_VERSION,
        entries: ClientReportReason::ALL
            .iter()
            .map(|reason| ClientReportEntry {
                reason: reason.reason(),
                category: reason.category(),
                quantity: reason.slot().load(Ordering::Relaxed),
            })
            .collect(),
    }
}

/// Subtract an acknowledged report. Losses recorded after the report was taken
/// survive, so a concurrent drop is reported on the next batch rather than lost.
pub fn commit(report: &ClientReport) {
    for reason in ClientReportReason::ALL {
        let reported = report.quantity(reason);
        if reported == 0 {
            continue;
        }
        let slot = reason.slot();
        let mut current = slot.load(Ordering::Relaxed);
        loop {
            let next = current.saturating_sub(reported);
            match slot.compare_exchange_weak(current, next, Ordering::Relaxed, Ordering::Relaxed) {
                Ok(_) => break,
                Err(observed) => current = observed,
            }
        }
    }
}

#[cfg(test)]
pub(crate) fn reset_for_test() {
    for reason in ClientReportReason::ALL {
        reason.slot().store(0, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;
    use std::collections::BTreeSet;

    #[test]
    #[serial(client_report)]
    fn every_reason_is_reported_even_when_zero() {
        reset_for_test();
        let report = take();
        assert_eq!(report.entries.len(), ClientReportReason::ALL.len());
        assert!(report.is_empty());
        assert_eq!(
            report
                .entries
                .iter()
                .map(|entry| (entry.reason, entry.category, entry.quantity))
                .collect::<Vec<_>>(),
            vec![
                ("queue_overflow", "snapshot_item", 0),
                ("ratelimit_backoff", "snapshot_batch", 0),
                ("network_error", "snapshot_batch", 0),
                ("poisoned", "snapshot_item", 0),
            ]
        );
    }

    #[test]
    #[serial(client_report)]
    fn taking_a_report_does_not_clear_it() {
        reset_for_test();
        record(ClientReportReason::NetworkError, 2);
        assert_eq!(take().quantity(ClientReportReason::NetworkError), 2);
        assert_eq!(take().quantity(ClientReportReason::NetworkError), 2);
    }

    #[test]
    #[serial(client_report)]
    fn commit_clears_only_the_acknowledged_quantity() {
        reset_for_test();
        record(ClientReportReason::Poisoned, 3);
        let report = take();
        record(ClientReportReason::Poisoned, 2);
        commit(&report);
        assert_eq!(take().quantity(ClientReportReason::Poisoned), 2);
        assert!(!take().is_empty());
    }

    #[test]
    #[serial(client_report)]
    fn commit_never_underflows() {
        reset_for_test();
        record(ClientReportReason::QueueOverflow, 1);
        let report = take();
        commit(&report);
        commit(&report);
        assert_eq!(take().quantity(ClientReportReason::QueueOverflow), 0);
    }

    #[test]
    #[serial(client_report)]
    fn serialized_shape_is_the_sentry_triple() {
        reset_for_test();
        record(ClientReportReason::RatelimitBackoff, 4);
        let report = take();
        let encoded = serde_json::to_value(&report).expect("serialize client report");
        assert_eq!(encoded["schema_version"], 1);
        let entry = encoded["entries"]
            .as_array()
            .expect("entries")
            .iter()
            .find(|entry| entry["reason"] == "ratelimit_backoff")
            .expect("ratelimit entry")
            .clone();
        assert_eq!(
            entry
                .as_object()
                .expect("object")
                .keys()
                .map(String::as_str)
                .collect::<BTreeSet<_>>(),
            BTreeSet::from(["reason", "category", "quantity"])
        );
        assert_eq!(entry["quantity"], 4);
    }
}
