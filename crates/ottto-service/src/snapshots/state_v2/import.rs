//! Pre-publication pacing and the Claude semantic mapper boundary.
use super::*;
use anyhow::bail;
use std::path::Path;
use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Pause {
    PublicationPending,
    UnknownClass,
    Malformed,
    Partial,
    Oversize,
    Mismatch,
    Io,
    UnsafeParent,
}
impl std::fmt::Display for Pause {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("state_v2_import_paused")
    }
}
impl std::error::Error for Pause {}
impl Pause {
    fn deterministic(self) -> bool {
        !matches!(self, Self::Io | Self::UnsafeParent)
    }
}
#[derive(Default)]
pub(super) struct Pace {
    attempts: u64,
    transient_failures: u8,
    next: Option<Instant>,
    disabled: bool,
}
impl Pace {
    pub(super) fn start(&mut self, now: Instant) -> Option<bool> {
        if self.disabled || self.next.is_some_and(|next| now < next) {
            return None;
        }
        let first = self.attempts == 0;
        self.attempts = self.attempts.saturating_add(1);
        self.next = now.checked_add(Duration::from_secs(24 * 3600));
        if self.next.is_none() {
            self.disabled = true;
        }
        Some(first)
    }
    pub(super) fn failed(&mut self, now: Instant, class: Pause) {
        let hours = if class.deterministic() {
            24
        } else {
            self.transient_failures = self.transient_failures.saturating_add(1);
            match self.transient_failures {
                1 => 1,
                2 => 6,
                _ => {
                    self.disabled = true;
                    return;
                }
            }
        };
        self.next = now.checked_add(Duration::from_secs(hours * 3600));
        // Overflow cannot grant a fresh attempt.
        if self.next.is_none() {
            self.disabled = true;
        }
    }
    pub(super) fn disabled(&self) -> bool {
        self.disabled
    }
}

/// Raw inventory and parity proof precede publication. The four semantic
/// adapters share a transaction and context in `kinds`; this boundary owns
/// their integration with runtime CAS and external restart custody.
pub(super) trait Mapper {
    /// Emit ALL private text from key, fixed/header, labels/aliases and raw
    /// holds, as well as packed values. Replacements must retain none silently.
    fn private_paths(
        header: &Header,
        value: &dyn Value,
        paths: &mut dyn FnMut(&str) -> Result<()>,
    ) -> Result<()>;
    /// Enumerate the complete reference list packed in this row, including
    /// repeated edges. Shared values must not reference other shared values.
    fn references(
        header: &Header,
        value: &dyn Value,
        refs: &mut dyn FnMut(&RowKey) -> Result<()>,
    ) -> Result<()>;
    fn inventory(&self, path: &Path) -> std::result::Result<(), Pause>;
    fn preflight(&self, index: &ScanIndex) -> std::result::Result<(), Pause>;
    fn populate<S: Store>(&self, store: &mut S, index: &ScanIndex) -> Result<()>;
    // Proof mismatch/oversize must return a typed Pause; engine/IO failures
    // remain transient. The framework never guesses from provider text.
    fn verify<S: Store>(&self, store: &mut S, index: &ScanIndex) -> Result<()>;
    /// Read every semantic row through Transaction::read_value, including
    /// projection-bearing rows: it verifies value digests while decoding. Never return
    /// a partially hydrated graph or normalize unknown raw holds away.
    fn hydrate<S: Store>(&self, store: &mut S) -> Result<ScanIndex>;
    /// Uses the SAME claim maxima/hold and repair comparisons as v1; the
    /// adapter streams current custody through txn, without a second graph.
    fn merge_cas<T: Transaction>(&self, txn: &mut T, index: &mut ScanIndex) -> Result<()>;
    /// Emit only dirty rows against the resident header map. Before mutating,
    /// bound the proposed page to 5k rows / 32 MiB, shrinking collection pages
    /// when necessary. More than 64 account windows is an alarm, never
    /// permission to drop unsettled custody. KEEP persisted shared refs: decode
    /// only each changed row's old refs, diff against new refs, adjust/reclaim
    /// in this transaction. Never perform whole-history GC during a save.
    fn delta<T: Transaction>(&self, txn: &mut T, index: &ScanIndex) -> Result<()>;
}
/// Semantic reads/extractors are integrated. Conversion and writes deliberately
/// refuse until original-authority inventory, import generation publication,
/// committable-unit selection and owner-locked R1 callbacks are connected.
pub(super) struct ClaudeMapper;
impl Mapper for ClaudeMapper {
    fn references(
        header: &Header,
        value: &dyn Value,
        refs: &mut dyn FnMut(&RowKey) -> Result<()>,
    ) -> Result<()> {
        kinds::references(header, value, refs)
    }
    fn private_paths(
        header: &Header,
        value: &dyn Value,
        paths: &mut dyn FnMut(&str) -> Result<()>,
    ) -> Result<()> {
        kinds::private_paths(header, value, paths)
    }
    fn inventory(&self, _: &Path) -> std::result::Result<(), Pause> {
        Err(Pause::PublicationPending)
    }
    fn preflight(&self, _: &ScanIndex) -> std::result::Result<(), Pause> {
        Err(Pause::PublicationPending)
    }
    fn populate<S: Store>(&self, _: &mut S, _: &ScanIndex) -> Result<()> {
        bail!(Pause::PublicationPending)
    }
    fn verify<S: Store>(&self, _: &mut S, _: &ScanIndex) -> Result<()> {
        bail!(Pause::PublicationPending)
    }
    fn hydrate<S: Store>(&self, store: &mut S) -> Result<ScanIndex> {
        let mut tx = store.begin(TxnMode::Read)?;
        let header = tx
            .get(&RowKey::Meta("identity".into()))?
            .ok_or(Hold::ForeignBinding)?;
        anyhow::ensure!(header.len <= CONTROL_BYTES, Hold::DbUnavailable);
        let mut bytes = Vec::new();
        tx.read_value(&header, &mut bytes)?;
        let identity: Identity = serde_json::from_slice(&bytes)?;
        anyhow::ensure!(
            identity.binding.source == super::super::scan_index_persistence::Source::Claude,
            Hold::ForeignBinding
        );
        let (index, _) = kinds::hydrate_txn(&mut tx, identity.binding)?;
        Ok(index)
    }
    fn merge_cas<T: Transaction>(&self, _: &mut T, _: &mut ScanIndex) -> Result<()> {
        bail!(Pause::PublicationPending)
    }
    fn delta<T: Transaction>(&self, _: &mut T, _: &ScanIndex) -> Result<()> {
        bail!(Pause::PublicationPending)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn monotonic_pacing_is_one_hour_six_hours_third_disable_or_daily() {
        let now = Instant::now();
        let mut pace = Pace::default();
        assert_eq!(pace.start(now), Some(true));
        pace.failed(now, Pause::Io);
        assert_eq!(pace.start(now + Duration::from_secs(3599)), None);
        let second = now + Duration::from_secs(3600);
        assert_eq!(pace.start(second), Some(false));
        pace.failed(second, Pause::Io);
        let third = second + Duration::from_secs(6 * 3600);
        assert_eq!(pace.start(third), Some(false));
        pace.failed(third, Pause::Io);
        assert!(pace.disabled());
        assert_eq!(pace.start(third + Duration::from_secs(48 * 3600)), None);
        let mut pace = Pace::default();
        assert_eq!(pace.start(now), Some(true));
        pace.failed(now, Pause::UnknownClass);
        assert_eq!(pace.start(now + Duration::from_secs(86400 - 1)), None);
        assert_eq!(pace.start(now + Duration::from_secs(86400)), Some(false));
        // Restart allowance is explicitly process-local, not wall-clock paced.
        assert_eq!(Pace::default().start(now), Some(true));
    }
}
