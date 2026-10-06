//! Source-owned capture/wake plumbing. Production remains closed; isolated
//! native callers exercise the same owner with synthetic authority adapters.
use super::*;
use crate::heap_layout_bound::{Counter, HeapLayoutBound};
use bounded_snapshot_retry::{PreparedRetry, RetryOwner};

pub(super) struct LiveAuthority {
    inputs: crate::snapshots::PiRetryInputs,
    policy: [u8; 32],
    destination: String,
    backfill_path: PathBuf,
    backfill: Option<[u8; 32]>,
}

// Include every input that can change Pi's post-policy body or admission.
// Volatile server clocks/counts and cadence recommendations are not authority.
pub(super) fn policy_seal(h: &crate::snapshot_client::ActivityHintResponse) -> Option<[u8; 32]> {
    if h.source != "pi"
        || !h.local_usage_reconciliation_enabled
        || h.backfill_window_days == 0
        || h.session_attribution_enabled
        || h.snapshot_head_cas_required
    {
        return None;
    }
    validated_receipt_window_days(h.backfill_window_days).ok()?;
    let mut digest = Sha256::new();
    digest.update(b"ottto:pi-retry-policy:v1\0");
    digest.update(h.backfill_window_days.to_be_bytes());
    digest.update([
        h.session_titles_enabled as u8,
        h.workspace_labels_enabled as u8,
        h.session_artifacts_enabled as u8,
        h.session_attribution_enabled as u8,
        h.session_attribution_labels_enabled as u8,
    ]);
    // Disabled attribution admits no key-dependent schedule/launch context.
    // Its off policy is checked afresh after each new relay-token acquisition.
    Some(digest.finalize().into())
}

pub(super) fn fresh_policy_seal(
    h: &mut crate::snapshot_client::ActivityHintResponse,
) -> Option<[u8; 32]> {
    if let Some(key) = h.session_attribution_hmac_key.as_mut() {
        key.zeroize();
    }
    policy_seal(h)
}

fn backfill_seal(path: &Path) -> Option<Option<[u8; 32]>> {
    match crate::snapshot_retry::read_state(path, crate::snapshot_retry::RESPONSE_BYTES) {
        Ok(bytes) => Some(Some(Sha256::digest(bytes).into())),
        Err(error) if error.kind() == ErrorKind::NotFound => Some(None),
        _ => None,
    }
}

impl LiveAuthority {
    pub(super) fn capture(
        source: SnapshotSource,
        home: &Path,
        support: &Path,
        hint: &crate::snapshot_client::ActivityHintResponse,
        destination: &str,
        backfill: &crate::backfill::BackfillState,
    ) -> Option<Self> {
        if source != SnapshotSource::Pi {
            return None;
        }
        let policy = policy_seal(hint)?;
        let roots = source.default_roots(home);
        let [root] = roots.as_slice() else {
            return None;
        };
        let inputs = crate::snapshots::PiRetryInputs::capture(root)?;
        let backfill_path = crate::backfill::backfill_state_path(support);
        let seal = backfill_seal(&backfill_path)?;
        // Do not bless a state file changed since the canonical reader ran.
        let current = if seal.is_some() {
            serde_json::from_slice(
                &crate::snapshot_retry::read_state(
                    &backfill_path,
                    crate::snapshot_retry::RESPONSE_BYTES,
                )
                .ok()?,
            )
            .ok()?
        } else {
            crate::backfill::BackfillState::default()
        };
        if &current != backfill || backfill_seal(&backfill_path)? != seal {
            return None;
        }
        Some(Self {
            inputs,
            policy,
            destination: destination.to_owned(),
            backfill_path,
            backfill: seal,
        })
    }

    pub(super) fn validate_inputs(&self, home: &Path) -> Result<()> {
        anyhow::ensure!(
            SnapshotSource::Pi.default_roots(home).as_slice() == [self.inputs.root()],
            "optional Pi root changed"
        );
        anyhow::ensure!(
            backfill_seal(&self.backfill_path) == Some(self.backfill),
            "optional snapshot cutoff changed"
        );
        self.inputs.validate()
    }

    pub(super) fn validate_capture(&self, home: &Path, items: &[SnapshotItem]) -> Result<()> {
        self.validate_inputs(home)?;
        anyhow::ensure!(
            self.inputs.covers(items),
            "optional Pi body lacks opened-file authority"
        );
        Ok(())
    }

    pub(super) fn policy(&self) -> &[u8; 32] {
        &self.policy
    }
    pub(super) fn destination(&self) -> &str {
        &self.destination
    }
}
impl HeapLayoutBound for LiveAuthority {
    fn heap_bound(&self, c: &mut Counter) -> Option<()> {
        let Self {
            inputs,
            policy: _,
            destination,
            backfill_path,
            backfill: _,
        } = self;
        inputs.heap_bound(c)?;
        destination.heap_bound(c)?;
        backfill_path.heap_bound(c)
    }
}

pub(super) struct LiveRetryOwner {
    enabled: bool,
    retry: RetryOwner,
}
impl LiveRetryOwner {
    pub(super) fn closed() -> Self {
        Self {
            enabled: false,
            retry: RetryOwner::default(),
        }
    }
    pub(super) fn production() -> Self {
        Self {
            enabled: bounded_snapshot_retry::production_activation_reviewed(),
            retry: RetryOwner::default(),
        }
    }
    #[cfg(test)]
    pub(super) fn isolated() -> Self {
        Self {
            enabled: true,
            retry: RetryOwner::default(),
        }
    }
    pub(super) fn enabled(&self) -> bool {
        self.enabled
    }
    pub(super) fn allowance(&self) -> usize {
        self.retry.allowance()
    }
    #[allow(clippy::too_many_arguments)]
    pub(super) fn capture_after_shed(
        &mut self,
        live: LiveAuthority,
        home: &Path,
        source: SnapshotSource,
        machine: &str,
        policy: SnapshotUploadPolicy,
        account: [u8; 32],
        items: &[SnapshotItem],
        working: &mut ScanIndex,
        committed: &ScanIndex,
        progress: &SnapshotUploadProgress,
        index_path: &Path,
        progress_path: &Path,
        first_shed: Instant,
        delay: Duration,
    ) -> bool {
        if !self.enabled
            || source != SnapshotSource::Pi
            || live.destination() != progress.destination_namespace_hash
            || live.validate_capture(home, items).is_err()
        {
            return false;
        }
        let Some(live_bound) = crate::heap_layout_bound::bound(&live, self.allowance()) else {
            return false;
        };
        let Some(allowance) = self.allowance().checked_sub(live_bound) else {
            return false;
        };
        // Only a successfully returned native checkpoint reaches this call.
        working.generation = committed.generation;
        working.mark_bounded_sweep_unsettled();
        let Some(mut page) = PreparedRetry::capture(
            source,
            machine,
            policy,
            account,
            items,
            working,
            committed,
            progress,
            index_path,
            progress_path,
            first_shed,
            delay,
            allowance.min(1024 * 1024),
        ) else {
            return false;
        };
        page.attach_live_authority(live, self.allowance()) && self.admit(page)
    }
    pub(super) fn admit(&mut self, page: PreparedRetry) -> bool {
        self.enabled && self.retry.admit(page)
    }
    pub(super) fn wake_before(&self, ordinary: Instant) -> Instant {
        if self.enabled {
            self.retry.wake_before(ordinary)
        } else {
            ordinary
        }
    }
    pub(super) fn clear(&mut self) {
        self.retry.clear();
    }

    pub(super) fn boundary(
        &mut self,
        busy: impl Iterator<Item = SnapshotSource>,
        home: &Path,
        support: &Path,
        daemon: &LocalDaemon,
    ) {
        if !self.enabled {
            return;
        }
        if !daemon.snapshot_retry_running().unwrap_or(false) {
            self.clear();
            return;
        }
        self.retry.boundary(busy, Instant::now(), |page| {
            // Fresh local credentials are scoped to this one turn. The page
            // owns only the hashed destination and account fence.
            let (device, secret) = load_snapshot_device_credentials()?;
            let client =
                SnapshotApiClient::new(snapshot_api_base_url()).with_receipt_state_dir(support);
            let source = page.source();
            let authority = page.authority();
            let live = page.take_live_authority()?;
            let mut validate = || {
                anyhow::ensure!(
                    daemon.snapshot_retry_running().unwrap_or(false),
                    "snapshot daemon stopped"
                );
                ensure_snapshot_scan_authority(&device, source, &client, &authority, daemon)?;
                ensure_snapshot_destination_current(live.destination())?;
                live.validate_inputs(home)
            };
            let result = page.turn_live(&client, &device, &secret, live.policy(), &mut validate);
            page.restore_live_authority(live);
            result
        });
    }
    #[cfg(test)]
    pub(super) fn isolated_boundary(
        &mut self,
        send: impl FnMut(&mut PreparedRetry) -> Result<SnapshotPageOutcome>,
    ) {
        self.retry
            .boundary(std::iter::empty(), Instant::now(), send);
    }
}
