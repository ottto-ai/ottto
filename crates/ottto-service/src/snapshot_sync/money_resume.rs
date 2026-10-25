//! A single bounded live-Claude finish, resumed before reading another page.
//! The future owns the original bodies and custody while the existing writer
//! works. Polling never waits on that writer or starts a background executor.
use super::*;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context as TaskContext, Poll, Wake, Waker};

struct NoopWake;
impl Wake for NoopWake {
    fn wake(self: std::sync::Arc<Self>) {}
}
fn waker() -> &'static Waker {
    static WAKER: OnceLock<Waker> = OnceLock::new();
    WAKER.get_or_init(|| Waker::from(std::sync::Arc::new(NoopWake)))
}

type Finish = Pin<Box<dyn Future<Output = Result<()>> + Send>>;
struct PendingFinish {
    future: Finish,
    completed: bool,
    started_unix: u64,
    recovery_binding: String,
    support_dir: PathBuf,
    index_path: PathBuf,
    index_revision: Option<FileRevision>,
    exclusions_revision: Option<FileRevision>,
    account_witness: [u8; 32],
    destination: String,
    policy: [u8; 32],
    client: SnapshotApiClient,
    owner: std::sync::Weak<Mutex<crate::DaemonState>>,
}
impl Drop for PendingFinish {
    fn drop(&mut self) {
        // A queued writer may have committed a send intent/counter after the
        // last poll. The next owner must reload it rather than reuse a stale
        // catalog and rearm a consumed physical slot.
        if !self.completed {
            super::unknown_recovery::invalidate(&self.support_dir);
        }
    }
}
static PENDING: Mutex<Option<PendingFinish>> = Mutex::new(None);

// Cancellation is scoped to the daemon that owns the parked graph. Other
// synthetic daemons/support directories cannot release each other's custody.
fn cancel_weak(owner: &std::sync::Weak<Mutex<crate::DaemonState>>) {
    let removed = {
        let Ok(mut slot) = PENDING.lock() else {
            return;
        };
        if slot
            .as_ref()
            .is_some_and(|pending| pending.owner.ptr_eq(owner))
        {
            slot.take()
        } else {
            None
        }
    };
    // Drop the ledger guard/reservations and zeroizing secret outside PENDING.
    drop(removed);
}

pub(crate) fn cancel_owner(daemon: &LocalDaemon) {
    cancel_weak(&std::sync::Arc::downgrade(&daemon.inner));
}

/// An unexpired owner may finish before cycle housekeeping. Its start is no
/// later than any captured body, including a writer result not consumed yet.
pub(super) fn privacy_owner_is_current(
    support: &Path,
    daemon: &LocalDaemon,
    now: u64,
) -> Result<bool> {
    let slot = PENDING.lock().map_err(|_| refusal())?;
    let owner = std::sync::Arc::downgrade(&daemon.inner);
    Ok(slot.as_ref().is_some_and(|pending| {
        pending.support_dir == support
            && pending.owner.ptr_eq(&owner)
            && now < pending.started_unix.saturating_add(24 * 3600)
    }))
}

pub(super) fn privacy_owner_matches(
    support: &Path,
    daemon: &LocalDaemon,
    now: u64,
    binding: &str,
    account_witness: &[u8; 32],
) -> Result<bool> {
    let slot = PENDING.lock().map_err(|_| refusal())?;
    let owner = std::sync::Arc::downgrade(&daemon.inner);
    Ok(slot.as_ref().is_some_and(|pending| {
        pending.support_dir == support
            && pending.owner.ptr_eq(&owner)
            && now < pending.started_unix.saturating_add(24 * 3600)
            && pending.recovery_binding == binding
            && &pending.account_witness == account_witness
    }))
}

/// Early credential/machine/account errors and a disabled Claude source can
/// bypass preparation entirely. They still release speculative collection.
/// Durable ledger/ACK custody remains in its existing independent stores.
pub(super) struct CycleScope<'a> {
    daemon: &'a LocalDaemon,
    cancel: bool,
}
impl<'a> CycleScope<'a> {
    pub(super) fn new(daemon: &'a LocalDaemon) -> Self {
        Self {
            daemon,
            cancel: true,
        }
    }
    pub(super) fn keep_claude(&mut self, enabled: bool) {
        self.cancel = !enabled;
        if !enabled {
            cancel_owner(self.daemon);
        }
    }
}
impl Drop for CycleScope<'_> {
    fn drop(&mut self) {
        if self.cancel {
            cancel_owner(self.daemon);
        }
    }
}

pub(crate) fn immediate<T>(future: impl Future<Output = T>) -> Option<T> {
    let mut future = std::pin::pin!(future);
    match future.as_mut().poll(&mut TaskContext::from_waker(waker())) {
        Poll::Ready(value) => Some(value),
        Poll::Pending => None,
    }
}

#[derive(Debug)]
struct AdmissionRefused;
impl std::fmt::Display for AdmissionRefused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("request money admission refused; ordinary collection remains available")
    }
}
impl std::error::Error for AdmissionRefused {}

pub(super) fn admission_refused() -> anyhow::Error {
    AdmissionRefused.into()
}
fn record_refusal(support: &Path, result: &Result<()>) {
    if result
        .as_ref()
        .err()
        .is_some_and(|error| error.is::<AdmissionRefused>())
        && !crate::snapshots::claude_request_money::store::live_refused(support)
    {
        crate::snapshots::claude_request_money::store::refuse_live(support);
        eprintln!("claude_request_money admission_refused=1 continuation_released=1");
    }
}

pub(crate) async fn until(
    mut ready: impl FnMut() -> crate::snapshots::claude_request_money::MoneyReceipt,
) -> Result<()> {
    use crate::snapshots::claude_request_money::MoneyReceipt;
    std::future::poll_fn(|_| match ready() {
        MoneyReceipt::Ready => Poll::Ready(Ok(())),
        MoneyReceipt::Pending => Poll::Pending,
        MoneyReceipt::Refused => Poll::Ready(Err(AdmissionRefused.into())),
    })
    .await
}

fn refusal() -> anyhow::Error {
    crate::source_rotation::LocalRefusal("request money scheduling checkpoint pending").into()
}

// Observation clocks/counts are allowed to advance; every collection, privacy,
// attribution and capability field must still match the authenticated hint.
pub(super) fn policy(mut hint: crate::snapshot_client::ActivityHintResponse) -> [u8; 32] {
    use std::hash::{Hash, Hasher};
    struct PolicyHash(Sha256);
    impl Hasher for PolicyHash {
        fn write(&mut self, bytes: &[u8]) {
            self.0.update(bytes);
        }
        fn finish(&self) -> u64 {
            let digest = self.0.clone().finalize();
            u64::from_be_bytes(digest[..8].try_into().expect("digest prefix"))
        }
    }
    hint.server_time.clear();
    hint.last_data_at = None;
    hint.record_count_15m = 0;
    hint.record_count_24h = 0;
    hint.recommended_scan_after.clear();
    let mut digest = PolicyHash(Sha256::new());
    digest.write(b"claude_money_resume_policy:v1\0");
    hint.hash(&mut digest);
    if let Some(key) = hint.session_attribution_hmac_key.as_mut() {
        key.zeroize();
    }
    digest.0.finalize().into()
}

// Saved indexes/list installs replace the file atomically. Check their
// identity and change clocks without rereading or cloning the whole index.
#[derive(PartialEq, Eq)]
struct FileRevision {
    bytes: u64,
    modified: std::time::SystemTime,
    #[cfg(unix)]
    object: (u64, u64, i64, i64),
}
fn index_revision(path: &Path) -> Result<Option<FileRevision>> {
    let metadata = match std::fs::metadata(path) {
        Ok(metadata) if metadata.is_file() => metadata,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
        _ => return Err(anyhow!("request money selected state unavailable")),
    };
    #[cfg(unix)]
    use std::os::unix::fs::MetadataExt;
    Ok(Some(FileRevision {
        bytes: metadata.len(),
        modified: metadata
            .modified()
            .map_err(|_| anyhow!("request money selected state unavailable"))?,
        #[cfg(unix)]
        object: (
            metadata.dev(),
            metadata.ino(),
            metadata.ctime(),
            metadata.ctime_nsec(),
        ),
    }))
}

fn graph_bytes<T: crate::heap_layout_bound::HeapLayoutBound>(graph: &T) -> Result<usize> {
    crate::heap_layout_bound::completed_bound(
        graph,
        crate::snapshots::claude_request_money::SHADOW_MEMORY_CEILING_BYTES,
    )
    .ok_or_else(|| {
        #[cfg(test)]
        eprintln!(
            "MONEY_OWNED_GRAPH_REFUSAL type={}",
            std::any::type_name::<T>()
        );
        admission_refused()
    })
}

/// One moving charge for the actual retained inputs. Refreshing replaces its
/// scan/index/progress slots, rather than charging those same graphs again.
pub(super) struct Memory {
    funds: crate::snapshots::claude_request_money::ShadowReservation,
    fixed: usize,
    progress: usize,
}
impl Memory {
    pub(super) fn refresh(
        &mut self,
        index: &ScanIndex,
        scan: &SourceScanResult,
        progress: Option<&SnapshotUploadProgress>,
        evidence: usize,
    ) -> Result<()> {
        let progress = match progress {
            Some(progress) => graph_bytes(progress)?,
            None => self.progress,
        };
        let bytes = self
            .fixed
            .saturating_add(graph_bytes(index)?)
            .saturating_add(graph_bytes(scan)?)
            .saturating_add(progress)
            .saturating_add(evidence);
        if !self.funds.resize(bytes) {
            return Err(admission_refused());
        }
        self.progress = progress;
        Ok(())
    }
    pub(super) fn evidence(
        &mut self,
        index: &ScanIndex,
        scan: &SourceScanResult,
        api: &crate::claude_local_otel::ClaudeLocalOtelLoadReport,
        trace: &crate::claude_local_otel::ClaudeTraceOwnershipLoadReport,
    ) -> Result<()> {
        self.refresh(
            index,
            scan,
            None,
            graph_bytes(api)?.saturating_add(graph_bytes(trace)?),
        )
    }
}

fn poll(mut pending: PendingFinish) -> Result<()> {
    match immediate(pending.future.as_mut()) {
        Some(result) => {
            // A completed future has consumed its writer results. Independent
            // outcome tickets remain owned by the current catalog. Only an
            // interrupted future can leave an unseen durable counter.
            pending.completed = result.is_ok()
                || result
                    .as_ref()
                    .err()
                    .is_some_and(|error| error.is::<super::SnapshotEntityDeferred>());
            record_refusal(&pending.support_dir, &result);
            result
        }
        None => {
            let mut slot = PENDING.lock().map_err(|_| refusal())?;
            if slot.is_some() {
                return Err(refusal());
            }
            let owner = pending.owner.clone();
            let witness = pending.account_witness;
            *slot = Some(pending);
            drop(slot);
            // Reset may race a poll while PENDING is temporarily empty. Check
            // again AFTER publication; reset also cancels published work.
            let current = owner.upgrade().and_then(|daemon| {
                let state = daemon.lock().ok()?;
                state
                    .running
                    .then(|| crate::snapshot_account_witness(&state.account))
            });
            if current != Some(witness) {
                cancel_weak(&owner);
                return Err(anyhow!("request money account custody withdrawn"));
            }
            Err(refusal())
        }
    }
}

/// Returns true if this turn resumed a finish, including terminal settlement.
/// Failed authority/policy/index checks drop the speculative graph; persisted
/// debt and exact ACK progress remain owned by their existing ledgers.
pub(super) fn resume(
    device: &LocalDeviceBinding,
    device_secret: &str,
    _home: &Path,
    support_dir: &Path,
    daemon: &LocalDaemon,
) -> Result<bool> {
    let pending = {
        let mut slot = PENDING.lock().map_err(|_| refusal())?;
        if !slot
            .as_ref()
            .is_some_and(|pending| pending.support_dir == support_dir)
        {
            return Ok(false);
        }
        slot.take().expect("matching finish")
    };
    if !source_money_resume(SnapshotSource::ClaudeCode, support_dir) {
        return Err(anyhow!("request money live custody withdrawn"));
    }
    ensure_snapshot_scan_authority(
        device,
        SnapshotSource::ClaudeCode,
        &pending.client,
        &pending.account_witness,
        daemon,
    )?;
    ensure_snapshot_destination_current(&pending.destination)?;
    if index_revision(&pending.index_path)? != pending.index_revision {
        return Err(anyhow!(
            "request money selected index changed during checkpoint"
        ));
    }
    if index_revision(&support_dir.join("snapshots/claude_code-reemission-exclusions.txt"))?
        != pending.exclusions_revision
    {
        return Err(anyhow!(
            "request money protection list changed during checkpoint"
        ));
    }
    let token =
        pending
            .client
            .issue_relay_token(device, device_secret, SnapshotSource::ClaudeCode)?;
    if policy(pending.client.get_activity_hint(&token)?) != pending.policy {
        return Err(anyhow!(
            "request money collection policy changed during checkpoint"
        ));
    }
    poll(pending)?;
    Ok(true)
}

#[allow(clippy::too_many_arguments)]
pub(super) fn start(
    preparation: SourcePreparation,
    index: ScanIndex,
    scan: SourceScanResult,
    device: &LocalDeviceBinding,
    device_secret: &str,
    machine_id: &str,
    home: &Path,
    support_dir: &Path,
    daemon: &LocalDaemon,
) -> Result<()> {
    #[cfg(test)]
    if let Some(hook) = BEFORE_START.with(|slot| slot.borrow_mut().take()) {
        hook();
    }
    let result = start_admitted(
        preparation,
        index,
        scan,
        device,
        device_secret,
        machine_id,
        home,
        support_dir,
        daemon,
    );
    record_refusal(support_dir, &result);
    result
}

#[allow(clippy::too_many_arguments)]
fn start_admitted(
    preparation: SourcePreparation,
    index: ScanIndex,
    scan: SourceScanResult,
    device: &LocalDeviceBinding,
    device_secret: &str,
    machine_id: &str,
    home: &Path,
    support_dir: &Path,
    daemon: &LocalDaemon,
) -> Result<()> {
    if resume(device, device_secret, home, support_dir, daemon)? {
        return Ok(());
    }
    if PENDING.lock().map_err(|_| refusal())?.is_some() {
        return Err(refusal());
    }
    // Move, never clone, the three collection graphs. Pay their retained heap
    // before boxing the continuation. The page builder independently admits
    // its scratch, evidence and output while suspended inside that builder.
    let limit = crate::snapshots::claude_request_money::SHADOW_MEMORY_CEILING_BYTES;
    let retained = crate::heap_layout_bound::completed_bound(&preparation, limit)
        .and_then(|bytes| {
            crate::heap_layout_bound::completed_bound(&index, limit - bytes)
                .map(|next| bytes + next)
        })
        .and_then(|bytes| {
            crate::heap_layout_bound::completed_bound(&scan, limit - bytes).map(|next| bytes + next)
        })
        .ok_or_else(|| {
            #[cfg(test)]
            eprintln!(
                "MONEY_OWNED_GRAPH_REFUSAL stage=retained preparation={:?} index={:?} scan={:?}",
                crate::heap_layout_bound::completed_bound(&preparation, limit),
                crate::heap_layout_bound::completed_bound(&index, limit),
                crate::heap_layout_bound::completed_bound(&scan, limit)
            );
            admission_refused()
        })?;
    // Pay only the metadata that is actually copied outside the moved input
    // graphs. In particular, never duplicate either entire index's charge.
    let context_bytes = graph_bytes(&preparation.receipt_client)?
        .saturating_mul(2)
        .saturating_add(preparation.index_path.as_os_str().len())
        .saturating_add(preparation.upload_destination_namespace.len())
        .saturating_add(device.device_id.len())
        .saturating_add(device.machine_id.as_ref().map_or(0, String::len))
        .saturating_add(
            device
                .sources
                .len()
                .saturating_mul(std::mem::size_of::<String>()),
        )
        .saturating_add(device.sources.iter().map(String::len).sum::<usize>())
        .saturating_add(device_secret.len())
        .saturating_add(machine_id.len())
        .saturating_add(home.as_os_str().len())
        .saturating_add(support_dir.as_os_str().len().saturating_mul(2))
        .saturating_add(16384);
    let progress = graph_bytes(&preparation.upload_progress)?;
    let fixed = retained
        .saturating_sub(graph_bytes(&index)?)
        .saturating_sub(graph_bytes(&scan)?)
        .saturating_sub(progress)
        .saturating_add(context_bytes);
    let funds = crate::snapshots::claude_request_money::ShadowReservation::admit(
        retained.saturating_add(context_bytes),
    )
    .ok_or_else(admission_refused)?;
    let mut memory = Memory {
        funds,
        fixed,
        progress,
    };
    let path = preparation.index_path.clone();
    let revision = index_revision(&path)?;
    let exclusions_revision =
        index_revision(&support_dir.join("snapshots/claude_code-reemission-exclusions.txt"))?;
    let account_witness = preparation.account_witness;
    let destination = preparation.upload_destination_namespace.clone();
    let hint = preparation.money_policy.ok_or_else(admission_refused)?;
    let client = preparation.receipt_client.clone();
    let resume_client = client.clone();
    let recovery_binding = super::unknown_recovery::binding(
        &destination,
        client.recovery_origin(),
        machine_id,
        &account_witness,
    );
    let owned_device = device.clone();
    let owned_secret = zeroize::Zeroizing::new(device_secret.to_owned());
    let machine_id = machine_id.to_owned();
    let home = home.to_owned();
    let support = support_dir.to_owned();
    let owner = std::sync::Arc::downgrade(&daemon.inner);
    let daemon = daemon.clone();
    let future = async move {
        // Retained optional retry is Pi-only; Claude never owns that window.
        let mut retry = live_snapshot_retry::LiveRetryOwner::closed();
        let mut transport = crate::net_resilience::TransportCycleOutcome::default();
        finish_sync_source_resume(
            preparation,
            index,
            scan,
            &client,
            &owned_device,
            &owned_secret,
            SnapshotSource::ClaudeCode,
            &machine_id,
            &home,
            &support,
            &daemon,
            &mut transport,
            &mut retry,
            Some(&mut memory),
        )
        .await
    };
    let inline = std::mem::size_of_val(&future);
    let allocation = crate::snapshots::claude_request_money::ShadowReservation::admit(
        inline.saturating_add(16384),
    )
    .ok_or_else(admission_refused)?;
    // Both charges live for exactly the continuation lifetime.
    let future = async move {
        let _allocation = allocation;
        future.await
    };
    poll(PendingFinish {
        future: Box::pin(future),
        completed: false,
        started_unix: super::unknown_recovery::now(support_dir),
        recovery_binding,
        support_dir: support_dir.to_owned(),
        index_path: path,
        index_revision: revision,
        exclusions_revision,
        account_witness,
        destination,
        policy: hint,
        client: resume_client,
        owner,
    })
}

#[cfg(test)]
pub(super) fn pending_for_test(support: &Path) -> bool {
    PENDING
        .lock()
        .unwrap()
        .as_ref()
        .is_some_and(|pending| pending.support_dir == support)
}

#[cfg(test)]
pub(crate) fn forget_for_test(support_dir: &Path) {
    let mut slot = PENDING.lock().unwrap();
    if slot
        .as_ref()
        .is_some_and(|pending| pending.support_dir == support_dir)
    {
        slot.take();
    }
}

#[cfg(test)]
thread_local! {
    static BEFORE_IMMEDIATE: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
    static BEFORE_START: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
}
#[cfg(test)]
pub(super) fn set_before_start_for_test(hook: impl FnOnce() + 'static) {
    BEFORE_START.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
}

#[cfg(test)]
pub(super) fn set_before_immediate_for_test(hook: impl FnOnce() + 'static) {
    BEFORE_IMMEDIATE.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
}
#[cfg(test)]
pub(super) fn before_immediate_for_test() {
    if let Some(hook) = BEFORE_IMMEDIATE.with(|slot| slot.borrow_mut().take()) {
        hook();
    }
}

#[cfg(test)]
pub(crate) fn drive_for_test<T>(future: impl Future<Output = T>) -> T {
    let mut future = std::pin::pin!(future);
    for _ in 0..128 {
        if let Some(value) = immediate(future.as_mut()) {
            return value;
        }
        crate::snapshots::claude_request_money::store::flush();
    }
    panic!("same admitted checkpoint continuation did not converge")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_real_pending_receipts_park_and_terminal_refusal_releases_immediately() {
        use crate::snapshots::claude_request_money::MoneyReceipt;
        assert!(immediate(until(|| MoneyReceipt::Ready)).unwrap().is_ok());
        assert!(immediate(until(|| MoneyReceipt::Refused))
            .unwrap()
            .unwrap_err()
            .is::<AdmissionRefused>());
        assert!(immediate(until(|| MoneyReceipt::Pending)).is_none());
    }

    #[test]
    #[serial_test::serial(claude_request_money_shadow)]
    fn moving_charge_does_not_stack_across_receipts_and_refused_growth_keeps_custody() {
        use crate::snapshots::claude_request_money as money;
        if !crate::heap_layout_bound::layout_supported() {
            return;
        }
        money::store::flush();
        let before = money::reserved_for_test();
        let mut index = ScanIndex::default();
        let scan = crate::snapshots::scan_source_roots_with_test_limit(
            SnapshotSource::ClaudeCode,
            &[],
            &mut index,
            "2026-08-23T18:40:00Z",
            183,
            16,
            false,
        )
        .unwrap();
        let progress = test_progress();
        let charge = graph_bytes(&index).unwrap()
            + graph_bytes(&scan).unwrap()
            + graph_bytes(&progress).unwrap();
        let mut memory = Memory {
            funds: money::ShadowReservation::admit(charge).unwrap(),
            fixed: 0,
            progress: graph_bytes(&progress).unwrap(),
        };
        for _ in 0..16 {
            memory.refresh(&index, &scan, Some(&progress), 0).unwrap();
            assert_eq!(
                money::reserved_for_test(),
                before + charge,
                "acknowledging another receipt must replace, not stack, the same graph's charge"
            );
        }
        let cap = money::ShadowReservation::admit(
            money::SHADOW_MEMORY_CEILING_BYTES - money::reserved_for_test(),
        )
        .unwrap();
        assert!(memory
            .refresh(&index, &scan, Some(&progress), 1)
            .unwrap_err()
            .is::<AdmissionRefused>());
        assert_eq!(
            memory.funds.bytes(),
            charge,
            "failed growth cannot release existing custody"
        );
        drop(cap);
        drop(memory);
        assert_eq!(money::reserved_for_test(), before);
    }

    #[test]
    fn policy_witness_survives_key_consumption_but_rejects_rotation_and_privacy_changes() {
        let hint: crate::snapshot_client::ActivityHintResponse = serde_json::from_value(serde_json::json!({
            "source":"claude_code", "server_time":"2026-10-22T10:00:00Z", "last_data_at":null,
            "record_count_15m":0, "record_count_24h":0, "local_usage_reconciliation_enabled":true,
            "backfill_window_days":183, "recommended_scan_after":"2026-10-22T10:05:00Z",
            "session_attribution_enabled":true, "session_attribution_hmac_key":"synthetic-policy-key-a",
            "session_attribution_hmac_key_version":"synthetic-v1"
        })).unwrap();
        // Preparation stores this witness BEFORE consuming its raw key.
        let witness = policy(hint.clone());
        let mut prepared = hint.clone();
        let mut raw = prepared.session_attribution_hmac_key.take().unwrap();
        raw.zeroize();
        assert!(prepared.session_attribution_hmac_key.is_none());
        assert_eq!(
            witness,
            policy(hint.clone()),
            "unchanged authenticated hint resumes the consumed-key preparation"
        );
        assert_ne!(
            witness,
            policy(prepared),
            "do not derive the saved witness from the stripped preparation"
        );
        let mut observations = hint.clone();
        observations.record_count_24h = 100;
        observations.server_time = "2026-10-22T12:00:00Z".into();
        observations.recommended_scan_after.clear();
        assert_eq!(witness, policy(observations));
        let mut rotated = hint.clone();
        rotated.session_attribution_hmac_key = Some("synthetic-policy-key-b".into());
        assert_ne!(
            witness,
            policy(rotated),
            "same-version key rotation must invalidate old work"
        );
        let mut privacy = hint;
        privacy.session_titles_enabled = false;
        assert_ne!(witness, policy(privacy));
    }

    fn test_progress() -> SnapshotUploadProgress {
        // Empty synthetic destination; no host account or credential access.
        SnapshotUploadProgress::new(
            "synthetic-money-destination".into(),
            snapshot_quarantine_witness(SnapshotSource::ClaudeCode),
        )
    }
}
