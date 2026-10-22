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
    support_dir: PathBuf,
    index_path: PathBuf,
    index_revision: Option<FileRevision>,
    exclusions_revision: Option<FileRevision>,
    account_witness: [u8; 32],
    destination: String,
    policy: crate::snapshot_client::ActivityHintResponse,
    client: SnapshotApiClient,
    _reservation: crate::snapshots::claude_request_money::ShadowReservation,
}
static PENDING: Mutex<Option<PendingFinish>> = Mutex::new(None);

pub(crate) fn immediate<T>(future: impl Future<Output = T>) -> Option<T> {
    let mut future = std::pin::pin!(future);
    match future.as_mut().poll(&mut TaskContext::from_waker(waker())) {
        Poll::Ready(value) => Some(value),
        Poll::Pending => None,
    }
}

pub(super) async fn until(mut ready: impl FnMut() -> bool) {
    std::future::poll_fn(|_| {
        if ready() {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    })
    .await
}

fn refusal() -> anyhow::Error {
    crate::source_rotation::LocalRefusal("request money scheduling checkpoint pending").into()
}

// Observation clocks/counts are allowed to advance; every collection, privacy,
// attribution and capability field must still match the authenticated hint.
fn policy(
    mut hint: crate::snapshot_client::ActivityHintResponse,
) -> crate::snapshot_client::ActivityHintResponse {
    hint.server_time.clear();
    hint.last_data_at = None;
    hint.record_count_15m = 0;
    hint.record_count_24h = 0;
    hint.recommended_scan_after.clear();
    hint
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

pub(super) fn retain<T: crate::heap_layout_bound::HeapLayoutBound>(
    graph: &T,
) -> Result<crate::snapshots::claude_request_money::ShadowReservation> {
    let bytes = crate::heap_layout_bound::completed_bound(
        graph,
        crate::snapshots::claude_request_money::SHADOW_MEMORY_CEILING_BYTES,
    )
    .ok_or_else(refusal)?;
    crate::snapshots::claude_request_money::ShadowReservation::admit(bytes).ok_or_else(refusal)
}

fn poll(mut pending: PendingFinish) -> Result<()> {
    match immediate(pending.future.as_mut()) {
        Some(result) => result,
        None => {
            let mut slot = PENDING.lock().map_err(|_| refusal())?;
            if slot.is_some() {
                return Err(refusal());
            }
            *slot = Some(pending);
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
        .ok_or_else(refusal)?;
    // A second input-graph charge covers the bounded metadata copies (hint,
    // paths, destination/client) retained outside the moved preparation.
    let context_bytes = device
        .device_id
        .len()
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
        .saturating_add(support_dir.as_os_str().len())
        .saturating_add(16384);
    let reservation = crate::snapshots::claude_request_money::ShadowReservation::admit(
        retained.saturating_mul(2).saturating_add(context_bytes),
    )
    .ok_or_else(refusal)?;
    let path = preparation.index_path.clone();
    let revision = index_revision(&path)?;
    let exclusions_revision =
        index_revision(&support_dir.join("snapshots/claude_code-reemission-exclusions.txt"))?;
    let account_witness = preparation.account_witness;
    let destination = preparation.upload_destination_namespace.clone();
    let hint = policy(preparation.activity_hint.clone());
    let client = preparation.receipt_client.clone();
    let resume_client = client.clone();
    let owned_device = device.clone();
    let owned_secret = zeroize::Zeroizing::new(device_secret.to_owned());
    let machine_id = machine_id.to_owned();
    let home = home.to_owned();
    let support = support_dir.to_owned();
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
        )
        .await
    };
    let inline = std::mem::size_of_val(&future);
    let allocation = crate::snapshots::claude_request_money::ShadowReservation::admit(
        inline.saturating_add(16384),
    )
    .ok_or_else(refusal)?;
    // Both charges live for exactly the continuation lifetime.
    let future = async move {
        let _allocation = allocation;
        future.await
    };
    poll(PendingFinish {
        future: Box::pin(future),
        support_dir: support_dir.to_owned(),
        index_path: path,
        index_revision: revision,
        exclusions_revision,
        account_witness,
        destination,
        policy: hint,
        client: resume_client,
        _reservation: reservation,
    })
}

#[cfg(test)]
pub(super) fn forget_for_test(support_dir: &Path) {
    let mut slot = PENDING.lock().unwrap();
    if slot
        .as_ref()
        .is_some_and(|pending| pending.support_dir == support_dir)
    {
        slot.take();
    }
}
