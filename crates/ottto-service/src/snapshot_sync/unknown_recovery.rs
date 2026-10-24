//! Bounded custody for an authorized batch whose outcome may be unknown.
//! The payload is final identity-encoded wire JSON, never a recipe for a POST.
//! All filesystem work runs on the existing money writer. No gate-OFF caller
//! loads this directory or allocates a catalog.
use super::*;
use crate::snapshots::claude_request_money::{self as money, store};
use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::sync::mpsc::{Receiver, TryRecvError};

const BODY_MAX: usize = 4 * 1024 * 1024;
const MANIFEST_MAX: usize = 64 * 1024;
const TOTAL_MAX: u64 = 16 * 1024 * 1024;
const ACTIVE_MAX: usize = 64;
const RECEIPT_MAX: usize = 1024;
const RECEIPT_BYTES_MAX: u64 = 256 * 1024;
const DEADLINE: u64 = 24 * 3600;
const RECEIPT_TTL: u64 = 35 * 86400;
const REPLAY_AT: [u64; 3] = [300, 3600, 21600];
const IO_FUNDS: usize = 2 * BODY_MAX + 8 * MANIFEST_MAX;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Entity {
    pub root: String,
    pub session: String,
    pub fingerprint: String,
    pub witness: String,
    pub witness_version: Option<u64>,
    pub files: Vec<String>,
    pub source_fingerprint: Option<String>,
    pub literal: bool,
    pub cache_patch: Option<crate::snapshots::CacheObservations>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Manifest {
    pub id: String,
    pub binding: String,
    pub context: String,
    pub created: u64,
    pub deadline: u64,
    /// Includes the original physical POST; 1 + at most three replays.
    pub posts: u8,
    pub not_before: u64,
    pub length: usize,
    pub sha256: String,
    pub head_cas: bool,
    pub ack_saved: bool,
    pub entities: Vec<Entity>,
    pub terminal: Option<Reason>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Reason {
    Exhausted,
    Expired,
    BindingLost,
    CorruptCustody,
    RevisionDowngrade,
    HttpConflict,
    Oversize,
    Validation,
    VersionSkew,
    Disabled,
    Resolved,
    Released,
}

/// Closed public/diagnostic allowlist. Full private manifest data never enters
/// this type, including through error formatting.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    outcome: String,
    reason: Reason,
    entities: usize,
    age_hours: u64,
    time_day: u64,
    attempts: u8,
    hash8: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CheckedManifest {
    checksum: String,
    manifest: Manifest,
}

#[derive(Debug)]
pub(super) struct Deferred {
    pub reason: Option<Reason>,
    pub not_before: u64,
    pub route_unavailable: bool,
}
impl std::fmt::Display for Deferred {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("request money immutable batch awaits bounded recovery")
    }
}
impl std::error::Error for Deferred {}

pub(super) fn now(support: &Path) -> u64 {
    money::recovery_now(support)
}
#[derive(Debug)]
struct CustodyFault;
impl std::fmt::Display for CustodyFault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("request money recovery custody fault")
    }
}
impl std::error::Error for CustodyFault {}
fn fault() -> anyhow::Error {
    CustodyFault.into()
}

pub(super) fn faulted(support: &Path, error: &anyhow::Error) {
    if !error.is::<CustodyFault>() {
        return;
    }
    if let Ok(mut catalogs) = CATALOGS.lock() {
        if let Some(catalog) = catalogs.get_mut(support) {
            catalog.fault = true;
        }
    }
    eprintln!("claude_request_money recovery_custody_fault=1");
}

fn dir(support: &Path) -> PathBuf {
    support.join("claude-money-recovery")
}
fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
pub(super) fn binding(namespace: &str, origin: &str, machine: &str, context: &str) -> String {
    let mut hash = Sha256::new();
    for field in [
        "unknown_ack:v1",
        namespace,
        origin,
        machine,
        "claude_code",
        context,
    ] {
        hash.update((field.len() as u64).to_be_bytes());
        hash.update(field.as_bytes());
    }
    format!("{:x}", hash.finalize())
}
fn valid_id(id: &str) -> bool {
    id.len() == 64 && id.bytes().all(|c| c.is_ascii_hexdigit())
}
fn path(root: &Path, id: &str, extension: &str) -> Result<PathBuf> {
    if !valid_id(id) {
        return Err(fault());
    }
    Ok(root.join(format!("{id}.{extension}")))
}
fn sync_dir(root: &Path) -> Result<()> {
    File::open(root)?.sync_all().map_err(Into::into)
}
fn private_dir(root: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        let mut builder = fs::DirBuilder::new();
        builder.recursive(true).mode(0o700);
        builder.create(root)?;
        let meta = fs::symlink_metadata(root)?;
        if !meta.is_dir() || meta.permissions().mode() & 0o077 != 0 {
            return Err(fault());
        }
    }
    #[cfg(not(unix))]
    fs::create_dir_all(root)?;
    Ok(())
}
fn read_capped(path: &Path, cap: usize) -> Result<Vec<u8>> {
    let meta = fs::symlink_metadata(path)?;
    if !meta.is_file() || meta.len() > cap as u64 {
        return Err(fault());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if meta.permissions().mode() & 0o077 != 0 {
            return Err(fault());
        }
    }
    let mut bytes = Vec::with_capacity(meta.len() as usize);
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    options
        .open(path)?
        .take(cap as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > cap {
        return Err(fault());
    }
    Ok(bytes)
}
fn footprint(root: &Path) -> Result<u64> {
    let mut bytes = 0_u64;
    let mut count = 0;
    for entry in fs::read_dir(root)? {
        count += 1;
        if count > 4 * ACTIVE_MAX + RECEIPT_MAX + 4 {
            return Err(fault());
        }
        let meta = fs::symlink_metadata(entry?.path())?;
        if !meta.is_file() {
            return Err(fault());
        }
        bytes = bytes.checked_add(meta.len()).ok_or_else(fault)?;
    }
    if bytes > TOTAL_MAX {
        return Err(fault());
    }
    Ok(bytes)
}
fn atomic(root: &Path, target: &Path, bytes: &[u8]) -> Result<()> {
    if footprint(root)?.saturating_add(bytes.len() as u64) > TOTAL_MAX {
        return Err(fault());
    }
    let staged = target.with_extension(format!(
        "{}.tmp",
        target.extension().unwrap().to_string_lossy()
    ));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&staged)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    fs::rename(&staged, target)?;
    sync_dir(root)
}
fn write_manifest(root: &Path, manifest: &Manifest) -> Result<()> {
    let value = serde_json::to_vec(manifest)?;
    let envelope = CheckedManifest {
        checksum: digest(&value),
        manifest: manifest.clone(),
    };
    let bytes = serde_json::to_vec(&envelope)?;
    if bytes.len() > MANIFEST_MAX {
        return Err(fault());
    }
    atomic(root, &path(root, &manifest.id, "json")?, &bytes)
}
fn validate_manifest(m: &Manifest) -> Result<()> {
    if !valid_id(&m.id)
        || !valid_id(&m.sha256)
        || !valid_id(&m.binding)
        || m.posts == 0
        || m.posts > 4
        || m.length > BODY_MAX
        || m.length == 0
        || m.deadline != m.created.saturating_add(DEADLINE)
        || m.entities.is_empty()
        || m.entities.len() > SNAPSHOT_BATCH_LIMIT
        || m.entities.iter().any(|e| {
            e.files.len() > 256
                || e.session.len() > 1024
                || e.root.len() > 1024
                || e.files.iter().any(|f| f.len() > 4096)
                || e.witness.len() != 64
                || e.fingerprint.len() != 64
        })
    {
        return Err(fault());
    }
    Ok(())
}
fn load(root: &Path) -> Result<Vec<Manifest>> {
    if !root.exists() {
        return Ok(Vec::new());
    }
    footprint(root)?;
    let mut ids = BTreeSet::new();
    for entry in fs::read_dir(root)? {
        let file = entry?.path();
        let name = file
            .file_name()
            .and_then(|s| s.to_str())
            .ok_or_else(fault)?;
        let Some((id, extension)) = name.split_once('.') else {
            continue;
        };
        if !matches!(extension, "json" | "body" | "json.tmp" | "body.tmp") {
            continue;
        }
        if !valid_id(id) || ids.len() >= ACTIVE_MAX && !ids.contains(id) {
            return Err(fault());
        }
        ids.insert(id.to_owned());
    }
    let mut entries = Vec::new();
    for id in ids {
        let decoded = (|| -> Result<Manifest> {
            let envelope: CheckedManifest =
                serde_json::from_slice(&read_capped(&path(root, &id, "json")?, MANIFEST_MAX)?)?;
            let m = envelope.manifest;
            if m.id != id || envelope.checksum != digest(&serde_json::to_vec(&m)?) {
                return Err(fault());
            }
            validate_manifest(&m)?;
            Ok(m)
        })();
        let mut m = decoded.unwrap_or_else(|_| Manifest {
            id,
            binding: "00".repeat(32),
            context: String::new(),
            created: 0,
            deadline: DEADLINE,
            posts: 1,
            not_before: 0,
            length: 0,
            sha256: "00".repeat(32),
            head_cas: false,
            ack_saved: false,
            entities: Vec::new(),
            terminal: Some(Reason::CorruptCustody),
        });
        if m.terminal != Some(Reason::CorruptCustody) {
            let bytes = read_capped(&path(root, &m.id, "body")?, BODY_MAX);
            if !bytes
                .as_ref()
                .is_ok_and(|b| b.len() == m.length && digest(b) == m.sha256)
            {
                m.terminal = Some(Reason::CorruptCustody);
            }
        }
        entries.push(m);
    }
    Ok(entries)
}
fn prune_receipts(root: &Path, now: u64) -> Result<()> {
    let mut count = 0;
    let mut bytes = 0;
    for entry in fs::read_dir(root)? {
        let file = entry?.path();
        if file.extension().and_then(|s| s.to_str()) != Some("receipt") {
            continue;
        }
        let encoded = read_capped(&file, 1024)?;
        let receipt: Receipt = serde_json::from_slice(&encoded)?;
        if now / 86400 > receipt.time_day.saturating_add(RECEIPT_TTL / 86400) {
            fs::remove_file(file)?;
        } else {
            count += 1;
            bytes += encoded.len() as u64;
        }
    }
    // Reserve a receipt for every admitted active batch, even at full custody.
    if count + ACTIVE_MAX >= RECEIPT_MAX
        || bytes + (ACTIVE_MAX as u64 + 1) * 1024 > RECEIPT_BYTES_MAX
    {
        return Err(fault());
    }
    Ok(())
}
fn capture(support: PathBuf, mut m: Manifest, body: &[u8]) -> Result<Manifest> {
    let root = dir(&support);
    private_dir(&root)?;
    sync_dir(&support)?;
    prune_receipts(&root, m.created)?;
    if load(&root)?.len() >= ACTIVE_MAX || body.len() > BODY_MAX {
        return Err(fault());
    }
    m.length = body.len();
    m.sha256 = digest(body);
    validate_manifest(&m)?;
    // Includes payload temp, manifest replacement temp and terminal receipt.
    let reserve = body.len() as u64 + 2 * MANIFEST_MAX as u64 + 2048;
    if footprint(&root)?.saturating_add(reserve) > TOTAL_MAX {
        return Err(fault());
    }
    let payload = path(&root, &m.id, "body")?;
    if payload.exists() || path(&root, &m.id, "json")?.exists() {
        return Err(fault());
    }
    atomic(&root, &payload, body)?;
    // The immutable body is durable before the send intent, which consumes the
    // original slot even if the process dies before its first POST.
    write_manifest(&root, &m)?;
    Ok(m)
}
fn terminal(support: PathBuf, m: Manifest, reason: Reason, now: u64) -> Result<()> {
    let root = dir(&support);
    prune_receipts(&root, now)?;
    let receipt = Receipt {
        outcome: if reason == Reason::Resolved {
            "resolved"
        } else {
            "unknown_outcome_unresolved"
        }
        .into(),
        reason,
        entities: m.entities.len(),
        age_hours: now.saturating_sub(m.created) / 3600,
        time_day: now / 86400,
        attempts: m.posts.saturating_sub(1),
        hash8: m.id[..8].into(),
    };
    let receipt_path = root.join(format!("{}.receipt", &m.id[..8]));
    if !receipt_path.exists() {
        atomic(&root, &receipt_path, &serde_json::to_vec(&receipt)?)?;
    }
    // Receipt AND existing bounded money release latch precede deletion. A
    // failed commit never evicts an unresolved body to make room for a send.
    for extension in ["json", "body", "json.tmp", "body.tmp"] {
        match fs::remove_file(path(&root, &m.id, extension)?) {
            Ok(()) => (),
            Err(e) if e.kind() == ErrorKind::NotFound => (),
            Err(e) => return Err(e.into()),
        }
    }
    sync_dir(&root)?;
    let mut unresolved = 0_u64;
    for entry in fs::read_dir(&root)? {
        let file = entry?.path();
        if file.extension().and_then(|s| s.to_str()) == Some("receipt") {
            let saved: Receipt = serde_json::from_slice(&read_capped(&file, 1024)?)?;
            unresolved += u64::from(saved.outcome == "unknown_outcome_unresolved");
        }
    }
    let status = serde_json::json!({"unknown_outcome_unresolved":unresolved,
        "active_batches":load(&root)?.len(), "time_day":now / 86400});
    atomic(&root, &root.join("status"), &serde_json::to_vec(&status)?)?;
    crate::local_resource_diagnostics::claude_money_unknown_outcome(&receipt);
    Ok(())
}

type Prepared = (Manifest, Vec<u8>, money::ShadowReservation);

pub(super) struct Ticket<T> {
    receiver: Receiver<Result<T>>,
}
impl<T> Ticket<T> {
    pub fn take(&self) -> Result<Option<T>> {
        match self.receiver.try_recv() {
            Ok(result) => result.map(Some),
            Err(TryRecvError::Empty) => Ok(None),
            Err(_) => Err(fault()),
        }
    }
}
fn job<T: Send + 'static>(
    operation: impl FnOnce() -> Result<T> + Send + 'static,
) -> Result<Ticket<T>> {
    Ok(Ticket {
        receiver: store::recovery_job(IO_FUNDS, move || operation().map_err(|_| fault()))
            .ok_or_else(fault)?,
    })
}
pub(super) async fn wait<T>(ticket: Ticket<T>) -> Result<T> {
    std::future::poll_fn(move |_| match ticket.take() {
        Ok(Some(value)) => std::task::Poll::Ready(Ok(value)),
        Ok(None) => std::task::Poll::Pending,
        Err(e) => std::task::Poll::Ready(Err(e)),
    })
    .await
}

#[derive(Default)]
struct Catalog {
    fault: bool,
    awaiting_ack: BTreeSet<String>,
    funds: Vec<money::ShadowReservation>,
    entries: Vec<Manifest>,
    loading: Option<Ticket<Vec<Manifest>>>,
}
static CATALOGS: Mutex<BTreeMap<PathBuf, Catalog>> = Mutex::new(BTreeMap::new());

/// Called before activity/token networking, including when the source's
/// network backoff would otherwise skip its finish. Expiry does not need HTTP.
pub(super) fn startup(support: &Path, binding: &str, now: u64) -> Result<bool> {
    let result = startup_inner(support, binding, now);
    if let Err(error) = &result {
        faulted(support, error);
    }
    result
}
fn startup_inner(support: &Path, binding: &str, now: u64) -> Result<bool> {
    if CATALOGS
        .lock()
        .map_err(|_| fault())?
        .get(support)
        .is_some_and(|c| c.fault)
    {
        return Err(fault());
    }
    let (updates, waiting) = {
        let mut outcomes = OUTCOMES.lock().map_err(|_| fault())?;
        let mut updates = Vec::new();
        let mut waiting = false;
        if let Some(tickets) = outcomes.get_mut(support) {
            while let Some(ticket) = tickets.first() {
                let Some(updated) = ticket.take()? else {
                    waiting = true;
                    break;
                };
                updates.push(updated);
                tickets.remove(0);
            }
            if !waiting {
                outcomes.remove(support);
            }
        }
        (updates, waiting)
    };
    for updated in updates {
        replace(support, updated)?;
    }
    if waiting {
        return Ok(false);
    }
    let mut catalogs = CATALOGS.lock().map_err(|_| fault())?;
    if !catalogs.contains_key(support) {
        let root = dir(support);
        let ticket = job(move || load(&root))?;
        catalogs.insert(
            support.to_path_buf(),
            Catalog {
                fault: false,
                awaiting_ack: BTreeSet::new(),
                funds: Vec::new(),
                entries: Vec::new(),
                loading: Some(ticket),
            },
        );
    }
    let catalog = catalogs.get_mut(support).unwrap();
    if let Some(ticket) = &catalog.loading {
        let Some(entries) = ticket.take()? else {
            return Ok(false);
        };
        let charge = entries
            .iter()
            .try_fold(0_usize, |n, m| {
                serde_json::to_vec(m)
                    .ok()
                    .and_then(|v| n.checked_add(v.len().saturating_mul(4)))
            })
            .ok_or_else(fault)?;
        let funds = money::ShadowReservation::admit(charge).ok_or_else(fault)?;
        catalog.entries = entries;
        catalog.funds.clear();
        catalog.funds.push(funds);
        catalog.loading = None;
    }
    let (legacy_receipt, legacy) = money::recovery_legacy_receipt(support);
    match legacy_receipt {
        money::MoneyReceipt::Pending => return Ok(false),
        money::MoneyReceipt::Refused => return Err(fault()),
        money::MoneyReceipt::Ready => (),
    }
    let legacy = legacy
        .into_iter()
        .filter(|id| !catalog.entries.iter().any(|m| &m.id == id))
        .collect::<Vec<_>>();
    if !legacy.is_empty() {
        let support = support.to_path_buf();
        catalog.loading = Some(job(move || {
            let root = dir(&support);
            private_dir(&root)?;
            sync_dir(&support)?;
            for id in legacy {
                let m = Manifest {
                    id,
                    binding: "00".repeat(32),
                    context: String::new(),
                    created: now,
                    deadline: now.saturating_add(DEADLINE),
                    posts: 1,
                    not_before: 0,
                    length: 0,
                    sha256: "00".repeat(32),
                    head_cas: false,
                    ack_saved: false,
                    entities: Vec::new(),
                    terminal: Some(Reason::CorruptCustody),
                };
                write_manifest(&root, &m)?;
            }
            load(&root)
        })?);
        return Ok(false);
    }
    let pending = catalog.entries.iter().find_map(|m| {
        let reason = m.terminal.or_else(|| {
            if money::recovery_released(support, &m.id) {
                Some(Reason::Released)
            } else if m.binding != binding {
                Some(Reason::BindingLost)
            } else if now >= m.deadline {
                Some(Reason::Expired)
            } else if m.posts >= 4 {
                Some(Reason::Exhausted)
            } else {
                None
            }
        });
        reason.map(|reason| (m.clone(), reason))
    });
    drop(catalogs);
    if let Some((m, reason)) = pending {
        match money::recovery_finish_receipt(support, &m.id, now, reason == Reason::Resolved) {
            money::MoneyReceipt::Ready => (),
            money::MoneyReceipt::Pending => return Ok(false),
            money::MoneyReceipt::Refused => return Err(fault()),
        }
        // The existing writer completes this before another startup is ready.
        let support_owned = support.to_path_buf();
        let ticket = job(move || {
            terminal(support_owned.clone(), m, reason, now)?;
            load(&dir(&support_owned))
        })?;
        CATALOGS
            .lock()
            .map_err(|_| fault())?
            .get_mut(support)
            .unwrap()
            .loading = Some(ticket);
        return Ok(false);
    }
    Ok(true)
}

pub(crate) fn blocked_file(support: &Path, key: &str, root: Option<&str>) -> bool {
    let Ok(catalogs) = CATALOGS.lock() else {
        return true;
    };
    let Some(catalog) = catalogs.get(support) else {
        return true;
    };
    catalog.loading.is_some()
        || catalog.entries.iter().any(|m| {
            !m.ack_saved
                && m.entities
                    .iter()
                    .any(|e| e.files.iter().any(|f| f == key) || root == Some(e.root.as_str()))
        })
}
pub(super) fn add(support: &Path, m: Manifest) -> Result<()> {
    let mut catalogs = CATALOGS.lock().map_err(|_| fault())?;
    let catalog = catalogs.get_mut(support).ok_or_else(fault)?;
    if !catalog.entries.iter().any(|old| old.id == m.id) {
        let charge = serde_json::to_vec(&m)?.len().saturating_mul(4);
        let funds = money::ShadowReservation::admit(charge).ok_or_else(fault)?;
        catalog.entries.push(m);
        catalog.funds.push(funds);
    }
    Ok(())
}
pub(super) fn due(support: &Path, now: u64) -> Result<Vec<Manifest>> {
    let catalogs = CATALOGS.lock().map_err(|_| fault())?;
    let catalog = catalogs.get(support).ok_or_else(fault)?;
    Ok(catalog
        .entries
        .iter()
        .filter(|m| {
            m.terminal.is_none()
                && !m.ack_saved
                && m.posts < 4
                && now < m.deadline
                && now >= m.not_before
                && now
                    >= m.created
                        .saturating_add(REPLAY_AT[usize::from(m.posts - 1)])
        })
        .cloned()
        .collect())
}
pub(super) fn capture_ticket(
    support: &Path,
    m: Manifest,
    bytes: Vec<u8>,
    funds: money::ShadowReservation,
) -> Result<Ticket<Prepared>> {
    let support = support.to_path_buf();
    job(move || {
        let m = capture(support, m, &bytes)?;
        Ok((m, bytes, funds))
    })
}
pub(super) fn replay_ticket(support: &Path, mut m: Manifest, now: u64) -> Result<Ticket<Prepared>> {
    let support = support.to_path_buf();
    job(move || {
        let root = dir(&support);
        let funds = money::ShadowReservation::admit(BODY_MAX).ok_or_else(fault)?;
        let bytes = read_capped(&path(&root, &m.id, "body")?, BODY_MAX)?;
        if bytes.len() != m.length
            || digest(&bytes) != m.sha256
            || now >= m.deadline
            || m.posts >= 4
        {
            return Err(fault());
        }
        m.posts += 1;
        write_manifest(&root, &m)?;
        Ok((m, bytes, funds))
    })
}
pub(super) fn outcome_ticket(
    support: &Path,
    mut m: Manifest,
    reason: Option<Reason>,
    not_before: u64,
) -> Result<Ticket<Manifest>> {
    let root = dir(support);
    m.terminal = reason;
    m.not_before = m.not_before.max(not_before);
    job(move || {
        write_manifest(&root, &m)?;
        Ok(m)
    })
}
pub(super) fn replace(support: &Path, m: Manifest) -> Result<()> {
    let mut catalogs = CATALOGS.lock().map_err(|_| fault())?;
    let slot = catalogs
        .get_mut(support)
        .and_then(|c| c.entries.iter_mut().find(|old| old.id == m.id))
        .ok_or_else(fault)?;
    *slot = m;
    Ok(())
}
pub(super) fn ack_saved(support: &Path, progress: &SnapshotUploadProgress) -> Result<()> {
    let mut catalogs = CATALOGS.lock().map_err(|_| fault())?;
    let Some(catalog) = catalogs.get_mut(support) else {
        return Ok(());
    };
    for m in &mut catalog.entries {
        if !m.ack_saved
            && catalog.awaiting_ack.contains(&m.id)
            && m.entities
                .iter()
                .all(|e| progress.contains_body(&e.fingerprint, &e.witness))
        {
            m.ack_saved = true;
            let ticket = outcome_ticket(support, m.clone(), m.terminal, m.not_before)?;
            OUTCOMES
                .lock()
                .map_err(|_| fault())?
                .entry(support.to_path_buf())
                .or_default()
                .push(ticket);
        }
    }
    Ok(())
}

pub(super) fn discard_unsaved_acks(support: &Path) {
    if let Ok(mut catalogs) = CATALOGS.lock() {
        if let Some(catalog) = catalogs.get_mut(support) {
            catalog.awaiting_ack.clear();
        }
    }
}

pub(super) fn resolve_saved(
    support: &Path,
    _progress: &SnapshotUploadProgress,
    now: u64,
) -> Result<()> {
    let mut catalogs = CATALOGS.lock().map_err(|_| fault())?;
    let Some(catalog) = catalogs.get_mut(support) else {
        return Ok(());
    };
    for m in &mut catalog.entries {
        if m.terminal.is_none() && m.ack_saved {
            // This in-memory mark is reached only AFTER ACK and selected saves.
            // Startup commits the release latch and count-only terminal receipt.
            m.terminal = Some(Reason::Resolved);
            m.not_before = now;
            let ticket = outcome_ticket(support, m.clone(), Some(Reason::Resolved), now)?;
            OUTCOMES
                .lock()
                .map_err(|_| fault())?
                .entry(support.to_path_buf())
                .or_default()
                .push(ticket);
        }
    }
    Ok(())
}

/// Recovery dispatch table. Entity outcomes are handled by the ordinary ACK
/// machine after full identity/head/witness validation. HTTP never supplies a
/// covering proof, and retained bodies never enter adaptive split/auth/gzip.
pub(super) fn error_transition(error: &anyhow::Error, now: u64) -> (Option<Reason>, u64) {
    if let Some(shed) = error.downcast_ref::<UploadShed>() {
        return (
            None,
            now.saturating_add(shed.retry_after.map_or(300, |d| d.as_secs())),
        );
    }
    if is_literal_version_skew(error) {
        return (Some(Reason::VersionSkew), 0);
    }
    if error.downcast_ref::<BatchRejected>().is_some() {
        return (Some(Reason::Validation), 0);
    }
    match error
        .downcast_ref::<UploadFailureDiagnostics>()
        .and_then(|e| e.batch_http_status())
    {
        Some(409 | 412) => (Some(Reason::HttpConflict), 0),
        Some(413) => (Some(Reason::Oversize), 0),
        // Auth failures, transport errors and invalid/incomplete ACKs carry no
        // evidence of the original POST's outcome. They spend the same slots.
        _ => (None, now),
    }
}

#[cfg(test)]
pub(super) fn forget(support: &Path) {
    CATALOGS.lock().unwrap().remove(support);
}

impl crate::snapshots::ClaudeHistoryEmissionItem for Entity {
    fn source_file_fingerprint(&self) -> Option<&str> {
        self.source_fingerprint.as_deref()
    }
    fn immutable_unknown_replay(&self) -> bool {
        true
    }
}

pub(super) fn manifest(
    support: &Path,
    index: &ScanIndex,
    request: &SnapshotBatchRequest,
    binding: String,
    head_cas: bool,
) -> Result<Manifest> {
    let head_cas = head_cas
        || request
            .snapshots
            .iter()
            .any(|item| item.cache_observations.is_some());
    let _metadata_funds = money::ShadowReservation::admit(4 * MANIFEST_MAX).ok_or_else(fault)?;
    let mut entities = Vec::new();
    let mut metadata_bytes = 0_usize;
    let mut lineage = Sha256::new();
    lineage.update(binding.as_bytes());
    lineage.update([u8::from(head_cas)]);
    for item in &request.snapshots {
        let root = money::family_root(item).to_string();
        let mut files = Vec::new();
        for key in index
            .files
            .keys()
            .filter(|key| money::logical_family_member(index, key).is_some_and(|(r, _)| r == root))
        {
            metadata_bytes = metadata_bytes.saturating_add(key.len());
            if files.len() >= 256 || key.len() > 4096 || metadata_bytes > MANIFEST_MAX / 2 {
                return Err(fault());
            }
            files.push(key.clone());
        }
        lineage.update((item.source_session_id.len() as u64).to_be_bytes());
        lineage.update(item.source_session_id.as_bytes());
        lineage.update(item.snapshot_fingerprint.as_bytes());
        if let Some(fp) = &item.source_file_fingerprint {
            lineage.update(fp.as_bytes());
        }
        entities.push(Entity {
            root,
            session: item.source_session_id.clone(),
            fingerprint: item.snapshot_fingerprint.clone(),
            witness: snapshot_upload_body_witness(item),
            witness_version: crate::snapshot_client::snapshot_ack_body_witness_version(item)?,
            files,
            source_fingerprint: item.source_file_fingerprint.clone(),
            cache_patch: item.cache_observations.clone(),
            literal: item.usage_accounting_contract.as_deref()
                == Some(money::REQUEST_OWNED_CONTRACT),
        });
    }
    let now = now(support);
    Ok(Manifest {
        id: format!("{:x}", lineage.finalize()),
        binding,
        context: index.recovery_upload_context().to_owned(),
        created: now,
        deadline: now.saturating_add(DEADLINE),
        posts: 1,
        not_before: now,
        length: 0,
        sha256: String::new(),
        head_cas,
        ack_saved: false,
        entities,
        terminal: None,
    })
}

#[derive(Default)]
pub(super) enum SendState {
    #[default]
    Empty,
    Reserving(Manifest, Vec<u8>, money::ShadowReservation),
    Ready(Manifest, Vec<u8>, money::ShadowReservation),
}

pub(super) async fn captured(support: &Path, state: &mut SendState) -> Result<()> {
    let ticket = match std::mem::take(state) {
        SendState::Reserving(m, body, funds) => {
            std::future::poll_fn(|_| match money::recovery_reserve_receipt(support, &m.id) {
                money::MoneyReceipt::Ready => std::task::Poll::Ready(Ok(())),
                money::MoneyReceipt::Pending => std::task::Poll::Pending,
                money::MoneyReceipt::Refused => std::task::Poll::Ready(Err(fault())),
            })
            .await
            .inspect_err(|error| faulted(support, error))?;
            capture_ticket(support, m, body, funds)?
        }
        _ => return Err(fault()),
    };
    let (m, bytes, funds) = wait(ticket)
        .await
        .inspect_err(|error| faulted(support, error))?;
    add(support, m.clone())?;
    *state = SendState::Ready(m, bytes, funds);
    Ok(())
}

/// Return Pending to the async owner instead of waiting on disk under its lock.
/// Once ready, send the retained wire bytes directly. Ordinary uploader retry,
/// auth fallback, bisection and gzip are never entered for this episode.
#[allow(clippy::too_many_arguments)]
pub(super) fn initial_post(
    support: &Path,
    index: &mut ScanIndex,
    client: &SnapshotApiClient,
    token: &str,
    request: &SnapshotBatchRequest,
    binding: &str,
    head_cas: bool,
    state: &mut SendState,
) -> Result<crate::snapshot_client::SnapshotBatchResponse> {
    if matches!(state, SendState::Empty) {
        let m = manifest(support, index, request, binding.to_owned(), head_cas)?;
        if CATALOGS
            .lock()
            .map_err(|_| fault())?
            .get(support)
            .is_some_and(|c| {
                c.entries.iter().any(|old| {
                    !old.ack_saved
                        && old.entities.iter().any(|e| {
                            m.entities
                                .iter()
                                .any(|new| new.root == e.root || new.session == e.session)
                        })
                })
            })
        {
            return Err(Deferred {
                reason: None,
                not_before: now(support),
                route_unavailable: false,
            }
            .into());
        }
        if money::recovery_released(support, &m.id) {
            let roots = m
                .entities
                .iter()
                .map(|e| (e.root.as_str(), e.files.as_slice()))
                .collect::<Vec<_>>();
            if m.entities.iter().any(|e| e.literal)
                && !index.recovery_history_permitted(support, &roots)
            {
                return Err(Deferred {
                    reason: None,
                    not_before: now(support),
                    route_unavailable: false,
                }
                .into());
            }
            let mut permitted = request.snapshots.clone();
            index.retain_claude_history_emission_permitted(&mut permitted);
            if permitted.len() != request.snapshots.len() {
                return Err(Deferred {
                    reason: None,
                    not_before: now(support),
                    route_unavailable: false,
                }
                .into());
            }

            // A terminal lineage can make normal offers, but never acquire a
            // fresh UNKNOWN allowance through reserialization or restart.
            let _body_funds = money::ShadowReservation::admit(BODY_MAX).ok_or_else(fault)?;
            let body = encode(request, m.head_cas)?;
            return client.upload_recovery_bytes(token, request, head_cas, &body);
        }
        let funds = money::ShadowReservation::admit(BODY_MAX).ok_or_else(fault)?;
        let body = encode(request, m.head_cas)?;
        *state = SendState::Reserving(m, body, funds);
        return Err(Pending.into());
    }
    let SendState::Ready(m, body, _funds) = std::mem::take(state) else {
        return Err(fault());
    };
    let roots = m
        .entities
        .iter()
        .map(|e| (e.root.as_str(), e.files.as_slice()))
        .collect::<Vec<_>>();
    if m.entities.iter().any(|e| e.literal) && !index.recovery_history_permitted(support, &roots) {
        return Err(Deferred {
            reason: None,
            not_before: now(support),
            route_unavailable: false,
        }
        .into());
    }
    let mut permitted = request.snapshots.clone();
    index.retain_claude_history_emission_permitted(&mut permitted);
    if permitted.len() != request.snapshots.len() {
        return Err(Deferred {
            reason: None,
            not_before: now(support),
            route_unavailable: false,
        }
        .into());
    }
    let result = client
        .upload_recovery_bytes(token, request, head_cas, &body)
        .and_then(|response| {
            validate_ack(&m, &response)?;
            Ok(response)
        });
    if result
        .as_ref()
        .err()
        .and_then(|e| e.downcast_ref::<UploadShed>())
        .is_some_and(|s| s.request_owned_route_unavailable)
    {
        money::note_route_pause(support, index, true);
    }
    if result.as_ref().is_ok_and(|response| !response.disabled) {
        CATALOGS
            .lock()
            .map_err(|_| fault())?
            .get_mut(support)
            .ok_or_else(fault)?
            .awaiting_ack
            .insert(m.id.clone());
    }
    // Outcome writes are awaited by the async owner, including Retry-After.
    // Keep no second copy of the retained payload after the one physical POST.
    let (reason, not_before) = result.as_ref().err().map_or(
        (
            result
                .as_ref()
                .ok()
                .filter(|r| r.disabled)
                .map(|_| Reason::Disabled),
            now(support),
        ),
        |e| error_transition(e, now(support)),
    );
    let ticket = outcome_ticket(support, m, reason, not_before)?;
    OUTCOMES
        .lock()
        .map_err(|_| fault())?
        .entry(support.to_path_buf())
        .or_default()
        .push(ticket);
    match result {
        Ok(response) => Ok(response),
        Err(error) => Err(Deferred {
            reason,
            not_before,
            route_unavailable: error
                .downcast_ref::<UploadShed>()
                .is_some_and(|s| s.request_owned_route_unavailable),
        }
        .into()),
    }
}

#[derive(Debug)]
pub(super) struct Pending;
impl std::fmt::Display for Pending {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("request money recovery capture pending")
    }
}
impl std::error::Error for Pending {}
static OUTCOMES: Mutex<BTreeMap<PathBuf, Vec<Ticket<Manifest>>>> = Mutex::new(BTreeMap::new());
pub(super) async fn outcomes(support: &Path) -> Result<()> {
    let tickets = OUTCOMES
        .lock()
        .map_err(|_| fault())?
        .remove(support)
        .unwrap_or_default();
    for ticket in tickets {
        replace(
            support,
            wait(ticket)
                .await
                .inspect_err(|error| faulted(support, error))?,
        )?;
    }
    Ok(())
}
fn encode(request: &SnapshotBatchRequest, head_cas: bool) -> Result<Vec<u8>> {
    let bytes = if head_cas {
        crate::snapshot_retry::encode_json(&request.wire_with_head_cas(), BODY_MAX)?
    } else {
        crate::snapshot_retry::encode_json(request, BODY_MAX)?
    };
    if bytes.len() > BODY_MAX {
        return Err(fault());
    }
    Ok(bytes)
}

/// The production LiteralGuard has not yet been composed into this branch.
/// Fail closed until owner B supplies it; this is NOT a second implementation
/// of that guard. Tests below exercise the integration's required contract.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum LiteralPermit {
    Permit,
    DenyAll,
    Unavailable,
}
pub(super) fn current_literal_guard(_index: &ScanIndex, _m: &Manifest) -> LiteralPermit {
    #[cfg(test)]
    if let Some(permit) = TEST_LITERAL_GUARD.with(std::cell::Cell::get) {
        return permit;
    }
    LiteralPermit::Unavailable
}
#[cfg(test)]
thread_local! { static TEST_LITERAL_GUARD: std::cell::Cell<Option<LiteralPermit>> = const { std::cell::Cell::new(None) }; }

pub(super) fn admitted(
    index: &mut ScanIndex,
    support: &Path,
    binding: &str,
    m: &Manifest,
    guard: LiteralPermit,
) -> Result<bool> {
    if m.binding != binding
        || m.context != index.recovery_upload_context()
        || !money::request_owned_live(support)
    {
        return Ok(false);
    }
    let roots = m
        .entities
        .iter()
        .map(|e| (e.root.as_str(), e.files.as_slice()))
        .collect::<Vec<_>>();
    if !index.recovery_history_permitted(support, &roots) {
        return Ok(false);
    }
    let mut entities = m.entities.clone();
    index.retain_claude_history_emission_permitted(&mut entities);
    if entities.len() != m.entities.len() {
        return Ok(false);
    }
    Ok(guard == LiteralPermit::Permit)
}

pub(super) fn validate_ack(
    m: &Manifest,
    response: &crate::snapshot_client::SnapshotBatchResponse,
) -> Result<()> {
    response.validate_recovery_ack(
        m.entities.iter().map(|e| {
            (
                e.session.as_str(),
                e.fingerprint.as_str(),
                e.witness_version,
                e.witness.as_str(),
            )
        }),
        m.head_cas,
    )
}

fn apply_ack(
    m: &Manifest,
    response: &crate::snapshot_client::SnapshotBatchResponse,
    progress: &mut SnapshotUploadProgress,
) {
    for e in &m.entities {
        if let Some(reference) = response
            .accepted_entities
            .iter()
            .chain(&response.unchanged_entities)
            .find(|r| r.source_session_id == e.session && r.snapshot_fingerprint == e.fingerprint)
        {
            if reference.unchanged_basis.is_some() {
                progress.hold_unstored_body(&e.fingerprint, &e.witness);
            } else {
                progress.record_body(&e.fingerprint, &e.witness);
                if let Some(patch) = &e.cache_patch {
                    let key = cache_session_key(&e.session);
                    let state = crate::snapshots::cache_state_from_patch(
                        progress.accepted_cache_states.get(&key),
                        patch,
                    );
                    progress.accepted_cache_states.insert(key, state);
                }
            }
            if let Some(etag) = &reference.head_etag {
                progress
                    .accepted_cache_heads
                    .insert(cache_session_key(&e.session), etag.clone());
            } else {
                progress
                    .accepted_cache_heads
                    .remove(&cache_session_key(&e.session));
            }
        } else if let Some(rejected) = response
            .rejected_entities
            .iter()
            .find(|r| r.source_session_id == e.session && r.snapshot_fingerprint == e.fingerprint)
        {
            match rejected.safe_reason() {
                "usage_decrease_held_for_review" => progress.quarantine_held_body(
                    &e.fingerprint,
                    &e.witness,
                    SnapshotHoldKind::Held,
                ),
                "usage_decrease_refused_after_review" => progress.quarantine_held_body(
                    &e.fingerprint,
                    &e.witness,
                    SnapshotHoldKind::Refused,
                ),
                _ if rejected.permanent => progress.quarantine_permanent_body(
                    &e.fingerprint,
                    &e.witness,
                    rejected.safe_reason(),
                ),
                _ => progress.quarantine_retryable_body(&e.fingerprint, &e.witness),
            }
        } else {
            progress.quarantine_retryable_body(&e.fingerprint, &e.witness);
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn replay_due(
    support: &Path,
    index: &mut ScanIndex,
    progress: &mut SnapshotUploadProgress,
    progress_path: &Path,
    client: &SnapshotApiClient,
    device: &LocalDeviceBinding,
    secret: &str,
    machine: &str,
    namespace: &str,
    authority: impl Fn() -> Result<()>,
) -> Result<()> {
    let binding = binding(namespace, client.recovery_origin(), machine, "");
    for m in due(support, now(support))? {
        let guard = current_literal_guard(index, &m);
        if !admitted(index, support, &binding, &m, guard)? {
            if guard == LiteralPermit::DenyAll {
                let updated = wait(outcome_ticket(
                    support,
                    m,
                    Some(Reason::RevisionDowngrade),
                    0,
                )?)
                .await?;
                replace(support, updated)?;
            }
            continue;
        }
        authority()?;
        let token = client.issue_relay_token(device, secret, SnapshotSource::ClaudeCode)?;
        // Counter save and payload read share the bounded money writer. A
        // crash at or after this save consumes the same slot on restart.
        let (m, bytes, _body_funds) = wait(replay_ticket(support, m, now(support))?).await?;
        replace(support, m.clone())?;
        authority()?;
        let guard = current_literal_guard(index, &m);
        if !admitted(index, support, &binding, &m, guard)? {
            let mut cancelled = m;
            cancelled.posts -= 1;
            let updated = wait(outcome_ticket(support, cancelled, None, now(support))?).await?;
            replace(support, updated)?;
            continue;
        }
        let request = SnapshotBatchRequest {
            schema_version: SNAPSHOT_SCHEMA_VERSION,
            source: "claude_code".into(),
            machine_id: machine.into(),
            collector_version: None,
            snapshots: Vec::new(),
            upload_policy: SnapshotUploadPolicy::default(),
            client_report: crate::client_report::ClientReport::empty(),
        };
        let result = client
            .upload_recovery_bytes(&token, &request, m.head_cas, &bytes)
            .and_then(|response| {
                validate_ack(&m, &response)?;
                authority()?;
                Ok(response)
            });
        drop(bytes);
        let mut m = m;
        let (reason, not_before) = match result {
            Ok(response) if !response.disabled => {
                let previous = progress.clone();
                apply_ack(&m, &response, progress);
                #[cfg(test)]
                crate::snapshot_sync::tests::permanent_finish_pipeline_tests::p2a_before_ack_save_for_test(progress_path);
                if progress.save(progress_path).is_err() {
                    *progress = previous;
                    return Err(SnapshotLocalStateRejected {
                        operation: "save recovery upload checkpoint",
                    }
                    .into());
                }
                m.ack_saved = true;
                // Selected save occurs in the ordinary finish. No debt or
                // history stamp can be retired by this in-memory ACK alone.
                (None, m.deadline)
            }
            Ok(_) => (Some(Reason::Disabled), 0),
            Err(error) => {
                let transition = error_transition(&error, now(support));
                if let Some(reason) = transition.0 {
                    let previous = progress.clone();
                    for e in &m.entities {
                        progress.quarantine_transient_body(
                            &e.fingerprint,
                            &e.witness,
                            now(support).saturating_add(1800),
                        );
                        if reason == Reason::VersionSkew {
                            progress
                                .quarantined_fingerprints
                                .get_mut(&e.fingerprint)
                                .unwrap()
                                .version_skew_attempts = 1;
                        }
                    }
                    if progress.save(progress_path).is_err() {
                        *progress = previous;
                        return Err(fault());
                    }
                }
                transition
            }
        };
        let updated = wait(outcome_ticket(support, m, reason, not_before)?).await?;
        replace(support, updated)?;
    }
    Ok(())
}

#[cfg(test)]
pub(super) struct TestGuard(Option<LiteralPermit>);
#[cfg(test)]
pub(super) fn guard_for_test(permit: LiteralPermit) -> TestGuard {
    TestGuard(TEST_LITERAL_GUARD.with(|value| value.replace(Some(permit))))
}
#[cfg(test)]
impl Drop for TestGuard {
    fn drop(&mut self) {
        TEST_LITERAL_GUARD.with(|value| value.set(self.0));
    }
}
#[cfg(test)]
pub(super) fn active_for_test(support: &Path) -> Vec<Manifest> {
    CATALOGS
        .lock()
        .unwrap()
        .get(support)
        .map_or_else(Vec::new, |c| c.entries.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn specimen(created: u64) -> (Manifest, Vec<u8>) {
        let bytes = br#"{"schema_version":1,"snapshots":[{"synthetic":true}]}"#.to_vec();
        (
            Manifest {
                id: "ab".repeat(32),
                binding: "cd".repeat(32),
                context: "context".into(),
                created,
                deadline: created + DEADLINE,
                posts: 1,
                not_before: created,
                length: bytes.len(),
                sha256: digest(&bytes),
                head_cas: false,
                ack_saved: false,
                entities: vec![Entity {
                    root: "synthetic-root".into(),
                    session: "synthetic-session".into(),
                    fingerprint: "ef".repeat(32),
                    witness: "12".repeat(32),
                    witness_version: Some(7),
                    files: vec!["/fixture/file.jsonl".into()],
                    source_fingerprint: Some("34".repeat(32)),
                    literal: true,
                    cache_patch: None,
                }],
                terminal: None,
            },
            bytes,
        )
    }
    #[test]
    #[serial_test::serial(claude_request_money_shadow)]
    fn durable_exact_bytes_counter_restart_deadline_and_private_receipt() {
        let scratch = crate::test_scratch::ScratchDir::new("money-unknown-custody");
        let (m, bytes) = specimen(1000);
        let m = capture(scratch.to_path_buf(), m, &bytes).unwrap();
        let root = dir(&scratch);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for entry in fs::read_dir(&root).unwrap() {
                assert_eq!(
                    entry.unwrap().metadata().unwrap().permissions().mode() & 0o777,
                    0o600
                );
            }
        }
        for (slot, elapsed) in REPLAY_AT.into_iter().enumerate() {
            let before = load(&root).unwrap().pop().unwrap();
            assert_eq!(before.posts, slot as u8 + 1);
            let (after, replay, _funds) = money_resume::drive_for_test(wait(
                replay_ticket(&scratch, before, 1000 + elapsed).unwrap(),
            ))
            .unwrap();
            assert_eq!(after.posts, slot as u8 + 2);
            assert_eq!(
                replay, bytes,
                "a restart replays exact final JSON, including timestamps and CAS"
            );
        }
        let exhausted = load(&root).unwrap().pop().unwrap();
        assert!(money_resume::drive_for_test(wait(
            replay_ticket(&scratch, exhausted.clone(), 23000).unwrap()
        ))
        .is_err());
        terminal(scratch.to_path_buf(), exhausted, Reason::Exhausted, 23000).unwrap();
        assert!(!path(&root, &m.id, "body").unwrap().exists());
        let receipt: serde_json::Value =
            serde_json::from_slice(&fs::read(root.join("abababab.receipt")).unwrap()).unwrap();
        assert_eq!(receipt["outcome"], "unknown_outcome_unresolved");
        assert_eq!(receipt["attempts"], 3);
        assert_eq!(receipt.as_object().unwrap().len(), 7);
        let encoded = receipt.to_string();
        for secret in [
            "synthetic-root",
            "synthetic-session",
            "/fixture/",
            &m.sha256,
            &m.binding,
        ] {
            assert!(!encoded.contains(secret));
        }
        let (mut expired, body) = specimen(1000);
        expired.id = "56".repeat(32);
        let expired = capture(scratch.to_path_buf(), expired, &body).unwrap();
        assert!(money_resume::drive_for_test(wait(
            replay_ticket(&scratch, expired, 1000 + DEADLINE).unwrap()
        ))
        .is_err());
        eprintln!("MONEY_UNKNOWN_CUSTODY exact_replay=true replays=3 restart_counter=true terminal_allowlist=true private_files=true");
    }
    #[test]
    fn custody_caps_include_stale_temps_and_corruption_never_reconstructs() {
        let scratch = crate::test_scratch::ScratchDir::new("money-unknown-caps");
        let root = dir(&scratch);
        private_dir(&root).unwrap();
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        options
            .open(root.join("occupied.tmp"))
            .unwrap()
            .set_len(TOTAL_MAX - 1024)
            .unwrap();
        let (m, body) = specimen(1000);
        assert!(capture(scratch.to_path_buf(), m.clone(), &body).is_err());
        assert!(
            !path(&root, &m.id, "body").unwrap().exists(),
            "reserve before an eligible POST"
        );
        fs::remove_file(root.join("occupied.tmp")).unwrap();
        let m = capture(scratch.to_path_buf(), m, &body).unwrap();
        let body_path = path(&root, &m.id, "body").unwrap();
        fs::write(&body_path, b"corrupt").unwrap();
        assert_eq!(
            load(&root).unwrap()[0].terminal,
            Some(Reason::CorruptCustody)
        );
        fs::remove_file(&body_path).unwrap();
        assert_eq!(
            load(&root).unwrap()[0].terminal,
            Some(Reason::CorruptCustody)
        );
    }
    #[test]
    fn complete_ack_partition_and_basis_override_exact_witness() {
        let (m, _) = specimen(1000);
        for basis in [
            None,
            Some("dominated_by_head"),
            Some("usage_identical"),
            Some("future_basis"),
        ] {
            let response: crate::snapshot_client::SnapshotBatchResponse = serde_json::from_value(serde_json::json!({
                "accepted":1,"sessions_reconciled":1,"session_ids":[],"disabled":false,"disabled_reason":null,
                "entity_ack_contract":"snapshot_entity_ack:v1", "accepted_entities":[],
                "unchanged_entities":[{"source_session_id":m.entities[0].session,
                    "snapshot_fingerprint":m.entities[0].fingerprint,"occurrence_count":1,
                    "body_witness_version":7,"body_witness_digest":m.entities[0].witness,"unchanged_basis":basis}],
                "rejected_entities":[],"conflict_entities":[] })).unwrap();
            // Any present basis, including a future basis, overrides an
            // echoed exact witness: it is resolved but never stored proof.
            validate_ack(&m, &response).unwrap();
            let mut progress = SnapshotUploadProgress::new(
                "test".into(),
                snapshot_quarantine_witness(SnapshotSource::ClaudeCode),
            );
            apply_ack(&m, &response, &mut progress);
            assert_eq!(
                progress
                    .accepted_body_witnesses
                    .contains_key(&m.entities[0].fingerprint),
                basis.is_none()
            );
            assert_eq!(
                progress.accepted_fingerprints.len(),
                usize::from(basis.is_none())
            );
        }
    }
}
