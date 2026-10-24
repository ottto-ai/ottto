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
// Matches the existing control carrier's hard slot cap. Together with the
// metadata and wire caps this also bounds one writer load's decoded graph.
const ACTIVE_MAX: usize = 16;
const RECEIPT_MAX: usize = 1024;
const RECEIPT_BYTES_MAX: u64 = 256 * 1024;
const DEADLINE: u64 = 24 * 3600;
const RECEIPT_TTL: u64 = 35 * 86400;
const REPLAY_AT: [u64; 3] = [300, 3600, 21600];
const IO_FUNDS: usize = 2 * BODY_MAX + 8 * MANIFEST_MAX;
const BODY_FUNDS: usize = BODY_MAX + 4 * MANIFEST_MAX;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct FileSelection {
    group: Option<String>,
    body: Option<String>,
    revision: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Entity {
    pub root: String,
    pub session: String,
    pub fingerprint: String,
    pub witness: String,
    pub witness_version: Option<u64>,
    pub files: Vec<String>,
    pub file_revisions: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub file_selections: Vec<FileSelection>,
    pub source_fingerprint: Option<String>,
    pub literal: bool,
    pub cache_patch: Option<crate::snapshots::CacheObservations>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Manifest {
    pub id: String,
    pub lineage: String,
    pub binding: String,
    pub context: String,
    pub policy: [u8; 32],
    pub created: u64,
    pub deadline: u64,
    /// Includes the original physical POST; 1 + at most three replays.
    pub posts: u8,
    pub slot: u8,
    pub not_before: u64,
    pub length: usize,
    pub sha256: String,
    pub head_cas: bool,
    pub ack_saved: bool,
    pub receipt_slot: Option<u16>,
    pub entities: Vec<Entity>,
    pub terminal: Option<Reason>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Reason {
    Exhausted,
    AdmissionDenied,
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
fn valid_digest(id: &str) -> bool {
    id.len() == 64 && id.bytes().all(|c| c.is_ascii_hexdigit())
}
fn valid_id(id: &str) -> bool {
    valid_digest(id)
        || id
            .split_once('-')
            .is_some_and(|(lineage, nonce)| valid_digest(lineage) && valid_digest(nonce))
}
fn id_lineage(id: &str) -> &str {
    id.split_once('-').map_or(id, |(lineage, _)| lineage)
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
    let mut filename = target.file_name().ok_or_else(fault)?.to_os_string();
    filename.push(".tmp");
    let staged = root.join(filename);
    // A crash before rename leaves an uncommitted stage. The authoritative
    // target (and its counter) is unchanged; replacing that stage cannot
    // consume or restore a POST slot. Never follow or truncate a foreign link.
    match fs::symlink_metadata(&staged) {
        Ok(meta) => {
            if !meta.is_file() {
                return Err(fault());
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::{MetadataExt, PermissionsExt};
                if meta.permissions().mode() & 0o777 != 0o600 || meta.nlink() != 1 {
                    return Err(fault());
                }
            }
        }
        Err(error) if error.kind() == ErrorKind::NotFound => (),
        Err(_) => return Err(fault()),
    }
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
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
        || !valid_digest(&m.lineage)
        || id_lineage(&m.id) != m.lineage
        || !valid_digest(&m.sha256)
        || !valid_digest(&m.binding)
        || m.terminal == Some(Reason::Resolved) && !m.ack_saved
        || m.posts == 0
        || m.posts > 4
        || m.slot > 3
        || m.length > BODY_MAX
        || m.length == 0
        || m.deadline != m.created.saturating_add(DEADLINE)
        || m.receipt_slot
            .is_some_and(|slot| usize::from(slot) >= RECEIPT_MAX)
        || m.entities.is_empty()
        || m.entities.len() > SNAPSHOT_BATCH_LIMIT
        || m.entities.iter().any(|e| {
            e.files.len() > 256
                || e.files.len() != e.file_revisions.len()
                || e.files.len() != e.file_selections.len()
                || e.file_selections.iter().any(|selection| {
                    !matches!(selection.revision, 2 | 3)
                        || selection.group.as_ref().is_some_and(|s| !valid_digest(s))
                        || selection.body.as_ref().is_some_and(|s| !valid_digest(s))
                })
                || e.file_revisions.iter().any(|r| r.len() > 256)
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
            if m.terminal != Some(Reason::CorruptCustody) {
                validate_manifest(&m)?;
            }
            Ok(m)
        })();
        let fallback_lineage = id_lineage(&id).to_owned();
        let mut m = decoded.unwrap_or_else(|_| Manifest {
            id,
            lineage: fallback_lineage,
            binding: "00".repeat(32),
            context: String::new(),
            policy: [0; 32],
            created: 0,
            deadline: DEADLINE,
            posts: 1,
            slot: 0,
            not_before: 0,
            length: 0,
            sha256: "00".repeat(32),
            head_cas: false,
            ack_saved: false,
            receipt_slot: None,
            entities: Vec::new(),
            terminal: Some(Reason::CorruptCustody),
        });
        let retirement_committed = m.terminal == Some(Reason::Resolved) && m.ack_saved
            || m.terminal.is_some()
                && m.receipt_slot.is_some_and(|slot| {
                    read_capped(&root.join(format!("receipt-{slot:04}.receipt")), 1024)
                        .ok()
                        .and_then(|bytes| serde_json::from_slice::<Receipt>(&bytes).ok())
                        .is_some_and(|receipt| {
                            receipt.outcome == "unknown_outcome_unresolved"
                                && Some(receipt.reason) == m.terminal
                                && receipt.hash8 == m.id[..8]
                        })
                });
        if m.terminal != Some(Reason::CorruptCustody) && !retirement_committed {
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
fn unwritten_receipts(root: &Path, active: &[Manifest]) -> usize {
    active
        .iter()
        .filter(|m| {
            m.receipt_slot.map_or(true, |slot| {
                !root.join(format!("receipt-{slot:04}.receipt")).exists()
            })
        })
        .count()
}
fn prune_receipts(root: &Path, now: u64, reserved: usize) -> Result<()> {
    let mut count = 0;
    let mut bytes = 0;
    for entry in fs::read_dir(root)? {
        let file = entry?.path();
        if file.extension().and_then(|s| s.to_str()) != Some("receipt") {
            continue;
        }
        let encoded = read_capped(&file, 1024)?;
        let receipt: Receipt = serde_json::from_slice(&encoded)?;
        if now / 86400 >= receipt.time_day.saturating_add(RECEIPT_TTL / 86400) {
            fs::remove_file(file)?;
        } else {
            count += 1;
            bytes += encoded.len() as u64;
        }
    }
    // Reserve a receipt for every admitted active batch, even at full custody.
    if count + reserved > RECEIPT_MAX || bytes + reserved as u64 * 1024 > RECEIPT_BYTES_MAX {
        return Err(fault());
    }
    Ok(())
}
fn capture(support: PathBuf, mut m: Manifest, body: &[u8]) -> Result<Manifest> {
    let root = dir(&support);
    private_dir(&root)?;
    sync_dir(&support)?;
    let active = load(&root)?;
    prune_receipts(&root, m.created, unwritten_receipts(&root, &active) + 1)?;
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
fn terminal(support: PathBuf, mut m: Manifest, reason: Reason, now: u64) -> Result<()> {
    let root = dir(&support);
    let active = load(&root)?;
    prune_receipts(&root, now, unwritten_receipts(&root, &active))?;
    if m.terminal != Some(reason) {
        m.terminal = Some(reason);
        write_manifest(&root, &m)?;
    }
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
    // Known outcomes have durable ACK/selected evidence. They must not spend
    // the 35-day unresolved-receipt quota on every ordinary successful POST.
    // UNKNOWN retirement still requires its individual receipt before deletion.
    if reason != Reason::Resolved {
        if m.receipt_slot.is_none() {
            let reserved = active
                .iter()
                .filter_map(|m| m.receipt_slot)
                .collect::<BTreeSet<_>>();
            let slot = (0..RECEIPT_MAX as u16)
                .find(|slot| {
                    !reserved.contains(slot)
                        && !root.join(format!("receipt-{slot:04}.receipt")).exists()
                })
                .ok_or_else(fault)?;
            m.receipt_slot = Some(slot);
            // Private slot reservation is durable before the count-only receipt.
            // A crash cannot merge hash-8 collisions or count this lineage twice.
            write_manifest(&root, &m)?;
        }
        let receipt_path = root.join(format!("receipt-{:04}.receipt", m.receipt_slot.unwrap()));
        if !receipt_path.exists() {
            atomic(&root, &receipt_path, &serde_json::to_vec(&receipt)?)?;
        }
    }
    // UNKNOWN's receipt AND existing bounded release latch precede deletion.
    // Known custody instead has its saved ACK and selected-save/expiry proof.
    // A failed commit never evicts an unresolved body to admit another send.
    for extension in ["body", "body.tmp", "json.tmp"] {
        match fs::remove_file(path(&root, &m.id, extension)?) {
            Ok(()) => (),
            Err(e) if e.kind() == ErrorKind::NotFound => (),
            Err(e) => return Err(e.into()),
        }
    }
    // Keep the authoritative retirement marker until payload deletion is
    // durable. Restart can finish it without inventing another unresolved
    // receipt, even if the payload is already gone.
    sync_dir(&root)?;
    match fs::remove_file(path(&root, &m.id, "json")?) {
        Ok(()) => (),
        Err(error) if error.kind() == ErrorKind::NotFound => (),
        Err(error) => return Err(error.into()),
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
    if reason != Reason::Resolved {
        crate::local_resource_diagnostics::claude_money_unknown_outcome(&receipt);
    }
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
struct CorruptBody(Manifest);
impl std::fmt::Debug for CorruptBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CorruptBody")
    }
}
impl std::fmt::Display for CorruptBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("request money retained payload unavailable")
    }
}
impl std::error::Error for CorruptBody {}
fn job<T: Send + 'static>(
    operation: impl FnOnce() -> Result<T> + Send + 'static,
) -> Result<Ticket<T>> {
    Ok(Ticket {
        receiver: store::recovery_job(IO_FUNDS, move || {
            let result = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(operation)) {
                Ok(result) => result,
                Err(_) => return Err(fault()),
            };
            result.map_err(|error| {
                if error.is::<CorruptBody>() {
                    error
                } else {
                    fault()
                }
            })
        })
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

#[cfg(test)]
thread_local! { static TRACE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) }; }
#[cfg(test)]
pub(super) struct TraceForTest(bool);
#[cfg(test)]
impl TraceForTest {
    pub fn enable() -> Self {
        Self(TRACE.with(|flag| flag.replace(true)))
    }
}
#[cfg(test)]
impl Drop for TraceForTest {
    fn drop(&mut self) {
        TRACE.with(|flag| flag.set(self.0));
    }
}
#[cfg(test)]
pub(super) fn tracing_for_test() -> bool {
    TRACE.with(std::cell::Cell::get)
}
#[cfg(test)]
pub(super) fn trace_for_test(
    phase: &str,
    support: &Path,
    index: &ScanIndex,
    progress: &SnapshotUploadProgress,
) {
    if !tracing_for_test() {
        return;
    }
    let Ok(catalogs) = CATALOGS.lock() else {
        return;
    };
    let attempts = catalogs.get(support).map(|c| c.entries.iter().take(4).map(|m| {
        serde_json::json!({"ack":m.ack_saved,"terminal":m.terminal,"posts":m.posts,
            "entities":m.entities.iter().take(4).map(|e| serde_json::json!({
                "fp8":e.fingerprint.get(..8),"literal":e.literal,"files":e.files.len(),
                "accepted":progress.accepted_fingerprints.contains(&e.fingerprint),
                "body":progress.accepted_body_witnesses.get(&e.fingerprint)==Some(&e.witness),
                "retry":progress.active_quarantine_retries.contains(&e.fingerprint),
                "quarantine":progress.quarantined_fingerprints.contains_key(&e.fingerprint),
                "selected_accepted":index.accepted_snapshot_fingerprint_recorded(&e.fingerprint),
                "selected_quarantine":index.quarantined_snapshot_fingerprints.contains_key(&e.fingerprint),
                "tuples":e.files.iter().zip(&e.file_revisions).zip(&e.file_selections).take(4)
                    .map(|((key,rev),selection)|serde_json::json!({
                        "wanted":selection.revision,"actual":index.files.get(key).map(|f|f.effective_upload_body_witness_revision),
                        "matches":index.selected_upload_tuple_recorded(key,rev,selection.group.as_deref(),selection.body.as_deref(),selection.revision)
                    })).collect::<Vec<_>>()
            })).collect::<Vec<_>>()})
    }).collect::<Vec<_>>());
    eprintln!(
        "MONEY_UNKNOWN_TRACE {}",
        serde_json::json!({"phase":phase,"attempts":attempts,
        "accepted":progress.accepted_fingerprints.len(),"bodies":progress.accepted_body_witnesses.len(),
        "quarantines":progress.quarantined_fingerprints.len(),"index_files":index.files.len()})
    );
}

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
                    lineage: id.clone(),
                    id,
                    binding: "00".repeat(32),
                    context: String::new(),
                    policy: [0; 32],
                    created: now,
                    deadline: now.saturating_add(DEADLINE),
                    posts: 1,
                    slot: 0,
                    not_before: 0,
                    length: 0,
                    sha256: "00".repeat(32),
                    head_cas: false,
                    ack_saved: false,
                    receipt_slot: None,
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
            if m.ack_saved {
                // A saved complete ACK has already ended UNKNOWN. Keep bytes
                // through the selected-save barrier, but never reinterpret a
                // successful last replay as exhausted UNKNOWN. At the hard
                // privacy deadline (or binding loss), retire known custody;
                // selected-file debt still requires its ordinary saved proof.
                return (m.binding != binding || now >= m.deadline).then_some(Reason::Resolved);
            }
            if m.binding != binding {
                Some(Reason::BindingLost)
            } else if now >= m.deadline {
                Some(Reason::Expired)
            } else if m.posts >= 4 {
                Some(Reason::Exhausted)
            } else if m.slot >= 3 {
                Some(Reason::AdmissionDenied)
            } else if money::recovery_released(support, &m.lineage) {
                Some(Reason::Released)
            } else {
                None
            }
        });
        reason.map(|reason| (m.clone(), reason))
    });
    drop(catalogs);
    if let Some((m, reason)) = pending {
        let another_attempt = CATALOGS
            .lock()
            .map_err(|_| fault())?
            .get(support)
            .is_some_and(|catalog| {
                catalog
                    .entries
                    .iter()
                    .any(|other| other.id != m.id && other.lineage == m.lineage)
            });
        let finish = if reason == Reason::Resolved && another_attempt {
            money::MoneyReceipt::Ready
        } else {
            money::recovery_finish_receipt(support, &m.lineage, now, reason == Reason::Resolved)
        };
        match finish {
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

pub(crate) fn initialized(support: &Path) -> bool {
    CATALOGS.lock().ok().is_some_and(|c| {
        c.get(support)
            .is_some_and(|c| c.loading.is_none() && !c.fault)
    })
}

pub(crate) fn blocked_file(support: &Path, key: &str, root: Option<&str>) -> bool {
    let Ok(catalogs) = CATALOGS.lock() else {
        return true;
    };
    let Some(catalog) = catalogs.get(support) else {
        // No known attempt is no UNKNOWN scope. The network coordinator must
        // finish startup reconciliation before it can authorize any POST.
        return false;
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
pub(super) fn due(support: &Path, now: u64) -> Result<(Vec<Manifest>, money::ShadowReservation)> {
    let catalogs = CATALOGS.lock().map_err(|_| fault())?;
    let catalog = catalogs.get(support).ok_or_else(fault)?;
    let eligible = |m: &&Manifest| {
        m.terminal.is_none()
            && !m.ack_saved
            && m.posts < 4
            && m.slot < 3
            && now < m.deadline
            && now >= m.not_before
            && now >= m.created.saturating_add(REPLAY_AT[usize::from(m.slot)])
    };
    let mut length = SnapshotPackingLength { bytes: 0 };
    for m in catalog.entries.iter().filter(eligible) {
        serde_json::to_writer(&mut length, m)?;
    }
    let funds =
        money::ShadowReservation::admit(length.bytes.saturating_mul(4)).ok_or_else(fault)?;
    Ok((
        catalog.entries.iter().filter(eligible).cloned().collect(),
        funds,
    ))
}

/// Retained exact outcomes remain current until their selected-state handoff.
/// This supplies identities only; proof/hold state must already exist durably.
pub(super) fn retained_progress_bodies(
    support: &Path,
    progress: &SnapshotUploadProgress,
) -> Result<(BTreeMap<String, String>, money::ShadowReservation)> {
    let catalogs = CATALOGS.lock().map_err(|_| fault())?;
    let catalog = catalogs.get(support).ok_or_else(fault)?;
    let count = catalog
        .entries
        .iter()
        .map(|m| m.entities.len())
        .sum::<usize>();
    // Funds cover this bounded map, the driver's copies and the current-index
    // identity set. No historical ACK map is cloned or added to this scope.
    let charge = count
        .saturating_mul(1024)
        .saturating_add(if count == 0 { 0 } else { 4096 });
    let funds = money::ShadowReservation::admit(charge).ok_or_else(fault)?;
    let mut bodies = BTreeMap::new();
    for e in catalog.entries.iter().flat_map(|m| &m.entities) {
        if progress.accepted_body_witnesses.get(&e.fingerprint) == Some(&e.witness)
            || progress
                .quarantined_fingerprints
                .get(&e.fingerprint)
                .is_some_and(|record| {
                    record.upload_body_witness.as_deref() == Some(e.witness.as_str())
                })
        {
            bodies.insert(e.fingerprint.clone(), e.witness.clone());
        }
    }
    Ok((bodies, funds))
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
        let funds = money::ShadowReservation::admit(BODY_FUNDS).ok_or_else(fault)?;
        if now >= m.deadline || m.posts >= 4 || m.slot >= 3 {
            return Err(fault());
        }
        let body = read_capped(&path(&root, &m.id, "body")?, BODY_MAX);
        let bytes = match body {
            Ok(bytes) if bytes.len() == m.length && digest(&bytes) == m.sha256 => bytes,
            _ => {
                m.terminal = Some(Reason::CorruptCustody);
                write_manifest(&root, &m)?;
                return Err(CorruptBody(m).into());
            }
        };
        m.posts += 1;
        m.slot += 1;
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
pub(super) fn ack_saved(support: &Path, _progress: &SnapshotUploadProgress) -> Result<()> {
    let mut catalogs = CATALOGS.lock().map_err(|_| fault())?;
    let Some(catalog) = catalogs.get_mut(support) else {
        return Ok(());
    };
    for m in &mut catalog.entries {
        // Complete validated outcomes include basis-present, held, refused and
        // conflict dispositions. Their durable ACK ends UNKNOWN without ever
        // recording an accepted body or retiring the applicable delivery debt.
        if !m.ack_saved && catalog.awaiting_ack.contains(&m.id) {
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
    selected: &ScanIndex,
    progress: &SnapshotUploadProgress,
    now: u64,
) -> Result<()> {
    let mut catalogs = CATALOGS.lock().map_err(|_| fault())?;
    let Some(catalog) = catalogs.get_mut(support) else {
        return Ok(());
    };
    for m in &mut catalog.entries {
        let selected_outcomes = m.entities.iter().all(|entity| {
            selected.accepted_snapshot_fingerprint_recorded(&entity.fingerprint)
                && progress.accepted_body_witnesses.get(&entity.fingerprint)
                    == Some(&entity.witness)
                && entity
                    .files
                    .iter()
                    .zip(&entity.file_revisions)
                    .zip(&entity.file_selections)
                    .all(|((key, revision), selection)| {
                        selected.selected_upload_tuple_recorded(
                            key,
                            revision,
                            selection.group.as_deref(),
                            selection.body.as_deref(),
                            selection.revision,
                        )
                    })
                || progress
                    .quarantined_fingerprints
                    .get(&entity.fingerprint)
                    .is_some_and(|record| {
                        record.upload_body_witness.as_deref() == Some(entity.witness.as_str())
                            && selected
                                .quarantined_snapshot_fingerprints
                                .get(&entity.fingerprint)
                                == Some(record)
                    })
        });
        if m.terminal.is_none() && m.ack_saved && selected_outcomes {
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

pub(super) fn invalidate(support: &Path) {
    if let Ok(mut catalogs) = CATALOGS.lock() {
        // An actual custody fault stays closed; dropping its future is not a
        // successful repair or permission to forget a lost Retry-After write.
        if catalogs.get(support).is_some_and(|c| c.fault) {
            return;
        }
        catalogs.remove(support);
    }
    if let Ok(mut outcomes) = OUTCOMES.lock() {
        outcomes.remove(support);
    }
}

#[cfg(test)]
pub(crate) fn forget(support: &Path) {
    CATALOGS.lock().unwrap().remove(support);
    OUTCOMES.lock().unwrap().remove(support);
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
    policy: [u8; 32],
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
    lineage.update(policy);
    lineage.update((index.recovery_upload_context().len() as u64).to_be_bytes());
    lineage.update(index.recovery_upload_context().as_bytes());
    lineage.update([u8::from(head_cas)]);
    for item in &request.snapshots {
        let root = money::family_root(item).to_string();
        let mut files = Vec::new();
        let mut file_revisions = Vec::new();
        let mut file_selections = Vec::new();
        for key in index
            .files
            .keys()
            .filter(|key| money::logical_family_member(index, key).is_some_and(|(r, _)| r == root))
        {
            let entry = &index.files[key];
            metadata_bytes = metadata_bytes
                .saturating_add(key.len())
                .saturating_add(
                    entry
                        .last_snapshot_fingerprint
                        .as_ref()
                        .map_or(0, String::len),
                )
                .saturating_add(
                    entry
                        .last_upload_body_witness
                        .as_ref()
                        .map_or(0, String::len),
                );
            if files.len() >= 256 || key.len() > 4096 || metadata_bytes > MANIFEST_MAX / 2 {
                return Err(fault());
            }
            files.push(key.clone());
            file_revisions.push(index.files[key].source_file_fingerprint.clone());
            file_selections.push(FileSelection {
                group: entry.last_snapshot_fingerprint.clone(),
                body: entry.last_upload_body_witness.clone(),
                revision: if index.request_money_live_revision() {
                    3
                } else {
                    effective_upload_body_witness_revision(SnapshotSource::ClaudeCode)
                },
            });
        }
        lineage.update((item.source_session_id.len() as u64).to_be_bytes());
        lineage.update(item.source_session_id.as_bytes());
        lineage.update(item.snapshot_fingerprint.as_bytes());
        let witness = snapshot_upload_body_witness(item);
        lineage.update(witness.as_bytes());
        if let Some(fp) = &item.source_file_fingerprint {
            lineage.update(fp.as_bytes());
        }
        entities.push(Entity {
            root,
            session: item.source_session_id.clone(),
            fingerprint: item.snapshot_fingerprint.clone(),
            witness,
            witness_version: crate::snapshot_client::snapshot_ack_body_witness_version(item)?,
            files,
            file_revisions,
            file_selections,
            source_fingerprint: item.source_file_fingerprint.clone(),
            cache_patch: item.cache_observations.clone(),
            literal: item.usage_accounting_contract.as_deref()
                == Some(money::REQUEST_OWNED_CONTRACT),
        });
    }
    let now = now(support);
    let lineage = format!("{:x}", lineage.finalize());
    static SEQUENCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let mut nonce = Sha256::new();
    nonce.update(std::process::id().to_be_bytes());
    nonce.update(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos())
            .to_be_bytes(),
    );
    nonce.update(
        SEQUENCE
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            .to_be_bytes(),
    );
    let id = format!("{lineage}-{:x}", nonce.finalize());
    Ok(Manifest {
        id,
        lineage,
        binding,
        context: index.recovery_upload_context().to_owned(),
        policy,
        created: now,
        deadline: now.saturating_add(DEADLINE),
        posts: 1,
        slot: 0,
        not_before: now,
        length: 0,
        sha256: String::new(),
        head_cas,
        ack_saved: false,
        receipt_slot: None,
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
            std::future::poll_fn(
                |_| match money::recovery_reserve_receipt(support, &m.lineage) {
                    money::MoneyReceipt::Ready => std::task::Poll::Ready(Ok(())),
                    money::MoneyReceipt::Pending => std::task::Poll::Pending,
                    money::MoneyReceipt::Refused => std::task::Poll::Ready(Err(fault())),
                },
            )
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
    policy: [u8; 32],
    state: &mut SendState,
) -> Result<crate::snapshot_client::SnapshotBatchResponse> {
    if matches!(state, SendState::Empty) {
        let m = manifest(
            support,
            index,
            request,
            binding.to_owned(),
            head_cas,
            policy,
        )?;
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
        if money::recovery_released(support, &m.lineage) {
            let roots = m
                .entities
                .iter()
                .map(|e| (e.root.as_str(), e.files.as_slice()))
                .collect::<Vec<_>>();
            if m.entities.iter().any(|e| e.literal)
                && (!index.initial_recovery_history_permitted(support, &roots)
                    || current_literal_guard(index, &m) != LiteralPermit::Permit)
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
            let _body_funds = money::ShadowReservation::admit(BODY_FUNDS).ok_or_else(fault)?;
            let body = encode(request, m.head_cas)?;
            return client.upload_recovery_bytes(token, request, head_cas, &body);
        }
        let funds = money::ShadowReservation::admit(BODY_FUNDS).ok_or_else(fault)?;
        let body = encode(request, m.head_cas)?;
        *state = SendState::Reserving(m, body, funds);
        return Err(Pending.into());
    }
    let SendState::Ready(m, body, _funds) = std::mem::take(state) else {
        return Err(fault());
    };
    if now(support) >= m.deadline {
        let ticket = outcome_ticket(support, m, Some(Reason::Expired), 0)?;
        OUTCOMES
            .lock()
            .map_err(|_| fault())?
            .entry(support.to_path_buf())
            .or_default()
            .push(ticket);
        return Err(Deferred {
            reason: None,
            not_before: now(support),
            route_unavailable: false,
        }
        .into());
    }
    let roots = m
        .entities
        .iter()
        .map(|e| (e.root.as_str(), e.files.as_slice()))
        .collect::<Vec<_>>();
    if m.entities.iter().any(|e| e.literal)
        && (!index.initial_recovery_history_permitted(support, &roots)
            || current_literal_guard(index, &m) != LiteralPermit::Permit)
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
        || now(support) >= m.deadline
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
    policy: [u8; 32],
    authority: impl Fn() -> Result<()>,
) -> Result<()> {
    let binding = binding(namespace, client.recovery_origin(), machine, "");
    let (due, _scope_funds) = due(support, now(support))?;
    for m in due {
        if m.binding != binding
            || m.context != index.recovery_upload_context()
            || m.policy != policy
        {
            let updated = wait(outcome_ticket(support, m, Some(Reason::BindingLost), 0)?).await?;
            replace(support, updated)?;
            continue;
        }
        let guard = current_literal_guard(index, &m);
        if !admitted(index, support, &binding, &m, guard)? {
            let mut m = m;
            m.slot = m.slot.saturating_add(1).min(3);
            let reason = if guard == LiteralPermit::DenyAll {
                Some(Reason::RevisionDowngrade)
            } else if m.slot >= 3 {
                Some(Reason::AdmissionDenied)
            } else {
                None
            };
            let next = if m.slot < 3 {
                m.created.saturating_add(REPLAY_AT[usize::from(m.slot)])
            } else {
                m.deadline
            };
            let updated = wait(outcome_ticket(support, m, reason, next)?).await?;
            replace(support, updated)?;
            continue;
        }
        authority()?;
        let token = client.issue_relay_token(device, secret, SnapshotSource::ClaudeCode)?;
        // Counter save and payload read share the bounded money writer. A
        // crash at or after this save consumes the same slot on restart.
        let prepared = wait(replay_ticket(support, m, now(support))?).await;
        let (m, bytes, _body_funds) = match prepared {
            Ok(prepared) => prepared,
            Err(error) if error.is::<CorruptBody>() => {
                replace(
                    support,
                    error.downcast::<CorruptBody>().map_err(|_| fault())?.0,
                )?;
                continue;
            }
            Err(error) => return Err(error),
        };
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
                        if reason == Reason::VersionSkew && e.literal {
                            progress.quarantine_literal_version_skew_body(
                                &e.fingerprint,
                                &e.witness,
                                now(support),
                            );
                        } else {
                            progress.quarantine_transient_body(
                                &e.fingerprint,
                                &e.witness,
                                now(support).saturating_add(1800),
                            );
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
    // Inspect durable state, including queued writes whose owner completed or
    // was cancelled. Never make a fixture's in-memory cache the proof.
    store::flush();
    load(&dir(support)).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    fn specimen(created: u64) -> (Manifest, Vec<u8>) {
        let bytes = br#"{"schema_version":1,"snapshots":[{"synthetic":true}]}"#.to_vec();
        (
            Manifest {
                id: "ab".repeat(32),
                lineage: "ab".repeat(32),
                binding: "cd".repeat(32),
                context: "context".into(),
                policy: [0; 32],
                created,
                deadline: created + DEADLINE,
                posts: 1,
                slot: 0,
                not_before: created,
                length: bytes.len(),
                sha256: digest(&bytes),
                head_cas: false,
                ack_saved: false,
                receipt_slot: None,
                entities: vec![Entity {
                    root: "synthetic-root".into(),
                    session: "synthetic-session".into(),
                    fingerprint: "ef".repeat(32),
                    witness: "12".repeat(32),
                    witness_version: Some(7),
                    files: vec!["/fixture/file.jsonl".into()],
                    file_revisions: vec!["34".repeat(32)],
                    file_selections: vec![FileSelection {
                        group: Some("56".repeat(32)),
                        body: Some("78".repeat(32)),
                        revision: 3,
                    }],
                    source_fingerprint: Some("34".repeat(32)),
                    literal: true,
                    cache_patch: None,
                }],
                terminal: None,
            },
            bytes,
        )
    }
    fn startup_ready(support: &Path, binding: &str, now: u64) {
        for _ in 0..32 {
            if startup(support, binding, now).unwrap() {
                return;
            }
            store::flush();
        }
        panic!("bounded recovery startup did not finish its writer receipts");
    }

    #[test]
    #[serial_test::serial(claude_request_money_shadow)]
    fn cold_start_binding_loss_and_missing_legacy_body_are_visible_unresolved() {
        for legacy in [false, true] {
            let scratch = crate::test_scratch::ScratchDir::new("money-unknown-startup");
            let _live = money::LiveForTest::new(&scratch);
            store::reload_for_test(&scratch).unwrap();
            store::with_ledger_for_test(&scratch, |ledger| {
                if legacy {
                    let mut rates = [0; 32]; rates[..8].copy_from_slice(&((1_u64 << 63) | 1).to_be_bytes());
                    assert_eq!(ledger.insert(format!("adopt:entity:v2:{}:rates", "aa".repeat(32)),
                        crate::snapshots::claude_request_census::ClaudeRequestCensusRecord::money_debt(rates, 1000)),
                        crate::snapshots::claude_request_census::ClaudeRequestCensusInsert::Stored);
                }
                assert!(store::checkpoint_for_test(&scratch, ledger));
            }).unwrap();
            let (m, body) = specimen(1000);
            if !legacy {
                capture(scratch.to_path_buf(), m.clone(), &body).unwrap();
            }
            startup_ready(&scratch, &"99".repeat(32), 1001);
            assert!(load(&dir(&scratch)).unwrap().is_empty());
            let receipts = fs::read_dir(dir(&scratch))
                .unwrap()
                .filter_map(|entry| {
                    let path = entry.unwrap().path();
                    (path.extension().and_then(|s| s.to_str()) == Some("receipt")).then(|| {
                        serde_json::from_slice::<Receipt>(&fs::read(path).unwrap()).unwrap()
                    })
                })
                .collect::<Vec<_>>();
            assert_eq!(receipts.len(), 1);
            assert_eq!(receipts[0].outcome, "unknown_outcome_unresolved");
            assert_eq!(
                receipts[0].reason,
                if legacy {
                    Reason::CorruptCustody
                } else {
                    Reason::BindingLost
                }
            );
            if !legacy {
                assert!(money::recovery_released(&scratch, &m.id));
            }
            forget(&scratch);
            startup_ready(&scratch, &m.binding, 1002);
            assert!(
                load(&dir(&scratch)).unwrap().is_empty(),
                "switching back cannot reconstruct an old replay"
            );
            forget(&scratch);
            store::forget_for_test(&scratch);
        }
    }

    #[test]
    #[serial_test::serial(claude_request_money_shadow)]
    fn committed_terminal_marker_survives_a_crash_after_payload_deletion() {
        for known in [false, true] {
            let scratch = crate::test_scratch::ScratchDir::new("money-retirement-restart");
            let _live = money::LiveForTest::new(&scratch);
            store::reload_for_test(&scratch).unwrap();
            store::with_ledger_for_test(&scratch, |ledger| {
                assert!(store::checkpoint_for_test(&scratch, ledger));
            })
            .unwrap();
            let (mut m, body) = specimen(1000);
            m.ack_saved = known;
            let mut m = capture(scratch.to_path_buf(), m, &body).unwrap();
            let reason = if known {
                Reason::Resolved
            } else {
                Reason::Expired
            };
            m.terminal = Some(reason);
            if !known {
                let mut released = false;
                for _ in 0..32 {
                    match money::recovery_release_receipt(&scratch, &m.lineage, m.deadline) {
                        money::MoneyReceipt::Ready => {
                            released = true;
                            break;
                        }
                        money::MoneyReceipt::Pending => store::flush(),
                        money::MoneyReceipt::Refused => {
                            panic!("terminal latch must be durable before payload deletion")
                        }
                    }
                }
                assert!(released);
                m.receipt_slot = Some(0);
                let receipt = Receipt {
                    outcome: "unknown_outcome_unresolved".into(),
                    reason,
                    entities: 1,
                    age_hours: 24,
                    time_day: 1,
                    attempts: 0,
                    hash8: m.id[..8].into(),
                };
                atomic(
                    &dir(&scratch),
                    &dir(&scratch).join("receipt-0000.receipt"),
                    &serde_json::to_vec(&receipt).unwrap(),
                )
                .unwrap();
            }
            write_manifest(&dir(&scratch), &m).unwrap();
            fs::remove_file(path(&dir(&scratch), &m.id, "body").unwrap()).unwrap();
            sync_dir(&dir(&scratch)).unwrap();
            // This is the committed deletion boundary before manifest unlink.
            let recovered = load(&dir(&scratch)).unwrap();
            assert_eq!(recovered.len(), 1);
            assert_eq!(recovered[0].terminal, Some(reason));
            startup_ready(&scratch, &m.binding, m.deadline);
            assert!(load(&dir(&scratch)).unwrap().is_empty());
            let receipts = fs::read_dir(dir(&scratch))
                .unwrap()
                .filter(|e| {
                    e.as_ref()
                        .unwrap()
                        .path()
                        .extension()
                        .and_then(|s| s.to_str())
                        == Some("receipt")
                })
                .count();
            assert_eq!(
                receipts,
                usize::from(!known),
                "restart cannot double-count a terminal outcome"
            );
            let status: serde_json::Value =
                serde_json::from_slice(&fs::read(dir(&scratch).join("status")).unwrap()).unwrap();
            assert_eq!(status["unknown_outcome_unresolved"], usize::from(!known));
            forget(&scratch);
            store::forget_for_test(&scratch);
        }
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
            serde_json::from_slice(&fs::read(root.join("receipt-0000.receipt")).unwrap()).unwrap();
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
        expired.lineage = expired.id.clone();
        let expired = capture(scratch.to_path_buf(), expired, &body).unwrap();
        assert!(money_resume::drive_for_test(wait(
            replay_ticket(&scratch, expired, 1000 + DEADLINE).unwrap()
        ))
        .is_err());
        eprintln!("MONEY_UNKNOWN_CUSTODY exact_replay=true replays=3 restart_counter=true terminal_allowlist=true private_files=true");
    }
    #[test]
    fn colliding_diagnostic_hashes_keep_distinct_private_receipt_reservations() {
        let scratch = crate::test_scratch::ScratchDir::new("money-unknown-hash8-collision");
        let (first, body) = specimen(1000);
        let mut second = first.clone();
        second.id = format!("{}{}", &first.id[..8], "56".repeat(28));
        second.lineage = second.id.clone();
        let first = capture(scratch.to_path_buf(), first, &body).unwrap();
        let second = capture(scratch.to_path_buf(), second, &body).unwrap();
        terminal(
            scratch.to_path_buf(),
            first,
            Reason::Expired,
            1000 + DEADLINE,
        )
        .unwrap();
        terminal(
            scratch.to_path_buf(),
            second,
            Reason::Expired,
            1000 + DEADLINE,
        )
        .unwrap();
        let root = dir(&scratch);
        let receipts = [0, 1].map(|slot| {
            serde_json::from_slice::<Receipt>(
                &fs::read(root.join(format!("receipt-{slot:04}.receipt"))).unwrap(),
            )
            .unwrap()
        });
        assert_eq!(receipts[0].hash8, receipts[1].hash8);
        assert_eq!(receipts[0].outcome, "unknown_outcome_unresolved");
        assert_eq!(receipts[1].outcome, "unknown_outcome_unresolved");
        assert!(load(&root).unwrap().is_empty());
        prune_receipts(&root, (receipts[0].time_day + 35) * 86400, 0).unwrap();
        assert!(!root.join("receipt-0000.receipt").exists());
        assert!(!root.join("receipt-0001.receipt").exists());
    }

    #[test]
    fn interrupted_metadata_stage_does_not_change_committed_counter() {
        let scratch = crate::test_scratch::ScratchDir::new("money-unknown-staged-counter");
        let (m, body) = specimen(1000);
        let m = capture(scratch.to_path_buf(), m, &body).unwrap();
        let root = dir(&scratch);
        let staged = path(&root, &m.id, "json.tmp").unwrap();
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&staged).unwrap();
        file.write_all(b"interrupted metadata").unwrap();
        file.sync_all().unwrap();
        drop(file);
        assert_eq!(load(&root).unwrap()[0].posts, 1);
        write_manifest(&root, &m).unwrap();
        assert_eq!(load(&root).unwrap()[0].posts, 1);
        assert!(!staged.exists());
        assert_eq!(
            read_capped(&path(&root, &m.id, "body").unwrap(), BODY_MAX).unwrap(),
            body
        );
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
