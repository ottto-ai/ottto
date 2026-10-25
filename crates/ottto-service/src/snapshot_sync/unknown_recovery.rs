//! Bounded custody for an authorized batch whose outcome may be unknown.
//! The payload is final identity-encoded wire JSON, never a recipe for a POST.
//! Payload/manifest work runs on the existing money writer. A fresh gate-OFF
//! caller allocates no catalog; existing custody gets privacy/terminal upkeep
//! before networking.
use super::*;
use crate::snapshots::claude_request_money::{self as money, store};
use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::sync::mpsc::TryRecvError;

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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) offer: Option<money::RecoveryOffer>,
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
    #[serde(default)]
    pub scope: money::recovery_scope::Scope,
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
#[derive(Serialize)]
struct CheckedManifestView<'a> {
    checksum: &'a str,
    manifest: &'a Manifest,
}
fn manifest_fits(m: &Manifest) -> bool {
    // A SHA-256 checksum always serializes as the same 64 unescaped bytes.
    const CHECKSUM: &str = "0000000000000000000000000000000000000000000000000000000000000000";
    // Hash +64, wire length +6, not-before at most +19, terminal reason +16;
    // counters remain one digit and the receipt slot is no wider than null.
    // Count the borrowed envelope with room for all later journal updates.
    // No second metadata graph is copied just to reject an oversized offer.
    const BOOKKEEPING_ROOM: usize = 128;
    crate::snapshot_retry::json_fits(
        &CheckedManifestView {
            checksum: CHECKSUM,
            manifest: m,
        },
        MANIFEST_MAX - BOOKKEEPING_ROOM,
    )
}

#[derive(Debug)]
pub(super) struct Deferred {
    pub reason: Option<Reason>,
    pub not_before: u64,
    pub route_unavailable: bool,
    pub source_backoff: Option<Option<Duration>>,
}
impl std::fmt::Display for Deferred {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("request money immutable batch awaits bounded recovery")
    }
}
impl std::error::Error for Deferred {}
#[derive(Debug)]
pub(super) struct Backoff {
    pub retry_after: Option<Duration>,
}
impl std::fmt::Display for Backoff {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("request money replay honors source backoff")
    }
}
impl std::error::Error for Backoff {}
fn source_backoff(error: &anyhow::Error) -> Option<Option<Duration>> {
    error
        .downcast_ref::<UploadShed>()
        .map(|shed| shed.retry_after)
        .or_else(|| is_literal_version_skew(error).then_some(Some(Duration::from_secs(1800))))
}

pub(super) fn now(support: &Path) -> u64 {
    money::recovery_now(support)
}
/// Local admission before capture/POST. Only unsent offers may be packed
/// again; a pending capture supplies its exact entity partition on resume.
#[derive(Debug)]
pub(super) struct UnsentPacking {
    pub kind: &'static str,
    pub resume: Option<Vec<String>>,
}
impl std::fmt::Display for UnsentPacking {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("request money unsent batch exceeds bounded custody admission")
    }
}
impl std::error::Error for UnsentPacking {}
fn unsent_packing(kind: &'static str) -> anyhow::Error {
    UnsentPacking { kind, resume: None }.into()
}

/// Admission pressure is recoverable after checkpointing accepted siblings.
/// It must never poison an otherwise healthy durable catalog.
#[derive(Debug)]
pub(super) struct CapacityFull;
impl std::fmt::Display for CapacityFull {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("request money recovery admission is full")
    }
}
impl std::error::Error for CapacityFull {}
fn capacity_full() -> anyhow::Error {
    CapacityFull.into()
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

/// OFF cannot strand a previously authorized payload past its privacy bound.
/// Probe only filenames in this bounded private directory. Status alone does
/// not hydrate custody; count-only receipts still need their daily TTL pass.
pub(super) fn existing_recovery_state(support: &Path) -> Result<bool> {
    let entries = match fs::read_dir(dir(support)) {
        Ok(entries) => entries,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(false),
        Err(_) => return Err(fault()),
    };
    for (count, entry) in entries.enumerate() {
        if count >= 4 * ACTIVE_MAX + RECEIPT_MAX + 4 {
            return Err(fault());
        }
        let name = entry.map_err(|_| fault())?.file_name();
        let name = name.to_str().ok_or_else(fault)?;
        if name.split_once('.').is_some_and(|(_, extension)| {
            matches!(
                extension,
                "json" | "body" | "json.tmp" | "body.tmp" | "receipt"
            )
        }) {
            return Ok(true);
        }
    }
    Ok(false)
}
fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
pub(super) fn binding(namespace: &str, origin: &str, machine: &str, account: &[u8; 32]) -> String {
    let mut hash = Sha256::new();
    for field in [
        b"unknown_ack:v2".as_slice(),
        namespace.as_bytes(),
        origin.as_bytes(),
        machine.as_bytes(),
        b"claude_code".as_slice(),
        account.as_slice(),
    ] {
        hash.update((field.len() as u64).to_be_bytes());
        hash.update(field);
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
    let checksum = digest(&value);
    let envelope = CheckedManifestView {
        checksum: &checksum,
        manifest,
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
        || !m.scope.valid()
        || m.entities
            .iter()
            .any(|e| !m.scope.roots.contains_key(&e.root))
        || m.entities.is_empty()
        || m.entities.len() > SNAPSHOT_BATCH_LIMIT
        || m.entities.iter().any(|e| {
            e.files.len() > 256
                || e.files.len() != e.file_revisions.len()
                || e.files.len() != e.file_selections.len()
                || e.file_selections.iter().any(|selection| {
                    !matches!(selection.revision, 2 | 3)
                        || selection.offer.is_some_and(|(_, at)| at > m.created)
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
            scope: money::recovery_scope::Scope::default(),
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
fn prune_receipts(root: &Path, now: u64, active: &[Manifest], extra: usize) -> Result<()> {
    let reserved = unwritten_receipts(root, active).saturating_add(extra);
    let mut count = 0;
    let mut bytes = 0;
    for entry in fs::read_dir(root)? {
        let file = entry?.path();
        if file.extension().and_then(|s| s.to_str()) != Some("receipt") {
            continue;
        }
        let encoded = read_capped(&file, 1024)?;
        let receipt: Receipt = serde_json::from_slice(&encoded)?;
        let slot = file
            .file_name()
            .and_then(|s| s.to_str())
            .and_then(|s| s.strip_prefix("receipt-"))
            .and_then(|s| s.strip_suffix(".receipt"))
            .and_then(|s| s.parse::<u16>().ok());
        let retirement_proof =
            slot.is_some_and(|slot| active.iter().any(|m| m.receipt_slot == Some(slot)));
        if !retirement_proof && now / 86400 >= receipt.time_day.saturating_add(RECEIPT_TTL / 86400)
        {
            fs::remove_file(file)?;
        } else {
            count += 1;
            bytes += encoded.len() as u64;
        }
    }
    // Reserve a receipt for every admitted active batch, even at full custody.
    if count + reserved > RECEIPT_MAX || bytes + reserved as u64 * 1024 > RECEIPT_BYTES_MAX {
        return Err(if extra > 0 { capacity_full() } else { fault() });
    }
    Ok(())
}
fn load_for_startup(root: &Path, now: u64) -> Result<Vec<Manifest>> {
    let entries = load(root)?;
    if root.exists() {
        prune_receipts(root, now, &entries, 0)?;
        publish_status(root, now, entries.len())?;
    }
    Ok(entries)
}
fn capture(support: PathBuf, mut m: Manifest, body: &[u8]) -> Result<Manifest> {
    let root = dir(&support);
    private_dir(&root)?;
    sync_dir(&support)?;
    let active = load(&root)?;
    prune_receipts(&root, m.created, &active, 1)?;
    if active.len() >= ACTIVE_MAX {
        return Err(capacity_full());
    }
    if body.len() > BODY_MAX {
        return Err(fault());
    }
    m.length = body.len();
    m.sha256 = digest(body);
    validate_manifest(&m)?;
    // Includes payload temp, manifest replacement temp and terminal receipt.
    let reserve = body.len() as u64 + 2 * MANIFEST_MAX as u64 + 2048;
    if footprint(&root)?.saturating_add(reserve) > TOTAL_MAX {
        return Err(capacity_full());
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
    prune_receipts(&root, now, &active, 0)?;
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
    drop(active);
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
    let remaining = load(&root)?;
    // A crashed retirement may be resumed after receipt TTL. Keep its original
    // proof until payload/marker deletion, then expire it without renewing age.
    prune_receipts(&root, now, &remaining, 0)?;
    publish_status(&root, now, remaining.len())?;
    if reason != Reason::Resolved {
        crate::local_resource_diagnostics::claude_money_unknown_outcome(&receipt);
    }
    Ok(())
}

fn publish_status(root: &Path, now: u64, active_batches: usize) -> Result<()> {
    let mut unresolved = 0_u64;
    for entry in fs::read_dir(root)? {
        let file = entry?.path();
        if file.extension().and_then(|s| s.to_str()) == Some("receipt") {
            let saved: Receipt = serde_json::from_slice(&read_capped(&file, 1024)?)?;
            unresolved += u64::from(saved.outcome == "unknown_outcome_unresolved");
        }
    }
    let status = serde_json::json!({"unknown_outcome_unresolved":unresolved,
        "active_batches":active_batches, "time_day":now / 86400});
    atomic(root, &root.join("status"), &serde_json::to_vec(&status)?)?;
    Ok(())
}

type Prepared = (Manifest, Vec<u8>, money::ShadowReservation);

pub(super) struct Ticket<T> {
    receiver: store::RecoveryJob<Result<T>>,
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
    job_with_result_funds(4 * MANIFEST_MAX, operation)
}
fn catalog_job(
    operation: impl FnOnce() -> Result<Vec<Manifest>> + Send + 'static,
) -> Result<Ticket<Vec<Manifest>>> {
    job_with_result_funds(4 * ACTIVE_MAX * MANIFEST_MAX, operation)
}
fn job_with_result_funds<T: Send + 'static>(
    retained: usize,
    operation: impl FnOnce() -> Result<T> + Send + 'static,
) -> Result<Ticket<T>> {
    Ok(Ticket {
        receiver: store::recovery_job(IO_FUNDS, retained, move || {
            let result = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(operation)) {
                Ok(result) => result,
                Err(_) => return Err(fault()),
            };
            result.map_err(|error| {
                if error.is::<CorruptBody>() || error.is::<CapacityFull>() {
                    error
                } else {
                    fault()
                }
            })
        })
        .ok_or_else(capacity_full)?,
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
    loaded: bool,
    awaiting_ack: BTreeSet<String>,
    funds: Vec<money::ShadowReservation>,
    entries: Vec<Manifest>,
    loading: Option<Ticket<Vec<Manifest>>>,
    maintenance_day: Option<u64>,
}
static CATALOGS: Mutex<BTreeMap<PathBuf, Catalog>> = Mutex::new(BTreeMap::new());

/// Called before activity/token networking, including when the source's
/// network backoff would otherwise skip its finish. Expiry does not need HTTP.
pub(super) fn startup(support: &Path, binding: &str, now: u64) -> Result<bool> {
    startup_checked(support, Some(binding), now)
}
/// Privacy/expiry does not require credentials, an enabled Claude source or
/// networking. Binding loss is reconciled once current identity is available.
pub(super) fn offline_startup(support: &Path, now: u64) -> Result<bool> {
    startup_checked(support, None, now)
}
fn startup_checked(support: &Path, binding: Option<&str>, now: u64) -> Result<bool> {
    let result = startup_inner(support, binding, now);
    if let Err(error) = &result {
        faulted(support, error);
    }
    result
}
pub(super) fn expired_payload(support: &Path, now: u64) -> Result<bool> {
    let catalogs = CATALOGS.lock().map_err(|_| fault())?;
    Ok(catalogs
        .get(support)
        .is_some_and(|catalog| catalog.entries.iter().any(|m| now >= m.deadline)))
}
fn startup_inner(support: &Path, binding: Option<&str>, now: u64) -> Result<bool> {
    if CATALOGS
        .lock()
        .map_err(|_| fault())?
        .get(support)
        .is_some_and(|c| c.fault)
    {
        return Err(fault());
    }
    let (updates, waiting, _handoff_funds) = {
        let mut outcomes = OUTCOMES.lock().map_err(|_| fault())?;
        // Keep received manifests paid after removing their tickets and until
        // replacement, without reversing the Catalog -> OUTCOMES lock order.
        let count = outcomes.get(support).map_or(0, Vec::len);
        let handoff = money::ShadowReservation::admit(count.saturating_mul(4 * MANIFEST_MAX))
            .ok_or_else(capacity_full)?;
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
        (updates, waiting, handoff)
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
        let ticket = catalog_job(move || load_for_startup(&root, now))?;
        catalogs.insert(
            support.to_path_buf(),
            Catalog {
                fault: false,
                loaded: false,
                awaiting_ack: BTreeSet::new(),
                funds: Vec::new(),
                entries: Vec::new(),
                loading: Some(ticket),
                maintenance_day: Some(now / 86400),
            },
        );
    }
    let catalog = catalogs.get_mut(support).unwrap();
    if catalog.loading.is_none() && catalog.maintenance_day != Some(now / 86400) {
        let root = dir(support);
        catalog.loading = Some(catalog_job(move || load_for_startup(&root, now))?);
        catalog.maintenance_day = Some(now / 86400);
        return Ok(false);
    }
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
        let funds = money::ShadowReservation::admit(charge).ok_or_else(capacity_full)?;
        catalog.entries = entries;
        catalog.loaded = true;
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
        catalog.loading = Some(catalog_job(move || {
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
                    scope: money::recovery_scope::Scope::default(),
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
                return (binding.is_some_and(|current| m.binding != current) || now >= m.deadline)
                    .then_some(Reason::Resolved);
            }
            if binding.is_some_and(|current| m.binding != current) {
                Some(Reason::BindingLost)
            } else if now >= m.deadline {
                Some(Reason::Expired)
            } else if m.posts >= 4 {
                Some(Reason::Exhausted)
            } else if m.slot >= 3 {
                Some(Reason::AdmissionDenied)
            } else if !money::request_owned_live(support) {
                Some(Reason::Disabled)
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
        let ticket = catalog_job(move || {
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

/// Ordinary cleanup of already validated, unexpired custody is Claude work,
/// not a reason to skip health or unrelated sources. Cold loads, expiry,
/// disable and binding loss must still finish before any cycle networking.
pub(super) fn networking_ready(support: &Path, binding: Option<&str>, now: u64) -> bool {
    CATALOGS.lock().ok().is_some_and(|catalogs| {
        catalogs.get(support).is_some_and(|catalog| {
            catalog.loaded
                && !catalog.fault
                && (catalog.entries.is_empty() || money::request_owned_live(support))
                && catalog.entries.iter().all(|m| {
                    now < m.deadline
                        && binding.map_or(true, |binding| m.binding == binding)
                        && !matches!(
                            m.terminal,
                            Some(Reason::Expired | Reason::Disabled | Reason::BindingLost)
                        )
                })
        })
    })
}

pub(crate) fn initialized(support: &Path) -> bool {
    CATALOGS.lock().ok().is_some_and(|c| {
        c.get(support)
            .is_some_and(|c| c.loading.is_none() && !c.fault)
    })
}

/// A newly parsed path can join an UNKNOWN component only after its identity
/// evidence is known. Preserve its pre-parse tuple even while it is permitted.
/// This is bookkeeping, not an emission hold or a history reservation.
pub(crate) fn needs_preparse_tuples(support: &Path) -> bool {
    let Ok(catalogs) = CATALOGS.lock() else {
        return true;
    };
    catalogs.get(support).is_some_and(|catalog| {
        catalog.loading.is_some()
            || catalog.fault
            || catalog.entries.iter().any(|manifest| !manifest.ack_saved)
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
                && (root.is_some_and(|r| m.scope.roots.contains_key(r))
                    || m.scope
                        .roots
                        .values()
                        .any(|files| files.iter().any(|f| f == key)))
        })
}
/// Close each unresolved component against current evidence once for the page.
/// None is an honest bounded-admission failure, never a partial allowlist.
pub(crate) struct HeldRoots {
    pub roots: BTreeSet<String>,
    _funds: money::ShadowReservation,
}
pub(crate) fn held_roots(support: &Path, index: &ScanIndex) -> Option<HeldRoots> {
    let catalogs = CATALOGS.lock().ok()?;
    let Some(catalog) = catalogs.get(support) else {
        return Some(HeldRoots {
            roots: BTreeSet::new(),
            _funds: money::ShadowReservation::admit(0)?,
        });
    };
    if catalog.loading.is_some() || catalog.fault {
        return None;
    }
    let count = catalog.entries.iter().filter(|m| !m.ack_saved).count();
    let funds = money::ShadowReservation::admit(4 * count * MANIFEST_MAX)?;
    let mut roots = BTreeSet::new();
    for m in catalog.entries.iter().filter(|m| !m.ack_saved) {
        let scope = money::recovery_scope::close(support, index, &m.scope)?;
        roots.extend(scope.roots.keys().cloned());
    }
    Some(HeldRoots {
        roots,
        _funds: funds,
    })
}

pub(super) fn add(support: &Path, m: Manifest) -> Result<()> {
    let mut catalogs = CATALOGS.lock().map_err(|_| fault())?;
    let catalog = catalogs.get_mut(support).ok_or_else(fault)?;
    if !catalog.entries.iter().any(|old| old.id == m.id) {
        let charge = serde_json::to_vec(&m)?.len().saturating_mul(4);
        let funds = money::ShadowReservation::admit(charge).ok_or_else(capacity_full)?;
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
    let funds = money::ShadowReservation::admit(length.bytes.saturating_mul(4))
        .ok_or_else(capacity_full)?;
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
    let funds = money::ShadowReservation::admit(charge).ok_or_else(capacity_full)?;
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

/// A durable body ACK may finish its original money offer without another
/// POST. Keep the immutable authorization bounds, even if ordinary selected
/// rollback has pruned the disposable offer carrier.
pub(super) fn saved_money_offers(
    support: &Path,
    index: &ScanIndex,
    item: &SnapshotItem,
    witness: &str,
    binding: &str,
    policy: [u8; 32],
) -> Result<
    Option<(
        BTreeMap<String, money::RecoveryOffer>,
        money::ShadowReservation,
    )>,
> {
    let catalogs = CATALOGS.lock().map_err(|_| fault())?;
    let catalog = catalogs.get(support).ok_or_else(fault)?;
    let entities = || {
        catalog
            .entries
            .iter()
            .filter(|m| {
                m.ack_saved
                    && m.terminal.is_none()
                    && m.binding == binding
                    && m.context == index.recovery_upload_context()
                    && m.policy == policy
            })
            .flat_map(|m| &m.entities)
            .filter(|e| {
                e.session == item.source_session_id
                    && e.fingerprint == item.snapshot_fingerprint
                    && e.witness == witness
                    && e.source_fingerprint == item.source_file_fingerprint
            })
    };
    let mut charge = 0_usize;
    for entity in entities() {
        for ((key, revision), selection) in entity
            .files
            .iter()
            .zip(&entity.file_revisions)
            .zip(&entity.file_selections)
        {
            if selection.offer.is_some()
                && index
                    .files
                    .get(key)
                    .is_some_and(|entry| &entry.source_file_fingerprint == revision)
            {
                charge = charge.saturating_add(key.len()).saturating_add(1024);
            }
        }
    }
    if charge == 0 {
        return Ok(None);
    }
    let Some(funds) = money::ShadowReservation::admit(charge.saturating_add(4096)) else {
        return Ok(None);
    };
    let mut offers = BTreeMap::<String, money::RecoveryOffer>::new();
    for entity in entities() {
        for ((key, revision), selection) in entity
            .files
            .iter()
            .zip(&entity.file_revisions)
            .zip(&entity.file_selections)
        {
            if let Some(offer) = selection.offer.filter(|_| {
                index
                    .files
                    .get(key)
                    .is_some_and(|entry| &entry.source_file_fingerprint == revision)
            }) {
                offers
                    .entry(key.clone())
                    .and_modify(|old| {
                        if offer.1 > old.1 {
                            *old = offer;
                        }
                    })
                    .or_insert(offer);
            }
        }
    }
    Ok(Some((offers, funds)))
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
        let funds = money::ShadowReservation::admit(BODY_FUNDS).ok_or_else(capacity_full)?;
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
                        ) && selection.offer.map_or(true, |offer| {
                            money::recovery_offer_debt_retired(support, key, offer)
                        })
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
        // A later exact selected cache projection may replace a known probe.
        // It must have its own real ACK and selected tuple, and cannot borrow
        // the probe's old offer while any contributing money debt remains.
        let superseded_body_selected = m.entities.iter().all(|entity| {
            selected.selected_current_recovery_body_recorded(
                &entity.session,
                &entity.fingerprint,
                &entity.files,
                if entity.literal { 3 } else { 2 },
                &progress.accepted_body_witnesses,
            ) && entity
                .files
                .iter()
                .zip(&entity.file_selections)
                .all(|(key, selection)| {
                    selection.offer.map_or(true, |offer| {
                        money::recovery_offer_debt_retired(support, key, offer)
                            && !money::money_due(support, key, u64::MAX)
                    })
                })
        });
        if m.terminal.is_none() && m.ack_saved && (selected_outcomes || superseded_body_selected) {
            // This mark follows ACK/selected saves and the original matching
            // money debt handoff. Known outcomes need no unresolved receipt.
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
    let _metadata_funds =
        money::ShadowReservation::admit(4 * MANIFEST_MAX).ok_or_else(capacity_full)?;
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
                return Err(unsent_packing("metadata"));
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
                offer: money::recovery_offer(support, key, &item.snapshot_fingerprint),
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
    let scope = money::recovery_scope::close_with_reason(
        support,
        index,
        &money::recovery_scope::Scope::seed(entities.iter().map(|e| e.root.clone())),
    )
    .map_err(|reason| unsent_packing(reason.as_str()))?;
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
        scope: scope.scope,
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
    Capacity,
    Reserving(Manifest, Vec<u8>, money::ShadowReservation),
    Ready(Manifest, Vec<u8>, money::ShadowReservation),
}

pub(super) async fn captured(support: &Path, state: &mut SendState) -> Result<()> {
    let SendState::Reserving(m, body, funds) = std::mem::take(state) else {
        return Err(fault());
    };
    let lineage = m.lineage.clone();
    let reserved =
        std::future::poll_fn(
            |_| match money::recovery_reserve_receipt(support, &lineage) {
                money::RecoveryAdmission::Ready => std::task::Poll::Ready(Ok(true)),
                money::RecoveryAdmission::Full => std::task::Poll::Ready(Ok(false)),
                money::RecoveryAdmission::Pending => std::task::Poll::Pending,
                money::RecoveryAdmission::Refused => std::task::Poll::Ready(Err(fault())),
            },
        )
        .await
        .inspect_err(|error| faulted(support, error))?;
    if !reserved {
        *state = SendState::Capacity;
        return Ok(());
    }
    let prepared = match capture_ticket(support, m, body, funds) {
        Ok(ticket) => wait(ticket).await,
        Err(error) => Err(error),
    };
    if prepared
        .as_ref()
        .err()
        .is_some_and(|error| error.is::<CapacityFull>())
    {
        // Capacity refusal precedes every payload/intent write and POST. Return
        // its unused latch reservation too; never accumulate orphan controls.
        std::future::poll_fn(|_| {
            match money::recovery_finish_receipt(support, &lineage, now(support), true) {
                money::MoneyReceipt::Ready => std::task::Poll::Ready(Ok(())),
                money::MoneyReceipt::Pending => std::task::Poll::Pending,
                money::MoneyReceipt::Refused => std::task::Poll::Ready(Err(fault())),
            }
        })
        .await
        .inspect_err(|error| faulted(support, error))?;
        *state = SendState::Capacity;
        return Ok(());
    }
    let (m, bytes, funds) = prepared.inspect_err(|error| faulted(support, error))?;
    add(support, m.clone())?;
    *state = SendState::Ready(m, bytes, funds);
    Ok(())
}

// A retained intent proves original authorization only after the original
// literal/history guard passes. Repeat the same check after custody yields.
fn initial_authorized(index: &mut ScanIndex, support: &Path, m: &Manifest) -> bool {
    if !m.entities.iter().any(|entity| entity.literal) {
        return true;
    }
    let roots = m
        .scope
        .roots
        .iter()
        .map(|(root, files)| (root.as_str(), files.as_slice()))
        .collect::<Vec<_>>();
    index.initial_recovery_history_permitted(support, &roots)
        && current_literal_guard(index, m) == LiteralPermit::Permit
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
    bootstrap: bool,
    policy: [u8; 32],
    state: &mut SendState,
) -> Result<crate::snapshot_client::SnapshotBatchResponse> {
    if matches!(state, SendState::Capacity) {
        return Err(capacity_full());
    }
    if let SendState::Ready(manifest, _, _) = state {
        let matches = manifest.entities.len() == request.snapshots.len()
            && manifest
                .entities
                .iter()
                .zip(&request.snapshots)
                .all(|(entity, item)| {
                    entity.session == item.source_session_id
                        && entity.fingerprint == item.snapshot_fingerprint
                        && entity.witness == snapshot_upload_body_witness(item)
                });
        if !matches {
            // The uploader restarts after an async capture. Earlier ACKs may
            // change its pending packing; recover the already captured exact
            // partition, without changing or subdividing its retained body.
            return Err(UnsentPacking {
                kind: "captured_partition",
                resume: Some(
                    manifest
                        .entities
                        .iter()
                        .map(|e| e.fingerprint.clone())
                        .collect(),
                ),
            }
            .into());
        }
    }
    if matches!(state, SendState::Empty) {
        // Pay before copying private metadata from the already packed request.
        // Reject an oversized manifest before allocating the serialized body.
        let funds = money::ShadowReservation::admit(BODY_FUNDS).ok_or_else(capacity_full)?;
        let metadata_scratch =
            money::ShadowReservation::admit(8 * MANIFEST_MAX).ok_or_else(capacity_full)?;
        let m = manifest(
            support,
            index,
            request,
            binding.to_owned(),
            head_cas,
            policy,
        )?;
        if !manifest_fits(&m) {
            return Err(unsent_packing("envelope"));
        }
        drop(metadata_scratch);
        if CATALOGS
            .lock()
            .map_err(|_| fault())?
            .get(support)
            .is_some_and(|c| {
                c.entries.iter().any(|old| {
                    !old.ack_saved
                        && (old.scope.intersects(&m.scope)
                            || old.entities.iter().any(|e| {
                                m.entities
                                    .iter()
                                    .any(|new| new.root == e.root || new.session == e.session)
                            }))
                })
            })
        {
            return Err(Deferred {
                reason: None,
                not_before: now(support),
                route_unavailable: false,
                source_backoff: None,
            }
            .into());
        }
        if !initial_authorized(index, support, &m) {
            return Err(Deferred {
                reason: None,
                not_before: now(support),
                route_unavailable: false,
                source_backoff: None,
            }
            .into());
        }
        if money::recovery_released(support, &m.lineage) {
            let mut permitted = request.snapshots.clone();
            index.retain_claude_history_emission_permitted(&mut permitted);
            if permitted.len() != request.snapshots.len() {
                return Err(Deferred {
                    reason: None,
                    not_before: now(support),
                    route_unavailable: false,
                    source_backoff: None,
                }
                .into());
            }

            // A terminal lineage can make normal offers, but never acquire a
            // fresh UNKNOWN allowance through reserialization or restart.
            let body = encode(request, m.head_cas).map_err(|_| unsent_packing("wire"))?;
            if !initial_authorized(index, support, &m) {
                return Err(Deferred {
                    reason: None,
                    not_before: now(support),
                    route_unavailable: false,
                    source_backoff: None,
                }
                .into());
            }
            return client.upload_recovery_bytes(token, request, head_cas, &body);
        }
        let body = encode(request, m.head_cas).map_err(|_| unsent_packing("wire"))?;
        let full = CATALOGS
            .lock()
            .map_err(|_| fault())?
            .get(support)
            .is_some_and(|catalog| {
                let (slots, bytes) = if bootstrap {
                    (ACTIVE_MAX / 2, TOTAL_MAX / 2)
                } else {
                    (ACTIVE_MAX, TOTAL_MAX)
                };
                // Conservatively reserve every receipt slot and replacement temp.
                // This check precedes the durable latch admission and capture.
                let retained = catalog
                    .entries
                    .iter()
                    .fold(RECEIPT_BYTES_MAX + 4096, |n, entry| {
                        n.saturating_add(entry.length as u64 + 2 * MANIFEST_MAX as u64)
                    });
                catalog.entries.len() >= slots
                    || retained.saturating_add(body.len() as u64 + 2 * MANIFEST_MAX as u64) > bytes
            });
        if full {
            return Err(capacity_full());
        }
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
            source_backoff: None,
        }
        .into());
    }
    if !initial_authorized(index, support, &m) {
        return Err(Deferred {
            reason: None,
            not_before: now(support),
            route_unavailable: false,
            source_backoff: None,
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
            source_backoff: None,
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
        // The send intent is already durable. The caller saves ACK progress
        // next, then ack_saved persists that transition. Failure before that
        // save leaves the existing intent UNKNOWN without an intermediate
        // unchanged-manifest write or another writer turn.
        return result;
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
    let backoff = result.as_ref().err().and_then(source_backoff);
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
            source_backoff: backoff,
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
        let _handoff =
            money::ShadowReservation::admit(4 * MANIFEST_MAX).ok_or_else(capacity_full)?;
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
    let Some(scope) = money::recovery_scope::close(support, index, &m.scope) else {
        return Ok(false);
    };
    let roots = scope
        .roots
        .iter()
        .map(|(root, files)| (root.as_str(), files.as_slice()))
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
    account: &[u8; 32],
    policy: [u8; 32],
    authority: impl Fn() -> Result<()>,
) -> Result<()> {
    let binding = binding(namespace, client.recovery_origin(), machine, account);
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
            let reason = (guard == LiteralPermit::DenyAll).then_some(Reason::RevisionDowngrade);
            let updated = wait(outcome_ticket(support, cancelled, reason, now(support))?).await?;
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
        let backoff = result.as_ref().err().and_then(source_backoff);
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
        // Persist the immutable attempt's outcome first, then stop all further
        // replay/new POSTs through the existing source-level shed branch.
        if let Some(retry_after) = backoff {
            return Err(Backoff { retry_after }.into());
        }
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

    #[test]
    fn metadata_admission_prepays_capture_and_terminal_bookkeeping() {
        let (mut manifest, _) = specimen(1000);
        let (mut low, mut high) = (0, MANIFEST_MAX);
        while low < high {
            let middle = (low + high).div_ceil(2);
            manifest.context = "x".repeat(middle);
            if manifest_fits(&manifest) {
                low = middle;
            } else {
                high = middle - 1;
            }
        }
        manifest.context = "x".repeat(low);
        assert!(manifest_fits(&manifest));
        manifest.context.push('x');
        assert!(!manifest_fits(&manifest));
        manifest.context.pop();
        manifest.sha256 = "ab".repeat(32);
        manifest.length = BODY_MAX;
        manifest.not_before = u64::MAX;
        manifest.receipt_slot = Some((RECEIPT_MAX - 1) as u16);
        manifest.terminal = Some(Reason::RevisionDowngrade);
        let encoded = serde_json::to_vec(&CheckedManifestView {
            checksum: &"cd".repeat(32),
            manifest: &manifest,
        })
        .unwrap();
        assert!(
            encoded.len() <= MANIFEST_MAX,
            "admitted metadata must leave room for every durable bookkeeping field"
        );
    }
    fn specimen(created: u64) -> (Manifest, Vec<u8>) {
        let bytes = br#"{"schema_version":1,"snapshots":[{"synthetic":true}]}"#.to_vec();
        (
            Manifest {
                id: "ab".repeat(32),
                lineage: "ab".repeat(32),
                binding: "cd".repeat(32),
                context: "context".into(),
                policy: [0; 32],
                scope: {
                    let mut scope = money::recovery_scope::Scope::seed(["synthetic-root".into()]);
                    scope
                        .roots
                        .get_mut("synthetic-root")
                        .unwrap()
                        .push("/fixture/file.jsonl".into());
                    scope
                },
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
                        offer: None,
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
        prune_receipts(&root, (receipts[0].time_day + 35) * 86400, &[], 0).unwrap();
        assert!(!root.join("receipt-0000.receipt").exists());
        assert!(!root.join("receipt-0001.receipt").exists());
    }

    #[test]
    #[serial_test::serial(claude_request_money_shadow)]
    fn receipt_ttl_runs_on_a_quiet_warm_startup_without_new_offers() {
        let scratch = crate::test_scratch::ScratchDir::new("money-unknown-quiet-ttl");
        let (m, body) = specimen(1000);
        let m = capture(scratch.to_path_buf(), m, &body).unwrap();
        let receipt_at = m.deadline;
        terminal(
            scratch.to_path_buf(),
            m.clone(),
            Reason::Expired,
            receipt_at,
        )
        .unwrap();
        assert!(existing_recovery_state(&scratch).unwrap());
        startup_ready(&scratch, &m.binding, receipt_at + 1);
        let receipt = dir(&scratch).join("receipt-0000.receipt");
        assert!(receipt.exists());
        // Keep the same initialized catalog; changing day must start a paid
        // writer pass even when there are no active payloads or new offers.
        let expired = (receipt_at / 86400 + RECEIPT_TTL / 86400) * 86400;
        startup_ready(&scratch, &m.binding, expired);
        assert!(!receipt.exists());
        let status: serde_json::Value =
            serde_json::from_slice(&fs::read(dir(&scratch).join("status")).unwrap()).unwrap();
        assert_eq!(status["unknown_outcome_unresolved"], 0);
        assert_eq!(status["active_batches"], 0);
        assert!(!existing_recovery_state(&scratch).unwrap());
        forget(&scratch);
        money::store::forget_for_test(&scratch);
    }

    #[test]
    fn receipt_ttl_does_not_destroy_a_pending_retirement_proof_or_renew_its_age() {
        let scratch = crate::test_scratch::ScratchDir::new("money-unknown-retirement-ttl");
        let (m, body) = specimen(1000);
        let mut m = capture(scratch.to_path_buf(), m, &body).unwrap();
        m.terminal = Some(Reason::Expired);
        m.receipt_slot = Some(0);
        let receipt_at = m.deadline;
        write_manifest(&dir(&scratch), &m).unwrap();
        let receipt = Receipt {
            outcome: "unknown_outcome_unresolved".into(),
            reason: Reason::Expired,
            entities: m.entities.len(),
            age_hours: 24,
            time_day: receipt_at / 86400,
            attempts: 0,
            hash8: m.id[..8].into(),
        };
        let receipt_path = dir(&scratch).join("receipt-0000.receipt");
        atomic(
            &dir(&scratch),
            &receipt_path,
            &serde_json::to_vec(&receipt).unwrap(),
        )
        .unwrap();
        let later = (receipt.time_day + 35) * 86400;
        prune_receipts(&dir(&scratch), later, std::slice::from_ref(&m), 0).unwrap();
        assert!(
            receipt_path.exists(),
            "the body still needs its committed retirement proof"
        );
        terminal(scratch.to_path_buf(), m.clone(), Reason::Expired, later).unwrap();
        assert!(!path(&dir(&scratch), &m.id, "body").unwrap().exists());
        assert!(!path(&dir(&scratch), &m.id, "json").unwrap().exists());
        assert!(
            !receipt_path.exists(),
            "the original receipt expires instead of being written with a new day"
        );
        let status: serde_json::Value =
            serde_json::from_slice(&fs::read(dir(&scratch).join("status")).unwrap()).unwrap();
        assert_eq!(status["unknown_outcome_unresolved"], 0);
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
    fn sixteen_active_manifests_are_kept_when_the_seventeenth_is_refused() {
        let scratch = crate::test_scratch::ScratchDir::new("money-sixteen-manifest-limit");
        let (template, body) = specimen(1000);
        for number in 1..=16 {
            let mut manifest = template.clone();
            manifest.id = format!("{number:064x}");
            manifest.lineage = manifest.id.clone();
            capture(scratch.to_path_buf(), manifest, &body).unwrap();
        }
        let mut next = template;
        next.id = format!("{:064x}", 17);
        next.lineage = next.id.clone();
        assert!(capture(scratch.to_path_buf(), next, &body)
            .unwrap_err()
            .is::<CapacityFull>());
        let saved = load(&dir(&scratch)).unwrap();
        assert_eq!(saved.len(), 16);
        for manifest in saved {
            assert_eq!(
                read_capped(
                    &path(&dir(&scratch), &manifest.id, "body").unwrap(),
                    BODY_MAX
                )
                .unwrap(),
                body
            );
        }
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
        assert!(capture(scratch.to_path_buf(), m.clone(), &body)
            .unwrap_err()
            .is::<CapacityFull>());
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
