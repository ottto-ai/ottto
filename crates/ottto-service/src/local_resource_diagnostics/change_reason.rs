//! Why a body changed or was re-sent, by single first cause. Counts only:
//! never a gate, cap or body field, and nothing here feeds selection,
//! emission, ACK or placement. Tags are process-local and bounded to one
//! page: file tags live from selection to that page's upload, entity tags
//! for that upload only. A lost tag counts as `unattributed`, never guessed.
//! Each snapshot request names its items' tags in one count header
//! (`request_header`); never in the body.
use super::{source_count, source_slot, CHANGE_REASON_START};
use crate::snapshots::ScanIndex;
use crate::transcript_acquisition::{FullReason, ReadMode};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::Ordering::Relaxed;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Token {
    Append,
    FinalizerRevision,
    AccountEvidence,
    CopyOwnership,
    ParserRevision,
    AckRecovery,
    HeadConflict,
    PrivacyOffErase,
    SourceReset,
    DestinationBootstrap,
    AdminOther,
    OperatorRepair,
    Unattributed,
}
/// Which selection cause put a file under `admin_other`; read only with that
/// token. A fingerprint move is `FingerprintObject` when the opened-object
/// ctime witness differs from the entry's stored one (the object identity
/// moved, perhaps with a sidecar too); else `FingerprintUnattributed`: the
/// entry keeps no per-input digest, so a Desktop store, OTLP sidecar,
/// launcher context, inode or sampled-byte move cannot be told apart.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum AdminCause {
    FingerprintObject,
    FingerprintUnattributed,
    /// A non-money body-witness revision adoption.
    Adoption,
    /// A cleared entry fingerprint.
    Rearm,
    /// An account memo-miss.
    Memo,
    /// A new file after a fresh index without prior-history evidence.
    NewFileFreshIndex,
    Audit,
    #[default]
    Other,
}
const CAUSES: [&str; 8] = [
    "fingerprint_object",
    "fingerprint_unattributed",
    "adoption",
    "rearm",
    "memo",
    "new_file_fresh_index",
    "audit",
    "other",
];
const CAUSE_FIELDS: [&str; 2] = ["files", "native_bytes"];
/// The Tail restore outcome of a read's selection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Restore {
    Bypass,
    Miss,
    Hit,
    HitDiscardedByCap,
}
/// Selection-time labels of a read: its restore outcome and retry provenance.
#[derive(Clone, Copy, Debug, Default)]
struct Context {
    restore: Option<&'static str>,
    audit_cap: bool,
    partial_save: bool,
}
#[derive(Clone, Copy, Debug, Default, Serialize)]
struct Cells {
    files: u64,
    native_bytes: u64,
}
/// Bounds the partial-save restore flags awaiting their next selection.
const RESTORED_CAP: usize = 4096;
const TOKENS: [&str; 13] = [
    "append",
    "finalizer_revision",
    "account_evidence",
    "copy_ownership",
    "parser_revision",
    "ack_recovery",
    "head_conflict",
    "privacy_off_erase",
    "source_reset",
    "destination_bootstrap",
    "admin_other",
    "operator_repair",
    "unattributed",
];
/// Entity grain. `accepted` is every ACKed entity, stored or unchanged, so
/// `usage_identical` is its subset and the money column is the difference.
const FIELDS: [&str; 7] = [
    "entities",
    "accepted",
    "usage_identical",
    "placement_y",
    "placement_n",
    "placement_u",
    "upload_bytes",
];
const ENTITIES: usize = 0;
const ACCEPTED: usize = 1;
const USAGE_IDENTICAL: usize = 2;
const PLACEMENT_Y: usize = 3;
const PLACEMENT_N: usize = 4;
const PLACEMENT_U: usize = 5;
const UPLOAD_BYTES: usize = 6;
/// File grain, per reason.
const READ_FIELDS: [&str; 3] = ["files", "native_bytes", "validation_bytes"];
/// The refold pair counts fingerprint reads that continued from stored
/// state (not Full); by design they read 0 native bytes.
const SUB_COUNTS: [&str; 4] = [
    "source_reset_same_size_edit_files",
    "admin_other_sidecar_or_fingerprint_files",
    "admin_other_fingerprint_refold_files",
    "admin_other_fingerprint_refold_native_bytes",
];
/// Disclosed U, never a hidden zero: money-only reveals are invisible to the
/// daemon, and late external evidence stays in admin_other's
/// sidecar_or_fingerprint sub-count until a per-entry sidecar digest exists.
const UNKNOWN: [&str; 2] = ["money_only_reveal", "late_external_evidence"];
const UPLOAD_START: usize = CHANGE_REASON_START;
const READ_START: usize = UPLOAD_START + TOKENS.len() * FIELDS.len();
const SUB_START: usize = READ_START + TOKENS.len() * READ_FIELDS.len();
const CAUSE_START: usize = SUB_START + SUB_COUNTS.len();
pub(super) const END: usize = CAUSE_START + CAUSES.len() * CAUSE_FIELDS.len();

/// Claude session bits from this page's identity tagging.
const KNOWN: u8 = 1;
const MOVED: u8 = 2;
const ACCOUNT: u8 = 4;

#[derive(Clone, Copy, Default)]
struct Entity {
    token: Option<Token>,
    attempted: bool,
    settled: bool,
}
struct Upload {
    entities: BTreeMap<String, Entity>,
    sessions: BTreeMap<String, u8>,
}
impl Upload {
    const NEW: Self = Self {
        entities: BTreeMap::new(),
        sessions: BTreeMap::new(),
    };
}
struct Tags {
    /// Index key -> (source slot, first cause, `admin_other` cause, read
    /// context), selection to upload.
    files: BTreeMap<String, (usize, Token, AdminCause, Context)>,
    /// Index keys whose prior entry a partial save restored, until their next
    /// selection; at most `RESTORED_CAP`.
    restored: BTreeSet<String>,
    /// Per source: `admin_other` reads by joint label, until the page line.
    admin: [BTreeMap<String, Cells>; 3],
    sessions: BTreeMap<String, u8>,
    /// Per source: the cause of a `NewFile`, decided at index load.
    new_file: [Token; 3],
    /// Per source, process-local and never persisted: the latest sharing
    /// policy bits (`SEEN` once known), and `OFF` while the latest change
    /// turned a flag off.
    policy: [u8; 3],
    upload: [Upload; 3],
}
impl Tags {
    const NEW: Self = Self {
        files: BTreeMap::new(),
        restored: BTreeSet::new(),
        admin: [BTreeMap::new(), BTreeMap::new(), BTreeMap::new()],
        sessions: BTreeMap::new(),
        new_file: [Token::Append; 3],
        policy: [0; 3],
        upload: [Upload::NEW, Upload::NEW, Upload::NEW],
    };
}
#[cfg(not(test))]
fn with_tags<T>(f: impl FnOnce(&mut Tags) -> T) -> T {
    static TAGS: std::sync::Mutex<Tags> = std::sync::Mutex::new(Tags::NEW);
    f(&mut TAGS.lock().unwrap_or_else(|error| error.into_inner()))
}
#[cfg(test)]
fn with_tags<T>(f: impl FnOnce(&mut Tags) -> T) -> T {
    thread_local! { static TAGS: std::cell::RefCell<Tags> = const { std::cell::RefCell::new(Tags::NEW) }; }
    TAGS.with(|tags| f(&mut tags.borrow_mut()))
}
fn add(source: &str, slot: usize, amount: u64) {
    if amount != 0 {
        source_count(source, slot, |n| n.fetch_add(amount, Relaxed));
    }
}

/// At index load: a fresh index re-sends this destination's own history
/// (`source_reset`) or bootstraps a moved one; without prior-history evidence
/// (unreadable, or a source that records none) it is `admin_other`.
pub(crate) fn index_loaded(
    source: &str,
    fresh: bool,
    prior: Option<crate::snapshots::PriorHistory>,
) {
    use crate::snapshots::PriorHistory;
    let token = match (fresh, prior) {
        (false, _) | (true, Some(PriorHistory::None)) => Token::Append,
        (true, Some(PriorHistory::Here)) => Token::SourceReset,
        (true, Some(PriorHistory::Moved)) => Token::DestinationBootstrap,
        (true, _) => Token::AdminOther,
    };
    if let Some(slot) = source_slot(source) {
        with_tags(|tags| tags.new_file[slot] = token);
    }
}
pub(crate) fn new_file_token(source: &str) -> Token {
    source_slot(source).map_or(Token::AdminOther, |slot| {
        with_tags(|tags| tags.new_file[slot])
    })
}
const POLICY_SEEN: u8 = 1 << 6;
const POLICY_OFF: u8 = 1 << 7;
/// The source's sharing-policy bits (titles, workspace labels, artifacts,
/// attribution, attribution labels) at each upload-context check. A restart
/// forgets the direction: its reads stay `admin_other`, never guessed.
pub(crate) fn upload_policy(source: &str, bits: u8) {
    let Some(slot) = source_slot(source) else {
        return;
    };
    with_tags(|tags| {
        let last = tags.policy[slot];
        let flipped = (last ^ bits) & !(POLICY_SEEN | POLICY_OFF);
        let off = if last & POLICY_SEEN == 0 || flipped == 0 {
            last & POLICY_OFF
        } else if flipped & !bits != 0 {
            POLICY_OFF
        } else {
            0
        };
        tags.policy[slot] = bits | POLICY_SEEN | off;
    });
}
/// An upload-context read of a delivered file while the latest sharing
/// change this process saw turned a flag off.
pub(crate) fn privacy_off(source: &str) -> bool {
    source_slot(source).is_some_and(|slot| with_tags(|tags| tags.policy[slot] & POLICY_OFF != 0))
}
fn moved_fingerprint(cause: AdminCause) -> bool {
    matches!(
        cause,
        AdminCause::FingerprintObject | AdminCause::FingerprintUnattributed
    )
}
/// A file the scan is about to read, with its selection-time first cause.
pub(crate) fn selected(source: &str, key: String, token: Token, cause: AdminCause) {
    let Some(slot) = source_slot(source) else {
        return;
    };
    if token == Token::AdminOther && moved_fingerprint(cause) {
        add(source, SUB_START + 1, 1);
    }
    with_tags(|tags| {
        // A Tail load refused on an owed head-CAS answer tags its read first;
        // the selection tag that follows keeps it.
        let tag = (slot, token, cause, Context::default());
        let old = tags.files.entry(key).or_insert(tag);
        if old.1 != Token::HeadConflict {
            *old = tag;
        }
    });
}
/// A completed read. Growth read as a replacing Full is a source reset.
pub(crate) fn read(
    source: &str,
    key: &str,
    mode: ReadMode,
    native_bytes: u64,
    validation_bytes: u64,
) {
    let reset = matches!(
        mode,
        ReadMode::Full(
            FullReason::Replaced
                | FullReason::Shrunk
                | FullReason::SameSizeEdit
                | FullReason::InvalidCheckpoint
        )
    );
    let (token, cause) = with_tags(|tags| match tags.files.get_mut(key) {
        Some((_, token, cause, _)) => {
            if reset && *token == Token::Append {
                *token = Token::SourceReset;
            }
            (*token, *cause)
        }
        None => (Token::Unattributed, AdminCause::Other),
    });
    if token == Token::SourceReset && mode == ReadMode::Full(FullReason::SameSizeEdit) {
        add(source, SUB_START, 1);
    }
    let row = READ_START + token as usize * READ_FIELDS.len();
    for (field, amount) in [1, native_bytes, validation_bytes].into_iter().enumerate() {
        add(source, row + field, amount);
    }
    if token == Token::AdminOther {
        let row = CAUSE_START + cause as usize * CAUSE_FIELDS.len();
        add(source, row, 1);
        add(source, row + 1, native_bytes);
        if moved_fingerprint(cause) && !matches!(mode, ReadMode::Full(_)) {
            add(source, SUB_START + 2, 1);
            add(source, SUB_START + 3, native_bytes);
        }
    }
}
/// A partial save restored this key's prior entry (process-local only).
pub(crate) fn partial_save_restored(key: &str) {
    with_tags(|tags| {
        if tags.restored.len() < RESTORED_CAP {
            tags.restored.insert(key.to_owned());
        }
    });
}
/// Right after selection: the restore outcome, with `(seal, indexed size,
/// opening extent)` on a kept hit, and the retry provenance (an outstanding
/// audit-cap clear; a partial-save restore flag, read and cleared here).
pub(crate) fn read_context(key: &str, restore: Restore, extent: Option<(u64, u64, u64)>) {
    let audit_cap = super::rearm_cause::audit_cap_cleared(key);
    let restore = match (restore, extent) {
        (Restore::Hit, Some((seal, indexed, opening))) => {
            match (seal < indexed, opening > indexed) {
                (true, true) => "hit.both",
                (true, false) => "hit.indexed_gap",
                (false, true) => "hit.new_bytes",
                (false, false) => "hit.neither",
            }
        }
        (Restore::Hit, None) => "hit",
        (Restore::Miss, _) => "miss",
        (Restore::Bypass, _) => "bypass",
        (Restore::HitDiscardedByCap, _) => "hit_discarded_by_cap",
    };
    with_tags(|tags| {
        let partial_save = tags.restored.remove(key);
        if let Some(tag) = tags.files.get_mut(key) {
            tag.3 = Context {
                restore: Some(restore),
                audit_cap,
                partial_save,
            };
        }
    });
}
/// Every completed body read, with or without an acquisition plan
/// `(mode, native bytes)`. An `admin_other` read counts under
/// `<cause>.<mode>`, `<cause>.restore.<outcome>` and
/// `<cause>.retry.<provenance>`. Without a plan its parser bytes count under
/// `no_plan`, never in `read`, so the planned rows still reconcile.
pub(crate) fn admin_read(
    source: &str,
    key: &str,
    plan: Option<(ReadMode, u64)>,
    parser_bytes: u64,
) {
    let Some(slot) = source_slot(source) else {
        return;
    };
    let (mode, bytes) = match plan {
        Some((ReadMode::Full(reason), bytes)) => {
            let reason = serde_json::to_value(reason).unwrap_or_default();
            (
                format!("full:{}", reason.as_str().unwrap_or("unknown")),
                bytes,
            )
        }
        Some((ReadMode::Tail, bytes)) => ("tail".to_owned(), bytes),
        Some((ReadMode::Unchanged, bytes)) => ("unchanged".to_owned(), bytes),
        None => ("no_plan".to_owned(), parser_bytes),
    };
    with_tags(|tags| {
        let Some(&(_, Token::AdminOther, cause, context)) = tags.files.get(key) else {
            return;
        };
        let labels = [
            Some(mode),
            context.restore.map(|outcome| format!("restore.{outcome}")),
            context
                .audit_cap
                .then(|| "retry.audit_cap_clear".to_owned()),
            context
                .partial_save
                .then(|| "retry.partial_save_restore".to_owned()),
        ];
        for label in labels.into_iter().flatten() {
            let cells = tags.admin[slot]
                .entry(format!("{}.{label}", CAUSES[cause as usize]))
                .or_default();
            cells.files = cells.files.saturating_add(1);
            cells.native_bytes = cells.native_bytes.saturating_add(bytes);
        }
    });
}
/// Claude identity tagging: `moved` is `None` without complete accepted state.
pub(crate) fn claude_placement(session: &str, moved: Option<bool>) {
    if let Some(moved) = moved {
        let bits = if moved { KNOWN | MOVED } else { KNOWN };
        with_tags(|tags| *tags.sessions.entry(session.to_owned()).or_default() |= bits);
    }
}
pub(crate) fn claude_account_evidence_applied(session: &str) {
    with_tags(|tags| *tags.sessions.entry(session.to_owned()).or_default() |= ACCOUNT);
}
/// Before the page's first attempt: this source's file tags become entity
/// tags through the scanned index. Replaces the previous page's entities.
pub(crate) fn propagate(source: &str, index: &ScanIndex) {
    let Some(slot) = source_slot(source) else {
        return;
    };
    with_tags(|tags| {
        let mut entities = BTreeMap::new();
        tags.files.retain(|key, (owner, token, _, _)| {
            if *owner != slot {
                return true;
            }
            for fingerprint in index
                .file_snapshot_fingerprints
                .get(key.as_str())
                .into_iter()
                .flatten()
            {
                let entity = Entity {
                    token: Some(*token),
                    ..Entity::default()
                };
                entities.insert(fingerprint.clone(), entity);
            }
            false
        });
        let sessions = std::mem::take(&mut tags.sessions);
        tags.upload[slot] = Upload { entities, sessions };
    });
}
/// Once per entity and page. `resend` is the delivery cause of an exact
/// resend; a changed body keeps its selection tag.
pub(crate) fn attempted(
    source: &str,
    fingerprint: &str,
    session: Option<&str>,
    resend: Option<Token>,
    bytes: u64,
) {
    let Some(slot) = source_slot(source) else {
        return;
    };
    let counted = with_tags(|tags| {
        let upload = &mut tags.upload[slot];
        let bits = session
            .and_then(|session| upload.sessions.get(session))
            .copied()
            .unwrap_or(0);
        let entity = upload.entities.entry(fingerprint.to_owned()).or_default();
        if entity.attempted {
            return None;
        }
        entity.attempted = true;
        let mut token = resend.or(entity.token).unwrap_or(Token::Unattributed);
        // Reveal: a moved Claude placement under own-account evidence.
        if bits & (MOVED | ACCOUNT) == MOVED | ACCOUNT
            && matches!(
                token,
                Token::AdminOther | Token::AckRecovery | Token::HeadConflict
            )
        {
            token = Token::AccountEvidence;
        }
        entity.token = Some(token);
        Some((token, bits))
    });
    let Some((token, bits)) = counted else {
        return;
    };
    let placement = if bits & MOVED != 0 {
        PLACEMENT_Y
    } else if bits & KNOWN != 0 {
        PLACEMENT_N
    } else {
        PLACEMENT_U
    };
    let row = UPLOAD_START + token as usize * FIELDS.len();
    add(source, row + ENTITIES, 1);
    add(source, row + placement, 1);
    add(source, row + UPLOAD_BYTES, bytes);
}
/// An entity ACK (stored or unchanged) for an entity attempted this page.
pub(crate) fn settled(source: &str, fingerprint: &str, usage_identical: bool) {
    let Some(slot) = source_slot(source) else {
        return;
    };
    let token = with_tags(|tags| {
        let entity = tags.upload[slot].entities.get_mut(fingerprint)?;
        if entity.settled {
            return None;
        }
        entity.settled = true;
        entity.token
    });
    if let Some(token) = token {
        let row = UPLOAD_START + token as usize * FIELDS.len();
        add(source, row + ACCEPTED, 1);
        add(source, row + USAGE_IDENTICAL, u64::from(usage_identical));
    }
}

/// One request's `X-Ottto-Upload-Reason` value: each item's attempted tag
/// as `name=count`, in token order, nonzero only. An item this page never
/// attempted counts as `unattributed`.
pub(crate) fn request_header<'a>(
    source: &str,
    fingerprints: impl IntoIterator<Item = &'a str>,
) -> String {
    let slot = source_slot(source);
    let mut counts = [0u64; TOKENS.len()];
    with_tags(|tags| {
        for fingerprint in fingerprints {
            let token = slot
                .and_then(|slot| tags.upload[slot].entities.get(fingerprint))
                .filter(|entity| entity.attempted)
                .and_then(|entity| entity.token)
                .unwrap_or(Token::Unattributed);
            counts[token as usize] += 1;
        }
    });
    TOKENS
        .into_iter()
        .zip(counts)
        .filter(|(_, n)| *n != 0)
        .map(|(name, n)| format!("{name}={n}"))
        .collect::<Vec<_>>()
        .join(",")
}

/// One page line's nonzero rows.
#[derive(Debug, Default, Serialize)]
pub(crate) struct Page {
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    upload: BTreeMap<&'static str, BTreeMap<&'static str, u64>>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    read: BTreeMap<&'static str, BTreeMap<&'static str, u64>>,
    #[serde(flatten)]
    sub_counts: BTreeMap<&'static str, u64>,
    /// `admin_other` reads per selection cause.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    admin_other_cause: BTreeMap<&'static str, BTreeMap<&'static str, u64>>,
    /// `admin_other` reads by joint label, from `admin_read`.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    admin_other_read: BTreeMap<String, Cells>,
    unknown: [&'static str; 2],
}
pub(crate) fn drain(source: &str) -> Option<Page> {
    let take = |slot: usize| source_count(source, slot, |n| n.swap(0, Relaxed));
    let cells = |base: usize, labels: &[&'static str]| {
        labels
            .iter()
            .enumerate()
            .map(|(field, label)| (*label, take(base + field)))
            .filter(|(_, n)| *n != 0)
            .collect::<BTreeMap<_, _>>()
    };
    let mut page = Page {
        unknown: UNKNOWN,
        ..Page::default()
    };
    for (token, name) in TOKENS.into_iter().enumerate() {
        let mut row = cells(UPLOAD_START + token * FIELDS.len(), &FIELDS[..]);
        if let Some(&accepted) = row.get("accepted") {
            let identical = row.get("usage_identical").copied().unwrap_or(0);
            row.insert(
                "money_changed_or_unknown",
                accepted.saturating_sub(identical),
            );
        }
        if !row.is_empty() {
            page.upload.insert(name, row);
        }
        let read = cells(READ_START + token * READ_FIELDS.len(), &READ_FIELDS[..]);
        if !read.is_empty() {
            page.read.insert(name, read);
        }
    }
    page.sub_counts = cells(SUB_START, &SUB_COUNTS[..]);
    for (cause, name) in CAUSES.into_iter().enumerate() {
        let row = cells(CAUSE_START + cause * CAUSE_FIELDS.len(), &CAUSE_FIELDS[..]);
        if !row.is_empty() {
            page.admin_other_cause.insert(name, row);
        }
    }
    if let Some(slot) = source_slot(source) {
        page.admin_other_read = with_tags(|tags| std::mem::take(&mut tags.admin[slot]));
    }
    (!page.upload.is_empty()
        || !page.read.is_empty()
        || !page.sub_counts.is_empty()
        || !page.admin_other_read.is_empty())
    .then_some(page)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// [behaviour] A body whose tag was lost (a restart drops every tag) or
    /// never set counts once under `unattributed`, with unknown placement.
    #[test]
    fn lost_tag_counts_unattributed_once() {
        selected(
            "pi",
            "synthetic-key".into(),
            Token::Append,
            AdminCause::Other,
        );
        with_tags(|tags| *tags = Tags::NEW);
        propagate("pi", &ScanIndex::default());
        attempted("pi", "synthetic-entity", None, None, 5);
        attempted("pi", "synthetic-entity", None, None, 5);
        settled("pi", "synthetic-entity", true);
        let page = serde_json::to_value(drain("pi").unwrap()).unwrap();
        assert_eq!(page["upload"].as_object().unwrap().len(), 1);
        let row = &page["upload"]["unattributed"];
        assert_eq!(row["entities"], 1);
        assert_eq!(row["upload_bytes"], 5);
        assert_eq!(row["placement_u"], 1);
        assert_eq!(row["accepted"], 1);
        assert_eq!(row["money_changed_or_unknown"], 0);
        assert_eq!(page["unknown"][0], "money_only_reveal");
        assert!(drain("pi").is_none(), "the line drains its slots");
    }

    /// [behaviour] A request names each item's attempted tag once, a retry
    /// keeps it, and an item never attempted or from another source is
    /// `unattributed`.
    #[test]
    fn request_header_counts_attempted_tags_per_request() {
        selected(
            "codex",
            "synthetic-key".into(),
            Token::ParserRevision,
            AdminCause::Other,
        );
        let mut index = ScanIndex::default();
        index.file_snapshot_fingerprints.insert(
            "synthetic-key".into(),
            std::collections::BTreeSet::from(["changed".into()]),
        );
        propagate("codex", &index);
        attempted("codex", "changed", None, None, 1);
        attempted("codex", "held", None, Some(Token::AckRecovery), 1);
        attempted("codex", "held-too", None, Some(Token::AckRecovery), 1);
        attempted("codex", "held", None, None, 1);
        assert_eq!(
            request_header("codex", ["held", "changed", "held-too", "unseen"]),
            "parser_revision=1,ack_recovery=2,unattributed=1"
        );
        assert_eq!(request_header("pi", ["changed"]), "unattributed=1");
        assert_eq!(request_header("codex", []), "");
    }

    /// [behaviour] A `head_conflict` tag survives a later selection of the
    /// same file; any other tag is replaced by the later selection.
    #[test]
    fn a_head_conflict_tag_survives_a_later_selection() {
        selected("pi", "owed".into(), Token::HeadConflict, AdminCause::Other);
        selected("pi", "owed".into(), Token::CopyOwnership, AdminCause::Other);
        selected("pi", "other".into(), Token::Append, AdminCause::Other);
        selected(
            "pi",
            "other".into(),
            Token::CopyOwnership,
            AdminCause::Other,
        );
        read("pi", "owed", ReadMode::Tail, 3, 0);
        read("pi", "other", ReadMode::Tail, 5, 0);
        let page = serde_json::to_value(drain("pi").unwrap()).unwrap();
        assert_eq!(page["read"]["head_conflict"]["files"], 1);
        assert_eq!(page["read"]["head_conflict"]["native_bytes"], 3);
        assert_eq!(page["read"]["copy_ownership"]["files"], 1);
        assert_eq!(page["read"]["copy_ownership"]["native_bytes"], 5);
        assert!(page["read"].get("append").is_none());
    }

    /// [behaviour] Each `admin_other` read counts once under its selection
    /// cause; a fingerprint read that continued from stored state also counts
    /// as a refold with its native bytes, and a Full one does not.
    #[test]
    fn admin_other_reads_split_by_cause() {
        use AdminCause as C;
        let cases = [
            (C::FingerprintObject, "fingerprint_object"),
            (C::FingerprintUnattributed, "fingerprint_unattributed"),
            (C::Adoption, "adoption"),
            (C::Rearm, "rearm"),
            (C::Memo, "memo"),
            (C::NewFileFreshIndex, "new_file_fresh_index"),
            (C::Audit, "audit"),
            (C::Other, "other"),
        ];
        for (n, (cause, name)) in (1u64..).zip(cases) {
            selected("pi", "admin".into(), Token::AdminOther, cause);
            read("pi", "admin", ReadMode::Tail, n, 2);
            let page = serde_json::to_value(drain("pi").unwrap()).unwrap();
            let split = page["admin_other_cause"].as_object().unwrap();
            assert_eq!(split.len(), 1, "{name}");
            assert_eq!(split[name]["files"], 1, "{name}");
            assert_eq!(split[name]["native_bytes"], n, "{name}");
            assert_eq!(page["read"]["admin_other"]["native_bytes"], n);
            let moved = matches!(cause, C::FingerprintObject | C::FingerprintUnattributed);
            let refold = &page["admin_other_fingerprint_refold_native_bytes"];
            assert_eq!(refold.as_u64(), moved.then_some(n), "{name}");
            assert_eq!(
                page["admin_other_sidecar_or_fingerprint_files"].as_u64(),
                moved.then_some(1),
                "{name}"
            );
        }
        selected("pi", "full".into(), Token::AdminOther, C::FingerprintObject);
        selected("pi", "kept".into(), Token::CopyOwnership, C::Memo);
        read("pi", "full", ReadMode::Full(FullReason::StateMissing), 9, 0);
        read("pi", "kept", ReadMode::Tail, 4, 0);
        let page = serde_json::to_value(drain("pi").unwrap()).unwrap();
        assert_eq!(
            page["admin_other_cause"]["fingerprint_object"]["native_bytes"],
            9
        );
        assert_eq!(page["admin_other_cause"].as_object().unwrap().len(), 1);
        assert!(page.get("admin_other_fingerprint_refold_files").is_none());
    }

    /// [behaviour] An `admin_other` read counts under its cause with its
    /// actual mode (no-plan parser bytes never in `read`) and its restore
    /// outcome, a kept hit by its seal against index size and opening extent.
    #[test]
    fn admin_other_read_counts_mode_and_restore() {
        let full = Some((ReadMode::Full(FullReason::StateMissing), 7));
        let cases = [
            (
                Restore::Hit,
                Some((5, 10, 12)),
                Some((ReadMode::Tail, 3)),
                "hit.both",
                "tail",
            ),
            (
                Restore::Hit,
                Some((5, 10, 10)),
                Some((ReadMode::Unchanged, 0)),
                "hit.indexed_gap",
                "unchanged",
            ),
            (
                Restore::Hit,
                Some((10, 10, 12)),
                full,
                "hit.new_bytes",
                "full:state_missing",
            ),
            (
                Restore::Hit,
                Some((10, 10, 10)),
                full,
                "hit.neither",
                "full:state_missing",
            ),
            (Restore::Hit, None, full, "hit", "full:state_missing"),
            (Restore::Miss, None, full, "miss", "full:state_missing"),
            (
                Restore::HitDiscardedByCap,
                Some((5, 10, 12)),
                full,
                "hit_discarded_by_cap",
                "full:state_missing",
            ),
            (Restore::Bypass, None, None, "bypass", "no_plan"),
        ];
        for (restore, extent, plan, outcome, mode) in cases {
            selected("pi", "k".into(), Token::AdminOther, AdminCause::Rearm);
            read_context("k", restore, extent);
            admin_read("pi", "k", plan, 9);
            let bytes = plan.map_or(9, |(_, bytes)| bytes);
            let page = serde_json::to_value(drain("pi").unwrap()).unwrap();
            let labels = page["admin_other_read"].as_object().unwrap();
            assert_eq!(labels.len(), 2, "{outcome}");
            for label in [format!("rearm.restore.{outcome}"), format!("rearm.{mode}")] {
                assert_eq!(labels[&label]["files"], 1, "{label}");
                assert_eq!(labels[&label]["native_bytes"], bytes, "{label}");
            }
            assert!(page.get("read").is_none(), "{outcome}");
        }
    }

    /// [behaviour] Retry provenance: an outstanding audit-cap clear, and a
    /// partial-save restore flag that the next selection reads and clears.
    /// Another first cause counts nowhere.
    #[test]
    fn admin_other_read_counts_retry_provenance() {
        use crate::local_resource_diagnostics::rearm_cause::{self, Cause};
        let mut entry = crate::snapshots::ScanIndexEntry {
            source_file_fingerprint: "old".into(),
            ..Default::default()
        };
        rearm_cause::clear("cap", &mut entry, Cause::AuditCapDelay);
        partial_save_restored("saved");
        let read_once = |key: &str, token| {
            selected("pi", key.into(), token, AdminCause::Other);
            read_context(key, Restore::Bypass, None);
            admin_read("pi", key, None, 4);
        };
        for key in ["cap", "saved", "plain"] {
            read_once(key, Token::AdminOther);
        }
        let page = serde_json::to_value(drain("pi").unwrap()).unwrap();
        let labels = page["admin_other_read"].as_object().unwrap();
        assert_eq!(labels["other.retry.audit_cap_clear"]["native_bytes"], 4);
        assert_eq!(labels["other.retry.partial_save_restore"]["files"], 1);
        assert_eq!(labels["other.no_plan"]["files"], 3);
        assert_eq!(labels["other.restore.bypass"]["native_bytes"], 12);
        read_once("saved", Token::AdminOther);
        read_once("kept", Token::CopyOwnership);
        let page = serde_json::to_value(drain("pi").unwrap()).unwrap();
        let labels = page["admin_other_read"].as_object().unwrap();
        assert_eq!(labels.len(), 2, "the flag was cleared at selection");
        assert_eq!(labels["other.no_plan"]["files"], 1);
    }
}
