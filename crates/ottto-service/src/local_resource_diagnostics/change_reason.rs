//! Why a body changed or was re-sent, by single first cause. Counts only:
//! never a gate, cap or wire field, and nothing here feeds selection,
//! emission, ACK or placement. Tags are process-local and bounded to one
//! page: file tags live from selection to that page's upload, entity tags
//! for that upload only. A lost tag counts as `unattributed`, never guessed.
use super::{source_count, source_slot, CHANGE_REASON_START};
use crate::snapshots::ScanIndex;
use crate::transcript_acquisition::{FullReason, ReadMode};
use serde::Serialize;
use std::collections::BTreeMap;
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
/// File grain: reason x read mode. A read mode is how, never why.
const MODES: [&str; 6] = [
    "tail",
    "state_missing",
    "scope_changed",
    "audit_due",
    "clock_changed",
    "other",
];
const READ_FIELDS: [&str; 3] = ["files", "native_bytes", "validation_bytes"];
const SUB_COUNTS: [&str; 2] = [
    "source_reset_same_size_edit_files",
    "admin_other_sidecar_or_fingerprint_files",
];
/// Disclosed U, never a hidden zero: money-only reveals are invisible to the
/// daemon, and late external evidence stays in admin_other's
/// sidecar_or_fingerprint sub-count until a per-entry sidecar digest exists.
const UNKNOWN: [&str; 2] = ["money_only_reveal", "late_external_evidence"];
const UPLOAD_START: usize = CHANGE_REASON_START;
const READ_START: usize = UPLOAD_START + TOKENS.len() * FIELDS.len();
const SUB_START: usize = READ_START + TOKENS.len() * MODES.len() * READ_FIELDS.len();
pub(super) const END: usize = SUB_START + SUB_COUNTS.len();

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
    /// Index key -> (source slot, first cause), selection to upload.
    files: BTreeMap<String, (usize, Token)>,
    sessions: BTreeMap<String, u8>,
    /// Per source: the cause of a `NewFile`, decided at index load.
    new_file: [Token; 3],
    upload: [Upload; 3],
}
impl Tags {
    const NEW: Self = Self {
        files: BTreeMap::new(),
        sessions: BTreeMap::new(),
        new_file: [Token::Append; 3],
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
/// A file the scan is about to read, with its selection-time first cause.
pub(crate) fn selected(source: &str, key: String, token: Token, sidecar_or_fingerprint: bool) {
    let Some(slot) = source_slot(source) else {
        return;
    };
    if sidecar_or_fingerprint {
        add(source, SUB_START + 1, 1);
    }
    with_tags(|tags| {
        tags.files.insert(key, (slot, token));
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
    let token = with_tags(|tags| match tags.files.get_mut(key) {
        Some((_, token)) => {
            if reset && *token == Token::Append {
                *token = Token::SourceReset;
            }
            *token
        }
        None => Token::Unattributed,
    });
    if token == Token::SourceReset && mode == ReadMode::Full(FullReason::SameSizeEdit) {
        add(source, SUB_START, 1);
    }
    let mode = match mode {
        ReadMode::Tail => 0,
        ReadMode::Full(FullReason::StateMissing) => 1,
        ReadMode::Full(FullReason::ScopeChanged) => 2,
        ReadMode::Full(FullReason::AuditDue) => 3,
        ReadMode::Full(FullReason::ClockChanged) => 4,
        _ => 5,
    };
    let row = READ_START + (token as usize * MODES.len() + mode) * READ_FIELDS.len();
    for (field, amount) in [1, native_bytes, validation_bytes].into_iter().enumerate() {
        add(source, row + field, amount);
    }
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
        tags.files.retain(|key, (owner, token)| {
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

/// One page line's nonzero rows.
#[derive(Debug, Default, Serialize)]
pub(crate) struct Page {
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    upload: BTreeMap<&'static str, BTreeMap<&'static str, u64>>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    read: BTreeMap<&'static str, BTreeMap<&'static str, BTreeMap<&'static str, u64>>>,
    #[serde(flatten)]
    sub_counts: BTreeMap<&'static str, u64>,
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
        let modes = MODES
            .into_iter()
            .enumerate()
            .map(|(mode, label)| {
                let base = READ_START + (token * MODES.len() + mode) * READ_FIELDS.len();
                (label, cells(base, &READ_FIELDS[..]))
            })
            .filter(|(_, cell)| !cell.is_empty())
            .collect::<BTreeMap<_, _>>();
        if !modes.is_empty() {
            page.read.insert(name, modes);
        }
    }
    page.sub_counts = cells(SUB_START, &SUB_COUNTS[..]);
    (!page.upload.is_empty() || !page.read.is_empty() || !page.sub_counts.is_empty())
        .then_some(page)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// [behaviour] A body whose tag was lost (a restart drops every tag) or
    /// never set counts once under `unattributed`, with unknown placement.
    #[test]
    fn lost_tag_counts_unattributed_once() {
        selected("pi", "synthetic-key".into(), Token::Append, false);
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
}
