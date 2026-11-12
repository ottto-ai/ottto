//! The first read's import list (`tail.first_read`, layout 8): one member row
//! per history file of a destination's first read, plus one summary row of
//! running totals. Rows change only inside `tail::apply`, in the same commit
//! as the file's debt and the pass's ACK state, so the totals never get ahead
//! of what is saved and a restart reads one row. Rows are only added or
//! reclassified, never removed, until the import is done ("frozen"); then the
//! member rows go and the summary is kept as the terminal record.
//!
//! The summary row's key starts with `:`; file keys are absolute paths.
use super::*;

pub(super) const SUMMARY_KEY: &[u8] = b":first_read";
const MEMBER_V1: u8 = 1;
const MEMBER_BYTES: usize = 11;
const SUMMARY_V1: u8 = 1;
/// Age buckets: 0 older than every boundary .. 4 newest, unknown or future.
pub(in crate::snapshots) const BUCKETS: usize = 5;

/// One member's class. Done never regresses; deleted-excluded is terminal.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(in crate::snapshots) enum Class {
    Owed = 1,
    Held = 2,
    Failed = 3,
    ExcludedPolicy = 4,
    ExcludedDeleted = 5,
    Done = 6,
}
impl Class {
    fn decode(byte: u8) -> Option<Self> {
        Some(match byte {
            1 => Self::Owed,
            2 => Self::Held,
            3 => Self::Failed,
            4 => Self::ExcludedPolicy,
            5 => Self::ExcludedDeleted,
            6 => Self::Done,
            _ => return None,
        })
    }
}

/// One member row: `[v1][class][bucket][bytes u64]`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::snapshots) struct Member {
    pub(in crate::snapshots) class: Class,
    /// The age witness bucket (`BUCKETS`), kept by tombstones.
    pub(in crate::snapshots) bucket: u8,
    /// The highest on-disk length seen while not done; frozen at done.
    pub(in crate::snapshots) bytes: u64,
}
impl Member {
    pub(in crate::snapshots) fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(MEMBER_BYTES);
        out.extend_from_slice(&[MEMBER_V1, self.class as u8, self.bucket]);
        out.extend_from_slice(&self.bytes.to_be_bytes());
        out
    }
    /// `None`: another version or a damaged value.
    pub(in crate::snapshots) fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != MEMBER_BYTES || bytes[0] != MEMBER_V1 || usize::from(bytes[2]) >= BUCKETS
        {
            return None;
        }
        Some(Self {
            class: Class::decode(bytes[1])?,
            bucket: bytes[2],
            bytes: u64::from_be_bytes(bytes[3..11].try_into().ok()?),
        })
    }
}

/// A member as one observation sees it, before the committed row resolves it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::snapshots) struct Observed {
    pub(in crate::snapshots) member: Member,
    /// No import debt is left but no positive proof was seen: done only when
    /// the committed row says the file was a member owing import debt.
    pub(in crate::snapshots) debt_gone: bool,
}

/// The committed row after `observed`: done never regresses (its bytes stay
/// frozen), a deleted exclusion stays one, a member whose import debt left by
/// an exact ACK or no-upload proof is done, and bytes never shrink.
pub(in crate::snapshots) fn resolve(old: Option<Member>, observed: Observed) -> Member {
    let new = observed.member;
    match old {
        Some(old) if matches!(old.class, Class::Done | Class::ExcludedDeleted) => old,
        Some(old) => Member {
            class: if observed.debt_gone {
                Class::Done
            } else {
                new.class
            },
            bucket: new.bucket,
            bytes: old.bytes.max(new.bytes),
        },
        None => new,
    }
}

/// The running totals of one generation, and its terminal record once frozen.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(in crate::snapshots) struct Summary {
    pub(in crate::snapshots) anchor_at_ms: u64,
    pub(in crate::snapshots) certified_at_ms: Option<u64>,
    pub(in crate::snapshots) counts: Counts,
    /// Enabled-source bitmask over `durable_sources::SOURCES` ordinals.
    pub(in crate::snapshots) sources_enabled: u64,
    pub(in crate::snapshots) done_at_ms: Option<u64>,
}
/// Member counts; `members - done - excluded - failed - held` are owed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(in crate::snapshots) struct Counts {
    pub(in crate::snapshots) members: u64,
    pub(in crate::snapshots) bytes_total: u64,
    pub(in crate::snapshots) done: u64,
    pub(in crate::snapshots) bytes_done: u64,
    pub(in crate::snapshots) held: u64,
    pub(in crate::snapshots) failed: u64,
    pub(in crate::snapshots) excluded: u64,
    /// Members that are not done, per age bucket: they obstruct coverage.
    pub(in crate::snapshots) obstruct: [u64; BUCKETS],
}
impl Counts {
    pub(in crate::snapshots) fn owed(&self) -> u64 {
        self.members
            .saturating_sub(self.done)
            .saturating_sub(self.excluded)
            .saturating_sub(self.failed)
            .saturating_sub(self.held)
    }
    fn tally(&mut self, member: Member, add: bool) {
        let step = |value: &mut u64, by: u64| {
            *value = if add {
                value.saturating_add(by)
            } else {
                value.saturating_sub(by)
            };
        };
        step(&mut self.members, 1);
        step(&mut self.bytes_total, member.bytes);
        match member.class {
            Class::Done => {
                step(&mut self.done, 1);
                step(&mut self.bytes_done, member.bytes);
            }
            Class::Held => step(&mut self.held, 1),
            Class::Failed => step(&mut self.failed, 1),
            Class::ExcludedPolicy | Class::ExcludedDeleted => step(&mut self.excluded, 1),
            Class::Owed => {}
        }
        if member.class != Class::Done {
            step(&mut self.obstruct[usize::from(member.bucket)], 1);
        }
    }
    fn replace(&mut self, old: Option<Member>, new: Member) {
        if let Some(old) = old {
            self.tally(old, false);
        }
        self.tally(new, true);
    }
}
impl Summary {
    pub(in crate::snapshots) fn open(&self) -> bool {
        self.done_at_ms.is_none()
    }
    /// Certified and nothing failed, held or owed.
    fn resolved(&self) -> bool {
        self.certified_at_ms.is_some()
            && self.counts.held == 0
            && self.counts.failed == 0
            && self.counts.owed() == 0
    }
    fn encode(&self) -> Vec<u8> {
        let mut out = vec![SUMMARY_V1];
        let mut word = |value: u64| out.extend_from_slice(&value.to_be_bytes());
        let c = &self.counts;
        word(self.anchor_at_ms);
        word(u64::from(self.certified_at_ms.is_some()));
        word(self.certified_at_ms.unwrap_or_default());
        for value in [
            c.members,
            c.bytes_total,
            c.done,
            c.bytes_done,
            c.held,
            c.failed,
            c.excluded,
        ] {
            word(value);
        }
        for value in c.obstruct {
            word(value);
        }
        word(self.sources_enabled);
        word(u64::from(self.done_at_ms.is_some()));
        word(self.done_at_ms.unwrap_or_default());
        out
    }
    /// `None`: another version or a damaged value; its owner writes nothing.
    pub(in crate::snapshots) fn decode(bytes: &[u8]) -> Option<Self> {
        const WORDS: usize = 1 + 2 + 7 + BUCKETS + 1 + 2;
        if bytes.len() != 1 + WORDS * 8 || bytes[0] != SUMMARY_V1 {
            return None;
        }
        let words = bytes[1..]
            .chunks_exact(8)
            .map(|chunk| u64::from_be_bytes(chunk.try_into().unwrap_or([0; 8])))
            .collect::<Vec<_>>();
        let flag = |at: usize| match words[at] {
            0 => Some(None),
            1 => Some(Some(words[at + 1])),
            _ => None,
        };
        let mut obstruct = [0; BUCKETS];
        obstruct.copy_from_slice(&words[10..10 + BUCKETS]);
        Some(Self {
            anchor_at_ms: words[0],
            certified_at_ms: flag(1)?,
            counts: Counts {
                members: words[3],
                bytes_total: words[4],
                done: words[5],
                bytes_done: words[6],
                held: words[7],
                failed: words[8],
                excluded: words[9],
                obstruct,
            },
            sources_enabled: words[10 + BUCKETS],
            done_at_ms: flag(11 + BUCKETS)?,
        })
    }
}

/// This pass's summary changes; later fields win, the first anchor stays.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(in crate::snapshots) struct SummaryEdit {
    /// Creates the generation when no summary is committed.
    pub(in crate::snapshots) anchor_at_ms: Option<u64>,
    /// A healthy complete walk began then (sticky once committed).
    pub(in crate::snapshots) certify_at_ms: Option<u64>,
    pub(in crate::snapshots) sources_enabled: Option<u64>,
    /// The last block sent: a freeze stamps `done_at` after it.
    pub(in crate::snapshots) floor_ms: Option<u64>,
    /// A source with no root: its empty inventory may freeze in the anchor's
    /// own commit. Any other generation never freezes in that commit.
    pub(in crate::snapshots) empty_inventory: bool,
}
impl SummaryEdit {
    pub(in crate::snapshots) fn merge(&mut self, later: Self) {
        self.anchor_at_ms = self.anchor_at_ms.or(later.anchor_at_ms);
        self.certify_at_ms = later.certify_at_ms.or(self.certify_at_ms);
        self.sources_enabled = later.sources_enabled.or(self.sources_enabled);
        self.floor_ms = self.floor_ms.max(later.floor_ms);
        self.empty_inventory |= later.empty_inventory;
    }
}

fn summary_row() -> Result<RowKey> {
    row(FIRST_READ, SUMMARY_KEY, 0)
}
fn member_row(file: &[u8]) -> Result<RowKey> {
    row(FIRST_READ, file, 0)
}
/// The committed summary: `Err` when unreadable, never a default.
pub(in crate::snapshots::state_v2) fn read_summary(tx: &mut dyn Transaction) -> Result<Option<Summary>> {
    let Some(header) = tx.get(&summary_row()?)? else {
        return Ok(None);
    };
    Summary::decode(&read_inline(tx, &header)?)
        .map(Some)
        .ok_or_else(|| anyhow::anyhow!("state_v2_first_read_summary"))
}
/// The committed member row of `file`: `Err` when unreadable.
pub(in crate::snapshots::state_v2) fn read_member(tx: &mut dyn Transaction, file: &[u8]) -> Result<Option<Member>> {
    let Some(header) = tx.get(&member_row(file)?)? else {
        return Ok(None);
    };
    Member::decode(&read_inline(tx, &header)?)
        .map(Some)
        .ok_or_else(|| anyhow::anyhow!("state_v2_first_read_member"))
}

/// One commit's view of the generation, from its first read of the summary.
pub(super) struct Commit {
    /// The committed summary, or the one this commit creates.
    summary: Option<Summary>,
    /// This commit creates the generation.
    creating: bool,
    /// A file's isolated block rolled back in this commit.
    rolled_back: bool,
}
impl Commit {
    /// An unreadable summary writes nothing: the block is omitted until it
    /// reads again, and no member row moves ahead of it.
    pub(super) fn begin(tx: &mut dyn Transaction, edit: Option<&SummaryEdit>) -> Self {
        let (summary, creating) = match read_summary(tx) {
            Ok(Some(summary)) => (Some(summary), false),
            Ok(None) => match edit.and_then(|edit| edit.anchor_at_ms) {
                Some(anchor_at_ms) => (
                    Some(Summary {
                        anchor_at_ms,
                        ..Summary::default()
                    }),
                    true,
                ),
                None => (None, false),
            },
            Err(_) => (None, false),
        };
        Self {
            summary,
            creating,
            rolled_back: false,
        }
    }
    pub(super) fn open(&self) -> bool {
        self.summary.is_some_and(|summary| summary.open())
    }
    /// Writes `file`'s member row inside its isolated block; the returned
    /// counts apply only if that block commits.
    pub(super) fn write(
        &self,
        tx: &mut dyn Transaction,
        file: &[u8],
        observed: Observed,
    ) -> Result<Counts> {
        let mut counts = self.summary.map(|s| s.counts).unwrap_or_default();
        // An unreadable row is left as it is (it already counts, and the
        // freeze recount refuses it): it never rolls back the file's debt.
        let Ok(old) = read_member(tx, file) else {
            return Ok(counts);
        };
        let new = resolve(old, observed);
        if old != Some(new) {
            put_inline(tx, &member_row(file)?, &new.encode())?;
            counts.replace(old, new);
        }
        Ok(counts)
    }
    pub(super) fn committed(&mut self, counts: Counts) {
        if let Some(summary) = self.summary.as_mut() {
            summary.counts = counts;
        }
    }
    /// A new member whose isolated block rolled back is never dropped: it is
    /// written failed outside the block, and this commit cannot freeze.
    pub(super) fn rolled_back(
        &mut self,
        tx: &mut dyn Transaction,
        file: &[u8],
        observed: Option<Observed>,
    ) -> Result<()> {
        self.rolled_back = true;
        let Some(observed) = observed.filter(|_| self.open()) else {
            return Ok(());
        };
        // An unreadable row is left as it is: it already counts.
        if !matches!(read_member(tx, file), Ok(None)) {
            return Ok(());
        }
        let failed = Member {
            class: Class::Failed,
            ..observed.member
        };
        put_inline(tx, &member_row(file)?, &failed.encode())?;
        if let Some(summary) = self.summary.as_mut() {
            summary.counts.replace(None, failed);
        }
        Ok(())
    }
    /// An erased file that was not delivered is a deleted exclusion with its
    /// age kept; a done or already excluded member stays as it is.
    pub(super) fn erased(&mut self, tx: &mut dyn Transaction, file: &[u8]) -> Result<()> {
        if !self.open() {
            return Ok(());
        }
        // An unreadable row stays: the recount refuses the freeze.
        let Ok(Some(old)) = read_member(tx, file) else {
            return Ok(());
        };
        if matches!(old.class, Class::Owed | Class::Held | Class::Failed) {
            let new = Member {
                class: Class::ExcludedDeleted,
                ..old
            };
            put_inline(tx, &member_row(file)?, &new.encode())?;
            if let Some(summary) = self.summary.as_mut() {
                summary.counts.replace(Some(old), new);
            }
        }
        Ok(())
    }
    /// The summary with this pass's edit, then the freeze check.
    pub(super) fn finish(self, tx: &mut dyn Transaction, edit: Option<&SummaryEdit>) -> Result<()> {
        let Some(mut summary) = self.summary.filter(Summary::open) else {
            return Ok(());
        };
        let before = (!self.creating).then_some(summary);
        let edit = edit.copied().unwrap_or_default();
        if summary.certified_at_ms.is_none() {
            summary.certified_at_ms = edit.certify_at_ms;
        }
        if let Some(sources) = edit.sources_enabled {
            summary.sources_enabled = sources;
        }
        let may_freeze = !self.rolled_back && (!self.creating || edit.empty_inventory);
        if may_freeze && summary.resolved() {
            // An unreadable row refuses the freeze; the save still commits.
            let Ok(recount) = recount(tx) else {
                return write_summary(tx, before, summary);
            };
            if recount == summary.counts {
                let now_ms = super::super::super::sampled_scan::now_seconds().saturating_mul(1000);
                summary.done_at_ms = Some(now_ms.max(edit.floor_ms.map_or(0, |f| f + 1)));
                clear_members(tx)?;
            } else {
                telemetry::event(
                    "first_read_recount",
                    &serde_json::json!({
                        "members": summary.counts.members, "recounted": recount.members,
                        "done": summary.counts.done, "recounted_done": recount.done,
                    }),
                );
                summary.counts = recount;
            }
        }
        write_summary(tx, before, summary)
    }
}
/// N4: the row is written only when it changes.
fn write_summary(tx: &mut dyn Transaction, before: Option<Summary>, summary: Summary) -> Result<()> {
    if before != Some(summary) {
        put_inline(tx, &summary_row()?, &summary.encode())?;
    }
    Ok(())
}

/// Every member row of the kind, in bounded header pages.
fn visit_members(
    tx: &mut dyn Transaction,
    visit: &mut dyn FnMut(&mut dyn Transaction, Header) -> Result<()>,
) -> Result<()> {
    let kind = RecordKind::parse(FIRST_READ)?;
    let mut after = None;
    loop {
        let page = tx.scan_kind(&kind, after.as_ref(), HEADER_PAGE)?;
        let Some(last) = page.last() else {
            return Ok(());
        };
        after = Some(last.key.clone());
        for header in page {
            if matches!(&header.key, RowKey::Record { key_bytes, .. } if key_bytes == SUMMARY_KEY) {
                continue;
            }
            visit(tx, header)?;
        }
    }
}
/// The single generic fail-closed check before a freeze: counts from the rows.
fn recount(tx: &mut dyn Transaction) -> Result<Counts> {
    let mut counts = Counts::default();
    visit_members(tx, &mut |tx, header| {
        let member = Member::decode(&read_inline(tx, &header)?)
            .ok_or_else(|| anyhow::anyhow!("state_v2_first_read_member"))?;
        counts.tally(member, true);
        Ok(())
    })?;
    Ok(counts)
}
/// At the freeze the member rows are no longer needed. Their keys are paths:
/// the removal owes a physical purge.
fn clear_members(tx: &mut dyn Transaction) -> Result<()> {
    let mut rows = Vec::new();
    visit_members(tx, &mut |_, header| {
        rows.push(header);
        Ok(())
    })?;
    purge(tx, rows)?;
    Ok(())
}
/// A path carry moves the member with the head; a destination that already
/// has a row keeps both (fail closed: the predecessor stays unresolved).
pub(super) fn carried(tx: &mut dyn Transaction, from: &[u8], to: &[u8]) -> Result<()> {
    let Some(old) = tx.get(&member_row(from)?)? else {
        return Ok(());
    };
    if tx.get(&member_row(to)?)?.is_some() {
        return Ok(());
    }
    move_row(tx, &old, member_row(to)?)
}
