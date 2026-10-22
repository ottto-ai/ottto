//! Per-scope totals: daily kind rows, parts, tools, files and sessions, plus
//! the residency model over appended lines.
//!
//! Residency: a line's tokens stay in context for every request of its own
//! session after it, until the next compaction. A reader that sees lines in
//! order keeps the tokens of lines entered since the last compaction
//! ("open"), adds them once per counted request, and clears them at a
//! compaction. That equals the whole-file multiplier of the kinds_version 1
//! reader and can stop and resume at any line.

use super::{
    KEEP_DAYS, MAX_ALL_FILES, MAX_ALL_TOOLS, MAX_FILES_PER_DAY, OWNERSHIP_DAYS, PERIOD_DAYS,
};
use crate::composition_kinds::{Kind, Part};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use time::Date;

/// A UTC day as its Julian day number.
pub(super) type Day = i32;

pub(super) fn day_of(date: Date) -> Day {
    date.to_julian_day()
}

pub(super) fn date_of(day: Day) -> Option<Date> {
    Date::from_julian_day(day).ok()
}

// -------------------------------------------------------------------------
// Kind and part codes for local state (their wire ids).
// -------------------------------------------------------------------------

/// Every kind (v1 and v2), for reading state back.
const ALL_KINDS: [Kind; 16] = [
    Kind::HarnessAttachments,
    Kind::ShellOutput,
    Kind::CodeReads,
    Kind::DocReadsMd,
    Kind::DocReadsHtml,
    Kind::MemoryNotes,
    Kind::BrowserAndImages,
    Kind::WebFetchSearch,
    Kind::AgentResults,
    Kind::OtherTools,
    Kind::FilesRead,
    Kind::CommandOutput,
    Kind::ComputerUse,
    Kind::WebAndBrowser,
    Kind::AutomaticAdditions,
    Kind::YourPrompts,
];

/// Every part, for reading state back. `part_position` keeps it complete:
/// a new variant fails to compile there, and the tests check the order.
pub(super) const ALL_PARTS: [Part; 32] = [
    Part::Unsplit,
    Part::ShellRead,
    Part::FileTool,
    Part::SkillFile,
    Part::InstructionsLater,
    Part::MemoryFile,
    Part::Git,
    Part::Search,
    Part::TestsBuilds,
    Part::OtherCommands,
    Part::AppControl,
    Part::Screenshots,
    Part::Web,
    Part::Browser,
    Part::Addon,
    Part::AgentReports,
    Part::BackgroundReports,
    Part::BuiltInOther,
    Part::StartNotMeasured,
    Part::ToolDescriptionsLater,
    Part::ListsUpdated,
    Part::InstructionsReloaded,
    Part::MemoryReloaded,
    Part::CompactionSummary,
    Part::Reminders,
    Part::Environment,
    Part::HookOutput,
    Part::FilesMentioned,
    Part::FilesChanged,
    Part::Other,
    Part::ByYou,
    Part::ByAgent,
];

#[cfg(test)]
pub(super) fn part_position(part: Part) -> usize {
    match part {
        Part::Unsplit => 0,
        Part::ShellRead => 1,
        Part::FileTool => 2,
        Part::SkillFile => 3,
        Part::InstructionsLater => 4,
        Part::MemoryFile => 5,
        Part::Git => 6,
        Part::Search => 7,
        Part::TestsBuilds => 8,
        Part::OtherCommands => 9,
        Part::AppControl => 10,
        Part::Screenshots => 11,
        Part::Web => 12,
        Part::Browser => 13,
        Part::Addon => 14,
        Part::AgentReports => 15,
        Part::BackgroundReports => 16,
        Part::BuiltInOther => 17,
        Part::StartNotMeasured => 18,
        Part::ToolDescriptionsLater => 19,
        Part::ListsUpdated => 20,
        Part::InstructionsReloaded => 21,
        Part::MemoryReloaded => 22,
        Part::CompactionSummary => 23,
        Part::Reminders => 24,
        Part::Environment => 25,
        Part::HookOutput => 26,
        Part::FilesMentioned => 27,
        Part::FilesChanged => 28,
        Part::Other => 29,
        Part::ByYou => 30,
        Part::ByAgent => 31,
    }
}

#[cfg(test)]
pub(super) fn kind_position(kind: Kind) -> usize {
    match kind {
        Kind::HarnessAttachments => 0,
        Kind::ShellOutput => 1,
        Kind::CodeReads => 2,
        Kind::DocReadsMd => 3,
        Kind::DocReadsHtml => 4,
        Kind::MemoryNotes => 5,
        Kind::BrowserAndImages => 6,
        Kind::WebFetchSearch => 7,
        Kind::AgentResults => 8,
        Kind::OtherTools => 9,
        Kind::FilesRead => 10,
        Kind::CommandOutput => 11,
        Kind::ComputerUse => 12,
        Kind::WebAndBrowser => 13,
        Kind::AutomaticAdditions => 14,
        Kind::YourPrompts => 15,
    }
}

#[cfg(test)]
pub(super) fn all_kinds() -> &'static [Kind] {
    &ALL_KINDS
}

pub(super) fn kind_from_str(text: &str) -> Option<Kind> {
    ALL_KINDS.iter().copied().find(|kind| kind.as_str() == text)
}

pub(super) fn part_from_str(text: &str) -> Option<Part> {
    ALL_PARTS.iter().copied().find(|part| part.as_str() == text)
}

// -------------------------------------------------------------------------
// Totals.
// -------------------------------------------------------------------------

/// Where one entered item counts: kind, part and (for add-on results) the
/// add-on server.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct Slot {
    pub(super) kind: Kind,
    pub(super) part: Part,
    pub(super) server: Option<Box<str>>,
}

impl Slot {
    pub(super) fn new(kind: Kind, part: Part, tool: &str) -> Self {
        let server = (part == Part::Addon)
            .then(|| tool.split_once('/').map(|(server, _)| server))
            .flatten()
            .filter(|server| !server.is_empty())
            .map(Into::into);
        Self { kind, part, server }
    }

    pub(super) fn plain(kind: Kind, part: Part) -> Self {
        Self {
            kind,
            part,
            server: None,
        }
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(super) struct Bucket {
    pub(super) events: u64,
    pub(super) tokens: u64,
    pub(super) residency: u64,
    pub(super) images: u64,
}

impl Bucket {
    fn add(&mut self, other: &Bucket) {
        self.events += other.events;
        self.tokens += other.tokens;
        self.residency += other.residency;
        self.images += other.images;
    }

    fn subtract(&mut self, other: &Bucket) {
        self.events = self.events.saturating_sub(other.events);
        self.tokens = self.tokens.saturating_sub(other.tokens);
        self.residency = self.residency.saturating_sub(other.residency);
        self.images = self.images.saturating_sub(other.images);
    }

    pub(super) fn is_zero(&self) -> bool {
        *self == Bucket::default()
    }

    fn as_array(&self) -> [u64; 4] {
        [self.events, self.tokens, self.residency, self.images]
    }

    fn from_array(values: [u64; 4]) -> Self {
        Self {
            events: values[0],
            tokens: values[1],
            residency: values[2],
            images: values[3],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct FileKey {
    pub(super) path: Box<str>,
    pub(super) kind: Kind,
    pub(super) part: Part,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(super) struct FileTotals {
    pub(super) events: u64,
    pub(super) tokens: u64,
    /// Latest access, unix seconds.
    pub(super) last: Option<i64>,
}

impl FileTotals {
    fn add(&mut self, tokens: u64, ts: Option<i64>) {
        self.events += 1;
        self.tokens += tokens;
        if let Some(ts) = ts {
            self.last = Some(self.last.map_or(ts, |last| last.max(ts)));
        }
    }

    /// Remove a share; true when nothing is left.
    fn take(&mut self, events: u64, tokens: u64) -> bool {
        self.events = self.events.saturating_sub(events);
        self.tokens = self.tokens.saturating_sub(tokens);
        self.events == 0 && self.tokens == 0
    }

    fn merge(&mut self, other: &FileTotals) {
        self.events += other.events;
        self.tokens += other.tokens;
        if let Some(ts) = other.last {
            self.last = Some(self.last.map_or(ts, |last| last.max(ts)));
        }
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(super) struct ToolTotals {
    pub(super) calls: u64,
    pub(super) tokens: u64,
    /// Distinct sessions (all history only).
    pub(super) sessions: u64,
    /// The kind of the tool's latest call.
    pub(super) kind: Option<Kind>,
}

impl ToolTotals {
    /// Remove a share; true when nothing is left.
    fn take(&mut self, calls: u64, tokens: u64) -> bool {
        self.calls = self.calls.saturating_sub(calls);
        self.tokens = self.tokens.saturating_sub(tokens);
        self.calls == 0 && self.tokens == 0
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(super) struct SessionTotals {
    /// Earliest line of the session's transcripts, unix seconds.
    pub(super) started: Option<i64>,
    pub(super) days: BTreeMap<Day, BTreeMap<Kind, u64>>,
}

/// One scope's totals. Days are UTC days; the 30-day maps keep only the
/// period, the daily rows keep `KEEP_DAYS`.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(super) struct Aggregate {
    pub(super) days: BTreeMap<(Day, Kind), Bucket>,
    pub(super) day_parts: BTreeMap<(Day, Slot), Bucket>,
    pub(super) all_parts: BTreeMap<Slot, Bucket>,
    pub(super) day_files: BTreeMap<(Day, FileKey), FileTotals>,
    /// All-history file totals, capped (approximate past the cap).
    pub(super) all_files: BTreeMap<FileKey, FileTotals>,
    pub(super) day_tools: BTreeMap<(Day, Box<str>), ToolTotals>,
    pub(super) all_tools: BTreeMap<Box<str>, ToolTotals>,
    /// Last day each (tool, session hash) pair was seen, for distinct counts.
    pub(super) tool_sessions: BTreeMap<(Box<str>, u64), Day>,
    pub(super) sessions: BTreeMap<Box<str>, SessionTotals>,
    /// The commit generation that last changed each day's rows.
    pub(super) day_generation: BTreeMap<Day, u64>,
}

/// One file's own share of the scope totals, so a full re-read can replace
/// it: daily rows (from the parts), parts, files, tools and session tokens
/// for the days of the daily-row window. Latest-access times, distinct
/// session counts and all-history totals of days past the window stay as
/// they were.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(super) struct Contribution {
    pub(super) parts: BTreeMap<(Day, Slot), Bucket>,
    /// (events, tokens) per day and file.
    pub(super) files: BTreeMap<(Day, FileKey), (u64, u64)>,
    /// (calls, tokens) per day and tool.
    pub(super) tools: BTreeMap<(Day, Box<str>), (u64, u64)>,
    /// The file's session (fixed from its first lines) and its tokens.
    pub(super) session: Option<Box<str>>,
    pub(super) sessions: BTreeMap<(Day, Kind), u64>,
}

/// Days a run may write: `[floor, today]`; the 30-day maps start at
/// `period_floor`.
#[derive(Debug, Clone, Copy)]
pub(super) struct Window {
    pub(super) floor: Day,
    pub(super) period_floor: Day,
    pub(super) today: Day,
}

impl Window {
    pub(super) fn ending(today: Day) -> Self {
        Self {
            floor: today - (KEEP_DAYS - 1),
            period_floor: today - (PERIOD_DAYS - 1),
            today,
        }
    }

    pub(super) fn contains(&self, day: Day) -> bool {
        day >= self.floor && day <= self.today
    }

    pub(super) fn ownership_floor(&self) -> Day {
        self.today - (OWNERSHIP_DAYS - 1)
    }
}

/// One counted item.
pub(super) struct Entered<'a> {
    pub(super) day: Day,
    pub(super) slot: Slot,
    pub(super) tokens: u64,
    pub(super) images: u64,
    pub(super) file: Option<&'a str>,
    pub(super) session: &'a str,
    pub(super) ts: Option<i64>,
}

/// Writes counted items into a scope's totals and the file's contribution.
pub(super) struct Sink<'a> {
    pub(super) agg: &'a mut Aggregate,
    pub(super) contribution: &'a mut Contribution,
    pub(super) window: Window,
    pub(super) generation: u64,
}

impl Sink<'_> {
    fn touch(&mut self, day: Day) {
        self.agg.day_generation.insert(day, self.generation);
    }

    /// Count an item. Returns false when its day is outside the window (the
    /// item is dropped, residency included).
    pub(super) fn entered(&mut self, item: &Entered) -> bool {
        if !self.window.contains(item.day) {
            return false;
        }
        let bucket = Bucket {
            events: 1,
            tokens: item.tokens,
            residency: 0,
            images: item.images,
        };
        self.add_bucket(item.day, &item.slot, &bucket);
        if let Some(path) = item.file {
            let key = FileKey {
                path: path.into(),
                kind: item.slot.kind,
                part: item.slot.part,
            };
            if item.day >= self.window.period_floor {
                self.agg
                    .day_files
                    .entry((item.day, key.clone()))
                    .or_default()
                    .add(item.tokens, item.ts);
            }
            self.agg
                .all_files
                .entry(key.clone())
                .or_default()
                .add(item.tokens, item.ts);
            let share = self.contribution.files.entry((item.day, key)).or_default();
            share.0 += 1;
            share.1 += item.tokens;
        }
        let share = &mut self.contribution;
        if share
            .session
            .as_deref()
            .map_or(true, |own| own == item.session)
        {
            share.session.get_or_insert_with(|| item.session.into());
            *share
                .sessions
                .entry((item.day, item.slot.kind))
                .or_default() += item.tokens;
        }
        *self
            .agg
            .sessions
            .entry(item.session.into())
            .or_default()
            .days
            .entry(item.day)
            .or_default()
            .entry(item.slot.kind)
            .or_default() += item.tokens;
        true
    }

    /// Add residency for open tokens of `day`/`slot`.
    pub(super) fn residency(&mut self, day: Day, slot: &Slot, amount: u64) {
        if amount == 0 || !self.window.contains(day) {
            return;
        }
        let bucket = Bucket {
            residency: amount,
            ..Bucket::default()
        };
        self.add_bucket(day, slot, &bucket);
    }

    fn add_bucket(&mut self, day: Day, slot: &Slot, bucket: &Bucket) {
        self.agg
            .days
            .entry((day, slot.kind))
            .or_default()
            .add(bucket);
        self.contribution
            .parts
            .entry((day, slot.clone()))
            .or_default()
            .add(bucket);
        if day >= self.window.period_floor {
            self.agg
                .day_parts
                .entry((day, slot.clone()))
                .or_default()
                .add(bucket);
        }
        self.agg
            .all_parts
            .entry(slot.clone())
            .or_default()
            .add(bucket);
        self.touch(day);
    }

    /// One tool result (or the image tokens of one) for the tools totals.
    pub(super) fn tool(
        &mut self,
        day: Day,
        tool: &str,
        kind: Kind,
        session: &str,
        tokens: u64,
        call: bool,
    ) {
        if tool.is_empty() || !self.window.contains(day) {
            return;
        }
        let calls = u64::from(call);
        let share = self
            .contribution
            .tools
            .entry((day, tool.into()))
            .or_default();
        share.0 += calls;
        share.1 += tokens;
        if day >= self.window.period_floor {
            let entry = self.agg.day_tools.entry((day, tool.into())).or_default();
            entry.calls += calls;
            entry.tokens += tokens;
            entry.kind = Some(kind);
        }
        let pair = (Box::<str>::from(tool), session_hash(session));
        let first_seen = !self.agg.tool_sessions.contains_key(&pair);
        let last = self.agg.tool_sessions.entry(pair).or_insert(day);
        *last = (*last).max(day);
        let entry = self.agg.all_tools.entry(tool.into()).or_default();
        entry.calls += calls;
        entry.tokens += tokens;
        entry.sessions += u64::from(first_seen);
        entry.kind = Some(kind);
    }

    /// The earliest line of a session's transcript, once it has counted
    /// items.
    pub(super) fn session_start(&mut self, session: &str, ts: Option<i64>) {
        let Some(ts) = ts else { return };
        if let Some(totals) = self.agg.sessions.get_mut(session) {
            totals.started = Some(totals.started.map_or(ts, |started| started.min(ts)));
        }
    }
}

pub(super) fn session_hash(session: &str) -> u64 {
    super::ownership::stable_hash(session.as_bytes())
}

impl Aggregate {
    /// Remove a file's earlier contribution before it is read again. Daily
    /// rows that reach zero are kept (as zeros), so the changed-days upload
    /// sends them and the server's earlier values are replaced.
    pub(super) fn subtract(&mut self, share: &Contribution, generation: u64) {
        for ((day, slot), bucket) in &share.parts {
            if let Some(row) = self.days.get_mut(&(*day, slot.kind)) {
                row.subtract(bucket);
                self.day_generation.insert(*day, generation);
            }
            let key = (*day, slot.clone());
            if let Some(row) = self.day_parts.get_mut(&key) {
                row.subtract(bucket);
                if row.is_zero() {
                    self.day_parts.remove(&key);
                }
            }
            if let Some(row) = self.all_parts.get_mut(slot) {
                row.subtract(bucket);
                if row.is_zero() {
                    self.all_parts.remove(slot);
                }
            }
        }
        for ((day, key), (events, tokens)) in &share.files {
            let day_key = (*day, key.clone());
            if let Some(totals) = self.day_files.get_mut(&day_key) {
                if totals.take(*events, *tokens) {
                    self.day_files.remove(&day_key);
                }
            }
            if let Some(totals) = self.all_files.get_mut(key) {
                if totals.take(*events, *tokens) {
                    self.all_files.remove(key);
                }
            }
        }
        for ((day, tool), (calls, tokens)) in &share.tools {
            let day_key = (*day, tool.clone());
            if let Some(totals) = self.day_tools.get_mut(&day_key) {
                if totals.take(*calls, *tokens) {
                    self.day_tools.remove(&day_key);
                }
            }
            if let Some(totals) = self.all_tools.get_mut(tool) {
                if totals.take(*calls, *tokens) {
                    self.all_tools.remove(tool);
                }
            }
        }
        if let Some(totals) = share
            .session
            .as_deref()
            .and_then(|session| self.sessions.get_mut(session))
        {
            for ((day, kind), tokens) in &share.sessions {
                if let Some(kinds) = totals.days.get_mut(day) {
                    if let Some(value) = kinds.get_mut(kind) {
                        *value = value.saturating_sub(*tokens);
                        if *value == 0 {
                            kinds.remove(kind);
                        }
                    }
                    if kinds.is_empty() {
                        totals.days.remove(day);
                    }
                }
            }
            if totals.days.is_empty() {
                self.sessions
                    .remove(share.session.as_deref().unwrap_or_default());
            }
        }
    }

    /// Drop what fell out of the window and trim the capped maps.
    pub(super) fn prune(&mut self, window: Window) {
        let floor = window.floor;
        let period = window.period_floor;
        self.days.retain(|(day, _), _| *day >= floor);
        self.day_generation.retain(|day, _| *day >= floor);
        self.day_parts.retain(|(day, _), _| *day >= period);
        self.day_files.retain(|(day, _), _| *day >= period);
        self.day_tools.retain(|(day, _), _| *day >= period);
        self.tool_sessions.retain(|_, day| *day >= period);
        self.sessions.retain(|_, totals| {
            totals.days.retain(|day, _| *day >= floor);
            !totals.days.is_empty()
        });
        trim_per_day_files(&mut self.day_files, MAX_FILES_PER_DAY);
        trim_by_tokens(&mut self.all_files, MAX_ALL_FILES, |totals| totals.tokens);
        trim_by_tokens(&mut self.all_tools, MAX_ALL_TOOLS, |totals| totals.tokens);
    }

    /// Bytes held, approximately (for the run's memory figure).
    pub(super) fn accounted_bytes(&self) -> usize {
        const ROW: usize = 72;
        let sessions: usize = self
            .sessions
            .values()
            .map(|totals| 48 + totals.days.len() * ROW)
            .sum();
        (self.days.len()
            + self.day_parts.len()
            + self.all_parts.len()
            + self.day_tools.len()
            + self.all_tools.len()
            + self.tool_sessions.len()
            + self.day_generation.len())
            * ROW
            + (self.day_files.len() + self.all_files.len()) * (ROW + 64)
            + sessions
    }
}

fn trim_per_day_files(map: &mut BTreeMap<(Day, FileKey), FileTotals>, cap: usize) {
    let mut per_day: BTreeMap<Day, Vec<(u64, FileKey)>> = BTreeMap::new();
    for ((day, key), totals) in map.iter() {
        per_day
            .entry(*day)
            .or_default()
            .push((totals.tokens, key.clone()));
    }
    for (day, mut entries) in per_day {
        if entries.len() <= cap {
            continue;
        }
        entries.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
        for (_, key) in entries.into_iter().skip(cap) {
            map.remove(&(day, key));
        }
    }
}

fn trim_by_tokens<K: Ord + Clone, V>(
    map: &mut BTreeMap<K, V>,
    cap: usize,
    tokens: impl Fn(&V) -> u64,
) {
    if map.len() <= cap {
        return;
    }
    let mut entries: Vec<(u64, K)> = map.iter().map(|(k, v)| (tokens(v), k.clone())).collect();
    entries.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
    for (_, key) in entries.into_iter().skip(cap) {
        map.remove(&key);
    }
}

// -------------------------------------------------------------------------
// Stored form (JSON rows with wire ids).
// -------------------------------------------------------------------------

type DayPartRow = (Day, String, String, Option<String>, [u64; 4]);
type DayFileRow = (Day, String, String, String, u64, u64, Option<i64>);
type SessionRow = (String, Option<i64>, Vec<(Day, Vec<(String, u64)>)>);

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub(super) struct StoredAggregate {
    days: Vec<(Day, String, [u64; 4])>,
    day_parts: Vec<DayPartRow>,
    all_parts: Vec<(String, String, Option<String>, [u64; 4])>,
    day_files: Vec<DayFileRow>,
    all_files: Vec<(String, String, String, u64, u64, Option<i64>)>,
    day_tools: Vec<(Day, String, Option<String>, u64, u64)>,
    all_tools: Vec<(String, Option<String>, u64, u64, u64)>,
    tool_sessions: Vec<(String, u64, Day)>,
    sessions: Vec<SessionRow>,
    day_generation: Vec<(Day, u64)>,
}

impl StoredAggregate {
    pub(super) fn from_aggregate(agg: &Aggregate) -> Self {
        let slot_parts = |slot: &Slot| {
            (
                slot.kind.as_str().to_string(),
                slot.part.as_str().to_string(),
                slot.server.as_deref().map(str::to_string),
            )
        };
        Self {
            days: agg
                .days
                .iter()
                .map(|((day, kind), bucket)| (*day, kind.as_str().to_string(), bucket.as_array()))
                .collect(),
            day_parts: agg
                .day_parts
                .iter()
                .map(|((day, slot), bucket)| {
                    let (kind, part, server) = slot_parts(slot);
                    (*day, kind, part, server, bucket.as_array())
                })
                .collect(),
            all_parts: agg
                .all_parts
                .iter()
                .map(|(slot, bucket)| {
                    let (kind, part, server) = slot_parts(slot);
                    (kind, part, server, bucket.as_array())
                })
                .collect(),
            day_files: agg
                .day_files
                .iter()
                .map(|((day, key), totals)| {
                    (
                        *day,
                        key.path.to_string(),
                        key.kind.as_str().to_string(),
                        key.part.as_str().to_string(),
                        totals.events,
                        totals.tokens,
                        totals.last,
                    )
                })
                .collect(),
            all_files: agg
                .all_files
                .iter()
                .map(|(key, totals)| {
                    (
                        key.path.to_string(),
                        key.kind.as_str().to_string(),
                        key.part.as_str().to_string(),
                        totals.events,
                        totals.tokens,
                        totals.last,
                    )
                })
                .collect(),
            day_tools: agg
                .day_tools
                .iter()
                .map(|((day, tool), totals)| {
                    (
                        *day,
                        tool.to_string(),
                        totals.kind.map(|kind| kind.as_str().to_string()),
                        totals.calls,
                        totals.tokens,
                    )
                })
                .collect(),
            all_tools: agg
                .all_tools
                .iter()
                .map(|(tool, totals)| {
                    (
                        tool.to_string(),
                        totals.kind.map(|kind| kind.as_str().to_string()),
                        totals.calls,
                        totals.tokens,
                        totals.sessions,
                    )
                })
                .collect(),
            tool_sessions: agg
                .tool_sessions
                .iter()
                .map(|((tool, session), day)| (tool.to_string(), *session, *day))
                .collect(),
            sessions: agg
                .sessions
                .iter()
                .map(|(session, totals)| {
                    (
                        session.to_string(),
                        totals.started,
                        totals
                            .days
                            .iter()
                            .map(|(day, kinds)| {
                                (
                                    *day,
                                    kinds
                                        .iter()
                                        .map(|(kind, tokens)| (kind.as_str().to_string(), *tokens))
                                        .collect(),
                                )
                            })
                            .collect(),
                    )
                })
                .collect(),
            day_generation: agg
                .day_generation
                .iter()
                .map(|(day, generation)| (*day, *generation))
                .collect(),
        }
    }

    /// Rebuild the totals. `None` when a row names an unknown kind or part
    /// (state from an incompatible build): the caller treats it as bad state.
    pub(super) fn into_aggregate(self) -> Option<Aggregate> {
        let slot = |kind: &str, part: &str, server: Option<String>| -> Option<Slot> {
            Some(Slot {
                kind: kind_from_str(kind)?,
                part: part_from_str(part)?,
                server: server.map(Into::into),
            })
        };
        let file_key = |path: String, kind: &str, part: &str| -> Option<FileKey> {
            Some(FileKey {
                path: path.into(),
                kind: kind_from_str(kind)?,
                part: part_from_str(part)?,
            })
        };
        let mut agg = Aggregate::default();
        for (day, kind, values) in self.days {
            agg.days
                .insert((day, kind_from_str(&kind)?), Bucket::from_array(values));
        }
        for (day, kind, part, server, values) in self.day_parts {
            agg.day_parts.insert(
                (day, slot(&kind, &part, server)?),
                Bucket::from_array(values),
            );
        }
        for (kind, part, server, values) in self.all_parts {
            agg.all_parts
                .insert(slot(&kind, &part, server)?, Bucket::from_array(values));
        }
        for (day, path, kind, part, events, tokens, last) in self.day_files {
            agg.day_files.insert(
                (day, file_key(path, &kind, &part)?),
                FileTotals {
                    events,
                    tokens,
                    last,
                },
            );
        }
        for (path, kind, part, events, tokens, last) in self.all_files {
            agg.all_files.insert(
                file_key(path, &kind, &part)?,
                FileTotals {
                    events,
                    tokens,
                    last,
                },
            );
        }
        let tool_kind = |kind: Option<String>| -> Option<Option<Kind>> {
            match kind {
                None => Some(None),
                Some(kind) => kind_from_str(&kind).map(Some),
            }
        };
        for (day, tool, kind, calls, tokens) in self.day_tools {
            agg.day_tools.insert(
                (day, tool.into()),
                ToolTotals {
                    calls,
                    tokens,
                    sessions: 0,
                    kind: tool_kind(kind)?,
                },
            );
        }
        for (tool, kind, calls, tokens, sessions) in self.all_tools {
            agg.all_tools.insert(
                tool.into(),
                ToolTotals {
                    calls,
                    tokens,
                    sessions,
                    kind: tool_kind(kind)?,
                },
            );
        }
        for (tool, session, day) in self.tool_sessions {
            agg.tool_sessions.insert((tool.into(), session), day);
        }
        for (session, started, days) in self.sessions {
            let mut totals = SessionTotals {
                started,
                days: BTreeMap::new(),
            };
            for (day, kinds) in days {
                let mut per_kind = BTreeMap::new();
                for (kind, tokens) in kinds {
                    per_kind.insert(kind_from_str(&kind)?, tokens);
                }
                totals.days.insert(day, per_kind);
            }
            agg.sessions.insert(session.into(), totals);
        }
        agg.day_generation = self.day_generation.into_iter().collect();
        Some(agg)
    }
}

/// Stored form of a file's contribution (wire ids).
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub(super) struct StoredContribution {
    parts: Vec<DayPartRow>,
    files: Vec<(Day, String, String, String, u64, u64)>,
    tools: Vec<(Day, String, u64, u64)>,
    session: Option<String>,
    sessions: Vec<(Day, String, u64)>,
}

impl StoredContribution {
    pub(super) fn from_share(share: &Contribution) -> Self {
        Self {
            parts: share
                .parts
                .iter()
                .map(|((day, slot), bucket)| {
                    (
                        *day,
                        slot.kind.as_str().to_string(),
                        slot.part.as_str().to_string(),
                        slot.server.as_deref().map(str::to_string),
                        bucket.as_array(),
                    )
                })
                .collect(),
            files: share
                .files
                .iter()
                .map(|((day, key), (events, tokens))| {
                    (
                        *day,
                        key.path.to_string(),
                        key.kind.as_str().to_string(),
                        key.part.as_str().to_string(),
                        *events,
                        *tokens,
                    )
                })
                .collect(),
            tools: share
                .tools
                .iter()
                .map(|((day, tool), (calls, tokens))| (*day, tool.to_string(), *calls, *tokens))
                .collect(),
            session: share.session.as_deref().map(str::to_string),
            sessions: share
                .sessions
                .iter()
                .map(|((day, kind), tokens)| (*day, kind.as_str().to_string(), *tokens))
                .collect(),
        }
    }

    /// None when a stored id is unknown.
    pub(super) fn into_share(self) -> Option<Contribution> {
        let mut share = Contribution {
            session: self.session.map(Into::into),
            ..Contribution::default()
        };
        for (day, kind, part, server, values) in self.parts {
            let slot = Slot {
                kind: kind_from_str(&kind)?,
                part: part_from_str(&part)?,
                server: server.map(Into::into),
            };
            share.parts.insert((day, slot), Bucket::from_array(values));
        }
        for (day, path, kind, part, events, tokens) in self.files {
            let key = FileKey {
                path: path.into(),
                kind: kind_from_str(&kind)?,
                part: part_from_str(&part)?,
            };
            share.files.insert((day, key), (events, tokens));
        }
        for (day, tool, calls, tokens) in self.tools {
            share.tools.insert((day, tool.into()), (calls, tokens));
        }
        for (day, kind, tokens) in self.sessions {
            share.sessions.insert((day, kind_from_str(&kind)?), tokens);
        }
        Some(share)
    }

    /// Drop days before `floor` (their daily rows are gone).
    pub(super) fn prune(&mut self, floor: Day) {
        self.parts.retain(|row| row.0 >= floor);
        self.files.retain(|row| row.0 >= floor);
        self.tools.retain(|row| row.0 >= floor);
        self.sessions.retain(|row| row.0 >= floor);
    }
}

/// Merge file totals across days (for the 30-day file values).
pub(super) fn merge_file_totals(into: &mut FileTotals, other: &FileTotals) {
    into.merge(other);
}
