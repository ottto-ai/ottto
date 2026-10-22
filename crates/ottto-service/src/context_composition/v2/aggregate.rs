//! Per-scope totals: daily kind rows, parts, tools, files and sessions, plus
//! the residency model over appended lines.
//!
//! Residency: a line's tokens stay in context for every request of its own
//! session after it, until the next compaction. A reader that sees lines in
//! order keeps the tokens of lines entered since the last compaction
//! ("open"), adds them once per counted request, and clears them at a
//! compaction. That equals the whole-file multiplier of the kinds_version 1
//! reader and can stop and resume at any line.

use super::{KEEP_DAYS, MAX_ALL_FILES, MAX_ALL_TOOLS, MAX_FILES_PER_DAY, PERIOD_DAYS};
use crate::composition_kinds::{Kind, Part};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
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

/// A kind or part held as itself and stored as its wire id, so stored rows
/// keep no text of their own. An unknown id fails the whole state file
/// (state from an incompatible build is bad state).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct Id<T>(pub(super) T);

impl Serialize for Id<Kind> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.0.as_str())
    }
}

impl Serialize for Id<Part> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.0.as_str())
    }
}

impl<'de> Deserialize<'de> for Id<Kind> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer
            .deserialize_str(IdVisitor(kind_from_str))
            .map(Id)
    }
}

impl<'de> Deserialize<'de> for Id<Part> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer
            .deserialize_str(IdVisitor(part_from_str))
            .map(Id)
    }
}

struct IdVisitor<T>(fn(&str) -> Option<T>);

impl<T> serde::de::Visitor<'_> for IdVisitor<T> {
    type Value = T;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("a kind or part id")
    }

    fn visit_str<E: serde::de::Error>(self, text: &str) -> Result<T, E> {
        (self.0)(text).ok_or_else(|| E::custom("unknown kind or part id"))
    }
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
    fn add(&mut self, other: &ToolTotals) {
        self.calls += other.calls;
        self.tokens += other.tokens;
        self.sessions += other.sessions;
        self.kind = other.kind.or(self.kind);
    }

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
    pub(super) days: Vec<(Day, Vec<(Kind, u64)>)>,
}

impl SessionTotals {
    fn add(&mut self, day: Day, kind: Kind, tokens: u64) {
        let at = self.days.binary_search_by_key(&day, |row| row.0)
            .unwrap_or_else(|at| { self.days.insert(at, (day, Vec::new())); at });
        let kinds = &mut self.days[at].1;
        match kinds.binary_search_by_key(&kind, |row| row.0) {
            Ok(at) => kinds[at].1 += tokens,
            Err(at) => kinds.insert(at, (kind, tokens)),
        }
    }
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
    /// Kept for the 30-day period only, while `all_tools.sessions` counts
    /// every session ever seen: a session that comes back after 30 days
    /// counts again there (an overcount, documented as a difference).
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

/// Writes counted items into one read's own totals and the file's
/// contribution. The read's totals join the scope's only when the read
/// succeeds (`Aggregate::merge`), so a failed read leaves the scope as it was.
pub(super) struct Sink<'a> {
    /// The scope's committed totals (read only: distinct-session checks).
    pub(super) base: &'a Aggregate,
    /// This read's totals.
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
        self.agg.sessions.entry(item.session.into()).or_default()
            .add(item.day, item.slot.kind, item.tokens);
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
        let first_seen = !self.base.tool_sessions.contains_key(&pair)
            && !self.agg.tool_sessions.contains_key(&pair);
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
        if self.agg.sessions.contains_key(session) || self.base.sessions.contains_key(session) {
            let totals = self.agg.sessions.entry(session.into()).or_default();
            totals.started = Some(totals.started.map_or(ts, |started| started.min(ts)));
        }
    }
}

pub(super) fn session_hash(session: &str) -> u64 {
    stable_hash(session.as_bytes())
}

/// FNV-1a 64: stable across builds and platforms (state is persisted).
pub(super) fn stable_hash(bytes: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0100_0000_01b3);
    }
    hash
}

impl Aggregate {
    /// Add one successful read's totals (see `Sink`).
    pub(super) fn merge(&mut self, delta: Aggregate) {
        for (key, bucket) in delta.days {
            self.days.entry(key).or_default().add(&bucket);
        }
        for (key, bucket) in delta.day_parts {
            self.day_parts.entry(key).or_default().add(&bucket);
        }
        for (key, bucket) in delta.all_parts {
            self.all_parts.entry(key).or_default().add(&bucket);
        }
        for (key, totals) in delta.day_files {
            self.day_files.entry(key).or_default().merge(&totals);
        }
        for (key, totals) in delta.all_files {
            self.all_files.entry(key).or_default().merge(&totals);
        }
        for (key, totals) in delta.day_tools {
            self.day_tools.entry(key).or_default().add(&totals);
        }
        for (key, totals) in delta.all_tools {
            self.all_tools.entry(key).or_default().add(&totals);
        }
        for (key, day) in delta.tool_sessions {
            let last = self.tool_sessions.entry(key).or_insert(day);
            *last = (*last).max(day);
        }
        for (session, totals) in delta.sessions {
            if totals.days.is_empty() && !self.sessions.contains_key(&session) {
                continue;
            }
            let into = self.sessions.entry(session).or_default();
            if let Some(ts) = totals.started {
                into.started = Some(into.started.map_or(ts, |started| started.min(ts)));
            }
            for (day, kinds) in totals.days {
                for (kind, tokens) in kinds { into.add(day, kind, tokens); }
            }
        }
        for (day, generation) in delta.day_generation {
            let into = self.day_generation.entry(day).or_insert(generation);
            *into = (*into).max(generation);
        }
    }

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
            // The all-history entry stays (even at zero): it holds the
            // tool's distinct-session count.
            if let Some(totals) = self.all_tools.get_mut(tool) {
                totals.take(*calls, *tokens);
            }
        }
        if let Some(totals) = share
            .session
            .as_deref()
            .and_then(|session| self.sessions.get_mut(session))
        {
            for ((day, kind), tokens) in &share.sessions {
                if let Ok(at) = totals.days.binary_search_by_key(day, |row| row.0) {
                    let kinds = &mut totals.days[at].1;
                    if let Ok(k) = kinds.binary_search_by_key(kind, |row| row.0) {
                        kinds[k].1 = kinds[k].1.saturating_sub(*tokens);
                        if kinds[k].1 == 0 { kinds.remove(k); }
                    }
                }
            }
            totals.days.retain(|(_, kinds)| !kinds.is_empty());
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
            totals.days.retain(|(day, _)| *day >= floor);
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
            .map(|totals| 48 + totals.days.iter().map(|(_, kinds)| 24 + kinds.capacity() * 16).sum::<usize>())
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

/// A sequence written straight from an iterator (nothing collected).
struct Rows<F>(F);

impl<F, I> Serialize for Rows<F>
where
    F: Fn() -> I,
    I: Iterator,
    I::Item: Serialize,
{
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_seq((self.0)())
    }
}

fn slot_ids(slot: &Slot) -> (&'static str, &'static str, Option<&str>) {
    (
        slot.kind.as_str(),
        slot.part.as_str(),
        slot.server.as_deref(),
    )
}

/// The totals written in the `StoredAggregate` layout straight from memory,
/// so a save or a content hash never holds a second copy of them.
pub(super) struct AggregateRef<'a> {
    pub(super) agg: &'a Aggregate,
    /// Without the commit generations: for comparing two states by content.
    pub(super) generations: bool,
}

impl Serialize for AggregateRef<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let agg = self.agg;
        let mut out = serializer.serialize_struct("StoredAggregate", 10)?;
        out.serialize_field(
            "days",
            &Rows(|| {
                agg.days
                    .iter()
                    .map(|((day, kind), bucket)| (*day, kind.as_str(), bucket.as_array()))
            }),
        )?;
        out.serialize_field(
            "day_parts",
            &Rows(|| {
                agg.day_parts.iter().map(|((day, slot), bucket)| {
                    let (kind, part, server) = slot_ids(slot);
                    (*day, kind, part, server, bucket.as_array())
                })
            }),
        )?;
        out.serialize_field(
            "all_parts",
            &Rows(|| {
                agg.all_parts.iter().map(|(slot, bucket)| {
                    let (kind, part, server) = slot_ids(slot);
                    (kind, part, server, bucket.as_array())
                })
            }),
        )?;
        out.serialize_field(
            "day_files",
            &Rows(|| {
                agg.day_files.iter().map(|((day, key), totals)| {
                    (
                        *day,
                        &*key.path,
                        key.kind.as_str(),
                        key.part.as_str(),
                        totals.events,
                        totals.tokens,
                        totals.last,
                    )
                })
            }),
        )?;
        out.serialize_field(
            "all_files",
            &Rows(|| {
                agg.all_files.iter().map(|(key, totals)| {
                    (
                        &*key.path,
                        key.kind.as_str(),
                        key.part.as_str(),
                        totals.events,
                        totals.tokens,
                        totals.last,
                    )
                })
            }),
        )?;
        out.serialize_field(
            "day_tools",
            &Rows(|| {
                agg.day_tools.iter().map(|((day, tool), totals)| {
                    (
                        *day,
                        &**tool,
                        totals.kind.map(Kind::as_str),
                        totals.calls,
                        totals.tokens,
                    )
                })
            }),
        )?;
        out.serialize_field(
            "all_tools",
            &Rows(|| {
                agg.all_tools.iter().map(|(tool, totals)| {
                    (
                        &**tool,
                        totals.kind.map(Kind::as_str),
                        totals.calls,
                        totals.tokens,
                        totals.sessions,
                    )
                })
            }),
        )?;
        out.serialize_field(
            "tool_sessions",
            &Rows(|| {
                agg.tool_sessions
                    .iter()
                    .map(|((tool, session), day)| (&**tool, *session, *day))
            }),
        )?;
        out.serialize_field(
            "sessions",
            &Rows(|| {
                agg.sessions.iter().map(|(session, totals)| {
                    let days = Rows(move || {
                        totals.days.iter().map(|(day, kinds)| {
                            let kinds = Rows(move || {
                                kinds.iter().map(|(kind, tokens)| (kind.as_str(), *tokens))
                            });
                            (*day, kinds)
                        })
                    });
                    (&**session, totals.started, days)
                })
            }),
        )?;
        let generations = self.generations.then_some(&agg.day_generation);
        out.serialize_field(
            "day_generation",
            &Rows(|| {
                generations
                    .into_iter()
                    .flatten()
                    .map(|(day, generation)| (*day, *generation))
            }),
        )?;
        out.end()
    }
}

type DayPartRow = (Day, Id<Kind>, Id<Part>, Option<Box<str>>, [u64; 4]);
type DayFileRow = (Day, Box<str>, Id<Kind>, Id<Part>, u64, u64, Option<i64>);
type FileRow = (Box<str>, Id<Kind>, Id<Part>, u64, u64, Option<i64>);
type PartRow = (Id<Kind>, Id<Part>, Option<Box<str>>, [u64; 4]);
type DayToolRow = (Day, Box<str>, Option<Id<Kind>>, u64, u64);
type ToolRow = (Box<str>, Option<Id<Kind>>, u64, u64, u64);
type SessionRow = (Box<str>, Option<i64>, Vec<(Day, Vec<(Id<Kind>, u64)>)>);

/// The totals as loaded: wire ids decode to kinds and parts as they are
/// read, so loading holds no text but names, tools and sessions (written by
/// `AggregateRef`, in the same layout).
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub(super) struct StoredAggregate {
    days: Vec<(Day, Id<Kind>, [u64; 4])>,
    day_parts: Vec<DayPartRow>,
    all_parts: Vec<PartRow>,
    day_files: Vec<DayFileRow>,
    all_files: Vec<FileRow>,
    day_tools: Vec<DayToolRow>,
    all_tools: Vec<ToolRow>,
    tool_sessions: Vec<(Box<str>, u64, Day)>,
    sessions: Vec<SessionRow>,
    day_generation: Vec<(Day, u64)>,
}

impl StoredAggregate {
    /// The copying form of `AggregateRef` (its reference in tests).
    #[cfg(test)]
    pub(super) fn from_aggregate(agg: &Aggregate) -> Self {
        let slot = |slot: &Slot| (Id(slot.kind), Id(slot.part), slot.server.clone());
        Self {
            days: agg
                .days
                .iter()
                .map(|((day, kind), bucket)| (*day, Id(*kind), bucket.as_array()))
                .collect(),
            day_parts: agg
                .day_parts
                .iter()
                .map(|((day, key), bucket)| {
                    let (kind, part, server) = slot(key);
                    (*day, kind, part, server, bucket.as_array())
                })
                .collect(),
            all_parts: agg
                .all_parts
                .iter()
                .map(|(key, bucket)| {
                    let (kind, part, server) = slot(key);
                    (kind, part, server, bucket.as_array())
                })
                .collect(),
            day_files: agg
                .day_files
                .iter()
                .map(|((day, key), totals)| {
                    (
                        *day,
                        key.path.clone(),
                        Id(key.kind),
                        Id(key.part),
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
                        key.path.clone(),
                        Id(key.kind),
                        Id(key.part),
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
                        tool.clone(),
                        totals.kind.map(Id),
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
                        tool.clone(),
                        totals.kind.map(Id),
                        totals.calls,
                        totals.tokens,
                        totals.sessions,
                    )
                })
                .collect(),
            tool_sessions: agg
                .tool_sessions
                .iter()
                .map(|((tool, session), day)| (tool.clone(), *session, *day))
                .collect(),
            sessions: agg
                .sessions
                .iter()
                .map(|(session, totals)| {
                    (
                        session.clone(),
                        totals.started,
                        totals
                            .days
                            .iter()
                            .map(|(day, kinds)| {
                                (
                                    *day,
                                    kinds
                                        .iter()
                                        .map(|(kind, tokens)| (Id(*kind), *tokens))
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

    /// Rebuild the totals (unknown ids already failed the load).
    pub(super) fn into_aggregate(self) -> Aggregate {
        let slot = |Id(kind), Id(part), server| Slot { kind, part, server };
        let file_key = |path, Id(kind), Id(part)| FileKey { path, kind, part };
        let mut agg = Aggregate::default();
        for (day, Id(kind), values) in self.days {
            agg.days.insert((day, kind), Bucket::from_array(values));
        }
        for (day, kind, part, server, values) in self.day_parts {
            agg.day_parts
                .insert((day, slot(kind, part, server)), Bucket::from_array(values));
        }
        for (kind, part, server, values) in self.all_parts {
            agg.all_parts
                .insert(slot(kind, part, server), Bucket::from_array(values));
        }
        for (day, path, kind, part, events, tokens, last) in self.day_files {
            agg.day_files.insert(
                (day, file_key(path, kind, part)),
                FileTotals {
                    events,
                    tokens,
                    last,
                },
            );
        }
        for (path, kind, part, events, tokens, last) in self.all_files {
            agg.all_files.insert(
                file_key(path, kind, part),
                FileTotals {
                    events,
                    tokens,
                    last,
                },
            );
        }
        for (day, tool, kind, calls, tokens) in self.day_tools {
            agg.day_tools.insert(
                (day, tool),
                ToolTotals {
                    calls,
                    tokens,
                    sessions: 0,
                    kind: kind.map(|Id(kind)| kind),
                },
            );
        }
        for (tool, kind, calls, tokens, sessions) in self.all_tools {
            agg.all_tools.insert(
                tool,
                ToolTotals {
                    calls,
                    tokens,
                    sessions,
                    kind: kind.map(|Id(kind)| kind),
                },
            );
        }
        for (tool, session, day) in self.tool_sessions {
            agg.tool_sessions.insert((tool, session), day);
        }
        for (session, started, days) in self.sessions {
            let days = days
                .into_iter()
                .map(|(day, kinds)| {
                    let kinds = kinds.into_iter().map(|(Id(kind), tokens)| (kind, tokens));
                    (day, kinds.collect())
                })
                .collect();
            agg.sessions
                .insert(session, SessionTotals { started, days });
        }
        agg.day_generation = self.day_generation.into_iter().collect();
        agg
    }
}

type StoredPartRow = (Day, String, String, Option<String>, [u64; 4]);

/// Stored form of a file's contribution (wire ids).
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub(super) struct StoredContribution {
    parts: Vec<StoredPartRow>,
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

    /// The file's session, as first counted.
    pub(super) fn session(&self) -> Option<&str> {
        self.session.as_deref()
    }

    /// (day, file name) of each per-day file row.
    pub(super) fn file_days(&self) -> impl Iterator<Item = (Day, &str)> {
        self.files.iter().map(|row| (row.0, row.1.as_str()))
    }

    /// Bytes held in memory, approximately: each row's fixed part and its
    /// text.
    pub(super) fn accounted_bytes(&self) -> usize {
        const ROW: usize = 96;
        self.parts
            .iter()
            .map(|row| ROW + row.1.len() + row.2.len() + row.3.as_ref().map_or(0, String::len))
            .chain(
                self.files
                    .iter()
                    .map(|row| ROW + row.1.len() + row.2.len() + row.3.len()),
            )
            .chain(self.tools.iter().map(|row| ROW / 2 + row.1.len()))
            .chain(self.sessions.iter().map(|row| ROW / 2 + row.1.len()))
            .sum::<usize>()
            + self.session.as_ref().map_or(0, String::len)
    }

    /// Drop all but the session (a cold file's share). Returns whether
    /// anything was dropped.
    pub(super) fn keep_session_only(&mut self) -> bool {
        let dropped = !(self.parts.is_empty()
            && self.files.is_empty()
            && self.tools.is_empty()
            && self.sessions.is_empty());
        self.parts = Vec::new();
        self.files = Vec::new();
        self.tools = Vec::new();
        self.sessions = Vec::new();
        dropped
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
