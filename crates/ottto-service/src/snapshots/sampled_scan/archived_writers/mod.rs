//! Hash-pinned, test-only copies of old record writers.
//!
//! The transition seed checks a post-save artifact against one of these instead
//! of against current production source, so a later writer can change freely
//! without invalidating proof about bytes already on users' disks. Each archive
//! is one `w_<sha8>.rs` plus its `w_<sha8>_helpers.json`; adding one never touches
//! another. `transition_serializer_regions.py --archive <sha>` documents the
//! verification. The live-source check in `transition_seed.rs` is separate and
//! keeps following current code.
//!
//! The seed feeds an archived writer live state, not the bytes it checks: the
//! retained reduction's `{:?}` rendering becomes a `StateNode`, each archived
//! type takes its fields from it by name (`FromState`), and the copied `encode`
//! serializes the result. A writer that moves a value to another wire position
//! therefore disagrees with the archive even when the old layout still parses
//! its bytes. `live_state.rs` and two test-only impls next to their private
//! types render the few production types without a derived `Debug`.
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::ffi::OsStr;
use std::path::Path;

use sha2::{Digest, Sha256};

#[rustfmt::skip]
#[path = "w_53d05a43.rs"]
pub(crate) mod w_53d05a43;

pub(crate) use w_53d05a43::W_53d05a43;

#[path = "live_state.rs"]
mod live_state;

const KNOWN_PINS: [&str; 1] = [W_53d05a43::PIN];

/// One copied source unit: `roots` select its regions, `sha256` pins their tokens.
pub(crate) struct Region {
    pub(crate) path: &'static str,
    pub(crate) roots: &'static [&'static str],
    pub(crate) sha256: &'static str,
}

/// Everything a v1 envelope records, free of current store types. `source_tag`
/// is the store's on-disk source byte.
#[derive(Clone)]
pub(crate) struct ArchivedRecord {
    pub(crate) source_tag: u8,
    pub(crate) key: [u8; 32],
    pub(crate) context: [u8; 32],
    pub(crate) scope: [u8; 32],
    pub(crate) entry: [u8; 32],
    pub(crate) allowlist: [u8; 32],
    pub(crate) generation: u64,
    pub(crate) device: u64,
    pub(crate) inode: u64,
    pub(crate) length: u64,
    pub(crate) modified: (i64, i64),
    pub(crate) birth_nanos: u64,
    pub(crate) sealed_offset: u64,
    pub(crate) sample_len: u32,
    pub(crate) head_sha256: [u8; 32],
    pub(crate) boundary_sha256: [u8; 32],
    pub(crate) verified_unix_seconds: u64,
    pub(crate) audit_debt: Option<u64>,
    pub(crate) body: Vec<u8>,
}

/// Live values the content digests cover; a record never stores them.
#[derive(Clone, Default)]
pub(crate) struct ArchivedContent {
    pub(crate) title: Option<String>,
    pub(crate) first_prompt_title: Option<String>,
    pub(crate) first_prompt_material: Option<String>,
    pub(crate) workspace_path: Option<std::path::PathBuf>,
    pub(crate) agent_label: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ContentDigests {
    pub(crate) first_prompt: Option<[u8; 32]>,
    pub(crate) workspace: Option<[u8; 32]>,
    pub(crate) agent_label: Option<[u8; 32]>,
    pub(crate) title: Option<[u8; 32]>,
}

pub(crate) enum Golden {
    /// The whole record for an opaque body: framing only.
    Frame {
        record: Box<ArchivedRecord>,
        expected: Vec<u8>,
    },
    /// A body this writer must parse and re-emit byte for byte.
    Body { source_tag: u8, body: Vec<u8> },
}

pub(crate) trait ArchivedWriter {
    /// The full 40-hex commit the regions were copied from.
    const SOURCE_SHA: &'static str;
    /// The short name fixture rows select the writer by.
    const PIN: &'static str;
    const FORMAT: u16;
    fn regions() -> &'static [Region];
    /// The allowlist digest this writer stamps for a source.
    fn allowlist(source_tag: u8) -> Result<[u8; 32], String>;
    /// The body this writer emits for a live reduction rendered as `state`.
    fn encode_state(source_tag: u8, state: &StateNode, line_cap: u64) -> Result<Vec<u8>, String>;
    /// Re-emit stored body bytes, or say why this writer never could have. A
    /// structural check only: stored digests and old-layout values pass through.
    fn encode_body(source_tag: u8, body: &[u8]) -> Result<Vec<u8>, String>;
    /// Header, opaque body and trailer.
    fn frame(record: &ArchivedRecord) -> Result<Vec<u8>, String>;
    /// Digests this writer's own functions compute for live content.
    fn content_digests(source_tag: u8, content: &ArchivedContent)
        -> Result<ContentDigests, String>;
    /// This writer's `session_start` digest of the fixed instruction transcripts.
    fn session_start_golden(source_tag: u8) -> Option<&'static str>;
    fn goldens() -> Vec<Golden>;

    /// The whole record for live state; `record.body` is replaced.
    fn encode_live(
        record: &ArchivedRecord,
        state: &StateNode,
        line_cap: u64,
    ) -> Result<Vec<u8>, String> {
        let mut framed = record.clone();
        framed.body = Self::encode_state(record.source_tag, state, line_cap)?;
        Self::frame(&framed)
    }
}

/// A `{:?}` rendering read back as data. Maps keep their rendered entries;
/// `FromState` rebuilds typed values from these by field name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum StateNode {
    Text(String),
    Number(String),
    /// A unit struct or variant, `None`, `true` or `false`.
    Name(String),
    Named(String, Vec<(String, StateNode)>),
    /// A tuple struct or variant, `Some(..)`, or a tuple when unnamed.
    Tuple(Option<String>, Vec<StateNode>),
    List(Vec<StateNode>),
    Map(Vec<(StateNode, StateNode)>),
    Set(Vec<StateNode>),
}

impl StateNode {
    pub(crate) fn parse(text: &str) -> Result<Self, String> {
        let mut parser = StateParser { text, at: 0 };
        let node = parser.node()?;
        parser.skip_space();
        if parser.at != text.len() {
            return Err(format!("trailing state text at byte {}", parser.at));
        }
        Ok(node)
    }

    /// Exchange two fields' values in every `owner` struct: the value a writer
    /// with those two `put` calls reversed would emit. Returns how many moved.
    pub(crate) fn swap_fields(&mut self, owner: &str, a: &str, b: &str) -> usize {
        let mut swapped = 0;
        match self {
            Self::Named(name, fields) => {
                let at = |field: &str| fields.iter().position(|(n, _)| n == field);
                if name == owner {
                    if let (Some(x), Some(y)) = (at(a), at(b)) {
                        let first = fields[x].1.clone();
                        fields[x].1 = std::mem::replace(&mut fields[y].1, first);
                        swapped += 1;
                    }
                }
                for (_, value) in fields.iter_mut() {
                    swapped += value.swap_fields(owner, a, b);
                }
            }
            Self::Tuple(_, items) | Self::List(items) | Self::Set(items) => {
                for item in items {
                    swapped += item.swap_fields(owner, a, b);
                }
            }
            Self::Map(entries) => {
                for (key, value) in entries {
                    swapped += key.swap_fields(owner, a, b) + value.swap_fields(owner, a, b);
                }
            }
            Self::Text(_) | Self::Number(_) | Self::Name(_) => {}
        }
        swapped
    }

    /// A content-free label for errors: rendered state can hold user text.
    fn kind(&self) -> String {
        match self {
            Self::Text(_) => "text".to_string(),
            Self::Number(_) => "number".to_string(),
            Self::Name(name) => name.clone(),
            Self::Named(name, _) => format!("{name} {{ .. }}"),
            Self::Tuple(Some(name), _) => format!("{name}(..)"),
            Self::Tuple(None, _) => "tuple".to_string(),
            Self::List(_) => "list".to_string(),
            Self::Map(_) => "map".to_string(),
            Self::Set(_) => "set".to_string(),
        }
    }
}

struct StateParser<'a> {
    text: &'a str,
    at: usize,
}

impl StateParser<'_> {
    fn peek(&self) -> Option<char> {
        self.text[self.at..].chars().next()
    }

    fn skip_space(&mut self) {
        while let Some(c) = self.peek().filter(|c| c.is_whitespace()) {
            self.at += c.len_utf8();
        }
    }

    fn eat(&mut self, want: char) -> bool {
        self.skip_space();
        let found = self.peek() == Some(want);
        if found {
            self.at += want.len_utf8();
        }
        found
    }

    fn expect(&mut self, want: char) -> Result<(), String> {
        if self.eat(want) {
            Ok(())
        } else {
            Err(format!("expected {want:?} at byte {}", self.at))
        }
    }

    fn word(&mut self) -> String {
        let start = self.at;
        while let Some(c) = self
            .peek()
            .filter(|c| c.is_alphanumeric() || matches!(c, '_' | '#' | '.' | '-'))
        {
            self.at += c.len_utf8();
        }
        let word = &self.text[start..self.at];
        word.strip_prefix("r#").unwrap_or(word).to_string()
    }

    fn node(&mut self) -> Result<StateNode, String> {
        self.skip_space();
        let Some(first) = self.peek() else {
            return Err("state text ended early".to_string());
        };
        if first == '"' {
            self.at += 1;
            return self.text().map(StateNode::Text);
        }
        if let Some(close) = [('[', ']'), ('(', ')'), ('{', '}')]
            .iter()
            .find(|(open, _)| *open == first)
            .map(|(_, close)| *close)
        {
            self.at += 1;
            return match close {
                ']' => self.items(']').map(StateNode::List),
                ')' => self.items(')').map(|items| StateNode::Tuple(None, items)),
                _ => self.braced(),
            };
        }
        if first == '-' || first.is_ascii_digit() {
            return Ok(StateNode::Number(self.word()));
        }
        if !(first.is_alphabetic() || first == '_') {
            return Err(format!("unexpected state text at byte {}", self.at));
        }
        let name = self.word();
        if self.eat('(') {
            return Ok(StateNode::Tuple(Some(name), self.items(')')?));
        }
        if self.eat('{') {
            return Ok(StateNode::Named(name, self.fields()?));
        }
        Ok(StateNode::Name(name))
    }

    fn items(&mut self, close: char) -> Result<Vec<StateNode>, String> {
        let mut items = Vec::new();
        while !self.eat(close) {
            items.push(self.node()?);
            if !self.eat(',') {
                self.expect(close)?;
                break;
            }
        }
        Ok(items)
    }

    fn fields(&mut self) -> Result<Vec<(String, StateNode)>, String> {
        let mut fields = Vec::new();
        while !self.eat('}') {
            self.skip_space();
            let name = self.word();
            self.expect(':')?;
            fields.push((name, self.node()?));
            if !self.eat(',') {
                self.expect('}')?;
                break;
            }
        }
        Ok(fields)
    }

    fn braced(&mut self) -> Result<StateNode, String> {
        if self.eat('}') {
            return Ok(StateNode::Map(Vec::new()));
        }
        let first = self.node()?;
        if !self.eat(':') {
            let mut items = vec![first];
            if self.eat(',') {
                items.extend(self.items('}')?);
            } else {
                self.expect('}')?;
            }
            return Ok(StateNode::Set(items));
        }
        let mut entries = vec![(first, self.node()?)];
        while self.eat(',') {
            if self.eat('}') {
                return Ok(StateNode::Map(entries));
            }
            let key = self.node()?;
            self.expect(':')?;
            entries.push((key, self.node()?));
        }
        self.expect('}')?;
        Ok(StateNode::Map(entries))
    }

    /// The body of a `{:?}` string after its opening quote.
    fn text(&mut self) -> Result<String, String> {
        let mut out = String::new();
        loop {
            let Some(c) = self.peek() else {
                return Err("unterminated state string".to_string());
            };
            self.at += c.len_utf8();
            match c {
                '"' => return Ok(out),
                '\\' => {
                    let Some(escape) = self.peek() else {
                        return Err("unterminated state escape".to_string());
                    };
                    self.at += escape.len_utf8();
                    out.push(match escape {
                        'n' => '\n',
                        'r' => '\r',
                        't' => '\t',
                        '0' => '\0',
                        '\\' | '"' | '\'' => escape,
                        'u' => {
                            self.expect('{')?;
                            let digits = self.word();
                            self.expect('}')?;
                            u32::from_str_radix(&digits, 16)
                                .ok()
                                .and_then(char::from_u32)
                                .ok_or_else(|| "bad unicode escape in state string".to_string())?
                        }
                        _ => return Err("unsupported escape in state string".to_string()),
                    });
                }
                _ => out.push(c),
            }
        }
    }
}

/// A typed value rebuilt from rendered live state.
pub(crate) trait FromState: Sized {
    fn from_state(node: &StateNode) -> Result<Self, String>;
}

/// A struct's rendered fields, consumed by name.
pub(crate) struct StateFields<'a> {
    owner: &'a str,
    fields: Vec<(&'a str, &'a StateNode)>,
}

impl<'a> StateFields<'a> {
    pub(crate) fn named(node: &'a StateNode, owner: &'a str) -> Result<Self, String> {
        let fields = match node {
            StateNode::Named(name, fields) if name == owner => fields
                .iter()
                .map(|(name, value)| (name.as_str(), value))
                .collect(),
            StateNode::Name(name) if name == owner => Vec::new(),
            other => return Err(format!("expected {owner}, found {}", other.kind())),
        };
        Ok(Self { owner, fields })
    }

    pub(crate) fn take<T: FromState>(&mut self, name: &str) -> Result<T, String> {
        let at = self
            .fields
            .iter()
            .position(|(field, _)| *field == name)
            .ok_or_else(|| format!("{}.{name} is missing from live state", self.owner))?;
        let (_, node) = self.fields.remove(at);
        T::from_state(node).map_err(|error| format!("{}.{name}: {error}", self.owner))
    }

    /// `E` and `I` fields never reach the wire, so a rendering may omit them.
    pub(crate) fn ignore<T: Default>(&mut self, name: &str) -> T {
        self.fields.retain(|(field, _)| *field != name);
        T::default()
    }

    pub(crate) fn finish(self) -> Result<(), String> {
        match self.fields.first() {
            None => Ok(()),
            Some((name, _)) => Err(format!("{}.{name} has no archived field", self.owner)),
        }
    }

    pub(crate) fn variant(node: &StateNode) -> Result<&str, String> {
        match node {
            StateNode::Name(name) | StateNode::Named(name, _) | StateNode::Tuple(Some(name), _) => {
                Ok(name)
            }
            other => Err(format!("expected an enum variant, found {}", other.kind())),
        }
    }

    pub(crate) fn unit(node: &StateNode, variant: &str) -> Result<(), String> {
        match node {
            StateNode::Name(name) if name == variant => Ok(()),
            other => Err(format!("expected {variant}, found {}", other.kind())),
        }
    }
}

/// A tuple struct's or variant's rendered items, consumed in order.
pub(crate) struct StateItems<'a> {
    owner: &'a str,
    items: std::slice::Iter<'a, StateNode>,
}

impl<'a> StateItems<'a> {
    pub(crate) fn tuple(node: &'a StateNode, owner: &'a str) -> Result<Self, String> {
        match node {
            StateNode::Tuple(Some(name), items) if name == owner => Ok(Self {
                owner,
                items: items.iter(),
            }),
            other => Err(format!("expected {owner}(..), found {}", other.kind())),
        }
    }

    pub(crate) fn take<T: FromState>(&mut self) -> Result<T, String> {
        let node = self
            .items
            .next()
            .ok_or_else(|| format!("{} has too few items", self.owner))?;
        T::from_state(node).map_err(|error| format!("{}.{error}", self.owner))
    }

    pub(crate) fn finish(mut self) -> Result<(), String> {
        match self.items.next() {
            None => Ok(()),
            Some(_) => Err(format!("{} has too many items", self.owner)),
        }
    }
}

macro_rules! numbers_from_state {
    ($($t:ty),* $(,)?) => {$(
        impl FromState for $t {
            fn from_state(node: &StateNode) -> Result<Self, String> {
                match node {
                    StateNode::Number(text) => text
                        .parse()
                        .map_err(|_| format!("{text} is not a {}", stringify!($t))),
                    other => Err(format!("expected a number, found {}", other.kind())),
                }
            }
        }
    )*};
}
numbers_from_state!(
    u8,
    u16,
    u32,
    u64,
    usize,
    i32,
    i64,
    i128,
    u128,
    std::num::NonZeroU64
);

impl FromState for bool {
    fn from_state(node: &StateNode) -> Result<Self, String> {
        match node {
            StateNode::Name(name) if name == "true" => Ok(true),
            StateNode::Name(name) if name == "false" => Ok(false),
            other => Err(format!("expected a bool, found {}", other.kind())),
        }
    }
}

impl FromState for String {
    fn from_state(node: &StateNode) -> Result<Self, String> {
        match node {
            StateNode::Text(text) => Ok(text.clone()),
            other => Err(format!("expected text, found {}", other.kind())),
        }
    }
}

impl FromState for std::path::PathBuf {
    fn from_state(node: &StateNode) -> Result<Self, String> {
        String::from_state(node).map(Self::from)
    }
}

/// Static labels: the copied `put` looks the text up in its own table.
impl FromState for &'static str {
    fn from_state(node: &StateNode) -> Result<Self, String> {
        Ok(Box::leak(String::from_state(node)?.into_boxed_str()))
    }
}

impl FromState for () {
    fn from_state(node: &StateNode) -> Result<Self, String> {
        match node {
            StateNode::Tuple(None, items) if items.is_empty() => Ok(()),
            other => Err(format!("expected (), found {}", other.kind())),
        }
    }
}

impl<T: FromState> FromState for Option<T> {
    fn from_state(node: &StateNode) -> Result<Self, String> {
        match node {
            StateNode::Name(name) if name == "None" => Ok(None),
            StateNode::Tuple(Some(name), items) if name == "Some" && items.len() == 1 => {
                T::from_state(&items[0]).map(Some)
            }
            other => Err(format!("expected an Option, found {}", other.kind())),
        }
    }
}

impl<T: FromState> FromState for Box<T> {
    fn from_state(node: &StateNode) -> Result<Self, String> {
        T::from_state(node).map(Box::new)
    }
}

fn state_list(node: &StateNode) -> Result<&[StateNode], String> {
    match node {
        StateNode::List(items) => Ok(items),
        other => Err(format!("expected a list, found {}", other.kind())),
    }
}

impl<T: FromState> FromState for Vec<T> {
    fn from_state(node: &StateNode) -> Result<Self, String> {
        state_list(node)?.iter().map(T::from_state).collect()
    }
}

impl<T: FromState> FromState for VecDeque<T> {
    fn from_state(node: &StateNode) -> Result<Self, String> {
        state_list(node)?.iter().map(T::from_state).collect()
    }
}

impl<T: FromState, const N: usize> FromState for [T; N] {
    fn from_state(node: &StateNode) -> Result<Self, String> {
        let items = Vec::<T>::from_state(node)?;
        let len = items.len();
        items
            .try_into()
            .map_err(|_| format!("expected {N} items, found {len}"))
    }
}

impl<K: FromState + Ord, V: FromState> FromState for BTreeMap<K, V> {
    fn from_state(node: &StateNode) -> Result<Self, String> {
        let entries = match node {
            StateNode::Map(entries) => entries,
            other => return Err(format!("expected a map, found {}", other.kind())),
        };
        let mut out = Self::new();
        for (key, value) in entries {
            if out
                .insert(K::from_state(key)?, V::from_state(value)?)
                .is_some()
            {
                return Err("duplicate rendered map key".to_string());
            }
        }
        Ok(out)
    }
}

impl<T: FromState + Ord> FromState for BTreeSet<T> {
    fn from_state(node: &StateNode) -> Result<Self, String> {
        let items: &[StateNode] = match node {
            StateNode::Set(items) => items,
            StateNode::Map(entries) if entries.is_empty() => &[],
            other => return Err(format!("expected a set, found {}", other.kind())),
        };
        let mut out = Self::new();
        for item in items {
            if !out.insert(T::from_state(item)?) {
                return Err("duplicate rendered set item".to_string());
            }
        }
        Ok(out)
    }
}

fn state_tuple(node: &StateNode, len: usize) -> Result<&[StateNode], String> {
    match node {
        StateNode::Tuple(None, items) if items.len() == len => Ok(items),
        other => Err(format!("expected a {len}-tuple, found {}", other.kind())),
    }
}

impl<A: FromState, B: FromState> FromState for (A, B) {
    fn from_state(node: &StateNode) -> Result<Self, String> {
        let items = state_tuple(node, 2)?;
        Ok((A::from_state(&items[0])?, B::from_state(&items[1])?))
    }
}

impl<A: FromState, B: FromState, C: FromState> FromState for (A, B, C) {
    fn from_state(node: &StateNode) -> Result<Self, String> {
        let items = state_tuple(node, 3)?;
        Ok((
            A::from_state(&items[0])?,
            B::from_state(&items[1])?,
            C::from_state(&items[2])?,
        ))
    }
}

pub(crate) fn decode_hex(hex: &str) -> Vec<u8> {
    hex.as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

pub(crate) fn assert_archive_matches_goldens<W: ArchivedWriter>() {
    let goldens = W::goldens();
    assert!(!goldens.is_empty(), "{} has no goldens", W::PIN);
    for golden in goldens {
        match golden {
            Golden::Frame { record, expected } => {
                assert_eq!(W::allowlist(record.source_tag), Ok(record.allowlist));
                assert_eq!(W::frame(&record), Ok(expected));
            }
            Golden::Body { source_tag, body } => {
                assert_eq!(W::encode_body(source_tag, &body), Ok(body));
            }
        }
    }
}

#[derive(serde::Deserialize)]
struct ArchiveReport {
    archive: String,
    hashes: BTreeMap<String, String>,
    roots: BTreeMap<String, BTreeSet<String>>,
    references: BTreeSet<String>,
}

fn source_root() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src")
}

fn verify_archive_in(
    pin: &str,
    text_only: bool,
    overrides: &[(&str, &str)],
    root: &Path,
    directory: Option<&Path>,
) -> Result<ArchiveReport, String> {
    let mut args = vec![OsStr::new("--archive"), OsStr::new(pin)];
    if text_only {
        args.push(OsStr::new("--archive-text-only"));
    }
    let output = super::run_extractor(&args, overrides, OsStr::new("python3"), root, directory);
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).into_owned());
    }
    Ok(serde_json::from_slice(&output.stdout).expect("archive verification returned invalid JSON"))
}

/// Text-only verification: tests run on shallow checkouts without `SOURCE_SHA`.
fn verify_archive(pin: &str, overrides: &[(&str, &str)]) -> Result<ArchiveReport, String> {
    verify_archive_in(pin, true, overrides, &source_root(), None)
}

/// Refuse a writer the rows have no archive for, before touching any store.
pub(super) fn require_known(pin: &str) {
    assert!(KNOWN_PINS.contains(&pin), "unknown archived writer: {pin}");
}

/// Guard the seed calls first. It reads only the archive, so production source
/// changes cannot refuse an old writer; region edits and helper drift do.
pub(super) fn assert_provenance<W: ArchivedWriter>() {
    static VERIFIED: std::sync::Mutex<BTreeSet<&'static str>> =
        std::sync::Mutex::new(BTreeSet::new());
    let mut verified = VERIFIED.lock().unwrap();
    if verified.contains(W::SOURCE_SHA) {
        return;
    }
    let report = verify_archive(W::PIN, &[])
        .unwrap_or_else(|error| panic!("archived writer {} refused: {error}", W::PIN));
    assert_eq!(report.archive, W::SOURCE_SHA);
    let declared = W::regions()
        .iter()
        .map(|region| (region.path.to_string(), region.sha256.to_string()))
        .collect::<BTreeMap<_, _>>();
    assert_eq!(report.hashes, declared);
    let roots = W::regions()
        .iter()
        .map(|region| {
            let names = region.roots.iter().map(ToString::to_string).collect();
            (region.path.to_string(), names)
        })
        .collect::<BTreeMap<_, BTreeSet<_>>>();
    assert_eq!(report.roots, roots);
    verified.insert(W::SOURCE_SHA);
}

const ARCHIVE_PATH: &str = "snapshots/sampled_scan/archived_writers/w_53d05a43.rs";
const INVENTORY_PATH: &str = "snapshots/sampled_scan/archived_writers/w_53d05a43_helpers.json";
const ARCHIVE_TEXT: &str = include_str!("w_53d05a43.rs");
const INVENTORY_TEXT: &str = include_str!("w_53d05a43_helpers.json");
const SYNTHETIC_UNIT: &str = "durable_tail_codec.rs";
const SYNTHETIC_SOURCE: &str = "fn a() {}";

fn synthetic_tokens_sha256() -> String {
    let tokens = ["fn", "a", "(", ")", "{", "}"].join("\0");
    format!("{:x}", Sha256::digest(tokens.as_bytes()))
}

/// A second, minimal archive, in the same file form as a real one.
fn synthetic_archive(sha: &str, pinned: &str) -> String {
    format!(
        "const SOURCE_SHA: &str = \"{sha}\";\n\
         const ARCHIVE_ROOT: &str = \"crate::snapshots::w_{short}\";\n\
         const REGIONS: &[Region] = &[Region {{\n\
         path: \"{SYNTHETIC_UNIT}\",\n\
         roots: &[],\n\
         sha256: \"{pinned}\",\n\
         }}];\n\
         // archive-region: {SYNTHETIC_UNIT}\n\
         {SYNTHETIC_SOURCE}\n\
         // archive-region-end\n",
        short = &sha[..8],
    )
}

fn refusal(result: Result<ArchiveReport, String>) -> String {
    match result {
        Ok(report) => panic!("archive {} must be refused", report.archive),
        Err(error) => error,
    }
}

fn assert_text_edit_refused(before: &str, after: &str, expected: &str) {
    assert_eq!(ARCHIVE_TEXT.matches(before).count(), 1, "edit premise");
    let edited = ARCHIVE_TEXT.replacen(before, after, 1);
    let error = refusal(verify_archive(W_53d05a43::PIN, &[(ARCHIVE_PATH, &edited)]));
    assert!(error.contains(expected), "{error}");
}

#[test]
fn archived_writer_53d05a43_matches_its_goldens() {
    assert_archive_matches_goldens::<W_53d05a43>();
}

#[test]
fn archived_writer_provenance_accepts_the_pinned_archive() {
    assert_provenance::<W_53d05a43>();
    let report = verify_archive(W_53d05a43::SOURCE_SHA, &[]).unwrap();
    assert_eq!(report.archive.len(), 40);
    assert_eq!(report.archive, W_53d05a43::SOURCE_SHA);
    assert_eq!(report.hashes.len(), W_53d05a43::regions().len());
    let inventory: BTreeMap<String, String> = serde_json::from_str(INVENTORY_TEXT).unwrap();
    assert_eq!(
        report.references,
        inventory.into_keys().collect::<BTreeSet<_>>()
    );
}

#[test]
fn archived_writer_one_byte_region_edit_fails_provenance() {
    assert_text_edit_refused(
        "    0 => Codex,",
        "    9 => Codex,",
        "archive region does not match its pin: snapshots.rs",
    );
    // Frozen framing and field lists sit behind the same guard.
    assert_text_edit_refused(
        "*b\"ottto-dt\"",
        "*b\"ottto-du\"",
        "archive region does not match its pin: durable_tail_store.rs",
    );
    assert_text_edit_refused(
        "    H session_start: Option<[u8; 32]>,\n    H title",
        "    H session_start: Option<[u8; 33]>,\n    H title",
        "archive region does not match its pin: snapshots/sampled_jsonl/durable.rs",
    );
}

#[test]
fn archived_writer_pin_or_marker_tampering_fails_provenance() {
    let region = &W_53d05a43::regions()[0];
    let flipped = if region.sha256.starts_with('0') {
        "1"
    } else {
        "0"
    };
    let edited = format!("{flipped}{}", &region.sha256[1..]);
    assert_text_edit_refused(
        region.sha256,
        &edited,
        "archive region does not match its pin",
    );
    let unmarked = ARCHIVE_TEXT.replace("// archive-region: snapshots/context_curve.rs\n", "");
    let error = refusal(verify_archive(
        W_53d05a43::PIN,
        &[(ARCHIVE_PATH, &unmarked)],
    ));
    assert!(
        error.contains("unbalanced archive region markers"),
        "{error}"
    );
}

#[test]
fn archived_writer_unknown_sha_fails() {
    for pin in ["00000000", &"0".repeat(40), "53d05a4", ""] {
        let error = refusal(verify_archive_in(pin, true, &[], &source_root(), None));
        assert!(error.contains("unknown archived writer"), "{error}");
    }
}

#[test]
#[should_panic(expected = "unknown archived writer: 00000000")]
fn archived_writer_unknown_pin_panics_before_any_store_read() {
    require_known("00000000");
}

#[test]
fn archived_writer_second_archive_leaves_the_first_unchanged() {
    let before = verify_archive(W_53d05a43::PIN, &[]).unwrap();
    let sha = "0123abcd".repeat(5);
    let path = "snapshots/sampled_scan/archived_writers/w_0123abcd.rs";
    let inventory = "snapshots/sampled_scan/archived_writers/w_0123abcd_helpers.json";
    let archive = synthetic_archive(&sha, &synthetic_tokens_sha256());
    let overrides = [(path, archive.as_str()), (inventory, "{}")];
    let after = verify_archive(W_53d05a43::PIN, &overrides).unwrap();
    assert_eq!(after.hashes, before.hashes);
    assert_eq!(after.references, before.references);
    let second = verify_archive(&sha, &overrides).unwrap();
    assert_eq!(second.archive, sha);
    assert_eq!(
        second.hashes,
        BTreeMap::from([(SYNTHETIC_UNIT.to_string(), synthetic_tokens_sha256())])
    );
}

#[test]
fn archived_writer_cannot_reach_production_paths() {
    assert_text_edit_refused(
        "use sha2::{Digest, Sha256};\n\npub(crate) struct W_53d05a43;",
        "use crate::snapshots::SnapshotSource;\n\npub(crate) struct W_53d05a43;",
        "archive reaches outside itself",
    );
    assert_text_edit_refused(
        "use super::{\n    decode_hex,",
        "use super::super::{\n    decode_hex,",
        "archive reaches outside itself",
    );
}

#[test]
fn archived_writer_helper_inventory_change_fails() {
    let mut inventory: BTreeMap<String, String> = serde_json::from_str(INVENTORY_TEXT).unwrap();
    let dropped = inventory.keys().next().unwrap().clone();
    inventory.remove(&dropped);
    let edited = serde_json::to_string(&inventory).unwrap();
    let error = refusal(verify_archive(
        W_53d05a43::PIN,
        &[(INVENTORY_PATH, &edited)],
    ));
    assert!(
        error.contains("archive helper inventory changed"),
        "{error}"
    );
    let mut inventory: BTreeMap<String, String> = serde_json::from_str(INVENTORY_TEXT).unwrap();
    inventory.insert(dropped, "reviewed later".to_string());
    let edited = serde_json::to_string(&inventory).unwrap();
    let error = refusal(verify_archive(
        W_53d05a43::PIN,
        &[(INVENTORY_PATH, &edited)],
    ));
    assert!(error.contains("unreviewed archive helper"), "{error}");
}

#[test]
fn archived_writer_stays_out_of_the_live_catalog() {
    let live = super::extract_with_python(None);
    assert!(live
        .hashes
        .keys()
        .all(|path| !path.contains("archived_writers")));
}

#[test]
fn archived_writer_refuses_bytes_it_could_not_have_written() {
    let body = W_53d05a43::goldens()
        .into_iter()
        .find_map(|golden| match golden {
            Golden::Body {
                source_tag: 1,
                body,
            } => Some(body),
            _ => None,
        })
        .unwrap();
    assert_eq!(W_53d05a43::encode_body(1, &body).as_ref(), Ok(&body));
    let mut extended = body.clone();
    extended.push(0);
    assert!(W_53d05a43::encode_body(1, &extended).is_err());
    assert!(W_53d05a43::encode_body(1, &body[..body.len() - 1]).is_err());
    assert_eq!(
        W_53d05a43::encode_body(2, &body),
        Err("body belongs to another source".to_string())
    );
    assert!(W_53d05a43::encode_body(3, &body).is_err());
    assert!(W_53d05a43::allowlist(3).is_err());
}

#[test]
fn archived_writer_encode_frames_its_own_body() {
    let golden = W_53d05a43::goldens();
    let Golden::Frame { record, expected } = &golden[0] else {
        panic!("frame goldens come first");
    };
    let body = golden
        .iter()
        .find_map(|golden| match golden {
            Golden::Body { source_tag, body } if *source_tag == record.source_tag => Some(body),
            _ => None,
        })
        .unwrap();
    let mut with_body = record.clone();
    with_body.body = W_53d05a43::encode_body(record.source_tag, body).unwrap();
    let framed = W_53d05a43::frame(&with_body).unwrap();
    assert_eq!(&framed[..8], &expected[..8]);
    assert_eq!(
        u16::from_le_bytes(framed[8..10].try_into().unwrap()),
        W_53d05a43::FORMAT
    );
    let digest_at = framed.len() - 32;
    assert_eq!(
        &framed[digest_at..],
        Sha256::digest(&framed[..digest_at]).as_slice()
    );
    assert!(W_53d05a43::encode_body(record.source_tag, b"opaque-v1-body").is_err());
}

#[test]
fn state_node_reads_debug_renderings() {
    #[derive(Debug)]
    struct Unit;
    #[derive(Debug)]
    struct Pair(i64, Option<u8>);
    #[derive(Debug)]
    struct Live {
        r#type: String,
        unit: Unit,
        pair: Pair,
        map: BTreeMap<String, Vec<u8>>,
        set: BTreeSet<u64>,
        empty: BTreeSet<u64>,
        tuple: (bool, ()),
    }
    let live = Live {
        r#type: "q\"\\\n\t\0\u{1}é".to_string(),
        unit: Unit,
        pair: Pair(-3, Some(7)),
        map: BTreeMap::from([("k".to_string(), vec![1, 2])]),
        set: BTreeSet::from([4, 5]),
        empty: BTreeSet::new(),
        tuple: (true, ()),
    };
    for rendered in [format!("{live:?}"), format!("{live:#?}")] {
        let node = StateNode::parse(&rendered).unwrap();
        let mut fields = StateFields::named(&node, "Live").unwrap();
        assert_eq!(fields.take::<String>("type").unwrap(), live.r#type);
        StateFields::unit(fields.fields[0].1, "Unit").unwrap();
        fields.ignore::<()>("unit");
        let mut pair = StateItems::tuple(fields.fields[0].1, "Pair").unwrap();
        assert_eq!(pair.take::<i64>().unwrap(), live.pair.0);
        assert_eq!(pair.take::<Option<u8>>().unwrap(), live.pair.1);
        pair.finish().unwrap();
        fields.ignore::<()>("pair");
        assert_eq!(
            fields.take::<BTreeMap<String, Vec<u8>>>("map").unwrap(),
            live.map
        );
        assert_eq!(fields.take::<BTreeSet<u64>>("set").unwrap(), live.set);
        assert_eq!(fields.take::<BTreeSet<u64>>("empty").unwrap(), live.empty);
        assert_eq!(fields.take::<(bool, ())>("tuple").unwrap(), live.tuple);
        fields.finish().unwrap();
    }
    let Unit = live.unit;
    assert!(StateNode::parse("Live { a: 1 } trailing").is_err());
    assert!(StateNode::parse("\"unterminated").is_err());
}

struct SyntheticRepo(std::path::PathBuf);
impl SyntheticRepo {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "ottto-archived-writer-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(path.join("crates/ottto-service/src")).unwrap();
        let repo = Self(path);
        repo.git(&["init", "--quiet"]);
        repo
    }
    fn git(&self, args: &[&str]) -> String {
        let output = std::process::Command::new("git")
            .args([
                "-c",
                "user.name=fixture",
                "-c",
                "user.email=fixture@example.invalid",
                "-c",
                "commit.gpgsign=false",
            ])
            .args(args)
            .current_dir(&self.0)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .output()
            .expect("git is a test prerequisite");
        assert!(output.status.success(), "{args:?}: {output:?}");
        String::from_utf8(output.stdout).unwrap().trim().to_string()
    }
    fn commit(&self, source: &str) -> String {
        let unit = format!("crates/ottto-service/src/{SYNTHETIC_UNIT}");
        std::fs::write(self.0.join(&unit), source).unwrap();
        self.git(&["add", &unit]);
        self.git(&["commit", "--quiet", "--allow-empty", "-m", "unit"]);
        self.git(&["rev-parse", "HEAD"])
    }
    fn verify(&self, sha: &str, archive: &str) -> Result<ArchiveReport, String> {
        let short = &sha[..8];
        let path = format!("snapshots/sampled_scan/archived_writers/w_{short}.rs");
        let inventory = format!("snapshots/sampled_scan/archived_writers/w_{short}_helpers.json");
        std::fs::create_dir_all(
            self.0
                .join("crates/ottto-service/src/snapshots/sampled_scan/archived_writers"),
        )
        .unwrap();
        verify_archive_in(
            sha,
            false,
            &[(path.as_str(), archive), (inventory.as_str(), "{}")],
            &self.0.join("crates/ottto-service/src"),
            Some(&self.0),
        )
    }
}
impl Drop for SyntheticRepo {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn archived_writer_git_mode_compares_the_named_commit() {
    let repo = SyntheticRepo::new();
    let pinned = synthetic_tokens_sha256();
    let frozen = repo.commit(SYNTHETIC_SOURCE);
    let report = repo.verify(&frozen, &synthetic_archive(&frozen, &pinned));
    assert_eq!(report.unwrap().archive, frozen);
    // Same archive text and pin, but this commit's source says otherwise.
    let drifted = repo.commit("fn b() {}");
    let error = refusal(repo.verify(&drifted, &synthetic_archive(&drifted, &pinned)));
    assert!(
        error.contains("archive region differs from its commit"),
        "{error}"
    );
}
