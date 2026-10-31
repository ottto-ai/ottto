//! Private ScanIndex storage component. The caller holds the existing checkpoint
//! flock throughout open, logical decode and legacy replacement. No acquisition authority
//! is conveyed by a storage digest or generation. Integration supplies the SAME
//! semantic serializer/lenient decoder and retains its baseline control view.
//!
//! Payloads are immutable JSON objects. A seekable logical JSON view splices their
//! interiors without decoding values or materializing the reconstructed index.
//! Candidate format constants/domains require SOURCE signoff before integration.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{self, BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::sync::Arc;

use anyhow::{bail, ensure, Context, Result};
use serde::de::{DeserializeSeed, Deserializer as _, IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub(crate) const OUTER_SCHEMA: u16 = 3;
pub(crate) const LOGICAL_SCHEMA: u16 = 2;
pub(crate) const STORAGE_FORMAT: u16 = 1;
pub(crate) const MAX_ROOT_BYTES: usize = 256 * 1024;
const MAX_OBJECTS: usize = 769;
const MAX_KEY_BYTES: usize = 16 * 1024;
const BUFFER_BYTES: usize = 32 * 1024;
const DOMAIN: &[u8] = b"ottto.scan-index.storage.v1\0";

/// Storage binding only. Use the existing destination/store namespace, never
/// release identity or the scratch directory used by a side harness.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Binding {
    pub source: Source,
    pub namespace_hash: String,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Source {
    Claude,
    Codex,
    Pi,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Field {
    AccountPending,
    UsagePending,
    RequestCensus,
}
impl Field {
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::AccountPending => "claude_account_family_pending",
            Self::UsagePending => "claude_usage_family_pending",
            Self::RequestCensus => "claude_request_census",
        }
    }
    fn tag(self) -> &'static str {
        match self {
            Self::AccountPending => "account",
            Self::UsagePending => "usage",
            Self::RequestCensus => "census",
        }
    }
    fn all() -> [Self; 3] {
        [
            Self::AccountPending,
            Self::UsagePending,
            Self::RequestCensus,
        ]
    }
}

/// Slot order is canonical; duplicate slots and empty bucket objects are refused.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(tag = "kind", deny_unknown_fields)]
pub(crate) enum Slot {
    #[serde(rename = "metadata")]
    Metadata,
    #[serde(rename = "bucket")]
    Bucket { field: Field, bucket: u8 },
}
impl Slot {
    fn label(self) -> String {
        match self {
            Self::Metadata => "metadata".into(),
            Self::Bucket { field, bucket } => format!("{}-{bucket:02x}", field.tag()),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Object {
    slot: Slot,
    #[serde(default)]
    generation: u64,
    bytes: u64,
    digest: String,
}
impl Object {
    fn same_payload(&self, other: &Self) -> bool {
        self.slot == other.slot && self.bytes == other.bytes && self.digest == other.digest
    }
    fn filename(&self) -> String {
        format!("{}-{}.json", self.slot.label(), self.digest)
    }
}

/// Strict bounded outer envelope. Only schema_version is interpreted by older
/// supported readers: it MUST yield `scan index refused: schema_version`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema_version: u16,
    // The pinned old header visitor requires this field BEFORE its schema
    // check. It is always empty and is NEVER the logical index's files map.
    files: BTreeMap<String, serde_json::Value>,
    storage_format: u16,
    logical_schema_version: u16,
    generation: u64,
    binding: Binding,
    padding_bytes: u64,
    #[serde(default)]
    maps: Vec<MapManifest>,
    objects: Vec<Object>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Stamp {
    dev: u64,
    ino: u64,
    bytes: u64,
    mtime: (i64, i64),
    ctime: (i64, i64),
}
impl Stamp {
    fn capture(file: &File, private: bool) -> Result<Self> {
        let m = file.metadata()?;
        ensure!(
            m.is_file() && m.uid() == unsafe { libc::geteuid() },
            "scan_index_unsafe_file"
        );
        ensure!(
            m.mode() & if private { 0o077 } else { 0o022 } == 0,
            "scan_index_unsafe_mode"
        );
        ensure!(m.nlink() == 1, "scan_index_aliased_file");
        Ok(Self {
            dev: m.dev(),
            ino: m.ino(),
            bytes: m.len(),
            mtime: (m.mtime(), m.mtime_nsec()),
            ctime: (m.ctime(), m.ctime_nsec()),
        })
    }
}

#[derive(Clone, Debug)]
enum Root {
    Missing,
    Unavailable {
        generation: u64,
    },
    Legacy {
        digest: String,
        generation: u64,
    },
    Sharded {
        digest: String,
        manifest: Manifest,
        stamps: Vec<Stamp>,
    },
}

/// Clone this with ScanIndex and selected subsets. No serialized field, retry
/// authority or receipt. The semantic integration must ALSO retain the exact
/// immutable baseline retry maxima and hold/repair provenance alongside this.
#[derive(Clone, Debug)]
pub(crate) struct LoadedRoot(Arc<Root>);
/// Opaque, in-process custody for a rebuild already authorized by the existing
/// LEGACY quarantine policy. Never minted for sharded/partial state or on load
/// of a missing root. Not a receipt and never persisted or inferred from names.
#[derive(Debug)]
pub(crate) struct LegacyRecovery {
    binding: Binding,
    root: String,
    quarantine: String,
    digest: String,
    spent: std::sync::atomic::AtomicBool,
}
impl LegacyRecovery {
    #[cfg_attr(
        test,
        allow(dead_code, reason = "the #[path] contract test crate does not call it")
    )]
    pub(crate) fn retained_bytes(&self) -> usize {
        self.binding.namespace_hash.capacity()
            + self.root.capacity()
            + self.quarantine.capacity()
            + self.digest.capacity()
    }
}

impl LoadedRoot {
    #[cfg_attr(
        test,
        allow(dead_code, reason = "the #[path] contract test crate does not call it")
    )]
    pub(crate) fn observed_missing() -> Self {
        Self(Arc::new(Root::Missing))
    }

    pub(crate) fn generation(&self) -> Option<u64> {
        match &*self.0 {
            Root::Sharded { manifest, .. } => Some(manifest.generation),
            Root::Legacy { generation, .. } | Root::Unavailable { generation } => Some(*generation),
            _ => None,
        }
    }
    #[cfg_attr(
        test,
        allow(dead_code, reason = "the #[path] contract test crate does not call it")
    )]
    pub(crate) fn unavailable(&self) -> Self {
        Self(Arc::new(Root::Unavailable {
            generation: self.generation().unwrap_or(0),
        }))
    }
    /// Conservative retained allocation charge, including shared Arc custody.
    /// At most 769 descriptors; never walks logical payload entries.
    #[cfg_attr(
        test,
        allow(dead_code, reason = "the #[path] contract test crate does not call it")
    )]
    pub(crate) fn retained_bytes(&self) -> Option<usize> {
        let mut n = std::mem::size_of::<Root>()
            + std::mem::align_of::<Root>()
            + 2 * std::mem::size_of::<usize>();
        let mut add = |bytes: usize| {
            n = n.checked_add(bytes)?;
            Some(())
        };
        match &*self.0 {
            Root::Legacy { digest, .. } => add(digest.capacity())?,
            Root::Sharded {
                digest,
                manifest,
                stamps,
            } => {
                add(digest.capacity())?;
                add(manifest.binding.namespace_hash.capacity())?;
                add(std::mem::align_of::<MapManifest>()
                    + std::mem::align_of::<Object>()
                    + std::mem::align_of::<Stamp>())?;
                add(manifest
                    .maps
                    .capacity()
                    .checked_mul(std::mem::size_of::<MapManifest>())?)?;
                for map in &manifest.maps {
                    add(map
                        .buckets
                        .capacity()
                        .checked_add(std::mem::align_of::<u8>())?)?;
                }
                add(manifest
                    .objects
                    .capacity()
                    .checked_mul(std::mem::size_of::<Object>())?)?;
                for object in &manifest.objects {
                    add(object.digest.capacity())?;
                }
                add(stamps
                    .capacity()
                    .checked_mul(std::mem::size_of::<Stamp>())?)?;
            }
            _ => {}
        }
        Some(n)
    }
    pub(crate) fn is_legacy(&self) -> bool {
        matches!(&*self.0, Root::Legacy { .. })
    }
}

/// All error text is low cardinality and contains no keys, paths or digests.
/// Storage errors never authorize quarantine, a fresh index, Full or fallback.
pub(crate) enum Opened {
    Missing(LoadedRoot),
    Legacy(File, LoadedRoot),
    Sharded(LogicalReader, LoadedRoot),
    Partial(PartialIndex, LoadedRoot),
}

/// A map is known only when its root inventory and EVERY referenced bucket
/// validate. Unknown carries no iterable entries and is never an empty map.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum UnavailableCause {
    Missing,
    Generation,
    Digest,
    Decode,
    Descriptor,
    Unsafe,
}
impl UnavailableCause {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Missing => "missing",
            Self::Generation => "generation",
            Self::Digest => "digest",
            Self::Decode => "decode",
            Self::Descriptor => "descriptor",
            Self::Unsafe => "unsafe",
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct MapUnavailable {
    pub map: Field,
    pub cause: UnavailableCause,
}
pub(crate) enum MapAvailability {
    Known(LogicalReader),
    Unknown(MapUnavailable),
}
/// Separate from a complete index: no implicit JSON/default/empty conversion.
/// Metadata and known siblings remain readable; unknown maps cannot authorize
/// retirement, release, fence opening, a legacy export or a new root commit.
pub(crate) struct PartialIndex {
    pub metadata: LogicalReader,
    pub maps: [MapAvailability; 3],
}
impl PartialIndex {
    /// Internal typed partial view: retain schema 3 and explicit availability.
    /// All known siblings share one decoder pass with metadata/held scopes.
    #[cfg_attr(
        test,
        allow(dead_code, reason = "the #[path] contract test crate does not call it")
    )]
    pub(crate) fn into_reader(self) -> Result<(LogicalReader, [Option<MapUnavailable>; 3])> {
        let mut reader = self.metadata;
        reader.spans.pop(); // final root brace
        let mut padding = 0;
        while matches!(reader.spans.last().map(|s| &s.piece), Some(Piece::Spaces)) {
            padding += reader.spans.pop().expect("padding span").len;
        }
        reader.length = reader.spans.iter().map(|s| s.len).sum();
        let mut unavailable = [None; 3];
        for (i, map) in self.maps.into_iter().enumerate() {
            match map {
                MapAvailability::Unknown(cause) => unavailable[i] = Some(cause),
                MapAvailability::Known(mut known) => {
                    known.spans.pop(); // final root brace
                    for span in known.spans.into_iter().skip(1) {
                        // own header
                        if !matches!(span.piece, Piece::Spaces) {
                            reader.push(span.len, span.piece)?;
                        }
                    }
                }
            }
        }
        reader.push(padding, Piece::Spaces)?;
        reader.push_bytes(b"}".to_vec())?;
        Ok((reader, unavailable))
    }
}
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct ReadStats {
    pub scanindex_orphan_init_discarded: u64,
    pub root_missing_reserved_only: u64,
    /// index_shard_unavailable{map,cause}, fixed low-cardinality axes only.
    pub index_shard_unavailable: [[u64; 6]; 3],
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct MapManifest {
    field: Field,
    generation: u64,
    buckets: Vec<u8>,
}

/// Existing checkpoint flock is a caller precondition. Directory handles and
/// openat/renameat/unlinkat constrain legacy replacement to this index root.
/// Ancestors are the existing trusted owned state tree, not provider paths.
pub(crate) struct LockedStore {
    parent: File,
    root_name: std::ffi::CString,
    objects_name: std::ffi::CString,
    binding: Binding,
    metadata_fields: &'static [&'static str],
    prior_root_seen: std::cell::Cell<bool>,
    authorized_legacy_replacement: std::cell::Cell<bool>,
    read_stats: std::cell::Cell<ReadStats>,
}

fn cstring(bytes: &[u8]) -> Result<std::ffi::CString> {
    std::ffi::CString::new(bytes).context("scan_index_invalid_component")
}
fn open_at(dir: &File, name: &std::ffi::CStr, flags: i32) -> io::Result<File> {
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
            0o600,
        )
    };
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(unsafe { File::from_raw_fd(fd) })
    }
}
fn rename_at(from: &File, a: &std::ffi::CStr, to: &File, b: &std::ffi::CStr) -> io::Result<()> {
    if unsafe { libc::renameat(from.as_raw_fd(), a.as_ptr(), to.as_raw_fd(), b.as_ptr()) } < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}
fn unlink_at(dir: &File, name: &std::ffi::CStr) -> io::Result<()> {
    if unsafe { libc::unlinkat(dir.as_raw_fd(), name.as_ptr(), 0) } < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}
fn check_directory(file: &File) -> Result<()> {
    let m = file.metadata()?;
    ensure!(
        m.is_dir() && m.uid() == unsafe { libc::geteuid() } && m.mode() & 0o077 == 0,
        "scan_index_unsafe_directory"
    );
    Ok(())
}
fn valid_digest(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn hex(bytes: impl AsRef<[u8]>) -> String {
    const HEX: &[u8] = b"0123456789abcdef";
    let mut text = String::with_capacity(bytes.as_ref().len() * 2);
    for b in bytes.as_ref() {
        text.push(HEX[(b >> 4) as usize] as char);
        text.push(HEX[(b & 15) as usize] as char);
    }
    text
}
fn root_digest(bytes: &[u8]) -> String {
    let mut hash = Sha256::new();
    hash.update(DOMAIN);
    hash.update(b"root\0");
    hash.update(bytes);
    hex(hash.finalize())
}

/// Bucket identity is deliberately storage-only and independent of field/value.
pub(crate) fn bucket_for(key: &str) -> u8 {
    let mut hash = Sha256::new();
    hash.update(DOMAIN);
    hash.update(b"bucket\0");
    hash.update(key.as_bytes());
    hash.finalize()[0]
}

struct HashWriter<W> {
    writer: W,
    hash: Sha256,
    bytes: u64,
}
impl<W: Write> HashWriter<W> {
    fn new(writer: W, binding: &Binding, slot: Slot) -> Result<Self> {
        let mut hash = Sha256::new();
        hash.update(DOMAIN);
        hash.update(b"object\0");
        hash.update(serde_json::to_vec(&(binding, slot))?);
        hash.update([0]);
        Ok(Self {
            writer,
            hash,
            bytes: 0,
        })
    }
    fn finish(mut self, slot: Slot) -> Object {
        self.hash.update(self.bytes.to_le_bytes());
        Object {
            slot,
            generation: 0,
            bytes: self.bytes,
            digest: hex(self.hash.finalize()),
        }
    }
}
impl<W: Write> Write for HashWriter<W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let n = self.writer.write(bytes)?;
        self.bytes = self
            .bytes
            .checked_add(n as u64)
            .ok_or_else(|| io::Error::other("scan_index_object_length"))?;
        self.hash.update(&bytes[..n]);
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
    }
}

// The probe is not a semantic decoder: it skips values and recognizes only the
// representation fence. Unknown versions refuse while visiting their header,
// before envelope size checks or ANY mutation. Arrays remain legacy-compatible.
struct Probe<'a>(&'a std::cell::Cell<bool>);
impl<'de> Visitor<'de> for Probe<'_> {
    type Value = (u16, u64);
    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("index representation header")
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> std::result::Result<(u16, u64), A::Error> {
        let schema = seq.next_element::<u16>()?.unwrap_or(LOGICAL_SCHEMA);
        if schema != LOGICAL_SCHEMA {
            return Err(serde::de::Error::custom(
                "scan_index_representation_refused",
            ));
        }
        let generation = seq.next_element::<u64>()?.unwrap_or(0);
        while seq.next_element::<IgnoredAny>()?.is_some() {}
        Ok((schema, generation))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> std::result::Result<(u16, u64), A::Error> {
        let mut schema = None;
        let mut storage = false;
        let mut generation = None;
        while let Some(key) = map.next_key::<String>()? {
            if key == "schema_version" {
                if schema.is_some() {
                    return Err(serde::de::Error::custom("scan_index_duplicate_header"));
                }
                let v: u16 = map.next_value()?;
                if v != LOGICAL_SCHEMA && v != OUTER_SCHEMA {
                    return Err(serde::de::Error::custom(
                        "scan_index_representation_refused",
                    ));
                }
                schema = Some(v);
                // New envelopes always put the fence first. Stop here so an
                // oversized/future root cannot force a corpus-sized parse.
                if v == OUTER_SCHEMA {
                    self.0.set(true);
                    return Err(serde::de::Error::custom("scan_index_header_complete"));
                }
            } else if key == "generation" {
                if generation.is_some() {
                    return Err(serde::de::Error::custom("scan_index_duplicate_header"));
                }
                generation = Some(map.next_value::<u64>()?);
            } else {
                storage |= key == "storage_format";
                map.next_value::<IgnoredAny>()?;
            }
        }
        if storage {
            return Err(serde::de::Error::custom("scan_index_bad_fence"));
        }
        Ok((schema.unwrap_or(LOGICAL_SCHEMA), generation.unwrap_or(0)))
    }
}

// Representation selection skips values lexically with a depth counter, not a
// depth-sized stack or serde recursion. Optional legacy census evidence can be
// arbitrarily deep; only the existing semantic decoder decides its admission.
fn storage_header(
    input: &mut impl std::io::BufRead,
    fenced: &std::cell::Cell<bool>,
) -> Result<(u16, u64)> {
    fn byte(input: &mut impl std::io::BufRead) -> Result<Option<u8>> {
        let value = input.fill_buf()?.first().copied();
        if value.is_some() {
            input.consume(1);
        }
        Ok(value)
    }
    fn ws(input: &mut impl std::io::BufRead) -> Result<Option<u8>> {
        loop {
            let value = input.fill_buf()?.first().copied();
            if value.is_some_and(|b| b.is_ascii_whitespace()) {
                input.consume(1);
            } else {
                return Ok(value);
            }
        }
    }
    // Only controls retain bytes, with a fixed numeric-token bound. All other
    // values, including strings and nested containers, use constant memory.
    fn value(input: &mut impl std::io::BufRead, control: bool) -> Result<Option<u64>> {
        ws(input)?;
        let mut depth = 0u64;
        let mut quoted = false;
        let mut escaped = false;
        let mut digits = [0u8; 32];
        let mut count = 0usize;
        let mut any = false;
        let mut trailing_space = false;
        let mut numeric_valid = true;
        loop {
            let next = input.fill_buf()?.first().copied();
            let Some(b) = next else {
                ensure!(!quoted && depth == 0, "scan_index_legacy_syntax");
                break;
            };
            if !quoted && depth == 0 && matches!(b, b',' | b'}' | b']') {
                break;
            }
            input.consume(1);
            any = true;
            if control {
                if b.is_ascii_whitespace() && !quoted && depth == 0 {
                    trailing_space = count > 0;
                } else {
                    numeric_valid &= !trailing_space;
                    if count < digits.len() {
                        digits[count] = b;
                    }
                    count = count.saturating_add(1);
                }
            }
            if quoted {
                if escaped {
                    escaped = false;
                } else if b == b'\\' {
                    escaped = true;
                } else if b == b'"' {
                    quoted = false;
                }
            } else {
                match b {
                    b'"' => quoted = true,
                    b'{' | b'[' => {
                        depth = depth.checked_add(1).context("scan_index_length_overflow")?
                    }
                    b'}' | b']' => {
                        depth = depth.checked_sub(1).context("scan_index_legacy_syntax")?
                    }
                    _ => {}
                }
            }
        }
        ensure!(any, "scan_index_legacy_syntax");
        if !control || !numeric_valid || count > digits.len() {
            return Ok(None);
        }
        Ok(std::str::from_utf8(&digits[..count])
            .ok()
            .and_then(|s| s.trim().parse().ok()))
    }
    match ws(input)? {
        Some(b'[') => {
            input.consume(1);
            let schema = value(input, true)?.unwrap_or(u64::from(LOGICAL_SCHEMA));
            ensure!(
                schema == u64::from(LOGICAL_SCHEMA),
                "scan_index_representation_refused"
            );
            let generation = if ws(input)? == Some(b',') {
                input.consume(1);
                value(input, true)?.unwrap_or(0)
            } else {
                0
            };
            Ok((LOGICAL_SCHEMA, generation))
        }
        Some(b'{') => {
            input.consume(1);
            let mut generation = 0;
            let mut schema = None;
            let mut storage = false;
            loop {
                if ws(input)? == Some(b'}') {
                    ensure!(!storage, "scan_index_bad_fence");
                    return Ok((LOGICAL_SCHEMA, generation));
                }
                ensure!(byte(input)? == Some(b'"'), "scan_index_legacy_syntax");
                let mut key = vec![b'"'];
                let mut escaped = false;
                loop {
                    let b = byte(input)?.context("scan_index_legacy_syntax")?;
                    ensure!(key.len() < MAX_KEY_BYTES * 6 + 2, "scan_index_key_size");
                    key.push(b);
                    if escaped {
                        escaped = false;
                    } else if b == b'\\' {
                        escaped = true;
                    } else if b == b'"' {
                        break;
                    }
                }
                let key: String = serde_json::from_slice(&key)
                    .map_err(|_| anyhow::anyhow!("scan_index_legacy_syntax"))?;
                ensure!(key.len() <= MAX_KEY_BYTES, "scan_index_key_size");
                // Retain this evidence even if its value or a later member is
                // truncated: syntax fallback must never erase a storage fence.
                if key == "storage_format" {
                    fenced.set(true);
                }
                ws(input)?;
                ensure!(byte(input)? == Some(b':'), "scan_index_legacy_syntax");
                let number = value(
                    input,
                    matches!(key.as_str(), "schema_version" | "generation"),
                )?;
                if key == "schema_version" {
                    ensure!(schema.is_none(), "scan_index_duplicate_header");
                    schema = number;
                    if number == Some(u64::from(OUTER_SCHEMA)) {
                        return Ok((OUTER_SCHEMA, generation));
                    }
                    if let Some(number) = number {
                        ensure!(
                            number == u64::from(LOGICAL_SCHEMA),
                            "scan_index_representation_refused"
                        );
                    }
                } else if key == "generation" {
                    generation = number.unwrap_or(0);
                } else if key == "storage_format" {
                    storage = true;
                }
                match ws(input)? {
                    Some(b',') => {
                        input.consume(1);
                    }
                    Some(b'}') => {
                        ensure!(!storage, "scan_index_bad_fence");
                        return Ok((LOGICAL_SCHEMA, generation));
                    }
                    _ => bail!("scan_index_legacy_syntax"),
                }
            }
        }
        _ => bail!("scan_index_legacy_syntax"),
    }
}

impl LockedStore {
    pub(crate) fn new(
        path: &Path,
        binding: Binding,
        metadata_fields: &'static [&'static str],
    ) -> Result<Self> {
        ensure!(valid_digest(&binding.namespace_hash), "scan_index_binding");
        let parent_path = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let parent_c = cstring(parent_path.as_os_str().as_bytes())?;
        let fd = unsafe {
            libc::open(
                parent_c.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        ensure!(fd >= 0, "scan_index_parent_open");
        let parent = unsafe { File::from_raw_fd(fd) };
        let metadata = parent.metadata()?;
        ensure!(
            metadata.is_dir()
                && metadata.uid() == unsafe { libc::geteuid() }
                && metadata.mode() & 0o022 == 0,
            "scan_index_unsafe_parent"
        );
        let root = path.file_name().context("scan_index_root_name")?.as_bytes();
        let root_name = cstring(root)?;
        let mut object_name = root.to_vec();
        object_name.extend_from_slice(b".shards");
        Ok(Self {
            parent,
            root_name,
            objects_name: cstring(&object_name)?,
            binding,
            metadata_fields,
            prior_root_seen: std::cell::Cell::new(false),
            authorized_legacy_replacement: std::cell::Cell::new(false),
            read_stats: std::cell::Cell::new(ReadStats::default()),
        })
    }
    fn directory(&self) -> Result<File> {
        let dir = open_at(
            &self.parent,
            &self.objects_name,
            libc::O_RDONLY | libc::O_DIRECTORY,
        )?;
        check_directory(&dir)?;
        Ok(dir)
    }
    fn payload_directory(&self) -> Result<File> {
        self.directory()
    }
    fn current(&self) -> Result<(Option<File>, Root)> {
        let mut file = match open_at(&self.parent, &self.root_name, libc::O_RDONLY) {
            Ok(file) => {
                self.prior_root_seen.set(true);
                file
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                match self.directory() {
                    Ok(dir) => {
                        self.refuse_reserved_without_root(&dir)?;
                        ensure!(
                            self.authorized_legacy_replacement.get(),
                            "scan_index_root_missing_with_shards"
                        );
                    }
                    Err(e)
                        if e.downcast_ref::<io::Error>()
                            .is_some_and(|e| e.kind() == io::ErrorKind::NotFound) => {}
                    Err(_) => bail!("scan_index_storage_requires_repair"),
                }
                return Ok((None, Root::Missing));
            }
            Err(e) => return Err(e.into()),
        };
        let before = Stamp::capture(&file, false)?;
        let fenced = std::cell::Cell::new(false);
        let (schema, generation) = match storage_header(
            &mut BufReader::with_capacity(BUFFER_BYTES, &mut file),
            &fenced,
        ) {
            Ok(header) => header,
            Err(error) if error.to_string() == "scan_index_legacy_syntax" => {
                ensure!(!fenced.get(), "scan_index_bad_fence");
                // Preserve the original legacy decoder's Syntax/HoldBudget
                // quarantine decision. Existing shard state instead fails
                // closed: a damaged envelope must never become a fresh index.
                match self.directory() {
                    Ok(_) => bail!("scan_index_manifest_refused"),
                    Err(e)
                        if e.downcast_ref::<io::Error>()
                            .is_some_and(|e| e.kind() == io::ErrorKind::NotFound) =>
                    {
                        (LOGICAL_SCHEMA, 0)
                    }
                    Err(_) => bail!("scan_index_storage_requires_repair"),
                }
            }
            Err(error) => return Err(error),
        };
        file.seek(SeekFrom::Start(0))?;
        let root = if schema == OUTER_SCHEMA {
            Stamp::capture(&file, true)?;
            ensure!(
                before.bytes <= MAX_ROOT_BYTES as u64,
                "scan_index_root_size"
            );
            let mut bytes = Vec::with_capacity(before.bytes as usize);
            (&mut file)
                .take(MAX_ROOT_BYTES as u64 + 1)
                .read_to_end(&mut bytes)?;
            ensure!(bytes.len() <= MAX_ROOT_BYTES, "scan_index_root_size");
            let manifest: Manifest = serde_json::from_slice(&bytes)
                .map_err(|_| anyhow::anyhow!("scan_index_manifest_refused"))?;
            self.validate_manifest(&manifest)?;
            Root::Sharded {
                digest: root_digest(&bytes),
                manifest,
                stamps: Vec::new(),
            }
        } else {
            let mut hash = Sha256::new();
            hash.update(DOMAIN);
            hash.update(b"legacy\0");
            let mut scratch = [0; BUFFER_BYTES];
            loop {
                let n = file.read(&mut scratch)?;
                if n == 0 {
                    break;
                }
                hash.update(&scratch[..n]);
            }
            Root::Legacy {
                digest: hex(hash.finalize()),
                generation,
            }
        };
        ensure!(
            before == Stamp::capture(&file, false)?,
            "scan_index_root_changed"
        );
        file.seek(SeekFrom::Start(0))?;
        Ok((Some(file), root))
    }
    fn validate_manifest(&self, manifest: &Manifest) -> Result<()> {
        ensure!(
            manifest.schema_version == OUTER_SCHEMA
                && manifest.storage_format == STORAGE_FORMAT
                && manifest.logical_schema_version == LOGICAL_SCHEMA,
            "scan_index_representation_refused"
        );
        ensure!(manifest.files.is_empty(), "scan_index_compatibility_fence");
        ensure!(manifest.binding == self.binding, "scan_index_binding");
        ensure!(
            !manifest.objects.is_empty() && manifest.objects.len() <= MAX_OBJECTS,
            "scan_index_descriptor_count"
        );
        ensure!(
            manifest.objects[0].slot == Slot::Metadata,
            "scan_index_metadata_missing"
        );
        ensure!(
            manifest.objects.windows(2).all(|p| p[0].slot < p[1].slot),
            "scan_index_duplicate_or_unordered_slot"
        );
        let mut total = 0u64;
        ensure!(manifest.maps.len() <= 3, "scan_index_map_count");
        for object in &manifest.objects {
            if matches!(object.slot, Slot::Metadata) {
                ensure!(
                    valid_digest(&object.digest) && object.bytes >= 2,
                    "scan_index_metadata_descriptor"
                );
            }
            total = total
                .checked_add(object.bytes)
                .context("scan_index_length_overflow")?;
        }
        ensure!(manifest.padding_bytes <= total, "scan_index_padding_size");
        ensure!(
            total
                .checked_add(manifest.padding_bytes)
                .is_some_and(|n| n <= i64::MAX as u64 - MAX_ROOT_BYTES as u64),
            "scan_index_length_overflow"
        );
        Ok(())
    }
    fn validate_object(&self, dir: &File, object: &Object) -> Result<Stamp> {
        let mut file = open_at(dir, &cstring(object.filename().as_bytes())?, libc::O_RDONLY)?;
        let before = Stamp::capture(&file, true)?;
        let mut boundary = [0u8; 1];
        file.read_exact(&mut boundary)?;
        ensure!(boundary == [b'{'], "scan_index_fragment_boundary");
        file.seek(SeekFrom::End(-1))?;
        file.read_exact(&mut boundary)?;
        ensure!(boundary == [b'}'], "scan_index_fragment_boundary");
        file.seek(SeekFrom::Start(0))?;
        ensure!(before.bytes == object.bytes, "scan_index_object_length");
        let mut hash = HashWriter::new(io::sink(), &self.binding, object.slot)?;
        let mut scratch = [0; BUFFER_BYTES];
        loop {
            let n = file.read(&mut scratch)?;
            if n == 0 {
                break;
            }
            hash.write_all(&scratch[..n])?;
        }
        ensure!(
            hash.finish(object.slot).same_payload(object),
            "scan_index_object_integrity"
        );
        file.seek(SeekFrom::Start(0))?;
        let mut decoder = serde_json::Deserializer::from_reader(BufReader::with_capacity(
            BUFFER_BYTES,
            KeyGuard::new(&mut file),
        ));
        let count = ObjectKeys {
            slot: object.slot,
            fields: self.metadata_fields,
        }
        .deserialize(&mut decoder)
        .context("scan_index_object_structure")?;
        decoder.end()?;
        ensure!(
            matches!(object.slot, Slot::Metadata) || count > 0,
            "scan_index_empty_bucket"
        );
        ensure!(
            before == Stamp::capture(&file, true)?,
            "scan_index_object_changed"
        );
        Ok(before)
    }
    #[cfg(test)]
    pub(crate) fn open(&self) -> Result<Opened> {
        self.open_structural()
    }
    // Internal reconciliation of a just-serialized publication. Production
    // LOAD callers must supply their semantic decoder through the checked API.
    fn open_structural(&self) -> Result<Opened> {
        self.open_with_map_validator(&mut |_, _| Ok(()))
    }
    /// Integration supplies the EXISTING semantic map codec. A semantic failure
    /// becomes Unknown for that map, never a defaulted/empty decoded container.
    pub(crate) fn open_with_map_validator(
        &self,
        validate: &mut impl FnMut(Field, &mut LogicalReader) -> Result<()>,
    ) -> Result<Opened> {
        self.recover_fresh_init()?;
        // Retain root-presence evidence BEFORE any fallible representation or
        // payload validation, including a missing/corrupt metadata object.
        match open_at(&self.parent, &self.root_name, libc::O_RDONLY) {
            Ok(file) => {
                Stamp::capture(&file, false)?;
                self.note_prior_root()?;
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        self.open_read_only_with_map_validator(validate)
    }

    /// Inspect an immutable published representation without a checkpoint lock.
    /// Never recover initialization, create a prior-root marker or repair state.
    /// Missing/in-progress storage refuses through current() rather than being
    /// converted into a fresh index.
    pub(crate) fn open_read_only_with_map_validator(
        &self,
        validate: &mut impl FnMut(Field, &mut LogicalReader) -> Result<()>,
    ) -> Result<Opened> {
        let (file, mut root) = self.current()?;
        match &mut root {
            Root::Missing => Ok(Opened::Missing(LoadedRoot(Arc::new(root)))),
            Root::Legacy { .. } => Ok(Opened::Legacy(
                file.context("scan_index_missing_file")?,
                LoadedRoot(Arc::new(root)),
            )),
            Root::Unavailable { .. } => bail!("scan_index_internal_partial"),
            Root::Sharded {
                manifest, stamps, ..
            } => {
                let dir = self.payload_directory()?;
                let meta = &manifest.objects[0];
                ensure!(
                    meta.generation == manifest.generation,
                    "scan_index_metadata_generation"
                );
                let meta_stamp = self.validate_object(&dir, meta)?;
                let mut verified = manifest.clone();
                verified.objects = vec![meta.clone()];
                let mut verified_stamps = vec![meta_stamp];
                let mut unknown = [None; 3];
                for (map_index, field) in Field::all().into_iter().enumerate() {
                    let inventories: Vec<_> =
                        manifest.maps.iter().filter(|m| m.field == field).collect();
                    let objects: Vec<_> = manifest
                        .objects
                        .iter()
                        .filter(|o| matches!(o.slot, Slot::Bucket { field:f,.. } if f == field))
                        .collect();
                    let declared = inventories.first().copied();
                    let cause = if inventories.len() != 1 {
                        Some(UnavailableCause::Descriptor)
                    } else if declared.is_some_and(|m| m.generation != manifest.generation) {
                        Some(UnavailableCause::Generation)
                    } else if declared.is_some_and(|m| {
                        m.buckets.len() != objects.len()
                            || !m.buckets.windows(2).all(|p| p[0] < p[1])
                            || m.buckets.iter().zip(&objects).any(
                                |(b, o)| !matches!(o.slot,Slot::Bucket {bucket,..} if bucket == *b),
                            )
                    }) {
                        Some(UnavailableCause::Descriptor)
                    } else {
                        None
                    };
                    unknown[map_index] = cause;
                    if cause.is_some() {
                        continue;
                    }
                    for object in objects {
                        let cause = if object.generation != manifest.generation {
                            Some(UnavailableCause::Generation)
                        } else if !valid_digest(&object.digest) {
                            Some(UnavailableCause::Digest)
                        } else if object.bytes < 2 {
                            Some(UnavailableCause::Descriptor)
                        } else {
                            None
                        };
                        if let Some(cause) = cause {
                            unknown[map_index] = Some(cause);
                            break;
                        }
                        match self.validate_object(&dir, object) {
                            Ok(stamp) => {
                                verified.objects.push(object.clone());
                                verified_stamps.push(stamp);
                            }
                            Err(error) => {
                                let cause = if error
                                    .downcast_ref::<io::Error>()
                                    .is_some_and(|e| e.kind() == io::ErrorKind::NotFound)
                                {
                                    UnavailableCause::Missing
                                } else if error.to_string().contains("integrity")
                                    || error.to_string().contains("length")
                                {
                                    UnavailableCause::Digest
                                } else if error.to_string().contains("unsafe")
                                    || error.to_string().contains("aliased")
                                {
                                    UnavailableCause::Unsafe
                                } else {
                                    UnavailableCause::Decode
                                };
                                unknown[map_index] = Some(cause);
                                break;
                            }
                        }
                    }
                }
                for (i, field) in Field::all().into_iter().enumerate() {
                    if unknown[i].is_none() {
                        let mut view = LogicalReader::selected(
                            dir.try_clone()?,
                            &verified,
                            &verified_stamps,
                            false,
                            &[field],
                        )?;
                        if validate(field, &mut view).is_err() {
                            unknown[i] = Some(UnavailableCause::Decode);
                        }
                    }
                }
                if unknown.iter().any(Option::is_some) {
                    let mut stats = self.read_stats.get();
                    for (i, cause) in unknown.iter().enumerate() {
                        if let Some(cause) = cause {
                            stats.index_shard_unavailable[i][*cause as usize] =
                                stats.index_shard_unavailable[i][*cause as usize].saturating_add(1);
                        }
                    }
                    self.read_stats.set(stats);
                    let metadata = LogicalReader::selected(
                        dir.try_clone()?,
                        &verified,
                        &verified_stamps,
                        true,
                        &[],
                    )?;
                    let mut maps = Vec::with_capacity(3);
                    for (i, field) in Field::all().into_iter().enumerate() {
                        maps.push(if let Some(cause) = unknown[i] {
                            MapAvailability::Unknown(MapUnavailable { map: field, cause })
                        } else {
                            MapAvailability::Known(LogicalReader::selected(
                                dir.try_clone()?,
                                &verified,
                                &verified_stamps,
                                false,
                                &[field],
                            )?)
                        });
                    }
                    let generation = manifest.generation;
                    return Ok(Opened::Partial(
                        PartialIndex {
                            metadata,
                            maps: maps
                                .try_into()
                                .map_err(|_| anyhow::anyhow!("scan_index_internal_maps"))?,
                        },
                        LoadedRoot(Arc::new(Root::Unavailable { generation })),
                    ));
                }
                *stamps = verified_stamps;
                let view = LogicalReader::new(dir, manifest, stamps)?;
                Ok(Opened::Sharded(view, LoadedRoot(Arc::new(root))))
            }
        }
    }

    /// An observed fresh load may write progress during its first sync pass.
    /// Keep that custody through publication, but reject ANY intervening root/
    /// quarantine witness. This check does not discard files or infer freshness.
    fn check_initial_cas(&self) -> Result<()> {
        if self.authorized_legacy_replacement.get() {
            return Ok(());
        }
        ensure!(
            !self.prior_root_seen.get(),
            "scan_index_prior_state_requires_repair"
        );
        let root = self.root_name.to_str()?;
        let stem = root.strip_suffix(".json").unwrap_or(root);
        let family = stem.strip_suffix("-v2").unwrap_or(stem);
        let temp_prefix = format!("{root}.storage-tmp-");
        visit_storage_directory(&self.parent, |name| {
            let text = name
                .to_str()
                .map_err(|_| anyhow::anyhow!("scan_index_prior_state_unknown"))?;
            if text.starts_with(family) {
                if text == format!("{stem}-upload-progress.lock")
                    || text == format!("{stem}-upload-progress.json")
                    || text == format!("{root}.lock")
                    || text == format!("{stem}.lock")
                {
                    Stamp::capture(&open_at(&self.parent, name, libc::O_RDONLY)?, false)?;
                } else if text.strip_prefix(&temp_prefix).is_some_and(|suffix| {
                    suffix.len() == 32 && suffix.bytes().all(|b| b.is_ascii_hexdigit())
                }) {
                    Stamp::capture(&open_at(&self.parent, name, libc::O_RDONLY)?, true)?;
                } else {
                    bail!("scan_index_prior_state_requires_repair");
                }
            }
            Ok(())
        })
    }

    /// Bounded manifest-only CAS on an already loaded sharded baseline. No old
    /// logical decode. Legacy callers still perform their original full CAS.
    pub(crate) fn compare(&self, expected: &LoadedRoot) -> Result<()> {
        ensure!(
            !matches!(&*expected.0, Root::Unavailable { .. }),
            "scan_index_unknown_maps_require_repair"
        );
        let (_, current) = self.current()?;
        let same = match (&*expected.0, &current) {
            (Root::Missing, Root::Missing) => {
                self.check_initial_cas()?;
                true
            }
            (Root::Legacy { digest: a, .. }, Root::Legacy { digest: b, .. }) => a == b,
            (
                Root::Sharded {
                    digest: a,
                    manifest: x,
                    ..
                },
                Root::Sharded {
                    digest: b,
                    manifest: y,
                    ..
                },
            ) => a == b && x.generation == y.generation,
            _ => false,
        };
        ensure!(same, "local snapshot scan index changed concurrently");
        Ok(())
    }

    #[cfg_attr(
        test,
        allow(dead_code, reason = "the #[path] contract test crate does not call it")
    )]
    pub(crate) fn legacy_recovery(&self, quarantine: &str) -> Result<Arc<LegacyRecovery>> {
        ensure!(
            quarantine.len() <= MAX_KEY_BYTES
                && !quarantine.contains('/')
                && quarantine != "."
                && quarantine != "..",
            "scan_index_legacy_recovery_refused"
        );
        let (_, root) = self.current()?;
        let Root::Legacy { digest, .. } = root else {
            bail!("scan_index_legacy_recovery_refused");
        };
        Ok(Arc::new(LegacyRecovery {
            binding: self.binding.clone(),
            root: self.root_name.to_str()?.into(),
            quarantine: quarantine.into(),
            digest,
            spent: std::sync::atomic::AtomicBool::new(false),
        }))
    }
    #[cfg_attr(
        test,
        allow(dead_code, reason = "the #[path] contract test crate does not call it")
    )]
    pub(crate) fn write_recovered_legacy(
        &self,
        recovery: &LegacyRecovery,
        generation: u64,
        encode: impl FnOnce(&mut dyn Write) -> Result<()>,
    ) -> Result<LoadedRoot> {
        ensure!(
            recovery.binding == self.binding
                && recovery.root.as_bytes() == self.root_name.to_bytes(),
            "scan_index_legacy_recovery_refused"
        );
        // Verify the exact preserved legacy witness, not merely a sibling name
        // or matching generation, before granting the missing-root replacement.
        let mut file = open_at(
            &self.parent,
            &cstring(recovery.quarantine.as_bytes())?,
            libc::O_RDONLY,
        )?;
        let before = Stamp::capture(&file, false)?;
        let mut hash = Sha256::new();
        hash.update(DOMAIN);
        hash.update(b"legacy\0");
        let mut scratch = [0; BUFFER_BYTES];
        loop {
            let n = file.read(&mut scratch)?;
            if n == 0 {
                break;
            }
            hash.update(&scratch[..n]);
        }
        ensure!(
            before == Stamp::capture(&file, false)? && hex(hash.finalize()) == recovery.digest,
            "scan_index_legacy_recovery_refused"
        );
        struct Reset<'a>(&'a std::cell::Cell<bool>);
        impl Drop for Reset<'_> {
            fn drop(&mut self) {
                self.0.set(false);
            }
        }
        ensure!(
            recovery
                .spent
                .compare_exchange(
                    false,
                    true,
                    std::sync::atomic::Ordering::AcqRel,
                    std::sync::atomic::Ordering::Acquire
                )
                .is_ok(),
            "scan_index_legacy_recovery_spent"
        );
        self.authorized_legacy_replacement.set(true);
        let _reset = Reset(&self.authorized_legacy_replacement);
        let result = self.write_legacy(&LoadedRoot(Arc::new(Root::Missing)), generation, encode);
        if result
            .as_ref()
            .is_err_and(|error| error.downcast_ref::<CommitPublished>().is_none())
            && !self.prior_root_seen.get()
            && matches!(open_at(&self.parent, &self.root_name, libc::O_RDONLY), Err(error) if error.kind() == io::ErrorKind::NotFound)
        {
            recovery
                .spent
                .store(false, std::sync::atomic::Ordering::Release);
        }
        result
    }

    /// Release N always writes the existing legacy format, including after a
    /// sharded load. Caller retains the existing normalization, semantic CAS,
    /// retry-claim merge and held-output checks. No new logical field table.
    pub(crate) fn write_legacy(
        &self,
        expected: &LoadedRoot,
        generation: u64,
        encode: impl FnOnce(&mut dyn Write) -> Result<()>,
    ) -> Result<LoadedRoot> {
        self.compare(expected)?;
        ensure!(
            expected.generation().unwrap_or(0).checked_add(1) == Some(generation),
            "scan_index_generation"
        );
        let mut prefix = self.root_name.to_bytes().to_vec();
        prefix.extend_from_slice(b".storage-tmp-");
        let temp = Temp::with_prefix(&self.parent, &prefix)?;
        {
            let mut output = BufWriter::with_capacity(BUFFER_BYTES, &temp.file);
            encode(&mut output)?;
            output.flush()?;
        }
        temp.file.sync_all()?;
        // The encoder's output must be legacy JSON at the promised generation.
        // Validate the control header using a temporary read handle; semantic
        // field/hold checks remain the existing serializer's responsibility.
        let mut candidate = open_at(&self.parent, &temp.name, libc::O_RDONLY)?;
        let header = serde_json::Deserializer::from_reader(BufReader::new(KeyGuard::headers(
            &mut candidate,
        )))
        .deserialize_any(Probe(&std::cell::Cell::new(false)))
        .map_err(|_| anyhow::anyhow!("scan_index_legacy_output_refused"))?;
        ensure!(
            header == (LOGICAL_SCHEMA, generation),
            "scan_index_legacy_output_refused"
        );
        self.compare(expected)?;
        rename_at(&self.parent, &temp.name, &self.parent, &self.root_name)?;
        let result = (|| -> Result<LoadedRoot> {
            self.note_prior_root()?;
            self.parent.sync_all()?;
            match self.open_structural()? {
                Opened::Legacy(_, root) if root.generation() == Some(generation) => Ok(root),
                _ => bail!("scan_index_legacy_output_refused"),
            }
        })();
        result.map_err(|_| {
            CommitPublished {
                generation,
                verified: false,
            }
            .into()
        })
    }
}

struct Temp<'a> {
    directory: &'a File,
    name: std::ffi::CString,
    file: File,
}
impl<'a> Temp<'a> {
    fn with_prefix(directory: &'a File, prefix: &[u8]) -> Result<Self> {
        let mut random = [0; 16];
        getrandom::fill(&mut random).map_err(|_| anyhow::anyhow!("scan_index_temp_random"))?;
        let mut name = prefix.to_vec();
        name.extend_from_slice(hex(random).as_bytes());
        let name = cstring(&name)?;
        let file = open_at(
            directory,
            &name,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
        )?;
        Ok(Self {
            directory,
            name,
            file,
        })
    }
}
impl Drop for Temp<'_> {
    fn drop(&mut self) {
        let _ = unlink_at(self.directory, &self.name);
    }
}

#[derive(Debug, thiserror::Error)]
#[error("scan_index_commit_published generation={generation} verified={verified}; reload before effects")]
pub(crate) struct CommitPublished {
    pub generation: u64,
    pub verified: bool,
}
/// tracks JSON punctuation and string escapes for resource admission.
struct KeyGuard<R> {
    inner: R,
    stack: Vec<(bool, bool)>, // object / expecting key
    string: bool,
    escaped: bool,
    key: bool,
    key_bytes: usize,
    headers: bool,
    header_key: [u8; 128],
    header_key_len: usize,
    control_value: bool,
    array_position: usize,
}
impl<R: Read> KeyGuard<R> {
    fn new(inner: R) -> Self {
        Self {
            inner,
            stack: Vec::with_capacity(256),
            string: false,
            escaped: false,
            key: false,
            key_bytes: 0,
            headers: false,
            header_key: [0; 128],
            header_key_len: 0,
            control_value: false,
            array_position: 0,
        }
    }
    fn headers(inner: R) -> Self {
        Self {
            headers: true,
            ..Self::new(inner)
        }
    }
}
impl<R: Read> Read for KeyGuard<R> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(output)?;
        for byte in &output[..n] {
            if self.string {
                if self.headers
                    && self.key
                    && self.stack.len() == 1
                    && self.header_key_len < self.header_key.len()
                {
                    self.header_key[self.header_key_len] = *byte;
                    self.header_key_len += 1;
                }
                if self.key {
                    self.key_bytes += 1;
                    if self.key_bytes > MAX_KEY_BYTES * 6 + 1 {
                        return Err(io::Error::other("scan_index_key_size"));
                    }
                }
                if self.escaped {
                    self.escaped = false;
                } else if *byte == b'\\' {
                    self.escaped = true;
                } else if *byte == b'"' {
                    self.string = false;
                    if self.headers && self.key && self.stack.len() == 1 {
                        // Control names are at most 14 decoded bytes (86 raw
                        // bytes with escapes). Capture is fixed-size; no value
                        // strings are allocated by this lexical guard.
                        let key = serde_json::from_slice::<String>(
                            &self.header_key[..self.header_key_len],
                        );
                        self.control_value =
                            matches!(key.as_deref(), Ok("schema_version" | "generation"));
                    }
                }
            } else {
                match byte {
                    b'"' => {
                        self.string = true;
                        self.escaped = false;
                        self.key = self
                            .stack
                            .last()
                            .is_some_and(|(object, key)| *object && *key);
                        self.key_bytes = 0;
                        if self.key && self.stack.len() == 1 {
                            self.header_key[0] = b'"';
                            self.header_key_len = 1;
                        } else if self.headers
                            && (self.stack.is_empty()
                                || (self.stack.len() == 1
                                    && (self.control_value
                                        || (!self.stack[0].0 && self.array_position < 2))))
                        {
                            // Headers are integers. Refuse a string BEFORE
                            // serde can allocate its invalid-type diagnostic.
                            return Err(io::Error::other("scan_index_header_type"));
                        }
                    }
                    b'{' | b'[' => {
                        if self.stack.len() >= 256 {
                            return Err(io::Error::other("scan_index_json_depth"));
                        }
                        self.stack.push((*byte == b'{', *byte == b'{'));
                    }
                    b'}' | b']' => {
                        self.stack.pop();
                    }
                    b':' => {
                        if let Some(state) = self.stack.last_mut() {
                            state.1 = false;
                        }
                    }
                    b',' => {
                        if self.stack.len() == 1 && !self.stack[0].0 {
                            self.array_position = self.array_position.saturating_add(1);
                        }
                        if let Some(state) = self.stack.last_mut() {
                            state.1 = state.0;
                        }
                    }
                    _ => {}
                }
            }
        }
        Ok(n)
    }
}

struct ObjectKeys {
    slot: Slot,
    fields: &'static [&'static str],
}
impl<'de> DeserializeSeed<'de> for ObjectKeys {
    type Value = usize;
    fn deserialize<D: serde::Deserializer<'de>>(
        self,
        decoder: D,
    ) -> std::result::Result<usize, D::Error> {
        decoder.deserialize_map(self)
    }
}
impl<'de> Visitor<'de> for ObjectKeys {
    type Value = usize;
    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("fragment object")
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> std::result::Result<usize, A::Error> {
        let mut previous: Option<String> = None;
        let mut names = BTreeSet::new();
        let mut count = 0;
        while let Some(key) = map.next_key::<String>()? {
            if key.len() > MAX_KEY_BYTES {
                return Err(serde::de::Error::custom("scan_index_key_size"));
            }
            let valid = match self.slot {
                Slot::Metadata => {
                    self.fields.contains(&key.as_str())
                        && key != "schema_version"
                        && key != "generation"
                        && !Field::all().iter().any(|f| f.name() == key)
                        && names.insert(key.clone())
                }
                Slot::Bucket { bucket, .. } => {
                    bucket_for(&key) == bucket && previous.as_ref().map_or(true, |p| p < &key)
                }
            };
            if !valid {
                return Err(serde::de::Error::custom("scan_index_fragment_key"));
            }
            map.next_value::<IgnoredAny>()?;
            previous = Some(key);
            count += 1;
        }
        Ok(count)
    }
}

/// Logical fragments hold at most ONE payload FD open. The owner wraps this in
/// BufReader and uses the existing BufRead+Seek lenient decoder globally.
enum Piece {
    Bytes(Vec<u8>),
    Spaces,
    Object { object: Object, stamp: Stamp },
}
struct Span {
    start: u64,
    len: u64,
    piece: Piece,
}
pub(crate) struct LogicalReader {
    directory: File,
    spans: Vec<Span>,
    position: u64,
    length: u64,
    opened: Option<(usize, File)>,
}
impl LogicalReader {
    fn new(directory: File, manifest: &Manifest, stamps: &[Stamp]) -> Result<Self> {
        Self::selected(directory, manifest, stamps, true, &Field::all())
    }
    fn selected(
        directory: File,
        manifest: &Manifest,
        stamps: &[Stamp],
        metadata: bool,
        fields: &[Field],
    ) -> Result<Self> {
        let mut reader = Self {
            directory,
            spans: Vec::with_capacity(MAX_OBJECTS * 2 + 10),
            position: 0,
            length: 0,
            opened: None,
        };
        reader.push_bytes(
            format!(
                "{{\"schema_version\":{},\"generation\":{}",
                if metadata && fields.is_empty() {
                    OUTER_SCHEMA
                } else {
                    manifest.logical_schema_version
                },
                manifest.generation
            )
            .into_bytes(),
        )?;
        if metadata {
            let metadata = &manifest.objects[0];
            // '{}' metadata can be empty. Whitespace-only interiors are legal too;
            // count keys instead of deciding from byte length at view construction.
            let file = open_at(
                &reader.directory,
                &cstring(metadata.filename().as_bytes())?,
                libc::O_RDONLY,
            )?;
            let mut decoder =
                serde_json::Deserializer::from_reader(BufReader::new(KeyGuard::new(file)));
            // Integrity/field validation already completed. This bounded key count
            // streams metadata without decoding its values or duplicating schema.
            let count = decoder.deserialize_map(KeyCount)?;
            if count > 0 {
                reader.push_bytes(b",".to_vec())?;
                reader.object(metadata, &stamps[0])?;
            }
        }
        for field in fields.iter().copied() {
            reader.push_bytes(format!(",\"{}\":{{", field.name()).into_bytes())?;
            let mut first = true;
            for (i, object) in manifest.objects.iter().enumerate() {
                if matches!(object.slot, Slot::Bucket { field: f, .. } if f == field) {
                    if !first {
                        reader.push_bytes(b",".to_vec())?;
                    }
                    reader.object(object, &stamps[i])?;
                    first = false;
                }
            }
            reader.push_bytes(b"}".to_vec())?;
        }
        reader.push(manifest.padding_bytes, Piece::Spaces)?;
        reader.push_bytes(b"}".to_vec())?;
        Ok(reader)
    }
    fn push_bytes(&mut self, bytes: Vec<u8>) -> Result<()> {
        self.push(bytes.len() as u64, Piece::Bytes(bytes))
    }
    fn object(&mut self, object: &Object, stamp: &Stamp) -> Result<()> {
        self.push(
            object.bytes - 2,
            Piece::Object {
                object: object.clone(),
                stamp: stamp.clone(),
            },
        )
    }
    fn push(&mut self, len: u64, piece: Piece) -> Result<()> {
        if len == 0 {
            return Ok(());
        }
        let end = self
            .length
            .checked_add(len)
            .context("scan_index_length_overflow")?;
        self.spans.push(Span {
            start: self.length,
            len,
            piece,
        });
        self.length = end;
        Ok(())
    }
}
struct KeyCount;
impl<'de> Visitor<'de> for KeyCount {
    type Value = usize;
    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("metadata object")
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> std::result::Result<usize, A::Error> {
        let mut count = 0;
        while map.next_key::<IgnoredAny>()?.is_some() {
            map.next_value::<IgnoredAny>()?;
            count += 1;
        }
        Ok(count)
    }
}
impl Read for LogicalReader {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() || self.position >= self.length {
            return Ok(0);
        }
        let i = self
            .spans
            .partition_point(|s| s.start + s.len <= self.position);
        let span = &self.spans[i];
        let offset = self.position - span.start;
        let count = (span.len - offset).min(output.len() as u64) as usize;
        let n = match &span.piece {
            Piece::Spaces => {
                output[..count].fill(b' ');
                count
            }
            Piece::Bytes(bytes) => {
                output[..count].copy_from_slice(&bytes[offset as usize..offset as usize + count]);
                count
            }
            Piece::Object { object, stamp } => {
                if !self.opened.as_ref().is_some_and(|(index, _)| *index == i) {
                    let file = open_at(
                        &self.directory,
                        &cstring(object.filename().as_bytes()).map_err(io::Error::other)?,
                        libc::O_RDONLY,
                    )?;
                    if Stamp::capture(&file, true).map_err(io::Error::other)? != *stamp {
                        return Err(io::Error::other("scan_index_object_changed"));
                    }
                    self.opened = Some((i, file));
                }
                let file = &mut self.opened.as_mut().expect("opened").1;
                file.seek(SeekFrom::Start(offset + 1))?;
                let n = file.read(&mut output[..count])?;
                if n == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "scan_index_object_truncated",
                    ));
                }
                if Stamp::capture(file, true).map_err(io::Error::other)? != *stamp {
                    return Err(io::Error::other("scan_index_object_changed"));
                }
                n
            }
        };
        self.position += n as u64;
        Ok(n)
    }
}
impl Seek for LogicalReader {
    fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
        let position = match from {
            SeekFrom::Start(n) => i128::from(n),
            SeekFrom::End(n) => i128::from(self.length) + i128::from(n),
            SeekFrom::Current(n) => i128::from(self.position) + i128::from(n),
        };
        self.position = u64::try_from(position)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "scan_index_seek"))?;
        Ok(self.position)
    }
}

// Uses directory handles throughout; never follows manifest/provider paths.
fn visit_storage_directory(
    dir: &File,
    mut visit: impl FnMut(&std::ffi::CStr) -> Result<()>,
) -> Result<()> {
    let file = open_at(dir, &cstring(b".")?, libc::O_RDONLY | libc::O_DIRECTORY)?;
    let fd = std::os::fd::IntoRawFd::into_raw_fd(file);
    let pointer = unsafe { libc::fdopendir(fd) };
    if pointer.is_null() {
        unsafe {
            libc::close(fd);
        }
        bail!("scan_index_directory_scan");
    }
    struct Scan(*mut libc::DIR);
    impl Drop for Scan {
        fn drop(&mut self) {
            unsafe {
                libc::closedir(self.0);
            }
        }
    }
    let scan = Scan(pointer);
    loop {
        #[cfg(target_os = "macos")]
        let errno = unsafe { libc::__error() };
        #[cfg(not(target_os = "macos"))]
        let errno = unsafe { libc::__errno_location() };
        unsafe {
            *errno = 0;
        }
        let entry = unsafe { libc::readdir(scan.0) };
        if entry.is_null() {
            ensure!(unsafe { *errno } == 0, "scan_index_directory_scan");
            break;
        }
        let name = unsafe { std::ffi::CStr::from_ptr((*entry).d_name.as_ptr()) };
        if matches!(name.to_bytes(), b"." | b"..") {
            continue;
        }
        visit(name)?;
    }
    Ok(())
}
/// Reserved N+1 class-L names: opaque to N, never objects or GC candidates.
/// Equivalent to ^prior-root-[0-9]{20}-[0-9a-f]{64}\.json$ or the fixed marker.
/// Syntax only: N neither reads their contents nor interprets their generation.
fn reserved_repair_filename(name: &str) -> bool {
    if name == "verified-complete.json" {
        return true;
    }
    let Some(stem) = name
        .strip_prefix("prior-root-")
        .and_then(|s| s.strip_suffix(".json"))
    else {
        return false;
    };
    let Some((generation, digest)) = stem.split_once('-') else {
        return false;
    };
    generation.len() == 20 && generation.bytes().all(|b| b.is_ascii_digit()) && valid_digest(digest)
}

fn orphan_slot(name: &str) -> Option<(Slot, &str)> {
    let stem = name.strip_suffix(".json")?;
    let (label, digest) = stem.rsplit_once('-')?;
    if !valid_digest(digest) {
        return None;
    }
    if label == "metadata" {
        return Some((Slot::Metadata, digest));
    }
    let (tag, bucket) = label.split_once('-')?;
    if bucket.len() != 2 {
        return None;
    }
    let bucket = u8::from_str_radix(bucket, 16).ok()?;
    let field = match tag {
        "account" => Field::AccountPending,
        "usage" => Field::UsagePending,
        "census" => Field::RequestCensus,
        _ => return None,
    };
    Some((Slot::Bucket { field, bucket }, digest))
}
fn owned_payload_temp(name: &str) -> bool {
    name.strip_prefix(".tmp-")
        .is_some_and(|s| s.len() == 32 && s.bytes().all(|b| b.is_ascii_hexdigit()))
}
impl LockedStore {
    pub(crate) fn take_read_stats(&self) -> ReadStats {
        self.read_stats.replace(ReadStats::default())
    }
    fn note_prior_root(&self) -> Result<()> {
        self.prior_root_seen.set(true);
        let mut name = self.root_name.to_bytes().to_vec();
        name.extend_from_slice(b".storage-prior");
        let name = cstring(&name)?;
        const MARKER: &[u8] = b"scan_index_prior_root_v1\n";
        match open_at(&self.parent, &name, libc::O_RDONLY) {
            Ok(mut file) => {
                let stamp = Stamp::capture(&file, true)?;
                ensure!(
                    stamp.bytes <= MARKER.len() as u64,
                    "scan_index_prior_marker"
                );
                let mut bytes = Vec::with_capacity(MARKER.len());
                file.read_to_end(&mut bytes)?;
                if bytes == MARKER {
                    return Ok(());
                }
                // Recover a pre-atomic empty/truncated OWN marker only while
                // the caller has an actual root. Unknown marker bytes refuse.
                ensure!(MARKER.starts_with(&bytes), "scan_index_prior_marker");
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        let mut prefix = self.root_name.to_bytes().to_vec();
        prefix.extend_from_slice(b".storage-tmp-");
        let temp = Temp::with_prefix(&self.parent, &prefix)?;
        let mut output = &temp.file;
        output.write_all(MARKER)?;
        temp.file.sync_all()?;
        rename_at(&self.parent, &temp.name, &self.parent, &name)?;
        self.parent.sync_all()?;
        Ok(())
    }
    /// Opaque repair controls are evidence of possible history, never freshness.
    /// Check names only, before validating or deleting any orphan payload.
    fn refuse_reserved_without_root(&self, dir: &File) -> Result<()> {
        visit_storage_directory(dir, |name| {
            if name.to_str().is_ok_and(reserved_repair_filename) {
                let mut stats = self.read_stats.get();
                stats.root_missing_reserved_only =
                    stats.root_missing_reserved_only.saturating_add(1);
                self.read_stats.set(stats);
                bail!("scan_index_root_missing_with_shards");
            }
            Ok(())
        })
    }
    fn recover_fresh_init(&self) -> Result<()> {
        match open_at(&self.parent, &self.root_name, libc::O_RDONLY) {
            Ok(_) => return Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        let dir = match self.payload_directory() {
            Ok(dir) => Some(dir),
            Err(e)
                if e.downcast_ref::<io::Error>()
                    .is_some_and(|e| e.kind() == io::ErrorKind::NotFound) =>
            {
                None
            }
            Err(e) => return Err(e),
        };
        if let Some(dir) = &dir {
            self.refuse_reserved_without_root(dir)?;
        }
        let root = self
            .root_name
            .to_str()
            .map_err(|_| anyhow::anyhow!("scan_index_root_name"))?;
        let stem = root.strip_suffix(".json").unwrap_or(root);
        let family = stem.strip_suffix("-v2").unwrap_or(stem);
        let temp_prefix = format!("{root}.storage-tmp-");
        let own_temp = |name: &str| {
            name.strip_prefix(&temp_prefix)
                .is_some_and(|s| s.len() == 32 && s.bytes().all(|b| b.is_ascii_hexdigit()))
        };
        let mut temps = false;
        // Validate EVERY parent witness before any deletion. Unrecognized
        // siblings in this index family are evidence of possible prior state.
        visit_storage_directory(&self.parent, |name| {
            let text = name
                .to_str()
                .map_err(|_| anyhow::anyhow!("scan_index_prior_state_unknown"))?;
            if own_temp(text) {
                Stamp::capture(&open_at(&self.parent, name, libc::O_RDONLY)?, true)?;
                temps = true;
            } else if text == format!("{stem}-upload-progress.lock") {
                Stamp::capture(&open_at(&self.parent, name, libc::O_RDONLY)?, false)?;
            } else if text.starts_with(family)
                && text != self.objects_name.to_str()?
                && text != format!("{root}.lock")
                && text != format!("{stem}.lock")
            {
                bail!("scan_index_prior_state_requires_repair");
            }
            Ok(())
        })?;
        ensure!(
            !self.prior_root_seen.get(),
            "scan_index_prior_state_requires_repair"
        );
        if let Some(dir) = &dir {
            visit_storage_directory(dir, |name| {
                let text = name
                    .to_str()
                    .map_err(|_| anyhow::anyhow!("scan_index_orphan_unknown"))?;
                if reserved_repair_filename(text) {
                    // A control appearing after the first pass must also stall.
                    self.refuse_reserved_without_root(dir)?;
                }
                let file = open_at(dir, name, libc::O_RDONLY)?;
                let stamp = Stamp::capture(&file, true)?;
                if let Some((slot, digest)) = orphan_slot(text) {
                    self.validate_object(
                        dir,
                        &Object {
                            slot,
                            generation: 0,
                            bytes: stamp.bytes,
                            digest: digest.into(),
                        },
                    )?;
                } else {
                    ensure!(owned_payload_temp(text), "scan_index_orphan_unknown");
                }
                Ok(())
            })?;
        }
        // Existing checkpoint flock excludes concurrent index publication.
        if let Some(dir) = dir {
            visit_storage_directory(&dir, |name| {
                if name.to_str().is_ok_and(reserved_repair_filename) {
                    return Ok(());
                }
                Stamp::capture(&open_at(&dir, name, libc::O_RDONLY)?, true)?;
                unlink_at(&dir, name)?;
                Ok(())
            })?;
            dir.sync_all()?;
            ensure!(
                unsafe {
                    libc::unlinkat(
                        self.parent.as_raw_fd(),
                        self.objects_name.as_ptr(),
                        libc::AT_REMOVEDIR,
                    )
                } == 0,
                "scan_index_orphan_directory"
            );
        } else if !temps {
            return Ok(());
        }
        visit_storage_directory(&self.parent, |name| {
            if name.to_str().is_ok_and(own_temp) {
                Stamp::capture(&open_at(&self.parent, name, libc::O_RDONLY)?, true)?;
                unlink_at(&self.parent, name)?;
            }
            Ok(())
        })?;
        self.parent.sync_all()?;
        let mut stats = self.read_stats.get();
        stats.scanindex_orphan_init_discarded =
            stats.scanindex_orphan_init_discarded.saturating_add(1);
        self.read_stats.set(stats);
        Ok(())
    }
}

#[cfg(test)]
mod repair_filename_tests {
    use super::*;

    #[test]
    fn repair_names_are_exact_and_disjoint_from_slots_and_temps() {
        let digest = "a".repeat(64);
        let prior = format!("prior-root-00000000000000000007-{digest}.json");
        for name in [prior.as_str(), "verified-complete.json"] {
            assert!(reserved_repair_filename(name));
            assert!(orphan_slot(name).is_none());
            assert!(!owned_payload_temp(name));
        }
        for bad in [
            format!("prior-root-{}-{digest}.json", "0".repeat(19)),
            format!("prior-root-{}-{digest}.json", "0".repeat(21)),
            format!("prior-root-0000000000000000000x-{digest}.json"),
            format!("prior-root-00000000000000000007-{}.json", "a".repeat(63)),
            format!("prior-root-00000000000000000007-{}.json", "a".repeat(65)),
            format!("prior-root-00000000000000000007-{}.json", "A".repeat(64)),
            format!("{prior}.tmp"),
            format!("./{prior}"),
            format!("x{prior}"),
            prior.replace(".json", ".JSON"),
            "verified-complete.json.tmp".into(),
            "verified-complete.JSON".into(),
            "./verified-complete.json".into(),
        ] {
            assert!(!reserved_repair_filename(&bad), "{bad}");
        }
        assert!(!Slot::Metadata.label().starts_with("prior-root-"));
        for field in Field::all() {
            for bucket in 0..=255 {
                assert!(!Slot::Bucket { field, bucket }
                    .label()
                    .starts_with("prior-root-"));
            }
        }
    }
}
