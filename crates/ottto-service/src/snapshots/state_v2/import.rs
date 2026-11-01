//! Pre-publication pacing and the Claude semantic mapper boundary.
use super::*;
use anyhow::bail;
use std::path::Path;
use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Pause {
    UnknownClass,
    Malformed,
    Partial,
    Oversize,
    Mismatch,
    Io,
    UnsafeParent,
}
impl std::fmt::Display for Pause {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("state_v2_import_paused")
    }
}
impl std::error::Error for Pause {}
/// Every attempt, whatever its pause class, is retried after one fixed day.
#[derive(Default)]
pub(super) struct Pace {
    attempts: u64,
    next: Option<Instant>,
}
impl Pace {
    pub(super) fn start(&mut self, now: Instant) -> Option<bool> {
        if self.next.is_some_and(|next| now < next) {
            return None;
        }
        let first = self.attempts == 0;
        self.attempts = self.attempts.saturating_add(1);
        self.next = Some(now + Duration::from_secs(24 * 3600));
        Some(first)
    }
}

/// Raw inventory and parity proof precede publication. The four semantic
/// adapters share a transaction and context in `kinds`; this boundary owns
/// their integration with runtime CAS.
pub(super) trait Mapper {
    /// Emit ALL private text from key, fixed/header, labels/aliases and raw
    /// holds, as well as packed values. Replacements must retain none silently.
    fn private_paths(
        header: &Header,
        value: &dyn Value,
        paths: &mut dyn FnMut(&str) -> Result<()>,
    ) -> Result<()>;
    /// Enumerate the complete reference list packed in this row, including
    /// repeated edges. Shared values must not reference other shared values.
    fn references(
        header: &Header,
        value: &dyn Value,
        refs: &mut dyn FnMut(&RowKey) -> Result<()>,
    ) -> Result<()>;
    fn inventory_context(&self, path: &Path) -> std::result::Result<Option<Original>, Pause>;
    fn import_generation(&self, index: &ScanIndex) -> Result<u64> {
        Ok(index.generation)
    }
    fn import_graph<S: Store>(
        &self,
        store: &mut S,
        index: &ScanIndex,
        original: Option<&Original>,
    ) -> Result<KindCx>;
    /// Read every semantic row through Transaction::read_value, verifying
    /// value digests while decoding. Never return
    /// a partially hydrated graph or normalize unknown raw holds away.
    fn hydrate_context<S: Store>(&self, store: &mut S) -> Result<(ScanIndex, KindCx)>;
}
/// Composed semantic mapper.
pub(super) struct ClaudeMapper;
impl Mapper for ClaudeMapper {
    fn references(
        header: &Header,
        value: &dyn Value,
        refs: &mut dyn FnMut(&RowKey) -> Result<()>,
    ) -> Result<()> {
        kinds::references(header, value, refs)
    }
    fn private_paths(
        header: &Header,
        value: &dyn Value,
        paths: &mut dyn FnMut(&str) -> Result<()>,
    ) -> Result<()> {
        kinds::private_paths(header, value, paths)
    }
    fn inventory_context(&self, path: &Path) -> std::result::Result<Option<Original>, Pause> {
        Original::read(path).map(Some)
    }
    fn import_generation(&self, index: &ScanIndex) -> Result<u64> {
        index
            .generation
            .checked_add(1)
            .ok_or_else(|| Pause::Oversize.into())
    }
    fn import_graph<S: Store>(
        &self,
        store: &mut S,
        index: &ScanIndex,
        original: Option<&Original>,
    ) -> Result<KindCx> {
        let original = original.ok_or(Pause::Mismatch)?;
        original.unchanged()?;
        let mut tx = store.begin(TxnMode::Write)?;
        let identity = identity(&mut tx)?;
        let generation = self.import_generation(index)?;
        anyhow::ensure!(identity.fence_generation == generation, Pause::Mismatch);
        let mut cx = KindCx::default();
        cx.binding = Some(identity.binding.clone());
        cx.presence = original.presence.clone();
        kinds::populate(index, &mut tx, &mut cx)?;
        anyhow::ensure!(
            tx.commit(index.generation, generation) == DurableCommitOutcome::Committed(generation),
            Pause::Mismatch
        );
        // A COMMIT advanced control.generation; the proof must compare the
        // normalized G graph against that one deliberate G+1 control change.
        let mut tx = store.begin(TxnMode::Read)?;
        let cx = verify_normalized_at(&mut tx, index, original, identity.binding, generation);
        // The read-back re-encodes the same rows; one gauge covers the import.
        telemetry::row_cap_save();
        cx
    }
    fn hydrate_context<S: Store>(&self, store: &mut S) -> Result<(ScanIndex, KindCx)> {
        let mut tx = store.begin(TxnMode::Read)?;
        let header = tx
            .get(&RowKey::Meta("identity".into()))?
            .ok_or(Hold::ForeignBinding)?;
        anyhow::ensure!(header.len <= CONTROL_BYTES, Hold::DbUnavailable);
        let mut bytes = Vec::new();
        tx.read_value(&header, &mut bytes)?;
        let identity: Identity = serde_json::from_slice(&bytes)?;
        anyhow::ensure!(
            identity.binding.source == super::super::scan_index_persistence::Source::Claude,
            Hold::ForeignBinding
        );
        kinds::hydrate_txn(&mut tx, identity.binding)
    }
}
impl ClaudeMapper {
    /// The one production save: merge current CAS custody, then run the
    /// semantic delta under the resident committed context. Emit the complete
    /// dirty delta with per-key SQLite header reads. Saves above 5k rows /
    /// 32 MiB reduce the next collection page; the whole save rolls back at its
    /// hard ceiling. More than 64 account windows is an alarm, never permission
    /// to drop unsettled custody. KEEP persisted shared refs: decode only each
    /// changed row's old refs, diff against new refs, adjust/reclaim in this
    /// transaction. Never perform whole-history GC during a save.
    pub(super) fn save(
        &self,
        db: &mut sqlite::Sqlite,
        identity: &Identity,
        previous: kinds::Baseline,
        next: &mut ScanIndex,
        cx: &mut KindCx,
        claim_only: bool,
    ) -> Result<kinds::Baseline> {
        {
            let mut tx = db.begin(TxnMode::Read)?;
            kinds_misc::merge_cas_at(&mut tx, next, previous.generation)?;
            kinds_files::merge_growth_cas(&mut tx, next)?;
        }
        super::super::sampled_audit::prune_growth_retention(
            next,
            super::super::sampled_scan::now_seconds(),
        );
        if !claim_only {
            next.retire_committed_claude_account_pending_windows();
        }
        super::super::lenient_decode::check_held_output(next)?;
        kinds::save_graph(db, identity, previous, next, cx)
    }
}

fn identity(tx: &mut dyn Transaction) -> Result<Identity> {
    let h = tx
        .get(&RowKey::Meta("identity".into()))?
        .ok_or(Hold::ForeignBinding)?;
    anyhow::ensure!(h.len <= CONTROL_BYTES, Hold::ForeignBinding);
    let mut bytes = Vec::new();
    tx.read_value(&h, &mut bytes)?;
    Ok(serde_json::from_slice(&bytes)?)
}

/// Evidence is collected before lenient decoding. It contains only bounded
/// descriptors/presence and exact file commitments, never a second index graph.
/// Kept private; filenames, commitments and namespace bindings are not telemetry.
#[derive(Default, Debug)]
pub(super) struct Original {
    progress: Option<super::ack::OriginalProgress>,
    pub(super) presence: std::collections::BTreeMap<String, bool>,
    files: Vec<OriginalFile>,
    missing: Option<std::path::PathBuf>,
}
#[derive(Debug)]
struct OriginalFile {
    path: std::path::PathBuf,
    stamp: OriginalStamp,
    digest: [u8; 32],
}
#[derive(Debug, PartialEq, Eq)]
struct OriginalStamp(u64, u64, u64, i64, i64, i64, i64);
impl OriginalStamp {
    fn read(file: &std::fs::File) -> Result<Self> {
        use std::os::unix::fs::MetadataExt;
        let m = file.metadata()?;
        anyhow::ensure!(
            m.is_file()
                && m.nlink() == 1
                && m.uid() == unsafe { libc::geteuid() }
                && m.mode() & 0o022 == 0,
            Pause::UnsafeParent
        );
        Ok(Self(
            m.dev(),
            m.ino(),
            m.len(),
            m.mtime(),
            m.mtime_nsec(),
            m.ctime(),
            m.ctime_nsec(),
        ))
    }
}
fn original_open(path: &Path) -> Result<std::fs::File> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    for ancestor in path.parent().into_iter().flat_map(Path::ancestors) {
        let m = std::fs::symlink_metadata(ancestor)?;
        anyhow::ensure!(
            m.is_dir() && !m.file_type().is_symlink(),
            Pause::UnsafeParent
        );
    }
    let parent = std::fs::metadata(path.parent().ok_or(Pause::UnsafeParent)?)?;
    anyhow::ensure!(
        parent.uid() == unsafe { libc::geteuid() } && parent.mode() & 0o022 == 0,
        Pause::UnsafeParent
    );
    Ok(std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)?)
}
fn original_hash(file: &mut std::fs::File) -> Result<[u8; 32]> {
    use sha2::Digest;
    use std::io::{Seek, SeekFrom};
    file.seek(SeekFrom::Start(0))?;
    let mut hash = sha2::Sha256::new();
    let mut buf = [0; 32 * 1024 + 3];
    let mut pending = 0;
    let mut strings = JsonStrings::Outside;
    loop {
        let n = file.read(&mut buf[pending..])?;
        if n == 0 {
            break;
        }
        let end = pending + n;
        hash.update(&buf[pending..end]);
        for byte in &buf[pending..end] {
            strings.byte(*byte)?;
        }
        pending = match std::str::from_utf8(&buf[..end]) {
            Ok(_) => 0,
            Err(e) if e.error_len().is_none() => {
                let n = end - e.valid_up_to();
                anyhow::ensure!(n <= 3, Pause::Malformed);
                buf.copy_within(e.valid_up_to()..end, 0);
                n
            }
            Err(_) => bail!(Pause::Malformed),
        };
    }
    anyhow::ensure!(
        pending == 0 && matches!(strings, JsonStrings::Outside),
        Pause::Malformed
    );
    Ok(hash.finalize().into())
}
/// Serde's IgnoredAny deliberately accepts invalid UTF-8 and unpaired surrogate
/// escapes. Validate string encoding while hashing, with constant retained state.
#[derive(Clone, Copy)]
enum JsonStrings {
    Outside,
    Text,
    Escape,
    Hex {
        remaining: u8,
        value: u16,
        low: bool,
    },
    LowSlash,
    LowU,
}
impl JsonStrings {
    fn byte(&mut self, b: u8) -> Result<()> {
        use JsonStrings::*;
        *self = match *self {
            Outside if b == b'"' => Text,
            Outside => Outside,
            Text if b == b'"' => Outside,
            Text if b == b'\\' => Escape,
            Text => {
                anyhow::ensure!(b >= 0x20, Pause::Malformed);
                Text
            }
            Escape if b == b'u' => Hex {
                remaining: 4,
                value: 0,
                low: false,
            },
            Escape if b"\"\\/bfnrt".contains(&b) => Text,
            Escape => bail!(Pause::Malformed),
            Hex {
                remaining,
                value,
                low,
            } => {
                let digit = match b {
                    b'0'..=b'9' => b - b'0',
                    b'a'..=b'f' => b - b'a' + 10,
                    b'A'..=b'F' => b - b'A' + 10,
                    _ => bail!(Pause::Malformed),
                };
                let value = (value << 4) | u16::from(digit);
                if remaining > 1 {
                    Hex {
                        remaining: remaining - 1,
                        value,
                        low,
                    }
                } else if low {
                    anyhow::ensure!((0xdc00..=0xdfff).contains(&value), Pause::Malformed);
                    Text
                } else if (0xd800..=0xdbff).contains(&value) {
                    LowSlash
                } else {
                    anyhow::ensure!(!(0xdc00..=0xdfff).contains(&value), Pause::Malformed);
                    Text
                }
            }
            LowSlash => {
                anyhow::ensure!(b == b'\\', Pause::Malformed);
                LowU
            }
            LowU => {
                anyhow::ensure!(b == b'u', Pause::Malformed);
                Hex {
                    remaining: 4,
                    value: 0,
                    low: true,
                }
            }
        };
        Ok(())
    }
}
impl OriginalFile {
    fn capture(path: &Path, file: &mut std::fs::File, stamp: OriginalStamp) -> Result<Self> {
        let digest = original_hash(file)?;
        let named = original_open(path)?;
        anyhow::ensure!(
            stamp == OriginalStamp::read(file)? && stamp == OriginalStamp::read(&named)?,
            Pause::Mismatch
        );
        Ok(Self {
            path: path.to_owned(),
            stamp,
            digest,
        })
    }
    fn unchanged(&self) -> Result<()> {
        let mut file = original_open(&self.path)?;
        anyhow::ensure!(
            self.stamp == OriginalStamp::read(&file)?
                && self.digest == original_hash(&mut file)?
                && self.stamp == OriginalStamp::read(&file)?,
            Pause::Mismatch
        );
        Ok(())
    }
}

/// Stream root presence and validate JSON grammar without allocating leaf
/// strings. The hashing pass separately validates their Unicode encoding.
struct Presence;
impl<'de> serde::de::Visitor<'de> for Presence {
    type Value = std::collections::BTreeMap<String, bool>;
    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("original index")
    }
    fn visit_map<A: serde::de::MapAccess<'de>>(
        self,
        mut map: A,
    ) -> std::result::Result<Self::Value, A::Error> {
        let mut fields = super::super::lenient_decode::FIELDS
            .iter()
            .map(|f| ((*f).into(), false))
            .collect::<Self::Value>();
        while let Some(name) = map.next_key::<String>()? {
            let present = fields
                .get_mut(&name)
                .ok_or_else(|| serde::de::Error::custom("unknown original field"))?;
            if *present {
                return Err(serde::de::Error::custom("duplicate original field"));
            }
            *present = true;
            map.next_value::<serde::de::IgnoredAny>()?;
        }
        Ok(fields)
    }
    fn visit_seq<A: serde::de::SeqAccess<'de>>(
        self,
        mut seq: A,
    ) -> std::result::Result<Self::Value, A::Error> {
        let mut fields = std::collections::BTreeMap::new();
        let mut ended = false;
        for name in super::super::lenient_decode::FIELDS {
            let present = !ended && seq.next_element::<serde::de::IgnoredAny>()?.is_some();
            ended |= !present;
            fields.insert((*name).into(), present);
        }
        if seq.next_element::<serde::de::IgnoredAny>()?.is_some() {
            return Err(serde::de::Error::custom("unknown original slot"));
        }
        Ok(fields)
    }
}
fn original_presence(input: impl Read) -> Result<std::collections::BTreeMap<String, bool>> {
    use serde::de::Deserializer;
    let mut de = serde_json::Deserializer::from_reader(input);
    let presence = (&mut de).deserialize_any(Presence)?;
    de.end()?;
    Ok(presence)
}
fn original_shape(input: impl std::io::BufRead) -> Result<()> {
    struct Observed<R> {
        input: R,
        failed: bool,
    }
    impl<R: std::io::BufRead> Read for Observed<R> {
        fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
            let result = self.input.read(out);
            self.failed |= result.is_err();
            result
        }
    }
    impl<R: std::io::BufRead> std::io::BufRead for Observed<R> {
        fn fill_buf(&mut self) -> std::io::Result<&[u8]> {
            let result = self.input.fill_buf();
            self.failed |= result.is_err();
            result
        }
        fn consume(&mut self, n: usize) {
            self.input.consume(n);
        }
    }
    let mut observed = Observed {
        input,
        failed: false,
    };
    let result = codec::inventory(&mut observed);
    if observed.failed {
        bail!(Pause::Io);
    }
    result.map_err(|p| {
        match p {
            codec::Pause::Unknown => Pause::UnknownClass,
            codec::Pause::Malformed => Pause::Malformed,
            codec::Pause::Oversize => Pause::Oversize,
        }
        .into()
    })
}
fn original_schema(file: &mut std::fs::File) -> Result<u16> {
    use serde::de::{Deserializer, IgnoredAny, MapAccess, Visitor};
    struct Probe<'a>(&'a std::cell::Cell<Option<u16>>);
    impl<'de> Visitor<'de> for Probe<'_> {
        type Value = ();
        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("v1 header")
        }
        fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> std::result::Result<(), A::Error> {
            while let Some(name) = map.next_key::<String>()? {
                if name == "schema_version" {
                    self.0.set(Some(map.next_value()?));
                    return Ok(());
                }
                map.next_value::<IgnoredAny>()?;
            }
            Err(serde::de::Error::custom("missing schema"))
        }
        fn visit_seq<A: serde::de::SeqAccess<'de>>(
            self,
            mut seq: A,
        ) -> std::result::Result<(), A::Error> {
            self.0.set(seq.next_element()?);
            Ok(())
        }
    }
    let mut de = serde_json::Deserializer::from_reader(
        file.take(super::super::scan_index_persistence::MAX_ROOT_BYTES as u64 + 1),
    );
    // The rest is deliberately unconsumed here, then fully checked by the
    // appropriate shape/manifest reader. Serde may report that suffix as an
    // error; a captured header only chooses a reader and never grants custody.
    let schema = std::cell::Cell::new(None);
    let _ = (&mut de).deserialize_any(Probe(&schema));
    schema.get().ok_or_else(|| Pause::Malformed.into())
}
impl Original {
    pub(super) fn read(path: &Path) -> std::result::Result<Self, Pause> {
        Self::read_inner(path).map_err(|e| {
            e.downcast_ref::<Pause>().copied().unwrap_or_else(|| {
                if e.downcast_ref::<std::io::Error>().is_some()
                    || e.downcast_ref::<serde_json::Error>()
                        .is_some_and(|e| e.is_io())
                {
                    Pause::Io
                } else {
                    Pause::Malformed
                }
            })
        })
    }
    fn read_inner(path: &Path) -> Result<Self> {
        use super::super::scan_index_persistence::{
            validate_object_digest, Field, Manifest, Slot, LOGICAL_SCHEMA, MAX_ROOT_BYTES,
            OUTER_SCHEMA,
        };
        use std::io::{BufReader, Seek, SeekFrom};
        let mut result = Self::default();
        if !fence::exists(path)? {
            anyhow::ensure!(
                !fence::exists(&fence::sibling(path, ".shards"))?,
                Pause::Partial
            );
            result.missing = Some(path.to_owned());
            return Ok(result);
        }
        let mut root = original_open(path)?;
        let stamp = OriginalStamp::read(&root)?;
        let schema = original_schema(&mut root)?;
        root.seek(SeekFrom::Start(0))?;
        if schema == LOGICAL_SCHEMA {
            // A legacy root references no shards. Existing v1 marker/orphan
            // directories do not add authority to this original logical graph.
            original_shape(BufReader::new(&mut root))?;
            root.seek(SeekFrom::Start(0))?;
            result.presence = original_presence(BufReader::new(&mut root))?;
        } else {
            anyhow::ensure!(schema == OUTER_SCHEMA, Pause::UnknownClass);
            anyhow::ensure!(stamp.2 <= MAX_ROOT_BYTES as u64, Pause::Oversize);
            let manifest: Manifest = serde_json::from_reader(BufReader::new(
                (&mut root).take(MAX_ROOT_BYTES as u64 + 1),
            ))?;
            let binding = super::super::scan_index_integration::scan_index_storage_binding(path)
                .ok_or(Pause::Mismatch)?;
            manifest.validate(&binding).map_err(|_| Pause::Mismatch)?;
            anyhow::ensure!(manifest.maps.len() == 3, Pause::Partial);
            for object in &manifest.objects {
                anyhow::ensure!(object.generation == manifest.generation, Pause::Mismatch);
            }
            for field in [
                Field::AccountPending,
                Field::UsagePending,
                Field::RequestCensus,
            ] {
                let mut maps = manifest.maps.iter().filter(|m| m.field == field);
                let map = maps.next().ok_or(Pause::Partial)?;
                anyhow::ensure!(
                    maps.next().is_none() && map.generation == manifest.generation,
                    Pause::Partial
                );
                let buckets: Vec<_> = manifest
                    .objects
                    .iter()
                    .filter_map(|o| match o.slot {
                        Slot::Bucket { field: f, bucket } if f == field => Some(bucket),
                        _ => None,
                    })
                    .collect();
                anyhow::ensure!(map.buckets == buckets, Pause::Partial);
            }
            for object in &manifest.objects {
                let shard_path = fence::sibling(path, ".shards").join(object.filename());
                let mut file = original_open(&shard_path).map_err(|e| {
                    if e.downcast_ref::<std::io::Error>()
                        .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound)
                    {
                        Pause::Partial.into()
                    } else {
                        e
                    }
                })?;
                let before = OriginalStamp::read(&file)?;
                anyhow::ensure!(before.2 == object.bytes, Pause::Mismatch);
                let prefix = match object.slot {
                    Slot::Metadata => String::new(),
                    Slot::Bucket { field, .. } => format!("{{\"{}\":", field.name()),
                };
                let suffix = if prefix.is_empty() { "" } else { "}" };
                original_shape(BufReader::new(
                    prefix.as_bytes().chain(&mut file).chain(suffix.as_bytes()),
                ))?;
                file.seek(SeekFrom::Start(0))?;
                if object.slot == Slot::Metadata {
                    result.presence = original_presence(BufReader::new(&mut file))?;
                    anyhow::ensure!(
                        !result.presence["schema_version"]
                            && !result.presence["generation"]
                            && [
                                Field::AccountPending,
                                Field::UsagePending,
                                Field::RequestCensus
                            ]
                            .iter()
                            .all(|f| !result.presence[f.name()]),
                        Pause::Mismatch
                    );
                } else {
                    // Validate string grammar without allocating the map.
                    let mut de = serde_json::Deserializer::from_reader(BufReader::new(&mut file));
                    serde::de::IgnoredAny::deserialize(&mut de)?;
                    de.end()?;
                }
                file.seek(SeekFrom::Start(0))?;
                validate_object_digest(&mut file, &binding, object).map_err(|_| Pause::Mismatch)?;
                result
                    .files
                    .push(OriginalFile::capture(&shard_path, &mut file, before)?);
            }
            // These fields are explicitly present in the authenticated logical view,
            // including each empty money map whose descriptor has no buckets.
            for name in [
                "schema_version",
                "generation",
                Field::AccountPending.name(),
                Field::UsagePending.name(),
                Field::RequestCensus.name(),
            ] {
                result.presence.insert(name.into(), true);
            }
        }
        result
            .files
            .insert(0, OriginalFile::capture(path, &mut root, stamp)?);
        result.unchanged()?;
        Ok(result)
    }
    pub(super) fn capture_progress(&mut self, path: &Path) -> Result<()> {
        self.progress = Some(super::ack::OriginalProgress::capture(path)?);
        Ok(())
    }
    pub(super) fn retry_identity(&self, proposed: Identity) -> Result<Identity> {
        self.progress
            .as_ref()
            .ok_or(Pause::Mismatch)?
            .retry_identity(proposed)
    }
    #[cfg(test)]
    pub(super) fn seal_progress<S: Store>(
        &self,
        path: &Path,
        identity: &Identity,
        store: &mut S,
    ) -> Result<()> {
        self.verify_baseline(path)?;
        self.progress
            .as_ref()
            .ok_or(Pause::Mismatch)?
            .seal(path, identity, store)
    }
    pub(super) fn publish_import(
        &self,
        path: &Path,
        identity: &Identity,
        db: sqlite::Sqlite,
        latched: &mut bool,
    ) -> Result<()> {
        self.verify_baseline(path)?;
        self.progress
            .as_ref()
            .ok_or(Pause::Mismatch)?
            .with_sealed_import(path, identity, db, |db| {
                db.finish_import()?;
                self.unchanged()?;
                fence::publish(path, identity, latched)
            })
    }
    fn verify_baseline(&self, path: &Path) -> Result<()> {
        for (n, source) in self.files.iter().enumerate() {
            let target = if n == 0 {
                fence::sibling(path, ".v1-readonly")
            } else {
                fence::sibling(path, ".v1-readonly.shards")
                    .join(source.path.file_name().ok_or(Pause::Mismatch)?)
            };
            let mut file = original_open(&target)?;
            anyhow::ensure!(source.digest == original_hash(&mut file)?, Pause::Mismatch);
        }
        Ok(())
    }
    pub(super) fn unchanged(&self) -> Result<()> {
        if let Some(path) = &self.missing {
            anyhow::ensure!(
                !fence::exists(path)? && !fence::exists(&fence::sibling(path, ".shards"))?,
                Pause::Mismatch
            );
        }
        for file in &self.files {
            file.unchanged()?;
        }
        Ok(())
    }
    pub(super) fn preserve(&self, path: &Path) -> Result<()> {
        use std::os::unix::fs::DirBuilderExt;
        self.unchanged()?;
        let mut bytes = 0_u64;
        let shards = fence::sibling(path, ".v1-readonly.shards");
        if self.files.len() > 1 {
            std::fs::DirBuilder::new().mode(0o700).create(&shards)?;
        }
        for (n, source) in self.files.iter().enumerate() {
            let target = if n == 0 {
                fence::sibling(path, ".v1-readonly")
            } else {
                shards.join(source.path.file_name().ok_or(Pause::Mismatch)?)
            };
            bytes = bytes
                .checked_add(fence::preserve_file(&source.path, &target)?)
                .ok_or(Pause::Oversize)?;
            let mut preserved = original_open(&target)?;
            anyhow::ensure!(
                source.digest == original_hash(&mut preserved)?,
                Pause::Mismatch
            );
        }
        if self.files.len() > 1 {
            super::super::sync_checkpoint_parent(&shards.join("unused"))?;
        }
        if !self.files.is_empty() {
            super::super::sync_checkpoint_parent(path)?;
        }
        self.unchanged()?;
        telemetry::event("baseline_bytes", &bytes);
        Ok(())
    }
}

/// Re-emit normalized semantic rows into a read-only comparator. This consumes
/// every value through the backend's checked streaming comparison, without
/// hydrating a second ScanIndex or retaining any packed history payloads.
/// The returned context is the one installed for the verified graph.
#[cfg(test)]
fn verify_normalized(
    tx: &mut dyn Transaction,
    index: &ScanIndex,
    original: &Original,
    binding: super::super::scan_index_persistence::Binding,
) -> Result<KindCx> {
    verify_normalized_at(tx, index, original, binding, index.generation)
}
fn verify_normalized_at(
    tx: &mut dyn Transaction,
    index: &ScanIndex,
    original: &Original,
    binding: super::super::scan_index_persistence::Binding,
    generation: u64,
) -> Result<KindCx> {
    let mut proof = ReadBack {
        inner: tx,
        generation,
        records: 0,
        refs: std::collections::BTreeMap::new(),
    };
    let mut cx = KindCx::default();
    cx.binding = Some(binding);
    cx.presence = original.presence.clone();
    kinds::populate(index, &mut proof, &mut cx)?;
    let mut count = 0_u64;
    let mut after = None;
    loop {
        let page = proof.inner.scan_prefix(
            RowPrefix {
                table: Table::Records,
            },
            after.as_ref(),
            128,
        )?;
        if page.is_empty() {
            break;
        }
        count = count
            .checked_add(page.len() as u64)
            .ok_or(Pause::Oversize)?;
        after = page.last().map(|h| h.key.clone());
    }
    anyhow::ensure!(count == proof.records, Pause::Mismatch);
    let mut after = None;
    loop {
        let page = proof.inner.scan_prefix(
            RowPrefix {
                table: Table::RequestSets,
            },
            after.as_ref(),
            128,
        )?;
        if page.is_empty() {
            break;
        }
        for h in &page {
            let Fixed::RequestSet { refs, .. } = h.fixed else {
                bail!(Pause::Mismatch);
            };
            anyhow::ensure!(proof.refs.remove(&h.key) == Some(refs), Pause::Mismatch);
        }
        after = page.last().map(|h| h.key.clone());
    }
    anyhow::ensure!(proof.refs.is_empty(), Pause::Mismatch);
    Ok(cx)
}
struct ReadBack<'a> {
    inner: &'a mut dyn Transaction,
    generation: u64,
    records: u64,
    refs: std::collections::BTreeMap<RowKey, u64>,
}
impl Transaction for ReadBack<'_> {
    // Present a fresh import to the semantic encoders. The real rows are read
    // only by put/candidate lookup, never rewritten by the proof.
    fn get(&mut self, _: &RowKey) -> Result<Option<Header>> {
        Ok(None)
    }
    fn read_value(&mut self, h: &Header, out: &mut dyn Write) -> Result<()> {
        self.inner.read_value(h, out)
    }
    fn put(&mut self, row: RowInput<'_>) -> Result<Header> {
        let h = self.inner.get(row.key)?.ok_or(Pause::Mismatch)?;
        let generation = control_json(&self.generation)?;
        let expected = if row.key == &RowKey::Meta("generation".into()) {
            generation.as_slice()
        } else {
            row.value
        };
        anyhow::ensure!(
            h.value_version == row.value_version && &h.fixed == row.fixed && {
                let mut actual = Vec::new();
                self.inner.read_value(&h, &mut actual)?;
                if matches!(row.key,RowKey::Record{kind,..} if kind.name().starts_with("raw_hold."))
                {
                    actual == expected
                } else {
                    codec::expand(&actual, value_cap(row.key))?
                        == codec::expand(expected, value_cap(row.key))?
                }
            },
            Pause::Mismatch
        );
        if matches!(row.key, RowKey::Record { .. }) {
            self.records = self.records.checked_add(1).ok_or(Pause::Oversize)?;
        }
        Ok(h)
    }
    fn delete(&mut self, _: &RowKey) -> Result<bool> {
        bail!(Pause::Mismatch)
    }
    fn request_set_candidates(
        &mut self,
        digest: &[u8; 32],
        after: u64,
        limit: usize,
    ) -> Result<Vec<Header>> {
        self.inner.request_set_candidates(digest, after, limit)
    }
    fn adjust_refs(&mut self, key: &RowKey, delta: i64) -> Result<u64> {
        anyhow::ensure!(delta > 0, Pause::Mismatch);
        anyhow::ensure!(
            self.refs.contains_key(key) || self.refs.len() < 8 * 1024 * 1024 / 128,
            Pause::Oversize
        );
        let count = self.refs.entry(key.clone()).or_default();
        *count = count.checked_add(delta as u64).ok_or(Pause::Oversize)?;
        Ok(*count)
    }
    fn scan_prefix(&mut self, _: RowPrefix, _: Option<&RowKey>, _: usize) -> Result<Vec<Header>> {
        Ok(Vec::new())
    }
    fn scan_kind(&mut self, _: &RecordKind, _: Option<&RowKey>, _: usize) -> Result<Vec<Header>> {
        Ok(Vec::new())
    }
    fn commit(self, _: u64, _: u64) -> DurableCommitOutcome {
        DurableCommitOutcome::NotPublished
    }
}

#[cfg(test)]
mod application_cases {
    use super::*;
    use std::collections::BTreeMap;
    use std::fs;
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    struct Corpus {
        dir: PathBuf,
        path: PathBuf,
    }
    impl Corpus {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let dir = std::env::temp_dir().canonicalize().unwrap().join(format!(
                "ottto-import-cases-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
            let parent = dir.join("a".repeat(64));
            fs::DirBuilder::new().mode(0o700).create(&parent).unwrap();
            Self {
                path: parent.join("claude_code-synthetic-scan-index.json"),
                dir,
            }
        }
        fn binding(&self) -> super::super::super::scan_index_persistence::Binding {
            super::super::super::scan_index_integration::scan_index_storage_binding(&self.path)
                .unwrap()
        }
        fn sharded(&self) -> BTreeMap<String, String> {
            let fixture: serde_json::Value = serde_json::from_str(include_str!(
                "../../../tests/fixtures/scan_index/real-shaped-v1.json"
            ))
            .unwrap();
            fs::write(&self.path, fixture["root"].as_str().unwrap()).unwrap();
            fs::set_permissions(&self.path, fs::Permissions::from_mode(0o600)).unwrap();
            let shards = fence::sibling(&self.path, ".shards");
            fs::DirBuilder::new().mode(0o700).create(&shards).unwrap();
            let mut out = BTreeMap::new();
            for (name, value) in fixture["payloads"].as_object().unwrap() {
                let text = value.as_str().unwrap();
                fs::write(shards.join(name), text).unwrap();
                fs::set_permissions(shards.join(name), fs::Permissions::from_mode(0o600)).unwrap();
                out.insert(name.clone(), text.into());
            }
            out
        }
        fn store(&self) -> sqlite::Sqlite {
            let mut db =
                sqlite::Sqlite::create_import(&self.dir.join("proof.v2.sqlite.import")).unwrap();
            db.path_extractor(kinds::private_paths);
            db.reference_extractor(kinds::references);
            db.control(
                "identity",
                &Identity {
                    format: FORMAT,
                    db_id: "synthetic-proof".into(),
                    binding: self.binding(),
                    fence_generation: 0,
                },
            )
            .unwrap();
            db.control("generation", &0_u64).unwrap();
            db
        }
    }
    impl Drop for Corpus {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.dir);
        }
    }

    /// [format] composed import advances once and seals owned progress before final path exists.
    #[test]
    fn composed_import_advances_once_and_seals_owned_progress_before_final_path_exists() {
        for generation in [0_u64, 41] {
            let c = Corpus::new();
            let index = ScanIndex {
                generation,
                ..Default::default()
            };
            ottto_core::write_owner_only_file_atomic(&c.path, &serde_json::to_vec(&index).unwrap())
                .unwrap();
            let mut original = Original::read(&c.path).unwrap();
            original.capture_progress(&c.path).unwrap();
            original.preserve(&c.path).unwrap();
            let identity = Identity {
                format: FORMAT,
                db_id: "composed-import".into(),
                binding: c.binding(),
                fence_generation: generation + 1,
            };
            let mut db =
                sqlite::Sqlite::create_import(&fence::sibling(&c.path, ".v2.sqlite.import"))
                    .unwrap();
            db.path_extractor(kinds::private_paths);
            db.reference_extractor(kinds::references);
            db.control("identity", &identity).unwrap();
            db.control("generation", &generation).unwrap();
            let verified = ClaudeMapper
                .import_graph(&mut db, &index, Some(&original))
                .unwrap();
            assert_eq!(
                index.generation, generation,
                "unpublished input is unchanged"
            );
            assert_eq!(
                db.read_control::<u64>("generation").unwrap(),
                Some(generation + 1)
            );
            assert_eq!(verified.presence, original.presence);
            let (mut loaded, _) = kinds::hydrate(&mut db, c.binding()).unwrap();
            assert_eq!(loaded.generation, generation + 1);
            loaded.generation = generation;
            assert_eq!(
                serde_json::to_vec(&loaded).unwrap(),
                serde_json::to_vec(&index).unwrap()
            );
            // Capture and verify on the import snapshot, before final DB exists.
            original.seal_progress(&c.path, &identity, &mut db).unwrap();
            original.seal_progress(&c.path, &identity, &mut db).unwrap();
            let receipt = fs::read(fence::sibling(&c.path, ".v2-ack-receipt")).unwrap();
            assert!(!fence::sibling(&c.path, ".v2.sqlite").exists());
            db.finish_import().unwrap();
            let mut proposed = identity.clone();
            proposed.db_id = "different-attempt".into();
            assert_eq!(original.retry_identity(proposed).unwrap(), identity);
            fence::cleanup_unpublished(&c.path, false).unwrap();
            assert_eq!(
                fs::read(fence::sibling(&c.path, ".v2-ack-receipt")).unwrap(),
                receipt,
                "failed-import companion custody survives ordinary orphan cleanup"
            );
        }
    }

    /// [format] real-data traversal admission: 3 MiB imports byte-equal in chunks;
    /// over-cap JSON refuses before publication, on expansion and on fenced save.
    #[test]
    fn large_traversal_import_roundtrips_and_above_cap_refuses() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../../tests/fixtures/scan_index/real-shaped-v1.json"
        ))
        .unwrap();
        for target in [3 * 1024 * 1024, 16 * 1024 * 1024 + 1] {
            let c = Corpus::new();
            let mut index = ScanIndex {
                traversal: serde_json::from_value(fixture["logical"]["traversal"].clone()).unwrap(),
                ..Default::default()
            };
            let traversal = index.traversal.as_mut().unwrap();
            traversal.observed_index_keys = (0..target / 133 - 20)
                .map(|n| format!("synthetic-{n:0120}"))
                .collect();
            let len = serde_json::to_vec(traversal).unwrap().len();
            traversal
                .context_fingerprint
                .push_str(&"x".repeat(target - len));
            let expected = serde_json::to_vec(&index.traversal).unwrap();
            assert_eq!(expected.len(), target);
            let original_bytes = serde_json::to_vec(&index).unwrap();
            ottto_core::write_owner_only_file_atomic(&c.path, &original_bytes).unwrap();
            let progress = serde_json::to_vec(&serde_json::json!({
                "schema_version": 3, "generation": 0,
                "destination_namespace_hash": c.binding().namespace_hash
            }))
            .unwrap();
            let progress_path =
                crate::snapshot_sync::with_state_v2_progress_lock(&c.path, |path| {
                    ottto_core::write_owner_only_file_atomic(path, &progress)?;
                    Ok(path.to_owned())
                })
                .unwrap();
            let mut original = Original::read(&c.path).unwrap();
            let identity = Identity {
                format: FORMAT,
                db_id: "large-traversal".into(),
                binding: c.binding(),
                fence_generation: 1,
            };
            let mut db =
                sqlite::Sqlite::create_import(&fence::sibling(&c.path, ".v2.sqlite.import"))
                    .unwrap();
            db.path_extractor(kinds::private_paths);
            db.reference_extractor(kinds::references);
            db.control("identity", &identity).unwrap();
            db.control("generation", &0_u64).unwrap();
            let result = ClaudeMapper.import_graph(&mut db, &index, Some(&original));
            let key = mapper::key("scan_state.traversal", "", 0).unwrap();
            if target > 16 * 1024 * 1024 {
                let error = result.err().unwrap();
                assert!(error.to_string().contains("state_v2_value_admission"));
                let compressed = codec::encode(&expected).unwrap();
                assert!(compressed.len() < 1024 * 1024);
                assert_eq!(
                    codec::expand(&compressed, value_cap(&key))
                        .unwrap_err()
                        .to_string(),
                    "state_v2_value_admission"
                );
                assert_eq!(fs::read(&c.path).unwrap(), original_bytes);
                assert_eq!(fs::read(&progress_path).unwrap(), progress);
                assert!(!fence::sibling(&c.path, ".v2.sqlite").exists());
                continue;
            }
            result.unwrap();
            let mut tx = db.begin(TxnMode::Read).unwrap();
            let header = tx.get(&key).unwrap().unwrap();
            assert!(header.parts > 0);
            let stored = mapper::bytes(&mut tx, &header).unwrap();
            assert_eq!(codec::expand(&stored, value_cap(&key)).unwrap(), expected);
            drop(tx);
            let restored = ClaudeMapper.hydrate_context(&mut db).unwrap().0;
            assert_eq!(serde_json::to_vec(&restored.traversal).unwrap(), expected);
            original.capture_progress(&c.path).unwrap();
            original.preserve(&c.path).unwrap();
            original
                .publish_import(&c.path, &identity, db, &mut false)
                .unwrap();
            let _lock = super::super::super::CheckpointLock::acquire(&c.path).unwrap();
            let mut current = super::super::runtime::load_locked(&c.path, None, true)
                .unwrap()
                .0
                .unwrap();
            let fence_bytes = fs::read(&c.path).unwrap();
            current.traversal.as_mut().unwrap().context_fingerprint = "x".repeat(16 * 1024 * 1024);
            let error =
                super::super::runtime::save_locked(&c.path, &mut current, false, None, true)
                    .unwrap_err();
            // Value admission is save pressure: the paced named hold, not DbUnavailable.
            assert_eq!(error.downcast_ref::<Hold>(), Some(&Hold::SaveCeiling));
            let reloaded = super::super::runtime::load_locked(&c.path, None, true)
                .unwrap()
                .0
                .unwrap();
            assert_eq!(reloaded.generation, 1);
            assert_eq!(serde_json::to_vec(&reloaded.traversal).unwrap(), expected);
            assert_eq!(fs::read(&c.path).unwrap(), fence_bytes);
            assert_eq!(fs::read(&progress_path).unwrap(), progress);
        }
    }

    /// [format] import publication holds progress owner and reopens real claude mapper at new generation.
    #[test]
    fn import_publication_holds_progress_owner_and_reopens_real_claude_mapper_at_new_generation() {
        let c = Corpus::new();
        let index = ScanIndex {
            generation: 9,
            ..Default::default()
        };
        ottto_core::write_owner_only_file_atomic(&c.path, &serde_json::to_vec(&index).unwrap())
            .unwrap();
        let mut original = Original::read(&c.path).unwrap();
        original.capture_progress(&c.path).unwrap();
        original.preserve(&c.path).unwrap();
        let identity = Identity {
            format: FORMAT,
            db_id: "real-publication".into(),
            binding: c.binding(),
            fence_generation: 10,
        };
        let mut db =
            sqlite::Sqlite::create_import(&fence::sibling(&c.path, ".v2.sqlite.import")).unwrap();
        db.path_extractor(kinds::private_paths);
        db.reference_extractor(kinds::references);
        db.control("identity", &identity).unwrap();
        db.control("generation", &9_u64).unwrap();
        ClaudeMapper
            .import_graph(&mut db, &index, Some(&original))
            .unwrap();
        original
            .progress
            .as_ref()
            .unwrap()
            .with_sealed_import(&c.path, &identity, db, |db| {
                assert!(
                    crate::snapshot_sync::with_state_v2_progress_lock(&c.path, |_| Ok(())).is_err(),
                    "the post-seal callback still owns the progress lock"
                );
                db.finish_import()?;
                original.unchanged()?;
                fence::publish(&c.path, &identity, &mut false)
            })
            .unwrap();
        let _lock = super::super::super::CheckpointLock::acquire(&c.path).unwrap();
        let loaded = super::super::runtime::load_locked(
            &c.path,
            None,
            super::super::runtime::published(&c.path).unwrap(),
        )
        .unwrap()
        .0
        .unwrap();
        assert_eq!(loaded.generation, 10);
        assert!(loaded.v2().persistence_v2.is_some());
    }

    /// [format] original progress requires owner and unchanged bytes and baseline.
    #[test]
    fn original_progress_requires_owner_and_unchanged_bytes_and_baseline() {
        let c = Corpus::new();
        let progress_path = c
            .path
            .with_file_name("claude_code-synthetic-scan-index-upload-progress.json");
        let bytes = serde_json::to_vec(&serde_json::json!({
            "schema_version":3, "generation":7, "destination_namespace_hash":c.binding().namespace_hash,
            "opaque_extension":{"exact":"bytes"}
        })).unwrap();
        ottto_core::write_owner_only_file_atomic(&progress_path, &bytes).unwrap();
        let mut original = Original::read(&c.path).unwrap();
        original.capture_progress(&c.path).unwrap();
        let identity = Identity {
            format: FORMAT,
            db_id: "owned-import".into(),
            binding: c.binding(),
            fence_generation: 1,
        };
        // An existing companion belongs to the exact original owner, not a name.
        let recovery = super::super::ack::ProgressRecovery::seal_import(
            identity.clone(),
            1,
            &c.path,
            Some(&bytes),
        )
        .unwrap();
        drop(recovery);
        assert_eq!(original.retry_identity(identity.clone()).unwrap(), identity);
        let mut changed = bytes.clone();
        changed.push(b' ');
        ottto_core::write_owner_only_file_atomic(&progress_path, &changed).unwrap();
        assert!(original.retry_identity(identity.clone()).is_err());
        ottto_core::write_owner_only_file_atomic(&progress_path, &bytes).unwrap();
        let foreign = serde_json::to_vec(
            &serde_json::json!({"schema_version":3,"destination_namespace_hash":"b".repeat(64)}),
        )
        .unwrap();
        ottto_core::write_owner_only_file_atomic(&progress_path, &foreign).unwrap();
        assert!(super::super::ack::OriginalProgress::capture(&c.path).is_err());
        assert_eq!(fs::read(&progress_path).unwrap(), foreign);
        assert!(!fence::sibling(&c.path, ".v2.sqlite").exists());
    }

    /// [format] original presence precedes normalization and inventory has no write side effects.
    #[test]
    fn original_presence_precedes_normalization_and_inventory_has_no_write_side_effects() {
        let c = Corpus::new();
        let bytes = br#"{"schema_version":2,"generation":0,"files":{},"claude_history_cutoff_unix_seconds":null,"accepted_snapshot_fingerprints":[]}"#;
        fs::write(&c.path, bytes).unwrap();
        let original = Original::read(&c.path).unwrap();
        assert!(original.presence["claude_history_cutoff_unix_seconds"]);
        assert!(original.presence["accepted_snapshot_fingerprints"]);
        assert!(!original.presence.contains_key("growth_retention"));
        assert_eq!(fs::read_dir(c.path.parent().unwrap()).unwrap().count(), 1);
        original.unchanged().unwrap();
        fs::write(&c.path, b"changed-original").unwrap();
        assert!(original.unchanged().is_err());
        assert_eq!(fs::read(&c.path).unwrap(), b"changed-original");
    }

    /// [format] desktop inventory conversion keeps original presence without digest custody.
    #[test]
    fn desktop_inventory_conversion_keeps_original_presence_without_digest_custody() {
        for inventory in [
            None,
            Some(serde_json::Value::Null),
            Some(serde_json::json!("a".repeat(64))),
        ] {
            let c = Corpus::new();
            let mut value = serde_json::json!({"schema_version":2,"generation":0,"files":{}});
            if let Some(inventory) = &inventory {
                value["claude_desktop_store_inventory"] = inventory.clone();
            }
            let bytes = serde_json::to_vec(&value).unwrap();
            fs::write(&c.path, &bytes).unwrap();
            let original = Original::read(&c.path).unwrap();
            assert_eq!(
                original.presence["claude_desktop_store_inventory"],
                inventory.is_some()
            );
            let mut index = super::super::super::lenient_decode::read(
                std::io::Cursor::new(&bytes),
                "load",
                "unattributed",
            )
            .unwrap();
            let mut db = c.store();
            let mut cx = KindCx::default();
            cx.binding = Some(c.binding());
            cx.presence = original.presence.clone();
            let mut tx = db.begin(TxnMode::Write).unwrap();
            kinds::populate(&index, &mut tx, &mut cx).unwrap();
            assert_eq!(tx.commit(0, 1), DurableCommitOutcome::Committed(1));
            index.generation = 1;
            let mut tx = db.begin(TxnMode::Read).unwrap();
            let verified = verify_normalized(&mut tx, &index, &original, c.binding()).unwrap();
            assert_eq!(verified.presence, original.presence);
            drop(tx);
            let (restored, loaded) = kinds::hydrate(&mut db, c.binding()).unwrap();
            assert_eq!(
                loaded.presence.get("claude_desktop_store_inventory"),
                original.presence.get("claude_desktop_store_inventory")
            );
            assert_eq!(restored.claude_desktop_store_inventory, None);
            assert_eq!(
                serde_json::to_vec(&restored).unwrap(),
                serde_json::to_vec(&index).unwrap()
            );
            assert_eq!(fs::read(&c.path).unwrap(), bytes);
        }
    }
    /// [format] duplicate unknown and invalid escaped originals pause before baseline.
    #[test]
    fn duplicate_unknown_and_invalid_escaped_originals_pause_before_baseline() {
        for bytes in [
            br#"{"schema_version":2,"files":{},"future_money":{"n":1}}"#.as_slice(),
            br#"{"schema_version":2,"files":{},"files":{}}"#,
            br#"{"schema_version":2,"files":{},"upload_context_fingerprint":"\q"}"#,
            br#"{"schema_version":2,"files":{},"upload_context_fingerprint":"\ud800"}"#,
            b"{\"schema_version\":2,\"files\":{},\"upload_context_fingerprint\":\"\xff\"}",
            br#"{"schema_version":2,"files":{},"claude_request_census":{"~lost":{}}}"#,
        ] {
            let c = Corpus::new();
            fs::write(&c.path, bytes).unwrap();
            assert!(Original::read(&c.path).is_err());
            assert_eq!(fs::read(&c.path).unwrap(), bytes);
            assert!(!fence::sibling(&c.path, ".v1-readonly").exists());
            assert!(!fence::sibling(&c.path, ".v2.sqlite.import").exists());
        }
    }

    /// [format] all referenced shards are inventoried and preserved without unreferenced files.
    #[test]
    fn all_referenced_shards_are_inventoried_and_preserved_without_unreferenced_files() {
        let c = Corpus::new();
        let payloads = c.sharded();
        let shards = fence::sibling(&c.path, ".shards");
        fs::write(shards.join("unreferenced.json"), b"not-authority").unwrap();
        let original = Original::read(&c.path).unwrap();
        assert_eq!(original.files.len(), payloads.len() + 1);
        assert!(original.presence["claude_account_family_pending"]);
        assert!(!original.presence.contains_key("growth_retention"));
        original.preserve(&c.path).unwrap();
        assert_eq!(
            fs::read(fence::sibling(&c.path, ".v1-readonly")).unwrap(),
            fs::read(&c.path).unwrap()
        );
        for (name, bytes) in &payloads {
            assert_eq!(
                fs::read(fence::sibling(&c.path, ".v1-readonly.shards").join(name)).unwrap(),
                bytes.as_bytes()
            );
        }
        assert!(!fence::sibling(&c.path, ".v1-readonly.shards")
            .join("unreferenced.json")
            .exists());
        let last = payloads.keys().find(|k| k.starts_with("census-")).unwrap();
        fs::remove_file(shards.join(last)).unwrap();
        assert!(Original::read(&c.path).is_err());
        assert!(original.unchanged().is_err());
    }

    /// [format] fifo referenced shard refuses without blocking the owner lock.
    #[test]
    fn fifo_referenced_shard_refuses_without_blocking_the_owner_lock() {
        use std::os::unix::{ffi::OsStrExt, fs::OpenOptionsExt};
        let c = Corpus::new();
        let payloads = c.sharded();
        let name = payloads
            .keys()
            .find(|name| name.starts_with("census-"))
            .unwrap();
        let fifo = fence::sibling(&c.path, ".shards").join(name);
        fs::remove_file(&fifo).unwrap();
        let name = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        let path = c.path.clone();
        let (send, receive) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || send.send(Original::read(&path)).unwrap());
        let result = receive.recv_timeout(Duration::from_secs(5));
        // Unblock a regressed reader before joining, so failure stays bounded
        // and leaves no thread holding the synthetic corpus open.
        let unblock = if result.is_err() {
            fs::OpenOptions::new()
                .write(true)
                .custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW)
                .open(&fifo)
                .ok()
        } else {
            None
        };
        worker.join().unwrap();
        drop(unblock);
        assert_eq!(
            result
                .expect("inventory blocked on a nonregular shard")
                .unwrap_err(),
            Pause::UnsafeParent
        );
        assert!(!fence::sibling(&c.path, ".v1-readonly").exists());
    }

    /// [format] unknown nested field in final shard pauses even with valid descriptor digest.
    #[test]
    fn unknown_nested_field_in_final_shard_pauses_even_with_valid_descriptor_digest() {
        use sha2::Digest;
        let c = Corpus::new();
        c.sharded();
        let mut root: serde_json::Value =
            serde_json::from_slice(&fs::read(&c.path).unwrap()).unwrap();
        let object = root["objects"].as_array_mut().unwrap().last_mut().unwrap();
        let body = br#"{"synthetic-file":{"v":1,"future_money":{"n":1}}}"#;
        let slot: super::super::super::scan_index_persistence::Slot =
            serde_json::from_value(object["slot"].clone()).unwrap();
        let mut hash = sha2::Sha256::new();
        hash.update(b"ottto.scan-index.storage.v1\0object\0");
        hash.update(serde_json::to_vec(&(c.binding(), slot)).unwrap());
        hash.update([0]);
        hash.update(body);
        hash.update((body.len() as u64).to_le_bytes());
        let digest = hash
            .finalize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        object["digest"] = digest.clone().into();
        object["bytes"] = body.len().into();
        fs::write(
            fence::sibling(&c.path, ".shards").join(format!("census-9c-{digest}.json")),
            body,
        )
        .unwrap();
        fs::write(&c.path, serde_json::to_vec(&root).unwrap()).unwrap();
        assert_eq!(Original::read(&c.path).unwrap_err(), Pause::UnknownClass);
        assert!(!fence::sibling(&c.path, ".v1-readonly").exists());
    }

    /// [format] f7 baseline failures remain unpublished and keep original authority.
    #[test]
    fn f7_baseline_failures_remain_unpublished_and_keep_original_authority() {
        for blocked in [".v1-readonly", ".v1-readonly.shards"] {
            let c = Corpus::new();
            c.sharded();
            let original = Original::read(&c.path).unwrap();
            let bytes = fs::read(&c.path).unwrap();
            fs::create_dir(fence::sibling(&c.path, blocked)).unwrap();
            assert!(original.preserve(&c.path).is_err());
            assert_eq!(fs::read(&c.path).unwrap(), bytes);
            assert!(!fence::evidence(&c.path).unwrap());
            fence::cleanup_unpublished(&c.path, false).unwrap();
            original.unchanged().unwrap();
            original.preserve(&c.path).unwrap();
        }
    }

    /// [format] normalized readback checks all groups raw custody presence and extra rows.
    #[test]
    fn normalized_readback_checks_all_groups_raw_custody_presence_and_extra_rows() {
        let c = Corpus::new();
        fs::write(&c.path, br#"{"schema_version":2,"generation":0,"files":{},"accepted_snapshot_fingerprints":[]}"#).unwrap();
        let original = Original::read(&c.path).unwrap();
        let mut index = ScanIndex::default();
        index
            .decode_holds
            .v2_insert(
                "claude_account_family_pending",
                "synthetic-raw".into(),
                br#"{ "retry_after_unix_seconds": "bad", "text": "\u0061" }"#.to_vec(),
                None,
                128,
            )
            .unwrap();
        index.decode_holds.v2_finish((u128::MAX, 7));
        index.accepted_snapshot_fingerprints.insert("f".repeat(64));
        let mut db = c.store();
        let mut cx = KindCx::default();
        cx.binding = Some(c.binding());
        cx.presence = original.presence.clone();
        let mut tx = db.begin(TxnMode::Write).unwrap();
        kinds::populate(&index, &mut tx, &mut cx).unwrap();
        assert_eq!(tx.commit(0, 1), DurableCommitOutcome::Committed(1));
        index.generation = 1;
        let mut tx = db.begin(TxnMode::Read).unwrap();
        let verified = verify_normalized(&mut tx, &index, &original, c.binding()).unwrap();
        assert_eq!(verified.presence, original.presence);
        drop(tx);
        let (restored, loaded) = kinds::hydrate(&mut db, c.binding()).unwrap();
        assert!(restored.decode_holds.same_as(&index.decode_holds));
        assert_eq!(restored.decode_holds.v2_provenance(), (u128::MAX, 7));
        assert_eq!(loaded.presence, original.presence);
        assert_eq!(
            serde_json::to_vec(&restored).unwrap(),
            serde_json::to_vec(&index).unwrap()
        );
        let mut tx = db.begin(TxnMode::Write).unwrap();
        tx.put(RowInput {
            key: &RowKey::record("file.confirmed_empty", b"orphan", 0).unwrap(),
            fixed: &Fixed::None,
            value_version: 1,
            value: &control_json(&true).unwrap(),
        })
        .unwrap();
        assert_eq!(tx.commit(1, 2), DurableCommitOutcome::Committed(2));
        index.generation = 2;
        let mut tx = db.begin(TxnMode::Read).unwrap();
        assert!(verify_normalized(&mut tx, &index, &original, c.binding()).is_err());
    }
    /// [format] f4 original unbound authority repair preserves freeze raw bytes and provenance.
    #[test]
    fn f4_original_unbound_authority_repair_preserves_freeze_raw_bytes_and_provenance() {
        let c = Corpus::new();
        let mut seed = ScanIndex::default();
        seed.insert_retry_pending_claude_authority_for_test("family");
        seed.accepted_snapshot_fingerprints.insert("f".repeat(64));
        let mut value = serde_json::to_value(&seed).unwrap();
        value["claude_usage_family_witnesses"]["family"]["legacy_owner_roots"] =
            serde_json::json!(["different-owner"]);
        value["claude_usage_authority_quarantine"]["family"]["retry_after_unix_seconds"] =
            serde_json::json!("mistyped-original");
        let bytes = serde_json::to_vec(&value).unwrap();
        fs::write(&c.path, &bytes).unwrap();
        // Import deliberately refuses mistyped original classes before a fence.
        // Already-authenticated raw holds still roundtrip through the mapper.
        assert_eq!(Original::read(&c.path).unwrap_err(), Pause::UnknownClass);
        assert_eq!(fs::read(&c.path).unwrap(), bytes);
        assert!(!fence::sibling(&c.path, ".v2.sqlite").exists());
        let original = Original {
            presence: original_presence(bytes.as_slice()).unwrap(),
            ..Default::default()
        };
        // The production v1 loader owns all original-span repair/freeze ordering.
        let mut normalized = ScanIndex::load(&c.path).unwrap();
        assert!(normalized.decode_holds_family("family"));
        assert!(normalized.claude_usage_authority_quarantine.is_empty());
        assert!(normalized.claude_usage_family_witnesses.is_empty());
        assert_eq!(normalized.decode_holds.v2_provenance().1, 0);
        let mut db = c.store();
        let mut cx = KindCx::default();
        cx.binding = Some(c.binding());
        cx.presence = original.presence.clone();
        let mut tx = db.begin(TxnMode::Write).unwrap();
        kinds::populate(&normalized, &mut tx, &mut cx).unwrap();
        assert_eq!(tx.commit(0, 1), DurableCommitOutcome::Committed(1));
        normalized.generation = 1;
        let (restored, loaded) = kinds::hydrate(&mut db, c.binding()).unwrap();
        assert_eq!(loaded.presence, original.presence);
        assert!(restored.decode_holds.same_as(&normalized.decode_holds));
        assert_eq!(
            restored.decode_holds.v2_provenance(),
            normalized.decode_holds.v2_provenance()
        );
        assert_eq!(
            restored.accepted_snapshot_fingerprints,
            normalized.accepted_snapshot_fingerprints
        );
        assert_eq!(
            serde_json::to_vec(&restored).unwrap(),
            serde_json::to_vec(&normalized).unwrap()
        );
        let mut tx = db.begin(TxnMode::Read).unwrap();
        verify_normalized(&mut tx, &normalized, &original, c.binding()).unwrap();
    }

    /// [format] complete real shaped money graph passes streaming readback with shared membership.
    #[test]
    fn complete_real_shaped_money_graph_passes_streaming_readback_with_shared_membership() {
        let c = Corpus::new();
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../../tests/fixtures/scan_index/real-shaped-v1.json"
        ))
        .unwrap();
        let mut index: ScanIndex = serde_json::from_value(fixture["logical"].clone()).unwrap();
        index.generation = 0;
        let raw = serde_json::to_vec(&index).unwrap();
        fs::write(&c.path, &raw).unwrap();
        let original = Original::read(&c.path).unwrap();
        let mut db = c.store();
        let mut cx = KindCx::default();
        cx.binding = Some(c.binding());
        cx.presence = original.presence.clone();
        let mut tx = db.begin(TxnMode::Write).unwrap();
        kinds::populate(&index, &mut tx, &mut cx).unwrap();
        assert_eq!(tx.commit(0, 1), DurableCommitOutcome::Committed(1));
        index.generation = 1;
        let mut tx = db.begin(TxnMode::Read).unwrap();
        let verified = verify_normalized(&mut tx, &index, &original, c.binding()).unwrap();
        assert_eq!(verified.presence, original.presence);
        assert_eq!(verified.binding, Some(c.binding()));
    }
}

#[cfg(test)]
mod codec_mapper_regressions {
    use super::*;
    /// [format] read back counts aggregated references to repeated empty evidence.
    #[test]
    fn read_back_counts_aggregated_references_to_repeated_empty_evidence() {
        let scratch = crate::test_scratch::ScratchDir::canonical("codec-ref-readback");
        let index: ScanIndex = serde_json::from_value(serde_json::json!({
            "schema_version":2,"files":{},"claude_usage_family_pending":{"f":{
                "census_window_end":"A","invalid":false,
                "member_request_id_hashes":{"a":[],"b":[]}
            }}
        }))
        .unwrap();
        let mut db = money_test_support::populate(
            &scratch.join("state.v2.sqlite.import"),
            &index,
            Default::default(),
        );
        let original = Original::default();
        let mut tx = db.begin(TxnMode::Read).unwrap();
        verify_normalized_at(&mut tx, &index, &original, money_test_support::binding(), 1).unwrap();
    }
}
