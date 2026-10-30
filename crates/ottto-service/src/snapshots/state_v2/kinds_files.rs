//! File-owned v1 state. No acquisition, settlement or retirement decisions.
//! The production mapper remains disabled until all groups and R1 are wired.
#![allow(dead_code)] // The integrator installs these adapters after parity proof.
use super::super::{ClaudeDesktopTitleIndexEntry, ScanIndexEntry, TerminalJsonlDisposition};
use super::*;
use anyhow::{ensure, Context};
use serde::de::DeserializeOwned;
use std::collections::{BTreeMap, BTreeSet};

pub(super) const KINDS: &[&str] = &[
    "file.progress",
    "file.receipt",
    "file.terminal",
    "file.confirmed_empty",
    "file.entities",
    "file.growth_retention",
    "accepted.activity",
    "v1_field.claude_desktop_title_files",
    "resume.checkpoint",
];
const VERSION: u32 = 1;
const PAGE: usize = 128;
const ENTITY_BUCKETS: u64 = 256;

// Unlike ScanIndexEntry's v1 containment decoder, this storage codec does not
// coerce unknown/malformed Codex spellings. Every typed field is explicit;
// receipts are independent rows, never inferred from a side-map file key.
fn clone_field<T: Clone>(value: &T) -> T {
    value.clone()
}
macro_rules! entry_wire {
    ($($name:ident: $ty:ty),* $(,)?) => {
        #[derive(Serialize, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct EntryWire { $($name: $ty),* }
        impl From<&ScanIndexEntry> for EntryWire {
            fn from(entry: &ScanIndexEntry) -> Self {
                Self { $($name: clone_field(&entry.$name)),* }
            }
        }
        impl EntryWire {
            fn entry(self) -> ScanIndexEntry {
                ScanIndexEntry { $($name: self.$name),*, upload_context_receipt: None }
            }
        }
    }
}
entry_wire! {
    size_bytes: u64, modified_unix_seconds: u64, modified_unix_nanos: Option<u64>,
    source_file_fingerprint: String, last_snapshot_fingerprint: Option<String>,
    last_upload_body_witness: Option<String>, effective_upload_body_witness_revision: u64,
    scan_identity_version: Option<String>, codex_joined_member_set: Option<String>,
    codex_captured_joined_member_set: Option<String>, codex_protected_owner: Option<String>,
    codex_applied_tier_receipt: Option<super::super::codex_file_join::AppliedTierReceipt>,
    codex_applied_tier_receipt_required: bool,
    codex_captured_tier_receipt: Option<super::super::codex_file_join::AppliedTierReceipt>,
    codex_captured_tier_receipt_required: bool, codex_captured_uncommitted: bool,
    codex_counting_v2: bool, codex_counting_owner: Option<String>,
    opened_changed_nanos: u64, opened_birth_nanos: u64,
}

fn hash(value: &str) -> Option<[u8; 32]> {
    let bytes = packed::hash_string(value).ok()?;
    (bytes.first() == Some(&1)).then(|| bytes[1..].try_into().expect("packed hash width"))
}
fn projection(entry: &ScanIndexEntry) -> Fixed {
    Fixed::File {
        size: entry.size_bytes,
        mtime_s: entry.modified_unix_seconds,
        mtime_ns: entry.modified_unix_nanos,
        ctime_ns: entry.opened_changed_nanos,
        birth_ns: entry.opened_birth_nanos,
        witness_rev: entry.effective_upload_body_witness_revision,
        flags: u64::from(entry.last_snapshot_fingerprint.is_some())
            | (u64::from(entry.last_upload_body_witness.is_some()) << 1)
            | (u64::from(entry.scan_identity_version.is_some()) << 2),
        source_fp: hash(&entry.source_file_fingerprint),
        last_snapshot_fp: entry.last_snapshot_fingerprint.as_deref().and_then(hash),
        body_witness: entry.last_upload_body_witness.as_deref().and_then(hash),
    }
}

/// Bounds both encoded and expanded JSON before allocation. A larger logical
/// unit must be withheld by the integration preflight; never truncate a value.
struct Bounded(Vec<u8>);
impl Write for Bounded {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if self
            .0
            .len()
            .checked_add(bytes.len())
            .map_or(true, |n| n > MUTABLE_VALUE_BYTES as usize)
        {
            return Err(std::io::Error::other("state_v2_files_value_admission"));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
fn encoded(value: &impl Serialize) -> Result<Vec<u8>> {
    let mut out = Bounded(Vec::new());
    packed::Json(value).write(&mut out)?;
    Ok(out.0)
}
fn decoded<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    let mut json = Bounded(Vec::new());
    packed::decode(bytes, &mut json)?;
    Ok(serde_json::from_slice(&json.0)?)
}
fn typed<T: DeserializeOwned + Serialize>(bytes: &[u8]) -> Result<T> {
    let value: T = decoded(bytes)?;
    ensure!(
        encoded(&value)? == bytes,
        "state_v2_files_noncanonical_value"
    );
    Ok(value)
}
struct Bytes<'a>(&'a [u8]);
impl Value for Bytes<'_> {
    fn write(&self, out: &mut dyn Write) -> Result<()> {
        out.write_all(self.0)?;
        Ok(())
    }
}
fn key(kind: &str, path: &str, position: u64) -> Result<RowKey> {
    let key = RowKey::record(kind, path.as_bytes(), position)?;
    admit_key(&key)?;
    Ok(key)
}
fn put(
    txn: &mut dyn Transaction,
    kind: &str,
    path: &str,
    position: u64,
    fixed: &Fixed,
    value: &impl Serialize,
) -> Result<()> {
    let key = key(kind, path, position)?;
    let bytes = encoded(value)?;
    if let Some(old) = txn.get(&key)? {
        if old.fixed == *fixed
            && old.value_version == VERSION
            && txn.value_matches(&old, &Bytes(&bytes))?
        {
            return Ok(());
        }
    }
    txn.put(RowInput {
        key: &key,
        fixed,
        value_version: VERSION,
        value: &Bytes(&bytes),
    })?;
    Ok(())
}
fn rows(
    txn: &mut dyn Transaction,
    kind: &str,
    mut visit: impl FnMut(&Header, &str, &[u8]) -> Result<()>,
) -> Result<()> {
    let kind = RecordKind::parse(kind)?;
    let mut after = None;
    loop {
        let page = txn.scan_kind(&kind, after.as_ref(), PAGE)?;
        if page.is_empty() {
            break;
        }
        for header in &page {
            ensure!(
                header.value_version == VERSION,
                "state_v2_files_value_version"
            );
            let RowKey::Record { key_bytes, .. } = &header.key else {
                anyhow::bail!("state_v2_files_key");
            };
            let path = std::str::from_utf8(key_bytes)?;
            let mut bytes = Bounded(Vec::new());
            txn.read_value(header, &mut bytes)?;
            visit(header, path, &bytes.0)?;
        }
        after = page.last().map(|header| header.key.clone());
    }
    Ok(())
}
fn singleton(header: &Header) -> Result<()> {
    ensure!(
        matches!(&header.key, RowKey::Record { position: 0, .. }),
        "state_v2_files_position"
    );
    Ok(())
}
fn map<T: Serialize>(
    prev: &BTreeMap<String, T>,
    next: &BTreeMap<String, T>,
    kind: &str,
    txn: &mut dyn Transaction,
) -> Result<()> {
    for path in prev.keys().filter(|path| !next.contains_key(*path)) {
        txn.delete(&key(kind, path, 0)?)?;
    }
    for (path, value) in next {
        if prev.get(path).map(encoded).transpose()?.as_deref() != Some(encoded(value)?.as_slice()) {
            put(txn, kind, path, 0, &Fixed::None, value)?;
        }
    }
    Ok(())
}
fn read_map<T: DeserializeOwned + Serialize>(
    txn: &mut dyn Transaction,
    kind: &str,
) -> Result<BTreeMap<String, T>> {
    let mut result = BTreeMap::new();
    rows(txn, kind, |header, path, bytes| {
        singleton(header)?;
        ensure!(header.fixed == Fixed::None, "state_v2_files_projection");
        ensure!(
            result.insert(path.to_owned(), typed(bytes)?).is_none(),
            "state_v2_files_duplicate"
        );
        Ok(())
    })?;
    Ok(result)
}

// A stable hash partition bounds independently mutable entity sets. Position 0
// is the complete presence/ownership manifest (including Some(empty)); positions
// 1..=256 are buckets. All are published in the caller's SAME transaction.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Entities {
    buckets: BTreeSet<u64>,
    count: u64,
}
fn bucket(entity: &str) -> u64 {
    use sha2::Digest;
    u64::from(sha2::Sha256::digest(entity.as_bytes())[0]) + 1
}
fn entities(set: &BTreeSet<String>) -> BTreeMap<u64, BTreeSet<&str>> {
    let mut buckets = BTreeMap::<u64, BTreeSet<&str>>::new();
    for entity in set {
        buckets.entry(bucket(entity)).or_default().insert(entity);
    }
    buckets
}
fn entity_delta(
    prev: &BTreeMap<String, BTreeSet<String>>,
    next: &BTreeMap<String, BTreeSet<String>>,
    txn: &mut dyn Transaction,
) -> Result<()> {
    for path in prev.keys().chain(next.keys()).collect::<BTreeSet<_>>() {
        if prev.get(path) == next.get(path) {
            continue;
        }
        let old = prev.get(path).map(entities).unwrap_or_default();
        let new = next.get(path).map(entities).unwrap_or_default();
        for position in old.keys().filter(|p| !new.contains_key(p)) {
            txn.delete(&key("file.entities", path, *position)?)?;
        }
        for (position, values) in &new {
            if old.get(position) != Some(values) {
                put(txn, "file.entities", path, *position, &Fixed::None, values)?;
            }
        }
        if let Some(set) = next.get(path) {
            put(
                txn,
                "file.entities",
                path,
                0,
                &Fixed::None,
                &Entities {
                    buckets: new.keys().copied().collect(),
                    count: set.len() as u64,
                },
            )?;
        } else {
            txn.delete(&key("file.entities", path, 0)?)?;
        }
    }
    Ok(())
}
fn read_entities(txn: &mut dyn Transaction) -> Result<BTreeMap<String, BTreeSet<String>>> {
    let mut result = BTreeMap::new();
    let mut expected: Option<(String, Entities)> = None;
    let mut seen = BTreeSet::new();
    let finish = |expected: &Option<(String, Entities)>,
                  seen: &BTreeSet<u64>,
                  result: &BTreeMap<String, BTreeSet<String>>|
     -> Result<()> {
        if let Some((path, manifest)) = expected {
            ensure!(
                &manifest.buckets == seen && result[path].len() as u64 == manifest.count,
                "state_v2_entities_manifest"
            );
        }
        Ok(())
    };
    rows(txn, "file.entities", |header, path, bytes| {
        ensure!(header.fixed == Fixed::None, "state_v2_files_projection");
        let RowKey::Record { position, .. } = &header.key else {
            unreachable!()
        };
        if *position == 0 {
            finish(&expected, &seen, &result)?;
            let manifest: Entities = typed(bytes)?;
            ensure!(
                manifest
                    .buckets
                    .iter()
                    .all(|p| (1..=ENTITY_BUCKETS).contains(p)),
                "state_v2_entities_bucket"
            );
            ensure!(
                result.insert(path.to_owned(), BTreeSet::new()).is_none(),
                "state_v2_entities_duplicate"
            );
            expected = Some((path.to_owned(), manifest));
            seen.clear();
        } else {
            let (owner, manifest) = expected
                .as_ref()
                .context("state_v2_entities_missing_manifest")?;
            ensure!(
                owner == path && manifest.buckets.contains(position) && seen.insert(*position),
                "state_v2_entities_owner"
            );
            let values: BTreeSet<String> = typed(bytes)?;
            ensure!(
                !values.is_empty() && values.iter().all(|v| bucket(v) == *position),
                "state_v2_entities_bucket"
            );
            result
                .get_mut(path)
                .context("state_v2_entities_owner")?
                .extend(values);
        }
        Ok(())
    })?;
    finish(&expected, &seen, &result)?;
    Ok(result)
}

/// Exact immutable record reference. No reduction/body bytes enter SQLite.
/// `publication` commits the entire file.progress value, including raw presence;
/// the certificate, interpretation pin and scope remain R1's checked inputs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ResumeCheckpoint {
    pub record_generation: u64,
    pub record_name: String,
    pub trailer_digest: [u8; 32],
    pub file_generation: u64,
    pub committed_bytes: u64,
    pub reduction_version: u16,
    pub reduction_allowlist: [u8; 32],
    pub reduction_pin: Vec<u8>,
    pub binding: super::super::scan_index_persistence::Binding,
    pub key_digest: [u8; 32],
    pub context: [u8; 32],
    pub scope: [u8; 32],
    pub entry: [u8; 32],
    pub publication: [u8; 16],
    pub certificate: Certificate,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Certificate {
    pub device: u64,
    pub inode: u64,
    pub length: u64,
    pub modified: (i64, i64),
    pub birth_nanos: u64,
    pub sealed_offset: u64,
    pub sample_len: u32,
    pub head_sha256: [u8; 32],
    pub boundary_sha256: [u8; 32],
    pub verified_unix_seconds: u64,
    pub audit_debt_unix_seconds: Option<u64>,
}
fn files_signature(index: &ScanIndex) -> Result<[u8; 32]> {
    use sha2::Digest;
    struct Sink(sha2::Sha256);
    impl Write for Sink {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.update(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut sink = Sink(sha2::Sha256::new());
    sink.0.update(b"ottto.state-v2.files-preflight.v1\0");
    serde_json::to_writer(
        &mut sink,
        &(
            &index.files,
            &index.file_snapshot_fingerprints,
            &index.snapshot_activity_at,
            &index.confirmed_empty_files,
            &index.terminal_jsonl_dispositions,
            &index.claude_desktop_title_files,
            &index.growth_retention,
        ),
    )?;
    Ok(sink.0.finalize().into())
}
fn publication(entry: &ScanIndexEntry) -> Result<[u8; 16]> {
    use sha2::Digest;
    let mut hash = value_digest_start(VERSION);
    hash.update(encoded(&EntryWire::from(entry))?);
    Ok(integrity(hash))
}
impl ResumeCheckpoint {
    fn validate(
        &self,
        path: &str,
        entry: &ScanIndexEntry,
        generation: u64,
        binding: &super::super::scan_index_persistence::Binding,
    ) -> Result<()> {
        ensure!(&self.binding == binding, "state_v2_resume_binding");
        ensure!(
            self.record_generation > 0
                && self.record_generation == self.file_generation
                && self.file_generation <= generation
                && self.reduction_version > 0
                && !self.reduction_pin.is_empty()
                && self.reduction_pin.len() <= KEY_BYTES,
            "state_v2_resume_generation_pin"
        );
        ensure!(
            self.committed_bytes <= entry.size_bytes
                && self.certificate.length == entry.size_bytes
                && self.certificate.sealed_offset == self.committed_bytes
                && self.certificate.birth_nanos == entry.opened_birth_nanos
                && self.publication == publication(entry)?,
            "state_v2_resume_extent_entry"
        );
        ensure!(
            u64::try_from(self.certificate.modified.0).ok() == Some(entry.modified_unix_seconds)
                && (0..1_000_000_000).contains(&self.certificate.modified.1)
                && entry.modified_unix_nanos.map_or(true, |ns| {
                    entry
                        .modified_unix_seconds
                        .checked_mul(1_000_000_000)
                        .and_then(|sec| sec.checked_add(self.certificate.modified.1 as u64))
                        == Some(ns)
                })
                && u64::from(self.certificate.sample_len) == self.committed_bytes.min(4096),
            "state_v2_resume_certificate"
        );
        #[cfg(unix)]
        {
            use crate::durable_tail_store::{key_digest, DurableSource};
            let source = match binding.source {
                super::super::scan_index_persistence::Source::Claude => DurableSource::ClaudeCode,
                super::super::scan_index_persistence::Source::Codex => DurableSource::Codex,
                super::super::scan_index_persistence::Source::Pi => {
                    anyhow::bail!("state_v2_resume_source")
                }
            };
            ensure!(
                self.entry
                    == crate::durable_tail_store::entry_digest(
                        &entry.source_file_fingerprint,
                        entry.last_upload_body_witness.as_deref()
                    ),
                "state_v2_resume_entry_binding"
            );
            ensure!(
                self.key_digest == key_digest(source, path),
                "state_v2_resume_key"
            );
        }
        let digest = self
            .key_digest
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        let prefix = format!("{digest}.{}.", self.record_generation);
        let attempt = self
            .record_name
            .strip_prefix(&prefix)
            .and_then(|s| s.strip_suffix(".rec"))
            .context("state_v2_resume_name")?;
        ensure!(
            !attempt.is_empty()
                && attempt.len() <= 128
                && attempt
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'),
            "state_v2_resume_name"
        );
        Ok(())
    }
}

/// The caller supplies a source-authoritative, dependency-settled finish proof;
/// age, ACK and ordinary pass completion have no representation in this API.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum FinishReason {
    IrreversibleTerminal,
    AuthoritativeRemoval,
}
#[derive(Clone, Debug)]
pub(super) struct FinishProof {
    pub prior: ResumeCheckpoint,
    pub reason: FinishReason,
    pub source_proof: [u8; 32],
    pub settled_dependencies: [u8; 32],
}
#[derive(Default)]
pub(super) struct StagedCheckpoints {
    pub replacements: BTreeMap<String, ResumeCheckpoint>,
    pub finished: BTreeMap<String, FinishProof>,
}
/// Called BEFORE Store::begin under the source-owner lock. R1 must fsync each
/// immutable file and its directory before returning staging proof. The mapper
/// owns no filesystem handles and never implements a promote step.
pub(super) trait ResumeHooks {
    fn stage(
        &mut self,
        prev: &ScanIndex,
        next: &ScanIndex,
        current: &BTreeMap<String, ResumeCheckpoint>,
    ) -> Result<StagedCheckpoints>;
    /// Same owner lock, only after an unambiguous durable commit. R1 protects
    /// current, staging, predecessor, backup and unresolved recovery roots.
    fn post_commit(
        &mut self,
        generation: u64,
        current: &BTreeMap<String, ResumeCheckpoint>,
    ) -> Result<()>;
}
struct Prepared {
    generation: u64,
    signature: [u8; 32],
    checkpoints: BTreeMap<String, ResumeCheckpoint>,
}
#[derive(Default)]
pub(super) struct KindCxFiles {
    pub binding: Option<super::super::scan_index_persistence::Binding>,
    committed: BTreeMap<String, ResumeCheckpoint>,
    prepared: Option<Prepared>,
    ambiguous: bool,
    // Legacy populate may lack references; every hydrated/live save requires
    // fresh staging, even after the final previously protected file finishes.
    require_preflight: bool,
}
impl KindCxFiles {
    pub(super) fn checkpoints(&self) -> &BTreeMap<String, ResumeCheckpoint> {
        &self.committed
    }
    pub(super) fn preflight(
        &mut self,
        prev: &ScanIndex,
        next: &ScanIndex,
        hooks: &mut dyn ResumeHooks,
    ) -> Result<()> {
        ensure!(
            !self.ambiguous && self.prepared.is_none(),
            "state_v2_resume_reopen_required"
        );
        self.require_preflight = true;
        let binding = self.binding.as_ref().context("state_v2_resume_binding")?;
        let staged = hooks.stage(prev, next, &self.committed)?;
        let mut checkpoints = self.committed.clone();
        let finished_paths: BTreeSet<_> = staged.finished.keys().cloned().collect();
        for (path, proof) in staged.finished {
            ensure!(
                checkpoints.get(&path) == Some(&proof.prior)
                    && !staged.replacements.contains_key(&path),
                "state_v2_resume_finish_proof"
            );
            ensure!(
                proof.source_proof != [0; 32] && proof.settled_dependencies != [0; 32],
                "state_v2_resume_finish_proof"
            );
            if proof.reason == FinishReason::AuthoritativeRemoval {
                ensure!(
                    !next.files.contains_key(&path),
                    "state_v2_resume_removal_present"
                );
            }
            // Proofs are exact-reference tokens from R1/source custody, not booleans.
            checkpoints.remove(&path);
        }
        for (path, checkpoint) in staged.replacements {
            let entry = next.files.get(&path).context("state_v2_resume_orphan")?;
            checkpoint.validate(&path, entry, next.generation, binding)?;
            ensure!(
                checkpoint.file_generation == next.generation,
                "state_v2_resume_staging_generation"
            );
            if let Some(old) = self.committed.get(&path) {
                ensure!(
                    old.record_name != checkpoint.record_name || old == &checkpoint,
                    "state_v2_resume_mutable_name"
                );
                if prev.files.get(&path).map(publication).transpose()? == Some(publication(entry)?)
                {
                    ensure!(old == &checkpoint, "state_v2_resume_unchanged_replaced");
                }
            }
            checkpoints.insert(path, checkpoint);
        }
        for (path, checkpoint) in &checkpoints {
            let entry = next
                .files
                .get(path)
                .context("state_v2_resume_finish_required")?;
            checkpoint.validate(path, entry, next.generation, binding)?;
        }
        // R1 must cover every changed, still-active file, including first admission.
        for (path, entry) in &next.files {
            if prev.files.get(path).map(publication).transpose()? != Some(publication(entry)?) {
                ensure!(
                    checkpoints.contains_key(path) || finished_paths.contains(path),
                    "state_v2_resume_stage_required"
                );
            }
        }
        self.prepared = Some(Prepared {
            generation: next.generation,
            signature: files_signature(next)?,
            checkpoints,
        });
        Ok(())
    }
    pub(super) fn post_commit(
        &mut self,
        outcome: &DurableCommitOutcome,
        hooks: &mut dyn ResumeHooks,
    ) -> Result<()> {
        match outcome {
            DurableCommitOutcome::Committed(generation)
            | DurableCommitOutcome::Published(generation) => {
                if self.prepared.as_ref().map(|p| p.generation) != Some(*generation) {
                    self.ambiguous = true;
                    anyhow::bail!("state_v2_resume_commit_generation");
                }
                let prepared = self
                    .prepared
                    .take()
                    .context("state_v2_resume_preflight_required")?;
                self.committed = prepared.checkpoints;
                hooks.post_commit(*generation, &self.committed)
            }
            DurableCommitOutcome::Ambiguous => {
                self.ambiguous = true;
                anyhow::bail!("state_v2_resume_reopen_required")
            }
            DurableCommitOutcome::NotPublished => {
                self.prepared = None;
                Ok(())
            }
        }
    }
}

pub(super) fn populate(
    index: &ScanIndex,
    txn: &mut dyn Transaction,
    cx: &mut KindCxFiles,
) -> Result<()> {
    delta(&ScanIndex::default(), index, txn, cx)
}
pub(super) fn delta(
    prev: &ScanIndex,
    next: &ScanIndex,
    txn: &mut dyn Transaction,
    cx: &mut KindCxFiles,
) -> Result<()> {
    ensure!(!cx.ambiguous, "state_v2_resume_reopen_required");
    if let Some(prepared) = &cx.prepared {
        ensure!(
            prepared.generation == next.generation && prepared.signature == files_signature(next)?,
            "state_v2_resume_preflight_changed"
        );
        let binding = cx.binding.as_ref().context("state_v2_resume_binding")?;
        for (path, checkpoint) in &prepared.checkpoints {
            checkpoint.validate(
                path,
                next.files.get(path).context("state_v2_resume_orphan")?,
                next.generation,
                binding,
            )?;
        }
    } else {
        ensure!(
            cx.committed.is_empty() && !cx.require_preflight,
            "state_v2_resume_preflight_required"
        );
    }

    for path in prev
        .files
        .keys()
        .filter(|path| !next.files.contains_key(*path))
    {
        txn.delete(&key("file.progress", path, 0)?)?;
        txn.delete(&key("file.receipt", path, 0)?)?;
    }
    for (path, entry) in &next.files {
        let value = EntryWire::from(entry);
        if prev
            .files
            .get(path)
            .map(|v| encoded(&EntryWire::from(v)))
            .transpose()?
            .as_deref()
            != Some(encoded(&value)?.as_slice())
        {
            put(txn, "file.progress", path, 0, &projection(entry), &value)?;
        }
        let before = prev
            .files
            .get(path)
            .and_then(|v| v.upload_context_receipt.as_ref());
        if before != entry.upload_context_receipt.as_ref() {
            if let Some(receipt) = &entry.upload_context_receipt {
                put(txn, "file.receipt", path, 0, &Fixed::None, receipt)?;
            } else {
                txn.delete(&key("file.receipt", path, 0)?)?;
            }
        }
    }
    map(
        &prev.terminal_jsonl_dispositions,
        &next.terminal_jsonl_dispositions,
        "file.terminal",
        txn,
    )?;
    map(
        &prev.snapshot_activity_at,
        &next.snapshot_activity_at,
        "accepted.activity",
        txn,
    )?;
    map(
        &prev.claude_desktop_title_files,
        &next.claude_desktop_title_files,
        "v1_field.claude_desktop_title_files",
        txn,
    )?;
    map(
        &prev.growth_retention,
        &next.growth_retention,
        "file.growth_retention",
        txn,
    )?;
    entity_delta(
        &prev.file_snapshot_fingerprints,
        &next.file_snapshot_fingerprints,
        txn,
    )?;
    for path in prev
        .confirmed_empty_files
        .difference(&next.confirmed_empty_files)
    {
        txn.delete(&key("file.confirmed_empty", path, 0)?)?;
    }
    for path in next
        .confirmed_empty_files
        .difference(&prev.confirmed_empty_files)
    {
        put(txn, "file.confirmed_empty", path, 0, &Fixed::None, &true)?;
    }
    if let Some(prepared) = &cx.prepared {
        ensure!(
            prepared.generation == next.generation,
            "state_v2_resume_preflight_generation"
        );
        map(
            &cx.committed,
            &prepared.checkpoints,
            "resume.checkpoint",
            txn,
        )?;
    } else {
        // Legacy import may have no restart references. A hydrated protected
        // graph must always use the preflight/staging seam before a save.
        ensure!(
            cx.committed.is_empty() && !cx.require_preflight,
            "state_v2_resume_preflight_required"
        );
    }
    Ok(())
}

// Store has a GAT and begin requires &mut self: it cannot be a `dyn Store`.
// Keep the existing engine abstraction rather than exposing SQLite here.
pub(super) fn hydrate<S: Store>(
    store: &mut S,
    index: &mut ScanIndex,
    cx: &mut KindCxFiles,
) -> Result<()> {
    ensure!(
        !cx.ambiguous && cx.prepared.is_none(),
        "state_v2_resume_reopen_required"
    );
    let mut txn = store.begin(TxnMode::Read)?;
    let mut files = BTreeMap::new();
    rows(&mut txn, "file.progress", |header, path, bytes| {
        singleton(header)?;
        let entry = typed::<EntryWire>(bytes)?.entry();
        ensure!(
            header.fixed == projection(&entry),
            "state_v2_files_projection"
        );
        files.insert(path.to_owned(), entry);
        Ok(())
    })?;
    let receipts: BTreeMap<String, super::super::upload_context_receipt::Receipt> =
        read_map(&mut txn, "file.receipt")?;
    for (path, receipt) in receipts {
        files
            .get_mut(&path)
            .context("state_v2_receipt_orphan")?
            .upload_context_receipt = Some(receipt);
    }
    let terminal: BTreeMap<String, TerminalJsonlDisposition> = read_map(&mut txn, "file.terminal")?;
    let activity = read_map(&mut txn, "accepted.activity")?;
    let titles: BTreeMap<String, ClaudeDesktopTitleIndexEntry> =
        read_map(&mut txn, "v1_field.claude_desktop_title_files")?;
    let growth = read_map(&mut txn, "file.growth_retention")?;
    let entity_sets = read_entities(&mut txn)?;
    let empty: BTreeMap<String, bool> = read_map(&mut txn, "file.confirmed_empty")?;
    ensure!(
        empty.values().all(|value| *value),
        "state_v2_files_empty_presence"
    );
    let checkpoints: BTreeMap<String, ResumeCheckpoint> = read_map(&mut txn, "resume.checkpoint")?;
    for (path, checkpoint) in &checkpoints {
        checkpoint.validate(
            path,
            files.get(path).context("state_v2_resume_orphan")?,
            index.generation,
            cx.binding.as_ref().context("state_v2_resume_binding")?,
        )?;
    }
    // Publish only after the entire subset (including manifests) verifies.
    // Runtime-only context counters/desired policy remain on the caller's graph.
    index.files = files;
    index.terminal_jsonl_dispositions = terminal;
    index.snapshot_activity_at = activity;
    index.claude_desktop_title_files = titles;
    index.growth_retention = growth;
    index.file_snapshot_fingerprints = entity_sets;
    index.confirmed_empty_files = empty.into_keys().collect();
    cx.committed = checkpoints;
    cx.require_preflight = true;
    Ok(())
}

/// Erasure compares private text conservatively, including literal fingerprint
/// spellings, nested map keys and title text. Never print or hash away a path.
pub(super) fn private_paths(
    header: &Header,
    value: &dyn Value,
    paths: &mut dyn FnMut(&str) -> Result<()>,
) -> Result<()> {
    let RowKey::Record {
        kind, key_bytes, ..
    } = &header.key
    else {
        anyhow::bail!("state_v2_files_key");
    };
    ensure!(
        KINDS.contains(&kind.name()) && header.value_version == VERSION,
        "state_v2_files_kind"
    );
    paths(std::str::from_utf8(key_bytes)?)?;
    let mut bytes = Bounded(Vec::new());
    value.write(&mut bytes)?;
    let value: serde_json::Value = decoded(&bytes.0)?;
    fn walk(value: &serde_json::Value, paths: &mut dyn FnMut(&str) -> Result<()>) -> Result<()> {
        match value {
            serde_json::Value::String(s) => paths(s)?,
            serde_json::Value::Array(values) => {
                for value in values {
                    walk(value, paths)?;
                }
            }
            serde_json::Value::Object(values) => {
                for (key, value) in values {
                    paths(key)?;
                    walk(value, paths)?;
                }
            }
            _ => {}
        }
        Ok(())
    }
    walk(&value, paths)
}

/// File-owned kinds contain no shared_values references. The integrator must
/// dispatch here explicitly rather than using the pending mapper's refusal.
pub(super) fn references(
    header: &Header,
    _: &dyn Value,
    _: &mut dyn FnMut(&RowKey) -> Result<()>,
) -> Result<()> {
    ensure!(
        matches!(&header.key, RowKey::Record { kind, .. } if KINDS.contains(&kind.name()))
            && header.value_version == VERSION,
        "state_v2_files_kind"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    struct Scratch(PathBuf);
    impl Scratch {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let path = std::env::temp_dir().canonicalize().unwrap().join(format!(
                "ottto-kinds-files-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }
        fn binding() -> super::super::super::scan_index_persistence::Binding {
            super::super::super::scan_index_persistence::Binding {
                source: super::super::super::scan_index_persistence::Source::Claude,
                namespace_hash: "a".repeat(64),
            }
        }
        fn store(&self) -> sqlite::Sqlite {
            let mut store =
                sqlite::Sqlite::create_import(&self.0.join("index.v2.sqlite.import")).unwrap();
            store.path_extractor(|h, v, p| {
                if matches!(&h.key, RowKey::Record { .. }) {
                    private_paths(h, v, p)
                } else {
                    Ok(())
                }
            });
            store
                .control(
                    "identity",
                    &Identity {
                        format: FORMAT,
                        db_id: "synthetic-files".into(),
                        binding: Self::binding(),
                        fence_generation: 0,
                    },
                )
                .unwrap();
            store.control("generation", &0_u64).unwrap();
            store
        }
    }
    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    fn cx() -> KindCxFiles {
        KindCxFiles {
            binding: Some(Scratch::binding()),
            ..Default::default()
        }
    }
    fn fixture() -> ScanIndex {
        let mut index: ScanIndex = serde_json::from_value(json!({
            "generation": 1,
            "files": {
                "/synthetic/a": {
                    "size_bytes": 17, "modified_unix_seconds": 1, "modified_unix_nanos": 1_000_000_007_u64,
                    "source_file_fingerprint": "/literal/fingerprint", "last_snapshot_fingerprint": "",
                    "last_upload_body_witness": "ABCDEF", "effective_upload_body_witness_revision": u64::MAX,
                    "scan_identity_version": "raw/version", "codex_joined_member_set": "",
                    "codex_captured_joined_member_set": "raw/captured", "codex_protected_owner": "raw/owner",
                    "codex_applied_tier_receipt": {"version": 65535, "derivation": "raw/derivation", "scope": "raw/scope", "records": 0, "prefix_digest": "raw/digest", "tiers": {"/private/key": "/private/value"}},
                    "codex_applied_tier_receipt_required": true,
                    "codex_captured_tier_receipt": {"version": 0, "derivation": "", "scope": "", "records": 0, "prefix_digest": "", "tiers": {}},
                    "codex_captured_tier_receipt_required": true, "codex_captured_uncommitted": true,
                    "codex_counting_v2": true, "codex_counting_owner": "raw/counting-owner",
                    "opened_changed_nanos": u64::MAX, "opened_birth_nanos": 9,
                    "upload_context_receipt": {"context_fingerprint": "/receipt/context", "replay_generation": u64::MAX, "source_witness": "/receipt/source", "body_witness": "/receipt/body"}
                },
                "": {"size_bytes": 0, "modified_unix_seconds": 0, "source_file_fingerprint": "", "last_snapshot_fingerprint": null}
            },
            "file_snapshot_fingerprints": {"/side-only": [], "/synthetic/a": ["", "raw/entity"]},
            "snapshot_activity_at": {"null-activity": null, "empty-activity": "", "raw/entity": "raw/time"},
            "confirmed_empty_files": ["/empty-only"],
            "terminal_jsonl_dispositions": {"/terminal-only": {"source_file_fingerprint": "/terminal/source", "parser_generation": "raw/parser", "loss": {"over_line_cap_count": 2, "recognized_usage_drop_count": 3, "dropped_usage_record_count": u64::MAX}}},
            "claude_desktop_title_files": {"/title-only": {"cli_session_id": "session", "title": "/private/title", "user_set": true,
                "account_identifier_hash": "", "original_identity": {"account_identifier_hash": null, "provider_workspace_hash": "", "source_created_at": "literal/date", "imported": false},
                "desktop_session_id": "", "spawned_from_desktop_session_id": null, "spawned_from_unresolved": true}},
            "growth_retention": {"/growth-only": {"predecessor_size": 0, "uncertain_passes": 4, "checked_generation": u64::MAX, "last_growth_full_unix": u64::MAX}, "": {}}
        })).unwrap();
        index.context_read_counts.files = 42;
        index.context_read_counts.local_bytes = 99;
        index.active_upload_context_fingerprint = Some("runtime/context".into());
        index
    }
    fn subset(index: &ScanIndex) -> Vec<u8> {
        serde_json::to_vec(&(
            &index.files,
            &index.file_snapshot_fingerprints,
            &index.snapshot_activity_at,
            &index.confirmed_empty_files,
            &index.terminal_jsonl_dispositions,
            &index.claude_desktop_title_files,
            &index.growth_retention,
        ))
        .unwrap()
    }
    struct Count<'a> {
        inner: &'a mut dyn Transaction,
        put: usize,
        deleted: usize,
    }
    impl Transaction for Count<'_> {
        fn get(&mut self, k: &RowKey) -> Result<Option<Header>> {
            self.inner.get(k)
        }
        fn read_value(&mut self, h: &Header, o: &mut dyn Write) -> Result<()> {
            self.inner.read_value(h, o)
        }
        fn put(&mut self, r: RowInput<'_>) -> Result<Header> {
            self.put += 1;
            self.inner.put(r)
        }
        fn delete(&mut self, k: &RowKey) -> Result<bool> {
            let deleted = self.inner.delete(k)?;
            self.deleted += usize::from(deleted);
            Ok(deleted)
        }
        fn value_matches(&mut self, h: &Header, v: &dyn Value) -> Result<bool> {
            self.inner.value_matches(h, v)
        }
        fn request_set_candidates(
            &mut self,
            c: &[u8; 32],
            a: u64,
            l: usize,
        ) -> Result<Vec<Header>> {
            self.inner.request_set_candidates(c, a, l)
        }
        fn adjust_refs(&mut self, k: &RowKey, d: i64) -> Result<u64> {
            self.inner.adjust_refs(k, d)
        }
        fn scan_prefix(
            &mut self,
            p: RowPrefix,
            a: Option<&RowKey>,
            l: usize,
        ) -> Result<Vec<Header>> {
            self.inner.scan_prefix(p, a, l)
        }
        fn scan_kind(
            &mut self,
            k: &RecordKind,
            a: Option<&RowKey>,
            l: usize,
        ) -> Result<Vec<Header>> {
            self.inner.scan_kind(k, a, l)
        }
        fn scan_family(
            &mut self,
            k: &RecordKind,
            b: &[u8],
            a: Option<u64>,
            l: usize,
        ) -> Result<Vec<Header>> {
            self.inner.scan_family(k, b, a, l)
        }
        fn commit(self, _: u64, _: u64) -> DurableCommitOutcome {
            panic!("fixture commits the owning transaction")
        }
    }
    #[test]
    fn v1_subset_round_trip_keeps_raw_codex_presence_side_only_rows_and_growth_claims() {
        let scratch = Scratch::new();
        let mut store = scratch.store();
        let index = fixture();
        let mut context = cx();
        let mut txn = store.begin(TxnMode::Write).unwrap();
        populate(&index, &mut txn, &mut context).unwrap();
        assert_eq!(txn.commit(0, 1), DurableCommitOutcome::Committed(1));
        let mut hydrated = ScanIndex {
            generation: 1,
            ..Default::default()
        };
        hydrated.context_read_counts.files = 7;
        hydrate(&mut store, &mut hydrated, &mut cx()).unwrap();
        assert_eq!(subset(&index), subset(&hydrated));
        assert_eq!(hydrated.context_read_counts.files, 7);
        assert_eq!(hydrated.active_upload_context_fingerprint, None);
        assert!(!hydrated.files.contains_key("/side-only"));
        assert!(!hydrated.files.contains_key("/title-only"));
        assert!(!hydrated.files.contains_key("/growth-only"));
        assert_eq!(
            hydrated.snapshot_activity_at.get("null-activity"),
            Some(&None)
        );
        assert_eq!(
            hydrated.file_snapshot_fingerprints.get("/side-only"),
            Some(&BTreeSet::new())
        );
    }
    #[test]
    fn unchanged_delta_writes_nothing_and_one_changed_growth_claim_writes_one_row() {
        let scratch = Scratch::new();
        let mut store = scratch.store();
        let index = fixture();
        let mut txn = store.begin(TxnMode::Write).unwrap();
        populate(&index, &mut txn, &mut cx()).unwrap();
        assert_eq!(txn.commit(0, 1), DurableCommitOutcome::Committed(1));
        let mut txn = store.begin(TxnMode::Write).unwrap();
        let mut count = Count {
            inner: &mut txn,
            put: 0,
            deleted: 0,
        };
        delta(&index, &index, &mut count, &mut cx()).unwrap();
        assert_eq!((count.put, count.deleted), (0, 0));
        let mut next = index.clone();
        next.growth_retention
            .get_mut("/growth-only")
            .unwrap()
            .checked_generation = Some(0);
        delta(&index, &next, &mut count, &mut cx()).unwrap();
        assert_eq!((count.put, count.deleted), (1, 0));
    }
    #[test]
    fn entity_manifest_is_stable_and_missing_bucket_refuses_without_partial_hydration() {
        let scratch = Scratch::new();
        let mut store = scratch.store();
        let mut index = fixture();
        index.file_snapshot_fingerprints.insert(
            "/many".into(),
            (0..512).map(|n| format!("entity-{n}")).collect(),
        );
        let mut txn = store.begin(TxnMode::Write).unwrap();
        populate(&index, &mut txn, &mut cx()).unwrap();
        assert_eq!(txn.commit(0, 1), DurableCommitOutcome::Committed(1));
        let mut actual = ScanIndex {
            generation: 1,
            ..Default::default()
        };
        hydrate(&mut store, &mut actual, &mut cx()).unwrap();
        assert_eq!(subset(&actual), subset(&index));
        let mut next = index.clone();
        next.file_snapshot_fingerprints
            .get_mut("/many")
            .unwrap()
            .insert("one-addition".into());
        let mut txn = store.begin(TxnMode::Write).unwrap();
        let mut count = Count {
            inner: &mut txn,
            put: 0,
            deleted: 0,
        };
        delta(&index, &next, &mut count, &mut cx()).unwrap();
        assert_eq!(count.put, 2);
        txn.delete(&key("file.entities", "/many", bucket("entity-0")).unwrap())
            .unwrap();
        assert_eq!(txn.commit(1, 2), DurableCommitOutcome::Committed(2));
        let before = subset(&actual);
        actual.generation = 2;
        assert!(hydrate(&mut store, &mut actual, &mut cx()).is_err());
        assert_eq!(subset(&actual), before);
    }
    #[test]
    fn receipt_does_not_invent_an_entry_and_header_projection_is_checked() {
        let scratch = Scratch::new();
        let mut store = scratch.store();
        let index = fixture();
        let mut txn = store.begin(TxnMode::Write).unwrap();
        populate(&index, &mut txn, &mut cx()).unwrap();
        put(
            &mut txn,
            "file.receipt",
            "/orphan",
            0,
            &Fixed::None,
            index.files["/synthetic/a"]
                .upload_context_receipt
                .as_ref()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(txn.commit(0, 1), DurableCommitOutcome::Committed(1));
        assert!(hydrate(&mut store, &mut ScanIndex::default(), &mut cx()).is_err());
        let mut txn = store.begin(TxnMode::Write).unwrap();
        txn.delete(&key("file.receipt", "/orphan", 0).unwrap())
            .unwrap();
        let entry = &index.files["/synthetic/a"];
        let mut fixed = projection(entry);
        let Fixed::File { size, .. } = &mut fixed else {
            unreachable!()
        };
        *size += 1;
        put(
            &mut txn,
            "file.progress",
            "/synthetic/a",
            0,
            &fixed,
            &EntryWire::from(entry),
        )
        .unwrap();
        assert_eq!(txn.commit(1, 2), DurableCommitOutcome::Committed(2));
        assert!(hydrate(&mut store, &mut ScanIndex::default(), &mut cx()).is_err());
    }
    #[test]
    fn extractor_covers_path_keys_and_raw_nested_keys_values_and_title_text() {
        let scratch = Scratch::new();
        let mut store = scratch.store();
        let index = fixture();
        let mut txn = store.begin(TxnMode::Write).unwrap();
        populate(&index, &mut txn, &mut cx()).unwrap();
        let mut texts = BTreeSet::new();
        for kind in KINDS {
            rows(&mut txn, kind, |header, _, bytes| {
                private_paths(header, &Bytes(bytes), &mut |s| {
                    texts.insert(s.to_owned());
                    Ok(())
                })
            })
            .unwrap();
        }
        for text in [
            "/synthetic/a",
            "/private/key",
            "/private/value",
            "/private/title",
            "/receipt/body",
            "/growth-only",
            "/side-only",
            "/literal/fingerprint",
        ] {
            assert!(
                texts.contains(text),
                "missing synthetic private text: {text}"
            );
        }
    }
    #[test]
    fn replacing_value_only_private_text_marks_erasure_in_the_same_commit() {
        let scratch = Scratch::new();
        let mut store = scratch.store();
        let index = fixture();
        let mut txn = store.begin(TxnMode::Write).unwrap();
        populate(&index, &mut txn, &mut cx()).unwrap();
        assert_eq!(txn.commit(0, 1), DurableCommitOutcome::Committed(1));
        let mut next = index.clone();
        next.claude_desktop_title_files
            .get_mut("/title-only")
            .unwrap()
            .title = None;
        let mut txn = store.begin(TxnMode::Write).unwrap();
        delta(&index, &next, &mut txn, &mut cx()).unwrap();
        assert_eq!(txn.commit(1, 2), DurableCommitOutcome::Committed(2));
        let mut txn = store.begin(TxnMode::Read).unwrap();
        let header = txn
            .get(&RowKey::Meta("erasure_pending".into()))
            .unwrap()
            .unwrap();
        let mut bytes = Vec::new();
        txn.read_value(&header, &mut bytes).unwrap();
        assert!(serde_json::from_slice::<u64>(&bytes).unwrap() > 0);
    }
    #[test]
    fn growth_inventory_recognizes_the_appended_v1_slot_and_all_four_fields() {
        let bytes = serde_json::to_vec(&fixture()).unwrap();
        assert_eq!(shape::inventory(std::io::Cursor::new(bytes)), Ok(()));
        let bytes = br#"{"files":{},"growth_retention":{"/key":{"predecessor_size":null,"uncertain_passes":0,"checked_generation":0,"last_growth_full_unix":0,"future":1}}}"#;
        assert_eq!(
            shape::inventory(std::io::Cursor::new(bytes)),
            Err(shape::Pause::Unknown)
        );
    }
    #[cfg(unix)]
    fn reference(path: &str, entry: &ScanIndexEntry, generation: u64) -> ResumeCheckpoint {
        let key_digest = crate::durable_tail_store::key_digest(
            crate::durable_tail_store::DurableSource::ClaudeCode,
            path,
        );
        let key_text = key_digest
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        let committed_bytes = entry.size_bytes;
        ResumeCheckpoint {
            record_generation: generation,
            record_name: format!("{key_text}.{generation}.unique-attempt.rec"),
            trailer_digest: [3; 32],
            file_generation: generation,
            committed_bytes,
            reduction_version: 1,
            reduction_allowlist: [4; 32],
            reduction_pin: vec![1, 0],
            binding: Scratch::binding(),
            key_digest,
            context: [5; 32],
            scope: [6; 32],
            entry: crate::durable_tail_store::entry_digest(
                &entry.source_file_fingerprint,
                entry.last_upload_body_witness.as_deref(),
            ),
            publication: publication(entry).unwrap(),
            certificate: Certificate {
                device: 1,
                inode: 2,
                length: entry.size_bytes,
                modified: (
                    entry.modified_unix_seconds as i64,
                    (entry.modified_unix_nanos.unwrap_or(0) % 1_000_000_000) as i64,
                ),
                birth_nanos: entry.opened_birth_nanos,
                sealed_offset: committed_bytes,
                sample_len: committed_bytes.min(4096) as u32,
                head_sha256: [7; 32],
                boundary_sha256: [8; 32],
                verified_unix_seconds: 1,
                audit_debt_unix_seconds: Some(0),
            },
        }
    }
    #[derive(Default)]
    struct Hooks {
        staged: StagedCheckpoints,
        events: Vec<&'static str>,
    }
    impl ResumeHooks for Hooks {
        fn stage(
            &mut self,
            _: &ScanIndex,
            _: &ScanIndex,
            _: &BTreeMap<String, ResumeCheckpoint>,
        ) -> Result<StagedCheckpoints> {
            self.events.push("stage");
            Ok(std::mem::take(&mut self.staged))
        }
        fn post_commit(&mut self, _: u64, _: &BTreeMap<String, ResumeCheckpoint>) -> Result<()> {
            self.events.push("post_commit");
            Ok(())
        }
    }
    #[test]
    #[cfg(unix)]
    fn checkpoint_is_atomic_exact_unchanged_across_global_saves_and_ambiguity_requires_reopen() {
        let scratch = Scratch::new();
        let mut store = scratch.store();
        let prev = ScanIndex::default();
        let mut next = fixture();
        next.files.remove("");
        let cp = reference("/synthetic/a", &next.files["/synthetic/a"], 1);
        let mut hooks = Hooks::default();
        hooks
            .staged
            .replacements
            .insert("/synthetic/a".into(), cp.clone());
        let mut context = cx();
        context.preflight(&prev, &next, &mut hooks).unwrap();
        assert_eq!(hooks.events, ["stage"]);
        let mut txn = store.begin(TxnMode::Write).unwrap();
        populate(&next, &mut txn, &mut context).unwrap();
        let outcome = txn.commit(0, 1);
        assert_eq!(outcome, DurableCommitOutcome::Committed(1));
        context.post_commit(&outcome, &mut hooks).unwrap();
        assert_eq!(hooks.events, ["stage", "post_commit"]);
        let mut loaded = ScanIndex {
            generation: 1,
            ..Default::default()
        };
        let mut reopened = cx();
        hydrate(&mut store, &mut loaded, &mut reopened).unwrap();
        assert_eq!(reopened.checkpoints()["/synthetic/a"], cp);
        let mut later = next.clone();
        later.generation = 2;
        context.preflight(&next, &later, &mut hooks).unwrap();
        let mut txn = store.begin(TxnMode::Write).unwrap();
        let mut count = Count {
            inner: &mut txn,
            put: 0,
            deleted: 0,
        };
        delta(&next, &later, &mut count, &mut context).unwrap();
        assert_eq!((count.put, count.deleted), (0, 0));
        let outcome = txn.commit(1, 2);
        context.post_commit(&outcome, &mut hooks).unwrap();
        loaded.generation = 2;
        hydrate(&mut store, &mut loaded, &mut reopened).unwrap();
        assert_eq!(reopened.checkpoints()["/synthetic/a"], cp);
        let mut held = later.clone();
        held.generation = 3;
        context.preflight(&later, &held, &mut hooks).unwrap();
        assert!(context
            .post_commit(&DurableCommitOutcome::Ambiguous, &mut hooks)
            .is_err());
        let mut txn = store.begin(TxnMode::Write).unwrap();
        assert!(delta(&later, &held, &mut txn, &mut context).is_err());
        assert_eq!(
            hooks
                .events
                .iter()
                .filter(|event| **event == "post_commit")
                .count(),
            2
        );
    }
    #[test]
    #[cfg(unix)]
    fn preflight_requires_stage_and_exact_finish_and_rejects_changed_inputs_and_unsafe_names() {
        let prev = ScanIndex::default();
        let mut next = fixture();
        next.files.remove("");
        let mut context = cx();
        let mut hooks = Hooks::default();
        assert!(context.preflight(&prev, &next, &mut hooks).is_err());
        let cp = reference("/synthetic/a", &next.files["/synthetic/a"], 1);
        let mut unsafe_cp = cp.clone();
        unsafe_cp.record_name = "../escape.rec".into();
        hooks
            .staged
            .replacements
            .insert("/synthetic/a".into(), unsafe_cp);
        assert!(context.preflight(&prev, &next, &mut hooks).is_err());
        hooks
            .staged
            .replacements
            .insert("/synthetic/a".into(), cp.clone());
        context.preflight(&prev, &next, &mut hooks).unwrap();
        let scratch = Scratch::new();
        let mut store = scratch.store();
        let mut txn = store.begin(TxnMode::Write).unwrap();
        next.files
            .get_mut("/synthetic/a")
            .unwrap()
            .last_snapshot_fingerprint = Some("changed-after-stage".into());
        let mut count = Count {
            inner: &mut txn,
            put: 0,
            deleted: 0,
        };
        assert!(populate(&next, &mut count, &mut context).is_err());
        assert_eq!((count.put, count.deleted), (0, 0));
        drop(txn);
        next.files
            .get_mut("/synthetic/a")
            .unwrap()
            .last_snapshot_fingerprint = Some("".into());
        let mut txn = store.begin(TxnMode::Write).unwrap();
        populate(&next, &mut txn, &mut context).unwrap();
        let outcome = txn.commit(0, 1);
        assert_eq!(outcome, DurableCommitOutcome::Committed(1));
        context.post_commit(&outcome, &mut hooks).unwrap();
        let mut removed = next.clone();
        removed.generation = 2;
        removed.files.clear();
        assert!(context.preflight(&next, &removed, &mut hooks).is_err());
        hooks.staged.finished.insert(
            "/synthetic/a".into(),
            FinishProof {
                prior: cp,
                reason: FinishReason::AuthoritativeRemoval,
                source_proof: [9; 32],
                settled_dependencies: [10; 32],
            },
        );
        context.preflight(&next, &removed, &mut hooks).unwrap();
        let mut txn = store.begin(TxnMode::Write).unwrap();
        delta(&next, &removed, &mut txn, &mut context).unwrap();
        assert!(txn
            .get(&key("resume.checkpoint", "/synthetic/a", 0).unwrap())
            .unwrap()
            .is_none());
        let outcome = txn.commit(1, 2);
        assert_eq!(outcome, DurableCommitOutcome::Committed(2));
        context.post_commit(&outcome, &mut hooks).unwrap();
        let mut loaded = ScanIndex {
            generation: 2,
            ..Default::default()
        };
        let mut reopened = cx();
        hydrate(&mut store, &mut loaded, &mut reopened).unwrap();
        assert!(loaded.files.is_empty() && reopened.checkpoints().is_empty());
        let mut txn = store.begin(TxnMode::Write).unwrap();
        assert!(delta(&loaded, &loaded, &mut txn, &mut reopened).is_err());
    }
}
