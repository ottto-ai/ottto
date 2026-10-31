//! Bounded `.jsonl.zst` rollout input behind the one opened-object parser seam.
//! Archive metadata never grants ownership or acceptance authority.
use crate::local_resource_diagnostics::{codex_zst_refused, CodexZstCause};
use std::collections::BTreeSet;
use std::fs::File;
use std::io::{self, BufRead, BufReader, Read};
use std::mem::size_of;
use std::path::Path;
#[path = "codex_decoder_allocation.rs"]
mod decoder_allocation;
use decoder_allocation::Context as DecoderContext;

/// One predicate for a candidate's encoding or the already-opened input kind.
/// A suffix is only a refusal signal, never ownership or decode authority.
pub(super) fn is_compressed_codex_rollout(
    path: Option<&Path>,
    input: Option<&OpenedInput>,
) -> bool {
    path.and_then(Path::file_name)
        .is_some_and(|name| name.as_encoded_bytes().ends_with(b".jsonl.zst"))
        || input.is_some_and(OpenedInput::is_compressed)
}

pub(super) fn refuse_compressed_codex(
    path: Option<&Path>,
    input: Option<&OpenedInput>,
    cause: CodexZstCause,
) -> io::Result<()> {
    if is_compressed_codex_rollout(path, input) {
        codex_zst_refused(cause);
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            serde_json::to_string(&cause).unwrap_or_else(|_| "compressed refusal".into()),
        ));
    }
    Ok(())
}

/// Compressed bytes buffered from the File, and decoded bytes buffered for the
/// line reader. Plain input keeps `BufReader::new`'s default capacity.
const BUFFER_BYTES: usize = 8 * 1024;
// Independent from the decoded-file limit: a small file may demand a huge window.
const WINDOW_LOG: u32 = 23;

fn invalid(message: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

// Darwin receipt: zstd 1.5.7, WindowLogMax(23), 514 MiB decoded fixture,
// Mac CI run 41213075990 decoder_allocation_receipt: actual-size peak
// 13,156,560 bytes, plus 10%, rounded up to 64 KiB
// = 14,483,456 bytes.
// Paid inside unchanged STATE_BYTES; admission preserves the primary Tail floor.
#[cfg(target_os = "macos")]
const COMPRESSED_INPUT_CREDIT: usize = 14_483_456;
// Other platforms retain CI run 40774588149's 8,894,448-byte requested peak
// plus 10%, rounded up to 64 KiB. No non-Darwin credit change.
#[cfg(not(target_os = "macos"))]
const COMPRESSED_INPUT_CREDIT: usize = 9_830_400;

/// Decoder portion of the measured whole-input credit, including input buffer.
fn decoder_reservation() -> io::Result<usize> {
    COMPRESSED_INPUT_CREDIT
        .checked_sub(BUFFER_BYTES + size_of::<BufReader<BoundedDecoder<File>>>())
        .ok_or_else(|| invalid("compressed rollout reservation overflow"))
}

/// Credit a caller pays before `OpenedInput::compressed`: decoder heap, the
/// boxed reader and its decoded-byte buffer. The JSONL line buffer and parsed
/// accumulator stay charged by their existing owners.
pub(super) fn compressed_input_credit() -> io::Result<usize> {
    decoder_reservation()?
        .checked_add(BUFFER_BYTES)
        .and_then(|n| n.checked_add(size_of::<BufReader<BoundedDecoder<File>>>()))
        .ok_or_else(|| invalid("compressed rollout credit overflow"))
}

pub(super) fn thread_cpu_micros() -> u64 {
    let mut spec: libc::timespec = unsafe { std::mem::zeroed() };
    // SAFETY: valid writable timespec, querying only the current thread.
    if unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, &mut spec) } != 0 {
        return 0;
    }
    (spec.tv_sec as u64)
        .saturating_mul(1_000_000)
        .saturating_add(spec.tv_nsec as u64 / 1_000)
}

/// Archive debt uses the existing closed diagnostic carrier and generic alarm.
/// Correction debt alarms only when the context owner creates that transition.
pub(super) fn archive_owed(cause: CodexZstCause, count: usize, alarm: bool) {
    crate::local_resource_diagnostics::codex_zst_held(cause, count);
    if alarm {
        crate::local_resource_diagnostics::durable_tail_alarm(
            "codex",
            &serde_json::json!({"archive_owed":count}),
        );
    }
}

/// Settled entries retain only the object stamp and disposition. Unsettled
/// acquisition metadata is boxed, so accepted populations retain no headers.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct ArchiveEvidence {
    pub(super) stamp: crate::transcript_acquisition::FileStamp,
    pub(super) disposition: ArchiveDisposition,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) work: Option<Box<ArchiveWork>>,
}
#[derive(Clone, serde::Serialize, serde::Deserialize, Default)]
pub(super) struct ArchiveWork {
    pub(super) header: Option<Box<ValidatedHeader>>,
    pub(super) body_witness: Option<String>,
    pub(super) attempts: u64,
    pub(super) header_attempted: bool,
    #[serde(skip)]
    pub(super) reservation_saved: bool,
    #[serde(skip)]
    pub(super) reserved: bool,
}
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub(crate) enum ArchiveDisposition {
    HeaderValidated,
    Acquired,
    Empty,
    Pending { attempts: u64, retry_after: u64 },
    Held { cause: CodexZstCause },
    // Retired draft format: it is owed, never a completion certificate.
    Refused { cause: CodexZstCause },
}
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub(super) struct ValidatedHeader {
    pub(super) owner: String,
    pub(super) created_unix_ms: Option<i64>,
    #[serde(default)]
    pub(super) parent: Option<String>,
}
impl ValidatedHeader {
    pub(super) fn from_bytes(bytes: &[u8]) -> Option<Self> {
        Self::from_line(bytes.strip_suffix(b"\n")?)
    }
    pub(super) fn from_line(bytes: &[u8]) -> Option<Self> {
        use super::*;
        let value: Value = serde_json::from_slice(bytes).ok()?;
        let (owner, created_unix_ms) = codex_file_join::owning_header(&value).ok()?;
        let meta = codex_session_meta_payload(&value)?;
        let parent = codex_identity_at(meta, &["forked_from_id"])
            .or_else(|| codex_identity_at(meta, &["parent_thread_id"]))
            .or_else(|| {
                codex_identity_at(
                    meta,
                    &["source", "subagent", "thread_spawn", "parent_thread_id"],
                )
            })
            .or_else(|| codex_identity_at(meta, &["history_base", "thread_id"]));
        let parent = resolve_codex_identity_option(parent).or_else(|| {
            [
                "forked_from_id",
                "parent_thread_id",
                "parent_session_id",
                "history_base",
                "subagent_history_start_ordinal",
            ]
            .iter()
            .any(|k| meta.get(k).is_some_and(|v| !v.is_null()))
            .then(String::new)
        });
        Some(Self {
            owner,
            created_unix_ms,
            parent,
        })
    }
}
impl ArchiveEvidence {
    pub(super) fn from_metadata(meta: std::fs::Metadata) -> io::Result<Self> {
        Ok(Self {
            stamp: crate::transcript_acquisition::FileStamp::capture(meta)?.content_only(),
            disposition: ArchiveDisposition::HeaderValidated,
            work: Some(Box::default()),
        })
    }
    pub(super) fn reserve(&mut self) {
        let work = self.work.get_or_insert_with(Box::default);
        work.attempts = work.attempts.saturating_add(1);
        work.reservation_saved = false;
        self.disposition = ArchiveDisposition::Pending {
            attempts: work.attempts,
            retry_after: super::sampled_scan::now_seconds().saturating_add(21600),
        };
    }
    pub(super) fn cancel_reservation(&mut self) {
        if let Some(w) = self.work.as_mut() {
            if w.reserved {
                w.attempts = w.attempts.saturating_sub(1);
            }
            w.reserved = false;
            w.reservation_saved = false;
        }
        self.disposition = ArchiveDisposition::HeaderValidated;
    }
    pub(super) fn ready_full(&self) -> bool {
        self.work
            .as_ref()
            .is_some_and(|w| w.reserved && w.reservation_saved)
            && matches!(self.disposition, ArchiveDisposition::Pending { .. })
    }
    pub(super) fn header(&self) -> Option<&ValidatedHeader> {
        self.work.as_ref()?.header.as_deref()
    }
    pub(super) fn owed_cause(&self) -> Option<CodexZstCause> {
        match self.disposition {
            ArchiveDisposition::Acquired | ArchiveDisposition::Empty => None,
            ArchiveDisposition::Held { cause } | ArchiveDisposition::Refused { cause } => {
                Some(cause)
            }
            _ => Some(CodexZstCause::OutputHeld),
        }
    }
    pub(super) fn quiet_disposition(&self) -> bool {
        match self.disposition {
            ArchiveDisposition::Acquired
            | ArchiveDisposition::Empty
            | ArchiveDisposition::Refused { .. } => true,
            ArchiveDisposition::Pending { retry_after, .. } => {
                super::sampled_scan::now_seconds() < retry_after
            }
            ArchiveDisposition::Held { cause } => {
                cause != CodexZstCause::OwnerUnproven
                    && cause != CodexZstCause::ArchiveEquivalenceUnproven
                    && cause != CodexZstCause::FamilyUnproven
                    && cause != CodexZstCause::ParentLedgerUnbound
            }
            ArchiveDisposition::HeaderValidated => false,
        }
    }
    pub(super) fn matches(&self, file: &File) -> bool {
        file.metadata()
            .and_then(crate::transcript_acquisition::FileStamp::capture)
            .is_ok_and(|s| self.stamp.same_content(&s))
    }
    pub(super) fn hold(&mut self, cause: CodexZstCause) {
        if matches!(
            cause,
            CodexZstCause::AdmissionRefused | CodexZstCause::AdmissionStarved
        ) {
            self.transient();
        } else {
            self.disposition = ArchiveDisposition::Held { cause };
        }
    }
    pub(super) fn transient(&mut self) {
        // A spent Full retains its existing durable retry, a refused Full does not.
        if !matches!(self.disposition, ArchiveDisposition::Pending { .. }) {
            self.disposition = ArchiveDisposition::HeaderValidated;
        }
    }
    pub(super) fn finish(&mut self, owner: Option<&str>, parsed: &super::ParsedJsonlFile) -> bool {
        if owner.is_none() || self.header().map(|h| h.owner.as_str()) != owner {
            self.hold(CodexZstCause::OwnerUnproven);
            return false;
        }
        if parsed.codex_parent_resolution_pending || parsed.codex_parent_unresolvable.is_some() {
            self.hold(CodexZstCause::ParentLedgerUnbound);
            return false;
        }
        if !parsed.complete() || parsed.zero_snapshot_usage_evidence {
            self.hold(CodexZstCause::OutputHeld);
            return false;
        }
        if parsed.snapshots.is_empty() {
            self.disposition = ArchiveDisposition::Empty;
            self.work = None;
        }
        true
    }
    pub(super) fn settle(&mut self, accepted: bool) {
        if accepted && matches!(self.disposition, ArchiveDisposition::Pending { .. }) {
            self.disposition = ArchiveDisposition::Acquired;
            self.work = None;
        }
    }
}
crate::heap_layout_bound::fields!(ValidatedHeader;owner,created_unix_ms,parent);
crate::heap_layout_bound::fields!(ArchiveWork;header,body_witness,attempts,header_attempted,reservation_saved,reserved);
crate::heap_layout_bound::fields!(ArchiveEvidence;stamp,disposition,work);
impl crate::heap_layout_bound::HeapLayoutBound for ArchiveDisposition {
    fn heap_bound(&self, c: &mut crate::heap_layout_bound::Counter) -> Option<()> {
        c.add(0)
    }
}
/// Streaming decoder with sticky failure and an explicit decoded-byte budget.
/// EOF is successful only after a complete frame (including checksum). Supports
/// concatenated frames; a truncated last frame is never a successful prefix.
pub(super) struct BoundedDecoder<R: Read> {
    input: BufReader<io::Take<R>>,
    physical_limit: u64,
    context: DecoderContext,
    reserved: usize,
    remaining: u64,
    frame_complete: bool,
    failed: bool,
    compressed_bytes: u64,
    decoded_bytes: u64,
    cpu_micros: u64,
}

impl<R: Read> BoundedDecoder<R> {
    fn new(input: R, decoded_limit: u64) -> io::Result<Self> {
        #[cfg(test)]
        super::codex_zst_refusal_tests::decoder_constructed();
        let reserved = decoder_reservation()?;
        let mut context = DecoderContext::new(reserved.saturating_sub(BUFFER_BYTES))
            .ok_or_else(|| io::Error::other("compressed rollout decoder allocation failed"))?;
        context
            .set_window_log(WINDOW_LOG)
            .map_err(|_| invalid("cannot bound compressed rollout window"))?;
        Ok(Self {
            input: BufReader::with_capacity(BUFFER_BYTES, input.take(u64::MAX)),
            physical_limit: u64::MAX,
            context,
            reserved,
            remaining: decoded_limit,
            frame_complete: false,
            failed: false,
            compressed_bytes: 0,
            decoded_bytes: 0,
            cpu_micros: 0,
        })
    }

    fn retained_bytes(&self) -> usize {
        self.input.capacity().saturating_add(self.context.sizeof())
    }

    fn read_inner(&mut self, output: &mut [u8]) -> io::Result<usize> {
        loop {
            let bytes = self.input.fill_buf()?;
            let input_ended = bytes.is_empty();
            if input_ended && self.frame_complete {
                return Ok(0);
            }
            // At the limit, probe one byte: a Take-style artificial EOF would
            // incorrectly turn over-limit content into a complete JSONL body.
            let mut probe = [0u8; 1];
            let at_limit = self.remaining == 0;
            let capacity = output
                .len()
                .min(self.remaining.min(usize::MAX as u64) as usize);
            let out = if at_limit {
                &mut probe[..]
            } else {
                &mut output[..capacity]
            };
            let (hint, consumed, produced) = self
                .context
                .decompress(bytes, out)
                .map_err(|_| invalid(CodexZstCause::DecodeFailed))?;
            self.compressed_bytes = self.compressed_bytes.saturating_add(consumed as u64);
            self.decoded_bytes = self.decoded_bytes.saturating_add(produced as u64);
            self.input.consume(consumed);
            self.frame_complete = hint == 0;
            // The credit was paid before construction; never grow past it.
            if self.retained_bytes() > self.reserved {
                return Err(invalid("compressed rollout decoder exceeded its credit"));
            }
            if at_limit && produced != 0 {
                return Err(invalid(CodexZstCause::DecodedOverLimit));
            }
            self.remaining -= produced as u64;
            if produced != 0 {
                return Ok(produced);
            }
            if consumed == 0 && !self.frame_complete {
                let kind = if input_ended {
                    io::ErrorKind::UnexpectedEof
                } else {
                    io::ErrorKind::InvalidData
                };
                return Err(io::Error::new(kind, CodexZstCause::DecodeFailed));
            }
        }
    }
}

impl<R: Read> Read for BoundedDecoder<R> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        if self.failed {
            return Err(invalid("compressed rollout previously failed"));
        }
        let started = crate::context_composition::thread_cpu_micros();
        let result = self.read_inner(output);
        if let Some((started, ended)) = started.zip(crate::context_composition::thread_cpu_micros())
        {
            self.cpu_micros = self
                .cpu_micros
                .saturating_add(ended.saturating_sub(started));
        }
        if result.is_err() {
            self.failed = true;
        }
        result
    }
}

impl<R: Read> Drop for BoundedDecoder<R> {
    fn drop(&mut self) {
        if self.physical_limit != u64::MAX {
            return;
        }
        crate::local_resource_diagnostics::traversal_point(
            "codex_zst_input",
            "codex",
            &serde_json::json!({
                "codex_zst_compressed_bytes": self.physical_limit - self.input.get_ref().limit(),
                "codex_zst_compressed_consumed_bytes": self.compressed_bytes,
                "codex_zst_decoded_bytes": self.decoded_bytes,
                "codex_zst_cpu_micros": self.cpu_micros,
                "codex_zst_decoder_native_peak_bytes": self.context.peak_bytes() as u64,
                "codex_zst_decoder_allocation_refusals": self.context.allocation_refusals(),
            }),
        );
    }
}

/// One securely opened handle throughout header/body parsing and final identity
/// validation. Compressed input exposes decoded bytes, but never a seek API:
/// sampled plain-file offsets cannot be applied to compressed data. Method
/// names match the `BufReader<File>` calls the parser already makes.
pub(super) enum OpenedInput {
    Plain(BufReader<File>),
    Compressed(
        Box<BufReader<BoundedDecoder<File>>>,
        Option<super::sampled_scan::codex_cursor::DecoderOwner>,
    ),
}

impl OpenedInput {
    pub(super) fn plain(file: File) -> Self {
        Self::Plain(BufReader::new(file))
    }

    /// `credit` must cover `compressed_input_credit()`. `decoded_limit` is the
    /// sticky per-file cap on decoded bytes; reaching it with more content,
    /// truncation, corruption or an oversized window fails the read.
    pub(super) fn compressed(file: File, decoded_limit: u64, credit: usize) -> io::Result<Self> {
        if credit < compressed_input_credit()? {
            return Err(invalid("compressed rollout input was not prepaid"));
        }
        let decoder = BoundedDecoder::new(file, decoded_limit)?;
        let decoded = BufReader::with_capacity(BUFFER_BYTES, decoder);
        Ok(Self::Compressed(Box::new(decoded), None))
    }

    pub(super) fn funded(
        file: File,
        cache: &std::sync::Arc<super::sampled_scan::SharedCache>,
    ) -> io::Result<Option<Self>> {
        Self::funded_inner(file, cache, true)
    }
    fn funded_inner(
        file: File,
        cache: &std::sync::Arc<super::sampled_scan::SharedCache>,
        count_refusal: bool,
    ) -> io::Result<Option<Self>> {
        let credit = compressed_input_credit()?;
        let Some(owner) = super::sampled_scan::codex_cursor::DecoderOwner::acquire(cache, credit)
        else {
            if count_refusal {
                codex_zst_refused(CodexZstCause::AdmissionRefused);
            }
            return Ok(None);
        };
        let mut input = Self::compressed(
            file,
            u64::MAX, // Full streams pause in the existing decoded-byte page budget.
            credit,
        );
        if let Ok(Self::Compressed(_, paid)) = &mut input {
            *paid = Some(owner);
        } else {
            owner.release();
        }
        input.map(Some)
    }
    fn header_only(mut self) -> Self {
        if let Self::Compressed(reader, _) = &mut self {
            let decoder = reader.get_mut();
            decoder.remaining = super::codex_file_join::MAX_HEADER_BYTES as u64;
            decoder.physical_limit = 2 * super::codex_file_join::MAX_HEADER_BYTES as u64;
            decoder.input.get_mut().set_limit(decoder.physical_limit);
        }
        self
    }
    pub(super) fn close(self) {
        if let Self::Compressed(reader, owner) = self {
            drop(reader);
            if let Some(owner) = owner {
                owner.release();
            }
        }
    }
    pub(super) fn is_compressed(&self) -> bool {
        matches!(self, Self::Compressed(..))
    }

    /// The original opened File: metadata and identity revalidation use it, so
    /// no path is ever reopened. Never seek a compressed File before its
    /// decoder reaches EOF.
    pub(super) fn get_ref(&self) -> &File {
        match self {
            Self::Plain(reader) => reader.get_ref(),
            Self::Compressed(reader, _) => reader.get_ref().input.get_ref().get_ref(),
        }
    }

    pub(super) fn get_mut(&mut self) -> &mut File {
        match self {
            Self::Plain(reader) => reader.get_mut(),
            Self::Compressed(reader, _) => reader.get_mut().input.get_mut().get_mut(),
        }
    }

    pub(super) fn buffer(&self) -> &[u8] {
        match self {
            Self::Plain(reader) => reader.buffer(),
            Self::Compressed(reader, _) => reader.buffer(),
        }
    }

    /// Funded decoder memory is charged by its outstanding SharedCache claim.
    /// Unfunded synthetic input charges its box, buffer and full decoder credit;
    /// plain input charges only its buffer.
    pub(super) fn capacity(&self) -> usize {
        match self {
            Self::Plain(reader) => reader.capacity(),
            Self::Compressed(_, Some(_)) => 0, // existing outstanding cache reservation
            Self::Compressed(reader, _) => {
                let boxed = size_of::<BufReader<BoundedDecoder<File>>>();
                boxed
                    .saturating_add(reader.capacity())
                    .saturating_add(reader.get_ref().reserved)
            }
        }
    }
}

impl Read for OpenedInput {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Plain(reader) => reader.read(output),
            Self::Compressed(reader, _) => reader.read(output),
        }
    }
}

impl BufRead for OpenedInput {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        match self {
            Self::Plain(reader) => reader.fill_buf(),
            Self::Compressed(reader, _) => reader.fill_buf(),
        }
    }

    fn consume(&mut self, amount: usize) {
        match self {
            Self::Plain(reader) => reader.consume(amount),
            Self::Compressed(reader, _) => reader.consume(amount),
        }
    }
}

#[derive(Debug)]
pub(super) struct ArchiveAdmissionYield;
impl std::fmt::Display for ArchiveAdmissionYield {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("archive admission yielded")
    }
}
impl std::error::Error for ArchiveAdmissionYield {}
#[derive(Debug)]
pub(super) enum HeaderRead {
    Validated(ValidatedHeader),
    Settled(String),
    Deferred,
}
impl super::ScanIndex {
    pub(super) fn inventory_archive_header(
        &mut self,
        candidate: &super::CandidateFile,
        cache: Option<&std::sync::Arc<super::sampled_scan::SharedCache>>,
    ) -> super::Result<HeaderRead> {
        use super::*;
        let key = local_index_key(&candidate.path);
        if self.decode_holds.contains("archives", &key) {
            return Ok(HeaderRead::Deferred);
        }
        let meta = std::fs::symlink_metadata(&candidate.path)?;
        let stamp = crate::transcript_acquisition::FileStamp::capture(meta.clone())?;
        if self
            .archives
            .get(&key)
            .map_or(true, |a| !a.stamp.same_content(&stamp))
        {
            self.archives
                .insert(key.clone(), ArchiveEvidence::from_metadata(meta)?);
        }
        let a = &self.archives[&key];
        if let Some(h) = a.header() {
            return Ok(HeaderRead::Validated(h.clone()));
        }
        if a.work.is_none() {
            if let Some(owner) = self.files.get(&key).and_then(|e| {
                e.codex_counting_owner
                    .as_deref()
                    .or(e.codex_protected_owner.as_deref())
            }) {
                return Ok(HeaderRead::Settled(owner.to_owned()));
            }
            return Ok(HeaderRead::Deferred);
        }
        if a.quiet_disposition() {
            return Ok(HeaderRead::Deferred);
        }
        if !self.archive_pass.ready(1) {
            if let Some(w) = self.archives.get_mut(&key).and_then(|a| a.work.as_mut()) {
                w.header_attempted = false;
            }
            return Ok(HeaderRead::Deferred);
        }
        // Reserve the bounded header separately from Full, durable before bytes.
        if !a.work.as_ref().is_some_and(|w| w.header_attempted) {
            self.archives
                .get_mut(&key)
                .unwrap()
                .work
                .as_mut()
                .unwrap()
                .header_attempted = true;
            self.archive_pass.dirty = true;
            return Ok(HeaderRead::Deferred);
        }
        if !a.work.as_ref().is_some_and(|w| w.reservation_saved) {
            self.archive_hold(&candidate.path, CodexZstCause::HeaderInvalid);
            return Ok(HeaderRead::Deferred);
        }
        self.archive_pass.started = true;
        let file = open_candidate_beneath_root(candidate)?;
        let Some(mut input) = cache
            .map(|c| OpenedInput::funded(file, c))
            .transpose()?
            .flatten()
        else {
            if let Some(w) = self.archives.get_mut(&key).and_then(|a| a.work.as_mut()) {
                w.header_attempted = false;
            }
            return Ok(HeaderRead::Deferred);
        };
        input = input.header_only();
        crate::context_composition::set_utility_qos();
        let result = (|| -> Result<ValidatedHeader> {
            let bytes =
                codex_file_join::read_header_line(&mut input)?.context("archive header bound")?;
            anyhow::ensure!(
                self.archives[&key].matches(input.get_ref()),
                "archive changed during header read"
            );
            ValidatedHeader::from_bytes(&bytes).context("archive header invalid")
        })();
        if let OpenedInput::Compressed(reader, _) = &input {
            let d = reader.get_ref();
            crate::local_resource_diagnostics::traversal_point(
                "codex_zst_inventory",
                "codex",
                &serde_json::json!({"physical_bytes":d.physical_limit-d.input.get_ref().limit(),"decoded_bytes":d.decoded_bytes}),
            );
        }
        input.close();
        match result {
            Ok(header) => {
                self.archives
                    .get_mut(&key)
                    .unwrap()
                    .work
                    .as_mut()
                    .unwrap()
                    .header = Some(Box::new(header.clone()));
                Ok(HeaderRead::Validated(header))
            }
            Err(_) => {
                self.archive_hold(&candidate.path, CodexZstCause::HeaderInvalid);
                Ok(HeaderRead::Deferred)
            }
        }
    }
    pub(crate) fn settle_archive_outcome<'a>(
        &mut self,
        mut accepted: impl FnMut(&str) -> Option<&'a str>,
    ) {
        for (key, a) in &mut self.archives {
            let Some(expected) = a.work.as_ref().and_then(|w| w.body_witness.as_ref()) else {
                continue;
            };
            let witness = self
                .file_snapshot_fingerprints
                .get(key)
                .into_iter()
                .flatten()
                .map(|fp| accepted(fp))
                .collect::<Option<BTreeSet<_>>>()
                .filter(|b| !b.is_empty())
                .map(super::snapshot_file_upload_body_set_hex);
            a.settle(witness.as_ref() == Some(expected));
        }
    }
}
impl super::OwnedSourceScan {
    /// Header reservations and all admitted Full reservations are batched.
    /// Plain steps return before any archive key allocation or map walk.
    pub(crate) fn persist_archive_reservation(
        &mut self,
        committed: &mut super::ScanIndex,
        path: &Path,
    ) -> anyhow::Result<()> {
        if !self.index.archive_pass.dirty {
            return Ok(());
        }
        let previous = std::mem::replace(&mut committed.archives, self.index.archives.clone());
        if let Err(e) = committed.save(path) {
            committed.archives = previous;
            if self
                .active_file
                .as_ref()
                .is_some_and(|a| a.parser.reader.reader.is_compressed())
            {
                if let Some(a) = self.active_file.take() {
                    a.parser.reader.reader.close();
                }
            }
            return Err(e);
        }
        self.index.generation = committed.generation;
        for a in self.index.archives.values_mut() {
            if let Some(w) = a.work.as_mut() {
                w.reservation_saved = true;
            }
        }
        self.index.archive_pass.dirty = false;
        Ok(())
    }
}

impl std::fmt::Debug for ArchiveEvidence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ArchiveEvidence")
            .field("unsettled", &self.work.is_some())
            .field("disposition", &self.disposition)
            .finish_non_exhaustive()
    }
}
impl std::fmt::Debug for ValidatedHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ValidatedHeader")
            .field("owner_bytes", &self.owner.len())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
pub(in crate::snapshots) mod tests {
    use super::super::*;
    use super::*;
    use crate::transcript_acquisition::Scope;
    use std::io::Write;
    use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};

    pub(in crate::snapshots) static DECODER_TEST_LOCK: Mutex<()> = Mutex::new(());
    const NOW: &str = "2026-10-07T12:00:00Z";
    static NEXT: AtomicU64 = AtomicU64::new(0);

    fn decode(data: &[u8], limit: u64) -> io::Result<Vec<u8>> {
        let mut reader = BoundedDecoder::new(data, limit)?;
        let mut decoded = Vec::new();
        let result = reader.read_to_end(&mut decoded).map(|_| decoded);
        assert!(reader.retained_bytes() <= reader.reserved);
        if result.is_err() {
            assert!(reader.read_exact(&mut [0; 1]).is_err(), "failure is sticky");
        }
        result
    }

    fn decoder_process_peak_rss_bytes() -> Option<u64> {
        let mut usage = std::mem::MaybeUninit::<libc::rusage>::uninit();
        // SAFETY: getrusage initializes the entire struct on success.
        if unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) } != 0 {
            return None;
        }
        let usage = unsafe { usage.assume_init() };
        let peak = u64::try_from(usage.ru_maxrss).ok()?;
        if cfg!(target_os = "macos") {
            Some(peak)
        } else {
            peak.checked_mul(1024)
        }
    }

    /// [regress] Darwin decoder peak outgrew the old 9.8 MB credit (Mac CI run 40942402563).
    #[test]
    fn decoder_credit_preserves_the_platform_receipt_and_margin() {
        #[cfg(target_os = "macos")]
        {
            let measured_peak = 13_156_560_usize; // Mac run 41213075990, zstd 1.5.7.
            assert!(
                compressed_input_credit().unwrap() >= measured_peak + measured_peak.div_ceil(10)
            );
            assert_eq!(compressed_input_credit().unwrap(), 14_483_456);
        }
        #[cfg(not(target_os = "macos"))]
        assert_eq!(compressed_input_credit().unwrap(), 9_830_400);
        // The live large-window measurement below independently fails if an
        // upgraded decoder no longer fits its platform credit plus 10%.
    }

    /// [behaviour]
    #[test]
    fn decoder_native_peak_is_visible_on_the_existing_input_carrier() {
        let f = fixture(
            &zstd::stream::encode_all(&b"synthetic\n"[..], 1).unwrap(),
            ".jsonl.zst",
        );
        let (_, rows) = crate::local_resource_diagnostics::capture(|| {
            let mut input = OpenedInput::compressed(
                File::open(&f.0).unwrap(),
                64,
                compressed_input_credit().unwrap(),
            )
            .unwrap();
            assert_eq!(std::io::copy(&mut input, &mut std::io::sink()).unwrap(), 10);
            input.close();
        });
        let counts = &rows
            .iter()
            .find(|r| r["stage"] == "codex_zst_input")
            .unwrap()["counts"];
        let peak = counts["codex_zst_decoder_native_peak_bytes"]
            .as_u64()
            .unwrap();
        assert!(peak > 0 && peak <= compressed_input_credit().unwrap() as u64);
        assert_eq!(counts["codex_zst_decoder_allocation_refusals"], 0);
    }

    /// [behaviour]
    #[test]
    fn decoder_production_window_peak_allocation() {
        // Streaming, unknown content size prevents the encoder shrinking the
        // window. Alternate small/large frames to exercise DCtx buffer resizing.
        // 514 MiB decoded: production archive scale, never retained as a whole.
        let archive = fixture(&[], ".jsonl.zst");
        let mut file = File::create(&archive.0).unwrap();
        let mut row = [b'a'; 64 * 1024];
        let mut random = 1_u64;
        for byte in &mut row[1..64 * 1024 - 2] {
            random ^= random << 13;
            random ^= random >> 7;
            random ^= random << 17;
            *byte = b'a' + (random % 26) as u8;
        }
        row[0] = b'"';
        row[64 * 1024 - 2] = b'"';
        row[64 * 1024 - 1] = b'\n';
        for log in [17, WINDOW_LOG, 17, WINDOW_LOG] {
            let mut encoder = zstd::stream::write::Encoder::new(&mut file, 1).unwrap();
            encoder.window_log(log).unwrap();
            let rows = if log == WINDOW_LOG { 4096 } else { 16 };
            for _ in 0..rows {
                encoder.write_all(&row).unwrap();
            }
            encoder.finish().unwrap();
        }
        drop(file);
        let mut file = File::open(&archive.0).unwrap();
        let mut prefix = [0; 18];
        file.read_exact(&mut prefix).unwrap();
        // The second frame, not the 1 MiB prefix, must declare an 8 MiB window.
        let first_size =
            zstd::zstd_safe::find_frame_compressed_size(&fs::read(&archive.0).unwrap()).unwrap();
        use std::io::{Seek, SeekFrom};
        file.seek(SeekFrom::Start(first_size as u64)).unwrap();
        file.read_exact(&mut prefix).unwrap();
        // Zstd frame descriptor: non-single-segment + window descriptor 13*8.
        assert_eq!(&prefix[..4], &[0x28, 0xb5, 0x2f, 0xfd]);
        assert_eq!(prefix[4] & 0x20, 0);
        assert_eq!(prefix[5], ((WINDOW_LOG - 10) * 8) as u8);
        file.seek(SeekFrom::Start(0)).unwrap();
        let credit = compressed_input_credit().unwrap();
        let rss_before = decoder_process_peak_rss_bytes();
        let (_, allocation) = crate::retry_allocation_probe::measure(|| {
            let mut input = OpenedInput::compressed(file, 2 * 1024 * 1024 * 1024, credit).unwrap();
            let mut output = [0; BUFFER_BYTES];
            let mut total = 0_u64;
            loop {
                let n = input.read(&mut output).unwrap();
                if n == 0 {
                    break;
                }
                total += n as u64;
            }
            assert_eq!(total, 514 * 1024 * 1024);
            input.close();
        });
        let rss_after = decoder_process_peak_rss_bytes();
        eprintln!("decoder_process_rss_receipt before_bytes={rss_before:?} after_bytes={rss_after:?} scope=whole_process_lifetime_high_water not_a_delta_or_gate=true");
        let peak = allocation
            .requested_peak_with_overlap
            .max(allocation.usable_peak_with_overlap);
        eprintln!("decoder_allocation_receipt zstd={} window_log={} decoded_bytes={} requested_peak={} usable_peak={} overlap_peak={} credit={}",
            zstd::zstd_safe::version_string(), WINDOW_LOG, 514 * 1024 * 1024,
            allocation.requested_peak, allocation.usable_peak, peak, credit);
        assert!(
            peak >= 8 * 1024 * 1024,
            "native zstd allocations must be counted"
        );
        assert!(
            peak + peak.div_ceil(10) <= credit,
            "measured peak plus 10% must fit prepaid credit"
        );
        assert_eq!(
            allocation.requested_live, 0,
            "all decoder allocations released"
        );
    }

    #[test]
    fn compressed_input_exact_limit_and_concatenated_frames() {
        let plain = b"{\"type\":\"session_meta\"}\n{\"type\":\"event_msg\"}\n";
        let mut encoded = zstd::stream::encode_all(&plain[..24], 1).unwrap();
        encoded.extend(zstd::stream::encode_all(&plain[24..], 1).unwrap());
        assert_eq!(decode(&encoded, plain.len() as u64).unwrap(), plain);
    }

    #[test]
    fn compressed_input_refuses_truncation_overlimit_garbage_and_large_window() {
        let encoded = zstd::stream::encode_all(&b"one\ntwo\n"[..], 1).unwrap();
        let mut trailing = encoded.clone();
        trailing.extend_from_slice(b"junk");
        let mut wide = zstd::stream::write::Encoder::new(Vec::new(), 1).unwrap();
        wide.window_log(WINDOW_LOG + 1).unwrap();
        wide.write_all(b"one\ntwo\n").unwrap();
        let wide = wide.finish().unwrap();
        for (data, limit) in [
            (&encoded[..encoded.len() - 1], 8),
            (&encoded[..], 7),
            (&trailing[..], 8),
            (&wide[..], 8),
            (&[][..], 8),
        ] {
            assert!(decode(data, limit).is_err());
        }
    }

    struct Fixture(PathBuf);
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.0);
        }
    }
    fn fixture(bytes: &[u8], suffix: &str) -> Fixture {
        let path = std::env::temp_dir().join(format!(
            "ottto-compressed-input-{}-{}{suffix}",
            std::process::id(),
            NEXT.fetch_add(1, AtomicOrdering::Relaxed)
        ));
        fs::write(&path, bytes).unwrap();
        Fixture(path)
    }

    // Same synthetic Codex shapes as transcript_acquisition_tests.
    fn synthetic_rollout() -> Vec<u8> {
        let mut rows = vec![json!({"type":"session_meta","payload":{"id":"compressed-fixture"}})];
        for n in [100_u64, 250, 400] {
            let usage = json!({"input_tokens":n,"cached_input_tokens":n/2,"output_tokens":n/10});
            rows.push(
                json!({"type":"event_msg", "timestamp":"2026-10-07T10:00:00Z",
                "payload":{"type":"token_count", "info":{"model":"gpt-synthetic",
                "total_token_usage":usage, "last_token_usage":usage}}}),
            );
        }
        let mut bytes = Vec::new();
        for row in rows {
            serde_json::to_writer(&mut bytes, &row).unwrap();
            bytes.push(b'\n');
        }
        bytes
    }

    fn codex_parser(input: OpenedInput, path: &Path) -> OwnedJsonlParser {
        OwnedJsonlParser::new_opened(
            input,
            path,
            SnapshotSource::Codex,
            apply_codex_line,
            Some(&CodexTitleMetadata::default()),
            None,
            None,
            false,
            true,
        )
        .unwrap()
    }

    fn parse(mut parser: OwnedJsonlParser, expected: &str, path: &Path) -> Result<Value> {
        while !parser.step()? {}
        let parsed = parser.finish(
            expected,
            path,
            NOW,
            "compressed-input-fixture".into(),
            Some(&CodexTitleMetadata::default()),
            None,
            None,
        )?;
        anyhow::ensure!(parsed.complete(), "fixture parse incomplete");
        Ok(json!({
            "report": format!("{:?}", parsed.report),
            "snapshots": parsed.snapshots,
        }))
    }

    #[test]
    fn compressed_rollout_uses_the_same_parser_and_original_file() {
        let plain = synthetic_rollout();
        let split = plain.len() / 2;
        let mut encoded = zstd::stream::encode_all(&plain[..split], 3).unwrap();
        encoded.extend(zstd::stream::encode_all(&plain[split..], 3).unwrap());
        let plain_file = fixture(&plain, ".jsonl");
        let compressed_file = fixture(&encoded, ".jsonl.zst");
        // One logical rollout path for both, so only the input kind differs.
        let logical = &plain_file.0;
        let credit = compressed_input_credit().unwrap();

        let mut file = File::open(&plain_file.0).unwrap();
        let expected = opened_object_identity(SnapshotSource::Codex, &mut file).unwrap();
        let parser = codex_parser(OpenedInput::plain(file), logical);
        let oracle = parse(parser, &expected, logical).unwrap();

        let mut file = File::open(&compressed_file.0).unwrap();
        let expected = opened_object_identity(SnapshotSource::Codex, &mut file).unwrap();
        let unpaid = OpenedInput::compressed(file.try_clone().unwrap(), u64::MAX, credit - 1);
        assert!(unpaid.is_err());
        let input = OpenedInput::compressed(file, plain.len() as u64, credit).unwrap();
        assert!(input.is_compressed());
        assert_eq!(input.capacity(), credit);
        // The parser holds the original opened object, never a reopened path.
        assert_eq!(
            input.get_ref().metadata().unwrap().len(),
            encoded.len() as u64
        );
        let mut parser = codex_parser(input, logical);
        // Physical-offset sampling and resume are refused for compressed input.
        let scope = Scope("compressed".into());
        let refused = parser.prepare_acquisition(None, &scope, None, 100);
        assert!(refused.is_err());
        assert!(parser.reader.acquisition.is_none());
        assert_eq!(parse(parser, &expected, logical).unwrap(), oracle);
    }

    #[test]
    fn compressed_exclusive_body_supersedes_an_earlier_state_only_emission() {
        let plain = synthetic_rollout();
        let archive = fixture(
            &zstd::stream::encode_all(&plain[..], 1).unwrap(),
            ".jsonl.zst",
        );
        let owner = "compressed-fixture";
        let mut metadata = CodexTitleMetadata::default();
        metadata.state_threads.insert(
            owner.into(),
            CodexStateThread {
                tokens_used: 825,
                model: Some("gpt-synthetic".into()),
                ..Default::default()
            },
        );
        let mut index = ScanIndex::default();
        let mut earlier = Vec::new();
        append_codex_state_only_snapshots(
            &mut earlier,
            &metadata,
            NOW,
            &mut index,
            &BTreeSet::new(),
        );
        assert_eq!(earlier.len(), 1);
        assert_eq!(earlier[0].unattributed_total_tokens, 825);
        assert!(earlier[0].usage_accounting_contract.is_none());
        index
            .codex_state_only_snapshot_fingerprints
            .insert(owner.into(), earlier[0].snapshot_fingerprint.clone());

        // Exercise the existing decoder + native parser seam directly. This
        // simulates future archive admission without activating discovery.
        let mut file = File::open(&archive.0).unwrap();
        let expected = opened_object_identity(SnapshotSource::Codex, &mut file).unwrap();
        let input =
            OpenedInput::compressed(file, plain.len() as u64, compressed_input_credit().unwrap())
                .unwrap();
        let mut parser = codex_parser(input, &archive.0);
        while !parser.step().unwrap() {}
        let mut parsed = parser
            .finish(
                &expected,
                &archive.0,
                NOW,
                "compressed-input-fixture".into(),
                Some(&metadata),
                None,
                None,
            )
            .unwrap();
        assert!(parsed.complete());
        assert_eq!(parsed.snapshots.len(), 1);
        let native = parsed.snapshots[0].clone();
        assert_eq!(native.source_session_id, owner);
        assert_eq!(
            native.usage_accounting_contract.as_deref(),
            Some("session_exclusive_reported_usage:v1")
        );
        assert_eq!(native.unattributed_total_tokens, 0);
        // The shared fixture reports last-token deltas 100 + 250 + 400.
        assert_eq!(native.input_tokens, 750);
        assert_eq!(native.cache_read_tokens, 375);
        assert_eq!(native.output_tokens, 75);
        assert_eq!(native.model_usage[0].model, "gpt-synthetic");
        append_codex_state_only_snapshots(
            &mut parsed.snapshots,
            &metadata,
            NOW,
            &mut index,
            &BTreeSet::new(),
        );
        assert_eq!(
            parsed.snapshots.len(),
            1,
            "old state-only evidence must not suppress the real parsed body or append a total"
        );

        // Daemon-side ordering oracle: the later contracted body is emitted
        // under the same session key, replacing the prior total. Actual backend
        // authority ranking remains the backend's independently enforced rule.
        let mut uploaded = BTreeMap::from([(owner.to_string(), earlier.remove(0))]);
        for item in parsed.snapshots {
            uploaded.insert(item.source_session_id.clone(), item);
        }
        assert_eq!(
            snapshot_upload_body_witness(&uploaded[owner]),
            snapshot_upload_body_witness(&native)
        );
        assert_eq!(uploaded[owner].model_usage, native.model_usage);
    }

    #[test]
    fn compressed_rollout_over_its_decoded_limit_never_finalizes() {
        let plain = synthetic_rollout();
        let encoded = zstd::stream::encode_all(&plain[..], 3).unwrap();
        let compressed_file = fixture(&encoded, ".jsonl.zst");
        let path = &compressed_file.0;
        let mut file = File::open(path).unwrap();
        let expected = opened_object_identity(SnapshotSource::Codex, &mut file).unwrap();
        let credit = compressed_input_credit().unwrap();
        // One byte short: every complete line before the cap still parses, but
        // the stream fails instead of ending as a shorter complete body.
        let input = OpenedInput::compressed(file, plain.len() as u64 - 1, credit).unwrap();
        let error = parse(codex_parser(input, path), &expected, path).unwrap_err();
        assert!(format!("{error:#}").contains("DecodedOverLimit"));
    }
    #[test]
    #[cfg_attr(
        not(any(target_os = "macos", target_os = "linux")),
        ignore = "needs validated heap layout"
    )]
    fn paid_decoder_closes_after_real_eof_early_read_error_and_caught_unwind() {
        let _lock = DECODER_TEST_LOCK.lock().unwrap();
        let encoded = zstd::stream::encode_all(&b"synthetic decoded content"[..], 1).unwrap();
        let valid = fixture(&encoded, ".zst");
        let corrupt = fixture(b"invalid frame", ".zst");
        let cache = Arc::new(sampled_scan::SharedCache::default());
        for exit in 0..4 {
            let ((result, decoded), rows) = crate::local_resource_diagnostics::capture(|| {
                let path = if exit == 2 { &corrupt.0 } else { &valid.0 };
                let mut input = OpenedInput::funded(File::open(path).unwrap(), &cache)
                    .unwrap()
                    .unwrap();
                if let OpenedInput::Compressed(reader, _) = &input {
                    assert_eq!(reader.get_ref().remaining, u64::MAX);
                }
                assert_eq!(
                    input.capacity(),
                    0,
                    "outstanding credit charges the decoder once"
                );
                let mut decoded = Vec::new();
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    if exit == 1 {
                        input.read_exact(&mut [0; 1])?;
                        return Ok(()); // actual read then early exit
                    }
                    input.read_to_end(&mut decoded)?;
                    if exit == 3 {
                        panic!("synthetic consumer unwind");
                    }
                    Ok::<_, io::Error>(())
                }));
                input.close(); // explicit release after caught unwind, before propagation
                (result, decoded)
            });
            assert_eq!(result.is_err(), exit == 3);
            if let Ok(result) = result {
                assert_eq!(result.is_err(), exit == 2);
            }
            if exit == 0 {
                assert_eq!(decoded, b"synthetic decoded content");
            }
            assert_eq!(cache.cursor_reserved(), 0);
            assert!(!rows.iter().any(|r| r["stage"] == "codex_zst_owner"));
            assert!(rows.iter().any(|r| r["stage"] == "codex_zst_input"));
        }
    }
    #[test]
    #[cfg_attr(
        not(any(target_os = "macos", target_os = "linux")),
        ignore = "needs validated heap layout"
    )]
    fn paid_decoder_yields_to_singleton_and_drop_safety_net_is_observable() {
        let _lock = DECODER_TEST_LOCK.lock().unwrap();
        let f = fixture(
            &zstd::stream::encode_all(&b"synthetic"[..], 1).unwrap(),
            ".zst",
        );
        let cache = Arc::new(sampled_scan::SharedCache::default());
        let other = Arc::new(sampled_scan::SharedCache::default());
        let (panic, rows) = crate::local_resource_diagnostics::capture(|| {
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let mut input = OpenedInput::funded(File::open(&f.0).unwrap(), &cache)
                    .unwrap()
                    .unwrap();
                input.read_exact(&mut [0; 1]).unwrap();
                assert!(OpenedInput::funded(File::open(&f.0).unwrap(), &other)
                    .unwrap()
                    .is_none());
                assert_eq!(other.cursor_reserved(), 0);
                panic!("exercise production decoder Drop fallback");
            }))
        });
        assert!(panic.is_err());
        assert_eq!(cache.cursor_reserved(), 0);
        assert_eq!(
            rows.iter()
                .filter(|r| r["counts"]["leaked_release"] == 1)
                .count(),
            1
        );
        OpenedInput::funded(File::open(&f.0).unwrap(), &other)
            .unwrap()
            .unwrap()
            .close();
        assert_eq!(other.cursor_reserved(), 0);
    }
    /// [money] Native and archive placement preserve own creator evidence and
    /// an evidence gap; every row retains its resolved evidence and remainder.
    #[test]
    fn archive_native_placement_preserves_resolved_evidence_and_untagged_remainder() {
        for creator in [false, true] {
            let mut rows: Vec<Value> = String::from_utf8(synthetic_rollout())
                .unwrap()
                .lines()
                .map(|l| serde_json::from_str(l).unwrap())
                .collect();
            if creator {
                rows[0]["timestamp"] = json!("2026-10-07T09:59:00Z");
                rows[0]["payload"]["creator_user_id"] = json!("synthetic-user");
                rows[0]["payload"]["creator_account_id"] = json!("synthetic-workspace");
            }
            let bytes = rows.iter().map(|r| format!("{r}\n")).collect::<String>();
            let archive =
                ArchiveFixture::new(&zstd::stream::encode_all(bytes.as_bytes(), 1).unwrap());
            let plain = Fixture(archive.0.with_extension(""));
            fs::write(&plain.0, &bytes).unwrap();
            let mut bodies = Vec::new();
            for (path, compressed) in [(&plain.0, false), (&archive.0, true)] {
                let mut file = File::open(path).unwrap();
                let expected = opened_object_identity(SnapshotSource::Codex, &mut file).unwrap();
                let input = if compressed {
                    OpenedInput::compressed(file, u64::MAX, compressed_input_credit().unwrap())
                        .unwrap()
                } else {
                    OpenedInput::plain(file)
                };
                bodies.push(parse(codex_parser(input, path), &expected, path).unwrap());
            }
            let a = &bodies[0]["snapshots"][0];
            let b = &bodies[1]["snapshots"][0];
            assert_eq!(a["session_account_evidence"], b["session_account_evidence"]);
            assert_eq!(!a["session_account_evidence"].is_null(), creator);
            assert_eq!(
                a["request_identity_refusals"],
                b["request_identity_refusals"]
            );
            for field in ["model_usage", "usage_buckets"] {
                let left = a[field].as_array().unwrap();
                let right = b[field].as_array().unwrap();
                assert_eq!(left.len(), right.len());
                for (x, y) in left.iter().zip(right) {
                    for name in [
                        "account_identifier_hash",
                        "identity_retained",
                        "auth_mode",
                        "billing_channel",
                        "billing_provider",
                        "subscription_product",
                        "identity_parts",
                    ] {
                        assert_eq!(x[name], y[name], "{name}");
                    }
                    let resolve = |item: &Value, row: &Value| {
                        row["evidence_ref"]
                            .as_u64()
                            .map(|n| item["request_evidence"][n as usize].clone())
                    };
                    assert_eq!(resolve(a, x), resolve(b, y));
                    // Native Codex has no contract-5 share split: all usage is
                    // the explicit untagged remainder, with its creator proof.
                    assert!(x["identity_parts"].is_null());
                    for name in [
                        "input_tokens",
                        "output_tokens",
                        "cache_read_tokens",
                        "cache_creation_5m_tokens",
                        "cache_creation_1h_tokens",
                        "reasoning_output_tokens",
                        "unattributed_total_tokens",
                        "request_count",
                        "cost_usd",
                        "input_cost_usd",
                        "output_cost_usd",
                        "cache_read_cost_usd",
                        "cache_creation_cost_usd",
                    ] {
                        assert_eq!(x[name], y[name], "untagged {name}");
                    }
                }
            }
        }
    }

    // Native synthetic filesystem fixture shared by the archive transitions.
    struct ArchiveFixture(PathBuf);
    impl ArchiveFixture {
        fn new(bytes: &[u8]) -> Self {
            let root = crate::test_scratch::private_dir("codex-archive-intake");
            let path = root.join("rollout-compressed-fixture.jsonl.zst");
            fs::write(&path, bytes).unwrap();
            Self(path)
        }
        fn candidate(&self) -> CandidateFile {
            let mut candidate = codex_zst_refusal_tests::candidate(&self.0);
            candidate.size_bytes = fs::metadata(&self.0).unwrap().len();
            candidate
        }
    }
    impl Drop for ArchiveFixture {
        fn drop(&mut self) {
            fs::remove_dir_all(self.0.parent().unwrap()).unwrap();
        }
    }
    struct Power(bool);
    impl crate::snapshot_sync::continuation::PlatformGates for Power {
        fn power(&mut self) -> crate::snapshot_sync::continuation::PlatformState {
            if self.0 {
                crate::snapshot_sync::continuation::PlatformState::Allowed
            } else {
                crate::snapshot_sync::continuation::PlatformState::Refused
            }
        }
        fn enter_background_qos(&mut self) -> crate::snapshot_sync::continuation::PlatformState {
            crate::snapshot_sync::continuation::PlatformState::Allowed
        }
        fn restore_qos(&mut self) {}
    }
    fn selector_scan(
        f: &ArchiveFixture,
        index: ScanIndex,
        cache: Arc<sampled_scan::SharedCache>,
        candidates: VecDeque<CandidateFile>,
        power: bool,
    ) -> OwnedSourceScan {
        let root = f.0.parent().unwrap().to_owned();
        let paths = candidates
            .iter()
            .map(|c| local_index_key(&c.path))
            .collect();
        let mut directories = codex_file_join::DirectoryCensus::new();
        directories.observe(&root, &fs::metadata(&root).unwrap());
        let inventory = codex_file_join::HeaderInventory::new(
            std::slice::from_ref(&root),
            &paths,
            Some(&directories),
        );
        let mut scan = OwnedSourceScan::new(
            SnapshotSource::Codex,
            &[],
            index,
            NOW,
            BACKFILL_WINDOW_DAYS,
            10,
            false,
            None,
            &[],
            false,
            true,
        )
        .with_sampled_acquisition(cache, Scope("archive-intake-test".into()));
        scan.identified_candidates = candidates;
        scan.census
            .observed_index_keys
            .extend(paths.iter().cloned());
        scan.codex_join_inventory = Some(inventory);
        scan.codex_join_prepared = false;
        scan.census_unix_seconds = None;
        scan.state_census_complete = true;
        scan.sidecar_census_complete = true;
        scan.index.archive_pass.gates = crate::snapshot_sync::ArchiveGates::new(Some(Power(power)));
        scan.index.archive_pass.prepare();
        let traversal = scan.index.traversal.as_mut().unwrap();
        traversal.codex_rollout_paths = paths;
        traversal.scan_roots = vec![root];
        traversal.pending_directories.clear();
        scan
    }
    fn finish_selector(
        mut scan: OwnedSourceScan,
        checkpoint: &Path,
    ) -> (ScanIndex, SourceScanResult) {
        let mut committed = scan.index.clone();
        for _ in 0..100000 {
            match scan.step(None) {
                OwnedSourceScanStep::Pending(mut next) => {
                    next.persist_archive_reservation(&mut committed, checkpoint)
                        .unwrap();
                    scan = next;
                }
                OwnedSourceScanStep::Complete {
                    mut index,
                    mut scan,
                    ..
                } => {
                    apply_upload_policy(
                        SnapshotSource::Codex,
                        &mut scan.snapshots,
                        SnapshotUploadPolicy::default(),
                    );
                    finalize_scan_after_policy(SnapshotSource::Codex, &mut scan, &mut index);
                    return (index, scan);
                }
            }
        }
        panic!("archive native scan made no bounded progress");
    }
    fn run_archive(
        f: &ArchiveFixture,
        index: ScanIndex,
        cache: Arc<sampled_scan::SharedCache>,
    ) -> (ScanIndex, SourceScanResult, Vec<Value>) {
        let ((index, scan), rows) = crate::local_resource_diagnostics::capture(|| {
            let mut candidates = fs::read_dir(f.0.parent().unwrap())
                .unwrap()
                .flatten()
                .filter_map(|e| {
                    let path = e.path();
                    if !transcript_path_admitted(SnapshotSource::Codex, &path) {
                        return None;
                    }
                    let mut c = codex_zst_refusal_tests::candidate(&path);
                    c.size_bytes = fs::metadata(&path).unwrap().len();
                    Some(c)
                })
                .collect::<Vec<_>>();
            candidates.sort_by_key(|c| codex_archive_path(&c.path));
            let scan = selector_scan(f, index, cache, candidates.into(), true);
            let checkpoint = fixture(b"", ".json");
            fs::remove_file(&checkpoint.0).unwrap();
            finish_selector(scan, &checkpoint.0)
        });
        (index, scan, rows)
    }
    fn full_decodes(rows: &[Value]) -> usize {
        rows.iter()
            .filter(|r| r["stage"] == "codex_zst_input")
            .count()
    }
    fn saved(index: &ScanIndex) -> ScanIndex {
        serde_json::from_slice(&serde_json::to_vec(index).unwrap()).unwrap()
    }

    /// [money] Standalone native ownership reads once. Every claimant, parent,
    /// damaged header and unresolved root is owed without a Full decode.
    #[test]
    fn native_archive_fence_is_conservative_and_quiet_between_saved_retries() {
        let _lock = DECODER_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for (case, cause) in [
            ("standalone", None),
            ("plain", Some(CodexZstCause::ArchiveEquivalenceUnproven)),
            ("sibling", Some(CodexZstCause::FamilyUnproven)),
            ("parent", Some(CodexZstCause::ParentLedgerUnbound)),
            ("root", Some(CodexZstCause::OwnerUnproven)),
            ("damaged", Some(CodexZstCause::HeaderInvalid)),
        ] {
            let mut rows: Vec<Value> = String::from_utf8(synthetic_rollout())
                .unwrap()
                .lines()
                .map(|l| serde_json::from_str(l).unwrap())
                .collect();
            if case == "parent" {
                rows[0]["payload"]["forked_from_id"] = json!("unresolved-parent");
            }
            let bytes = rows.iter().map(|r| format!("{r}\n")).collect::<String>();
            let f = ArchiveFixture::new(
                if case == "damaged" {
                    b"invalid zstd".to_vec()
                } else {
                    zstd::stream::encode_all(bytes.as_bytes(), 1).unwrap()
                }
                .as_slice(),
            );
            let mut candidates = VecDeque::from([f.candidate()]);
            if case == "sibling" || case == "plain" {
                let path = f.0.parent().unwrap().join(if case == "sibling" {
                    "renamed.jsonl.zst"
                } else {
                    "rollout-compressed-fixture.jsonl"
                });
                fs::write(
                    &path,
                    if case == "plain" {
                        bytes.into_bytes()
                    } else {
                        fs::read(&f.0).unwrap()
                    },
                )
                .unwrap();
                let mut c = codex_zst_refusal_tests::candidate(&path);
                c.size_bytes = fs::metadata(&path).unwrap().len();
                candidates.push_front(c);
            }
            let mut scan = selector_scan(
                &f,
                ScanIndex::default(),
                Arc::new(sampled_scan::SharedCache::default()),
                candidates,
                true,
            );
            if case == "root" {
                scan.index
                    .legacy_unresolved_root_file_witnesses
                    .insert("unresolved-root".into());
            }
            let checkpoint = fixture(b"", ".json");
            fs::remove_file(&checkpoint.0).unwrap();
            let ((index, result), logs) =
                crate::local_resource_diagnostics::capture(|| finish_selector(scan, &checkpoint.0));
            let key = local_index_key(&f.0);
            if let Some(cause) = cause {
                assert_eq!(index.archives[&key].owed_cause(), Some(cause), "{case}");
                assert_eq!(full_decodes(&logs), 0, "{case}");
                assert_eq!(
                    result.unreadable_path_count, 0,
                    "archive debt stays out of plain errors"
                );
                assert!(!result.census_complete, "archive debt stays disclosed");
                let (_, _, quiet) = run_archive(
                    &f,
                    saved(&index),
                    Arc::new(sampled_scan::SharedCache::default()),
                );
                assert_eq!(full_decodes(&quiet), 0, "{case}");
            } else {
                assert_eq!(result.snapshots.len(), 1);
                assert_eq!(result.snapshots[0].input_tokens, 750);
                assert_eq!(full_decodes(&logs), 1);
            }
        }
    }
    /// [format] Saved header and page-wide Full reservations precede body
    /// bytes. Restart preserves owed custody; a failed save consumes no Full.
    #[test]
    fn archive_reservation_survives_crash_and_save_failure_reads_no_body() {
        let _lock = DECODER_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for fail in [false, true] {
            let f = ArchiveFixture::new(
                &zstd::stream::encode_all(&synthetic_rollout()[..], 1).unwrap(),
            );
            let mut scan = selector_scan(
                &f,
                ScanIndex::default(),
                Arc::new(sampled_scan::SharedCache::default()),
                VecDeque::from([f.candidate()]),
                true,
            );
            let mut committed = scan.index.clone();
            let checkpoint = fixture(b"", ".json");
            fs::remove_file(&checkpoint.0).unwrap();
            let mut reserved = false;
            for _ in 0..1000 {
                let OwnedSourceScanStep::Pending(mut next) = scan.step(None) else {
                    panic!("reservation seam missing")
                };
                let full = next
                    .index
                    .archives
                    .values()
                    .any(|a| matches!(a.disposition, ArchiveDisposition::Pending { .. }));
                if full && next.index.archive_pass.dirty {
                    reserved = true;
                    if fail {
                        fs::remove_file(&checkpoint.0).unwrap();
                        fs::create_dir(&checkpoint.0).unwrap();
                    }
                    assert!(
                        next.active_file.is_none(),
                        "batch precedes parser construction"
                    );
                    let result = next.persist_archive_reservation(&mut committed, &checkpoint.0);
                    assert_eq!(result.is_err(), fail);
                    if fail {
                        fs::remove_dir(&checkpoint.0).unwrap();
                    } else {
                        let restored = ScanIndex::load(&checkpoint.0).unwrap();
                        assert_eq!(restored.archive_owed_count(), 1);
                        let ((_, quiet, logs), bytes) =
                            sampled_scan::transition_fixture::observe_consumed(|| {
                                run_archive(
                                    &f,
                                    restored,
                                    Arc::new(sampled_scan::SharedCache::default()),
                                )
                            });
                        assert!(!quiet.census_complete);
                        assert_eq!(quiet.unreadable_path_count, 0);
                        assert_eq!(bytes, 0);
                        assert_eq!(full_decodes(&logs), 0);
                        assert!(logs.iter().any(|l| l["stage"] == "codex_zst_held"));
                    }
                    break;
                }
                next.persist_archive_reservation(&mut committed, &checkpoint.0)
                    .unwrap();
                scan = next;
            }
            assert!(reserved);
        }
    }
    /// [money] Exact destination bodies settle; wrong and partial bodies keep
    /// acquisition owed. Settled entries discard header and body scratch.
    #[test]
    fn archive_exact_body_receipt_is_required_for_settlement_and_quiet_restart() {
        let _lock = DECODER_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let f =
            ArchiveFixture::new(&zstd::stream::encode_all(&synthetic_rollout()[..], 1).unwrap());
        let (index, result, _) = run_archive(
            &f,
            ScanIndex::default(),
            Arc::new(sampled_scan::SharedCache::default()),
        );
        for exact in [false, true] {
            let mut staged = saved(&index);
            let bodies: BTreeMap<_, _> = result
                .snapshots
                .iter()
                .map(|s| {
                    (
                        s.snapshot_fingerprint.clone(),
                        if exact {
                            snapshot_upload_body_witness(s)
                        } else {
                            "wrong".into()
                        },
                    )
                })
                .collect();
            staged.settle_archive_outcome(|fp| bodies.get(fp).map(String::as_str));
            let a = &staged.archives[&local_index_key(&f.0)];
            assert_eq!(matches!(a.disposition, ArchiveDisposition::Acquired), exact);
            assert_eq!(a.work.is_none(), exact);
            assert!(staged.files[&local_index_key(&f.0)]
                .codex_counting_owner
                .is_some());
            let (_, quiet, logs) = run_archive(
                &f,
                saved(&staged),
                Arc::new(sampled_scan::SharedCache::default()),
            );
            assert!(quiet.snapshots.is_empty());
            assert_eq!(full_decodes(&logs), 0);
            assert_eq!(quiet.census_complete, exact);
        }
    }
    /// [behaviour] Resource refusal costs no Full or six-hour delay; the next
    /// permitted pass can finish using the ordinary native parser.
    #[test]
    fn archive_transient_denial_recovers_next_pass_and_pages_to_eof() {
        let _lock = DECODER_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut bytes = synthetic_rollout();
        let line = json!({"type":"unknown","padding":"x".repeat(1024)}).to_string() + "\n";
        for _ in 0..66000 {
            bytes.extend_from_slice(line.as_bytes());
        }
        let f = ArchiveFixture::new(&zstd::stream::encode_all(bytes.as_slice(), 1).unwrap());
        let checkpoint = fixture(b"", ".json");
        fs::remove_file(&checkpoint.0).unwrap();
        let scan = selector_scan(
            &f,
            ScanIndex::default(),
            Arc::new(sampled_scan::SharedCache::default()),
            VecDeque::from([f.candidate()]),
            false,
        );
        let ((index, result), logs) =
            crate::local_resource_diagnostics::capture(|| finish_selector(scan, &checkpoint.0));
        assert!(result.snapshots.is_empty());
        assert_eq!(full_decodes(&logs), 0);
        assert!(!matches!(
            index.archives[&local_index_key(&f.0)].disposition,
            ArchiveDisposition::Pending { .. }
        ));
        let (_, result, logs) = run_archive(
            &f,
            saved(&index),
            Arc::new(sampled_scan::SharedCache::default()),
        );
        assert_eq!(result.snapshots.len(), 1);
        assert_eq!(full_decodes(&logs), 1);
        assert!(logs
            .iter()
            .any(|l| l["counts"]["codex_zst_decoded_bytes"].as_u64() == Some(bytes.len() as u64)));

        // A cancelled reservation has spent no Full and must not buy a retry
        // penalty or a retry counter. A structural post-Full failure is quiet.
        for spent in [false, true] {
            let mut held = saved(&index);
            let a = held.archives.get_mut(&local_index_key(&f.0)).unwrap();
            a.reserve();
            a.work.as_mut().unwrap().reserved = true;
            if spent {
                a.hold(CodexZstCause::OwnerUnproven);
            } else {
                a.cancel_reservation();
                assert_eq!(a.work.as_ref().unwrap().attempts, 0);
            }
            let (_, next, logs) = run_archive(
                &f,
                saved(&held),
                Arc::new(sampled_scan::SharedCache::default()),
            );
            assert_eq!(full_decodes(&logs), usize::from(!spent));
            assert_eq!(next.snapshots.is_empty(), spent);
        }
    }

    /// [format] Unknown side-map records remain opaque owed custody. Retired
    /// domination labels decode conservatively; no unknown state grants ACK.
    #[test]
    fn archive_marker_compatibility_and_plain_bytes_remain_independent() {
        let f = ArchiveFixture::new(b"metadata only");
        let key = local_index_key(&f.0);
        let mut index = ScanIndex::default();
        let before = serde_json::to_value(&index).unwrap();
        index.archives.insert(
            key.clone(),
            ArchiveEvidence::from_metadata(fs::metadata(&f.0).unwrap()).unwrap(),
        );
        for value in [
            json!("future"),
            json!({"disposition":"new-version"}),
            json!(false),
        ] {
            let mut wire = serde_json::to_value(&index).unwrap();
            wire["archives"][&key] = value;
            let checkpoint = fixture(&serde_json::to_vec(&wire).unwrap(), ".json");
            let held = ScanIndex::load(&checkpoint.0).unwrap();
            assert_eq!(held.archive_owed_count(), 1);
            assert!(held.accepted_snapshot_fingerprints.is_empty());
        }
        assert_eq!(
            serde_json::from_value::<CodexZstCause>(json!("archive_dominated")).unwrap(),
            CodexZstCause::ArchiveEquivalenceUnproven
        );
        index.archives.clear();
        assert_eq!(before, serde_json::to_value(index).unwrap());
    }
    /// [money] Correction debt alarms once per context transition, and the
    /// accepted head never grants a new archive Full on policy/replay churn.
    #[test]
    fn archive_context_change_holds_correction_without_regrant() {
        let _lock = DECODER_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let f =
            ArchiveFixture::new(&zstd::stream::encode_all(&synthetic_rollout()[..], 1).unwrap());
        let (mut index, result, _) = run_archive(
            &f,
            ScanIndex::default(),
            Arc::new(sampled_scan::SharedCache::default()),
        );
        let bodies: BTreeMap<_, _> = result
            .snapshots
            .iter()
            .map(|s| {
                (
                    s.snapshot_fingerprint.clone(),
                    snapshot_upload_body_witness(s),
                )
            })
            .collect();
        index.settle_archive_outcome(|fp| bodies.get(fp).map(String::as_str));
        for replay in [false, true] {
            let mut changed = saved(&index);
            changed.activate_upload_context("first".into());
            let (_, logs) = crate::local_resource_diagnostics::capture(|| {
                for _ in 0..2 {
                    if replay {
                        changed.prepare_historical_replay("changed".into());
                    } else {
                        changed.activate_upload_context("changed".into());
                    }
                }
            });
            assert_eq!(changed.archive_owed_count(), 1);
            assert!(changed.files.contains_key(&local_index_key(&f.0)));
            assert_eq!(
                logs.iter()
                    .filter(|l| l["stage"] == "durable_tail_alarm")
                    .count(),
                1
            );
            let (_, scan, logs) = run_archive(
                &f,
                saved(&changed),
                Arc::new(sampled_scan::SharedCache::default()),
            );
            assert!(!scan.census_complete);
            assert_eq!(full_decodes(&logs), 0);
            assert!(!logs.iter().any(|l| l["stage"] == "durable_tail_alarm"));
        }
    }

    fn downgrade_member(root: &Path, owner: &str, compressed: bool) -> PathBuf {
        let dir = root.join("sessions");
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join(format!(
            "rollout-{owner}.jsonl{}",
            if compressed { ".zst" } else { "" }
        ));
        let bytes = codex_file_join::tests::member(owner, "response", 100, 100)
            .iter()
            .map(|v| format!("{v}\n"))
            .collect::<String>();
        fs::write(
            &path,
            if compressed {
                zstd::stream::encode_all(bytes.as_bytes(), 1).unwrap()
            } else {
                bytes.into_bytes()
            },
        )
        .unwrap();
        path
    }
    fn downgrade_accepted(path: &Path, body: &SnapshotItem) -> ScanIndex {
        let mut index = ScanIndex::default();
        let key = local_index_key(path);
        let fp = body.snapshot_fingerprint.clone();
        index.files.insert(
            key.clone(),
            ScanIndexEntry {
                source_file_fingerprint: "accepted-source".into(),
                last_snapshot_fingerprint: Some(fp.clone()),
                last_upload_body_witness: Some(snapshot_upload_body_witness(body)),
                scan_identity_version: Some(LOCAL_SCAN_INDEX_IDENTITY_VERSION.into()),
                ..Default::default()
            },
        );
        index
            .file_snapshot_fingerprints
            .insert(key, BTreeSet::from([fp.clone()]));
        index
            .snapshot_activity_at
            .insert(fp.clone(), snapshot_semantic_activity_at(body));
        index.accepted_snapshot_fingerprints.insert(fp);
        index
    }
    fn downgrade_seed(index: &mut ScanIndex, path: &Path) {
        let mut a = ArchiveEvidence::from_metadata(fs::metadata(path).unwrap()).unwrap();
        a.hold(CodexZstCause::FamilyUnproven);
        index.archives.insert(local_index_key(path), a);
        index
            .files
            .entry(local_index_key(path))
            .or_default()
            .scan_identity_version = Some(LOCAL_SCAN_INDEX_IDENTITY_VERSION.into());
    }
    /// [format] The historical-runtime driver consumes a genuine native
    /// accepted head and unknown additive marker, with a same-generation CAS.
    #[test]
    fn write_codex_zst_downgrade_fixture() {
        let root = crate::test_scratch::private_dir("archive-old-writer");
        let owner = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
        let plain = downgrade_member(&root, owner, false);
        let (_, native) = codex_file_join::tests::scan(&root, ScanIndex::default(), 10);
        assert_eq!(native.snapshots.len(), 1);
        let mut index = downgrade_accepted(&plain, &native.snapshots[0]);
        let archive = downgrade_member(&root, "ffffffff-bbbb-4ccc-8ddd-eeeeeeeeeeee", true);
        downgrade_seed(&mut index, &archive);
        index
            .files
            .get_mut(&local_index_key(&archive))
            .unwrap()
            .scan_identity_version = Some(LOCAL_SCAN_INDEX_IDENTITY_VERSION.into());
        let out = std::env::var_os("OTTTO_ZST_DOWNGRADE_FIXTURE_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| root.join("out"));
        fs::create_dir_all(&out).unwrap();
        index.save(&out.join("branch.json")).unwrap();
        let mut control = serde_json::to_value(&index).unwrap();
        control.as_object_mut().unwrap().remove("archives");
        fs::write(
            out.join("as-today.json"),
            serde_json::to_vec(&control).unwrap(),
        )
        .unwrap();
        let singleton = downgrade_member(&out.join("activation"), owner, true);
        let mut activation = downgrade_accepted(&singleton, &native.snapshots[0]);
        downgrade_seed(&mut activation, &singleton);
        let a = activation
            .archives
            .get_mut(&local_index_key(&singleton))
            .unwrap();
        a.disposition = ArchiveDisposition::Acquired;
        a.work = None;
        activation.save(&out.join("activation.json")).unwrap();
        fs::write(out.join("activation-key.txt"), local_index_key(&singleton)).unwrap();
        fs::remove_dir_all(root).unwrap();
    }
    /// [format] Old writers discard unknown markers without resetting native
    /// accepted incidence; re-upgrade preserves those exact accepted heads.
    #[test]
    fn verify_codex_zst_downgrade_roundtrip() {
        let Some(root) = std::env::var_os("OTTTO_ZST_DOWNGRADE_FIXTURE_DIR").map(PathBuf::from)
        else {
            return;
        };
        let expected = ScanIndex::load(&root.join("as-today.json")).unwrap();
        for label in ["stable", "r1"] {
            let (index, origin) =
                ScanIndex::load_inner(&root.join(format!("{label}.json")), None).unwrap();
            assert!(matches!(origin, LoadOrigin::Loaded(_)));
            assert_eq!(index.files.len(), 2);
            assert_eq!(
                index.file_snapshot_fingerprints,
                expected.file_snapshot_fingerprints
            );
            assert_eq!(
                index.accepted_snapshot_fingerprints,
                expected.accepted_snapshot_fingerprints
            );
            assert!(index.archives.is_empty());
        }
    }
    /// [format] A historical census cannot erase the archive object: ordinary
    /// discovery schedules it again after re-upgrade, without fabricating ACKs.
    #[test]
    fn historical_census_saved_singleton_schedules_a1_on_reupgrade() {
        let Some(root) = std::env::var_os("OTTTO_ZST_DOWNGRADE_FIXTURE_DIR").map(PathBuf::from)
        else {
            return;
        };
        let key = fs::read_to_string(root.join("activation-key.txt")).unwrap();
        for label in ["stable", "r1"] {
            let index = ScanIndex::load(&root.join(format!("{label}-census.json"))).unwrap();
            assert!(!index.files.contains_key(&key));
            assert!(!index.file_snapshot_fingerprints.contains_key(&key));
            let mut scan = OwnedSourceScan::new(
                SnapshotSource::Codex,
                &[root.join("activation/sessions")],
                index,
                NOW,
                7,
                10,
                false,
                None,
                &[],
                false,
                false,
            );
            scan.index.archive_pass.gates =
                crate::snapshot_sync::ArchiveGates::new(Some(Power(false)));
            for _ in 0..100 {
                if scan
                    .identified_candidates
                    .iter()
                    .any(|c| local_index_key(&c.path) == key)
                {
                    break;
                }
                scan = match scan.step(None) {
                    OwnedSourceScanStep::Pending(next) => next,
                    OwnedSourceScanStep::Complete { .. } => panic!("archive remains discoverable"),
                };
            }
            let candidate = scan
                .identified_candidates
                .iter()
                .find(|c| local_index_key(&c.path) == key)
                .unwrap();
            assert_eq!(
                scan.index.candidate_decision(candidate),
                CandidateDecision::Parse
            );
            assert!(!scan.index.files.contains_key(&key));
        }
    }
    /// [behaviour] Settled archive metadata owns no header/body heap and the
    /// ordinary entry retains main's layout, independent of archive population.
    #[test]
    fn settled_archive_metadata_discards_acquisition_allocations() {
        let f = ArchiveFixture::new(b"metadata only");
        let mut a = ArchiveEvidence::from_metadata(fs::metadata(&f.0).unwrap()).unwrap();
        a.reserve();
        a.work.as_mut().unwrap().body_witness = Some("body".repeat(100));
        a.settle(true);
        assert!(a.work.is_none());
        assert!(std::mem::size_of::<ArchiveEvidence>() <= 128);
        #[cfg(target_os = "macos")]
        assert_eq!(std::mem::size_of::<ScanIndexEntry>(), 560);
    }
    /// [money] Empty is terminal only without usage evidence; an empty output
    /// with recognized usage remains owed instead of becoming a zero total.
    #[test]
    fn archive_empty_requires_zero_usage_evidence() {
        let data = synthetic_rollout();
        let f = fixture(&data, ".jsonl");
        for evidence in [false, true] {
            let mut file = File::open(&f.0).unwrap();
            let expected = opened_object_identity(SnapshotSource::Codex, &mut file).unwrap();
            let mut parser = codex_parser(OpenedInput::plain(file), &f.0);
            while !parser.step().unwrap() {}
            let mut parsed = parser
                .finish(
                    &expected,
                    &f.0,
                    NOW,
                    "fixture".into(),
                    Some(&CodexTitleMetadata::default()),
                    None,
                    None,
                )
                .unwrap();
            parsed.snapshots.clear();
            parsed.zero_snapshot_usage_evidence = evidence;
            let mut a = ArchiveEvidence::from_metadata(fs::metadata(&f.0).unwrap()).unwrap();
            a.work.as_mut().unwrap().header = Some(Box::new(
                ValidatedHeader::from_line(data.split(|b| *b == b'\n').next().unwrap()).unwrap(),
            ));
            a.reserve();
            assert_eq!(a.finish(Some("compressed-fixture"), &parsed), !evidence);
            assert_eq!(
                matches!(a.disposition, ArchiveDisposition::Empty),
                !evidence
            );
        }
    }
}
