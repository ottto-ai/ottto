//! Bounded `.jsonl.zst` rollout input behind the one opened-object parser seam.
//! Archive metadata never grants ownership or acceptance authority.
use crate::local_resource_diagnostics::{codex_zst_refused, CodexZstCause};
#[cfg(test)]
use std::collections::BTreeMap;
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

impl super::OwnedSourceScan {
    pub(crate) fn persist_archive_reservation(
        &mut self,
        committed: &mut super::ScanIndex,
        path: &Path,
    ) -> anyhow::Result<()> {
        let Some((key, evidence)) = self.active_file.as_ref().and_then(|active| {
            let key = super::local_index_key(&active.candidate.path);
            let entry = self.index.files.get_mut(&key)?;
            let evidence = entry.archive.as_mut()?;
            (!evidence.reservation_saved).then_some((key, evidence))
        }) else {
            return Ok(());
        };
        let previous = committed.files.get(&key).cloned();
        let reserved = committed.files.entry(key.clone()).or_default();
        reserved.archive = Some(evidence.clone());
        if let Err(error) = committed.save(path) {
            if let Some(entry) = previous {
                committed.files.insert(key, entry);
            } else {
                committed.files.remove(&key);
            }
            if let Some(active) = self.active_file.take() {
                active.parser.reader.reader.close();
            }
            return Err(error);
        }
        self.index.generation = committed.generation;
        evidence.reservation_saved = true;
        if evidence.decode_attempts == 1 {
            crate::local_resource_diagnostics::traversal_point(
                "codex_zst_first_read",
                "codex",
                &serde_json::json!({"codex_zst_first_read": 1}),
            );
        }
        if evidence.decode_attempts > 1 {
            crate::local_resource_diagnostics::traversal_point(
                "codex_zst_first_read_retry",
                "codex",
                &serde_json::json!({"codex_zst_first_read_retry": 1}),
            );
            // Any repeated Full is the named exception: alarm once per saved retry.
            crate::local_resource_diagnostics::traversal_point(
                "codex_zst_retry_alarm",
                "codex",
                &serde_json::json!({"codex_zst_retry_alarm": 1, "decode_attempt": evidence.decode_attempts}),
            );
        }
        Ok(())
    }
}
/// Metadata: no content, offsets, checkpoint or acceptance authority.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct ArchiveEvidence {
    pub(super) stamp: crate::transcript_acquisition::FileStamp,
    pub(super) logical_id: String,
    pub(super) owner: Option<String>,
    pub(super) disposition: ArchiveDisposition,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) body_witness: Option<String>,
    #[serde(skip)]
    pub(super) reservation_saved: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) header_validated: Option<ValidatedHeader>,
    #[serde(default)]
    header_attempted: bool,
    #[serde(default, deserialize_with = "header_bound_or_false")]
    header_bound_reached: bool,
    #[serde(default)]
    pub(super) decode_attempts: u64,
    #[serde(default)]
    pub(super) hold: Option<CodexZstCause>,
}
// Compatibility: an unknown representation grants no skip authority. Consume it
// without retaining arbitrary malformed content or failing the whole entry.
fn header_bound_or_false<'de, D: serde::Deserializer<'de>>(de: D) -> Result<bool, D::Error> {
    #[derive(serde::Deserialize)]
    #[serde(untagged)]
    enum Flag {
        Bool(bool),
        Other(serde::de::IgnoredAny),
    }
    Ok(matches!(
        serde::Deserialize::deserialize(de)?,
        Flag::Bool(true)
    ))
}
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub(crate) enum ArchiveDisposition {
    HeaderValidated,
    Acquired,
    Empty,
    Pending { attempts: u64, retry_after: u64 },
    Held { cause: CodexZstCause },
    Refused { cause: CodexZstCause },
}
/// Metadata: metadata only, never a group member or completion certificate.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub(super) struct ValidatedHeader {
    pub(super) owner: String,
    pub(super) digest: String,
    pub(super) created_unix_ms: Option<i64>,
}
impl ValidatedHeader {
    pub(super) fn from_bytes(bytes: &[u8]) -> Option<Self> {
        Self::from_line(bytes.strip_suffix(b"\n")?)
    }
    pub(super) fn from_line(bytes: &[u8]) -> Option<Self> {
        use super::*;
        if bytes.len() > jsonl_line_cap() {
            return None;
        }
        let value: Value = serde_json::from_slice(bytes).ok()?;
        let (owner, created_unix_ms) = codex_file_join::owning_header(&value).ok()?;
        let digest = Sha256::new().chain_update(bytes).chain_update(b"\n");
        Some(Self {
            owner,
            digest: format!("{:x}", digest.finalize()),
            created_unix_ms,
        })
    }
}
crate::heap_layout_bound::fields!(ValidatedHeader; owner, digest, created_unix_ms);
impl ArchiveEvidence {
    fn header_for(&self, _path: &Path) -> Option<&ValidatedHeader> {
        self.header_validated.as_ref()
    }
    pub(super) fn begin(file: &File, path: &Path, previous: Option<&Self>) -> io::Result<Self> {
        let stamp = crate::transcript_acquisition::FileStamp::capture(file.metadata()?)?;
        let logical = path.with_extension("");
        let logical_id = super::codex_session_id_candidates_from_path(&logical)
            .into_iter()
            .next()
            .ok_or_else(|| invalid("compressed rollout logical id unavailable"))?;
        // The retained historical body keeps its validated identity while a
        // changed stamp waits for acquisition. Current-header and retry facts
        // below remain scoped to the matching stamp.
        let logical_id = previous.map_or(logical_id, |old| old.logical_id.clone());
        let previous = previous.filter(|old| old.stamp.same_content(&stamp));
        let attempts = previous
            .map_or(0, |old| old.decode_attempts)
            .saturating_add(1);
        Ok(Self {
            stamp: stamp.content_only(),
            logical_id,
            owner: None,
            body_witness: None,
            reservation_saved: false,
            decode_attempts: attempts,
            hold: None,
            header_attempted: previous.is_some_and(|a| a.header_attempted),
            header_bound_reached: previous.is_some_and(|a| a.header_bound_reached),
            header_validated: previous.and_then(|a| a.header_validated.clone()),
            disposition: ArchiveDisposition::Pending {
                attempts,
                retry_after: super::sampled_scan::now_seconds().saturating_add(6 * 3600),
            },
        })
    }
    /// Paced custody retries spend the existing saved reservation. Keep the
    /// retry deadline instead of turning revocable debt into a terminal state.
    pub(super) fn defer_custody(&mut self, cause: CodexZstCause) {
        let retry_after = match self.disposition {
            ArchiveDisposition::Pending { retry_after, .. }
                if retry_after > super::sampled_scan::now_seconds() =>
            {
                retry_after
            }
            _ => super::sampled_scan::now_seconds().saturating_add(6 * 3600),
        };
        self.hold = Some(cause);
        self.disposition = ArchiveDisposition::Pending {
            attempts: self.decode_attempts,
            retry_after,
        };
        codex_zst_refused(cause);
    }

    pub(super) fn finish(
        &mut self,
        owner: Option<String>,
        path: &Path,
        parsed: &super::ParsedJsonlFile,
    ) -> bool {
        use ArchiveDisposition::*;
        let header = self.header_for(path);
        self.owner = owner.filter(|o| header.is_some_and(|h| h.owner == *o));
        if let Some(owner) = &self.owner {
            self.logical_id = owner.clone();
        }
        if self.owner.is_none() {
            codex_zst_refused(CodexZstCause::OwnerUnproven);
            self.disposition = Held {
                cause: CodexZstCause::OwnerUnproven,
            };
        } else if !parsed.complete()
            && !parsed.codex_parent_resolution_pending
            && !parsed
                .codex_parent_unresolvable
                .is_some_and(|c| c.deferred())
        {
            codex_zst_refused(CodexZstCause::OutputHeld);
            self.disposition = Held {
                cause: CodexZstCause::OutputHeld,
            };
        } else if parsed.complete() && parsed.snapshots.is_empty() {
            self.disposition = Empty;
        }
        if parsed.codex_parent_resolution_pending || parsed.codex_parent_unresolvable.is_some() {
            self.defer_custody(CodexZstCause::ParentLedgerUnbound);
            return false;
        }
        self.owner.is_some() && parsed.complete()
    }
    pub(super) fn quiet_disposition(&self) -> bool {
        !matches!(self.disposition, ArchiveDisposition::HeaderValidated)
            && !matches!(self.disposition, ArchiveDisposition::Pending { retry_after, .. } if super::sampled_scan::now_seconds() >= retry_after)
    }
    pub(super) fn quiet(&self, file: &File) -> bool {
        self.matches(file) && self.quiet_disposition()
    }
    pub(super) fn settle(&mut self, accepted: bool) {
        if accepted && matches!(self.disposition, ArchiveDisposition::Pending { .. }) {
            self.disposition = ArchiveDisposition::Acquired;
        }
    }
    pub(super) fn terminal_cause(&self) -> Option<CodexZstCause> {
        match self.disposition {
            ArchiveDisposition::Held { cause } | ArchiveDisposition::Refused { cause } => {
                Some(cause)
            }
            _ => None,
        }
    }
    fn header_bound_pending(&self) -> bool {
        use ArchiveDisposition::*;
        self.header_bound_reached && matches!(self.disposition, HeaderValidated | Pending { .. })
    }
    pub(super) fn matches(&self, file: &File) -> bool {
        file.metadata()
            .and_then(crate::transcript_acquisition::FileStamp::capture)
            .is_ok_and(|stamp| self.stamp.same_content(&stamp))
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

/// The shared admission gates supply power permission and account for header CPU.
#[derive(Clone, Debug, Default)]
pub(super) struct HeaderWork {
    pub(super) allowed: bool,
    pub(super) physical_bytes: u64,
    pub(super) decoded_bytes: u64,
    pub(super) cpu_micros: u64,
}
crate::heap_layout_bound::fields!(HeaderWork; allowed, physical_bytes, decoded_bytes, cpu_micros);
#[derive(Debug)]
pub(super) struct ArchiveAdmissionYield;
impl std::fmt::Display for ArchiveAdmissionYield {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("compressed rollout admission yielded")
    }
}
impl std::error::Error for ArchiveAdmissionYield {}
#[derive(Debug)]
pub(super) enum HeaderRead {
    Validated(ValidatedHeader),
    BoundReached,
    Deferred,
}
impl super::ScanIndex {
    pub(super) fn inventory_archive_header(
        &mut self,
        candidate: &super::CandidateFile,
        cache: Option<&std::sync::Arc<super::sampled_scan::SharedCache>>,
        work: &mut HeaderWork,
    ) -> super::Result<HeaderRead> {
        use super::*;
        // Cached ownership evidence cannot grant acquisition permission.
        if !work.allowed {
            return Ok(HeaderRead::Deferred);
        }
        let key = local_index_key(&candidate.path);
        if self.decode_holds_file(&key) {
            crate::local_resource_diagnostics::codex_zst_held(CodexZstCause::OwnerUnproven);
            crate::local_resource_diagnostics::durable_tail_alarm(
                "codex",
                &serde_json::json!({"archive_held":1}),
            );
            return Ok(HeaderRead::Deferred);
        }
        let file = open_candidate_beneath_root(candidate)?;
        let previous = self.files.get(&key).and_then(|e| e.archive.as_deref());
        let old = previous.filter(|a| a.matches(&file));
        if let Some(header) = old.and_then(|a| a.header_for(&candidate.path)) {
            return Ok(HeaderRead::Validated(header.clone()));
        }
        if let Some(old) = old {
            if old.header_bound_pending() {
                return Ok(HeaderRead::BoundReached);
            }
            if old.quiet(&file)
                && (old.header_attempted
                    || !matches!(old.disposition, ArchiveDisposition::HeaderValidated))
            {
                codex_zst_refused(CodexZstCause::HeaderInvalid);
                anyhow::bail!("archive header unavailable without another read");
            }
        }
        if work.cpu_micros >= 30_000_000 {
            return Ok(HeaderRead::Deferred);
        }
        crate::context_composition::set_utility_qos();
        let started = crate::context_composition::thread_cpu_micros();
        let mut evidence = ArchiveEvidence::begin(&file, &candidate.path, previous)?;
        evidence.disposition = ArchiveDisposition::HeaderValidated;
        evidence.decode_attempts = 0;
        let mut input = match cache.map(|cache| (cache, OpenedInput::funded(file, cache))) {
            Some((_cache, Ok(Some(input)))) => input.header_only(),
            Some((_cache, Ok(None))) => {
                crate::local_resource_diagnostics::codex_zst_refused(
                    CodexZstCause::AdmissionStarved,
                );
                return Ok(HeaderRead::Deferred);
            }
            _ => {
                codex_zst_refused(CodexZstCause::AdmissionRefused);
                return Ok(HeaderRead::Deferred);
            }
        };
        evidence.header_attempted = true;
        self.files.entry(key.clone()).or_default().archive = Some(Box::new(evidence));
        let result = (|| -> Result<HeaderRead> {
            let line = codex_file_join::read_header_line(&mut input)?;
            let evidence = self.files[&key].archive.as_ref().expect("header attempt");
            anyhow::ensure!(
                evidence.matches(input.get_ref()),
                "archive changed during header read"
            );
            let Some(bytes) = line else {
                return Ok(HeaderRead::BoundReached);
            };
            let header =
                ValidatedHeader::from_bytes(&bytes).context("invalid archive owning header")?;
            Ok(HeaderRead::Validated(header))
        })();
        let (physical, decoded, compressed) = match &input {
            OpenedInput::Compressed(r, _) => (
                r.get_ref().physical_limit - r.get_ref().input.get_ref().limit(),
                r.get_ref().decoded_bytes,
                r.get_ref().compressed_bytes,
            ),
            _ => unreachable!(),
        };
        // Unknown CPU exhausts the header work: unknown is denied.
        let cpu = started
            .zip(crate::context_composition::thread_cpu_micros())
            .map_or(u64::MAX, |(started, ended)| ended.saturating_sub(started));
        work.physical_bytes = work.physical_bytes.saturating_add(physical);
        work.decoded_bytes = work.decoded_bytes.saturating_add(decoded);
        work.cpu_micros = work.cpu_micros.saturating_add(cpu);
        // S2 inventory counts actual physical I/O, including read-ahead/errors.
        crate::local_resource_diagnostics::traversal_point(
            "codex_zst_inventory",
            "codex",
            &serde_json::json!({
                "codex_aux_reads": {"header_read_attempts": {"inventory": 1}, "header_read_bytes": {"inventory": physical}},
                "codex_zst_inventory_decoded_bytes": decoded,
                "codex_zst_inventory_physical_bytes": physical,
                "codex_zst_inventory_compressed_consumed_bytes": compressed,
                "codex_zst_inventory_cpu_micros": cpu,
                "codex_zst_decoder_native_peak_bytes": match &input {
                    OpenedInput::Compressed(r, _) => r.get_ref().context.peak_bytes(),
                    _ => 0,
                },
                "codex_zst_decoder_allocation_refusals": match &input {
                    OpenedInput::Compressed(r, _) => r.get_ref().context.allocation_refusals(),
                    _ => 0,
                },
            }),
        );
        input.close();
        let entry = self.files.get_mut(&key).expect("header attempt");
        let evidence = entry.archive.as_mut().expect("header attempt");
        match &result {
            Ok(HeaderRead::Validated(header)) => evidence.header_validated = Some(header.clone()),
            Ok(HeaderRead::BoundReached) => evidence.header_bound_reached = true,
            Err(_) => {
                evidence.defer_custody(CodexZstCause::HeaderInvalid);
                codex_zst_refused(CodexZstCause::HeaderInvalid);
            }
            _ => {}
        }
        result
    }
    #[cfg(test)]
    pub(crate) fn settle_archive_bodies(&mut self, accepted: &BTreeMap<String, String>) {
        self.settle_archive_outcome(|fp| accepted.get(fp).map(String::as_str));
    }
    pub(crate) fn settle_archive_outcome<'a>(
        &mut self,
        mut accepted: impl FnMut(&str) -> Option<&'a str>,
    ) {
        for (key, entry) in &mut self.files {
            if let Some(archive) = entry.archive.as_mut() {
                let accepted_witness = self
                    .file_snapshot_fingerprints
                    .get(key)
                    .into_iter()
                    .flatten()
                    .map(|fp| accepted(fp))
                    .collect::<Option<BTreeSet<_>>>()
                    .filter(|b| !b.is_empty())
                    .map(super::snapshot_file_upload_body_set_hex);
                archive
                    .settle(accepted_witness.is_some() && accepted_witness == archive.body_witness);
            }
        }
    }
}
crate::heap_layout_bound::fields!(ArchiveEvidence; stamp, logical_id, owner, disposition, body_witness, reservation_saved, header_validated, header_attempted, decode_attempts, header_bound_reached, hold);
impl crate::heap_layout_bound::HeapLayoutBound for ArchiveDisposition {
    fn heap_bound(&self, c: &mut crate::heap_layout_bound::Counter) -> Option<()> {
        c.add(0)
    }
}

impl std::fmt::Debug for ArchiveEvidence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ArchiveEvidence")
            .field("attempts", &self.decode_attempts)
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
            let plain = fixture(bytes.as_bytes(), ".jsonl");
            let archive = fixture(
                &zstd::stream::encode_all(bytes.as_bytes(), 1).unwrap(),
                ".jsonl.zst",
            );
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
                bodies.push(parse(codex_parser(input, &plain.0), &expected, &plain.0).unwrap());
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
        scan.index.archive_pass.gates = crate::snapshot_sync::ArchiveGates::new(Power(power));
        scan.index.archive_pass.prepare();
        let traversal = scan.index.traversal.as_mut().unwrap();
        traversal.codex_rollout_paths = paths;
        traversal.scan_roots = vec![root];
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
            let scan = if index
                .files
                .get(&local_index_key(&f.0))
                .and_then(|e| e.archive.as_ref())
                .is_some_and(|a| a.quiet(&File::open(&f.0).unwrap()))
            {
                let mut scan = OwnedSourceScan::new(
                    SnapshotSource::Codex,
                    &[f.0.parent().unwrap().to_owned()],
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
                scan.index.archive_pass.gates =
                    crate::snapshot_sync::ArchiveGates::new(Power(true));
                scan
            } else {
                selector_scan(f, index, cache, VecDeque::from([f.candidate()]), true)
            };
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

    /// [money] Standalone uses native totals; every conservative fence class stays
    /// owed with its cause, saved deadline and zero decodes on the following pass.
    #[test]
    fn native_archive_fence_is_conservative_and_quiet_between_saved_retries() {
        let _lock = DECODER_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for (case, cause) in [
            ("standalone", None),
            ("sibling", Some(CodexZstCause::FamilyUnproven)),
            ("damaged", Some(CodexZstCause::OwnerUnproven)),
            ("parent", Some(CodexZstCause::ParentLedgerUnbound)),
            ("creator", Some(CodexZstCause::OwnerUnproven)),
            ("unaffordable", Some(CodexZstCause::AdmissionRefused)),
        ] {
            let mut bytes = synthetic_rollout();
            if case == "parent" || case == "creator" {
                let mut rows: Vec<Value> = String::from_utf8(bytes)
                    .unwrap()
                    .lines()
                    .map(|l| serde_json::from_str(l).unwrap())
                    .collect();
                if case == "parent" {
                    rows[0]["payload"]["forked_from_id"] =
                        json!("ffffffff-bbbb-4ccc-8ddd-eeeeeeeeeeee");
                    rows[0]["payload"]["history_mode"] = json!("paginated");
                } else {
                    rows[0]["timestamp"] = json!("2026-10-07T09:59:00Z");
                    rows[0]["payload"]["creator_user_id"] = json!("creator-one");
                    rows[0]["payload"]["creator_account_id"] = json!("account-one");
                    let mut conflict = rows[0].clone();
                    conflict["payload"]["creator_account_id"] = json!("account-two");
                    rows.insert(1, conflict);
                }
                bytes = rows
                    .iter()
                    .map(|r| format!("{r}\n"))
                    .collect::<String>()
                    .into_bytes();
            }
            let f = ArchiveFixture::new(&zstd::stream::encode_all(&bytes[..], 1).unwrap());
            let key = local_index_key(&f.0);
            let cache = Arc::new(sampled_scan::SharedCache::default());
            let mut candidates = VecDeque::from([f.candidate()]);
            if case == "sibling" || case == "damaged" {
                let path =
                    f.0.parent()
                        .unwrap()
                        .join("other-compressed-fixture.jsonl.zst");
                fs::write(
                    &path,
                    if case == "sibling" {
                        fs::read(&f.0).unwrap()
                    } else {
                        b"invalid zstd".to_vec()
                    },
                )
                .unwrap();
                let mut candidate = codex_zst_refusal_tests::candidate(&path);
                candidate.size_bytes = fs::metadata(&path).unwrap().len();
                candidates.push_back(candidate);
            }
            let scan = selector_scan(
                &f,
                ScanIndex::default(),
                cache.clone(),
                candidates,
                case != "unaffordable",
            );
            let ((index, result), rows) = crate::local_resource_diagnostics::capture(|| {
                let checkpoint = fixture(b"", ".json");
                fs::remove_file(&checkpoint.0).unwrap();
                finish_selector(scan, &checkpoint.0)
            });
            if let Some(cause) = cause {
                assert!(result.snapshots.is_empty(), "{case}");
                if let Some(a) = index.files.get(&key).and_then(|e| e.archive.as_ref()) {
                    assert_eq!(a.hold, Some(cause), "{case}");
                    assert!(
                        matches!(a.disposition, ArchiveDisposition::Pending { retry_after, .. } if retry_after >= sampled_scan::now_seconds())
                    );
                    let (_, quiet, quiet_rows) = run_archive(
                        &f,
                        saved(&index),
                        Arc::new(sampled_scan::SharedCache::default()),
                    );
                    assert!(quiet.snapshots.is_empty(), "{case}");
                    assert_eq!(full_decodes(&quiet_rows), 0, "{case}");
                } else {
                    assert_eq!(case, "unaffordable");
                    assert_eq!(full_decodes(&rows), 0);
                }
            } else {
                assert_eq!(result.snapshots.len(), 1);
                assert_eq!(result.snapshots[0].input_tokens, 750);
                assert_eq!(full_decodes(&rows), 1);
            }
        }
    }

    /// [format] A crash after reservation and a refused save both precede any
    /// Full bytes; the committed deadline survives reload without spending again.
    #[test]
    fn archive_reservation_survives_crash_and_save_failure_reads_no_body() {
        let _lock = DECODER_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for fail in [false, true] {
            let f = ArchiveFixture::new(
                &zstd::stream::encode_all(&synthetic_rollout()[..], 1).unwrap(),
            );
            let key = local_index_key(&f.0);
            let cache = Arc::new(sampled_scan::SharedCache::default());
            let mut scan = selector_scan(
                &f,
                ScanIndex::default(),
                cache.clone(),
                VecDeque::from([f.candidate()]),
                true,
            );
            let mut committed = ScanIndex::default();
            let checkpoint = fixture(b"", ".json");
            fs::remove_file(&checkpoint.0).unwrap();
            let path = checkpoint.0.clone();
            if fail {
                fs::create_dir(&path).unwrap();
            }
            let mut reserved = false;
            for _ in 0..1000 {
                let OwnedSourceScanStep::Pending(mut next) = scan.step(None) else {
                    panic!("missing reservation seam")
                };
                if next
                    .active_file
                    .as_ref()
                    .is_some_and(|a| a.parser.reader.reader.is_compressed())
                {
                    reserved = true;
                    let active = next.active_file.as_ref().unwrap();
                    assert_eq!(active.parser.reader.consumed_bytes(), 0);
                    let result = next.persist_archive_reservation(&mut committed, &path);
                    assert_eq!(result.is_err(), fail);
                    if fail {
                        assert!(next.active_file.is_none());
                        assert!(!committed.files.contains_key(&key));
                        fs::remove_dir(&path).unwrap();
                    } else {
                        let restored = ScanIndex::load(&path).unwrap();
                        assert_eq!(
                            restored.files[&key]
                                .archive
                                .as_ref()
                                .unwrap()
                                .decode_attempts,
                            1
                        );
                        assert!(restored.files[&key]
                            .archive
                            .as_ref()
                            .unwrap()
                            .quiet(&File::open(&f.0).unwrap()));
                        next.active_file
                            .take()
                            .unwrap()
                            .parser
                            .reader
                            .reader
                            .close();
                    }
                    break;
                }
                scan = next;
            }
            assert!(reserved, "reservation boundary reached");
            assert_eq!(cache.cursor_reserved(), 0);
        }
    }

    /// [money] Only the destination's exact accepted bodies settle an archive;
    /// old/wrong bodies and partial acknowledgements retain its saved custody.
    #[test]
    fn archive_exact_body_receipt_is_required_for_settlement_and_quiet_restart() {
        use sampled_scan::transition_fixture::{money_oracle, scan_money};
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
        let key = local_index_key(&f.0);
        let accepted: BTreeMap<_, _> = result
            .snapshots
            .iter()
            .map(|s| {
                (
                    s.snapshot_fingerprint.clone(),
                    snapshot_upload_body_witness(s),
                )
            })
            .collect();
        for exact in [false, true] {
            let mut staged = saved(&index);
            let evidence = if exact {
                accepted.clone()
            } else {
                accepted
                    .keys()
                    .map(|fp| (fp.clone(), "wrong-body".into()))
                    .collect()
            };
            staged.settle_archive_bodies(&evidence);
            assert_eq!(
                matches!(
                    staged.files[&key].archive.as_ref().unwrap().disposition,
                    ArchiveDisposition::Acquired
                ),
                exact
            );
            let (((restart, quiet, rows), consumed), samples) =
                crate::transcript_acquisition::capture_sample_reads(|| {
                    sampled_scan::transition_fixture::observe_consumed(|| {
                        run_archive(
                            &f,
                            saved(&staged),
                            Arc::new(sampled_scan::SharedCache::default()),
                        )
                    })
                });
            assert!(quiet.snapshots.is_empty());
            assert_eq!(full_decodes(&rows), 0);
            if exact {
                let mut route = scan_money(SnapshotSource::Codex, &restart, &quiet);
                route.mode = sampled_scan::transition_fixture::Mode::Restart;
                route.io.consumed = consumed;
                // The selector rejected the quiet key before object identity,
                // header or parser construction; sampled acquisition is observed.
                assert!(samples.is_empty());
                assert!(!rows.iter().any(|r| r["stage"] == "codex_zst_inventory"));
                route.io.cheap_checks = Some(
                    samples
                        .iter()
                        .map(|r| r.result.as_ref().copied().unwrap_or(0) as u64)
                        .sum(),
                );
                route.io.anchor_reads = Some(0);
                route.io.other_reads = Some(0);
                money_oracle::assert_quiet_restart_zero_bytes(&route);
            }
        }
        let (cold_index, cold, _) = run_archive(
            &f,
            ScanIndex::default(),
            Arc::new(sampled_scan::SharedCache::default()),
        );
        let lhs = scan_money(SnapshotSource::Codex, &index, &result);
        let rhs = scan_money(SnapshotSource::Codex, &cold_index, &cold);
        money_oracle::assert_equivalent(&lhs, &rhs);
    }

    /// [money] Context changes preserve the accepted head and keep correction
    /// debt visible without granting an automatic archive reread.
    #[test]
    fn archive_context_change_holds_correction_without_regrant() {
        let f =
            ArchiveFixture::new(&zstd::stream::encode_all(&synthetic_rollout()[..], 1).unwrap());
        let (mut index, result, _) = run_archive(
            &f,
            ScanIndex::default(),
            Arc::new(sampled_scan::SharedCache::default()),
        );
        let accepted = result
            .snapshots
            .iter()
            .map(|s| {
                (
                    s.snapshot_fingerprint.clone(),
                    snapshot_upload_body_witness(s),
                )
            })
            .collect();
        index.settle_archive_bodies(&accepted);
        index.activate_upload_context("first".into());
        let key = local_index_key(&f.0);
        let head = index.files[&key].last_snapshot_fingerprint.clone();
        index.activate_upload_context("changed".into());
        assert_eq!(index.files[&key].last_snapshot_fingerprint, head);
        assert_eq!(
            index.files[&key].archive.as_ref().unwrap().hold,
            Some(CodexZstCause::CorrectionUnapplied)
        );
        let (_, scan, rows) = run_archive(
            &f,
            saved(&index),
            Arc::new(sampled_scan::SharedCache::default()),
        );
        assert!(scan.snapshots.is_empty());
        assert_eq!(full_decodes(&rows), 0);
    }

    /// [format] An elapsed fence retry saves a new paced deadline; a Full
    /// already in flight retains the reservation saved before its first byte.
    #[test]
    fn archive_hold_paces_elapsed_fence_retries_without_spending_a_full() {
        let f = ArchiveFixture::new(b"metadata only");
        for expired in [false, true] {
            let mut a = ArchiveEvidence::begin(&File::open(&f.0).unwrap(), &f.0, None).unwrap();
            a.decode_attempts = 0;
            let deadline = if expired {
                0
            } else {
                sampled_scan::now_seconds() + 21600
            };
            a.disposition = ArchiveDisposition::Pending {
                attempts: 0,
                retry_after: deadline,
            };
            a.defer_custody(CodexZstCause::OwnerUnproven);
            let ArchiveDisposition::Pending { retry_after, .. } = a.disposition else {
                panic!("held retry remains owed")
            };
            assert!(retry_after >= sampled_scan::now_seconds());
            if !expired {
                assert_eq!(retry_after, deadline);
            }
            assert_eq!(a.decode_attempts, 0);
        }
    }

    /// [format] Unknown/malformed archive metadata is held by the existing
    /// lenient file owner; unchanged plain entries serialize identically.
    #[test]
    fn archive_marker_compatibility_and_plain_bytes_remain_independent() {
        let f = ArchiveFixture::new(b"metadata only");
        let key = local_index_key(&f.0);
        let mut index = ScanIndex::default();
        let before = serde_json::to_value(&index).unwrap();
        let a = ArchiveEvidence::begin(&File::open(&f.0).unwrap(), &f.0, None).unwrap();
        index.files.entry(key.clone()).or_default().archive = Some(Box::new(a));
        for malformed in [
            json!("future-v9"),
            json!({"disposition":"future"}),
            json!(false),
        ] {
            let mut wire = serde_json::to_value(&index).unwrap();
            wire["files"][&key]["archive"] = malformed;
            let path = f.0.parent().unwrap().join("compat.json");
            fs::write(&path, serde_json::to_vec(&wire).unwrap()).unwrap();
            let held = ScanIndex::load(&path).unwrap();
            assert!(held.decode_holds_file(&key));
            assert!(held.accepted_snapshot_fingerprints.is_empty());
            let mut held = held;
            let (_, rows) = crate::local_resource_diagnostics::capture(|| {
                let result = held
                    .inventory_archive_header(
                        &f.candidate(),
                        Some(&Arc::new(sampled_scan::SharedCache::default())),
                        &mut HeaderWork {
                            allowed: true,
                            ..Default::default()
                        },
                    )
                    .unwrap();
                assert!(matches!(result, HeaderRead::Deferred));
            });
            assert!(!rows
                .iter()
                .any(|r| r["stage"] == "codex_zst_inventory" || r["stage"] == "codex_zst_input"));
        }
        index.files.clear();
        assert_eq!(before, serde_json::to_value(index).unwrap());
    }

    /// [behaviour] An archive larger than one decoded page finishes through
    /// the ordinary parser and yields inside large records without a total cap.
    #[test]
    fn archive_pages_to_eof_without_a_decoded_total_cutoff() {
        let _lock = DECODER_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut bytes = synthetic_rollout();
        let line = json!({"type":"unknown","padding":"x".repeat(1024)}).to_string() + "\n";
        for _ in 0..66000 {
            bytes.extend_from_slice(line.as_bytes());
        }
        let f = ArchiveFixture::new(&zstd::stream::encode_all(&bytes[..], 1).unwrap());
        let (_, result, rows) = run_archive(
            &f,
            ScanIndex::default(),
            Arc::new(sampled_scan::SharedCache::default()),
        );
        assert_eq!(result.snapshots.len(), 1);
        assert_eq!(result.snapshots[0].input_tokens, 750);
        assert_eq!(full_decodes(&rows), 1);
        assert!(rows.iter().any(|r| r["stage"] == "codex_zst_input"
            && r["counts"]["codex_zst_decoded_bytes"].as_u64() == Some(bytes.len() as u64)));
    }
    /// [money] Equal and subset native archive bodies settle without upload;
    /// superset, divergence and cumulative-only coverage preserve the accepted head.
    #[test]
    fn archive_same_session_fence_requires_exact_accepted_subset_or_equality() {
        use codex_file_join::tests::member;
        let _lock = DECODER_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let owner = "compressed-fixture";
        for relation in [
            "equal",
            "subset",
            "superset",
            "divergent",
            "cumulative-only",
        ] {
            let mut plain = member(owner, "response-one", 100, 100);
            let mut archive = plain.clone();
            if relation == "subset" {
                plain.extend(member(owner, "response-two", 200, 300).into_iter().skip(1));
            }
            if relation == "superset" {
                archive.extend(member(owner, "response-two", 200, 300).into_iter().skip(1));
            }
            if relation == "divergent" {
                archive = member(owner, "response-other", 100, 100);
            }
            if relation == "cumulative-only" {
                plain = member(owner, "response-new", 200, 1000);
            }
            let encode = |rows: &[Value]| {
                rows.iter()
                    .map(|r| serde_json::to_string(r).unwrap() + "\n")
                    .collect::<String>()
            };
            let f = ArchiveFixture::new(
                &zstd::stream::encode_all(encode(&archive).as_bytes(), 1).unwrap(),
            );
            let path = f.0.with_extension("");
            fs::write(&path, encode(&plain)).unwrap();
            let mut candidate = codex_zst_refusal_tests::candidate(&path);
            candidate.size_bytes = fs::metadata(&path).unwrap().len();
            let cache = Arc::new(sampled_scan::SharedCache::default());
            let checkpoint = fixture(b"", ".json");
            fs::remove_file(&checkpoint.0).unwrap();
            let initial = selector_scan(
                &f,
                ScanIndex::default(),
                cache.clone(),
                VecDeque::from([candidate.clone()]),
                true,
            );
            let (mut accepted, first) = finish_selector(initial, &checkpoint.0);
            assert_eq!(first.snapshots.len(), 1, "{relation}");
            accepted.record_accepted_snapshot_fingerprints(
                &first
                    .snapshots
                    .iter()
                    .map(|s| s.snapshot_fingerprint.clone())
                    .collect(),
            );
            let before = accepted.files[&local_index_key(&path)].clone();
            let mut prior = sampled_scan::transition_fixture::scan_money(
                SnapshotSource::Codex,
                &accepted,
                &first,
            );
            prior.accepted.insert(
                owner.into(),
                sampled_scan::transition_fixture::Accepted {
                    body: prior.snapshots[owner].clone(),
                    witness: before.last_upload_body_witness.clone().unwrap(),
                },
            );
            let candidates = VecDeque::from([candidate, f.candidate()]);
            let scan = selector_scan(&f, accepted, cache.clone(), candidates, true);
            let (after, output) = finish_selector(scan, &checkpoint.0);
            assert!(output.snapshots.is_empty(), "{relation}");
            let a = after.files[&local_index_key(&f.0)]
                .archive
                .as_ref()
                .unwrap();
            if relation == "equal" || relation == "subset" {
                assert!(
                    matches!(
                        a.disposition,
                        ArchiveDisposition::Refused {
                            cause: CodexZstCause::ArchiveDominated
                        }
                    ),
                    "{relation}: {a:?}"
                );
            } else {
                assert_eq!(
                    a.hold,
                    Some(CodexZstCause::ArchiveEquivalenceUnproven),
                    "{relation}"
                );
                assert!(matches!(a.disposition, ArchiveDisposition::Pending { .. }));
            }
            assert_eq!(
                after.files[&local_index_key(&path)].last_snapshot_fingerprint,
                before.last_snapshot_fingerprint
            );
            assert_eq!(
                after.files[&local_index_key(&path)].last_upload_body_witness,
                before.last_upload_body_witness
            );
            if relation != "equal" && relation != "subset" {
                let mut held = sampled_scan::transition_fixture::scan_money(
                    SnapshotSource::Codex,
                    &after,
                    &output,
                );
                held.accepted = prior.accepted.clone();
                sampled_scan::transition_fixture::money_oracle::assert_held(
                    owner, &prior, &held, &prior,
                );
                sampled_scan::transition_fixture::money_oracle::assert_no_smaller_reemit(
                    owner, &prior, &held, &prior, true,
                );
            }
            let (_, quiet, rows) = run_archive(
                &f,
                saved(&after),
                Arc::new(sampled_scan::SharedCache::default()),
            );
            assert!(quiet.snapshots.is_empty());
            assert_eq!(full_decodes(&rows), 0, "{relation}");
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
        let mut a = ArchiveEvidence::begin(&File::open(path).unwrap(), path, None).unwrap();
        a.disposition = ArchiveDisposition::Pending {
            attempts: 1,
            retry_after: sampled_scan::now_seconds().saturating_add(21600),
        };
        a.hold = Some(CodexZstCause::FamilyUnproven);
        index
            .files
            .entry(local_index_key(path))
            .or_default()
            .archive = Some(Box::new(a));
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
        for e in control["files"].as_object_mut().unwrap().values_mut() {
            e.as_object_mut().unwrap().remove("archive");
        }
        fs::write(
            out.join("as-today.json"),
            serde_json::to_vec(&control).unwrap(),
        )
        .unwrap();
        let singleton = downgrade_member(&out.join("activation"), owner, true);
        let mut activation = downgrade_accepted(&singleton, &native.snapshots[0]);
        downgrade_seed(&mut activation, &singleton);
        activation
            .files
            .get_mut(&local_index_key(&singleton))
            .unwrap()
            .archive
            .as_mut()
            .unwrap()
            .disposition = ArchiveDisposition::Acquired;
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
            assert!(index.files.values().all(|e| e.archive.is_none()));
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
            scan.index.archive_pass.gates = crate::snapshot_sync::ArchiveGates::new(Power(false));
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
}
