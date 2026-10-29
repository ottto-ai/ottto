//! Bounded `.jsonl.zst` rollout input behind the one opened-object parser seam.
//! Discovery/twin binding is enabled separately by 11b.
use crate::local_resource_diagnostics::{codex_zst_refused, CodexZstCause};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{self, BufRead, BufReader, Read};
use std::mem::size_of;
use std::path::Path;
use std::sync::{Mutex, PoisonError};
use zstd::zstd_safe::{DCtx, DParameter, InBuffer, OutBuffer};

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

// Bundled zstd 1.5.7, WindowLogMax(23), 514 MiB synthetic concatenated
// archive: CI run 40774588149 measured 8,894,448 bytes peak (native heap +
// buffers + box, including resize overlap). Add 10%, round up to 64 KiB.
// Paid inside STATE_BYTES; the fixed primary Tail floor remains unchanged.
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

static STREAKS: Mutex<BTreeMap<[u8; 32], u8>> = Mutex::new(BTreeMap::new());
pub(super) fn admission_streak(key: &str, yielded: bool) -> u8 {
    use sha2::Digest;
    let hash = sha2::Sha256::digest(key.as_bytes()).into();
    let mut slots = STREAKS.lock().unwrap_or_else(PoisonError::into_inner);
    let previous = slots.remove(&hash).unwrap_or(0);
    if !yielded {
        return 0;
    }
    if slots.len() == 256 {
        slots.pop_first();
    }
    let count = previous.saturating_add(1).min(13);
    slots.insert(hash, count);
    count
}
/// Count starved tracked keys, optionally scoped to one physical archive.
pub(super) fn admission_starved_count(key: Option<&str>) -> usize {
    use sha2::Digest;
    let hash: Option<[u8; 32]> = key.map(|key| sha2::Sha256::digest(key.as_bytes()).into());
    STREAKS
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .iter()
        .filter(|(k, n)| **n >= 12 && hash.as_ref().map_or(true, |h| h == *k))
        .count()
}
impl super::OwnedSourceScan {
    pub(crate) fn persist_archive_reservation(
        &mut self,
        committed: &mut super::ScanIndex,
        path: &Path,
    ) -> anyhow::Result<()> {
        let Some((key, evidence)) = self.active_file.as_ref().and_then(|active| {
            let key = super::local_index_key(&active.candidate.path);
            let evidence = self.index.files.get_mut(&key)?.archive.as_mut()?;
            (!evidence.reservation_saved).then_some((key, evidence))
        }) else {
            return Ok(());
        };
        let previous = committed.files.get(&key).cloned();
        committed.files.entry(key.clone()).or_default().archive = Some(evidence.clone());
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
        if evidence.decode_attempts > 1 && !evidence.user_change {
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
        if evidence.user_change {
            crate::local_resource_diagnostics::traversal_point(
                "full_reads",
                "codex",
                &serde_json::json!({"full_reads": {"user_change": 1}, "compressed_user_change": 1}),
            );
        }
        Ok(())
    }
}
/// SOURCE Q3: no content, offsets, checkpoint or acceptance authority.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
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
    #[serde(default)]
    pub(super) decode_attempts: u8,
    #[serde(default)]
    terminal_failures: u8,
    #[serde(default)]
    terminal_attempt: u8,
    #[serde(default)]
    pub(super) user_change: bool,
    #[serde(default, deserialize_with = "bounded_archive_context")]
    pub(super) user_context: Option<String>,
    #[serde(default)]
    pub(super) user_generation: u64,
    #[serde(default = "exhausted_archive_generation")]
    pub(super) user_change_spent: u64,
}
fn exhausted_archive_generation() -> u64 {
    u64::MAX
}
// H: only the domain-separated policy digest is retained, never setting values.
fn valid_archive_context(context: &str) -> bool {
    context.len() == 64
        && context
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn bounded_archive_context<'de, D: serde::Deserializer<'de>>(
    de: D,
) -> Result<Option<String>, D::Error> {
    use serde::Deserialize;
    Ok(Option::<String>::deserialize(de)?.filter(|s| valid_archive_context(s)))
}
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub(crate) enum ArchiveDisposition {
    HeaderValidated,
    Acquired,
    Empty,
    Pending { attempts: u8, retry_after: u64 },
    Held { cause: CodexZstCause },
    Refused { cause: CodexZstCause },
}
/// SOURCE Q3b: metadata only, never a group member or completion certificate.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub(super) struct ValidatedHeader {
    pub(super) owner: String,
    pub(super) digest: String,
    pub(super) created_unix_ms: Option<i64>,
    #[serde(default, deserialize_with = "bounded_cli_version")]
    cli_version: Option<String>,
}
fn bounded_cli_version<'de, D: serde::Deserializer<'de>>(
    de: D,
) -> Result<Option<String>, D::Error> {
    use serde::Deserialize;
    Ok(Option::<String>::deserialize(de)?.filter(|s| ValidatedHeader::bounded_version(s)))
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
        let meta = codex_session_meta_payload(&value)?;
        let digest = Sha256::new().chain_update(bytes).chain_update(b"\n");
        Some(Self {
            owner: resolve_codex_identity_option(codex_identity_at(meta, &["id"]))?,
            digest: format!("{:x}", digest.finalize()),
            created_unix_ms: meta
                .get("timestamp")
                .and_then(Value::as_str)
                .and_then(|ts| OffsetDateTime::parse(ts, &Rfc3339).ok())
                .and_then(|ts| i64::try_from(ts.unix_timestamp_nanos() / 1_000_000).ok()),
            cli_version: meta
                .get("cli_version")
                .and_then(Value::as_str)
                .filter(|s| Self::bounded_version(s))
                .map(str::to_owned),
        })
    }
    fn filename_matches(&self, path: &Path) -> bool {
        super::codex_session_id_candidates_from_path(&path.with_extension("")).contains(&self.owner)
    }
    fn bounded_version(s: &str) -> bool {
        s.len() <= 64 && s.bytes().all(|b| (0x20..=0x7e).contains(&b))
    }
    pub(super) fn cli_version(&self) -> Option<&str> {
        self.cli_version
            .as_deref()
            .filter(|s| Self::bounded_version(s))
    }
}
crate::heap_layout_bound::fields!(ValidatedHeader; owner, digest, created_unix_ms, cli_version);
impl ArchiveEvidence {
    fn header_for(&self, path: &Path) -> Option<&ValidatedHeader> {
        self.header_validated
            .as_ref()
            .filter(|h| h.filename_matches(path))
    }
    pub(super) fn begin(file: &File, path: &Path, previous: Option<&Self>) -> io::Result<Self> {
        let stamp = crate::transcript_acquisition::FileStamp::capture(file.metadata()?)?;
        let previous = previous.filter(|old| old.stamp.same_content(&stamp));
        let logical = path.with_extension("");
        let logical_id = super::codex_session_id_candidates_from_path(&logical)
            .into_iter()
            .next()
            .ok_or_else(|| invalid("compressed rollout logical id unavailable"))?;
        let logical_id = previous.map_or(logical_id, |old| old.logical_id.clone());
        let correction = previous.is_some_and(|old| old.user_change);
        let attempts = if correction {
            previous.map_or(0, |old| old.decode_attempts)
        } else {
            previous
                .map_or(0, |old| {
                    old.decode_attempts.max(match old.disposition {
                        ArchiveDisposition::Pending { attempts, .. } => attempts,
                        ArchiveDisposition::HeaderValidated => 0,
                        _ => 1,
                    })
                })
                .saturating_add(1)
        };
        Ok(Self {
            stamp: stamp.content_only(),
            logical_id,
            owner: None,
            body_witness: None,
            reservation_saved: false,
            decode_attempts: attempts,
            terminal_failures: previous.map_or(0, |a| a.terminal_failures),
            terminal_attempt: previous.map_or(0, |a| a.terminal_attempt),
            user_change: previous.is_some_and(|a| a.user_change),
            user_context: previous.and_then(|a| a.user_context.clone()),
            user_generation: previous.map_or(0, |a| a.user_generation),
            // Written in the reservation before any byte. ACK debt stays separate.
            user_change_spent: previous.map_or(0, |a| {
                if correction {
                    a.user_generation
                } else {
                    a.user_change_spent
                }
            }),
            header_attempted: previous.is_some_and(|a| a.header_attempted),
            header_validated: previous.and_then(|a| a.header_validated.clone()),
            disposition: ArchiveDisposition::Pending {
                attempts,
                retry_after: super::sampled_scan::now_seconds().saturating_add(6 * 3600),
            },
        })
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
        self.owner.is_some() && parsed.complete()
    }
    pub(super) fn quiet(&self, file: &File) -> bool {
        self.matches(file)
            && !matches!(self.disposition, ArchiveDisposition::HeaderValidated)
            && !matches!(self.disposition, ArchiveDisposition::Pending { retry_after, .. } if super::sampled_scan::now_seconds() >= retry_after)
    }
    pub(super) fn stop_exhausted(&mut self) -> bool {
        if self.user_change {
            if self
                .user_context
                .as_deref()
                .is_some_and(valid_archive_context)
                && self.user_change_spent < self.user_generation
            {
                return false; // An independent A3 grant does not spend the A1 budget.
            }
            self.disposition = ArchiveDisposition::Held {
                cause: CodexZstCause::CorrectionUnapplied,
            };
            codex_zst_refused(CodexZstCause::CorrectionUnapplied);
            return true;
        }
        if let ArchiveDisposition::Pending { attempts, .. } = self.disposition {
            self.decode_attempts = self.decode_attempts.max(attempts);
        }
        let cause = if self.terminal_failures >= 3 {
            Some(CodexZstCause::SettlementStuck)
        } else if self.decode_attempts >= 6 {
            Some(CodexZstCause::DecodeBudget)
        } else {
            None
        };
        if let Some(cause) = cause {
            self.disposition = ArchiveDisposition::Held { cause };
            codex_zst_refused(cause); // Per committed attempt, never a quiet-pass counter.
        }
        cause.is_some()
    }
    pub(super) fn settle(&mut self, accepted: bool, terminal: bool) {
        let pending = matches!(self.disposition, ArchiveDisposition::Pending { .. });
        let stuck = matches!(
            self.disposition,
            ArchiveDisposition::Held {
                cause: CodexZstCause::SettlementStuck | CodexZstCause::DecodeBudget
            }
        ) || (self.user_change
            && matches!(
                self.disposition,
                ArchiveDisposition::Held {
                    cause: CodexZstCause::CorrectionUnapplied
                }
            ));
        if !(pending || stuck) {
            return;
        }
        if accepted {
            self.disposition = ArchiveDisposition::Acquired;
            self.user_change = false;
        } else if pending {
            if terminal
                && !self.user_change
                && self.body_witness.is_some()
                && self.terminal_attempt < self.decode_attempts
            {
                self.terminal_failures = self.terminal_failures.saturating_add(1);
                self.terminal_attempt = self.decode_attempts;
            }
            self.stop_exhausted();
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
    pub(super) fn invalid_header(&self, path: &Path, metadata: &std::fs::Metadata) -> bool {
        let bound = self.header_for(path).is_some();
        !bound
            && (self.header_attempted
                || !matches!(self.disposition, ArchiveDisposition::HeaderValidated))
            && crate::transcript_acquisition::FileStamp::capture(metadata.clone())
                .is_ok_and(|stamp| self.stamp.same_content(&stamp))
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
    context: DCtx<'static>,
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
        let mut context = DCtx::try_create()
            .ok_or_else(|| io::Error::other("compressed rollout decoder allocation failed"))?;
        context
            .set_parameter(DParameter::WindowLogMax(WINDOW_LOG))
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
            let mut input = InBuffer::around(bytes);
            // At the limit, probe one byte: a Take-style artificial EOF would
            // incorrectly turn over-limit content into a complete JSONL body.
            let mut probe = [0u8; 1];
            let at_limit = self.remaining == 0;
            let capacity = output
                .len()
                .min(self.remaining.min(usize::MAX as u64) as usize);
            let mut out = if at_limit {
                OutBuffer::around(&mut probe[..])
            } else {
                OutBuffer::around(&mut output[..capacity])
            };
            let hint = self
                .context
                .decompress_stream(&mut out, &mut input)
                .map_err(|_| invalid(CodexZstCause::DecodeFailed))?;
            let consumed = input.pos;
            let produced = out.pos();
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
        let started = thread_cpu_micros();
        let result = self.read_inner(output);
        self.cpu_micros = self
            .cpu_micros
            .saturating_add(thread_cpu_micros().saturating_sub(started));
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
            &std::collections::BTreeMap::from([
                (
                    "codex_zst_compressed_bytes",
                    self.physical_limit - self.input.get_ref().limit(),
                ),
                ("codex_zst_compressed_consumed_bytes", self.compressed_bytes),
                ("codex_zst_decoded_bytes", self.decoded_bytes),
                ("codex_zst_cpu_micros", self.cpu_micros),
            ]),
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
        let credit = compressed_input_credit()?;
        let Some(owner) = super::sampled_scan::codex_cursor::DecoderOwner::acquire(cache, credit)
        else {
            codex_zst_refused(CodexZstCause::AdmissionRefused);
            return Ok(None);
        };
        let mut input = Self::compressed(
            file,
            super::max_jsonl_file_bytes(super::SnapshotSource::Codex),
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

/// 11b supplies AC + utility-QoS permission and folds CPU into catch-up pacing.
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
impl super::ScanCensus {
    pub(super) fn archive_parser_failure(
        &mut self,
        source: super::SnapshotSource,
        index: &super::ScanIndex,
        path: &Path,
        error: &anyhow::Error,
    ) {
        let archive = index
            .files
            .get(&super::local_index_key(path))
            .and_then(|e| e.archive.as_deref());
        let bodyless_pending = archive.is_some_and(|a| {
            matches!(a.disposition, ArchiveDisposition::Pending { .. }) && a.body_witness.is_none()
        });
        if source != super::SnapshotSource::Codex
            || !is_compressed_codex_rollout(Some(path), None)
            || error.is::<ArchiveAdmissionYield>()
            || bodyless_pending
        {
            self.archive_failure(index, path, super::UnreadableCause::Reduction);
        } else {
            let cause = archive
                .and_then(|a| a.terminal_cause())
                .unwrap_or(CodexZstCause::ConstructorUnfunded);
            self.archive_residue(path, archive, cause);
        }
    }
    pub(super) fn archive_failure(
        &mut self,
        index: &super::ScanIndex,
        path: &Path,
        normal: super::UnreadableCause,
    ) {
        let key = super::local_index_key(path);
        let archive = index.files.get(&key).and_then(|e| e.archive.as_deref());
        if let Some(cause) = archive.and_then(|a| a.terminal_cause()).or_else(|| {
            (admission_starved_count(Some(&key)) > 0).then_some(CodexZstCause::AdmissionStarved)
        }) {
            self.archive_residue(path, archive, cause);
        } else {
            self.record_unreadable(normal, 1);
        }
    }

    pub(super) fn archive_residue(
        &mut self,
        path: &Path,
        archive: Option<&ArchiveEvidence>,
        cause: CodexZstCause,
    ) {
        self.archive_terminal_index_keys
            .insert(super::local_index_key(path));
        self.archive_terminal_sessions
            .extend(super::codex_session_id_candidates_from_path(
                &path.with_extension(""),
            ));
        if let Some(archive) = archive {
            self.archive_terminal_sessions
                .insert(archive.logical_id.clone());
        }
        crate::local_resource_diagnostics::traversal_point(
            "archive_terminal_residue",
            "codex",
            &serde_json::json!({
                "archive_terminal_residue": BTreeMap::from([(cause, 1)]),
                "archive_terminal_residue_session_count": self.archive_terminal_sessions.len(),
            }),
        );
    }
}
impl super::ScanIndex {
    pub(super) fn archive_scoped_unknown(&self, key: &str) -> bool {
        let Some(t) = self.traversal.as_ref() else {
            return false;
        };
        self.files
            .get(key)
            .and_then(|e| e.codex_counting_owner.as_ref())
            .is_some_and(|o| {
                t.residue
                    .blocked_session_ids
                    .iter()
                    .any(|id| super::codex_protected_owner(id) == *o)
            })
            || self
                .files
                .get(key)
                .and_then(|e| e.archive.as_ref())
                .is_some_and(|a| t.residue.blocked_session_ids.contains(&a.logical_id))
            || {
                let path = Path::new(key);
                let logical = if is_compressed_codex_rollout(Some(path), None) {
                    path.with_extension("")
                } else {
                    path.to_owned()
                };
                super::codex_session_id_candidates_from_path(&logical)
                    .iter()
                    .any(|o| t.residue.blocked_session_ids.contains(o))
            }
    }
    pub(crate) fn activate_archive_user_context(&mut self, context: String) {
        if !valid_archive_context(&context) {
            return; // Malformed input never creates permission.
        }
        self.active_archive_user_context = Some(context.clone());
        for entry in self.files.values_mut() {
            let Some(archive) = entry.archive.as_mut() else {
                continue;
            };
            if archive.user_context.is_none() && archive.user_change {
                archive.user_change_spent = archive.user_generation; // missing/malformed H cannot authorize a Full
            }
            let changed = archive
                .user_context
                .as_ref()
                .is_some_and(|old| old != &context);
            archive.user_context = Some(context.clone());
            if changed && (archive.body_witness.is_some() || archive.user_change) {
                archive.user_change = true;
                // Only an independent policy transition replaces an absent-field sentinel.
                archive.user_change_spent = archive.user_generation;
                if let Some(next) = archive.user_generation.checked_add(1) {
                    archive.user_generation = next;
                } else {
                    archive.user_change_spent = u64::MAX; // fail closed at generation exhaustion
                }
                archive.body_witness = None;
                archive.disposition = ArchiveDisposition::Pending {
                    attempts: archive.decode_attempts,
                    retry_after: 0,
                };
            } else if archive.user_change && archive.user_change_spent >= archive.user_generation {
                archive.disposition = ArchiveDisposition::Held {
                    cause: CodexZstCause::CorrectionUnapplied,
                };
            }
        }
    }
    pub(super) fn hold_archive_corrections(&mut self, revision: Option<u64>) {
        for entry in self.files.values_mut() {
            if revision.is_some_and(|r| entry.effective_upload_body_witness_revision >= r) {
                continue;
            }
            if let Some(archive) = entry
                .archive
                .as_mut()
                .filter(|a| matches!(a.disposition, ArchiveDisposition::Acquired))
            {
                archive.disposition = ArchiveDisposition::Held {
                    cause: CodexZstCause::CorrectionUnapplied,
                };
                codex_zst_refused(CodexZstCause::CorrectionUnapplied);
            }
        }
    }

    pub fn codex_archive_cli_version(&self, path: &Path) -> Option<&str> {
        self.archive_header(path)?.cli_version()
    }
    pub(super) fn archive_header(&self, path: &Path) -> Option<&ValidatedHeader> {
        let key = super::local_index_key(path);
        let archive = self.files.get(&key)?.archive.as_ref()?;
        let meta = std::fs::symlink_metadata(path).ok()?;
        let stamp = crate::transcript_acquisition::FileStamp::capture(meta).ok()?;
        archive.stamp.same_content(&stamp).then_some(())?;
        archive.header_for(path)
    }
    pub(super) fn inventory_archive_header(
        &mut self,
        candidate: &super::CandidateFile,
        cache: Option<&std::sync::Arc<super::sampled_scan::SharedCache>>,
        work: &mut HeaderWork,
    ) -> super::Result<(ValidatedHeader, usize)> {
        use super::*;
        let file = open_candidate_beneath_root(candidate)?;
        let key = local_index_key(&candidate.path);
        let old = self
            .files
            .get(&key)
            .and_then(|e| e.archive.as_deref())
            .filter(|a| a.matches(&file));
        if let Some(header) = old.and_then(|a| a.header_for(&candidate.path)) {
            return Ok((header.clone(), 0));
        }
        if old.is_some_and(|a| {
            a.header_attempted || !matches!(a.disposition, ArchiveDisposition::HeaderValidated)
        }) {
            codex_zst_refused(CodexZstCause::HeaderInvalid);
            anyhow::bail!("archive header unavailable without another read");
        }
        if !work.allowed || work.cpu_micros >= 30_000_000 {
            codex_zst_refused(CodexZstCause::AdmissionRefused);
            anyhow::bail!("archive inventory power/QoS/CPU gate");
        }
        let started = thread_cpu_micros();
        let mut evidence = ArchiveEvidence::begin(&file, &candidate.path, old)?;
        evidence.disposition = ArchiveDisposition::HeaderValidated;
        evidence.decode_attempts = 0;
        let mut input = match cache.map(|cache| OpenedInput::funded(file, cache)) {
            Some(Ok(input)) => input.context("header admission unavailable")?.header_only(),
            _ => {
                codex_zst_refused(CodexZstCause::AdmissionRefused);
                anyhow::bail!("archive header admission unavailable");
            }
        };
        evidence.header_attempted = true;
        self.files.entry(key.clone()).or_default().archive = Some(Box::new(evidence));
        let mut bytes = Vec::new();
        let result = (|| -> Result<ValidatedHeader> {
            (&mut input)
                .take(codex_file_join::MAX_HEADER_BYTES as u64)
                .read_until(b'\n', &mut bytes)?;
            let header =
                ValidatedHeader::from_bytes(&bytes).context("invalid archive owning header")?;
            let evidence = self.files[&key].archive.as_ref().expect("header attempt");
            anyhow::ensure!(
                evidence.matches(input.get_ref()),
                "archive changed during header read"
            );
            anyhow::ensure!(
                header.filename_matches(&candidate.path),
                "archive header owner mismatch"
            );
            Ok(header)
        })();
        let (physical, decoded, compressed) = match &input {
            OpenedInput::Compressed(r, _) => (
                r.get_ref().physical_limit - r.get_ref().input.get_ref().limit(),
                r.get_ref().decoded_bytes,
                r.get_ref().compressed_bytes,
            ),
            _ => unreachable!(),
        };
        let cpu = thread_cpu_micros().saturating_sub(started);
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
            }),
        );
        input.close();
        let entry = self.files.get_mut(&key).expect("header attempt");
        let evidence = entry.archive.as_mut().expect("header attempt");
        if let Ok(header) = &result {
            evidence.header_validated = Some(header.clone());
        } else {
            codex_zst_refused(CodexZstCause::HeaderInvalid);
        }
        result.map(|header| (header, physical as usize))
    }
    #[cfg(test)]
    pub(crate) fn settle_archive_bodies(&mut self, accepted: &BTreeMap<String, String>) {
        self.settle_archive_outcome(accepted, true, None);
    }
    pub(crate) fn settle_archive_outcome(
        &mut self,
        accepted: &BTreeMap<String, String>,
        terminal: bool,
        submitted: Option<&BTreeMap<String, String>>,
    ) {
        for (key, entry) in &mut self.files {
            if let Some(archive) = entry.archive.as_mut() {
                let matches = |facts: &BTreeMap<String, String>| {
                    self.file_snapshot_fingerprints
                        .get(key)
                        .into_iter()
                        .flatten()
                        .map(|fp| facts.get(fp))
                        .collect::<Option<BTreeSet<_>>>()
                        .filter(|b| !b.is_empty())
                        .map(super::snapshot_file_upload_body_set_hex)
                        .is_some_and(|w| Some(w) == archive.body_witness)
                };
                let settled = matches(accepted);
                let terminal = terminal && submitted.map_or(true, matches);
                archive.settle(settled, terminal);
            }
        }
    }
    pub(super) fn archive_decode_error(&mut self, path: &Path, error: &anyhow::Error) {
        let cause = error.chain().find_map(|e| {
            e.downcast_ref::<io::Error>()
                .and_then(io::Error::get_ref)
                .and_then(|e| e.downcast_ref::<CodexZstCause>())
        });
        let archive = self
            .files
            .get_mut(&super::local_index_key(path))
            .and_then(|e| e.archive.as_mut());
        if let Some((archive, &cause)) = archive.zip(cause) {
            archive.disposition = ArchiveDisposition::Refused { cause };
            codex_zst_refused(cause);
        }
    }
}
crate::heap_layout_bound::fields!(ArchiveEvidence; stamp, logical_id, owner, disposition, body_witness, reservation_saved, header_validated, header_attempted, decode_attempts, terminal_failures, terminal_attempt, user_change, user_context, user_generation, user_change_spent);
impl crate::heap_layout_bound::HeapLayoutBound for ArchiveDisposition {
    fn heap_bound(&self, c: &mut crate::heap_layout_bound::Counter) -> Option<()> {
        c.add(0)
    }
}

#[cfg(test)]
pub(in crate::snapshots) mod tests {
    include!("codex_archive_header_tests.rs");
    include!("codex_archive_correction_tests.rs");
    include!("codex_archive_ru_tests.rs");
    include!("codex_archive_released_entry_tests.rs");
    include!("codex_archive_downgrade_tests.rs");
    include!("codex_archive_released_writer_tests.rs");
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
    pub(in crate::snapshots) use DECODER_TEST_LOCK as ARCHIVE_TEST_LOCK;
    struct ArchiveFixture(PathBuf);
    impl ArchiveFixture {
        fn new(bytes: &[u8]) -> Self {
            let root = crate::test_scratch::private_dir("codex-archive-completion");
            let path = root.join("rollout-compressed-fixture.jsonl.zst");
            fs::write(&path, bytes).unwrap();
            Self(path)
        }
        fn candidate(&self) -> CandidateFile {
            let mut candidate = super::super::codex_zst_refusal_tests::candidate(&self.0);
            candidate.size_bytes = fs::metadata(&self.0).unwrap().len();
            candidate
        }
    }
    impl Drop for ArchiveFixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(self.0.parent().unwrap());
        }
    }
    #[derive(Clone, Default)]
    struct Ends(Arc<Mutex<Vec<super::super::line_delivery::DeliveryEnd>>>);
    impl super::super::line_delivery::LineObserver for Ends {
        fn begin(
            &mut self,
            file: &super::super::line_delivery::FileView,
        ) -> super::super::line_delivery::Want {
            assert_eq!(file.mode, super::super::line_delivery::DeliveryMode::Full);
            super::super::line_delivery::Want::Lines
        }
        fn line(
            &mut self,
            _: &super::super::line_delivery::FileView,
            _: &super::super::line_delivery::PhysicalLine<'_>,
        ) {
        }
        fn end(
            &mut self,
            _: &super::super::line_delivery::FileView,
            end: &super::super::line_delivery::DeliveryEnd,
        ) {
            self.0.lock().unwrap().push(*end);
        }
    }
    // Inject the candidate at the selection seam: discovery remains plain-only
    // until 11b. Everything from secure open through LD/output is production.
    fn archive_pass(
        f: &ArchiveFixture,
        index: ScanIndex,
        paid: bool,
        limit: Option<u64>,
    ) -> (ScanIndex, SourceScanResult, Vec<Value>, Ends) {
        archive_pass_with(f, index, paid, limit, &[], |_| {})
    }
    fn archive_pass_with(
        f: &ArchiveFixture,
        index: ScanIndex,
        paid: bool,
        limit: Option<u64>,
        roots: &[PathBuf],
        setup: impl FnOnce(&mut OwnedSourceScan),
    ) -> (ScanIndex, SourceScanResult, Vec<Value>, Ends) {
        let ends = Ends::default();
        let mut committed = index.clone();
        let reservation_path = f.0.parent().unwrap().join("reservation.json");
        fs::write(&reservation_path, serde_json::to_vec(&committed).unwrap()).unwrap();
        let ((index, result), diagnostics) = crate::local_resource_diagnostics::capture(|| {
            let mut scan = OwnedSourceScan::new(
                SnapshotSource::Codex,
                roots,
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
            .with_line_observer("archive", Box::new(ends.clone()));
            if paid {
                scan = scan.with_sampled_acquisition(
                    Arc::new(sampled_scan::SharedCache::default()),
                    Scope("archive-test".into()),
                );
            }
            scan.identified_candidates = VecDeque::from([f.candidate()]);
            scan.census
                .observed_index_keys
                .insert(local_index_key(&f.0));
            scan.codex_join_prepared = true;
            scan.census_unix_seconds = None;
            setup(&mut scan);
            for _ in 0..1000 {
                match scan.step(None) {
                    OwnedSourceScanStep::Pending(mut next) => {
                        next.persist_archive_reservation(&mut committed, &reservation_path)
                            .unwrap();
                        // Synthetic over-limit without allocating a 2GiB fixture.
                        if let Some(limit) = limit {
                            let (active, lease) = next.active_file.into_parts();
                            let mut active = active;
                            if let Some(active) = active.as_mut() {
                                if active.charged_bytes == 0 {
                                    if let OpenedInput::Compressed(reader, _) =
                                        &mut active.parser.reader.reader
                                    {
                                        reader.get_mut().remaining = limit;
                                    }
                                }
                            }
                            next.active_file =
                                sampled_scan::codex_cursor::ActiveFrame::new(active, lease);
                        }
                        scan = next;
                    }
                    OwnedSourceScanStep::Complete {
                        mut index,
                        mut scan,
                        ..
                    } => {
                        finalize_scan_after_policy(SnapshotSource::Codex, &mut scan, &mut index);
                        return (index, scan);
                    }
                }
            }
            panic!("archive scan did not complete");
        });
        (index, result, diagnostics, ends)
    }
    fn decodes(rows: &[Value]) -> usize {
        rows.iter()
            .filter(|row| {
                row["stage"] == "codex_zst_input" || row["stage"] == "codex_zst_inventory"
            })
            .count()
    }
    fn checkpoint(index: &ScanIndex) -> ScanIndex {
        let partial = index.committable_subset_with_local_holds(
            &ScanIndex::default(),
            &BTreeSet::new(),
            &BTreeMap::new(),
            &BTreeSet::new(),
        );
        serde_json::from_slice(&serde_json::to_vec(&partial).unwrap()).unwrap()
    }
    #[test]
    #[cfg_attr(
        not(target_os = "macos"),
        ignore = "funded decoder needs validated heap layout"
    )]
    fn archive_acquisition_money_identity_ld_and_failure_checkpoint_are_quiet() {
        let _lock = ARCHIVE_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let bytes = synthetic_rollout();
        let f = ArchiveFixture::new(&zstd::stream::encode_all(&bytes[..], 1).unwrap());
        let (mut index, result, rows, ends) = archive_pass(&f, ScanIndex::default(), true, None);
        assert_eq!(decodes(&rows), 1);
        assert_eq!(
            *ends.0.lock().unwrap(),
            vec![super::super::line_delivery::DeliveryEnd::Complete]
        );
        assert_eq!(result.snapshots.len(), 1);
        let plain = fixture(&bytes, ".jsonl");
        let mut file = File::open(&plain.0).unwrap();
        let identity = opened_object_identity(SnapshotSource::Codex, &mut file).unwrap();
        let oracle = parse(
            codex_parser(OpenedInput::plain(file), &plain.0),
            &identity,
            &plain.0,
        )
        .unwrap();
        let actual = serde_json::to_value(&result.snapshots[0]).unwrap();
        for key in [
            "source_session_id",
            "input_tokens",
            "output_tokens",
            "cache_read_tokens",
            "cache_creation_5m_tokens",
            "cache_creation_1h_tokens",
            "reasoning_output_tokens",
            "unattributed_total_tokens",
            "request_count",
            "model_usage",
            "usage_buckets",
            "usage_accounting_contract",
        ] {
            assert_eq!(
                actual[key], oracle["snapshots"][0][key],
                "money field {key}"
            );
        }
        assert_eq!(result.snapshots[0].source_session_id, "compressed-fixture");
        let key = local_index_key(&f.0);
        assert!(matches!(
            index.files[&key].archive.as_ref().unwrap().disposition,
            ArchiveDisposition::Pending { attempts: 1, .. }
        ));
        let saved = checkpoint(&index); // upload failure / lost ACK, then restart
        assert!(saved.files[&key].last_snapshot_fingerprint.is_none());
        assert!(saved.accepted_snapshot_fingerprints.is_empty());
        assert!(!saved.file_snapshot_fingerprints.contains_key(&key));
        let expected_pending_money = serde_json::to_value(&result.snapshots).unwrap();
        // Neither an unsettled in-memory pass nor its durable checkpoint can
        // consume another decode before six hours; neither fabricates a body.
        for state in [index.clone(), saved] {
            let missing_body = state.files[&key].last_snapshot_fingerprint.is_none();
            let (mut state, result, rows, _) = archive_pass(&f, state, true, None);
            assert_eq!(decodes(&rows), 0);
            assert!(result.snapshots.is_empty());
            assert_eq!(result.unreadable_path_count > 0, missing_body);
            retry_due(&mut state, &key);
            let (mut state, offered, rows, _) = archive_pass(&f, state, true, None);
            assert_eq!(decodes(&rows), 1);
            assert_eq!(
                rows.iter()
                    .filter(|r| r["stage"] == "codex_zst_first_read_retry")
                    .count(),
                1
            );
            assert!(rows.iter().any(
                |r| r["counts"]["codex_zst_decoded_bytes"].as_u64() == Some(bytes.len() as u64)
            ));
            assert_eq!(
                serde_json::to_value(&offered.snapshots).unwrap(),
                expected_pending_money
            );
            let accepted = offered
                .snapshots
                .iter()
                .map(|s| {
                    (
                        s.snapshot_fingerprint.clone(),
                        snapshot_upload_body_witness(s),
                    )
                })
                .collect::<BTreeMap<_, _>>();
            // An ACK for an older body with the same semantic fp is insufficient.
            state.settle_archive_bodies(
                &accepted
                    .keys()
                    .map(|fp| (fp.clone(), "wrong-body".into()))
                    .collect(),
            );
            assert!(matches!(
                state.files[&key].archive.as_ref().unwrap().disposition,
                ArchiveDisposition::Pending { .. }
            ));
            state.settle_archive_bodies(&accepted);
            assert!(matches!(
                state.files[&key].archive.as_ref().unwrap().disposition,
                ArchiveDisposition::Acquired
            ));
            let mut replay = state.clone();
            assert!(replay.prepare_historical_replay("explicit-replay".into()));
            assert!(replay.accepted_snapshot_fingerprints.is_empty());
            // SOURCE first-read-only: replay resets delivery facts but cannot
            // authorize a second body read or manufacture an entity ACK.
            for state in [state.clone(), checkpoint(&state), replay] {
                let (_, result, rows, _) = archive_pass(&f, state, true, None);
                assert_eq!(decodes(&rows), 0);
                assert!(result.snapshots.is_empty());
            }
        }
        // Terminal settlement precedes checkpoint selection; the subset never
        // invents settlement from a semantic ACK alone.
        index.settle_archive_bodies(
            &result
                .snapshots
                .iter()
                .map(|s| {
                    (
                        s.snapshot_fingerprint.clone(),
                        snapshot_upload_body_witness(s),
                    )
                })
                .collect(),
        );
        let accepted = result
            .snapshots
            .iter()
            .map(|s| s.snapshot_fingerprint.clone())
            .collect();
        let partial = index.committable_subset_with_local_holds(
            &ScanIndex::default(),
            &accepted,
            &BTreeMap::new(),
            &BTreeSet::new(),
        );
        assert!(matches!(
            partial.files[&key].archive.as_ref().unwrap().disposition,
            ArchiveDisposition::Acquired
        ));
    }
    fn retry_due(index: &mut ScanIndex, key: &str) {
        let ArchiveDisposition::Pending { retry_after, .. } = &mut index
            .files
            .get_mut(key)
            .unwrap()
            .archive
            .as_mut()
            .unwrap()
            .disposition
        else {
            panic!("not pending")
        };
        *retry_after = 0; // synthetic passage of six hours, no process-wide clock
    }
    #[test]
    #[cfg_attr(
        not(target_os = "macos"),
        ignore = "funded decoder needs validated heap layout"
    )]
    fn archive_retry_six_hour_bound_and_three_failed_settlements_hold() {
        let _lock = ARCHIVE_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let f =
            ArchiveFixture::new(&zstd::stream::encode_all(&synthetic_rollout()[..], 1).unwrap());
        let key = local_index_key(&f.0);
        let mut state = ScanIndex::default();
        for attempt in 1..=3 {
            let before = sampled_scan::now_seconds();
            let (index, result, rows, _) = archive_pass(&f, state, true, None);
            let after = sampled_scan::now_seconds();
            assert_eq!(decodes(&rows), 1);
            assert_eq!(result.snapshots.len(), 1);
            let ArchiveDisposition::Pending {
                attempts,
                retry_after,
            } = index.files[&key].archive.as_ref().unwrap().disposition
            else {
                panic!("not pending")
            };
            assert_eq!(attempts, attempt);
            assert!((before + 6 * 3600..=after + 6 * 3600).contains(&retry_after));
            // A mid-upload page checkpoint carries evidence without treating
            // this still-live upload as another failed settlement.
            assert!(matches!(
                checkpoint(&index).files[&key]
                    .archive
                    .as_ref()
                    .unwrap()
                    .disposition,
                ArchiveDisposition::Pending { .. }
            ));
            let (saved, rows) = crate::local_resource_diagnostics::capture(|| {
                let mut failed = index;
                failed.settle_archive_bodies(&BTreeMap::new());
                checkpoint(&failed)
            });
            state = saved;
            if attempt < 3 {
                let (saved, result, rows, _) = archive_pass(&f, state, true, None);
                assert_eq!(decodes(&rows), 0);
                assert!(result.snapshots.is_empty());
                state = checkpoint(&saved);
                retry_due(&mut state, &key);
            } else {
                assert!(matches!(
                    state.files[&key].archive.as_ref().unwrap().disposition,
                    ArchiveDisposition::Held {
                        cause: CodexZstCause::SettlementStuck
                    }
                ));
                assert!(rows.iter().any(|r| r["counts"]["codex_zst_refused"]
                    ["CompressedSettlementStuck"]
                    .as_u64()
                    .is_some_and(|n| n > 0)));
                for _ in 0..2 {
                    let (saved, result, rows, _) = archive_pass(&f, checkpoint(&state), true, None);
                    assert_eq!(decodes(&rows), 0);
                    assert!(result.snapshots.is_empty());
                    assert_eq!(
                        result.unreadable_path_count, 0,
                        "terminal archive uses scoped residue"
                    );
                    assert!(saved.codex_parent_ownership_ledgers.is_empty());
                    assert!(saved.accepted_snapshot_fingerprints.is_empty());
                    state = saved;
                }
            }
        }
    }
    #[test]
    #[cfg_attr(
        not(target_os = "macos"),
        ignore = "funded decoder needs validated heap layout"
    )]
    fn archive_failed_attempts_never_publish_and_refusals_survive_restart() {
        let _lock = ARCHIVE_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let bytes = synthetic_rollout();
        let valid = zstd::stream::encode_all(&bytes[..], 1).unwrap();
        let mut encoder = zstd::stream::Encoder::new(Vec::new(), 1).unwrap();
        encoder.include_checksum(true).unwrap();
        encoder.write_all(&bytes).unwrap();
        let mut checksum = encoder.finish().unwrap();
        *checksum.last_mut().unwrap() ^= 1;
        for (encoded, paid, limit) in [
            (b"corrupt".to_vec(), true, None),
            (checksum, true, None),
            (valid[..valid.len() - 1].to_vec(), true, None),
            (valid.clone(), true, Some(1)),
        ] {
            let f = ArchiveFixture::new(&encoded);
            let (index, result, rows, ends) = archive_pass(&f, ScanIndex::default(), paid, limit);
            assert_eq!(decodes(&rows), usize::from(paid));
            assert!(result.snapshots.is_empty());
            assert!(index.codex_parent_ownership_ledgers.is_empty());
            assert!(!ends
                .0
                .lock()
                .unwrap()
                .contains(&super::super::line_delivery::DeliveryEnd::Complete));
            assert!(matches!(
                index.files[&local_index_key(&f.0)]
                    .archive
                    .as_ref()
                    .unwrap()
                    .disposition,
                ArchiveDisposition::Refused { .. }
            ));
            let cause = if limit.is_some() {
                CodexZstCause::DecodedOverLimit
            } else {
                CodexZstCause::DecodeFailed
            };
            assert!(
                matches!(index.files[&local_index_key(&f.0)].archive.as_ref().unwrap().disposition,
                ArchiveDisposition::Refused { cause: actual } if actual == cause)
            );
            if let Some(limit) = limit {
                assert!(rows.iter().any(|r| r["counts"]["codex_zst_decoded_bytes"]
                    .as_u64()
                    .is_some_and(|n| n > limit)));
            }
            let (_, result, rows, _) = archive_pass(&f, checkpoint(&index), true, None);
            assert_eq!(decodes(&rows), 0);
            assert!(result.snapshots.is_empty());
            assert_eq!(
                result.unreadable_path_count, 0,
                "terminal archive uses scoped residue"
            );
        }
    }
    #[test]
    #[cfg_attr(
        not(target_os = "macos"),
        ignore = "funded decoder needs validated heap layout"
    )]
    fn archive_empty_held_and_selected_held_restore_carry_only_evidence() {
        let _lock = ARCHIVE_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for bytes in [
            b"{\"type\":\"session_meta\",\"payload\":{\"id\":\"compressed-fixture\"}}\n".to_vec(),
            b"{\"type\":\"session_meta\",\"payload\":{\"id\":\"wrong-owner\"}}\n".to_vec(),
            [synthetic_rollout(), b"{\"type\":\"event_msg\",\"payload\":{\"type\":\"token_count\",\"info\":{\"total_token_usage\":{\"input_tokens\":\"bad\"}}}}\n".to_vec()].concat(),
        ] {
            let f = ArchiveFixture::new(&zstd::stream::encode_all(&bytes[..], 1).unwrap());
            let before = ScanIndex::default();
            let proof_state = |index: &ScanIndex| serde_json::json!({
                "proofs": index.codex_parent_prefix_proofs,
                "side": index.codex_parent_side,
                "evicted": index.codex_counting_evicted_legacy,
                "evictions": index.codex_counting_evictions,
            });
            let baseline = proof_state(&before);
            let (mut index, result, _, _) = archive_pass(&f, before, true, None);
            assert_eq!(proof_state(&index), baseline);
            assert!(result.snapshots.is_empty());
            let key = local_index_key(&f.0);
            index.files.get_mut(&key).unwrap().last_snapshot_fingerprint =
                Some("unacknowledged".into());
            let held = BTreeSet::from(["unacknowledged".into()]);
            let previous = ScanIndex::default();
            let oracle = index.with_locally_held_keys_reverted(&previous, &held, &held);
            let mut restored = index.into_locally_held_keys_reverted(&previous, &held, &held);
            assert_eq!(
                serde_json::to_value(&restored.files).unwrap(),
                serde_json::to_value(oracle.files).unwrap()
            );
            assert!(restored.files[&key].last_snapshot_fingerprint.is_none());
            restored.migrate(f.candidate());
            restored.record(f.candidate(), None, ScanParseOutcome::Unknown);
            let unhealthy = matches!(restored.files[&key].archive.as_ref().unwrap().disposition, ArchiveDisposition::Held { .. } | ArchiveDisposition::Refused { .. });
            let (_, result, rows, _) = archive_pass(&f, checkpoint(&restored), true, None);
            assert_eq!(result.unreadable_path_count > 0, unhealthy);
            assert_eq!(decodes(&rows), 0);
            assert!(result.snapshots.is_empty());
        }
    }
    #[test]
    #[cfg_attr(
        not(target_os = "macos"),
        ignore = "funded decoder needs validated heap layout"
    )]
    fn archive_uses_logical_sidecar_classification_and_blocks_ambiguous_names() {
        let _lock = ARCHIVE_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let f =
            ArchiveFixture::new(&zstd::stream::encode_all(&synthetic_rollout()[..], 1).unwrap());
        let mut metadata = CodexTitleMetadata::default();
        metadata
            .state_created_threads
            .insert("compressed-fixture".into());
        let cache = Arc::new(sampled_scan::SharedCache::default());
        let mut index = ScanIndex::default();
        let mut parser = sampled_scan::new_source_parser(
            File::open(&f.0).unwrap(),
            &f.candidate(),
            SnapshotSource::Codex,
            &metadata,
            None,
            None,
            false,
            false,
            false,
            &mut index,
            Some(&cache),
        )
        .unwrap();
        while !parser.step().unwrap() {}
        assert!(parser.accumulator.codex_created_thread_native_only);
        assert!(!parser.accumulator.codex_usage_accounting_complete());
        parser.reader.reader.close();
        let modern =
            f.0.with_file_name("rollout-2026-10-28T10-00-00-compressed-fixture.jsonl.zst");
        fs::copy(&f.0, &modern).unwrap();
        let candidate = super::super::codex_zst_refusal_tests::candidate(&modern);
        let mut index = ScanIndex::default();
        assert!(sampled_scan::new_source_parser(
            File::open(&modern).unwrap(),
            &candidate,
            SnapshotSource::Codex,
            &metadata,
            None,
            None,
            false,
            false,
            false,
            &mut index,
            None
        )
        .is_err());
        for id in [
            "compressed-fixture",
            "2026-10-28T10-00-00-compressed-fixture",
        ] {
            assert!(index.codex_state_only_blocked_session_ids.contains(id));
        }
    }
    #[test]
    #[cfg_attr(not(target_os = "macos"), ignore = "needs validated heap layout")]
    fn paid_decoder_closes_after_real_eof_early_read_error_and_caught_unwind() {
        let _lock = DECODER_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
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
                    assert_eq!(
                        reader.get_ref().remaining,
                        max_jsonl_file_bytes(SnapshotSource::Codex)
                    );
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
    #[cfg_attr(not(target_os = "macos"), ignore = "needs validated heap layout")]
    fn paid_decoder_yields_to_singleton_and_drop_safety_net_is_observable() {
        let _lock = DECODER_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
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
    fn factory(
        f: &ArchiveFixture,
        index: &mut ScanIndex,
        cache: Option<&Arc<sampled_scan::SharedCache>>,
    ) -> Result<OwnedJsonlParser> {
        sampled_scan::new_source_parser(
            File::open(&f.0).unwrap(),
            &f.candidate(),
            SnapshotSource::Codex,
            &CodexTitleMetadata::default(),
            None,
            None,
            false,
            true,
            false,
            index,
            cache,
        )
    }
    fn assert_pending(index: &ScanIndex, path: &Path, expected: u8) {
        assert!(
            matches!(index.files[&local_index_key(path)].archive.as_ref().unwrap().disposition,
            ArchiveDisposition::Pending { attempts, .. } if attempts == expected)
        );
    }
    #[test]
    #[cfg_attr(not(target_os = "macos"), ignore = "needs validated heap layout")]
    fn archive_admission_yields_without_consuming_evidence_or_a_retry() {
        let _lock = ARCHIVE_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let f =
            ArchiveFixture::new(&zstd::stream::encode_all(&synthetic_rollout()[..], 1).unwrap());
        let key = local_index_key(&f.0);
        let (mut previous, _, _, _) = archive_pass(&f, ScanIndex::default(), true, None);
        retry_due(&mut previous, &key);
        for baseline in [ScanIndex::default(), checkpoint(&previous)] {
            for why in 0..3 {
                let mut index = baseline.clone();
                let cache = Arc::new(sampled_scan::SharedCache::default());
                let busy = (why == 1).then(|| {
                    OpenedInput::funded(File::open(&f.0).unwrap(), &cache)
                        .unwrap()
                        .unwrap()
                });
                let (result, rows) = crate::local_resource_diagnostics::capture(|| {
                    if why == 2 {
                        sampled_scan::codex_cursor::with_test_state_budget(0, || {
                            factory(&f, &mut index, Some(&cache))
                        })
                    } else {
                        factory(&f, &mut index, (why != 0).then_some(&cache))
                    }
                });
                assert!(result.is_err());
                assert_eq!(
                    serde_json::to_value(&index.files).unwrap(),
                    serde_json::to_value(&baseline.files).unwrap()
                );
                assert_eq!(decodes(&rows), 0);
                assert!(!rows
                    .iter()
                    .any(|r| r["stage"] == "codex_zst_first_read_retry"));
                assert!(rows.iter().any(|r| r["counts"]["codex_zst_refused"]
                    ["CompressedAdmissionRefused"]
                    .as_u64()
                    .is_some_and(|n| n > 0)));
                if let Some(input) = busy {
                    input.close();
                }
                let (_, result, rows, _) = archive_pass(&f, index, true, None);
                assert_eq!(decodes(&rows), 1);
                assert_eq!(result.snapshots.len(), 1);
            }
        }
    }
    #[test]
    #[cfg_attr(not(target_os = "macos"), ignore = "needs validated heap layout")]
    fn archive_interrupted_decode_budget_sticks_and_content_change_resets_attempts() {
        let _lock = ARCHIVE_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let bytes = synthetic_rollout();
        let encoded = zstd::stream::encode_all(&bytes[..], 1).unwrap();
        let f = ArchiveFixture::new(&encoded);
        let key = local_index_key(&f.0);
        let (mut index, _, _, _) = archive_pass(&f, ScanIndex::default(), true, None);
        index
            .files
            .get_mut(&key)
            .unwrap()
            .archive
            .as_mut()
            .unwrap()
            .disposition = ArchiveDisposition::Pending {
            attempts: 6,
            retry_after: 0,
        };
        index
            .files
            .get_mut(&key)
            .unwrap()
            .archive
            .as_mut()
            .unwrap()
            .decode_attempts = 6;
        let (held, result, rows, _) = archive_pass(&f, checkpoint(&index), true, None);
        assert_eq!(decodes(&rows), 0, "restart must not admit attempt seven");
        assert!(result.snapshots.is_empty());
        assert!(held.accepted_snapshot_fingerprints.is_empty());
        assert!(matches!(
            held.files[&key].archive.as_ref().unwrap().disposition,
            ArchiveDisposition::Held {
                cause: CodexZstCause::DecodeBudget
            }
        ));
        for (n, cause) in [CodexZstCause::DecodeBudget, CodexZstCause::DecodeFailed]
            .into_iter()
            .enumerate()
        {
            let mut state = held.clone();
            state
                .files
                .get_mut(&key)
                .unwrap()
                .archive
                .as_mut()
                .unwrap()
                .stamp =
                crate::transcript_acquisition::FileStamp::capture(fs::metadata(&f.0).unwrap())
                    .unwrap()
                    .content_only();
            if cause == CodexZstCause::DecodeFailed {
                state
                    .files
                    .get_mut(&key)
                    .unwrap()
                    .archive
                    .as_mut()
                    .unwrap()
                    .disposition = ArchiveDisposition::Refused { cause };
            }
            let (_, result, rows, _) = archive_pass(&f, checkpoint(&state), true, None);
            assert_eq!(decodes(&rows), 0);
            assert!(result.snapshots.is_empty());
            let mut changed = encoded.clone();
            changed.extend(zstd::stream::encode_all(&vec![b'\n'; n + 1][..], 1).unwrap());
            fs::write(&f.0, changed).unwrap();
            let (fresh, result, rows, _) = archive_pass(&f, state, true, None);
            assert_eq!(decodes(&rows), 1);
            assert_eq!(result.snapshots.len(), 1);
            assert_pending(&fresh, &f.0, 1);
            assert!(!rows
                .iter()
                .any(|r| r["stage"] == "codex_zst_first_read_retry"));
            fs::write(&f.0, &encoded).unwrap();
        }
    }
    #[test]
    #[cfg_attr(not(target_os = "macos"), ignore = "needs validated heap layout")]
    fn archive_identity_revalidation_failure_remains_pending_and_releases_owner() {
        let _lock = ARCHIVE_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let f =
            ArchiveFixture::new(&zstd::stream::encode_all(&synthetic_rollout()[..], 1).unwrap());
        let path = f.0.clone();
        let (index, result, rows, ends) = with_after_reader_eof(
            move |_| {
                let mut file = fs::OpenOptions::new().append(true).open(&path).unwrap();
                file.write_all(&zstd::stream::encode_all(&b"\n"[..], 1).unwrap())
                    .unwrap();
            },
            || archive_pass(&f, ScanIndex::default(), true, None),
        );
        assert_eq!(decodes(&rows), 1);
        assert_pending(&index, &f.0, 1);
        assert!(result.snapshots.is_empty());
        assert!(!ends
            .0
            .lock()
            .unwrap()
            .contains(&super::super::line_delivery::DeliveryEnd::Complete));
        assert!(!rows.iter().any(|r| r["stage"] == "codex_zst_owner"));
    }
    #[test]
    #[cfg_attr(not(target_os = "macos"), ignore = "needs validated heap layout")]
    fn archive_expired_launch_evidence_is_a_pending_finish_error() {
        use base64::Engine;
        let _lock = ARCHIVE_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let id = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
        let bytes = String::from_utf8(synthetic_rollout())
            .unwrap()
            .replace("compressed-fixture", id);
        let mut f = ArchiveFixture::new(&zstd::stream::encode_all(bytes.as_bytes(), 1).unwrap());
        let path = f.0.with_file_name(format!("rollout-{id}.jsonl.zst"));
        fs::rename(&f.0, &path).unwrap();
        f.0 = path;
        let cache = Arc::new(sampled_scan::SharedCache::default());
        let mut index = ScanIndex::default();
        let mut parser = factory(&f, &mut index, Some(&cache)).unwrap();
        while !parser.step().unwrap() {}
        let expected =
            opened_object_identity(SnapshotSource::Codex, parser.reader.reader.get_mut()).unwrap();
        let key = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([7_u8; 32]);
        let context = crate::session_attribution::SessionAttributionContext::from_activity_hint(
            SnapshotSource::Codex,
            f.0.parent().unwrap(),
            true,
            Some(&key),
            Some(crate::session_attribution::SESSION_ATTRIBUTION_HMAC_KEY_VERSION),
        )
        .unwrap();
        let workers = [id.to_string()];
        for _ in 0..10 {
            if context.prepare_launch_step(&workers).unwrap() {
                break;
            }
        }
        assert!(context.launches_prepared(&workers));
        context.expire_launch_lookup_for_test();
        let error = parser
            .finish(
                &expected,
                &f.0,
                NOW,
                "fixture".into(),
                Some(&CodexTitleMetadata::default()),
                None,
                Some(&context),
            )
            .unwrap_err();
        assert!(error
            .to_string()
            .contains("launch evidence lookup incomplete"));
        index.archive_decode_error(&f.0, &error);
        assert_pending(&index, &f.0, 1);
        assert_eq!(cache.cursor_reserved(), 0);
        for state in [index.clone(), checkpoint(&index)] {
            let (_, result, rows, _) = archive_pass(&f, state, true, None);
            assert_eq!(decodes(&rows), 0);
            assert!(result.snapshots.is_empty());
            assert!(result.unreadable_path_count > 0);
        }
    }
    #[test]
    #[cfg_attr(not(target_os = "macos"), ignore = "needs validated heap layout")]
    fn pending_io_without_body_remains_disclosed_on_every_quiet_pass() {
        let _lock = ARCHIVE_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let f =
            ArchiveFixture::new(&zstd::stream::encode_all(&synthetic_rollout()[..], 1).unwrap());
        let cache = Arc::new(sampled_scan::SharedCache::default());
        let mut index = ScanIndex::default();
        let parser = factory(&f, &mut index, Some(&cache)).unwrap();
        parser.reader.reader.close(); // interrupted first read, without body or ACK
        index.archive_decode_error(&f.0, &io::Error::other("synthetic step EIO").into());
        for _ in 0..3 {
            let (next, result, rows, _) = archive_pass(&f, checkpoint(&index), true, None);
            assert_pending(&next, &f.0, 1);
            assert_eq!(decodes(&rows), 0);
            assert!(result.snapshots.is_empty());
            assert!(result.unreadable_path_count > 0);
            index = next;
        }
    }
    #[test]
    #[cfg_attr(not(target_os = "macos"), ignore = "needs validated heap layout")]
    fn admission_starvation_alarms_at_twelve_passes_without_touching_evidence() {
        let _lock = ARCHIVE_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let f =
            ArchiveFixture::new(&zstd::stream::encode_all(&synthetic_rollout()[..], 1).unwrap());
        let mut index = ScanIndex::default();
        let saved_index = f.0.parent().unwrap().join("index.json");
        for pass in 1..=14 {
            assert!(serde_json::to_value(&index)
                .unwrap()
                .get("compressed_admission_yields")
                .is_none());
            index.save(&saved_index).unwrap();
            assert!(!fs::read_to_string(&saved_index)
                .unwrap()
                .contains("compressed_admission_yields"));
            index = ScanIndex::load(&saved_index).unwrap();
            let (next, result, rows, _) = archive_pass(&f, index, false, None);
            assert!(next.files.is_empty());
            assert_eq!(decodes(&rows), 0);
            assert_eq!(result.unreadable_path_count > 0, pass < 12);
            assert_eq!(
                rows.iter()
                    .filter(|r| r["stage"] == "codex_zst_refused")
                    .count(),
                1
            );
            assert_eq!(
                rows.iter()
                    .filter(|r| r["stage"] == "codex_zst_admission_alarm")
                    .count(),
                usize::from(pass == 12)
            );
            index = next;
        }
        let (index, _, rows, _) = archive_pass(&f, index, true, None);
        assert_eq!(decodes(&rows), 1);
        let key = local_index_key(&f.0);
        assert_eq!(
            admission_streak(&key, true),
            1,
            "funding reset the process streak"
        );
        admission_streak(&key, false);
        assert!(index.files[&key].archive.is_some());
    }
    #[test]
    fn admission_streaks_are_bounded_and_retired_with_archive_keys() {
        let _lock = ARCHIVE_TEST_LOCK
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        STREAKS
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clear();
        for i in 0..512 {
            assert_eq!(admission_streak(&format!("synthetic-archive-{i}"), true), 1);
            assert!(STREAKS.lock().unwrap_or_else(PoisonError::into_inner).len() <= 256);
        }
        assert_eq!(
            STREAKS.lock().unwrap_or_else(PoisonError::into_inner).len(),
            256
        );
        let f = ArchiveFixture::new(b"synthetic stamp only");
        let key = local_index_key(&f.0);
        assert_eq!(admission_streak(&key, true), 1);
        let mut index = ScanIndex::default();
        index.files.entry(key.clone()).or_default().archive = Some(Box::new(
            ArchiveEvidence::begin(&File::open(&f.0).unwrap(), &f.0, None).unwrap(),
        ));
        assert!(serde_json::to_value(&index)
            .unwrap()
            .get("compressed_admission_yields")
            .is_none());
        assert!(!super::super::lenient_decode::FIELDS.contains(&"compressed_admission_yields"));
        index.remove_file_entry(&key);
        assert!(!index.files.contains_key(&key));
        assert_eq!(
            admission_streak(&key, true),
            1,
            "retirement reset the streak"
        );
        STREAKS
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clear();
        assert_eq!(
            admission_streak(&key, true),
            1,
            "new process starts a new streak"
        );
        admission_streak(&key, false);
    }
    #[test]
    #[cfg_attr(not(target_os = "macos"), ignore = "needs validated heap layout")]
    fn actual_plain_codex_record_has_no_archive_allocation() {
        let _lock = ARCHIVE_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut f = ArchiveFixture::new(&synthetic_rollout());
        let plain = f.0.with_extension("");
        fs::rename(&f.0, &plain).unwrap();
        f.0 = plain;
        let (index, result, rows, _) = archive_pass(&f, ScanIndex::default(), true, None);
        assert_eq!(result.snapshots.len(), 1);
        assert_eq!(decodes(&rows), 0);
        let entry = &index.files[&local_index_key(&f.0)];
        assert!(entry.last_snapshot_fingerprint.is_some());
        assert!(entry.archive.is_none());
        let mut charge = crate::heap_layout_bound::Counter::new(usize::MAX);
        crate::heap_layout_bound::HeapLayoutBound::heap_bound(&entry.archive, &mut charge).unwrap();
        assert_eq!(charge.bytes, 0);
    }
    fn ack_bodies(scan: &SourceScanResult) -> BTreeMap<String, String> {
        scan.snapshots
            .iter()
            .map(|s| {
                (
                    s.snapshot_fingerprint.clone(),
                    snapshot_upload_body_witness(s),
                )
            })
            .collect()
    }
    fn staged_archive(
        f: &ArchiveFixture,
        index: ScanIndex,
        cache: Arc<sampled_scan::SharedCache>,
    ) -> OwnedSourceScan {
        staged_archive_with(f, index, cache, |_| {})
    }
    fn staged_archive_with(
        f: &ArchiveFixture,
        index: ScanIndex,
        cache: Arc<sampled_scan::SharedCache>,
        setup: impl FnOnce(&mut OwnedSourceScan),
    ) -> OwnedSourceScan {
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
        .with_sampled_acquisition(cache, Scope("archive-test".into()));
        scan.identified_candidates = VecDeque::from([f.candidate()]);
        scan.census
            .observed_index_keys
            .insert(local_index_key(&f.0));
        scan.codex_join_prepared = true;
        scan.census_unix_seconds = None;
        setup(&mut scan);
        for _ in 0..1000 {
            scan = match scan.step(None) {
                OwnedSourceScanStep::Pending(next) => next,
                _ => panic!("archive should pause before first read"),
            };
            if scan.active_file.is_some() {
                return scan;
            }
        }
        panic!("archive was not staged");
    }
    fn decoded_in(scan: &OwnedSourceScan) -> u64 {
        match &scan.active_file.as_ref().unwrap().parser.reader.reader {
            OpenedInput::Compressed(reader, _) => reader.get_ref().decoded_bytes,
            _ => panic!("expected funded decoder"),
        }
    }
    #[test]
    #[cfg_attr(not(target_os = "macos"), ignore = "needs validated heap layout")]
    fn retained_ack_cannot_settle_a_new_failed_archive_attempt() {
        let _lock = ARCHIVE_TEST_LOCK
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let original = synthetic_rollout();
        let f = ArchiveFixture::new(&zstd::stream::encode_all(&original[..], 1).unwrap());
        let key = local_index_key(&f.0);
        let (mut index, first, _, _) = archive_pass(&f, ScanIndex::default(), true, None);
        let old_ack = ack_bodies(&first);
        index.settle_archive_bodies(&old_ack);
        assert!(matches!(
            index.files[&key].archive.as_ref().unwrap().disposition,
            ArchiveDisposition::Acquired
        ));
        let old_witness = index.files[&key].last_upload_body_witness.clone();
        let old_fps = index.file_snapshot_fingerprints[&key].clone();
        let changed = String::from_utf8(original).unwrap().replace("400", "900");
        fs::write(
            &f.0,
            zstd::stream::encode_all(changed.as_bytes(), 1).unwrap(),
        )
        .unwrap();
        let cache = Arc::new(sampled_scan::SharedCache::default());
        let mut parser = factory(&f, &mut index, Some(&cache)).unwrap();
        assert!(!parser.step().unwrap());
        parser.reader.reader.close();
        index.archive_decode_error(&f.0, &io::Error::other("synthetic mid-read EIO").into());
        assert_eq!(index.files[&key].last_upload_body_witness, old_witness);
        assert_eq!(index.file_snapshot_fingerprints[&key], old_fps);
        assert!(index.files[&key]
            .archive
            .as_ref()
            .unwrap()
            .body_witness
            .is_none());
        index.settle_archive_bodies(&old_ack);
        assert_pending(&index, &f.0, 1);
        let mut restored: ScanIndex =
            serde_json::from_slice(&serde_json::to_vec(&index).unwrap()).unwrap();
        restored.settle_archive_bodies(&old_ack);
        assert_pending(&restored, &f.0, 1);
        retry_due(&mut restored, &key);
        let (mut next, body, _, _) = archive_pass(&f, restored, true, None);
        assert_eq!(body.snapshots.len(), 1);
        next.settle_archive_bodies(&old_ack);
        assert_pending(&next, &f.0, 2);
        next.settle_archive_bodies(&ack_bodies(&body));
        assert!(matches!(
            next.files[&key].archive.as_ref().unwrap().disposition,
            ArchiveDisposition::Acquired
        ));
    }
    #[test]
    #[cfg_attr(not(target_os = "macos"), ignore = "needs validated heap layout")]
    fn archive_and_plain_prior_exclusive_bodies_suppress_state_only_replacements() {
        let _lock = ARCHIVE_TEST_LOCK
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let id = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
        for archive in [true, false] {
            for modern in [false, true] {
                let bytes = String::from_utf8(synthetic_rollout())
                    .unwrap()
                    .replace("compressed-fixture", id);
                let encoded = zstd::stream::encode_all(bytes.as_bytes(), 1).unwrap();
                let mut f = ArchiveFixture::new(if archive { &encoded } else { bytes.as_bytes() });
                let prefix = if modern {
                    "rollout-2026-10-07T12-00-00-"
                } else {
                    "rollout-"
                };
                let suffix = if archive { ".jsonl.zst" } else { ".jsonl" };
                let path = f.0.with_file_name(format!("{prefix}{id}{suffix}"));
                fs::rename(&f.0, &path).unwrap();
                f.0 = path;
                let key = local_index_key(&f.0);
                let mut metadata = CodexTitleMetadata::default();
                metadata.state_threads.insert(
                    id.into(),
                    CodexStateThread {
                        tokens_used: 440,
                        model: Some("gpt-synthetic".into()),
                        ..Default::default()
                    },
                );
                let mut control = Vec::new();
                append_codex_state_only_snapshots(
                    &mut control,
                    &metadata,
                    NOW,
                    &mut ScanIndex::default(),
                    &BTreeSet::new(),
                );
                assert_eq!(control.len(), 1, "trusted state fallback is reachable");
                let (mut index, first, _, _) =
                    archive_pass_with(&f, ScanIndex::default(), true, None, &[], |scan| {
                        scan.codex_title_metadata = metadata.clone();
                    });
                assert_eq!(first.snapshots.len(), 1);
                let native = first.snapshots[0].clone();
                assert_eq!(native.source_session_id, id);
                assert_eq!(native.unattributed_total_tokens, 0);
                assert!(!native.model_usage.is_empty());
                assert_eq!(
                    native.usage_accounting_contract.as_deref(),
                    Some("session_exclusive_reported_usage:v1")
                );
                index.settle_archive_bodies(&ack_bodies(&first));
                assert!(
                    !index.codex_state_only_blocked_session_ids.contains(id),
                    "coverage must work after native block clears"
                );
                let witness = index.files[&key].last_upload_body_witness.clone();
                for state in [
                    index.clone(),
                    serde_json::from_slice(&serde_json::to_vec(&index).unwrap()).unwrap(),
                ] {
                    let (quiet, result, rows, _) =
                        archive_pass_with(&f, state, true, None, &[], |scan| {
                            scan.codex_title_metadata = metadata.clone();
                        });
                    assert_eq!(decodes(&rows), 0);
                    assert!(
                        result.snapshots.is_empty(),
                        "archive={archive}, modern={modern}: no state-only replacement"
                    );
                    assert_eq!(quiet.files[&key].last_upload_body_witness, witness);
                    assert_eq!(
                        snapshot_upload_body_witness(&native),
                        ack_bodies(&first)[&native.snapshot_fingerprint]
                    );
                }
                if archive {
                    let mut changed = bytes.as_bytes().to_vec();
                    changed.push(b'\n');
                    fs::write(&f.0, zstd::stream::encode_all(&changed[..], 1).unwrap()).unwrap();
                    let cache = Arc::new(sampled_scan::SharedCache::default());
                    let parser = factory(&f, &mut index, Some(&cache)).unwrap();
                    parser.reader.reader.close();
                    index.archive_decode_error(&f.0, &io::Error::other("synthetic EIO").into());
                    let evidence = index.files[&key].archive.as_ref().unwrap();
                    assert!(evidence.owner.is_none());
                    assert_eq!(evidence.logical_id, id, "retain prior native body coverage");
                    let mut pending = Vec::new();
                    append_codex_state_only_snapshots(
                        &mut pending,
                        &metadata,
                        NOW,
                        &mut index,
                        &BTreeSet::new(),
                    );
                    assert!(pending.is_empty());
                }
                if modern {
                    // Existing plain-file edge case: both legal filename grammars
                    // have state support. Keep this separate bug visible to owners.
                    metadata.state_threads.insert(
                        format!("2026-10-07T12-00-00-{id}"),
                        metadata.state_threads[id].clone(),
                    );
                    let mut ambiguous = Vec::new();
                    append_codex_state_only_snapshots(
                        &mut ambiguous,
                        &metadata,
                        NOW,
                        &mut index,
                        &BTreeSet::new(),
                    );
                    let replacement = ambiguous.iter().find(|s| s.source_session_id == id);
                    assert_eq!(replacement.is_some(), !archive);
                    if let Some(replacement) = replacement {
                        assert_eq!(replacement.unattributed_total_tokens, 440);
                        assert_ne!(replacement.model_usage, native.model_usage);
                    }
                }
            }
        }
    }
    #[test]
    #[cfg_attr(not(target_os = "macos"), ignore = "needs validated heap layout")]
    fn archive_reservation_is_durable_before_read_and_survives_mid_decode_crash() {
        let _lock = ARCHIVE_TEST_LOCK
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let f =
            ArchiveFixture::new(&zstd::stream::encode_all(&synthetic_rollout()[..], 1).unwrap());
        let path = f.0.parent().unwrap().join("mid-read-index.json");
        let key = local_index_key(&f.0);
        let cache = Arc::new(sampled_scan::SharedCache::default());
        let mut committed = ScanIndex::default();
        committed.save(&path).unwrap();
        let mut scan = staged_archive(&f, committed.clone(), Arc::clone(&cache));
        for _ in 0..3 {
            assert_eq!(decoded_in(&scan), 0);
            scan = match scan.step(None) {
                OwnedSourceScanStep::Pending(next) => next,
                _ => panic!("unsaved reservation must wait"),
            };
        }
        assert!(!ScanIndex::load(&path).unwrap().files.contains_key(&key));
        scan.persist_archive_reservation(&mut committed, &path)
            .unwrap();
        let saved = ScanIndex::load(&path).unwrap();
        assert_pending(&saved, &f.0, 1);
        let deadline = match saved.files[&key].archive.as_ref().unwrap().disposition {
            ArchiveDisposition::Pending { retry_after, .. } => retry_after,
            _ => unreachable!(),
        };
        assert!(saved.files[&key]
            .archive
            .as_ref()
            .unwrap()
            .body_witness
            .is_none());
        assert!(saved.files[&key].last_snapshot_fingerprint.is_none());
        assert!(
            saved.file_snapshot_fingerprints.is_empty()
                && saved.accepted_snapshot_fingerprints.is_empty()
        );
        scan = match scan.step(None) {
            OwnedSourceScanStep::Pending(next) => next,
            _ => panic!("fixture should be mid-parse"),
        };
        assert!(decoded_in(&scan) > 0);
        scan.active_file
            .take()
            .unwrap()
            .parser
            .reader
            .reader
            .close(); // process-death simulation, release fixture credit
        assert_eq!(cache.cursor_reserved(), 0);
        let (mut restarted, result, rows, _) =
            archive_pass(&f, ScanIndex::load(&path).unwrap(), true, None);
        assert_eq!(decodes(&rows), 0);
        assert!(result.snapshots.is_empty());
        assert_pending(&restarted, &f.0, 1);
        assert!(
            matches!(restarted.files[&key].archive.as_ref().unwrap().disposition, ArchiveDisposition::Pending { retry_after, .. } if retry_after == deadline)
        );
        retry_due(&mut restarted, &key);
        fs::write(&path, serde_json::to_vec(&restarted).unwrap()).unwrap();
        let mut second = staged_archive(&f, restarted.clone(), Arc::clone(&cache));
        second
            .persist_archive_reservation(&mut restarted, &path)
            .unwrap();
        assert_pending(&ScanIndex::load(&path).unwrap(), &f.0, 2);
        second
            .active_file
            .take()
            .unwrap()
            .parser
            .reader
            .reader
            .close();
    }
    #[test]
    #[cfg_attr(not(target_os = "macos"), ignore = "needs validated heap layout")]
    fn archive_reservation_save_failure_releases_owner_and_restores_committed_entry() {
        let _lock = ARCHIVE_TEST_LOCK
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let f =
            ArchiveFixture::new(&zstd::stream::encode_all(&synthetic_rollout()[..], 1).unwrap());
        let cache = Arc::new(sampled_scan::SharedCache::default());
        let mut committed = ScanIndex::default();
        let before = serde_json::to_value(&committed.files).unwrap();
        let mut scan = staged_archive(&f, committed.clone(), Arc::clone(&cache));
        let blocked = f.0.parent().unwrap().join("not-a-directory");
        fs::write(&blocked, b"fixture").unwrap();
        let (error, rows) = crate::local_resource_diagnostics::capture(|| {
            scan.persist_archive_reservation(&mut committed, &blocked.join("index.json"))
        });
        assert!(error.is_err());
        assert_eq!(serde_json::to_value(&committed.files).unwrap(), before);
        assert!(scan.active_file.is_none());
        assert_eq!(cache.cursor_reserved(), 0);
        assert!(!rows.iter().any(|r| r["stage"] == "codex_zst_owner"));
        assert!(rows.iter().any(
            |r| r["stage"] == "codex_zst_input" && r["counts"]["codex_zst_decoded_bytes"] == 0
        ));
    }
    #[test]
    fn decoder_read_io_is_not_a_sticky_content_refusal() {
        struct Broken;
        impl Read for Broken {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                Err(io::Error::other("synthetic EIO"))
            }
        }
        let mut decoder = BoundedDecoder::new(Broken, 1024).unwrap();
        let error = decoder.read_to_end(&mut Vec::new()).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Other);
        assert!(error
            .get_ref()
            .and_then(|e| e.downcast_ref::<CodexZstCause>())
            .is_none());
    }
    #[test]
    fn plain_entries_have_no_archive_allocation_and_stubs_grant_no_authority() {
        use crate::heap_layout_bound::HeapLayoutBound;
        for source in [SnapshotSource::ClaudeCode, SnapshotSource::Codex] {
            let entry = ScanIndexEntry::default();
            assert!(entry.archive.is_none(), "{source:?}");
            let mut counter = crate::heap_layout_bound::Counter::new(usize::MAX);
            entry.heap_bound(&mut counter).unwrap();
            assert_eq!(
                counter.bytes, 0,
                "{source:?} has no heap for archive metadata"
            );
        }
        let f = ArchiveFixture::new(b"synthetic stamp only");
        let evidence = ArchiveEvidence::begin(&File::open(&f.0).unwrap(), &f.0, None).unwrap();
        let key = local_index_key(&f.0);
        let minimum = size_of::<ArchiveEvidence>() + evidence.logical_id.capacity();
        let mut index = ScanIndex::default();
        index.files.entry(key.clone()).or_default().archive = Some(Box::new(evidence));
        let mut charge = crate::heap_layout_bound::Counter::new(usize::MAX);
        index.files[&key].heap_bound(&mut charge).unwrap();
        assert!(charge.bytes >= minimum, "boxed evidence must be charged");
        let saved = checkpoint(&index);
        let stub = &saved.files[&key];
        assert_eq!((stub.size_bytes, stub.modified_unix_seconds), (0, 0));
        assert!(stub.source_file_fingerprint.is_empty() && stub.scan_identity_version.is_none());
        assert!(
            stub.last_snapshot_fingerprint.is_none() && stub.last_upload_body_witness.is_none()
        );
        assert!(saved.file_snapshot_fingerprints.is_empty());
        assert!(saved.accepted_snapshot_fingerprints.is_empty());
        assert!(saved.confirmed_empty_files.is_empty());
        assert!(saved.traversal.is_none());
    }
    #[test]
    #[cfg_attr(not(target_os = "macos"), ignore = "needs validated heap layout")]
    fn archive_priority_receipt_survives_trace_expiry_and_lost_ack() {
        let _lock = ARCHIVE_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let turn = "aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa";
        let mut records: Vec<Value> = synthetic_rollout()
            .split(|b| *b == b'\n')
            .filter(|r| !r.is_empty())
            .map(|r| serde_json::from_slice(r).unwrap())
            .collect();
        records.insert(
            1,
            json!({"type":"turn_context","payload":{"turn_id":turn,"model":"gpt-synthetic"}}),
        );
        let bytes = records
            .iter()
            .map(|r| serde_json::to_string(r).unwrap() + "\n")
            .collect::<String>();
        let f = ArchiveFixture::new(&zstd::stream::encode_all(bytes.as_bytes(), 1).unwrap());
        let (index, first, _, _) =
            archive_pass_with(&f, ScanIndex::default(), true, None, &[], |scan| {
                let mut traces = CodexTurnTraceMap::default();
                traces.priority_turns.insert(turn.into());
                scan.codex_turn_traces = Some(Arc::new(traces));
            });
        assert_eq!(first.snapshots.len(), 1);
        assert!(first.snapshots[0].model_usage.iter().any(|r| r
            .selector_context
            .get("service_tier")
            .map(String::as_str)
            == Some("priority")));
        let key = local_index_key(&f.0);
        assert!(codex_file_join::receipt_state(index.files.get(&key))
            .0
            .is_some());
        let mut saved = checkpoint(&index);
        retry_due(&mut saved, &key);
        let (_, recovered, rows, _) = archive_pass(&f, saved, true, None); // traces expired
        assert_eq!(decodes(&rows), 1);
        assert_eq!(
            serde_json::to_value(&recovered.snapshots).unwrap(),
            serde_json::to_value(&first.snapshots).unwrap()
        );
    }
    #[test]
    #[cfg_attr(not(target_os = "macos"), ignore = "needs validated heap layout")]
    fn archive_v2_and_legacy_ack_evidence_carry_with_settled_bodies() {
        use super::super::codex_counting_version::AckEvidence;
        let _cutover = super::super::codex_counting_version::TestCutover::set(0);
        let _lock = ARCHIVE_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let f =
            ArchiveFixture::new(&zstd::stream::encode_all(&synthetic_rollout()[..], 1).unwrap());
        let key = local_index_key(&f.0);
        for v2 in [false, true] {
            let mut prior = ScanIndex::default();
            prior.files.insert(
                key.clone(),
                ScanIndexEntry {
                    codex_counting_v2: v2,
                    last_snapshot_fingerprint: Some("previous-ack".into()),
                    ..Default::default()
                },
            );
            let (mut index, result, rows, _) = archive_pass(&f, prior, true, None);
            assert_eq!(decodes(&rows), 1);
            assert_eq!(result.snapshots.len(), 1);
            let bodies = result
                .snapshots
                .iter()
                .map(|s| {
                    (
                        s.snapshot_fingerprint.clone(),
                        snapshot_upload_body_witness(s),
                    )
                })
                .collect();
            index.settle_archive_bodies(&bodies);
            let expected = if v2 {
                AckEvidence::V2Marked
            } else {
                AckEvidence::LegacyAcked
            };
            assert_eq!(AckEvidence::of_view([&index.files[&key]]), expected);
            for entry in [
                index.files[&key].clone(),
                serde_json::from_value(serde_json::to_value(&index.files[&key]).unwrap()).unwrap(),
            ] {
                assert_eq!(AckEvidence::of_view([&entry]), expected);
                assert!(matches!(
                    entry.archive.as_ref().unwrap().disposition,
                    ArchiveDisposition::Acquired
                ));
            }
            let (_, result, rows, _) = archive_pass(&f, index, true, None);
            assert_eq!(decodes(&rows), 0);
            assert!(result.snapshots.is_empty());
        }
    }
    #[test]
    #[cfg_attr(not(target_os = "macos"), ignore = "needs validated heap layout")]
    fn archive_fork_child_before_plain_parent_recovers_exclusive_money_on_bounded_retry() {
        let _lock = ARCHIVE_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let parent = "bbbbbbbb-1111-4111-8111-bbbbbbbbbbbb";
        let meta = |id: &str| json!({"timestamp":"2026-10-07T08:00:00Z","type":"session_meta","payload":{"id":id,"thread_source":"user"}});
        let turn = |id: &str| json!({"timestamp":"2026-10-07T08:00:01Z","type":"turn_context","payload":{"turn_id":id,"model":"gpt-synthetic"}});
        let usage = |input, cached, output, reasoning| json!({"timestamp":"2026-10-07T08:00:02Z","type":"event_msg","payload":{"type":"token_count","info":{"model":"gpt-synthetic","total_token_usage":{"input_tokens":input,"cached_input_tokens":cached,"output_tokens":output,"reasoning_output_tokens":reasoning}}}});
        let jsonl = |rows: Vec<Value>| {
            rows.iter()
                .map(|r| serde_json::to_string(r).unwrap() + "\n")
                .collect::<String>()
        };
        let inherited = [turn("parent-turn-1"), usage(100, 80, 10, 2)];
        let mut header = meta("compressed-fixture");
        header["payload"]["forked_from_id"] = json!(parent);
        let child = jsonl(vec![
            header,
            inherited[0].clone(),
            inherited[1].clone(),
            turn("child-turn-1"),
            usage(130, 100, 14, 3),
        ]);
        let f = ArchiveFixture::new(&zstd::stream::encode_all(child.as_bytes(), 1).unwrap());
        let roots = [f.0.parent().unwrap().to_owned()];
        let (index, result, rows, ends) =
            archive_pass_with(&f, ScanIndex::default(), true, None, &roots, |_| {});
        assert_eq!(decodes(&rows), 1);
        assert!(result.snapshots.is_empty());
        assert_pending(&index, &f.0, 1);
        assert!(!ends
            .0
            .lock()
            .unwrap()
            .contains(&super::super::line_delivery::DeliveryEnd::Complete));
        assert!(index.codex_parent_ownership_refs.contains(parent));
        let mut index = checkpoint(&index);
        let path = roots[0].join(format!("rollout-{parent}.jsonl"));
        fs::write(
            &path,
            jsonl(vec![
                meta(parent),
                inherited[0].clone(),
                inherited[1].clone(),
                turn("parent-turn-2"),
                usage(160, 125, 18, 4),
            ]),
        )
        .unwrap();
        for _ in 0..8 {
            scan_source_roots(
                SnapshotSource::Codex,
                &roots,
                &mut index,
                NOW,
                BACKFILL_WINDOW_DAYS,
            )
            .unwrap();
            if index.codex_parent_ownership_ledgers.contains_key(parent) {
                break;
            }
        }
        assert!(index.codex_parent_ownership_ledgers.contains_key(parent));
        let key = local_index_key(&f.0);
        let (mut saved, result, rows, _) = archive_pass_with(&f, index, true, None, &roots, |_| {});
        assert_eq!(
            decodes(&rows),
            0,
            "parent arrival does not bypass six hours"
        );
        assert!(result.unreadable_path_count > 0);
        assert!(!result
            .snapshots
            .iter()
            .any(|s| s.source_session_id == "compressed-fixture"));
        retry_due(&mut saved, &key);
        let (after, result, rows, _) = archive_pass_with(&f, saved, true, None, &roots, |_| {});
        assert_eq!(decodes(&rows), 1);
        assert_pending(&after, &f.0, 2);
        let child = result
            .snapshots
            .iter()
            .find(|s| s.source_session_id == "compressed-fixture")
            .expect("recovered child");
        assert_eq!(
            (
                child.input_tokens,
                child.cache_read_tokens,
                child.output_tokens
            ),
            (30, 20, 4)
        );
        assert_eq!(
            child.provenance.input_token_scope.as_deref(),
            Some("inclusive_cached")
        );
    }
}
