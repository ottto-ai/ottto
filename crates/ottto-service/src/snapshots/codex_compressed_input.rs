//! Bounded `.jsonl.zst` rollout input behind the one opened-object parser seam.
//! Discovery does not enumerate compressed rollouts yet. Activation must also
//! bind the header, plain/compressed twin identity and decoder credit at each
//! open site before it constructs `OpenedInput::compressed`.
#![cfg_attr(not(test), allow(dead_code))]
use crate::local_resource_diagnostics::{codex_zst_refused, CodexZstCause};
use std::fs::File;
use std::io::{self, BufRead, BufReader, Read};
use std::mem::size_of;
use std::path::Path;
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

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

/// Decoder heap credit: the compressed input buffer plus twice zstd's own
/// streaming bound for this window, covering old and new buffers that may
/// coexist while a frame resizes them.
fn decoder_reservation() -> io::Result<usize> {
    // SAFETY: pure size query, no pointers or external state. Bound is for the
    // same bundled zstd version and window limit used by this decoder.
    let estimate =
        unsafe { zstd::zstd_safe::zstd_sys::ZSTD_estimateDStreamSize(1usize << WINDOW_LOG) };
    // SAFETY: zstd error classification is a pure integer query.
    if unsafe { zstd::zstd_safe::zstd_sys::ZSTD_isError(estimate) } != 0 {
        return Err(invalid("cannot bound compressed rollout decoder"));
    }
    estimate
        .checked_mul(2)
        .and_then(|n| n.checked_add(BUFFER_BYTES))
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

fn thread_cpu_micros() -> u64 {
    let mut spec: libc::timespec = unsafe { std::mem::zeroed() };
    // SAFETY: valid writable timespec, querying only the current thread.
    if unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, &mut spec) } != 0 {
        return 0;
    }
    (spec.tv_sec as u64)
        .saturating_mul(1_000_000)
        .saturating_add(spec.tv_nsec as u64 / 1_000)
}

/// SOURCE Q3: no content, offsets, checkpoint or acceptance authority.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub(crate) struct ArchiveEvidence {
    pub(super) stamp: crate::transcript_acquisition::FileStamp,
    pub(super) logical_id: String,
    pub(super) owner: Option<String>,
    pub(super) disposition: ArchiveDisposition,
}
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub(crate) enum ArchiveDisposition {
    Acquired,
    Empty,
    Pending { attempts: u8, retry_after: u64 },
    Held { cause: CodexZstCause },
    Refused { cause: CodexZstCause },
}
impl ArchiveEvidence {
    pub(super) fn begin(file: &File, path: &Path, previous: Option<&Self>) -> io::Result<Self> {
        let logical = path.with_extension("");
        let logical_id = super::codex_session_id_candidates_from_path(&logical)
            .into_iter()
            .next()
            .ok_or_else(|| invalid("compressed rollout logical id unavailable"))?;
        let now = super::sampled_scan::now_seconds();
        let attempts = match previous
            .filter(|old| old.matches(file))
            .map(|old| &old.disposition)
        {
            Some(ArchiveDisposition::Pending { attempts, .. }) => attempts.saturating_add(1),
            _ => 1,
        };
        if attempts > 1 {
            crate::local_resource_diagnostics::traversal_point(
                "codex_zst_first_read_retry",
                "codex",
                &std::collections::BTreeMap::from([("codex_zst_first_read_retry", 1_u64)]),
            );
        }
        Ok(Self {
            stamp: crate::transcript_acquisition::FileStamp::capture(file.metadata()?)?
                .content_only(),
            logical_id,
            owner: None,
            disposition: ArchiveDisposition::Pending {
                attempts,
                retry_after: now.saturating_add(6 * 3600),
            },
        })
    }
    pub(super) fn finish(
        &mut self,
        owner: Option<String>,
        path: &Path,
        complete: bool,
        empty: bool,
    ) -> bool {
        use ArchiveDisposition::*;
        let logical = path.with_extension("");
        self.owner = owner
            .filter(|owner| super::codex_session_id_candidates_from_path(&logical).contains(owner));
        if let Some(owner) = &self.owner {
            self.logical_id = owner.clone();
        }
        if self.owner.is_none() {
            codex_zst_refused(CodexZstCause::OwnerUnproven);
            self.disposition = Refused {
                cause: CodexZstCause::OwnerUnproven,
            };
        } else if !complete {
            self.disposition = Held {
                cause: CodexZstCause::OutputHeld,
            };
        } else if empty {
            self.disposition = Empty;
        }
        self.owner.is_some() && complete
    }
    pub(super) fn quiet(&self, file: &File) -> bool {
        self.matches(file)
            && !matches!(self.disposition, ArchiveDisposition::Pending { retry_after, .. } if super::sampled_scan::now_seconds() >= retry_after)
    }
    pub(super) fn settle(&mut self, accepted: bool) {
        if let ArchiveDisposition::Pending { attempts, .. } = self.disposition {
            if accepted {
                self.disposition = ArchiveDisposition::Acquired;
            } else if attempts >= 3 {
                self.disposition = ArchiveDisposition::Held {
                    cause: CodexZstCause::SettlementStuck,
                };
                codex_zst_refused(CodexZstCause::SettlementStuck);
            }
        }
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
    input: BufReader<R>,
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
            input: BufReader::with_capacity(BUFFER_BYTES, input),
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
                .map_err(|_| invalid("invalid compressed rollout frame"))?;
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
                return Err(invalid("compressed rollout decoded-byte limit"));
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
                return Err(io::Error::new(kind, "incomplete compressed rollout"));
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
        crate::local_resource_diagnostics::traversal_point(
            "codex_zst_input",
            "codex",
            &std::collections::BTreeMap::from([
                ("codex_zst_compressed_bytes", self.compressed_bytes),
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
    ) -> io::Result<Self> {
        let credit = compressed_input_credit()?;
        let owner = super::sampled_scan::codex_cursor::DecoderOwner::acquire(cache, credit)
            .ok_or_else(|| invalid("compressed rollout admission refused"))?;
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
        input
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
            Self::Compressed(reader, _) => reader.get_ref().input.get_ref(),
        }
    }

    pub(super) fn get_mut(&mut self) -> &mut File {
        match self {
            Self::Plain(reader) => reader.get_mut(),
            Self::Compressed(reader, _) => reader.get_mut().input.get_mut(),
        }
    }

    pub(super) fn buffer(&self) -> &[u8] {
        match self {
            Self::Plain(reader) => reader.buffer(),
            Self::Compressed(reader, _) => reader.buffer(),
        }
    }

    /// Retained heap charge: funded input is already charged by SharedCache.
    /// Unfunded test input charges its box, buffers and full decoder credit;
    /// plain input charges exactly its buffer capacity.
    pub(super) fn capacity(&self) -> usize {
        match self {
            Self::Plain(reader) => reader.capacity(),
            Self::Compressed(_, Some(_)) => 0, // outstanding SharedCache claim owns this charge
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

impl super::ScanIndex {
    pub(crate) fn settle_archive_bodies(
        &mut self,
        accepted: &std::collections::BTreeMap<String, String>,
    ) {
        for (key, entry) in &mut self.files {
            if let Some(archive) = entry.archive.as_mut() {
                let bodies = self
                    .file_snapshot_fingerprints
                    .get(key)
                    .filter(|fps| !fps.is_empty())
                    .and_then(|fps| {
                        fps.iter()
                            .map(|fp| accepted.get(fp))
                            .collect::<Option<std::collections::BTreeSet<_>>>()
                    });
                let settled = bodies
                    .map(super::snapshot_file_upload_body_set_hex)
                    .as_ref()
                    .zip(entry.last_upload_body_witness.as_ref())
                    .is_some_and(|(a, b)| a == b);
                archive.settle(settled);
            }
        }
    }
    pub(super) fn archive_refuse(&mut self, path: &Path, cause: CodexZstCause) {
        if let Some(archive) = self
            .files
            .get_mut(&super::local_index_key(path))
            .and_then(|entry| entry.archive.as_mut())
        {
            archive.disposition = ArchiveDisposition::Refused { cause };
            codex_zst_refused(cause);
        }
    }
}
crate::heap_layout_bound::fields!(ArchiveEvidence; stamp, logical_id, owner, disposition);
impl crate::heap_layout_bound::HeapLayoutBound for ArchiveDisposition {
    fn heap_bound(&self, c: &mut crate::heap_layout_bound::Counter) -> Option<()> {
        c.add(0)
    }
}

#[cfg(test)]
pub(in crate::snapshots) mod tests {
    use super::super::*;
    use super::*;
    use crate::transcript_acquisition::Scope;
    use std::io::Write;
    use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};

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
        assert!(format!("{error:#}").contains("decoded-byte limit"));
    }
    pub(in crate::snapshots) static ARCHIVE_TEST_LOCK: Mutex<()> = Mutex::new(());
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
        let ends = Ends::default();
        let ((index, result), diagnostics) = crate::local_resource_diagnostics::capture(|| {
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
            for _ in 0..1000 {
                match scan.step(None) {
                    OwnedSourceScanStep::Pending(mut next) => {
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
            .filter(|row| row["stage"] == "codex_zst_input")
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
        let _lock = ARCHIVE_TEST_LOCK.lock().unwrap();
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
            let (mut state, result, rows, _) = archive_pass(&f, state, true, None);
            assert_eq!(decodes(&rows), 0);
            assert!(result.snapshots.is_empty());
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
            for state in [state.clone(), checkpoint(&state)] {
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
        let _lock = ARCHIVE_TEST_LOCK.lock().unwrap();
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
        let _lock = ARCHIVE_TEST_LOCK.lock().unwrap();
        let bytes = synthetic_rollout();
        let valid = zstd::stream::encode_all(&bytes[..], 1).unwrap();
        for (encoded, paid, limit) in [
            (b"corrupt".to_vec(), true, None),
            (valid[..valid.len() - 1].to_vec(), true, None),
            (valid.clone(), true, Some(1)),
            (valid.clone(), false, None),
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
            let (_, result, rows, _) = archive_pass(&f, checkpoint(&index), true, None);
            assert_eq!(decodes(&rows), 0);
            assert!(result.snapshots.is_empty());
        }
    }
    #[test]
    #[cfg_attr(
        not(target_os = "macos"),
        ignore = "funded decoder needs validated heap layout"
    )]
    fn archive_empty_held_and_selected_held_restore_carry_only_evidence() {
        let _lock = ARCHIVE_TEST_LOCK.lock().unwrap();
        for bytes in [
            b"{\"type\":\"session_meta\",\"payload\":{\"id\":\"compressed-fixture\"}}\n".to_vec(),
            b"{\"type\":\"session_meta\",\"payload\":{\"id\":\"wrong-owner\"}}\n".to_vec(),
            [synthetic_rollout(), b"{\"type\":\"event_msg\",\"payload\":{\"type\":\"token_count\",\"info\":{\"total_token_usage\":{\"input_tokens\":\"bad\"}}}}\n".to_vec()].concat(),
        ] {
            let f = ArchiveFixture::new(&zstd::stream::encode_all(&bytes[..], 1).unwrap());
            let (mut index, result, _, _) = archive_pass(&f, ScanIndex::default(), true, None);
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
            let (_, result, rows, _) = archive_pass(&f, checkpoint(&restored), true, None);
            assert_eq!(decodes(&rows), 0);
            assert!(result.snapshots.is_empty());
        }
    }
    #[test]
    #[cfg_attr(
        not(target_os = "macos"),
        ignore = "funded decoder needs validated heap layout"
    )]
    fn archive_decoder_has_one_process_owner_and_explicit_release() {
        let _lock = ARCHIVE_TEST_LOCK.lock().unwrap();
        let f =
            ArchiveFixture::new(&zstd::stream::encode_all(&synthetic_rollout()[..], 1).unwrap());
        let first = Arc::new(sampled_scan::SharedCache::default());
        let second = Arc::new(sampled_scan::SharedCache::default());
        let input = OpenedInput::funded(File::open(&f.0).unwrap(), &first).unwrap();
        assert_eq!(first.cursor_reserved(), compressed_input_credit().unwrap());
        assert!(OpenedInput::funded(File::open(&f.0).unwrap(), &second).is_err());
        input.close();
        assert_eq!(first.cursor_reserved(), 0);
        OpenedInput::funded(File::open(&f.0).unwrap(), &second)
            .unwrap()
            .close();
        assert_eq!(second.cursor_reserved(), 0);
    }
    #[test]
    #[cfg_attr(
        not(target_os = "macos"),
        ignore = "funded decoder needs validated heap layout"
    )]
    fn archive_uses_logical_sidecar_classification_and_blocks_ambiguous_names() {
        let _lock = ARCHIVE_TEST_LOCK.lock().unwrap();
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
    #[cfg_attr(
        not(target_os = "macos"),
        ignore = "funded decoder needs validated heap layout"
    )]
    fn archive_owner_normal_early_return_and_finish_error_release_explicitly() {
        let _lock = ARCHIVE_TEST_LOCK.lock().unwrap();
        let f =
            ArchiveFixture::new(&zstd::stream::encode_all(&synthetic_rollout()[..], 1).unwrap());
        let cache = Arc::new(sampled_scan::SharedCache::default());
        let (_, rows) = crate::local_resource_diagnostics::capture(|| {
            fn early_return(input: OpenedInput) {
                input.close();
            }
            early_return(OpenedInput::funded(File::open(&f.0).unwrap(), &cache).unwrap());
            assert_eq!(cache.cursor_reserved(), 0);
            let input = OpenedInput::funded(File::open(&f.0).unwrap(), &cache).unwrap();
            let parser = codex_parser(input, &f.0);
            assert!(parser
                .finish(
                    "unused",
                    &f.0,
                    NOW,
                    "fixture".into(),
                    Some(&CodexTitleMetadata::default()),
                    None,
                    None
                )
                .is_err());
            assert_eq!(cache.cursor_reserved(), 0);
        });
        assert!(!rows.iter().any(|row| row["stage"] == "codex_zst_owner"));
    }
    #[test]
    #[cfg_attr(
        not(target_os = "macos"),
        ignore = "funded decoder needs validated heap layout"
    )]
    fn archive_owner_unwind_refunds_and_reports_safety_net_release() {
        let _lock = ARCHIVE_TEST_LOCK.lock().unwrap();
        let f =
            ArchiveFixture::new(&zstd::stream::encode_all(&synthetic_rollout()[..], 1).unwrap());
        let cache = Arc::new(sampled_scan::SharedCache::default());
        let (result, rows) = crate::local_resource_diagnostics::capture(|| {
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _input = OpenedInput::funded(File::open(&f.0).unwrap(), &cache).unwrap();
                panic!("synthetic archive unwind");
            }))
        });
        assert!(result.is_err());
        assert_eq!(cache.cursor_reserved(), 0);
        let leaks = rows
            .iter()
            .filter(|row| row["stage"] == "codex_zst_owner")
            .map(|row| row["counts"]["leaked_release"].as_u64().unwrap())
            .sum::<u64>();
        assert_eq!(leaks, 1);
        OpenedInput::funded(File::open(&f.0).unwrap(), &cache)
            .unwrap()
            .close();
        assert_eq!(cache.cursor_reserved(), 0);
    }
}
