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
#[allow(clippy::large_enum_variant)] // Keep main's inline Plain buffer; M3 custody allocates only ON.
pub(super) enum OpenedInput {
    Plain(BufReader<File>),
    Durable(Box<BufReader<NativeFile>>),
    Compressed(
        Box<BufReader<BoundedDecoder<File>>>,
        Option<super::sampled_scan::codex_cursor::DecoderOwner>,
    ),
}

pub(super) struct NativeFile {
    file: File,
    custody: super::DurableCustody,
}
impl Read for NativeFile {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        #[cfg(unix)]
        if let Some(attempt) = self.custody.retail_mut() {
            return attempt.read(&mut self.file, bytes);
        }
        let read = self.file.read(bytes);
        #[cfg(all(test, unix))]
        super::sampled_scan::durable_tail::tests::a0h_record_read(&read);
        read
    }
}
impl io::Seek for NativeFile {
    fn seek(&mut self, at: io::SeekFrom) -> io::Result<u64> {
        self.file.seek(at)
    }
}

impl OpenedInput {
    pub(super) fn plain(file: File) -> Self {
        if super::restart_restore::enabled() {
            Self::Durable(Box::new(BufReader::new(NativeFile {
                file,
                custody: Default::default(),
            })))
        } else {
            Self::Plain(BufReader::new(file))
        }
    }

    pub(super) fn take_durable(&mut self) -> super::DurableCustody {
        match self {
            Self::Durable(reader) => std::mem::take(&mut reader.get_mut().custody),
            Self::Plain(_) | Self::Compressed(..) => Default::default(),
        }
    }
    pub(super) fn accepts_durable(&self) -> bool {
        match self {
            Self::Plain(_) => true,
            Self::Durable(reader) => reader.get_ref().custody.is_empty(),
            Self::Compressed(..) => false,
        }
    }
    pub(super) fn put_durable(&mut self, durable: super::DurableCustody) {
        match self {
            Self::Plain(_) if durable.is_empty() => {}
            Self::Durable(reader) if reader.get_ref().custody.is_empty() => {
                reader.get_mut().custody = durable
            }
            _ => unreachable!("validated empty Plain owner"),
        }
    }

    #[cfg(all(test, unix))]
    pub(super) fn put_retail(&mut self, attempt: super::sampled_scan::durable_tail::RetailAttempt) {
        if let Self::Durable(reader) = self {
            reader.get_mut().custody.put_retail(attempt);
        }
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
            Self::Durable(reader) => &reader.get_ref().file,
            Self::Compressed(reader, _) => reader.get_ref().input.get_ref(),
        }
    }

    pub(super) fn get_mut(&mut self) -> &mut File {
        match self {
            Self::Plain(reader) => reader.get_mut(),
            Self::Durable(reader) => &mut reader.get_mut().file,
            Self::Compressed(reader, _) => reader.get_mut().input.get_mut(),
        }
    }

    pub(super) fn buffer(&self) -> &[u8] {
        match self {
            Self::Plain(reader) => reader.buffer(),
            Self::Durable(reader) => reader.buffer(),
            Self::Compressed(reader, _) => reader.buffer(),
        }
    }

    /// Funded decoder memory is charged by its outstanding SharedCache claim.
    /// Unfunded synthetic input charges its box, buffer and full decoder credit;
    /// plain input charges only its buffer.
    pub(super) fn custody_heap_bound(
        &self,
        c: &mut crate::heap_layout_bound::Counter,
    ) -> Option<()> {
        use crate::heap_layout_bound::HeapLayoutBound;
        if let Self::Durable(reader) = self {
            reader.get_ref().custody.heap_bound(c)?;
        }
        Some(())
    }

    pub(super) fn capacity(&self) -> usize {
        match self {
            Self::Plain(reader) => reader.capacity(),
            Self::Durable(reader) => reader
                .capacity()
                .saturating_add(size_of::<BufReader<NativeFile>>())
                .saturating_add(std::mem::align_of::<BufReader<NativeFile>>()),
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
            Self::Durable(reader) => reader.read(output),
            Self::Compressed(reader, _) => reader.read(output),
        }
    }
}

impl BufRead for OpenedInput {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        match self {
            Self::Plain(reader) => reader.fill_buf(),
            Self::Durable(reader) => reader.fill_buf(),
            Self::Compressed(reader, _) => reader.fill_buf(),
        }
    }

    fn consume(&mut self, amount: usize) {
        match self {
            Self::Plain(reader) => reader.consume(amount),
            Self::Durable(reader) => reader.consume(amount),
            Self::Compressed(reader, _) => reader.consume(amount),
        }
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
        assert!(format!("{error:#}").contains("decoded-byte limit"));
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
}
