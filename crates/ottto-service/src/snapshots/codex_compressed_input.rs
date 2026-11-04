//! Bounded `.jsonl.zst` rollout input behind the one opened-object parser seam.
//! Encoding never grants ownership or acceptance authority.
use crate::local_resource_diagnostics::{codex_zst_refused, CodexZstCause};
#[cfg(test)]
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

// Darwin's large-block cache can return up to 2x a request, so no single peak
// receipt bounds it (Mac CI run 41373345993 refused at 16,285,728 charged bytes).
// Credit: zstd 1.5.7 WindowLogMax(23) requested peak 8,894,480 bytes (Mac CI run
// 41213075990), doubled, plus 10%, rounded up to 64 KiB = 19,595,264 bytes.
// Paid inside unchanged STATE_BYTES; admission preserves the primary Tail floor.
#[cfg(target_os = "macos")]
const COMPRESSED_INPUT_CREDIT: usize = (2 * 8_894_480 * 11_usize)
    .div_ceil(10)
    .next_multiple_of(64 * 1024);
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

    pub(super) fn decoded_bytes(&self) -> u64 {
        self.decoded_bytes
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

    // Zstd fails the stream on any refused allocation: a resource limit stays
    // owed and retried, and only an unrefused failure can be structural.
    fn classified(&self, error: io::Error) -> io::Error {
        if self.context.allocation_refusals() > 0 {
            io::Error::new(io::ErrorKind::WouldBlock, CodexZstCause::AdmissionRefused)
        } else {
            error
        }
    }
}

impl<R: Read> Read for BoundedDecoder<R> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        if self.failed {
            return Err(self.classified(invalid("compressed rollout previously failed")));
        }
        let started = crate::context_composition::thread_cpu_micros();
        let result = self
            .read_inner(output)
            .map_err(|error| self.classified(error));
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
#[allow(
    clippy::large_enum_variant,
    reason = "keeps main's inline Plain buffer"
)]
pub(super) enum OpenedInput {
    Plain(BufReader<File>),
    Compressed(
        Box<BufReader<BoundedDecoder<File>>>,
        Option<super::sampled_scan::codex_cursor::DecoderOwner>,
    ),
}

impl OpenedInput {
    /// The ordinary input encoding, after the caller securely opens the object.
    /// Refused decoder funding uses the caller's ordinary requeue/yield path.
    pub(super) fn encoded(
        file: File,
        path: &Path,
        cache: Option<&std::sync::Arc<super::sampled_scan::SharedCache>>,
    ) -> io::Result<Self> {
        if !is_compressed_codex_rollout(Some(path), None) {
            return Ok(Self::plain(file));
        }
        cache
            .map(|cache| Self::funded(file, cache))
            .transpose()?
            .flatten()
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::WouldBlock, CodexZstCause::AdmissionRefused)
            })
    }

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
    pub(super) fn header_only(mut self) -> Self {
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
            let measured_peak = 16_285_728_usize; // Mac run 41373345993, zstd 1.5.7.
            assert!(
                compressed_input_credit().unwrap() >= measured_peak + measured_peak.div_ceil(10)
            );
            assert_eq!(compressed_input_credit().unwrap(), 19_595_264);
        }
        #[cfg(not(target_os = "macos"))]
        assert_eq!(compressed_input_credit().unwrap(), 9_830_400);
        // The live large-window measurement below independently fails if an
        // upgraded decoder no longer fits its platform credit plus 10%.
    }

    /// [regress] An allocation refusal after partial decode was read as corrupt input and
    /// quiet-latched valid data (Mac CI run 41373345993).
    #[test]
    fn allocation_refusal_after_partial_decode_stays_owed() {
        let mut encoded = Vec::new();
        for log in [17, WINDOW_LOG] {
            let mut encoder = zstd::stream::write::Encoder::new(&mut encoded, 1).unwrap();
            encoder.window_log(log).unwrap();
            encoder.write_all(&[b'a'; 64 * 1024]).unwrap();
            encoder.finish().unwrap();
        }
        let mut decoder = BoundedDecoder::new(&encoded[..], u64::MAX).unwrap();
        // Room for the first frame's 128 KiB window, not the second's 8 MiB.
        decoder.context = DecoderContext::new(2 * 1024 * 1024).unwrap();
        decoder.context.set_window_log(WINDOW_LOG).unwrap();
        let error = std::io::copy(&mut decoder, &mut std::io::sink()).unwrap_err();
        assert_eq!(decoder.decoded_bytes(), 64 * 1024);
        assert_eq!(decoder.context.allocation_refusals(), 1);
        let repeated = decoder.read(&mut [0; 1]).unwrap_err();
        for failure in [&error, &repeated] {
            assert_eq!(failure.kind(), io::ErrorKind::Other);
        }

        // A resource failure is retryable ordinary acquisition, never a
        // structural/empty result. A fresh funded stream still decodes both frames.
        assert_eq!(decode(&encoded, u64::MAX).unwrap().len(), 128 * 1024);
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
            let owner = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
            rows[0]["payload"]["id"] = json!(owner);
            if creator {
                rows[0]["timestamp"] = json!("2026-10-07T09:59:00Z");
                rows[0]["payload"]["creator_user_id"] = json!("synthetic-user");
                rows[0]["payload"]["creator_account_id"] = json!("synthetic-workspace");
            }
            let bytes = rows.iter().map(|r| format!("{r}\n")).collect::<String>();
            let mut archive =
                ArchiveFixture::new(&zstd::stream::encode_all(bytes.as_bytes(), 1).unwrap());
            let uuid_path = archive
                .0
                .parent()
                .unwrap()
                .join(format!("rollout-{owner}.jsonl.zst"));
            fs::rename(&archive.0, &uuid_path).unwrap();
            archive.0 = uuid_path;
            assert_eq!(
                codex_session_id_from_path(&archive.0).as_deref(),
                Some(owner)
            );
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
            assert_eq!(!a["session_account_evidence"].is_null(), creator);
            use sampled_scan::transition_fixture::{
                money_oracle::assert_placement_equivalent, Mode, RouteResult,
            };
            let routes = bodies
                .iter()
                .enumerate()
                .map(|(n, body)| {
                    let mut route = RouteResult::emitted(
                        if n == 0 { Mode::ColdFull } else { Mode::Ram },
                        SnapshotSource::Codex,
                        vec![],
                        &[],
                    );
                    route
                        .snapshots
                        .insert(owner.into(), body["snapshots"][0].clone());
                    route
                })
                .collect::<Vec<_>>();
            assert_placement_equivalent(&routes[0], &routes[1]);
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
    fn selector_scan(
        f: &ArchiveFixture,
        index: ScanIndex,
        cache: Arc<sampled_scan::SharedCache>,
        mut candidates: VecDeque<CandidateFile>,
        _power: bool,
    ) -> OwnedSourceScan {
        let root = f.0.parent().unwrap().to_owned();
        let paths = candidates
            .iter()
            .map(|c| local_index_key(&c.path))
            .collect();
        candidates.retain(|candidate| {
            !codex_file_join::shadowed_compressed_path(&candidate.path, &paths)
        });
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
            None,
            &[],
            false,
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
        let traversal = scan.index.traversal.as_mut().unwrap();
        traversal.codex_rollout_paths = paths;
        traversal.scan_roots = vec![root];
        traversal.pending_directories.clear();
        scan
    }
    fn finish_selector(scan: OwnedSourceScan, checkpoint: &Path) -> (ScanIndex, SourceScanResult) {
        finish_selector_with(scan, checkpoint, |_| {})
    }
    fn finish_selector_with(
        scan: OwnedSourceScan,
        checkpoint: &Path,
        observe: impl FnMut(&mut OwnedSourceScan),
    ) -> (ScanIndex, SourceScanResult) {
        finish_selector_context(scan, checkpoint, observe, None)
    }
    fn finish_selector_context(
        mut scan: OwnedSourceScan,
        checkpoint: &Path,
        mut observe: impl FnMut(&mut OwnedSourceScan),
        attribution: Option<&crate::session_attribution::SessionAttributionContext>,
    ) -> (ScanIndex, SourceScanResult) {
        let committed = scan.index.clone();
        // Restart fixtures retain the exact CAS generation, as real loaded
        // indexes do; a new empty pathname cannot stand in for that database.
        if committed.generation > 0 && !checkpoint.exists() {
            fs::write(checkpoint, serde_json::to_vec(&committed).unwrap()).unwrap();
        }
        for _ in 0..100000 {
            match scan.step(attribution) {
                OwnedSourceScanStep::Pending(mut next) => {
                    observe(&mut next);
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

    /// [money] Standalone native ownership and legacy user forks read once.
    /// Claimants, damaged headers and unresolved roots owe no Full decode.
    /// Paid damaged-header attempts retain their cause and deadline across
    /// funded/unfunded passes and restart without physical re-reads.
    #[test]
    fn native_archive_fence_is_conservative_and_quiet_between_saved_retries() {
        let _lock = DECODER_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for case in ["standalone", "plain", "parent", "damaged"] {
            let mut bytes = synthetic_rollout();
            if case == "parent" {
                let text = String::from_utf8(bytes).unwrap().replace(
                    "\"id\":\"compressed-fixture\"",
                    "\"id\":\"compressed-fixture\",\"forked_from_id\":\"unresolved-parent\"",
                );
                bytes = text.into_bytes();
            }
            let f = ArchiveFixture::new(&if case == "damaged" {
                b"invalid zstd".to_vec()
            } else {
                zstd::stream::encode_all(&bytes[..], 1).unwrap()
            });
            if case == "plain" {
                fs::write(f.0.with_extension(""), &bytes).unwrap();
            }
            let (index, result, logs) = run_archive(
                &f,
                ScanIndex::default(),
                Arc::new(sampled_scan::SharedCache::default()),
            );
            if case == "damaged" {
                assert!(result.snapshots.is_empty());
                assert!(
                    result.unreadable_path_count > 0 || result.ownership_incomplete_file_count > 0
                );
                assert!(!index.confirmed_empty_files.contains(&local_index_key(&f.0)));
            } else {
                assert_eq!(result.snapshots.len(), 1, "{case}");
                assert_eq!(result.snapshots[0].input_tokens, 750, "{case}");
                // Ordinary header + body decoders are both accounted. Exact plain wins.
                assert_eq!(full_decodes(&logs) == 0, case == "plain");
            }
        }
    }
    /// [regress] Fork children, legacy user forks included, use the shared
    /// ownership parser even after restart from an old parent-held header.
    /// Plain/archive money and placement agree; ordinal children never charge
    /// the inherited prefix.
    #[test]
    fn archive_nonledger_children_resume_through_shared_ownership() {
        use sampled_scan::transition_fixture::{money_oracle, scan_money, Mode, RouteResult};
        let _lock = DECODER_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for kind in ["subagent", "ordinal", "history_base", "legacy"] {
            let mut rows: Vec<Value> = String::from_utf8(synthetic_rollout())
                .unwrap()
                .lines()
                .map(|line| serde_json::from_str(line).unwrap())
                .collect();
            let owner = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
            rows[0]["payload"]["id"] = json!(owner);
            rows[0]["timestamp"] = json!("2026-10-07T09:59:00Z");
            rows[0]["payload"]["creator_user_id"] = json!("synthetic-user");
            rows[0]["payload"]["creator_account_id"] = json!("synthetic-workspace");
            match kind {
                "subagent" => {
                    rows[0]["payload"]["source"] = json!({"subagent": {
                        "thread_spawn": {"parent_thread_id": "unresolved-parent"}
                    }});
                }
                "ordinal" => {
                    rows[0]["payload"]["parent_thread_id"] = json!("unresolved-parent");
                    rows[0]["payload"]["subagent_history_start_ordinal"] = json!(2);
                    for (ordinal, row) in rows.iter_mut().enumerate() {
                        row["ordinal"] = json!(ordinal);
                    }
                }
                "history_base" => {
                    rows[0]["payload"]["history_base"] = json!({"thread_id": "unresolved-parent"});
                }
                "legacy" => {
                    rows[0]["payload"]["forked_from_id"] = json!("unresolved-parent");
                }
                _ => unreachable!(),
            }
            let bytes = rows
                .iter()
                .map(|row| format!("{row}\n"))
                .collect::<String>();
            let mut f =
                ArchiveFixture::new(&zstd::stream::encode_all(bytes.as_bytes(), 1).unwrap());
            let path =
                f.0.parent()
                    .unwrap()
                    .join(format!("rollout-{owner}.jsonl.zst"));
            fs::rename(&f.0, &path).unwrap();
            f.0 = path;
            let key = local_index_key(&f.0);
            let mut old = ScanIndex::default();
            let mut legacy = serde_json::to_value(&old).unwrap();
            legacy["archives"] = json!({key.clone(): {
                "owner": owner, "disposition": {"Held": {
                    "cause": "CompressedParentLedgerUnbound", "quiet": true
                }}, "work": {"header": rows[0], "attempts": 1}
            }});
            old = serde_json::from_value(legacy).unwrap();
            let (index, result, logs) = run_archive(
                &f,
                saved(&old),
                Arc::new(sampled_scan::SharedCache::default()),
            );
            assert_eq!(full_decodes(&logs), 2, "ordinary header and body: {kind}");
            assert_eq!(result.snapshots.len(), 1, "{kind}");
            assert_eq!(
                result.snapshots[0].input_tokens,
                if kind == "ordinal" { 650 } else { 750 }
            );
            assert_eq!(
                result.snapshots[0].request_count,
                if kind == "ordinal" { 2 } else { 3 }
            );

            // Use the same logical path and ordinary parser on uncompressed
            // bytes. The production oracle normalizes physical fingerprints.
            let plain = fixture(bytes.as_bytes(), ".jsonl");
            let mut file = File::open(&plain.0).unwrap();
            let expected = opened_object_identity(SnapshotSource::Codex, &mut file).unwrap();
            let mut parser = codex_parser(OpenedInput::plain(file), &f.0);
            sampled_scan::configure_tier_replay(&mut parser, &f.candidate(), &old);
            codex_counting_version::configure_singleton(&mut parser, &f.candidate(), &old);
            while !parser.step().unwrap() {}
            let parsed = parser
                .finish(
                    &expected,
                    &f.0,
                    NOW,
                    "plain-fixture".into(),
                    Some(&CodexTitleMetadata::default()),
                    None,
                    None,
                )
                .unwrap();
            assert!(parsed.complete());
            let mut items = parsed.snapshots;
            apply_upload_policy(
                SnapshotSource::Codex,
                &mut items,
                SnapshotUploadPolicy::default(),
            );
            assert_eq!(
                items[0].session_account_evidence.is_some(),
                !matches!(kind, "history_base" | "legacy")
            );
            let mut batch = crate::snapshots::tests::valid_v6_batch_request();
            batch.source = SnapshotSource::Codex.api_slug().into();
            batch.snapshots = items.clone();
            let cold = RouteResult::emitted(
                Mode::ColdFull,
                SnapshotSource::Codex,
                vec![serde_json::to_vec(&batch).unwrap()],
                &items,
            );
            let actual = scan_money(SnapshotSource::Codex, &index, &result);
            money_oracle::assert_placement_equivalent(&cold, &actual);
            assert_eq!(
                cold.normalized, actual.normalized,
                "plain/archive money: {kind}"
            );
        }
    }
    /// [format] Saved header and page-wide Full reservations precede body
    /// bytes. A restart keeps owed custody and retries, counted, on the next
    /// pass with the money of a cold Full; a failed save consumes no Full.
    #[test]
    fn archive_reservation_retries_after_crash_and_failed_save_reads_no_body() {
        use sampled_scan::transition_fixture::{money_oracle, scan_money};
        let _lock = DECODER_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let f =
            ArchiveFixture::new(&zstd::stream::encode_all(&synthetic_rollout()[..], 1).unwrap());
        let (cold_index, cold_scan, _) = run_archive(
            &f,
            ScanIndex::default(),
            Arc::new(sampled_scan::SharedCache::default()),
        );
        let cold = scan_money(SnapshotSource::Codex, &cold_index, &cold_scan);
        let mut scan = selector_scan(
            &f,
            ScanIndex::default(),
            Arc::new(sampled_scan::SharedCache::default()),
            VecDeque::from([f.candidate()]),
            true,
        );
        for _ in 0..10000 {
            scan = match scan.step(None) {
                OwnedSourceScanStep::Pending(next) => next,
                OwnedSourceScanStep::Complete { .. } => panic!("must interrupt a live body"),
            };
            if scan
                .active_file
                .as_ref()
                .is_some_and(|a| a.parser.reader.consumed_bytes() > 0)
            {
                break;
            }
        }
        assert!(scan.active_file.is_some());
        let checkpoint = fixture(b"", ".json");
        fs::remove_file(&checkpoint.0).unwrap();
        scan.index.save(&checkpoint.0).unwrap();
        // A failed checkpoint cannot consume or grant accepted money.
        let before = fs::read(&checkpoint.0).unwrap();
        let mut stale = scan.index.clone();
        stale.generation = stale.generation.saturating_sub(1);
        assert!(stale.save(&checkpoint.0).is_err());
        assert_eq!(fs::read(&checkpoint.0).unwrap(), before);
        drop(scan);
        let restored = ScanIndex::load(&checkpoint.0).unwrap();
        assert!(restored.accepted_snapshot_fingerprints.is_empty());
        let (actual_index, actual_scan, _) =
            run_archive(&f, restored, Arc::new(sampled_scan::SharedCache::default()));
        money_oracle::assert_equivalent(
            &cold,
            &scan_money(SnapshotSource::Codex, &actual_index, &actual_scan),
        );
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
        let previous = ScanIndex::default();
        let (working, result, _) = run_archive(
            &f,
            previous.clone(),
            Arc::new(sampled_scan::SharedCache::default()),
        );
        assert_eq!(result.snapshots.len(), 1);
        assert_eq!(result.snapshots[0].input_tokens, 750);
        for outcome in ["wrong-body", "wrong-destination", "partial", "accept"] {
            let accepted = crate::snapshot_sync::archive_upload_checkpoint(
                working.clone(),
                &result,
                &previous,
                outcome,
            );
            let key = local_index_key(&f.0);
            if outcome == "accept" {
                assert!(accepted.files[&key].codex_counting_owner.is_some());
                assert_eq!(
                    accepted.files[&key].last_upload_body_witness,
                    Some(snapshot_upload_body_witness(&result.snapshots[0]))
                );
                let ((_, quiet, _), consumed) =
                    sampled_scan::transition_fixture::observe_consumed(|| {
                        run_archive(
                            &f,
                            saved(&accepted),
                            Arc::new(sampled_scan::SharedCache::default()),
                        )
                    });
                assert!(quiet.snapshots.is_empty());
                assert_eq!(consumed, 0);
                assert!(quiet.census_complete);
            } else {
                assert!(
                    !accepted.files.contains_key(&key),
                    "{outcome} cannot settle a new file"
                );
                assert!(!accepted
                    .accepted_snapshot_fingerprints
                    .contains(&result.snapshots[0].snapshot_fingerprint));
            }
        }
    }
    /// [behaviour] Resource refusal costs no Full or six-hour delay; the next
    /// permitted pass can finish using the ordinary native parser.
    #[test]
    fn archive_transient_denial_recovers_next_pass_and_pages_to_eof() {
        use sampled_scan::transition_fixture::{money_oracle, observe_consumed, scan_money};
        let _lock = DECODER_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        with_test_limits_for_test(16 * 1024, 4 * 1024, 1024, || {
            let mut bytes = synthetic_rollout();
            let padding = json!({"type":"unknown", "padding":"x".repeat(1024)}).to_string() + "\n";
            for _ in 0..32 {
                bytes.extend_from_slice(padding.as_bytes());
            }
            assert!(bytes.len() > 4 * 1024);
            let f = ArchiveFixture::new(&zstd::stream::encode_all(&bytes[..], 1).unwrap());
            let cache = Arc::new(sampled_scan::SharedCache::default());
            // Prove the current header once before denying BODY funding.
            // Reuse performs no header-byte acquisition; there is no invented
            // cached-header read failure or wildcard-owner shortcut.
            let root = f.0.parent().unwrap().to_owned();
            let paths = BTreeSet::from([local_index_key(&f.0)]);
            let mut directories = codex_file_join::DirectoryCensus::new();
            directories.observe(&root, &fs::metadata(&root).unwrap());
            let mut headers =
                codex_file_join::HeaderInventory::new(&[root], &paths, Some(&directories));
            while !headers.step_encoded(&CodexTitleMetadata::default(), Some(&cache)) {}
            assert!(headers.complete);
            // Hold the process decoder singleton: ordinary body acquisition
            // cannot acquire funding despite otherwise sufficient STATE_BYTES.
            let occupied = OpenedInput::funded(File::open(&f.0).unwrap(), &cache)
                .unwrap()
                .unwrap();
            let mut scan = selector_scan(
                &f,
                ScanIndex::default(),
                cache.clone(),
                VecDeque::from([f.candidate()]),
                true,
            );
            let key = local_index_key(&f.0);
            scan.codex_selected_flags.insert(key.clone(), (true, true));
            let checkpoint = fixture(b"", ".json");
            fs::remove_file(&checkpoint.0).unwrap();
            let ((mut refused, result), logs) =
                crate::local_resource_diagnostics::capture(|| finish_selector(scan, &checkpoint.0));
            assert!(result.snapshots.is_empty());
            assert_eq!(full_decodes(&logs), 0);
            assert!(!refused.confirmed_empty_files.contains(&key));
            assert!(refused.accepted_snapshot_fingerprints.is_empty());
            let pending = refused
                .traversal
                .as_ref()
                .unwrap()
                .pending_candidates
                .iter()
                .find(|p| p.path == f.0)
                .expect("refused ordinary candidate stays queued");
            assert!(
                pending.census_member && pending.watcher_hint,
                "both selection flags survive refusal"
            );
            refused.save(&checkpoint.0).unwrap();
            occupied.close();
            let restored = ScanIndex::load(&checkpoint.0).unwrap();
            let restart = selector_scan(
                &f,
                restored,
                cache.clone(),
                VecDeque::from([f.candidate()]),
                true,
            );
            let (actual_index, actual, _) = {
                let (index, scan) = finish_selector(restart, &checkpoint.0);
                (index, scan, ())
            };
            assert_eq!(actual.snapshots.len(), 1);
            assert_eq!(actual.snapshots[0].input_tokens, 750);
            let (cold_index, cold, _) = run_archive(
                &f,
                ScanIndex::default(),
                Arc::new(sampled_scan::SharedCache::default()),
            );
            money_oracle::assert_equivalent(
                &scan_money(SnapshotSource::Codex, &cold_index, &cold),
                &scan_money(SnapshotSource::Codex, &actual_index, &actual),
            );

            // One interruption after prefix consumption. The durable input
            // obligation is saved before acquisition; restart reconstructs and
            // discloses prefix work, then this owner runs to EOF without another restart.
            let scan = selector_scan(
                &f,
                ScanIndex::default(),
                cache,
                VecDeque::from([f.candidate()]),
                true,
            );
            let mut owed = scan.index.clone();
            let restart_file = fixture(b"", ".json");
            fs::remove_file(&restart_file.0).unwrap();
            owed.save(&restart_file.0).unwrap();
            let (((), prefix), first_logs) = crate::local_resource_diagnostics::capture(|| {
                observe_consumed(|| {
                    let mut scan = scan;
                    for _ in 0..10000 {
                        scan = match scan.step(None) {
                            OwnedSourceScanStep::Pending(next) => next,
                            OwnedSourceScanStep::Complete { .. } => panic!("interrupt before EOF"),
                        };
                        if scan
                            .active_file
                            .as_ref()
                            .is_some_and(|a| a.parser.reader.consumed_bytes() > 4096)
                        {
                            return;
                        }
                    }
                    panic!("no decoded prefix progress");
                })
            });
            assert!(prefix > 4096);
            let ((restarted_index, restarted, second_logs), after) = observe_consumed(|| {
                run_archive(
                    &f,
                    ScanIndex::load(&restart_file.0).unwrap(),
                    Arc::new(sampled_scan::SharedCache::default()),
                )
            });
            assert!(after >= bytes.len() as u64);
            let decoded = |logs: &[Value]| {
                logs.iter()
                    .filter_map(|l| l["counts"]["codex_zst_decoded_bytes"].as_u64())
                    .sum::<u64>()
            };
            assert!(
                decoded(&first_logs) + decoded(&second_logs) > bytes.len() as u64,
                "physical prefix reconstruction is counted"
            );
            money_oracle::assert_equivalent(
                &scan_money(SnapshotSource::Codex, &cold_index, &cold),
                &scan_money(SnapshotSource::Codex, &restarted_index, &restarted),
            );
        });
    }

    /// [money] Shed and partial checkpoints restart from the production
    /// committable subset, take one due Full and settle from a real uploader ACK.
    #[test]
    fn archive_unstored_body_restarts_from_committable_and_accepts_retry() {
        let _lock = DECODER_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for outcome in ["shed", "partial"] {
            let f = ArchiveFixture::new(
                &zstd::stream::encode_all(&synthetic_rollout()[..], 1).unwrap(),
            );
            let previous = ScanIndex::default();
            let (working, result, _) = run_archive(
                &f,
                previous.clone(),
                Arc::new(sampled_scan::SharedCache::default()),
            );
            let held = result
                .snapshots
                .iter()
                .map(|s| s.snapshot_fingerprint.clone())
                .collect();
            let reverted =
                working
                    .clone()
                    .into_locally_held_keys_reverted(&previous, &held, &BTreeSet::new());
            let key = local_index_key(&f.0);
            assert!(!reverted.files.contains_key(&key));
            let committed = crate::snapshot_sync::archive_upload_checkpoint(
                working, &result, &previous, outcome,
            );
            assert!(!committed.files.contains_key(&key));
            assert!(!committed.file_snapshot_fingerprints.contains_key(&key));
            let (working, retry, _) = run_archive(
                &f,
                saved(&committed),
                Arc::new(sampled_scan::SharedCache::default()),
            );
            assert_eq!(retry.snapshots.len(), 1);
            assert_eq!(
                snapshot_upload_body_witness(&retry.snapshots[0]),
                snapshot_upload_body_witness(&result.snapshots[0])
            );
            let accepted = crate::snapshot_sync::archive_upload_checkpoint(
                working, &retry, &committed, "accept",
            );
            assert!(accepted
                .accepted_snapshot_fingerprints
                .contains(&retry.snapshots[0].snapshot_fingerprint));
            assert_eq!(
                accepted.files[&key].last_upload_body_witness,
                Some(snapshot_upload_body_witness(&retry.snapshots[0]))
            );
        }
    }
    /// [money] A hinted archive refused before inventory has no minted marker;
    /// complete follow-up passes can acquire it normally.
    #[test]
    fn archive_hint_after_incomplete_inventory_recovers() {
        let _lock = DECODER_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for incomplete in [false, true] {
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
            scan.index
                .traversal
                .as_mut()
                .unwrap()
                .codex_rollout_paths
                .clear();
            let inventory = scan.codex_join_inventory.as_mut().unwrap();
            let root = f.0.parent().unwrap().to_owned();
            let mut directories = codex_file_join::DirectoryCensus::new();
            directories.observe(&root, &fs::metadata(&root).unwrap());
            *inventory = codex_file_join::HeaderInventory::new(
                &[root],
                &BTreeSet::new(),
                Some(&directories),
            );
            inventory.complete = !incomplete;
            let checkpoint = fixture(b"", ".json");
            fs::remove_file(&checkpoint.0).unwrap();
            let ((mut index, refused), logs) =
                crate::local_resource_diagnostics::capture(|| finish_selector(scan, &checkpoint.0));
            assert!(refused.snapshots.is_empty());
            assert!(!logs
                .iter()
                .any(|l| l["stage"] == "codex_zst_input" || l["stage"] == "codex_zst_inventory"));
            if !incomplete {
                assert!(refused.census_complete);
                assert_eq!(refused.unreadable_path_count, 0);
                assert_eq!(refused.ownership_incomplete_file_count, 0);
            }
            assert!(!index.files.contains_key(&local_index_key(&f.0)));
            // A complete follow-up is a new census, not the failed generation's
            // accumulated traversal errors paired with a synthetic complete header list.
            index.traversal = None;
            let (working, result, logs) = run_archive(
                &f,
                saved(&index),
                Arc::new(sampled_scan::SharedCache::default()),
            );
            assert_eq!(full_decodes(&logs), 2);
            let accepted =
                crate::snapshot_sync::archive_upload_checkpoint(working, &result, &index, "accept");
            let (_, quiet, logs) = run_archive(
                &f,
                saved(&accepted),
                Arc::new(sampled_scan::SharedCache::default()),
            );
            assert_eq!(full_decodes(&logs), 0);
            assert!(quiet.snapshots.is_empty());
        }
    }

    /// [money] Gone cancels an active paid Full before another record and
    /// releases decoder credit without minting a replacement marker.
    #[test]
    fn archive_gone_closes_an_active_full() {
        let _lock = DECODER_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let f =
            ArchiveFixture::new(&zstd::stream::encode_all(&synthetic_rollout()[..], 1).unwrap());
        let cache = Arc::new(sampled_scan::SharedCache::default());
        let scan = selector_scan(
            &f,
            ScanIndex::default(),
            cache.clone(),
            VecDeque::from([f.candidate()]),
            true,
        );
        let checkpoint = fixture(b"", ".json");
        fs::remove_file(&checkpoint.0).unwrap();
        let mut gone = false;
        let (index, result) = finish_selector_with(scan, &checkpoint.0, |next| {
            if !gone
                && next
                    .active_file
                    .as_ref()
                    .is_some_and(|a| a.parser.reader.consumed_bytes() > 0)
            {
                fs::remove_file(&f.0).unwrap();
                gone = true;
            }
        });
        assert!(gone);
        assert!(!index.files.contains_key(&local_index_key(&f.0)));
        assert!(result.snapshots.is_empty());
        assert_eq!(cache.cursor_reserved(), 0);
    }
    /// [money] Quiet outcomes survive repeated selection and expired clocks;
    /// proven deletion retires the marker without phantom archive debt.
    #[test]
    fn archive_quiet_projection_survives_three_passes_and_deletion() {
        let _lock = DECODER_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for empty in [false, true] {
            let bytes = if empty {
                b"{\"type\":\"session_meta\",\"payload\":{\"id\":\"compressed-fixture\"}}\n"
                    .to_vec()
            } else {
                synthetic_rollout()
            };
            let f = ArchiveFixture::new(&zstd::stream::encode_all(&bytes[..], 1).unwrap());
            let previous = ScanIndex::default();
            let (working, result, _) = run_archive(
                &f,
                previous.clone(),
                Arc::new(sampled_scan::SharedCache::default()),
            );
            let mut index = crate::snapshot_sync::archive_upload_checkpoint(
                working, &result, &previous, "accept",
            );
            let key = local_index_key(&f.0);
            for _ in 0..3 {
                let ((next, scan, _), consumed) =
                    sampled_scan::transition_fixture::observe_consumed(|| {
                        run_archive(
                            &f,
                            saved(&index),
                            Arc::new(sampled_scan::SharedCache::default()),
                        )
                    });
                assert_eq!(consumed, 0, "settled ordinary input stays quiet");
                assert!(scan.snapshots.is_empty());
                assert_eq!(
                    next.accepted_snapshot_fingerprints,
                    index.accepted_snapshot_fingerprints
                );
                index = next;
            }
            fs::remove_file(&f.0).unwrap();
            index.traversal = None;
            let (next, scan, _) =
                run_archive(&f, index, Arc::new(sampled_scan::SharedCache::default()));
            assert!(!next.files.contains_key(&key));
            assert!(scan.snapshots.is_empty());
        }
    }
    /// [money] A second archive cannot reuse the first archive's live absence
    /// witness after a claimant appears in the same inventory home.
    #[test]
    fn archive_fence_is_fresh_for_each_archive() {
        let _lock = DECODER_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let f =
            ArchiveFixture::new(&zstd::stream::encode_all(&synthetic_rollout()[..], 1).unwrap());
        let b = f.0.parent().unwrap().join("rollout-second.jsonl.zst");
        let bytes = String::from_utf8(synthetic_rollout())
            .unwrap()
            .replace("compressed-fixture", "second");
        fs::write(&b, zstd::stream::encode_all(bytes.as_bytes(), 1).unwrap()).unwrap();
        let mut second = codex_zst_refusal_tests::candidate(&b);
        second.size_bytes = fs::metadata(&b).unwrap().len();
        let scan = selector_scan(
            &f,
            ScanIndex::default(),
            Arc::new(sampled_scan::SharedCache::default()),
            VecDeque::from([f.candidate(), second]),
            true,
        );
        let checkpoint = fixture(b"", ".json");
        fs::remove_file(&checkpoint.0).unwrap();
        let mut appeared = false;
        let ((index, result), logs) = crate::local_resource_diagnostics::capture(|| {
            finish_selector_with(scan, &checkpoint.0, |next| {
                if !appeared && next.index.files.contains_key(&local_index_key(&f.0)) {
                    fs::write(f.0.parent().unwrap().join("rollout-claimant.jsonl"), &bytes)
                        .unwrap();
                    appeared = true;
                }
            })
        });
        assert!(appeared);
        assert_eq!(
            full_decodes(&logs),
            3,
            "two current headers, one body before membership changes"
        );
        assert_eq!(result.snapshots.len(), 1);
        assert!(!index.files.contains_key(&local_index_key(&b)));
    }
    /// [off=main] Archive correction/held debt discloses money without blocking
    /// the ordinary completed census, backfill marker or plain re-offers.
    #[test]
    #[serial_test::serial]
    #[serial_test::serial(source_cadences, source_manifests, client_report)]
    fn archive_debt_preserves_replay_and_plain_reoffers() {
        let _lock = DECODER_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let f =
            ArchiveFixture::new(&zstd::stream::encode_all(&synthetic_rollout()[..], 1).unwrap());
        let (working, scan, _) = run_archive(
            &f,
            ScanIndex::default(),
            Arc::new(sampled_scan::SharedCache::default()),
        );
        let mut index = crate::snapshot_sync::archive_upload_checkpoint(
            working,
            &scan,
            &ScanIndex::default(),
            "accept",
        );
        // Ordinary known-file ownership debt discloses an unsettled census
        // without revoking exact accepted bodies or blocking plain reoffers.
        let key = local_index_key(&f.0);
        let accepted = index.accepted_snapshot_fingerprints.clone();
        index.prepare_historical_replay("replay".into());
        let (index, mut scan, _) = run_archive(
            &f,
            saved(&index),
            Arc::new(sampled_scan::SharedCache::default()),
        );
        assert_eq!(scan.snapshots.len(), 1);
        assert_eq!(scan.snapshots[0].input_tokens, 750);
        assert!(!accepted.is_empty());
        assert!(index.files.contains_key(&key));
        scan.ownership_incomplete_file_count += 1;
        let expected_files = index.files.len();
        crate::snapshot_sync::assert_archive_debt_preserves_replay_progress(
            index,
            scan,
            expected_files,
        );
    }
    /// [regress] A plain append between reservation and admission cancels only
    /// the unspent archive attempt; the next pass can read its native body.
    #[test]
    fn archive_inventory_race_recovers_on_the_next_pass() {
        let _lock = DECODER_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let f =
            ArchiveFixture::new(&zstd::stream::encode_all(&synthetic_rollout()[..], 1).unwrap());
        let plain = f.0.parent().unwrap().join("rollout-other.jsonl");
        fs::write(
            &plain,
            String::from_utf8(synthetic_rollout())
                .unwrap()
                .replace("compressed-fixture", "other"),
        )
        .unwrap();
        let mut c = codex_zst_refusal_tests::candidate(&plain);
        c.size_bytes = fs::metadata(&plain).unwrap().len();
        let scan = selector_scan(
            &f,
            ScanIndex::default(),
            Arc::new(sampled_scan::SharedCache::default()),
            VecDeque::from([c, f.candidate()]),
            true,
        );
        let checkpoint = fixture(b"", ".json");
        fs::remove_file(&checkpoint.0).unwrap();
        let mut appended = false;
        let (index, first) = finish_selector_with(scan, &checkpoint.0, |next| {
            if !appended && next.codex_join_prepared && next.active_file.is_none() {
                fs::OpenOptions::new()
                    .append(true)
                    .open(&plain)
                    .unwrap()
                    .write_all(b"{}\n")
                    .unwrap();
                appended = true;
            }
        });
        assert!(appended);
        assert_eq!(first.unreadable_path_count, 0);
        assert!(first
            .snapshots
            .iter()
            .all(|s| s.source_session_id != "compressed-fixture"));
        assert!(!index.files.contains_key(&local_index_key(&f.0)));
        let (_, next, logs) = run_archive(
            &f,
            saved(&index),
            Arc::new(sampled_scan::SharedCache::default()),
        );
        assert!(next
            .snapshots
            .iter()
            .any(|s| s.source_session_id == "compressed-fixture"));
        assert_eq!(full_decodes(&logs), 2);
    }
    /// [regress] Expanding a plain join group can evict an archive from the
    /// page without reserving a Full or imposing a six-hour retry deadline.
    #[test]
    fn archive_page_eviction_does_not_reserve_a_full() {
        let _lock = DECODER_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let f =
            ArchiveFixture::new(&zstd::stream::encode_all(&synthetic_rollout()[..], 1).unwrap());
        let root = f.0.parent().unwrap();
        let mut members = Vec::new();
        for (name, response, total) in [("one", "one", 100), ("two", "two", 200)] {
            let path = root.join(format!("rollout-{name}.jsonl"));
            let rows = codex_file_join::tests::member("other", response, 100, total);
            fs::write(
                &path,
                rows.iter().map(|r| format!("{r}\n")).collect::<String>(),
            )
            .unwrap();
            let mut c = codex_zst_refusal_tests::candidate(&path);
            c.size_bytes = fs::metadata(&path).unwrap().len();
            members.push(c);
        }
        let mut scan = selector_scan(
            &f,
            ScanIndex::default(),
            Arc::new(sampled_scan::SharedCache::default()),
            VecDeque::from([members[0].clone(), f.candidate()]),
            true,
        );
        scan.file_limit = 2;
        let paths = BTreeSet::from([
            local_index_key(&f.0),
            local_index_key(&members[0].path),
            local_index_key(&members[1].path),
        ]);
        let mut directories = codex_file_join::DirectoryCensus::new();
        directories.observe(root, &fs::metadata(root).unwrap());
        scan.codex_join_inventory = Some(codex_file_join::HeaderInventory::new(
            &[root.to_owned()],
            &paths,
            Some(&directories),
        ));
        scan.index.traversal.as_mut().unwrap().codex_rollout_paths = paths;
        let checkpoint = fixture(b"", ".json");
        fs::remove_file(&checkpoint.0).unwrap();
        let (index, _) = finish_selector(scan, &checkpoint.0);
        assert!(!index.files.contains_key(&local_index_key(&f.0)));
        assert!(index
            .traversal
            .as_ref()
            .unwrap()
            .pending_candidates
            .iter()
            .any(|c| c.path == f.0));
    }
    /// [money] Secure-open and native tier-receipt refusals stay in archive
    /// custody while unrelated plain output and census eligibility are equal.
    #[test]
    fn archive_open_and_receipt_refusals_preserve_plain_work() {
        let _lock = DECODER_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for refusal in ["body", "receipt", "launch", "parsed-launch"] {
            let mut f = ArchiveFixture::new(
                &zstd::stream::encode_all(&synthetic_rollout()[..], 1).unwrap(),
            );
            let launch_home = crate::test_scratch::ScratchDir::new("archive-launch-refusal");
            let context = if matches!(refusal, "launch" | "parsed-launch") {
                use base64::Engine;
                let uuid = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
                if refusal == "launch" {
                    let path = f.0.parent().unwrap().join(format!("{uuid}.jsonl.zst"));
                    fs::rename(&f.0, &path).unwrap();
                    f.0 = path;
                }
                let bytes = String::from_utf8(synthetic_rollout())
                    .unwrap()
                    .replace("compressed-fixture", uuid);
                fs::write(&f.0, zstd::stream::encode_all(bytes.as_bytes(), 1).unwrap()).unwrap();
                let inbox = launch_home.join(".ottto/launch-events");
                fs::create_dir_all(&inbox).unwrap();
                fs::write(inbox.join("pending"), b"not a directory").unwrap();
                let key = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([13_u8; 32]);
                crate::session_attribution::SessionAttributionContext::from_activity_hint(
                    SnapshotSource::Codex,
                    &launch_home,
                    true,
                    Some(&key),
                    Some(crate::session_attribution::SESSION_ATTRIBUTION_HMAC_KEY_VERSION),
                )
            } else {
                None
            };
            let plain = f.0.parent().unwrap().join("rollout-other.jsonl");
            fs::write(
                &plain,
                String::from_utf8(synthetic_rollout())
                    .unwrap()
                    .replace("compressed-fixture", "other"),
            )
            .unwrap();
            let mut c = codex_zst_refusal_tests::candidate(&plain);
            c.size_bytes = fs::metadata(&plain).unwrap().len();
            let baseline = selector_scan(
                &f,
                ScanIndex::default(),
                Arc::new(sampled_scan::SharedCache::default()),
                VecDeque::from([c.clone()]),
                true,
            );
            let checkpoint = fixture(b"", ".json");
            fs::remove_file(&checkpoint.0).unwrap();
            let (_, control) =
                finish_selector_context(baseline, &checkpoint.0, |_| {}, context.as_ref());
            if refusal == "body" {
                // The complete first frame exposes a current owning header;
                // body acquisition then reaches a corrupt second frame.
                let mut encoded = fs::read(&f.0).unwrap();
                encoded.extend_from_slice(b"invalid body frame");
                fs::write(&f.0, encoded).unwrap();
            }
            let scan = selector_scan(
                &f,
                ScanIndex::default(),
                Arc::new(sampled_scan::SharedCache::default()),
                VecDeque::from([c, f.candidate()]),
                true,
            );
            let mut injected = false;
            let (index, result) = finish_selector_context(
                scan,
                &checkpoint.0,
                |next| {
                    if refusal == "receipt" && !injected {
                        if let Some(active) = next
                            .active_file
                            .as_mut()
                            .filter(|a| codex_archive_path(&a.candidate.path))
                        {
                            active
                                .parser
                                .accumulator
                                .codex_tier_replay
                                .as_mut()
                                .unwrap()
                                .admitted(Some(("synthetic-tier".into(), "x".repeat(65))));
                            injected = true;
                        }
                    }
                },
                context.as_ref(),
            );
            if refusal == "receipt" {
                assert!(injected);
            }
            assert!(!index.files.contains_key(&local_index_key(&f.0)));
            assert_eq!(result.snapshots.len(), control.snapshots.len());
            for (actual, expected) in result.snapshots.iter().zip(&control.snapshots) {
                assert_eq!(
                    snapshot_upload_body_witness(actual),
                    snapshot_upload_body_witness(expected)
                );
            }
            assert_eq!(result.unreadable_path_count, control.unreadable_path_count);
            assert_eq!(result.census_complete, control.census_complete);
            assert_eq!(
                result.census_residue_index_key_count,
                control.census_residue_index_key_count
            );
            assert!(result
                .snapshots
                .iter()
                .all(|s| s.source_session_id != "compressed-fixture"));
        }
    }
    /// [format] Unknown archive records become archive-only owed custody,
    /// never ordinary decode holds or an acceptance certificate.
    #[test]
    fn archive_marker_compatibility_and_plain_bytes_remain_independent() {
        let index = ScanIndex::default();
        let before = serde_json::to_value(&index).unwrap();
        for retired in [
            json!("future"),
            json!(false),
            json!({"path": {
                "stamp": null, "disposition": "Acquired"
            }}),
            json!({"path": {"disposition": {"Held": {
                "cause": "CompressedAdmissionRefused", "quiet": false
            }}}}),
        ] {
            let mut wire = before.clone();
            wire["archives"] = retired;
            wire["archive_deferred_alarm_count"] = json!(7);
            let checkpoint = fixture(&serde_json::to_vec(&wire).unwrap(), ".json");
            let mut decoded = ScanIndex::load(&checkpoint.0).unwrap();
            assert!(decoded.decode_holds.is_empty());
            assert!(decoded.accepted_snapshot_fingerprints.is_empty());
            assert_eq!(serde_json::to_value(&decoded).unwrap(), before);
            decoded.save(&checkpoint.0).unwrap();
            let restored = ScanIndex::load(&checkpoint.0).unwrap();
            assert!(restored.decode_holds.is_empty());
            assert!(restored.files.is_empty());
            assert!(serde_json::to_value(&restored)
                .unwrap()
                .get("archives")
                .is_none());
        }
    }
    /// [money] Held replay == seeded: correction debt keeps the acquired body's
    /// ownership and witnesses, reads no archive byte and emits no second copy,
    /// so the seeded emission stays the money, in totals and placement.
    #[test]
    fn archive_held_replay_equals_seeded() {
        use sampled_scan::transition_fixture::{money_oracle, scan_money};
        let _lock = DECODER_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let f =
            ArchiveFixture::new(&zstd::stream::encode_all(&synthetic_rollout()[..], 1).unwrap());
        let (working, emitted, _) = run_archive(
            &f,
            ScanIndex::default(),
            Arc::new(sampled_scan::SharedCache::default()),
        );
        let seeded = crate::snapshot_sync::archive_upload_checkpoint(
            working,
            &emitted,
            &ScanIndex::default(),
            "accept",
        );
        let mut replayed = saved(&seeded);
        replayed.prepare_historical_replay("replay".into());
        let (index, scan, _) =
            run_archive(&f, replayed, Arc::new(sampled_scan::SharedCache::default()));
        // The archive-only no-regrant latch is retired. An explicit ordinary
        // replay uses the same parser and must preserve totals and placement.
        assert_eq!(scan.snapshots.len(), 1);
        money_oracle::assert_equivalent(
            &scan_money(SnapshotSource::Codex, &seeded, &emitted),
            &scan_money(SnapshotSource::Codex, &index, &scan),
        );
        let key = local_index_key(&f.0);
        assert_eq!(
            index.files[&key].codex_counting_owner,
            seeded.files[&key].codex_counting_owner
        );
        assert_eq!(
            index.files[&key].last_upload_body_witness,
            seeded.files[&key].last_upload_body_witness
        );
    }

    /// [money] Correction debt alarms once per replay transition, and the
    /// accepted head never grants a new archive Full on replay churn. A
    /// setting or capability change holds no correction at all.
    #[test]
    fn archive_replay_holds_correction_without_regrant_but_context_does_not() {
        let _lock = DECODER_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let f =
            ArchiveFixture::new(&zstd::stream::encode_all(&synthetic_rollout()[..], 1).unwrap());
        let (working, result, _) = run_archive(
            &f,
            ScanIndex::default(),
            Arc::new(sampled_scan::SharedCache::default()),
        );
        let mut index = crate::snapshot_sync::archive_upload_checkpoint(
            working,
            &result,
            &ScanIndex::default(),
            "accept",
        );
        let before = index.files[&local_index_key(&f.0)]
            .last_upload_body_witness
            .clone();
        let (_, logs) = crate::local_resource_diagnostics::capture(|| {
            index.activate_file_upload_context(SnapshotSource::Codex, "changed".into())
        });
        assert!(!logs.iter().any(|l| l["stage"] == "durable_tail_alarm"));
        let ((flipped, quiet, _), consumed) =
            sampled_scan::transition_fixture::observe_consumed(|| {
                run_archive(
                    &f,
                    saved(&index),
                    Arc::new(sampled_scan::SharedCache::default()),
                )
            });
        assert_eq!(consumed, 0);
        assert!(quiet.snapshots.is_empty());
        assert_eq!(
            flipped.files[&local_index_key(&f.0)].last_upload_body_witness,
            before
        );
        // Explicit replay remains an ordinary re-read; a context flip alone
        // never grants it and cannot settle another body.
        index.prepare_historical_replay("changed".into());
        let (_, replay, _) = run_archive(&f, index, Arc::new(sampled_scan::SharedCache::default()));
        assert_eq!(replay.snapshots.len(), 1);
        assert_eq!(replay.snapshots[0].input_tokens, 750);
    }

    /// [money] Retired native entries never erase an archive's own owner
    /// or regrant a Full.
    #[test]
    fn archive_owner_survives_aged_entry_retirement() {
        let _lock = DECODER_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let f =
            ArchiveFixture::new(&zstd::stream::encode_all(&synthetic_rollout()[..], 1).unwrap());
        let (working, result, _) = run_archive(
            &f,
            ScanIndex::default(),
            Arc::new(sampled_scan::SharedCache::default()),
        );
        let index = crate::snapshot_sync::archive_upload_checkpoint(
            working,
            &result,
            &ScanIndex::default(),
            "accept",
        );
        let key = local_index_key(&f.0);
        let owner = index.files[&key].codex_counting_owner.clone();
        assert!(owner.is_some());
        let accepted = index.accepted_snapshot_fingerprints.clone();
        File::options()
            .write(true)
            .open(&f.0)
            .unwrap()
            .set_modified(std::time::UNIX_EPOCH + std::time::Duration::from_secs(1))
            .unwrap();
        let mut index = index;
        index.traversal = None;
        let scan = OwnedSourceScan::new(
            SnapshotSource::Codex,
            &[f.0.parent().unwrap().to_owned()],
            index,
            NOW,
            BACKFILL_WINDOW_DAYS,
            10,
            None,
            &[],
            false,
        )
        .with_sampled_acquisition(
            Arc::new(sampled_scan::SharedCache::default()),
            Scope("archive-age".into()),
        );
        let checkpoint = fixture(b"", ".json");
        fs::remove_file(&checkpoint.0).unwrap();
        let (index, scan) = finish_selector(scan, &checkpoint.0);
        assert!(scan.census_complete);
        assert!(scan.snapshots.is_empty());
        assert_eq!(
            index.accepted_snapshot_fingerprints, accepted,
            "age exclusion never manufactures or clears ACKs"
        );
        if let Some(entry) = index.files.get(&key) {
            assert_eq!(entry.codex_counting_owner, owner);
        }
    }

    /// [format] Header, structural and alarm evidence survives a held page;
    /// an unspent structural constructor failure retains its paced retry.
    #[test]
    fn archive_nonwitness_custody_survives_partial_and_local_hold() {
        let _lock = DECODER_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let f =
            ArchiveFixture::new(&zstd::stream::encode_all(&synthetic_rollout()[..], 1).unwrap());
        let (working, result, _) = run_archive(
            &f,
            ScanIndex::default(),
            Arc::new(sampled_scan::SharedCache::default()),
        );
        let accepted = crate::snapshot_sync::archive_upload_checkpoint(
            working,
            &result,
            &ScanIndex::default(),
            "accept",
        );
        let key = local_index_key(&f.0);
        for local in [false, true] {
            let committed = if local {
                accepted.clone().into_locally_held_keys_reverted(
                    &accepted,
                    &BTreeSet::from([key.clone()]),
                    &BTreeSet::new(),
                )
            } else {
                crate::snapshot_sync::archive_upload_checkpoint(
                    accepted.clone(),
                    &result,
                    &accepted,
                    "partial",
                )
            };
            assert_eq!(
                serde_json::to_value(&committed.files[&key]).unwrap(),
                serde_json::to_value(&accepted.files[&key]).unwrap()
            );
            assert_eq!(
                committed.file_snapshot_fingerprints,
                accepted.file_snapshot_fingerprints
            );
            assert_eq!(
                committed.accepted_snapshot_fingerprints,
                accepted.accepted_snapshot_fingerprints
            );
            let ((_, quiet, _), consumed) =
                sampled_scan::transition_fixture::observe_consumed(|| {
                    run_archive(
                        &f,
                        saved(&committed),
                        Arc::new(sampled_scan::SharedCache::default()),
                    )
                });
            assert_eq!(consumed, 0);
            assert!(quiet.snapshots.is_empty());
        }
    }

    /// [money] An exact archive ACK on an incomplete initial census keeps its
    /// own context across reload; later acquisitions retain the new context. A
    /// context change re-owes no archive.
    #[test]
    fn archive_context_is_per_marker_before_source_context_promotion() {
        let _lock = DECODER_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let f =
            ArchiveFixture::new(&zstd::stream::encode_all(&synthetic_rollout()[..], 1).unwrap());
        let plain = f.0.parent().unwrap().join("rollout-plain-pending.jsonl");
        fs::write(
            &plain,
            String::from_utf8(synthetic_rollout())
                .unwrap()
                .replace("compressed-fixture", "plain-pending"),
        )
        .unwrap();
        let mut index = ScanIndex {
            historical_replay_generation: Some("unchanged".into()),
            ..ScanIndex::default()
        };
        index.activate_file_upload_context(SnapshotSource::Codex, "first".into());
        for phase in ["first", "changed"] {
            let mut candidates = VecDeque::from([f.candidate()]);
            if phase == "changed" {
                let b = f.0.parent().unwrap().join("rollout-new.jsonl.zst");
                let bytes = String::from_utf8(synthetic_rollout())
                    .unwrap()
                    .replace("compressed-fixture", "new");
                fs::write(&b, zstd::stream::encode_all(bytes.as_bytes(), 1).unwrap()).unwrap();
                let mut c = codex_zst_refusal_tests::candidate(&b);
                c.size_bytes = fs::metadata(&b).unwrap().len();
                candidates.push_back(c);
            }
            let mut plain_candidate = codex_zst_refusal_tests::candidate(&plain);
            plain_candidate.size_bytes = fs::metadata(&plain).unwrap().len();
            candidates.push_back(plain_candidate.clone());
            let mut scan = selector_scan(
                &f,
                index,
                Arc::new(sampled_scan::SharedCache::default()),
                candidates,
                true,
            );
            scan.identified_candidates
                .retain(|c| codex_archive_path(&c.path));
            scan.index
                .traversal
                .as_mut()
                .unwrap()
                .pending_candidates
                .push_back(ScanTraversalPath {
                    scan_root: plain_candidate.scan_root,
                    path: plain.clone(),
                    census_member: true,
                    watcher_hint: false,
                });
            let checkpoint = fixture(b"", ".json");
            fs::remove_file(&checkpoint.0).unwrap();
            let previous = scan.index.clone();
            let (working, result) = finish_selector(scan, &checkpoint.0);
            assert!(!result.census_complete);
            // Per item, not source-wide: the still-pending plain census member
            // earns no upload-context receipt before the census completes.
            let plain_key = local_index_key(&plain);
            assert!(working
                .files
                .get(&plain_key)
                .map_or(true, |e| e.upload_context_receipt.is_none()));
            let accepted = crate::snapshot_sync::archive_upload_checkpoint(
                working, &result, &previous, "accept",
            );
            let checkpoint = fixture(&serde_json::to_vec(&accepted).unwrap(), ".json");
            index = ScanIndex::load(&checkpoint.0).unwrap();
            assert!(serde_json::to_value(&accepted)
                .unwrap()
                .get("upload_context_fingerprint")
                .is_none());
            assert!(index
                .files
                .get(&plain_key)
                .map_or(true, |e| e.upload_context_receipt.is_none()));
            assert_eq!(
                index.historical_replay_generation.as_deref(),
                Some("unchanged")
            );
            let (_, alarms) = crate::local_resource_diagnostics::capture(|| {
                index.activate_file_upload_context(SnapshotSource::Codex, "changed".into())
            });
            assert!(!alarms.iter().any(|l| l["stage"] == "durable_tail_alarm"
                || l["stage"] == "codex_zst_input"
                || l["stage"] == "codex_zst_inventory"));
            let first_key = local_index_key(&f.0);
            assert!(index.files[&first_key].last_upload_body_witness.is_some());
            if phase == "changed" {
                let b = f.0.parent().unwrap().join("rollout-new.jsonl.zst");
                assert_eq!(
                    serde_json::to_value(&index.files[&local_index_key(&b)].upload_context_receipt)
                        .unwrap()["context_fingerprint"],
                    "changed"
                );
            }
        }
    }

    /// [regress] Compressed byte length never refuses an archive before decoder admission.
    #[test]
    fn archive_over_the_former_file_limit_reaches_opened_identity() {
        let fixture =
            ArchiveFixture::new(&zstd::stream::encode_all(&synthetic_rollout()[..], 1).unwrap());
        let bytes = former_file_cap(SnapshotSource::Codex) + 1;
        File::options()
            .write(true)
            .open(&fixture.0)
            .unwrap()
            .set_len(bytes)
            .unwrap();
        let mut candidate = fixture.candidate();
        let (file, _) =
            open_candidate_file_stat_retained(SnapshotSource::Codex, &mut candidate, None, false)
                .expect("archive size is not decoder admission");
        assert_eq!(file.metadata().unwrap().len(), bytes);
        assert_eq!(candidate.size_bytes, bytes);
        // This exercises bounded metadata/identity admission only. Appended
        // sparse padding is not a valid archive and is not sent to the decoder.
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
        downgrade_member(&root, owner, false);
        let (_, native) = codex_file_join::tests::scan(&root, ScanIndex::default(), 10);
        assert_eq!(native.snapshots.len(), 1);
        let out = std::env::var_os("OTTTO_ZST_DOWNGRADE_FIXTURE_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| root.join("out"));
        fs::create_dir_all(&out).unwrap();
        let index = archive_transitions::carried_downgrade_index(&out);
        let control = serde_json::to_value(&index).unwrap();
        let mut branch = control.clone();
        branch["archives"] = json!({
            "synthetic-old-held": {
                "context": "synthetic-context", "owner": "synthetic-owner",
                "stamp": null, "disposition": {"Held": {
                    "cause": "CompressedAdmissionRefused", "quiet": false
                }}, "work": {"attempts": 1, "header_attempts": 1, "retry_after": 0}
            },
            "synthetic-old-acquired": {
                "context": "synthetic-context", "owner": "synthetic-owner",
                "stamp": null, "disposition": "Acquired", "work": null
            }
        });
        branch["archive_deferred_alarm_count"] = json!(1);
        fs::write(
            out.join("branch.json"),
            serde_json::to_vec(&branch).unwrap(),
        )
        .unwrap();
        fs::write(
            out.join("as-today.json"),
            serde_json::to_vec(&control).unwrap(),
        )
        .unwrap();
        let singleton = downgrade_member(&out.join("activation"), owner, true);
        let mut activation = downgrade_accepted(&singleton, &native.snapshots[0]);
        downgrade_seed(&mut activation, &singleton);
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
            assert!(matches!(origin, LoadOrigin::Loaded));
            assert_eq!(index.files.len(), 2);
            assert_eq!(
                index.file_snapshot_fingerprints,
                expected.file_snapshot_fingerprints
            );
            assert_eq!(
                index.accepted_snapshot_fingerprints,
                expected.accepted_snapshot_fingerprints
            );
            assert!(serde_json::to_value(&index)
                .unwrap()
                .get("archives")
                .is_none());
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
                None,
                &[],
                false,
            );
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
        #[cfg(target_os = "macos")]
        assert_eq!(std::mem::size_of::<ScanIndexEntry>(), 560);
    }
    /// [money] Empty is terminal only without usage evidence; an empty output
    /// with recognized usage remains owed instead of becoming a zero total.
    #[test]
    fn archive_empty_requires_zero_usage_evidence() {
        let _lock = DECODER_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for evidence in [false, true] {
            let data = if evidence {
                // Usage cannot acquire a valid time; this is real recognized
                // evidence, not a manually emptied successful parse.
                String::from_utf8(synthetic_rollout())
                    .unwrap()
                    .replace("2026-10-07T10:00:00Z", "not-a-time")
                    .into_bytes()
            } else {
                b"{\"type\":\"session_meta\",\"payload\":{\"id\":\"compressed-fixture\"}}\n"
                    .to_vec()
            };
            let f = ArchiveFixture::new(&zstd::stream::encode_all(&data[..], 1).unwrap());
            let mut file = File::open(&f.0).unwrap();
            let expected = opened_object_identity(SnapshotSource::Codex, &mut file).unwrap();
            let input = OpenedInput::compressed(file, u64::MAX, compressed_input_credit().unwrap())
                .unwrap();
            let mut parser = codex_parser(input, &f.0);
            while !parser.step().unwrap() {}
            let parsed = parser
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
            assert!(parsed.snapshots.is_empty());
            assert_eq!(parsed.zero_snapshot_usage_evidence, evidence);
            assert_eq!(parsed.complete(), !evidence);
            let (index, scan, _) = run_archive(
                &f,
                ScanIndex::default(),
                Arc::new(sampled_scan::SharedCache::default()),
            );
            assert!(scan.snapshots.is_empty());
            assert_eq!(
                index.confirmed_empty_files.contains(&local_index_key(&f.0)),
                !evidence
            );
            assert!(index.accepted_snapshot_fingerprints.is_empty());
            assert_eq!(scan.zero_snapshot_usage_evidence_count > 0, evidence);
        }
    }
    mod archive_transitions {
        use super::*;
        include!("codex_archive_transition_tests.rs");
    }
}
