//! Bounded `.jsonl.zst` rollout input behind the one opened-object parser seam.
//! Encoding never grants ownership or acceptance authority.
use crate::local_resource_diagnostics::{codex_zst_refused, CodexZstCause};
use std::fs::File;
use std::io::{self, BufRead, BufReader, Read};
use std::mem::size_of;
use std::path::Path;
mod decoder_allocation;
use decoder_allocation::Context as DecoderContext;

/// One predicate for a candidate's encoding or the already-opened input kind.
/// A suffix is only a refusal signal, never ownership or decode authority.
pub(in crate::snapshots) fn is_compressed_codex_rollout(
    path: Option<&Path>,
    input: Option<&OpenedInput>,
) -> bool {
    path.and_then(Path::file_name)
        .is_some_and(|name| name.as_encoded_bytes().ends_with(b".jsonl.zst"))
        || input.is_some_and(OpenedInput::is_compressed)
}

pub(in crate::snapshots) fn refuse_compressed_codex(
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

// Darwin's large-block cache can return up to 2x a request. A macOS CI run
// refused at 16,285,728 charged bytes. Double zstd 1.5.7's measured requested
// peak of 8,894,480 bytes at WindowLogMax(23), add 10%, and round up to 64 KiB
// for a credit of 19,595,264 bytes.
// Paid inside unchanged STATE_BYTES; admission preserves the primary Tail floor.
#[cfg(target_os = "macos")]
const COMPRESSED_INPUT_CREDIT: usize = (2 * 8_894_480 * 11_usize)
    .div_ceil(10)
    .next_multiple_of(64 * 1024);
// For other platforms, the measured requested peak was 8,894,448 bytes.
// Add 10% and round up to 64 KiB.
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
pub(in crate::snapshots) fn compressed_input_credit() -> io::Result<usize> {
    decoder_reservation()?
        .checked_add(BUFFER_BYTES)
        .and_then(|n| n.checked_add(size_of::<BufReader<BoundedDecoder<File>>>()))
        .ok_or_else(|| invalid("compressed rollout credit overflow"))
}

/// Streaming decoder with sticky failure and an explicit decoded-byte budget.
/// EOF is successful only after a complete frame (including checksum). Supports
/// concatenated frames; a truncated last frame is never a successful prefix.
pub(in crate::snapshots) struct BoundedDecoder<R: Read> {
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
    /// Set by `OpenedInput::header_only`: an inventory header read.
    header: bool,
}

impl<R: Read> BoundedDecoder<R> {
    fn new(input: R, decoded_limit: u64) -> io::Result<Self> {
        #[cfg(test)]
        crate::snapshots::codex_zst_refusal_tests::decoder_constructed();
        let reserved = decoder_reservation()?;
        let mut context =
            DecoderContext::new(reserved.saturating_sub(BUFFER_BYTES)).ok_or_else(|| {
                io::Error::new(io::ErrorKind::WouldBlock, CodexZstCause::AdmissionRefused)
            })?;
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
            header: false,
        })
    }

    fn retained_bytes(&self) -> usize {
        self.input.capacity().saturating_add(self.context.sizeof())
    }

    #[cfg(test)]
    pub(in crate::snapshots) fn decoded_bytes(&self) -> u64 {
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
        use crate::local_resource_diagnostics as diagnostics;
        let counts = [
            self.physical_limit - self.input.get_ref().limit(),
            self.compressed_bytes,
            self.decoded_bytes,
            self.cpu_micros,
            self.context.peak_bytes() as u64,
            self.context.allocation_refusals(),
        ];
        // Header reads fold into one per-walk row; every body decode keeps its own.
        if self.header {
            diagnostics::codex_zst_input_header(counts);
            return;
        }
        let counts: std::collections::BTreeMap<&str, u64> = diagnostics::CODEX_ZST_INPUT_KEYS
            .into_iter()
            .zip(counts)
            .collect();
        diagnostics::traversal_point("codex_zst_input", "codex", &counts);
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
pub(in crate::snapshots) enum OpenedInput {
    Plain(BufReader<File>),
    Compressed(
        Box<BufReader<BoundedDecoder<File>>>,
        Option<crate::snapshots::sampled_scan::codex_cursor::DecoderOwner>,
    ),
}

impl OpenedInput {
    /// The ordinary input encoding, after the caller securely opens the object.
    /// Refused decoder funding uses the caller's ordinary requeue/yield path.
    pub(in crate::snapshots) fn encoded(
        file: File,
        path: &Path,
        cache: Option<&std::sync::Arc<crate::snapshots::sampled_scan::SharedCache>>,
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

    pub(in crate::snapshots) fn plain(file: File) -> Self {
        Self::Plain(BufReader::new(file))
    }

    /// `credit` must cover `compressed_input_credit()`. `decoded_limit` is the
    /// sticky per-file cap on decoded bytes; reaching it with more content,
    /// truncation, corruption or an oversized window fails the read.
    pub(in crate::snapshots) fn compressed(
        file: File,
        decoded_limit: u64,
        credit: usize,
    ) -> io::Result<Self> {
        if credit < compressed_input_credit()? {
            return Err(invalid("compressed rollout input was not prepaid"));
        }
        let decoder = BoundedDecoder::new(file, decoded_limit)?;
        let decoded = BufReader::with_capacity(BUFFER_BYTES, decoder);
        Ok(Self::Compressed(Box::new(decoded), None))
    }

    pub(in crate::snapshots) fn funded(
        file: File,
        cache: &std::sync::Arc<crate::snapshots::sampled_scan::SharedCache>,
    ) -> io::Result<Option<Self>> {
        let credit = compressed_input_credit()?;
        let Some(owner) =
            crate::snapshots::sampled_scan::codex_cursor::DecoderOwner::acquire(cache, credit)
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
    pub(in crate::snapshots) fn header_only(mut self) -> Self {
        if let Self::Compressed(reader, _) = &mut self {
            let decoder = reader.get_mut();
            decoder.remaining = crate::snapshots::codex_file_join::MAX_HEADER_BYTES as u64;
            decoder.physical_limit = 2 * crate::snapshots::codex_file_join::MAX_HEADER_BYTES as u64;
            decoder.input.get_mut().set_limit(decoder.physical_limit);
            decoder.header = true;
        }
        self
    }
    pub(in crate::snapshots) fn close(self) {
        if let Self::Compressed(reader, owner) = self {
            drop(reader);
            if let Some(owner) = owner {
                owner.release();
            }
        }
    }
    pub(in crate::snapshots) fn is_compressed(&self) -> bool {
        matches!(self, Self::Compressed(..))
    }

    /// The original opened File: metadata and identity revalidation use it, so
    /// no path is ever reopened. Never seek a compressed File before its
    /// decoder reaches EOF.
    pub(in crate::snapshots) fn get_ref(&self) -> &File {
        match self {
            Self::Plain(reader) => reader.get_ref(),
            Self::Compressed(reader, _) => reader.get_ref().input.get_ref().get_ref(),
        }
    }

    pub(in crate::snapshots) fn get_mut(&mut self) -> &mut File {
        match self {
            Self::Plain(reader) => reader.get_mut(),
            Self::Compressed(reader, _) => reader.get_mut().input.get_mut().get_mut(),
        }
    }

    pub(in crate::snapshots) fn buffer(&self) -> &[u8] {
        match self {
            Self::Plain(reader) => reader.buffer(),
            Self::Compressed(reader, _) => reader.buffer(),
        }
    }

    /// Funded decoder memory is charged by its outstanding SharedCache claim.
    /// Unfunded synthetic input charges its box, buffer and full decoder credit;
    /// plain input charges only its buffer.
    pub(in crate::snapshots) fn capacity(&self) -> usize {
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
#[rustfmt::skip]
pub(in crate::snapshots) mod tests;
