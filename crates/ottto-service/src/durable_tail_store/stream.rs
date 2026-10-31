//! Native write-ahead I/O. Owned operations cross the Stores mutex boundary;
//! only compact candidate registration and metadata checks run under that lock.
//! Flushed writes and rename survive process death. This is not a power-loss
//! durability promise: directory fsync is bounded to the pass boundary.
use super::*;
use crate::durable_tail_codec as codec;
use std::io::BufWriter;
use std::time::{Duration, SystemTime};

const STREAM_BYTES: usize = 64 * 1024;
const PAUSE_RECHECK: Duration = Duration::from_secs(60);

pub(super) struct ResourcePause {
    pub(super) since: SystemTime,
    next_probe: SystemTime,
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct RecordIdentity {
    binding: Binding,
    certificate: DurableCertificate,
    format: u16,
    allowlist: Digest32,
    acquisition: AcquisitionFields,
    generation: u64,
    encoded_len: u64,
    trailer: Digest32,
}
impl RecordIdentity {
    pub(crate) fn binding(&self) -> &Binding {
        &self.binding
    }
    pub(crate) fn certificate(&self) -> &DurableCertificate {
        &self.certificate
    }
    pub(crate) fn format(&self) -> u16 {
        self.format
    }
    pub(crate) fn allowlist(&self) -> &Digest32 {
        &self.allowlist
    }
    pub(crate) fn acquired_revision(&self) -> u64 {
        self.acquisition.acquired_revision
    }
    pub(crate) fn protocol(&self) -> crate::snapshots::AcquisitionProtocol {
        self.acquisition.protocol
    }
    pub(crate) fn generation(&self) -> u64 {
        self.generation
    }
    pub(crate) fn sealed_offset(&self) -> u64 {
        self.certificate.sealed_offset
    }
    pub(crate) fn encoded_len(&self) -> u64 {
        self.encoded_len
    }
    pub(crate) fn trailer(&self) -> &Digest32 {
        &self.trailer
    }
    fn wire(&self) -> WireRecordIdentity {
        WireRecordIdentity {
            key: self.binding.key,
            allowlist: self.allowlist,
            format: self.format,
            generation: self.generation,
            encoded_len: self.encoded_len,
            trailer: self.trailer,
        }
    }
}

#[derive(PartialEq, Eq)]
pub(crate) struct ReceiptProof {
    identity: Box<RecordIdentity>,
    stamp: Stamp,
    content: Digest32,
}
impl ReceiptProof {
    pub(crate) fn identity(&self) -> &RecordIdentity {
        &self.identity
    }
    pub(crate) fn generation(&self) -> u64 {
        self.identity.generation
    }
}

impl std::fmt::Debug for RecordIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecordIdentity")
            .field("format", &self.format)
            .field("encoded_len", &self.encoded_len)
            .finish()
    }
}
impl std::fmt::Debug for ReceiptProof {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("ReceiptProof").field(&self.identity).finish()
    }
}

pub(crate) struct PreparedHeader {
    pub(crate) binding: Binding,
    pub(crate) certificate: DurableCertificate,
    pub(crate) format: u16,
    pub(crate) allowlist: Digest32,
    pub(crate) acquisition: AcquisitionFields,
    pub(crate) generation: u64,
    pub(crate) body_len: usize,
}
impl PreparedHeader {
    fn parts(&self) -> HeaderParts<'_> {
        HeaderParts {
            binding: &self.binding,
            certificate: &self.certificate,
            allowlist: &self.allowlist,
            acquisition: Some(self.acquisition),
            format: self.format,
            generation: self.generation,
            body_len: self.body_len,
        }
    }
}

struct Attempt {
    dir: PathBuf,
    path: PathBuf,
    key: Digest32,
    prior: Option<Stamp>,
    prior_known: bool,
    cleanup: Arc<TempCleanupCounts>,
    temp: Option<OwnedTemp>,
    identity: Option<RecordIdentity>,
    content: Digest32,
}
impl Attempt {
    fn failure(self, stage: &'static str, error: io::Error) -> PrepareStoreFailure {
        PrepareStoreFailure {
            attempt: Box::new(self),
            stage,
            error,
            protected: None,
        }
    }
    fn writer(&self) -> io::Result<()> {
        crate::locked_state_dir::held_for(&self.dir)
            .filter(|writer| self.dir.starts_with(writer.state_dir()))
            .map(|_| ())
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "native writer no longer held",
                )
            })
    }
}

pub(crate) struct PrepareStoreFailure {
    attempt: Box<Attempt>,
    stage: &'static str,
    error: io::Error,
    protected: Option<Refusal>,
}
impl PrepareStoreFailure {
    pub(crate) fn stage(&self) -> &'static str {
        self.stage
    }
    pub(crate) fn identity(&self) -> Option<&RecordIdentity> {
        self.attempt.identity.as_ref()
    }
    pub(crate) fn protected(&self) -> Option<Refusal> {
        self.protected
    }
    pub(crate) fn is_enospc(&self) -> bool {
        no_space(&self.error)
    }
    pub(crate) fn discard(&mut self) -> io::Result<()> {
        self.attempt.writer()?;
        if let Some(temp) = self.attempt.temp.as_mut() {
            temp.discard()?;
        }
        self.attempt.temp = None;
        Ok(())
    }
}

pub(crate) struct StreamPreparation {
    attempt: Attempt,
    header: PreparedHeader,
}
pub(crate) struct PreparedRecord {
    attempt: Box<Attempt>,
}
impl PreparedRecord {
    pub(crate) fn identity(&self) -> &RecordIdentity {
        self.attempt.identity.as_ref().expect("encoded identity")
    }
    pub(crate) fn discard(mut self) -> io::Result<()> {
        self.attempt.writer()?;
        if let Some(temp) = self.attempt.temp.as_mut() {
            temp.discard()?;
        }
        Ok(())
    }
}
pub(crate) struct PendingCommit {
    attempt: Attempt,
}
pub(crate) struct StreamCommit {
    attempt: Attempt,
    stamp: Stamp,
}

/// One fixed staging buffer; neither the reduction nor envelope is materialized.
struct BodySink<'a> {
    output: &'a mut BufWriter<OwnedTemp>,
    wire: &'a mut Sha256,
    content: &'a mut Sha256,
    remaining: usize,
    error: Option<i32>,
}
impl Write for BodySink<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.remaining {
            return Err(io::Error::other("body exceeds measured size"));
        }
        let n = self
            .output
            .write(bytes)
            .inspect_err(|error| self.error = error.raw_os_error())?;
        self.wire.update(&bytes[..n]);
        self.content.update(&bytes[..n]);
        self.remaining -= n;
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.output
            .flush()
            .inspect_err(|error| self.error = error.raw_os_error())
    }
}
impl StreamPreparation {
    pub(crate) fn write(
        mut self,
        body: impl FnOnce(&mut dyn Write) -> Result<usize, codec::Refuse>,
    ) -> Result<PreparedRecord, PrepareStoreFailure> {
        let result = (|| {
            self.attempt.writer()?;
            ensure_private_dir(&self.attempt.dir)?;
            let metadata = inspect_path(&self.attempt.dir)?;
            if !metadata.is_dir() || metadata.uid() != our_uid() || metadata.mode() & 0o777 != 0o700
            {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "private native store",
                ));
            }
            let temp = OwnedTemp::prepare(
                &self.attempt.dir,
                &self.attempt.path,
                self.attempt.cleanup.clone(),
            )?;
            let mut output = BufWriter::with_capacity(STREAM_BYTES, temp);
            let mut header = [0; HEADER_V3_BYTES];
            let size = header_len(
                self.header.format,
                self.header.binding.source,
                &self.header.allowlist,
            )
            .map_err(|_| io::Error::other("unadmitted representation"))?;
            let mut destination = &mut header[..size];
            write_header(&mut destination, self.header.parts())?;
            let mut wire = Sha256::new();
            wire.update(&header[..size]);
            let mut normalized = header;
            normalized[171..179].fill(0);
            let mut content = Sha256::new();
            let domain = b"ottto-dt-content:v2";
            content.update((domain.len() as u64).to_le_bytes());
            content.update(domain);
            content.update((size as u64).to_le_bytes());
            content.update(&normalized[..size]);
            content.update((self.header.body_len as u64).to_le_bytes());
            let written = output.write_all(&header[..size]).and_then(|_| {
                let mut sink = BodySink {
                    output: &mut output,
                    wire: &mut wire,
                    content: &mut content,
                    remaining: self.header.body_len,
                    error: None,
                };
                let encoded = body(&mut sink);
                match encoded {
                    Ok(n) if n == self.header.body_len && sink.remaining == 0 => Ok(()),
                    _ => Err(sink
                        .error
                        .map(io::Error::from_raw_os_error)
                        .unwrap_or_else(|| io::Error::other("stream body refused"))),
                }
            });
            let trailer: Digest32 = wire.finalize().into();
            let result = written
                .and_then(|_| output.write_all(&trailer))
                .and_then(|_| output.flush());
            // into_parts never flushes again: a failed write retains exact temp ownership.
            let (temp, _) = output.into_parts();
            self.attempt.temp = Some(temp);
            result?;
            self.attempt.content = content.finalize().into();
            self.attempt.identity = Some(RecordIdentity {
                binding: self.header.binding.clone(),
                certificate: self.header.certificate.clone(),
                format: self.header.format,
                allowlist: self.header.allowlist,
                acquisition: self.header.acquisition,
                generation: self.header.generation,
                encoded_len: (size + self.header.body_len + TRAILER_BYTES) as u64,
                trailer,
            });
            Ok(())
        })();
        match result {
            Ok(()) => Ok(PreparedRecord {
                attempt: Box::new(self.attempt),
            }),
            Err(error) => Err(self.attempt.failure("stream_write", error)),
        }
    }
}
impl PendingCommit {
    pub(crate) fn commit(mut self) -> Result<StreamCommit, PrepareStoreFailure> {
        let result = (|| {
            self.attempt.writer()?;
            let temp = self
                .attempt
                .temp
                .as_mut()
                .ok_or_else(|| io::Error::other("missing stage"))?;
            let stamp = temp.commit(&self.attempt.path, self.attempt.prior)?;
            if stamp_at(&self.attempt.path)? != Some(stamp) {
                return Err(io::Error::other("renamed survivor changed"));
            }
            Ok(stamp)
        })();
        match result {
            Ok(stamp) => Ok(StreamCommit {
                attempt: self.attempt,
                stamp,
            }),
            Err(error) => Err(self.attempt.failure("stream_rename", error)),
        }
    }
}

pub(crate) struct ResolvePreparation {
    failure: PrepareStoreFailure,
}
pub(crate) struct StreamResolution {
    failure: PrepareStoreFailure,
    result: Resolution,
    read: u64,
}
enum Resolution {
    Receipted(Stamp),
    Absent,
    Survived,
    Protected(Refusal),
}
pub(crate) enum FailureDisposition {
    Receipted(ReceiptProof),
    PublishDegraded {
        strict_rebind: bool,
        cause: &'static str,
    },
    Hold {
        cause: &'static str,
    },
    Protected(Refusal),
}
impl ResolvePreparation {
    pub(crate) fn resolve(mut self) -> StreamResolution {
        let mut read = 0;
        let result = (|| {
            self.failure.attempt.writer()?;
            if let Some(protected) = self.failure.protected {
                return Ok(Resolution::Protected(protected));
            }
            // Both paths are tried explicitly. OwnedTemp::Drop is only fallback cleanup.
            let _ = self.failure.discard();
            let attempt = &self.failure.attempt;
            let current = stamp_at(&attempt.path)?;
            let Some(stamp) = current else {
                return Ok(Resolution::Absent);
            };
            if let Some(identity) = attempt.identity.as_ref() {
                if let Some(stamp) = verify_stream_candidate(&attempt.path, identity, &mut read)? {
                    return Ok(Resolution::Receipted(stamp));
                }
            }
            if !attempt.prior_known || Some(stamp) != attempt.prior {
                return Ok(Resolution::Protected(Refusal::Unbindable));
            }
            // ENOSPC never authorizes destruction of a valid predecessor.
            if self.failure.is_enospc() {
                return Ok(Resolution::Survived);
            }
            #[cfg(test)]
            test_hooks::write_failure("native_cleanup")?;
            if stamp_at(&attempt.path)? != Some(stamp) {
                return Ok(Resolution::Protected(Refusal::Unbindable));
            }
            remove_if_present(&attempt.path)?;
            sync_dir(&attempt.dir)?;
            if stamp_at(&attempt.path)?.is_none() {
                Ok(Resolution::Absent)
            } else {
                Err(io::Error::other("native cleanup not absent"))
            }
        })();
        // A failed explicit cleanup is observable, but Drop must never perform
        // disk I/O later when this resolution is delivered under Stores.
        if let Some(mut temp) = self.failure.attempt.temp.take() {
            if temp.file.is_some() {
                temp.cleanup.fallback.fetch_add(1, Ordering::Relaxed);
                let _ = temp.discard();
                temp.file.take();
            }
        }
        StreamResolution {
            failure: self.failure,
            result: result.unwrap_or(Resolution::Survived),
            read,
        }
    }
}

// Recovery reads one bounded buffer and validates the original trailer, length,
// held FD and exact current path stamp; it never reencodes a decoded envelope.
fn verify_stream_candidate(
    path: &Path,
    expected: &RecordIdentity,
    read: &mut u64,
) -> io::Result<Option<Stamp>> {
    let before = stamp_at(path)?;
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != our_uid()
        || metadata.mode() & 0o777 != 0o600
        || Some(Stamp::of(&metadata)) != before
        || metadata.len() != expected.encoded_len
    {
        return Ok(None);
    }
    let mut remaining = expected.encoded_len - TRAILER_BYTES as u64;
    let mut hash = Sha256::new();
    let mut buffer = [0; STREAM_BYTES];
    while remaining > 0 {
        let n = (remaining as usize).min(buffer.len());
        file.read_exact(&mut buffer[..n])?;
        *read += n as u64;
        hash.update(&buffer[..n]);
        remaining -= n as u64;
    }
    let mut trailer = [0; TRAILER_BYTES];
    file.read_exact(&mut trailer)?;
    *read += TRAILER_BYTES as u64;
    let digest: Digest32 = hash.finalize().into();
    Ok((digest == expected.trailer
        && trailer == expected.trailer
        && Some(Stamp::of(&file.metadata()?)) == before
        && stamp_at(path)? == before)
        .then_some(before)
        .flatten())
}

pub(crate) struct PassFlush {
    dir: PathBuf,
    dirty: Arc<AtomicU64>,
    generation: u64,
}
impl PassFlush {
    pub(crate) fn flush(self) -> io::Result<()> {
        if crate::locked_state_dir::held_for(&self.dir).is_none() {
            return Err(io::Error::other("flush writer lost"));
        }
        sync_dir(&self.dir)?;
        sync_dir(
            self.dir
                .parent()
                .ok_or_else(|| io::Error::other("store parent"))?,
        )?;
        let _ =
            self.dirty
                .compare_exchange(self.generation, 0, Ordering::AcqRel, Ordering::Relaxed);
        Ok(())
    }
}

impl DurableTailStore {
    /// Re-arm a fully verified native predecessor using only its exact saved
    /// stamp and bounded header. A memo without a verified content digest is
    /// not authority. Never enumerate or re-read its body on a warm write.
    pub(crate) fn authorize_native(&mut self, binding: &Binding, revision: u64) -> bool {
        let Some((Some(_), stamp, _)) = self.durable.get(&binding.key).copied() else {
            return false;
        };
        let path = self.record_path(&binding.key);
        let checked = (|| -> io::Result<bool> {
            if stamp_at(&path)? != Some(stamp) {
                return Ok(false);
            }
            let mut file = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
                .open(&path)?;
            let metadata = file.metadata()?;
            if !metadata.is_file()
                || metadata.uid() != our_uid()
                || metadata.mode() & 0o777 != 0o600
                || Stamp::of(&metadata) != stamp
            {
                return Ok(false);
            }
            let mut bytes = [0; HEADER_V3_BYTES];
            file.read_exact(&mut bytes)?;
            self.counters.guard_header_bytes += HEADER_V3_BYTES as u64;
            let header = decode_header(&bytes, &binding.key, binding.source)
                .map_err(|_| io::Error::other("native predecessor header"))?;
            Ok(header.format == FORMAT_V3
                && header.record.binding == *binding
                && header
                    .record
                    .acquisition
                    .is_some_and(|acquisition| acquisition.acquired_revision == revision)
                && metadata.len() == (HEADER_V3_BYTES + header.body_len + TRAILER_BYTES) as u64
                && Stamp::of(&file.metadata()?) == stamp
                && stamp_at(&path)? == Some(stamp))
        })()
        .unwrap_or(false);
        if checked {
            if let Some((_, _, allowed)) = self.durable.get_mut(&binding.key) {
                *allowed = true;
            }
        }
        checked
    }

    pub(crate) fn prepare_stream(
        &mut self,
        writer: &dyn SingleWriter,
        header: PreparedHeader,
    ) -> Result<StreamPreparation, PrepareStoreFailure> {
        let key = header.binding.key;
        let mut attempt = Attempt {
            dir: self.dir.clone(),
            path: self.record_path(&key),
            key,
            prior: None,
            prior_known: false,
            cleanup: self.cleanup.clone(),
            temp: None,
            identity: None,
            content: [0; 32],
        };
        let mut protected = None;
        let mut budget_refused = false;
        let result = (|| {
            self.check_writer(writer)?;
            if self.disabled.is_some() {
                return Err(io::Error::other("store disabled"));
            }
            if !self.check_resources(writer, 0)? {
                return Err(io::Error::from_raw_os_error(libc::ENOSPC));
            }
            let size = header_len(header.format, header.binding.source, &header.allowlist)
                .map_err(|reason| {
                    protected = Some(reason);
                    io::Error::other("unadmitted representation")
                })?;
            if header.binding.source != self.source
                || header.format != FORMAT_V3
                || header.binding.entry != [0; 32]
                || size
                    .checked_add(header.body_len)
                    .and_then(|n| n.checked_add(TRAILER_BYTES))
                    .map_or(true, |n| n > RECORD_BYTES)
            {
                return Err(io::Error::other("invalid native header"));
            }
            let encoded_len = size + header.body_len + TRAILER_BYTES;
            if self.stream_records >= MAX_BATCH
                || self
                    .stream_bytes
                    .checked_add(encoded_len)
                    .map_or(true, |bytes| bytes > WRITE_PASS_BYTES)
            {
                self.counters.records_deferred += 1;
                self.counters.budget_refused += 1;
                budget_refused = true;
                return Err(io::Error::other("native pass allowance exhausted"));
            }
            if self.pending.contains_key(&key) {
                protected = Some(Refusal::ReceiptPending);
                return Err(io::Error::other("same key receipt pending"));
            }
            if self.pending.len() >= MAX_BATCH {
                self.counters.budget_refused += 1;
                budget_refused = true;
                return Err(io::Error::other("pending capacity"));
            }
            attempt.prior = stamp_at(&attempt.path)?;
            if let Some(prior) = attempt.prior {
                // Saved proof owns verification; header dispatch still protects unknown U.
                let mut file = OpenOptions::new()
                    .read(true)
                    .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
                    .open(&attempt.path)?;
                let metadata = file.metadata()?;
                if !metadata.is_file()
                    || metadata.uid() != our_uid()
                    || metadata.mode() & 0o777 != 0o600
                    || Stamp::of(&metadata) != prior
                {
                    protected = Some(Refusal::Unbindable);
                    return Err(io::Error::other("predecessor metadata"));
                }
                let mut bytes = [0; HEADER_V3_BYTES];
                file.read_exact(&mut bytes[..DISPATCH_BYTES])?;
                let (_, _, _, size) = dispatch(&bytes[..DISPATCH_BYTES]).map_err(|reason| {
                    protected = Some(reason);
                    io::Error::other("protected predecessor")
                })?;
                file.read_exact(&mut bytes[DISPATCH_BYTES..size])?;
                let old = decode_header(&bytes[..size], &key, self.source).map_err(|reason| {
                    protected = Some(reason);
                    io::Error::other("protected predecessor")
                })?;
                self.counters.guard_header_bytes += size as u64;
                if retired_pin(self.source, old.format, &old.record.allowlist) {
                    // THE classifier verifies the opaque predecessor and funds the
                    // ordinary exact-stamp overwrite permission; never decode it.
                    match self.classify(&key, "overwrite", Some(writer)) {
                        Ok(_) => {}
                        Err(Refusal::Corrupt)
                            if old.record.binding.context == header.binding.context
                                && self.rebuilt.get(&key) == Some(&Rebuild::Started)
                                && self.durable.get(&key).is_some_and(|(content, stamp, _)| {
                                    content.is_none() && *stamp == prior
                                }) =>
                        {
                            self.memoize(key, (None, prior, true));
                        }
                        Err(reason) => {
                            protected = Some(reason);
                            return Err(io::Error::other("unverified retired predecessor"));
                        }
                    }
                }
                if stamp_at(&attempt.path)? != Some(prior) || !self.authorized(&key, old.format) {
                    protected = Some(Refusal::Unbindable);
                    return Err(io::Error::other("unproved predecessor"));
                }
            }
            attempt.prior_known = true;
            self.stream_records += 1;
            self.stream_bytes += encoded_len;
            Ok(())
        })();
        match result {
            Ok(()) => Ok(StreamPreparation { attempt, header }),
            Err(error) => {
                let mut failure = attempt.failure(
                    if budget_refused {
                        "stream_budget"
                    } else {
                        "stream_prepare"
                    },
                    error,
                );
                failure.protected = protected;
                Err(failure)
            }
        }
    }
    pub(crate) fn commit_stream(
        &mut self,
        writer: &dyn SingleWriter,
        prepared: PreparedRecord,
    ) -> Result<PendingCommit, PrepareStoreFailure> {
        let attempt = *prepared.attempt;
        let result = (|| {
            self.check_writer(writer)?;
            if self.disabled.is_some()
                || self.pending.len() >= MAX_BATCH
                || self.pending.contains_key(&attempt.key)
            {
                return Err(io::Error::other("native registration unavailable"));
            }
            let identity = attempt.identity.as_ref().expect("prepared identity");
            if stamp_at(&attempt.path)? != attempt.prior {
                return Err(io::Error::other("predecessor changed before registration"));
            }
            self.pending.insert(
                attempt.key,
                PendingWrite {
                    prior: attempt.prior,
                    candidate: identity.wire(),
                    content: attempt.content,
                    completed: None,
                    failures: 0,
                },
            );
            Ok(())
        })();
        match result {
            Ok(()) => Ok(PendingCommit { attempt }),
            Err(error) => {
                let mut failure = attempt.failure("stream_register", error);
                failure.protected = Some(Refusal::ReceiptPending);
                Err(failure)
            }
        }
    }
    pub(crate) fn finish_stream(
        &mut self,
        committed: StreamCommit,
    ) -> Result<ReceiptProof, PrepareStoreFailure> {
        let StreamCommit { attempt, stamp } = committed;
        let result = (|| {
            let identity = attempt.identity.as_ref().expect("committed identity");
            if stamp_at(&attempt.path)? != Some(stamp)
                || !self.pending.get(&attempt.key).is_some_and(|pending| {
                    pending.candidate == identity.wire() && pending.content == attempt.content
                })
            {
                return Err(io::Error::other("native completion mismatch"));
            }
            self.retain_receipt(WireReceiptProof {
                identity: identity.wire(),
                stamp,
                content: attempt.content,
            })?;
            let batch = BatchReceipt {
                written: 1,
                bytes_written: identity.encoded_len,
                completed: vec![WireReceiptProof {
                    identity: identity.wire(),
                    stamp,
                    content: attempt.content,
                }],
                ..Default::default()
            };
            self.finish_batch(batch)?;
            self.stream_dirty.fetch_add(1, Ordering::Relaxed);
            Ok(())
        })();
        match result {
            Ok(()) => Ok(ReceiptProof {
                identity: Box::new(attempt.identity.expect("receipt identity")),
                stamp,
                content: attempt.content,
            }),
            Err(error) => Err(attempt.failure("stream_finish", error)),
        }
    }
    pub(crate) fn resolve_failed_stream(
        &mut self,
        writer: &dyn SingleWriter,
        mut failure: PrepareStoreFailure,
    ) -> ResolvePreparation {
        if self.check_writer(writer).is_err() || failure.attempt.dir != self.dir {
            failure.protected = Some(Refusal::Unbindable);
        }
        self.counters.store_fault_reason = Some(if failure.is_enospc() {
            "enospc"
        } else {
            failure.stage
        });
        if failure.is_enospc() {
            self.pause_resources();
        }
        ResolvePreparation { failure }
    }
    pub(crate) fn finish_resolution(&mut self, resolution: StreamResolution) -> FailureDisposition {
        let StreamResolution {
            failure,
            result,
            read,
        } = resolution;
        self.counters.guard_header_bytes += read;
        if let Resolution::Receipted(stamp) = result {
            return match self.finish_stream(StreamCommit {
                attempt: *failure.attempt,
                stamp,
            }) {
                Ok(receipt) => FailureDisposition::Receipted(receipt),
                Err(failure) => {
                    self.pending.remove(&failure.attempt.key);
                    FailureDisposition::Hold {
                        cause: "receipt_mismatch",
                    }
                }
            };
        }
        self.pending.remove(&failure.attempt.key);
        if let Resolution::Protected(reason) = result {
            return FailureDisposition::Protected(reason);
        }
        self.counters.store_faults += 1;
        if matches!(result, Resolution::Absent) {
            self.durable.remove(&failure.attempt.key);
            return FailureDisposition::PublishDegraded {
                strict_rebind: false,
                cause: failure.stage,
            };
        }
        self.counters.store_write_cleanup_failed += 1;
        if self.source == DurableSource::Codex {
            self.disable("write_cleanup_failed");
            // No pending or saved proof may claim disabled-store authority.
            self.pending.clear();
            FailureDisposition::PublishDegraded {
                strict_rebind: true,
                cause: "write_cleanup_failed",
            }
        } else {
            FailureDisposition::Hold {
                cause: "stale_survivor",
            }
        }
    }
    /// Only a registered exact native candidate can produce this proof.
    /// None is not absence and never discharges a candidate-less owed mark.
    pub(crate) fn reconcile_stream(
        &mut self,
        writer: &dyn SingleWriter,
        key: &Digest32,
    ) -> Result<Option<ReceiptProof>, Refusal> {
        self.check_writer(writer).map_err(|_| Refusal::Unbindable)?;
        if self.disabled.is_some() {
            return Ok(None);
        }
        let Some(pending) = self.pending.get(key).copied() else {
            return Ok(None);
        };
        if pending.candidate.format != FORMAT_V3 {
            return Err(Refusal::ReceiptPending);
        }
        let path = self.record_path(key);
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(&path)
            .map_err(|_| Refusal::ReceiptPending)?;
        let header_stamp = Stamp::of(&file.metadata().map_err(|_| Refusal::ReceiptPending)?);
        let mut bytes = [0; HEADER_V3_BYTES];
        file.read_exact(&mut bytes)
            .map_err(|_| Refusal::ReceiptPending)?;
        self.counters.guard_header_bytes += HEADER_V3_BYTES as u64;
        let header = decode_header(&bytes, key, self.source)?;
        let Some(acquisition) = header.record.acquisition else {
            return Err(Refusal::ReceiptPending);
        };
        let identity = RecordIdentity {
            binding: header.record.binding,
            certificate: header.record.certificate,
            format: header.format,
            allowlist: header.record.allowlist,
            acquisition,
            generation: header.generation,
            encoded_len: (HEADER_V3_BYTES + header.body_len + TRAILER_BYTES) as u64,
            trailer: pending.candidate.trailer,
        };
        if identity.wire() != pending.candidate {
            return Err(Refusal::ReceiptPending);
        }
        let mut read = 0;
        let verified = verify_stream_candidate(&path, &identity, &mut read)
            .ok()
            .flatten();
        self.counters.guard_verify_bytes += read;
        let stamp = verified
            .filter(|stamp| *stamp == header_stamp)
            .ok_or(Refusal::ReceiptPending)?;
        let attempt = Attempt {
            dir: self.dir.clone(),
            path,
            key: *key,
            prior: pending.prior,
            prior_known: true,
            cleanup: self.cleanup.clone(),
            temp: None,
            identity: Some(identity),
            content: pending.content,
        };
        self.finish_stream(StreamCommit { attempt, stamp })
            .map(Some)
            .map_err(|_| Refusal::ReceiptPending)
    }
    pub(crate) fn receipt_current(&self, receipt: &ReceiptProof) -> bool {
        stamp_at(&self.record_path(&receipt.identity.binding.key))
            .ok()
            .flatten()
            == Some(receipt.stamp)
            && self
                .durable
                .get(&receipt.identity.binding.key)
                .is_some_and(|(content, stamp, _)| {
                    *content == Some(receipt.content) && *stamp == receipt.stamp
                })
    }
    pub(crate) fn replacement_receipted(
        &self,
        original: &MutationWitness,
        receipt: &ReceiptProof,
    ) -> bool {
        original.key == receipt.identity.binding.key
            && original.content != receipt.content
            && self.receipt_current(receipt)
    }
    pub(crate) fn flush_pass(
        &mut self,
        writer: &dyn SingleWriter,
    ) -> io::Result<Option<PassFlush>> {
        self.check_writer(writer)?;
        let generation = self.stream_dirty.load(Ordering::Acquire);
        if generation == 0 || self.stream_flush_taken {
            return Ok(None);
        }
        self.stream_flush_taken = true;
        // Keep dirty through failures: a later pass always gets another bounded flush.
        self.counters.native_flushes += 1;
        Ok(Some(PassFlush {
            dir: self.dir.clone(),
            dirty: self.stream_dirty.clone(),
            generation,
        }))
    }
    pub(super) fn pause_resources(&mut self) {
        if self.resource_pause.is_none() {
            let now = SystemTime::now();
            self.resource_pause = Some(ResourcePause {
                since: now,
                next_probe: now + PAUSE_RECHECK,
            });
        }
    }
    #[cfg(all(test, target_os = "macos"))]
    pub(crate) fn expire_resource_pause_for_test(&mut self) {
        if let Some(pause) = self.resource_pause.as_mut() {
            pause.next_probe = SystemTime::UNIX_EPOCH;
        }
        self.resource_checked = false;
    }
    pub(crate) fn resource_paused(&self) -> bool {
        self.resource_pause.is_some()
    }
    pub(crate) fn check_resources(
        &mut self,
        writer: &dyn SingleWriter,
        index_len: u64,
    ) -> io::Result<bool> {
        if self.check_writer(writer).is_err() || self.disabled.is_some() {
            return Ok(false);
        }
        let now = SystemTime::now();
        if let Some(pause) = self.resource_pause.as_mut() {
            if now < pause.next_probe {
                self.counters.resource_pause_skipped += 1;
                return Ok(false);
            }
            pause.next_probe = now + PAUSE_RECHECK;
        } else if self.resource_checked {
            return Ok(self.resource_granted);
        }
        self.counters.resource_pause_checks += 1;
        let dir = if self.dir.exists() {
            self.dir.as_path()
        } else {
            self.dir.parent().unwrap_or(&self.dir)
        };
        // One statvfs reserves a whole bounded pass, not one syscall per record.
        let enough = above_floor(dir, WRITE_PASS_BYTES as u64, index_len)
            .inspect_err(|_| self.counters.store_write_failed[2] += 1)?;
        self.resource_checked = true;
        self.resource_granted = enough;
        if !enough {
            if self.resource_pause.is_none() {
                self.counters.store_fault_reason = Some("resource_floor");
                self.counters.budget_refused += 1;
            }
            self.pause_resources();
            return Ok(false);
        }
        if let Some(pause) = self.resource_pause.take() {
            self.counters.resource_paused_seconds =
                self.counters.resource_paused_seconds.saturating_add(
                    now.duration_since(pause.since)
                        .map_or(0, |age| age.as_secs()),
                );
        }
        Ok(true)
    }
    pub(crate) fn note_degraded_publish(&mut self) {
        self.counters.durable_write_failed_published += 1;
    }
    pub(crate) fn note_stale_refusal(&mut self) {
        self.counters.stale_record_refused += 1;
    }
    pub(crate) fn stream_reserve_bytes(&self) -> Option<u64> {
        // Staging owns directory/canonical/temp names plus fixed identity/buffer.
        let paths = self
            .dir
            .as_os_str()
            .len()
            .checked_mul(4)?
            .checked_add(512)?;
        Some(paths.checked_add(STREAM_BYTES)?.checked_add(4096)? as u64)
    }
}

impl std::fmt::Debug for PrepareStoreFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PrepareStoreFailure")
            .field("stage", &self.stage)
            .field("error", &self.error)
            .finish_non_exhaustive()
    }
}
impl std::fmt::Display for PrepareStoreFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.stage, self.error)
    }
}
impl std::error::Error for PrepareStoreFailure {}

/// Preserve the original errno even when both write and cleanup failed.
pub(super) fn no_space(error: &io::Error) -> bool {
    matches!(error.raw_os_error(), Some(libc::ENOSPC | libc::EDQUOT))
        || error
            .get_ref()
            .and_then(|source| source.downcast_ref::<WriteCleanupFailure>())
            .is_some_and(|failure| no_space(&failure.write))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::durable_tail_store::tests::{binding, certificate, Scratch};

    fn header(scratch: &Scratch, source: DurableSource, count: u64) -> (PreparedHeader, Vec<u8>) {
        let snapshot = source.properties().snapshot;
        let body = crate::snapshots::durable_store_fixture_body(snapshot, count, count * 7);
        let path = scratch.transcript("native.jsonl", b"{}\n");
        let mut binding = binding("account", "scope", ("fp-a", None));
        binding.source = source;
        binding.entry = [0; 32];
        (
            PreparedHeader {
                binding,
                certificate: certificate(&path),
                format: FORMAT_V3,
                allowlist: source.properties().allowlist(),
                acquisition: AcquisitionFields {
                    acquired_revision: 17,
                    protocol: crate::snapshots::AcquisitionProtocol::WriteAhead,
                },
                generation: 9,
                body_len: body.len(),
            },
            body,
        )
    }
    fn commit(
        store: &mut DurableTailStore,
        writer: &dyn SingleWriter,
        header: PreparedHeader,
        body: &[u8],
    ) -> ReceiptProof {
        let prepared = store
            .prepare_stream(writer, header)
            .unwrap()
            .write(|out| {
                out.write_all(body)
                    .map_err(|_| codec::Refuse::WriteFailed)?;
                Ok(body.len())
            })
            .unwrap();
        let committed = store
            .commit_stream(writer, prepared)
            .unwrap()
            .commit()
            .unwrap();
        store.finish_stream(committed).unwrap()
    }
    /// [money] native population beyond memo bound reverifies and updates without hold.
    #[test]
    fn native_population_beyond_memo_bound_reverifies_and_updates_without_hold() {
        if !crate::test_isolation::run_here() {
            return;
        }
        let scratch = Scratch::new();
        let writer = crate::locked_state_dir::test_locks::hold(&scratch.root);
        let mut store = DurableTailStore::new(
            store_dir_for_index(&scratch.root.join("index.json")),
            DurableSource::Codex,
        );
        for n in 0..=MAX_RECORDS {
            if n % MAX_BATCH == 0 {
                store.begin_pass();
            }
            let (mut header, body) = header(&scratch, DurableSource::Codex, n as u64 + 1);
            header.binding.key = key_digest(DurableSource::Codex, &format!("native-{n}"));
            commit(&mut store, writer, header, &body);
            assert!(store.durable.len() <= MAX_RECORDS);
            assert!(!store.has_pending());
        }
        assert_eq!(store.counters.records_written, MAX_RECORDS as u64 + 1);
        assert!(store.counters.memo_evicted > 0);
        let (mut next, body) = header(&scratch, DurableSource::Codex, 999);
        next.binding.key = key_digest(DurableSource::Codex, "native-0");
        store.begin_pass();
        let before = store.counters.guard_verify_bytes;
        let record = match store.read(&next.binding.key) {
            ReadOutcome::Found(record) => record,
            other => panic!("cold memo record was refused: {other:?}"),
        };
        store.authorize(
            &record,
            &Expected {
                binding: record.record.binding.clone(),
                committed_generation: next.generation,
            },
        );
        assert!(
            store.counters.guard_verify_bytes > before,
            "cold memo reread counted"
        );
        commit(&mut store, writer, next, &body);
        assert_eq!(store.counters.records_written, MAX_RECORDS as u64 + 2);
        assert!(store.durable.len() <= MAX_RECORDS);
        assert_eq!(store.counters.mutation_unproved, 0);
        assert!(store.disabled().is_none());
    }

    /// [format] newly staged codex record is refused by both released decoders.
    #[test]
    fn newly_staged_codex_record_is_refused_by_both_released_decoders() {
        if !crate::test_isolation::run_here() {
            return;
        }
        let scratch = Scratch::new();
        let writer = crate::locked_state_dir::test_locks::hold(&scratch.root);
        let mut store = DurableTailStore::new(
            store_dir_for_index(&scratch.root.join("index.json")),
            DurableSource::Codex,
        );
        let (header, body) = header(&scratch, DurableSource::Codex, 3);
        let key = header.binding.key;
        let original = PendingRecord {
            binding: header.binding.clone(),
            certificate: header.certificate.clone(),
            body: body.clone(),
            allowlist: header.allowlist,
            acquisition: None,
        };
        let receipt = commit(&mut store, writer, header, &body);
        assert_eq!(receipt.identity().format(), FORMAT_V3);
        assert_eq!(
            receipt.identity().protocol(),
            crate::snapshots::AcquisitionProtocol::WriteAhead
        );
        let bytes = fs::read(store.record_path(&key)).unwrap();
        super::super::released_decoders_tests::assert_old_readers_refuse_native_v3(
            &bytes,
            &original,
            receipt.generation(),
        );
        assert_eq!(
            fs::read(store.record_path(&key)).unwrap(),
            bytes,
            "old reader leaves A unchanged"
        );
    }
    /// [money] stream is byte identical and flush is once per dirty pass.
    #[test]
    fn stream_is_byte_identical_and_flush_is_once_per_dirty_pass() {
        if !crate::test_isolation::run_here() {
            return;
        }
        let scratch = Scratch::new();
        let lock = crate::locked_state_dir::test_locks::hold(&scratch.root);
        let mut store = scratch.store();
        let (header, body) = header(&scratch, DurableSource::ClaudeCode, 1);
        let expected = encode(&DurableRecord {
            record: PendingRecord {
                binding: header.binding.clone(),
                certificate: header.certificate.clone(),
                body: body.clone(),
                allowlist: header.allowlist,
                acquisition: Some(header.acquisition),
            },
            index_generation: header.generation,
            format: FORMAT_V3,
            envelope_audit_debt: None,
            wire: None,
        });
        let receipt = commit(&mut store, lock, header, &body);
        assert_eq!(
            fs::read(store.record_path(&receipt.identity.binding.key)).unwrap(),
            expected
        );
        assert!(store.receipt_current(&receipt));
        assert_eq!(receipt.identity.acquired_revision(), 17);
        assert_eq!(
            receipt.identity.protocol(),
            crate::snapshots::AcquisitionProtocol::WriteAhead
        );
        assert_eq!(receipt.identity.generation(), 9);
        assert_eq!(receipt.generation(), 9);
        assert_eq!(receipt.identity.format(), FORMAT_V3);
        assert_eq!(
            receipt.identity.allowlist(),
            &DurableSource::ClaudeCode.properties().allowlist()
        );
        assert_eq!(
            receipt.identity.certificate().sealed_offset,
            receipt.identity.sealed_offset()
        );
        assert_eq!(receipt.identity.encoded_len(), expected.len() as u64);
        assert_eq!(receipt.identity.trailer(), &expected[expected.len() - 32..]);
        let flush = store.flush_pass(lock).unwrap().expect("dirty pass");
        assert!(store.flush_pass(lock).unwrap().is_none());
        flush.flush().unwrap();
        store.begin_pass();
        assert!(store.flush_pass(lock).unwrap().is_none());
        assert!(store.stream_reserve_bytes().unwrap() >= STREAM_BYTES as u64);
    }
    /// [format] first complete stage failed rename is absent not a survivor.
    #[test]
    fn first_complete_stage_failed_rename_is_absent_not_a_survivor() {
        if !crate::test_isolation::run_here() {
            return;
        }
        for source in [DurableSource::ClaudeCode, DurableSource::Codex] {
            let scratch = Scratch::new();
            let lock = crate::locked_state_dir::test_locks::hold(&scratch.root);
            let mut store = DurableTailStore::new(
                store_dir_for_index(&scratch.root.join("index.json")),
                source,
            );
            let (header, body) = header(&scratch, source, 1);
            let prepared = store
                .prepare_stream(lock, header)
                .unwrap()
                .write(|out| {
                    out.write_all(&body)
                        .map_err(|_| codec::Refuse::WriteFailed)?;
                    Ok(body.len())
                })
                .unwrap();
            let failure = prepared
                .attempt
                .failure("stream_rename", io::Error::other("rename failed"));
            assert!(failure.attempt.identity.is_some());
            assert!(stamp_at(&failure.attempt.path).unwrap().is_none());
            let plan = store.resolve_failed_stream(lock, failure);
            assert!(matches!(
                store.finish_resolution(plan.resolve()),
                FailureDisposition::PublishDegraded {
                    strict_rebind: false,
                    ..
                }
            ));
            assert!(store.disabled().is_none());
            assert!(store.pending.is_empty());
        }
    }
    /// [format] claude cleanup proves absence and recovery receipts only exact candidate.
    #[test]
    fn claude_cleanup_proves_absence_and_recovery_receipts_only_exact_candidate() {
        if !crate::test_isolation::run_here() {
            return;
        }
        let scratch = Scratch::new();
        let lock = crate::locked_state_dir::test_locks::hold(&scratch.root);
        let mut store = scratch.store();
        let (header_a, body_a) = header(&scratch, DurableSource::ClaudeCode, 1);
        let receipt_a = commit(&mut store, lock, header_a, &body_a);
        let (header_b, _) = header(&scratch, DurableSource::ClaudeCode, 2);
        let failure = store
            .prepare_stream(lock, header_b)
            .unwrap()
            .write(|_| Err(codec::Refuse::WriteFailed))
            .err()
            .unwrap();
        let plan = store.resolve_failed_stream(lock, failure);
        assert!(matches!(
            store.finish_resolution(plan.resolve()),
            FailureDisposition::PublishDegraded {
                strict_rebind: false,
                ..
            }
        ));
        assert!(!store.record_path(&receipt_a.identity.binding.key).exists());
        assert!(!store.receipt_current(&receipt_a));
        let (header_b, body_b) = header(&scratch, DurableSource::ClaudeCode, 2);
        let prepared = store
            .prepare_stream(lock, header_b)
            .unwrap()
            .write(|out| {
                out.write_all(&body_b)
                    .map_err(|_| codec::Refuse::WriteFailed)?;
                Ok(body_b.len())
            })
            .unwrap();
        let committed = store
            .commit_stream(lock, prepared)
            .unwrap()
            .commit()
            .unwrap();
        let failure = committed
            .attempt
            .failure("lost_delivery", io::Error::other("interrupted delivery"));
        let plan = store.resolve_failed_stream(lock, failure);
        let FailureDisposition::Receipted(receipt) = store.finish_resolution(plan.resolve()) else {
            panic!("exact renamed candidate lost");
        };
        assert!(store.receipt_current(&receipt));
        assert!(store.pending.is_empty());
        store.note_degraded_publish();
        store.note_stale_refusal();
        assert_eq!(store.counters().durable_write_failed_published, 1);
        assert_eq!(store.counters().stale_record_refused, 1);
    }
}
