//! Whole-line reader with a frozen file extent.
//!
//! Reads a transcript from a saved offset up to the length the file had when
//! the read started, so bytes appended during the read wait for the next run.
//! Only lines that end in `\n` are handed out; a partial last line stays
//! unread. Size alone never skips a record.

use std::fs::File;
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom};

#[cfg(not(test))]
type ReaderFile = std::io::Take<File>;

#[cfg(test)]
struct ReaderFile(std::io::Take<File>);
#[cfg(test)]
impl Read for ReaderFile {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let read = self.0.read(buffer)?;
        super::checkpoint::record_transcript_read(read as u64);
        Ok(read)
    }
}

const READ_BUFFER_BYTES: usize = 256 * 1024;

pub(super) enum LineEvent<'a> {
    /// A complete line, without its `\n`.
    Line(&'a [u8]),
}

pub(super) struct LineReader {
    reader: BufReader<ReaderFile>,
    /// Offset of the first byte not yet consumed.
    pos: u64,
    /// The length at open: nothing past it is read.
    end: u64,
    line: Vec<u8>,
}

impl LineReader {
    pub(super) fn open(
        file: File,
        offset: u64,
        end: u64,
        _skipping: bool,
    ) -> std::io::Result<Self> {
        Self::with_buffer(file, offset, end, READ_BUFFER_BYTES)
    }

    /// Small head probes should not prefetch the daily reader's large buffer.
    pub(super) fn with_buffer(
        mut file: File,
        offset: u64,
        end: u64,
        capacity: usize,
    ) -> std::io::Result<Self> {
        file.seek(SeekFrom::Start(offset))?;
        // Bound prefetch too: a file may grow after the length was pinned.
        let file = file.take(end.saturating_sub(offset));
        #[cfg(test)]
        let file = ReaderFile(file);
        Ok(Self {
            reader: BufReader::with_capacity(capacity, file),
            pos: offset,
            end: end.max(offset),
            line: Vec::new(),
        })
    }

    /// The offset after the last consumed byte: the checkpoint offset.
    pub(super) fn position(&self) -> u64 {
        self.pos
    }

    /// Whether the reader stopped inside an over-long line.
    pub(super) fn skipping(&self) -> bool {
        false
    }

    /// Bytes held for the current line (for memory accounting).
    pub(super) fn buffer_bytes(&self) -> usize {
        self.line.capacity() + self.reader.capacity()
    }

    /// The next event, or `None` when no complete line remains before the
    /// length at open.
    pub(super) fn next_event(&mut self) -> std::io::Result<Option<LineEvent<'_>>> {
        crate::snapshots::release_line_buffer(&mut self.line);
        let remaining = self.end - self.pos;
        if remaining == 0 {
            return Ok(None);
        }
        let read = (&mut self.reader)
            .take(remaining)
            .read_until(b'\n', &mut self.line)?;
        crate::local_resource_diagnostics::jsonl::line_buffer(self.line.capacity());
        if self.line.last() == Some(&b'\n') {
            self.pos += read as u64;
            self.line.pop();
            crate::local_resource_diagnostics::jsonl::line(self.line.len());
            return Ok(Some(LineEvent::Line(&self.line)));
        }
        // A partial last line (or the file shrank under us): leave it.
        Ok(None)
    }
}
