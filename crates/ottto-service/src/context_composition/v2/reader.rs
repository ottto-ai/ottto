//! Bounded line reader.
//!
//! Reads a transcript from a saved offset up to the length the file had when
//! the read started, so bytes appended during the read wait for the next run.
//! Only lines that end in `\n` are handed out; a partial last line stays
//! unread. A line longer than the guard is skipped to its end and counted,
//! even across runs (the checkpoint keeps the skipping flag).

use std::fs::File;
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom};

#[cfg(not(test))]
type ReaderFile = File;

#[cfg(test)]
struct ReaderFile(File);
#[cfg(test)]
impl Read for ReaderFile {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let read = self.0.read(buffer)?;
        super::checkpoint::record_read(read as u64);
        Ok(read)
    }
}

/// Lines longer than this are skipped, never buffered.
pub(super) const MAX_LINE_BYTES: usize = 16 * 1024 * 1024;
const READ_BUFFER_BYTES: usize = 256 * 1024;

pub(super) enum LineEvent<'a> {
    /// A complete line, without its `\n`.
    Line(&'a [u8]),
    /// A line over the guard started here; it is skipped to its end.
    TooLong,
}

pub(super) struct LineReader {
    reader: BufReader<ReaderFile>,
    /// Offset of the first byte not yet consumed.
    pos: u64,
    /// The length at open: nothing past it is read.
    end: u64,
    line: Vec<u8>,
    skipping: bool,
    max_line: usize,
}

impl LineReader {
    pub(super) fn open(file: File, offset: u64, end: u64, skipping: bool) -> std::io::Result<Self> {
        Self::with_guard(file, offset, end, skipping, MAX_LINE_BYTES)
    }

    pub(super) fn with_guard(
        mut file: File,
        offset: u64,
        end: u64,
        skipping: bool,
        max_line: usize,
    ) -> std::io::Result<Self> {
        file.seek(SeekFrom::Start(offset))?;
        #[cfg(test)]
        let file = ReaderFile(file);
        Ok(Self {
            reader: BufReader::with_capacity(READ_BUFFER_BYTES, file),
            pos: offset,
            end: end.max(offset),
            line: Vec::new(),
            skipping,
            max_line,
        })
    }

    /// The offset after the last consumed byte: the checkpoint offset.
    pub(super) fn position(&self) -> u64 {
        self.pos
    }

    /// Whether the reader stopped inside an over-long line.
    pub(super) fn skipping(&self) -> bool {
        self.skipping
    }

    /// Bytes held for the current line (for memory accounting).
    pub(super) fn buffer_bytes(&self) -> usize {
        self.line.capacity() + READ_BUFFER_BYTES
    }

    /// The next event, or `None` when no complete line remains before the
    /// length at open.
    pub(super) fn next_event(&mut self) -> std::io::Result<Option<LineEvent<'_>>> {
        if self.skipping && !self.skip_to_line_end()? {
            return Ok(None);
        }
        self.line.clear();
        let remaining = self.end - self.pos;
        if remaining == 0 {
            return Ok(None);
        }
        let limit = remaining.min(self.max_line as u64 + 1);
        let read = (&mut self.reader)
            .take(limit)
            .read_until(b'\n', &mut self.line)?;
        if self.line.last() == Some(&b'\n') {
            self.pos += read as u64;
            self.line.pop();
            return Ok(Some(LineEvent::Line(&self.line)));
        }
        if read as u64 == limit && limit > self.max_line as u64 {
            // Over the guard: consume what was read and skip the rest of the
            // line, now or in a later run.
            self.pos += read as u64;
            self.line.clear();
            self.line.shrink_to(64 * 1024);
            self.skipping = true;
            return Ok(Some(LineEvent::TooLong));
        }
        // A partial last line (or the file shrank under us): leave it.
        Ok(None)
    }

    /// Consume bytes up to and including the next `\n`. Returns false when
    /// the length at open is reached first.
    fn skip_to_line_end(&mut self) -> std::io::Result<bool> {
        while self.pos < self.end {
            let available = self.reader.fill_buf()?;
            if available.is_empty() {
                return Ok(false);
            }
            let window = available.len().min((self.end - self.pos) as usize);
            match available[..window].iter().position(|byte| *byte == b'\n') {
                Some(index) => {
                    self.reader.consume(index + 1);
                    self.pos += index as u64 + 1;
                    self.skipping = false;
                    return Ok(true);
                }
                None => {
                    self.reader.consume(window);
                    self.pos += window as u64;
                }
            }
        }
        Ok(false)
    }
}
