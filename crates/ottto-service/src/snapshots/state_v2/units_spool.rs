//! Anonymous owner-only scratch. Unlink before writing private bytes; every
//! reader has its own positional cursor, so cloned plans share no seek offset.
use super::*;
use anyhow::ensure;
use std::fs::File;
use std::io::{self, BufWriter};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::FileExt;
use std::sync::Arc;

#[derive(Clone)]
pub(super) struct Payload {
    file: Arc<File>,
    start: u64,
    len: u64,
}
pub(super) struct Builder {
    file: BufWriter<File>,
    len: u64,
    cap: u64,
}
impl Builder {
    pub(super) fn new(cap: u64) -> Result<Self> {
        let path = std::env::temp_dir().join("ottto-v2-scratch-XXXXXX");
        let mut name = std::ffi::CString::new(path.as_os_str().as_bytes())?.into_bytes_with_nul();
        let fd = unsafe { libc::mkstemp(name.as_mut_ptr().cast()) };
        ensure!(fd >= 0, "state_v2_scratch_open");
        let file = unsafe { File::from_raw_fd(fd) };
        let unlinked = unsafe { libc::unlink(name.as_ptr().cast()) };
        ensure!(unlinked == 0, "state_v2_scratch_unlink");
        ensure!(
            unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) } == 0,
            "state_v2_scratch_cloexec"
        );
        Ok(Self {
            file: BufWriter::with_capacity(64 * 1024, file),
            len: 0,
            cap,
        })
    }
    pub(super) fn finish(mut self) -> Result<Payload> {
        self.file.flush()?;
        Ok(Payload {
            file: Arc::new(
                self.file
                    .into_inner()
                    .map_err(|_| io::Error::other("state_v2_scratch_flush"))?,
            ),
            start: 0,
            len: self.len,
        })
    }
}
impl Write for Builder {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let len = self
            .len
            .checked_add(bytes.len() as u64)
            .filter(|n| *n <= self.cap)
            .ok_or_else(|| io::Error::other("state_v2_save_admission"))?;
        self.file.write_all(bytes)?;
        self.len = len;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}
/// One anonymous file per plan/carry, rather than one descriptor per row.
#[derive(Default)]
pub(super) struct Arena {
    file: Option<Arc<File>>,
    end: u64,
}
struct Append {
    file: Arc<File>,
    start: u64,
    len: u64,
    cap: u64,
}
impl Write for Append {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let len = self
            .len
            .checked_add(bytes.len() as u64)
            .filter(|n| *n <= self.cap)
            .ok_or_else(|| io::Error::other("state_v2_save_admission"))?;
        self.file.write_all_at(bytes, self.start + self.len)?;
        self.len = len;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
impl Arena {
    pub(super) fn append(
        &mut self,
        cap: u64,
        emit: impl FnOnce(&mut dyn Write) -> Result<()>,
    ) -> Result<Payload> {
        ensure!(
            self.end.saturating_add(cap) <= 512 * 1024 * 1024,
            "state_v2_save_admission"
        );
        if self.file.is_none() {
            self.file = Some(Builder::new(0)?.finish()?.file);
        }
        let file = self
            .file
            .as_ref()
            .expect("initialized anonymous arena")
            .clone();
        let mut writer = BufWriter::with_capacity(
            64 * 1024,
            Append {
                file: file.clone(),
                start: self.end,
                len: 0,
                cap,
            },
        );
        emit(&mut writer)?;
        writer.flush()?;
        let writer = writer
            .into_inner()
            .map_err(|_| io::Error::other("state_v2_scratch_flush"))?;
        let payload = Payload {
            file,
            start: self.end,
            len: writer.len,
        };
        self.end = self
            .end
            .checked_add(writer.len)
            .ok_or_else(|| io::Error::other("state_v2_save_admission"))?;
        Ok(payload)
    }
}

impl Payload {
    pub(super) fn capture(value: &dyn Value, cap: u64) -> Result<Self> {
        let mut writer = Builder::new(cap)?;
        value.write(&mut writer)?;
        writer.finish()
    }
    pub(super) fn len(&self) -> u64 {
        self.len
    }
    pub(super) fn reader(&self) -> std::io::BufReader<Reader<'_>> {
        std::io::BufReader::with_capacity(
            64 * 1024,
            Reader {
                payload: self,
                at: 0,
            },
        )
    }
    pub(super) fn matches(&self, other: &Self) -> Result<bool> {
        if self.len != other.len {
            return Ok(false);
        }
        let mut a = self.reader();
        let mut b = other.reader();
        let mut left = [0; 32 * 1024];
        let mut right = [0; 32 * 1024];
        loop {
            let n = a.read(&mut left)?;
            b.read_exact(&mut right[..n])?;
            if left[..n] != right[..n] {
                return Ok(false);
            }
            if n == 0 {
                return Ok(true);
            }
        }
    }
}
pub(super) struct Reader<'a> {
    payload: &'a Payload,
    at: u64,
}
impl Read for Reader<'_> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let n = out
            .len()
            .min(self.payload.len.saturating_sub(self.at) as usize);
        if n == 0 {
            return Ok(0);
        }
        let n = self
            .payload
            .file
            .read_at(&mut out[..n], self.payload.start + self.at)?;
        if n == 0 {
            return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
        }
        self.at += n as u64;
        Ok(n)
    }
}
impl Value for Payload {
    fn write(&self, out: &mut dyn Write) -> Result<()> {
        io::copy(&mut self.reader(), out)?;
        Ok(())
    }
}
impl Serialize for Payload {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        use serde::ser::{Error, SerializeSeq};
        let mut seq = serializer.serialize_seq(Some(self.len as usize))?;
        let mut reader = self.reader();
        let mut bytes = [0; 32 * 1024];
        loop {
            let n = reader.read(&mut bytes).map_err(S::Error::custom)?;
            if n == 0 {
                break;
            }
            for byte in &bytes[..n] {
                seq.serialize_element(byte)?;
            }
        }
        seq.end()
    }
}
#[cfg(test)]
impl Payload {
    pub(super) fn shares_arena(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.file, &other.file)
    }
}
