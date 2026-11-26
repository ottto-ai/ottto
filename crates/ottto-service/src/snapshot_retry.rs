//! Snapshot response size limits.
#[cfg(test)]
use anyhow::Result;

pub(crate) const RESPONSE_BYTES: usize = 128 * 1024;
pub(crate) const TOKEN_RESPONSE_BYTES: usize = 16 * 1024;
#[cfg(test)]
pub(crate) const REQUEST_BYTES: usize = 256 * 1024;

#[cfg(test)]
pub(crate) fn encode_json<T: serde::Serialize>(value: &T, cap: usize) -> Result<Vec<u8>> {
    struct CappedVec {
        bytes: Vec<u8>,
        cap: usize,
    }
    impl std::io::Write for CappedVec {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if self
                .bytes
                .len()
                .checked_add(bytes.len())
                .map_or(true, |n| n > self.cap)
            {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "optional snapshot request cap",
                ));
            }
            self.bytes.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut writer = CappedVec {
        bytes: Vec::with_capacity(4096.min(cap)),
        cap,
    };
    serde_json::to_writer(&mut writer, value)?;
    Ok(writer.bytes)
}
