//! Lossless bounded byte codec. It compresses JSON field names and canonical
//! hash strings without changing JSON spelling, positional slots, or raw holds.
//! No short hash is promoted to global identity and no string is truncated.
use super::*;
use std::io;

const BLOCK: usize = 32 * 1024;
// FORMAT owns this ordered dictionary. Only exact quoted spellings match.
const WORDS: &[&[u8]] = &[
    b"\"source_file_fingerprint\"",
    b"\"last_snapshot_fingerprint\"",
    b"\"modified_unix_seconds\"",
    b"\"modified_unix_nanos\"",
    b"\"request_hashes\"",
    b"\"member_request_hashes\"",
    b"\"member_requests\"",
    b"\"request_hash\"",
    b"\"input_tokens\"",
    b"\"output_tokens\"",
    b"\"cache_read_input_tokens\"",
    b"\"cache_creation_input_tokens\"",
    b"\"census_window_end\"",
    b"\"account_identifier_hash\"",
    b"\"identity_revision\"",
    b"\"previous_windows\"",
    b"\"source_file_fingerprints\"",
    b"\"census_complete\"",
    b"\"retry_after_unix_seconds\"",
    b"\"proven_witness_fingerprint\"",
    b"\"member_source_file_fingerprints\"",
    b"\"scan_identity_version\"",
    b"\"last_upload_body_witness\"",
    b"\"effective_upload_body_witness_revision\"",
    b"\"model\"",
    b"\"effort\"",
    b"\"speed\"",
    b"\"version\"",
];

pub(super) struct Encoder<W: Write> {
    out: W,
    block: Vec<u8>,
    decoded: u64,
}
impl<W: Write> Encoder<W> {
    pub(super) fn new(out: W) -> Self {
        Self {
            out,
            block: Vec::with_capacity(BLOCK),
            decoded: 0,
        }
    }
    fn block(&mut self) -> io::Result<()> {
        let mut at = 0;
        let mut start = 0;
        while at < self.block.len() {
            let rest = &self.block[at..];
            let word = if rest[0] == b'"' {
                WORDS.iter().position(|word| rest.starts_with(word))
            } else {
                None
            };
            let hex_len = [64_usize, 16].into_iter().find(|len| {
                rest.len() >= len + 2
                    && rest[0] == b'"'
                    && rest[len + 1] == b'"'
                    && rest[1..len + 1]
                        .iter()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
            });
            if let Some(word) = word {
                self.out.write_all(&self.block[start..at])?;
                self.out.write_all(&[0xff, 0, word as u8])?;
                at += WORDS[word].len();
                start = at;
            } else if let Some(len) = hex_len {
                self.out.write_all(&self.block[start..at])?;
                self.out.write_all(&[0xff, 1, (len / 2) as u8])?;
                let nibble = |b: u8| if b <= b'9' { b - b'0' } else { b - b'a' + 10 };
                for pair in rest[1..len + 1].chunks_exact(2) {
                    self.out
                        .write_all(&[(nibble(pair[0]) << 4) | nibble(pair[1])])?;
                }
                at += len + 2;
                start = at;
            } else if rest[0] == 0xff {
                return Err(io::Error::other("state_v2_non_json_byte"));
            } else {
                at += 1;
            }
        }
        self.out.write_all(&self.block[start..])?;
        self.block.clear();
        Ok(())
    }
    pub(super) fn finish(mut self) -> io::Result<W> {
        self.block()?;
        self.out.flush()?;
        Ok(self.out)
    }
}
impl<W: Write> Write for Encoder<W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.decoded = self
            .decoded
            .checked_add(bytes.len() as u64)
            .filter(|n| *n <= VALUE_BYTES)
            .ok_or_else(|| io::Error::other("state_v2_value_admission"))?;
        let mut rest = bytes;
        while !rest.is_empty() {
            let n = rest.len().min(BLOCK - self.block.len());
            self.block.extend_from_slice(&rest[..n]);
            rest = &rest[n..];
            if self.block.len() == BLOCK {
                self.block()?;
            }
        }
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        self.block()?;
        self.out.flush()
    }
}

pub(super) fn decode(mut input: impl Read, out: &mut dyn Write) -> Result<()> {
    let mut decoded = 0_u64;
    let mut byte = [0];
    while input.read(&mut byte)? != 0 {
        let mut small = [0_u8; 66];
        let bytes = if byte[0] != 0xff {
            &byte[..]
        } else {
            let mut tag = [0; 2];
            input.read_exact(&mut tag)?;
            match tag {
                [0, word] => *WORDS
                    .get(word as usize)
                    .ok_or_else(|| anyhow::anyhow!("state_v2_packed_dictionary"))?,
                [1, len @ (8 | 32)] => {
                    small[0] = b'"';
                    for i in 0..len as usize {
                        input.read_exact(&mut byte)?;
                        small[i * 2 + 1] = b"0123456789abcdef"[(byte[0] >> 4) as usize];
                        small[i * 2 + 2] = b"0123456789abcdef"[(byte[0] & 15) as usize];
                    }
                    small[len as usize * 2 + 1] = b'"';
                    &small[..len as usize * 2 + 2]
                }
                _ => anyhow::bail!("state_v2_packed_tag"),
            }
        };
        decoded = decoded
            .checked_add(bytes.len() as u64)
            .filter(|n| *n <= VALUE_BYTES)
            .ok_or_else(|| anyhow::anyhow!("state_v2_packed_admission"))?;
        out.write_all(bytes)?;
    }
    Ok(())
}

pub(super) struct Json<'a, T: Serialize + ?Sized>(pub &'a T);
impl<T: Serialize + ?Sized> Value for Json<'_, T> {
    fn write(&self, out: &mut dyn Write) -> Result<()> {
        let mut encoder = Encoder::new(out);
        serde_json::to_writer(&mut encoder, self.0)?;
        encoder.finish()?;
        Ok(())
    }
}

/// HSTR packs only canonical lowercase 64-digit hashes. Literal spellings,
/// including malformed strings, uppercase and empty, remain byte-exact.
pub(super) fn hash_string(value: &str) -> Result<Vec<u8>> {
    anyhow::ensure!(value.len() <= KEY_BYTES, "state_v2_string_admission");
    if value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        let mut bytes = Vec::with_capacity(33);
        bytes.push(1);
        let nibble = |b: u8| if b <= b'9' { b - b'0' } else { b - b'a' + 10 };
        for pair in value.as_bytes().chunks_exact(2) {
            bytes.push((nibble(pair[0]) << 4) | nibble(pair[1]));
        }
        Ok(bytes)
    } else {
        let mut bytes = Vec::with_capacity(value.len() + 1);
        bytes.push(0);
        bytes.extend_from_slice(value.as_bytes());
        Ok(bytes)
    }
}

pub(super) fn read_hash_string(bytes: &[u8]) -> Result<String> {
    anyhow::ensure!(bytes.len() <= KEY_BYTES + 1, "state_v2_string_admission");
    match bytes.split_first() {
        Some((0, rest)) => {
            let s = std::str::from_utf8(rest)?;
            // Reject a second spelling of canonical packed bytes.
            anyhow::ensure!(hash_string(s)? == bytes, "state_v2_hstr_noncanonical");
            Ok(s.to_owned())
        }
        Some((1, rest)) if rest.len() == 32 => Ok(rest
            .iter()
            .flat_map(|b| {
                [
                    b"0123456789abcdef"[(b >> 4) as usize] as char,
                    b"0123456789abcdef"[(b & 15) as usize] as char,
                ]
            })
            .collect()),
        _ => anyhow::bail!("state_v2_hstr_tag"),
    }
}

#[cfg(test)]
#[test]
fn shipped_dictionary_is_append_only() {
    use sha2::Digest;
    const SHIPPED: usize = 28;
    assert!(WORDS.len() >= SHIPPED);
    let unique: std::collections::BTreeSet<_> = WORDS.iter().collect();
    assert_eq!(unique.len(), WORDS.len());
    let mut hash = sha2::Sha256::new();
    for word in &WORDS[..SHIPPED] {
        hash.update((word.len() as u32).to_be_bytes());
        hash.update(word);
    }
    assert_eq!(
        format!("{:x}", hash.finalize()),
        "2752da8c05d83800a5ff3d89b12b81deab65b382c0f8017bf7306aa3eb9becd6"
    );
}
