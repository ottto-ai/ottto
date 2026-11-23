//! Lowercase hex encoding and shape checks (SHA-256 digests, UUIDs).

use serde::{Serialize, Serializer};
use sha2::{Digest, Sha256};
use std::fmt;

/// Two lowercase hex digits per byte.
pub(crate) fn encode(bytes: &[u8]) -> String {
    LowerHex(bytes).to_string()
}

/// [`encode`] without the `String`: written 32 bytes at a time through a stack
/// buffer.
pub(crate) struct LowerHex<'a>(pub(crate) &'a [u8]);
impl fmt::Display for LowerHex<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        const DIGITS: &[u8; 16] = b"0123456789abcdef";
        let mut text = [0_u8; 64];
        for chunk in self.0.chunks(32) {
            for (slot, byte) in text.chunks_exact_mut(2).zip(chunk) {
                slot[0] = DIGITS[usize::from(byte >> 4)];
                slot[1] = DIGITS[usize::from(byte & 15)];
            }
            f.write_str(std::str::from_utf8(&text[..chunk.len() * 2]).map_err(|_| fmt::Error)?)?;
        }
        Ok(())
    }
}
impl Serialize for LowerHex<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

/// Inverse of [`encode`] (either case); `None` on odd length or a non-hex pair.
pub(crate) fn decode(raw: &str) -> Option<Vec<u8>> {
    (raw.len() % 2 == 0).then_some(())?;
    (0..raw.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&raw[index..index + 2], 16).ok())
        .collect()
}

/// SHA-256 of `bytes` as 64 lowercase hex digits.
pub(crate) fn sha256_lower(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

/// The 36-byte 8-4-4-4-12 hex UUID shape (either case).
pub(crate) fn is_uuid(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 36
        && bytes.iter().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => *byte == b'-',
            _ => byte.is_ascii_hexdigit(),
        })
}

/// 64 lowercase hex digits: the shape `format!("{:x}", Sha256::digest(..))` writes.
pub(crate) fn is_sha256_lower(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// 64 hex digits in either case.
pub(crate) fn is_sha256_any_case(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// [behaviour] Lowercase-only shape: exact length 64, digits and a-f.
    #[test]
    fn sha256_lower_accepts_only_64_lowercase_hex_digits() {
        assert!(is_sha256_lower(&"0a".repeat(32)));
        assert!(!is_sha256_lower(&"0A".repeat(32)));
        assert!(!is_sha256_lower(&"a".repeat(63)));
        assert!(!is_sha256_lower(&"a".repeat(65)));
        assert!(!is_sha256_lower(&format!("{}g", "a".repeat(63))));
    }

    /// [behaviour] Any-case shape: exact length 64, digits and a-f/A-F.
    #[test]
    fn sha256_any_case_accepts_64_hex_digits_of_either_case() {
        assert!(is_sha256_any_case(&"0a".repeat(32)));
        assert!(is_sha256_any_case(&"0A".repeat(32)));
        assert!(!is_sha256_any_case(&"A".repeat(63)));
        assert!(!is_sha256_any_case(&"A".repeat(65)));
        assert!(!is_sha256_any_case(&format!("{}g", "A".repeat(63))));
    }
}
