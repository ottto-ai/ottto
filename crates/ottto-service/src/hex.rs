//! Lowercase hex encoding and shape checks (SHA-256 digests, UUIDs).

use sha2::{Digest, Sha256};

/// Two lowercase hex digits per byte.
pub(crate) fn encode(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
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
