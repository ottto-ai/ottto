//! Shape checks for a SHA-256 digest written as 64 hex digits.

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

    #[test]
    fn sha256_lower_accepts_only_64_lowercase_hex_digits() {
        assert!(is_sha256_lower(&"0a".repeat(32)));
        assert!(!is_sha256_lower(&"0A".repeat(32)));
        assert!(!is_sha256_lower(&"a".repeat(63)));
        assert!(!is_sha256_lower(&"a".repeat(65)));
        assert!(!is_sha256_lower(&format!("{}g", "a".repeat(63))));
    }

    #[test]
    fn sha256_any_case_accepts_64_hex_digits_of_either_case() {
        assert!(is_sha256_any_case(&"0a".repeat(32)));
        assert!(is_sha256_any_case(&"0A".repeat(32)));
        assert!(!is_sha256_any_case(&"A".repeat(63)));
        assert!(!is_sha256_any_case(&"A".repeat(65)));
        assert!(!is_sha256_any_case(&format!("{}g", "A".repeat(63))));
    }
}
