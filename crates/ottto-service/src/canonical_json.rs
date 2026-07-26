//! RFC 8785 (JSON Canonicalization Scheme) serialization.
//!
//! One canonical serialization exists so that a hash computed here and a hash
//! computed by another implementation over the same logical value are byte-for
//! byte comparable. Everything that participates in a durable content identity
//! goes through this module; nothing else is allowed to invent a byte order.
//!
//! Supported at this contract version: `null`, booleans, strings, integers that
//! fit `i64`/`u64`, arrays, and objects. Non-integer numbers are **rejected**
//! rather than approximated: RFC 8785 requires ECMAScript `Number::toString`
//! shortest round-trip formatting, and silently emitting Rust's `f64` rendering
//! instead would produce bytes a conforming implementation disagrees with. Any
//! payload that needs a fractional value carries it as a decimal string (which
//! is what the snapshot wire already does for money).

use std::fmt;

/// The canonicalization contract version. It is part of every hash-lineage
/// statement: a change here changes bytes, so it changes hashes.
pub const CANONICAL_JSON_CONTRACT_VERSION: &str = "rfc8785:integers-only:v1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CanonicalJsonError {
    /// A number that is not an exact `i64`/`u64` integer.
    NonIntegerNumber { pointer: String },
}

impl fmt::Display for CanonicalJsonError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NonIntegerNumber { pointer } => write!(
                formatter,
                "canonical JSON at {CANONICAL_JSON_CONTRACT_VERSION} rejects the non-integer \
                 number at JSON pointer {pointer}"
            ),
        }
    }
}

impl std::error::Error for CanonicalJsonError {}

/// Canonicalize `value` into RFC 8785 bytes.
pub fn canonicalize(value: &serde_json::Value) -> Result<Vec<u8>, CanonicalJsonError> {
    let mut out = Vec::new();
    write_value(value, &mut String::new(), &mut out)?;
    Ok(out)
}

/// True when every number reachable from `value` is an exact integer, i.e.
/// when [`canonicalize`] can succeed. Used by contract tests that assert a
/// body shape stays canonicalizable as it evolves.
pub fn is_canonicalizable(value: &serde_json::Value) -> bool {
    canonicalize(value).is_ok()
}

fn write_value(
    value: &serde_json::Value,
    pointer: &mut String,
    out: &mut Vec<u8>,
) -> Result<(), CanonicalJsonError> {
    match value {
        serde_json::Value::Null => out.extend_from_slice(b"null"),
        serde_json::Value::Bool(true) => out.extend_from_slice(b"true"),
        serde_json::Value::Bool(false) => out.extend_from_slice(b"false"),
        serde_json::Value::Number(number) => {
            if let Some(unsigned) = number.as_u64() {
                out.extend_from_slice(unsigned.to_string().as_bytes());
            } else if let Some(signed) = number.as_i64() {
                out.extend_from_slice(signed.to_string().as_bytes());
            } else {
                return Err(CanonicalJsonError::NonIntegerNumber {
                    pointer: if pointer.is_empty() {
                        "/".to_string()
                    } else {
                        pointer.clone()
                    },
                });
            }
        }
        serde_json::Value::String(text) => write_string(text, out),
        serde_json::Value::Array(items) => {
            out.push(b'[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                let restore = pointer.len();
                pointer.push('/');
                pointer.push_str(&index.to_string());
                write_value(item, pointer, out)?;
                pointer.truncate(restore);
            }
            out.push(b']');
        }
        serde_json::Value::Object(members) => {
            // RFC 8785 orders members by their UTF-16 code units, which is not
            // the same as Rust's code-point ordering above U+FFFF.
            let mut keys = members.keys().collect::<Vec<_>>();
            keys.sort_by_key(|key| key.encode_utf16().collect::<Vec<u16>>());
            out.push(b'{');
            for (index, key) in keys.into_iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                write_string(key, out);
                out.push(b':');
                let restore = pointer.len();
                pointer.push('/');
                pointer.push_str(&escape_pointer_token(key));
                write_value(&members[key], pointer, out)?;
                pointer.truncate(restore);
            }
            out.push(b'}');
        }
    }
    Ok(())
}

/// RFC 8785 §3.2.2.2 string serialization: the two mandatory escapes, the five
/// short control escapes, `\u00xx` for every other control character, and the
/// raw UTF-8 bytes for everything else.
fn write_string(text: &str, out: &mut Vec<u8>) {
    out.push(b'"');
    for character in text.chars() {
        match character {
            '"' => out.extend_from_slice(b"\\\""),
            '\\' => out.extend_from_slice(b"\\\\"),
            '\u{8}' => out.extend_from_slice(b"\\b"),
            '\u{9}' => out.extend_from_slice(b"\\t"),
            '\u{a}' => out.extend_from_slice(b"\\n"),
            '\u{c}' => out.extend_from_slice(b"\\f"),
            '\u{d}' => out.extend_from_slice(b"\\r"),
            control if control < '\u{20}' => {
                out.extend_from_slice(format!("\\u{:04x}", control as u32).as_bytes());
            }
            other => {
                let mut buffer = [0u8; 4];
                out.extend_from_slice(other.encode_utf8(&mut buffer).as_bytes());
            }
        }
    }
    out.push(b'"');
}

fn escape_pointer_token(token: &str) -> String {
    token.replace('~', "~0").replace('/', "~1")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn canonical(value: &serde_json::Value) -> String {
        String::from_utf8(canonicalize(value).expect("canonicalize")).expect("utf8")
    }

    #[test]
    fn members_are_ordered_by_utf16_code_units() {
        // U+10000 encodes as the surrogate pair D800 DC00, so it sorts BEFORE
        // U+E000 under UTF-16 and AFTER it under code-point ordering. The RFC
        // 8785 answer is the UTF-16 one.
        let value = json!({ "\u{10000}": 1, "\u{e000}": 2, "a": 3 });
        assert_eq!(
            canonical(&value),
            "{\"a\":3,\"\u{10000}\":1,\"\u{e000}\":2}"
        );
    }

    #[test]
    fn nested_members_are_ordered_and_unspaced() {
        let value = json!({
            "outer": { "b": [3, 2, 1], "a": null },
            "Z": true,
        });
        assert_eq!(
            canonical(&value),
            "{\"Z\":true,\"outer\":{\"a\":null,\"b\":[3,2,1]}}"
        );
    }

    #[test]
    fn strings_use_the_rfc_escape_set() {
        let value = json!({ "k": "quote\" back\\ tab\t nl\n bell\u{7} del\u{7f} é" });
        assert_eq!(
            canonical(&value),
            "{\"k\":\"quote\\\" back\\\\ tab\\t nl\\n bell\\u0007 del\u{7f} é\"}"
        );
    }

    #[test]
    fn integers_render_without_exponent_or_sign_padding() {
        let value = json!({ "big": u64::MAX, "neg": i64::MIN, "zero": 0 });
        assert_eq!(
            canonical(&value),
            format!("{{\"big\":{},\"neg\":{},\"zero\":0}}", u64::MAX, i64::MIN)
        );
    }

    #[test]
    fn non_integer_numbers_are_rejected_with_their_pointer() {
        let value = json!({ "a": { "b": [0, 1.5] } });
        let error = canonicalize(&value).expect_err("must reject");
        assert_eq!(
            error,
            CanonicalJsonError::NonIntegerNumber {
                pointer: "/a/b/1".to_string()
            }
        );
        assert!(!is_canonicalizable(&value));
        assert!(is_canonicalizable(&json!({ "a": { "b": [0, 1] } })));
    }

    #[test]
    fn rejection_pointer_escapes_json_pointer_tokens() {
        let value = json!({ "a/b": 1.5 });
        let error = canonicalize(&value).expect_err("must reject");
        assert_eq!(
            error,
            CanonicalJsonError::NonIntegerNumber {
                pointer: "/a~1b".to_string()
            }
        );
    }

    #[test]
    fn canonicalization_is_idempotent_over_a_reparse() {
        let value = json!({
            "b": [ { "y": 1, "x": "é" } ],
            "a": "\t",
        });
        let once = canonicalize(&value).expect("canonicalize");
        let reparsed: serde_json::Value =
            serde_json::from_slice(&once).expect("canonical bytes parse");
        assert_eq!(canonicalize(&reparsed).expect("canonicalize"), once);
    }

    #[test]
    fn contract_version_is_pinned() {
        // Changing this string changes every content hash derived from it, so
        // it moves only with a deliberate, announced hash-epoch bump.
        assert_eq!(CANONICAL_JSON_CONTRACT_VERSION, "rfc8785:integers-only:v1");
    }
}
