//! Trimmed string and unsigned integer readers at a key path in a
//! transcript JSON value.

use serde_json::Value;

pub(in crate::snapshots) fn string_at(value: &Value, path: &[&str]) -> Option<String> {
    let mut current = value;
    for key in path {
        current = current.get(*key)?;
    }
    match current {
        Value::String(value) if !value.trim().is_empty() => Some(value.trim().to_string()),
        _ => None,
    }
}

pub(in crate::snapshots) fn string_eq_at(value: &Value, path: &[&str], expected: &str) -> bool {
    string_at(value, path).is_some_and(|value| value == expected)
}

pub(in crate::snapshots) fn u64_at(value: &Value, path: &[&str]) -> Option<u64> {
    let mut current = value;
    for key in path {
        current = current.get(*key)?;
    }
    match current {
        Value::Number(number) => number.as_u64(),
        Value::String(value) => value.parse::<u64>().ok(),
        _ => None,
    }
}
