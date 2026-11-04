//! Test support for the parser's native finish. Content (`X`) is never
//! re-derived from the file: a Tail source stores it as session facts.

#[cfg(test)]
use std::fs::File;

#[cfg(test)]
use super::*;

/// The finished parser's upload items, as the money tests compare them.
#[cfg(test)]
pub(in crate::snapshots) fn test_finish_items(
    parser: OwnedJsonlParser,
    path: &Path,
    source: SnapshotSource,
) -> Value {
    items(parser, path, source)
}

#[cfg(test)]
/// The finished upload items of a parser that read to completion. Claude
/// finishes with the money context the scan passes (the `e2` fold's read
/// context over an index holding the file), so the money fold is compared
/// too.
fn items(parser: OwnedJsonlParser, path: &Path, source: SnapshotSource) -> Value {
    items_at(parser, path, source)
}

#[cfg(test)]
fn items_at(parser: OwnedJsonlParser, path: &Path, source: SnapshotSource) -> Value {
    const COLLECTED: &str = "2026-10-27T08:00:00Z";
    let identity = opened_object_identity(source, &mut File::open(path).unwrap()).unwrap();
    let mut index = ScanIndex::default();
    index.files.insert(
        local_index_key(path),
        serde_json::from_value(
            serde_json::json!({"size_bytes":1,"modified_unix_seconds":1,"source_file_fingerprint":"fp"}),
        )
        .unwrap(),
    );
    let twins = Default::default();
    let money =
        (source == SnapshotSource::ClaudeCode).then_some(claude_request_money::e2::ReadContext {
            index: &index,
            path,
            twins: &twins,
        });
    let parsed = parser
        .finish_with_repository_identity(
            &identity,
            path,
            COLLECTED,
            "fp".into(),
            None,
            None,
            None,
            None,
            money,
        )
        .unwrap();
    // The fold is not serialized (`serde(skip)`): compare its entity body.
    let money = parsed
        .snapshots
        .iter()
        .map(|item| {
            item.claude_money
                .as_deref()
                .map(|fold| format!("{:?}", fold.entity))
        })
        .collect::<Vec<_>>();
    if source == SnapshotSource::ClaudeCode {
        assert!(money.iter().all(Option::is_some), "the money fold ran");
    }
    serde_json::json!({"items": serde_json::to_value(&parsed.snapshots).unwrap(), "money": money})
}
