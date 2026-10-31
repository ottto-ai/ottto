//! The retained v1 wire-order contract. V2 behavior uses shared wire fixtures.

use super::*;

#[test]
fn wire_ids_and_parts() {
    assert_eq!(
        Kind::ALL.map(Kind::as_str),
        [
            "harness_attachments",
            "shell_output",
            "code_reads",
            "doc_reads_md",
            "doc_reads_html",
            "memory_notes",
            "browser_and_images",
            "web_fetch_search",
            "agent_results",
            "other_tools",
        ]
    );
    for (index, kind) in Kind::ALL.into_iter().enumerate() {
        assert_eq!(kind.index(), index);
    }
    // Row order inside a day follows declaration order; v1 order is unchanged.
    let mut sorted = Kind::ALL;
    sorted.sort();
    assert_eq!(sorted, Kind::ALL);
}

#[test]
#[cfg(debug_assertions)]
#[should_panic(expected = "has no kinds_version 1 slot")]
fn v2_kind_has_no_v1_slot() {
    Kind::FilesRead.index();
}
