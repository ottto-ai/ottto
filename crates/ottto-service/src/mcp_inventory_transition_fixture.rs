//! Consumer adapter for the shared native transition fixture.
use super::*;

pub(crate) fn assert_version(home: &Path, feed: &CodexVersionFeed, expected: &str) {
    let sample = feed.snapshot().0.expect("native EOF supplied a version");
    // Production inventory construction, with transcript opens forbidden.
    super::super::snapshots::with_transcript_io_denied(|| {
        let built = build_inventory(
            home,
            SnapshotSource::Codex,
            None,
            unbounded_deadline(),
            sample.version(),
        );
        assert_eq!(built.inventory.client_version.as_deref(), Some(expected));
    });
}
