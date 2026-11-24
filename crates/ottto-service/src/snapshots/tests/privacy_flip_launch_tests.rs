//! A launcher-started file's identity does not depend on attribution.
use super::*;

const CONTROLLER: &str = "a9789dcf-1e4a-4a6e-8abd-f30094efb269";

fn write_event(home: &Path) {
    let raw = json!({"schema":"agent_launch.v1",
        "controller_session_ref":CONTROLLER,
        "worker_session_ref":SESSION, "relationship_kind":"launched",
        "workflow_ref":null, "pr_ref":null, "launch_ts":"2026-09-20T10:00:00Z",
        "capture_source":"launcher_event:opus_cli_agent", "evidence":"direct"})
    .to_string();
    let reduced = crate::launch_events::validate_event(&raw).unwrap();
    let dir = home.join(".ottto/launch-events/processed");
    fs::create_dir_all(&dir).unwrap();
    fs::write(
        dir.join(format!(
            "{}.json",
            crate::launch_events::event_digest(&reduced)
        )),
        raw,
    )
    .unwrap();
}

/// The file's source fingerprint from a cold walk.
fn fingerprint(
    f: &Fixture,
    scan_events: Option<&Path>,
    attribution: Option<&crate::session_attribution::SessionAttributionContext>,
) -> String {
    let mut index = ScanIndex::default();
    index.activate_file_upload_context(f.source, "d".repeat(64));
    let mut scan = OwnedSourceScan::new(
        f.source,
        std::slice::from_ref(&f.root),
        index,
        "2026-10-29T12:00:00Z",
        BACKFILL_WINDOW_DAYS,
        10,
        None,
        &[],
        false,
    );
    if let Some(home) = scan_events {
        scan = scan.with_launch_events(home);
    }
    loop {
        match scan.step(attribution) {
            OwnedSourceScanStep::Pending(next) => scan = next,
            OwnedSourceScanStep::Complete { index, .. } => {
                return index.files[&f.key()].source_file_fingerprint.clone();
            }
        }
    }
}

/// [behaviour] the witness folds with attribution off exactly as with it on, so
/// an attribution flip changes no launcher-started file's fingerprint.
#[test]
fn launch_witness_folds_independent_of_attribution() {
    use base64::Engine;
    for source in [SnapshotSource::ClaudeCode, SnapshotSource::Pi] {
        let f = Fixture::new(source);
        let home = f.root.join("launch-home");
        write_event(&home);
        let attribution =
            crate::session_attribution::SessionAttributionContext::from_activity_hint(
                source,
                &home,
                true,
                Some(&base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([13_u8; 32])),
                Some(crate::session_attribution::SESSION_ATTRIBUTION_HMAC_KEY_VERSION),
            )
            .unwrap();
        let off = fingerprint(&f, Some(&home), None);
        assert_eq!(
            off,
            fingerprint(&f, None, Some(&attribution)),
            "{source:?}: attribution off and on"
        );
        assert_ne!(
            off,
            fingerprint(&f, None, None),
            "{source:?}: positive control, the witness is folded"
        );
    }
}
