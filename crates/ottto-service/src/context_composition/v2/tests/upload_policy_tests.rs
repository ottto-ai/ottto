//! Composition lane of the upload filter, checked on the captured POST body.
use super::super::aggregate::{FileKey, FileTotals};
use super::super::health::{HealthEntry, HealthRecord};
use super::super::scope::Scope;
use super::super::upload::{ack_path, upload_scope, UploadOutcome};
use super::*;
use crate::snapshots::SnapshotUploadPolicy;

const FILE: &str = "SENTINEL-FILE.md";

fn labels(on: bool) -> SnapshotUploadPolicy {
    SnapshotUploadPolicy {
        session_titles_enabled: on,
        workspace_labels_enabled: on,
        ..SnapshotUploadPolicy::default()
    }
}

fn scope_with_file() -> Scope {
    let mut scope = super::details::scope();
    let day = day_of(base_now().date());
    let key = FileKey {
        path: FILE.into(),
        kind: Kind::FilesRead,
        part: crate::composition_kinds::Part::FileTool,
    };
    let totals = FileTotals {
        events: 1,
        tokens: 40,
        last: Some(base_now().unix_timestamp()),
    };
    scope.agg.day_files.insert((day, key.clone()), totals);
    scope.agg.all_files.insert(key, totals);
    scope.agg.day_generation.insert(day, 1);
    scope.generation = 1;
    scope
}

#[test]
fn names_off_omits_file_rows_and_keeps_the_same_body_otherwise() {
    let scope = scope_with_file();
    let on = super::details::payload(&scope, true, true);
    assert!(on.to_string().contains(FILE));
    assert!(on["top_files"].is_array());
    assert!(on["top_files_7d"].is_array());

    let off = super::details::payload(&scope, true, false);
    assert!(!off.to_string().contains(FILE));
    assert!(off.get("top_files").is_none());
    assert!(off.get("top_files_7d").is_none());
    assert_eq!(off["daily_aggregates"], on["daily_aggregates"]);
    assert_eq!(off["session_count_window"], on["session_count_window"]);
    assert_eq!(off["sessions_7d"].is_array(), on["sessions_7d"].is_array());
    assert!(off["tools"].as_array().unwrap().is_empty());
}

#[test]
fn a_label_flip_alone_uploads_once_and_an_old_ack_stays_quiet() {
    let dir = scratch("upload-policy-flip");
    let now = base_now();
    let window = Window::ending(day_of(now.date()));
    let scope = scope_with_file();
    let mut capture = Capture::default();
    let upload = |capture: &mut Capture, on: bool| {
        let mut target = UploadTarget {
            uploader: capture,
            machine_id: "machine-test",
            destination: "test-destination",
            policy: labels(on),
            details_enabled: false,
        };
        upload_scope(&dir, Source::Claude, &scope, &mut target, now, window).outcome
    };
    assert_eq!(upload(&mut capture, true), UploadOutcome::Uploaded);
    assert_eq!(upload(&mut capture, true), UploadOutcome::Unchanged);
    assert_eq!(upload(&mut capture, false), UploadOutcome::Uploaded);
    assert_eq!(upload(&mut capture, false), UploadOutcome::Unchanged);
    assert_eq!(upload(&mut capture, true), UploadOutcome::Uploaded);
    assert_eq!(capture.payloads.len(), 3);
    assert!(capture.payloads[0]["top_files"].is_array());
    assert!(capture.payloads[1].get("top_files").is_none());

    // An ack saved before this field existed matches any setting.
    let path = ack_path(&dir, Source::Claude, &scope.scope_id);
    let mut ack: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    ack.as_object_mut().unwrap().remove("names_enabled");
    fs::write(&path, serde_json::to_vec(&ack).unwrap()).unwrap();
    assert_eq!(upload(&mut capture, false), UploadOutcome::Unchanged);
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn run_health_body_has_only_its_allowlisted_fields() {
    // Adding a field stops this compiling, so its author decides on a rule.
    let _ = |body: HealthRecord| {
        let HealthRecord {
            schema: _,
            run_day: _,
            destination: _,
            posted: _,
            entries: _,
        } = body;
    };
    let _ = |body: HealthEntry| {
        let HealthEntry {
            agent_source: _,
            finished: _,
            scan_completed_at: _,
            files_checked: _,
            audit_differences: _,
            full_read_waiting_files: _,
            full_read_backlog_bytes: _,
            backlog_growth_days: _,
            bytes_read: _,
            cpu_seconds: _,
            duration_ms: _,
            accounted_bytes: _,
            scopes_quarantined: _,
            files_quarantined: _,
            agent_resets: _,
            checkpoint_restarts: _,
        } = body;
    };
}
