use super::*;
use crate::claude_local_otel::{ClaudeApiEvidenceRead, ClaudeLocalOtelEvidence};
use sha2::{Digest, Sha256};

#[derive(Debug, PartialEq, Eq)]
struct Row(&'static str, Option<u64>);

impl ReportedRequest for Row {
    fn request_key(&self) -> &str {
        self.0
    }

    fn reported_cost_micros(&self) -> Option<u64> {
        self.1
    }
}

#[test]
fn one_holder_attaches_each_row_once_and_preserves_missing_cost() {
    let rows = [Row("request-a", Some(100)), Row("request-b", None)];
    let duplicates = BTreeSet::new();
    let mut holder_visits = 0;
    let mut compatible_visits = 0;
    let mut costs = Vec::new();
    let counts = join(
        SessionReport {
            rows: &rows,
            complete: true,
            duplicate_keys: &duplicates,
        },
        |key| {
            holder_visits += 1;
            assert_eq!(key, rows[holder_visits - 1].request_key());
            Holders::One(42)
        },
        |_, holder| {
            compatible_visits += 1;
            assert_eq!(*holder, 42);
            true
        },
        |event| match event {
            Attachment::Matched { row, holder } => {
                assert_eq!(holder, 42);
                assert!(std::ptr::eq(row, &rows[costs.len()]));
                costs.push(row.reported_cost_micros());
            }
            _ => panic!("one compatible holder must match"),
        },
    );
    assert_eq!(holder_visits, 2);
    assert_eq!(compatible_visits, 2);
    assert_eq!(costs, [Some(100), None]);
    assert_eq!(
        counts,
        JoinCounts {
            matched: 2,
            complete: true,
            ..Default::default()
        }
    );
}

#[test]
fn holder_and_compatibility_outcomes_are_exclusive() {
    let rows = [
        Row("unheld", None),
        Row("many", Some(10)),
        Row("incompatible", Some(20)),
        Row("skipped", Some(30)),
    ];
    let duplicates = BTreeSet::new();
    let mut events = Vec::new();
    let counts = join(
        SessionReport {
            rows: &rows,
            complete: false,
            duplicate_keys: &duplicates,
        },
        |key| match key {
            "unheld" => Holders::None,
            "many" => Holders::Many,
            "incompatible" => Holders::One("holder"),
            "skipped" => Holders::HeldNotAttachable,
            _ => unreachable!(),
        },
        |row, _| {
            assert_eq!(row.request_key(), "incompatible");
            false
        },
        |event| events.push(event),
    );
    assert_eq!(
        events,
        [
            Attachment::Unheld(&rows[0]),
            Attachment::Disclosed {
                row: &rows[1],
                reason: DisclosureReason::ManyHolders,
            },
            Attachment::Disclosed {
                row: &rows[2],
                reason: DisclosureReason::Incompatible,
            },
        ]
    );
    assert_eq!(
        counts,
        JoinCounts {
            unheld: 1,
            disclosed: 2,
            complete: false,
            ..Default::default()
        }
    );
}

#[test]
fn held_not_attachable_is_silent_even_for_a_conflicting_key() {
    let rows = [Row("skipped", Some(10))];
    let duplicates = BTreeSet::from(["skipped".to_string()]);
    let counts = join(
        SessionReport {
            rows: &rows,
            complete: false,
            duplicate_keys: &duplicates,
        },
        |_| Holders::<()>::HeldNotAttachable,
        |_, _| panic!("skipped holder cannot be compared"),
        |_| panic!("skipped holder cannot emit an attachment event"),
    );
    assert_eq!(counts, JoinCounts::default());
}

#[test]
fn claude_report_borrows_rows_and_keeps_reader_health_without_rereading() {
    let dir = crate::test_scratch::private_dir("telemetry-attach");
    let store = dir.join("local-otel/claude-code-effort");
    std::fs::create_dir_all(&store).unwrap();
    let path = |root: &str| store.join(format!("{:x}.jsonl", Sha256::digest(root.as_bytes())));
    let row = |root: &str, request: &str, fingerprint: &str, cost| ClaudeLocalOtelEvidence {
        session_id: root.to_string(),
        request_id: request.to_string(),
        fingerprint: fingerprint.to_string(),
        cost_usd_micros: cost,
        ..Default::default()
    };
    let write = |root: &str, rows: &[ClaudeLocalOtelEvidence]| {
        let text: String = rows
            .iter()
            .map(|row| format!("{}\n", serde_json::to_string(row).unwrap()))
            .collect();
        std::fs::write(path(root), text).unwrap();
    };
    write("healthy", &[row("healthy", "req", "a", Some(7))]);
    write(
        "conflict",
        &[
            row("conflict", "req", "a", Some(10)),
            row("conflict", "req", "b", Some(99)),
        ],
    );
    write("no-request", &[row("no-request", "", "a", None)]);
    write("wrong-session", &[row("another-root", "req", "a", None)]);
    std::fs::write(path("malformed"), b"not json\n").unwrap();
    std::fs::write(path("empty"), b"").unwrap();
    // Exactly the existing reader's cap is incomplete, just like above it.
    for (root, bytes) in [
        ("at-cap", 64 * 1024 * 1024),
        ("over-cap", 64 * 1024 * 1024 + 1),
    ] {
        std::fs::File::create(path(root))
            .unwrap()
            .set_len(bytes)
            .unwrap();
    }
    let roots = [
        "healthy",
        "conflict",
        "no-request",
        "wrong-session",
        "malformed",
        "empty",
        "missing",
        "at-cap",
        "over-cap",
    ];
    let read = ClaudeApiEvidenceRead::load(&dir, roots.map(str::to_string)).unwrap();
    // Reports must remain the already-read view even after the source disappears.
    std::fs::remove_dir_all(&dir).unwrap();
    assert!(read.session_report("unread-root").is_none());
    let report = read.session_report("healthy").unwrap();
    assert!(report.complete);
    assert!(std::ptr::eq(
        report.rows,
        read.evidence["healthy"].as_slice()
    ));
    assert_eq!(report.rows[0].request_key(), "req");
    assert_eq!(report.rows[0].reported_cost_micros(), Some(7));
    assert!(read.session_report("empty").unwrap().complete);
    for root in &roots[1..] {
        if *root != "empty" {
            assert!(!read.session_report(root).unwrap().complete, "{root}");
        }
    }
    let conflict = read.session_report("conflict").unwrap();
    assert_eq!(conflict.rows.len(), 2);
    assert!(conflict.duplicate_keys.contains("req"));
    let counts = join(
        conflict,
        |_| Holders::One(()),
        |_, _| panic!("reader conflict must veto compatibility"),
        |event| {
            assert!(matches!(
                event,
                Attachment::Disclosed {
                    reason: DisclosureReason::DuplicateReport,
                    ..
                }
            ))
        },
    );
    assert_eq!(counts.disclosed, 2);
    assert_eq!(counts.matched, 0);
    assert!(!counts.complete);
    for root in [
        "missing",
        "malformed",
        "wrong-session",
        "at-cap",
        "over-cap",
    ] {
        assert!(read.session_report(root).unwrap().rows.is_empty(), "{root}");
    }
    let counts = join(
        read.session_report("no-request").unwrap(),
        |_| Holders::One(()),
        |_, _| panic!("legacy missing-id row must not reach compatibility"),
        |event| {
            assert!(matches!(
                event,
                Attachment::Disclosed {
                    reason: DisclosureReason::Incompatible,
                    ..
                }
            ))
        },
    );
    assert_eq!(counts.disclosed, 1);
    assert_eq!(counts.matched + counts.unheld, 0);
    assert!(!counts.complete);
}
