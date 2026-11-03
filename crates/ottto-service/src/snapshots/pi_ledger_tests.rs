//! Pi's pure usage reducers and ledger shape: the fork cutoff and its heap
//! bound. Moved from the retired Pi record codec's tests; these never needed
//! the codec.
use super::*;
use serde_json::Value;

const FORK_TIME: &str = "2026-10-27T06:00:00.000000001Z";
const PARENT_CANARY: &str = "/synthetic/CANARY_PI_PARENT/session.jsonl";

fn fork_header(parent: Option<&str>, at: &str) -> Value {
    serde_json::json!({"type":"session", "id":"synthetic-pi-fork",
        "timestamp":at, "parentSession":parent})
}
fn fork_usage(kind: &str, id: &str, at: &str, input: u64) -> Value {
    let usage = serde_json::json!({"input":input, "output":2});
    if matches!(kind, "compaction" | "branch_summary" | "usage") {
        serde_json::json!({"type":kind, "id":id, "timestamp":at, "usage":usage})
    } else {
        serde_json::json!({"type":kind, "id":id, "timestamp":at,
            "message":{"role":"assistant", "responseId":id, "model":"gpt-5.4",
                "timestamp":at, "usage":usage}})
    }
}

/// [money] Fork usage of every entry kind stamped before the header is skipped
/// and counted; usage at or after the header counts.
#[test]
fn fork_copies_before_the_header_skip_usage_but_at_and_after_count() {
    use crate::local_resource_diagnostics::cache_lifecycle;
    for kind in [
        "message",
        "message_end",
        "compaction",
        "branch_summary",
        "usage",
    ] {
        let mut acc = SnapshotAccumulator::new(SnapshotSource::Pi);
        apply_pi_line(&fork_header(Some(PARENT_CANARY), FORK_TIME), &mut acc);
        let (_, counts) = cache_lifecycle::observe(|| {
            apply_pi_line(
                &fork_usage(kind, "before", "2026-10-27T06:00:00Z", 100),
                &mut acc,
            );
            apply_pi_line(&fork_usage(kind, "at", FORK_TIME, 20), &mut acc);
            apply_pi_line(
                &fork_usage(kind, "after", "2026-10-27T06:00:00.000000002Z", 30),
                &mut acc,
            );
        });
        assert_eq!(acc.accepted_usage_totals.input_tokens, 50, "{kind}");
        assert_eq!(acc.accepted_usage_totals.request_count, 2, "{kind}");
        assert_eq!(counts.pi_fork_copies_skipped_entries, 1);
        assert_eq!(counts.pi_fork_copies_skipped_tokens, 102);
        // An ordinary file keeps historical usage, with normal identity.
        let mut ordinary = SnapshotAccumulator::new(SnapshotSource::Pi);
        apply_pi_line(&fork_header(None, FORK_TIME), &mut ordinary);
        apply_pi_line(
            &fork_usage(kind, "before", "2026-10-27T06:00:00Z", 100),
            &mut ordinary,
        );
        assert_eq!(ordinary.accepted_usage_totals.input_tokens, 100);
    }
    // Envelope time wins; only an absent envelope falls back to provider time.
    let mut acc = SnapshotAccumulator::new(SnapshotSource::Pi);
    apply_pi_line(&fork_header(Some(PARENT_CANARY), FORK_TIME), &mut acc);
    for (i, (envelope, provider, expected)) in [
        (
            Some("2026-10-27T05:59:59Z"),
            Some("2026-10-27T07:00:00Z"),
            0,
        ),
        (None, Some("2026-10-27T05:59:59Z"), 0),
        (Some("invalid"), Some("2026-10-27T05:59:59Z"), 100),
        (None, None, 200),
    ]
    .into_iter()
    .enumerate()
    {
        let mut value = fork_usage("message", &format!("clock-{i}"), FORK_TIME, 100);
        value.as_object_mut().unwrap().remove("timestamp");
        value["message"]
            .as_object_mut()
            .unwrap()
            .remove("timestamp");
        if let Some(at) = envelope {
            value["timestamp"] = serde_json::json!(at);
        }
        if let Some(at) = provider {
            value["message"]["timestamp"] = serde_json::json!(at);
        }
        apply_pi_line(&value, &mut acc);
        assert_eq!(
            acc.accepted_usage_totals.input_tokens, expected,
            "clock {i}"
        );
    }
    for at in ["invalid", ""] {
        let mut acc = SnapshotAccumulator::new(SnapshotSource::Pi);
        apply_pi_line(&fork_header(Some(PARENT_CANARY), at), &mut acc);
        apply_pi_line(
            &fork_usage("message", "old", "2026-10-26T00:00:00Z", 100),
            &mut acc,
        );
        assert_eq!(
            acc.accepted_usage_totals.input_tokens, 100,
            "unknown header clock"
        );
    }
    let mut acc = SnapshotAccumulator::new(SnapshotSource::Pi);
    apply_pi_line(&fork_header(Some(PARENT_CANARY), FORK_TIME), &mut acc);
    let mut copied = fork_usage("usage", "copy", "2026-10-27T05:59:59Z", 100);
    copied["model"] = serde_json::json!("copied-context-model");
    apply_pi_line(&copied, &mut acc);
    assert_eq!(acc.latest_model.as_deref(), Some("copied-context-model"));
    for kind in ["compaction", "branch_summary"] {
        apply_pi_line(&fork_usage(kind, kind, FORK_TIME, 20), &mut acc);
    }
    assert_eq!(acc.accepted_usage_totals.input_tokens, 40);
    assert!(acc
        .usage_buckets
        .values()
        .flat_map(|b| b.rows.keys())
        .all(|k| k.model == "copied-context-model"));
}

/// [format] A fork's box is charged by the heap bound, and the ledger stays one
/// word over its map.
#[test]
#[cfg_attr(
    not(any(target_os = "macos", target_os = "linux")),
    ignore = "native heap layout"
)]
fn fork_heap_bound_charges_inline_box_allocation() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let base = PiLedger::default();
    assert_eq!(
        std::mem::size_of::<PiLedger>(),
        std::mem::size_of::<BTreeMap<String, PiUsageDedupState>>() + 8
    );
    let mut fork = base.clone();
    fork.note_header(&fork_header(Some(PARENT_CANARY), FORK_TIME));
    let extra = std::mem::size_of::<PiFork>() + std::mem::align_of::<PiFork>();
    for measure in [
        crate::heap_layout_bound::bound::<PiLedger>,
        crate::heap_layout_bound::completed_bound::<PiLedger>,
    ] {
        let before = measure(&base, usize::MAX).unwrap();
        let after = measure(&fork, usize::MAX).unwrap();
        assert_eq!(after - before, extra);
        assert!(measure(&fork, after - 1).is_none());
    }
}
