//! Pi body codec controls: trailing fields, decode funding and integrity.
use super::*;
use crate::durable_tail_codec::{DecodeFailure, HDigest};
use crate::durable_tail_store::RECORD_BYTES;

fn digest(byte: u8) -> String {
    format!("{byte:02x}").repeat(32)
}

/// Three response keys: an unpaired message, a message/message_end pair with
/// a repeat, and a divergent pair, so all three containers hold entries.
fn ledger() -> BTreeMap<String, PiUsageDedupState> {
    use PiUsageRecordShape::{Message, MessageEnd};
    let mut keys = BTreeMap::<String, PiUsageDedupState>::new();
    for (key, records) in [
        (0x01, vec![(Message, 0x21)]),
        (
            0x02,
            vec![
                (Message, 0x22),
                (MessageEnd, 0x22),
                (Message, 0x22),
                (MessageEnd, 0x25),
            ],
        ),
        (0x03, vec![(MessageEnd, 0x23), (Message, 0x24)]),
    ] {
        let state = keys.entry(digest(key)).or_default();
        for (shape, occurrence) in records {
            state.record(shape, digest(occurrence));
        }
    }
    keys
}

fn reduction(keys: BTreeMap<String, PiUsageDedupState>) -> CachedJsonlReduction {
    let mut accumulator = SnapshotAccumulator::new(SnapshotSource::Pi);
    *accumulator.seen_pi_usage_keys = keys;
    CachedJsonlReduction {
        accumulator,
        report: JsonlReadReport::default(),
        recognized_usage_drop_count: 1,
        positive_recognized_usage_count: 2,
        positive_usage_evidence: true,
    }
}

fn put(e: &mut Enc, reduction: &CachedJsonlReduction, rederive: &Rederive) -> Result<(), Refuse> {
    let CachedJsonlReduction {
        accumulator,
        report,
        recognized_usage_drop_count,
        positive_recognized_usage_count,
        positive_usage_evidence,
    } = reduction;
    put_body(
        e,
        accumulator,
        report,
        (
            *recognized_usage_drop_count,
            *positive_recognized_usage_count,
            *positive_usage_evidence,
        ),
        rederive,
    )
}

fn body(reduction: &CachedJsonlReduction) -> Result<Vec<u8>, Refuse> {
    let mut e = Enc::bytes(RECORD_BYTES);
    put(&mut e, reduction, &Rederive::default())?;
    Ok(e.into_bytes())
}

fn section(keys: &BTreeMap<String, PiUsageDedupState>) -> Vec<u8> {
    let mut e = Enc::bytes(RECORD_BYTES);
    PiSection::put_borrowed(&mut e, keys, &false, &None).unwrap();
    e.into_bytes()
}

/// Forge an over-cap current-format body to exercise reader refusal.
fn unbounded_body(reduction: &CachedJsonlReduction) -> Vec<u8> {
    let mut e = Enc::bytes(RECORD_BYTES);
    e.with_moved_field("SnapshotAccumulator.seen_pi_usage_keys", |e| {
        reduction.put(e)
    })
    .unwrap();
    Rederive::default().put(&mut e).unwrap();
    let ledger = &reduction.accumulator.seen_pi_usage_keys;
    let (has_parent, header_nanos) = ledger.fork_parts();
    PiSection::put_borrowed(&mut e, ledger.usage_keys(), &has_parent, &header_nanos).unwrap();
    e.into_bytes()
}

fn verify_without_allocation(body: &[u8]) -> Result<(), Corrupt> {
    let (result, stats) =
        crate::retry_allocation_probe::measure_caller_thread(|| verify_body(&mut Dec::new(body)));
    assert_eq!(stats.allocations, 0, "{stats:?}");
    result
}

/// Every key, occurrence count and digest, and the fork values. `Debug`
/// prints counts only.
fn ledger_contents(reduction: &CachedJsonlReduction) -> impl PartialEq + std::fmt::Debug {
    let ledger = &reduction.accumulator.seen_pi_usage_keys;
    let keys = ledger
        .iter()
        .map(|(key, state)| {
            (
                key.clone(),
                state.message.clone(),
                state.message_end.clone(),
                state.paired_digests.clone(),
            )
        })
        .collect::<Vec<_>>();
    (keys, ledger.fork_parts())
}

fn take_section(d: &mut Dec<'_>) -> Result<PiSection, Corrupt> {
    PiSection::take(d)
}

/// [format] The populated body counts exactly and round-trips.
#[test]
fn plain_trailing_pi_body_counts_and_round_trips() {
    let original = reduction(ledger());
    assert!(original
        .accumulator
        .seen_pi_usage_keys
        .values()
        .any(|state| !state.message.is_empty()
            && !state.message_end.is_empty()
            && !state.paired_digests.is_empty()));
    let bytes = body(&original).unwrap();
    assert_eq!(bytes, unbounded_body(&original));
    let mut count = Enc::count(usize::MAX);
    put(&mut count, &original, &Rederive::default()).unwrap();
    assert_eq!(count.counted(), bytes.len());
    assert_eq!(verify_without_allocation(&bytes), Ok(()));
    let decoded = take_body(&mut Dec::new(&bytes)).unwrap();
    assert_eq!(
        ledger_contents(&decoded.reduction),
        ledger_contents(&original)
    );
    let mut again = Enc::bytes(RECORD_BYTES);
    put(&mut again, &decoded.reduction, &decoded.rederive).unwrap();
    assert_eq!(again.into_bytes(), bytes);
}

/// [format] Pi fork accounting and durable body contract.
#[test]
fn pi_section_bytes_are_pinned() {
    let keys = BTreeMap::from([(
        digest(0x11),
        PiUsageDedupState {
            message: BTreeMap::from([(digest(0x22), 1)]),
            message_end: BTreeMap::new(),
            paired_digests: BTreeSet::from([digest(0x33)]),
        },
    )]);
    let golden = [
        &[1_u8][..],
        &[0x11; 32],
        &[1],
        &[0x22; 32],
        &[1, 0, 1],
        &[0x33; 32],
        // No parent, no local header time.
        &[0, 0],
    ]
    .concat();
    assert_eq!(section(&keys), golden);
    assert!(body(&reduction(keys)).unwrap().ends_with(&golden));
}

/// [format] Pi fork accounting and durable body contract.
/// The ledger charges the decode allowance before it allocates, and a
/// refused charge leaves nothing allocated.
#[test]
fn ledger_decode_funds_the_tree_before_any_allocation() {
    let bytes = section(&ledger());
    let mut paid = 0_u64;
    let mut grant = |more: u64| {
        paid += more;
        true
    };
    let (taken, stats) = crate::retry_allocation_probe::measure_caller_thread(|| {
        let mut d = Dec::bounded(&bytes, &mut grant);
        let result = take_section(&mut d);
        d.outcome(result).map(|section| section.usage_keys.len())
    });
    assert_eq!(taken, Ok(3));
    assert!(
        stats.requested_peak_with_overlap as u64 <= paid,
        "{stats:?}, paid={paid}"
    );
    // Three keys need four tree nodes; an allowance of two refuses at once.
    let node = crate::heap_layout_bound::tree_node_bytes::<String, PiUsageDedupState>().unwrap();
    let mut calls = 0;
    let mut short = |more: u64| {
        calls += 1;
        more <= 2 * node as u64
    };
    let (refused, stats) = crate::retry_allocation_probe::measure_caller_thread(|| {
        let mut d = Dec::bounded(&bytes, &mut short);
        let result = take_section(&mut d);
        d.outcome(result).map(|section| section.usage_keys.len())
    });
    assert_eq!(refused, Err(DecodeFailure::Budget));
    assert_eq!(calls, 1);
    assert_eq!(
        stats.allocations, 0,
        "allocation before allowance: {stats:?}"
    );
    // Even with the tree funded, the first key's String must be charged
    // before its capacity grows.
    let mut calls = 0;
    let mut tree_only = |_: u64| {
        calls += 1;
        calls == 1
    };
    let (refused, stats) = crate::retry_allocation_probe::measure_caller_thread(|| {
        let mut d = Dec::bounded(&bytes, &mut tree_only);
        let result = take_section(&mut d);
        d.outcome(result).map(|section| section.usage_keys.len())
    });
    assert_eq!(refused, Err(DecodeFailure::Budget));
    assert_eq!(calls, 2);
    assert_eq!(stats.allocations, 0, "unfunded H string: {stats:?}");
}

/// [format] Pi fork accounting and durable body contract.
#[test]
fn ledger_cap_decodes_at_the_bound_and_refuses_past_it() {
    let mut keys = (0..PI_LEDGER_MAX_KEYS)
        .map(|n| (format!("{n:064x}"), PiUsageDedupState::default()))
        .collect::<BTreeMap<_, _>>();
    let at_cap = body(&reduction(keys.clone())).unwrap();
    assert_eq!(verify_without_allocation(&at_cap), Ok(()));
    let decoded = take_body(&mut Dec::new(&at_cap)).unwrap();
    assert_eq!(
        decoded.reduction.accumulator.seen_pi_usage_keys.len(),
        PI_LEDGER_MAX_KEYS
    );
    keys.insert(
        format!("{PI_LEDGER_MAX_KEYS:064x}"),
        PiUsageDedupState::default(),
    );
    let over = reduction(keys);
    assert_eq!(body(&over), Err(Refuse::TooLarge));
    // A record that carries one key too many anyway is corrupt (T14), refused
    // before the ledger asks the allowance for anything.
    let forged = unbounded_body(&over);
    assert_eq!(verify_without_allocation(&forged), Err(Corrupt));
    assert!(take_body(&mut Dec::new(&forged)).is_err());
    let bytes = section(&over.accumulator.seen_pi_usage_keys);
    let mut calls = 0;
    let mut grant = |_: u64| {
        calls += 1;
        true
    };
    let mut d = Dec::bounded(&bytes, &mut grant);
    let result = take_ledger(&mut d).map(|keys| keys.len());
    assert_eq!(d.outcome(result), Err(DecodeFailure::Integrity));
    assert_eq!(calls, 0);
}

/// [format] Pi fork accounting and durable body contract.
/// Only the ledger may leave the shared body, only inside one Pi body's
/// scope, and only from a Pi accumulator.
#[test]
fn moved_ledger_allowance_is_scoped_to_one_pi_body() {
    let pi = reduction(ledger());
    for exit in 0..3 {
        let mut e = Enc::bytes(RECORD_BYTES);
        match exit {
            0 => put(&mut e, &pi, &Rederive::default()).unwrap(),
            1 => assert_eq!(
                e.with_moved_field("SnapshotAccumulator.seen_pi_usage_keys", |e| {
                    pi.put(e)?;
                    Err::<(), _>(Refuse::TooLarge)
                }),
                Err(Refuse::TooLarge)
            ),
            _ => assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _ = e.with_moved_field::<()>("SnapshotAccumulator.seen_pi_usage_keys", |e| {
                    pi.put(e)?;
                    panic!("synthetic unwind")
                });
            }))
            .is_err()),
        }
        let mut non_pi = pi.clone();
        non_pi.accumulator.source = SnapshotSource::ClaudeCode;
        assert_eq!(
            non_pi.put(&mut e),
            Err(Refuse::NonEmpty("SnapshotAccumulator.seen_pi_usage_keys"))
        );
    }
    let mut other = pi.clone();
    other.accumulator.claude_fork_parent = Some("synthetic-parent".into());
    assert_eq!(
        body(&other),
        Err(Refuse::NonEmpty("SnapshotAccumulator.claude_fork_parent"))
    );
    for source in [SnapshotSource::ClaudeCode, SnapshotSource::Codex] {
        let mut other = pi.clone();
        other.accumulator.source = source;
        assert_eq!(
            body(&other),
            Err(Refuse::NotRederivable("SnapshotAccumulator.source"))
        );
    }
}

/// [format] Truncation, trailing bytes and duplicate ledger keys refuse.
#[test]
fn corrupt_or_truncated_trailing_fields_are_refused() {
    let keys = ledger();
    let bytes = body(&reduction(keys.clone())).unwrap();
    let section = section(&keys);
    let at = bytes.len() - section.len();
    let refused = |candidate: &[u8]| {
        assert_eq!(verify_without_allocation(candidate), Err(Corrupt));
        assert!(take_body(&mut Dec::new(candidate)).is_err());
    };
    for end in 0..bytes.len() {
        refused(&bytes[..end]);
    }
    refused(&[&bytes[..], &[0_u8]].concat());
    refused(&[&bytes[..], &section].concat());
    let (key, state) = keys.into_iter().next().unwrap();
    let mut e = Enc::bytes(RECORD_BYTES);
    e.varint(2).unwrap();
    for _ in 0..2 {
        key.put_h(&mut e, "fixture").unwrap();
        state.put(&mut e).unwrap();
    }
    false.put(&mut e).unwrap();
    Option::<i128>::None.put(&mut e).unwrap();
    refused(&[&bytes[..at], &e.into_bytes()].concat());
}

/// [format] Pi fork accounting and durable body contract.
/// Every ledger key and digest is 64-char lower hex.
#[test]
fn ledger_h_values_must_be_lower_hex_digests() {
    for invalid in [
        "id".to_string(),
        "A".repeat(64),
        "g".repeat(64),
        "0".repeat(63),
    ] {
        let mut keys = ledger();
        keys.insert(invalid.clone(), PiUsageDedupState::default());
        assert_eq!(
            body(&reduction(keys)),
            Err(Refuse::NotDigest("PiSection.usage_keys"))
        );
        let mut keys = ledger();
        keys.entry(digest(0x01))
            .or_default()
            .paired_digests
            .insert(invalid);
        assert_eq!(
            body(&reduction(keys)),
            Err(Refuse::NotDigest("PiUsageDedupState.paired_digests"))
        );
    }
}

/// [format] Pi fork accounting and durable body contract.
#[test]
fn pi_registered_body_rows_preserve_populated_body_bytes() {
    use crate::durable_tail_store::DurableSource;
    let original = reduction(ledger());
    let row = DurableSource::Pi.properties();
    assert_eq!(row.tag, 3);
    assert_eq!(row.source.slot(), 2);
    assert_eq!(row.write_format, 3);
    assert_eq!(row.representations.len(), 1);
    let pin = row.allowlist();
    assert_eq!(
        row.representation(3, &pin).unwrap().allowlist_pin,
        // The Pi allowlist pin, including the fork fields of PiSection.
        "c4f301b3ec5afe28933bfb8af315fe3061fd6d93184589f559206b38d7f81ce8"
    );
    for format in [0, 1, 2, 4] {
        assert!(row.representation(format, &pin).is_none());
    }
    assert!(row.representation(3, &[0; 32]).is_none());
    let bytes = (row.encode)(&original, RECORD_BYTES, 1024 * 1024).unwrap();
    assert_eq!(bytes, unbounded_body(&original));
    assert_eq!((row.verify)(&mut Dec::new(&bytes)), Ok(()));
    let decoded = (row.decode)(&bytes, SnapshotSource::Pi).unwrap();
    assert_eq!(
        (row.encode)(&decoded.reduction, RECORD_BYTES, 1024 * 1024).unwrap(),
        bytes
    );
    let plan = BodyEncoding::new(
        &original.accumulator,
        &original.report,
        (1, 2, true),
        1024 * 1024,
        true,
    )
    .unwrap();
    let len = plan.count(RECORD_BYTES).unwrap();
    let mut streamed = Vec::new();
    assert_eq!(plan.write(&mut streamed, len).unwrap(), bytes.len());
    assert_eq!(streamed, bytes);
    for end in 0..bytes.len() {
        assert!((row.verify)(&mut Dec::new(&bytes[..end])).is_err());
        assert!((row.decode)(&bytes[..end], SnapshotSource::Pi).is_err());
    }
}

/// [format] Pi fork accounting and durable body contract.
#[cfg(unix)]
#[test]
#[cfg_attr(not(target_os = "macos"), ignore = "needs macOS heap layout")]
fn pi_registered_bounded_decode_charges_the_shared_graph_and_ledger() {
    use crate::durable_tail_store::{ActiveLease, DurableSource, LeaseWait};
    let original = reduction(ledger());
    let row = DurableSource::Pi.properties();
    let bytes = (row.encode)(&original, RECORD_BYTES, 1024 * 1024).unwrap();
    let LeaseWait::Granted(mut lease) = ActiveLease::acquire("pi") else {
        panic!("isolated active lease");
    };
    let decoded = (row.decode_bounded)(&bytes, SnapshotSource::Pi, &mut lease).unwrap();
    assert_eq!(
        (row.encode)(&decoded.reduction, RECORD_BYTES, 1024 * 1024).unwrap(),
        bytes
    );
    drop(decoded);
    lease.release();
    let LeaseWait::Granted(mut lease) = ActiveLease::acquire("pi") else {
        panic!("released active lease");
    };
    lease
        .charge(crate::durable_tail_store::ACTIVE_BYTES)
        .unwrap();
    assert!(matches!(
        (row.decode_bounded)(&bytes, SnapshotSource::Pi, &mut lease),
        Err(DecodeFailure::Budget)
    ));
    lease.release();
}

const FORK_TIME: &str = "2026-10-27T06:00:00.000000001Z";
const PARENT_CANARY: &str = "/synthetic/CANARY_M2_PARENT/session.jsonl";

fn fork_header(parent: Option<&str>, at: &str) -> Value {
    serde_json::json!({"type":"session", "id":"synthetic-m2-fork",
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

/// [regress] Pi fork accounting and durable body contract.
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
            acc.seen_pi_usage_keys.finish_fork_read(|_| false);
        });
        assert_eq!(acc.accepted_usage_totals.input_tokens, 50, "{kind}");
        assert_eq!(acc.accepted_usage_totals.request_count, 2, "{kind}");
        assert_eq!(counts.pi_fork_copies_skipped_entries, 1);
        assert_eq!(counts.pi_fork_copies_skipped_tokens, 102);
        assert_eq!(counts.pi_fork_parent_unseen, 1);
        assert!(acc
            .seen_pi_usage_keys
            .fork
            .as_ref()
            .unwrap()
            .parent_ref
            .is_none());
        // An ordinary file keeps historical usage, with normal identity.
        let mut ordinary = SnapshotAccumulator::new(SnapshotSource::Pi);
        apply_pi_line(&fork_header(None, FORK_TIME), &mut ordinary);
        apply_pi_line(
            &fork_usage(kind, "before", "2026-10-27T06:00:00Z", 100),
            &mut ordinary,
        );
        assert_eq!(ordinary.accepted_usage_totals.input_tokens, 100);
    }
}

/// [regress] Pi fork accounting and durable body contract.
#[test]
fn fork_cutoff_uses_envelope_then_provider_only_when_envelope_is_absent() {
    let header = fork_header(Some(PARENT_CANARY), FORK_TIME);
    let mut acc = SnapshotAccumulator::new(SnapshotSource::Pi);
    apply_pi_line(&header, &mut acc);
    let mut value = fork_usage("message", "envelope", "2026-10-27T05:59:59Z", 100);
    value["message"]["timestamp"] = serde_json::json!("2026-10-27T07:00:00Z");
    apply_pi_line(&value, &mut acc); // old envelope, later provider: copied
    assert_eq!(acc.accepted_usage_totals.input_tokens, 0);
    value["message"]["responseId"] = serde_json::json!("provider");
    value["message"]["timestamp"] = serde_json::json!("2026-10-27T05:59:59Z");
    value.as_object_mut().unwrap().remove("timestamp");
    apply_pi_line(&value, &mut acc); // absent envelope: provider proves copied
    assert_eq!(acc.accepted_usage_totals.input_tokens, 0);
    value["timestamp"] = serde_json::json!("invalid");
    value["message"]["responseId"] = serde_json::json!("invalid-envelope");
    apply_pi_line(&value, &mut acc); // invalid envelope cannot prove a copy
    assert_eq!(acc.accepted_usage_totals.input_tokens, 100);
    value.as_object_mut().unwrap().remove("timestamp");
    value["message"]
        .as_object_mut()
        .unwrap()
        .remove("timestamp");
    value["message"]["responseId"] = serde_json::json!("no-clock");
    apply_pi_line(&value, &mut acc);
    assert_eq!(acc.accepted_usage_totals.input_tokens, 200);
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
        let (_, counts) = crate::local_resource_diagnostics::cache_lifecycle::observe(|| {
            acc.seen_pi_usage_keys.finish_fork_read(|_| true)
        });
        assert_eq!(counts.pi_fork_cutoff_unknown, 1);
    }
}

/// [format] Pi fork accounting and durable body contract.
#[test]
fn fork_round_trip_keeps_only_local_cutoff_fields_and_funds_the_box() {
    let mut original = reduction(ledger());
    original
        .accumulator
        .seen_pi_usage_keys
        .note_header(&fork_header(Some(PARENT_CANARY), FORK_TIME));
    let bytes = body(&original).unwrap();
    assert!(!bytes
        .windows(PARENT_CANARY.len())
        .any(|w| w == PARENT_CANARY.as_bytes()));
    assert!(!format!("{:?}", original.accumulator.seen_pi_usage_keys).contains(PARENT_CANARY));
    assert!(!format!("{:?}", original.accumulator.seen_pi_usage_keys)
        .contains(&pi_timestamp_nanos(FORK_TIME).unwrap().to_string()));
    assert_eq!(verify_without_allocation(&bytes), Ok(()));
    let decoded = take_body(&mut Dec::new(&bytes)).unwrap();
    let fork = decoded
        .reduction
        .accumulator
        .seen_pi_usage_keys
        .fork
        .as_ref()
        .unwrap();
    assert!(fork.has_parent);
    assert_eq!(fork.header_nanos, pi_timestamp_nanos(FORK_TIME));
    assert!(fork.parent_ref.is_none());
    assert_eq!(body(&decoded.reduction).unwrap(), bytes);
    let cloned = original.accumulator.seen_pi_usage_keys.clone();
    assert!(cloned.fork.as_ref().unwrap().parent_ref.is_none());
}

/// [format] Pi fork accounting and durable body contract.
#[test]
fn non_pi_fork_refuses_instead_of_silently_dropping_and_default_is_empty() {
    use crate::durable_tail_codec::DurableEmpty;
    let ledger = PiLedger {
        fork: Some(Box::default()),
        ..PiLedger::default()
    };
    assert!(ledger.durable_empty());
    for source in [SnapshotSource::ClaudeCode, SnapshotSource::Codex] {
        let mut acc = SnapshotAccumulator::new(source);
        acc.seen_pi_usage_keys =
            PiLedger::from_parts(BTreeMap::new(), true, pi_timestamp_nanos(FORK_TIME));
        assert!(!acc.seen_pi_usage_keys.durable_empty());
        assert_eq!(
            acc.put(&mut Enc::count(RECORD_BYTES)),
            Err(Refuse::NonEmpty("SnapshotAccumulator.seen_pi_usage_keys"))
        );
    }
}

/// [format] Pi fork accounting and durable body contract.
#[test]
#[cfg_attr(not(target_os = "macos"), ignore = "native heap layout")]
fn fork_heap_bound_charges_inline_box_allocation_and_parent_capacity() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    // Measure the decoder's charge on an empty ledger (no native tree layout).
    let with_fork = PiLedger::from_parts(BTreeMap::new(), true, pi_timestamp_nanos(FORK_TIME));
    let mut e = Enc::bytes(RECORD_BYTES);
    let (has_parent, nanos) = with_fork.fork_parts();
    PiSection::put_borrowed(&mut e, with_fork.usage_keys(), &has_parent, &nanos).unwrap();
    let section = e.into_bytes();
    let mut charged = 0;
    let mut grant = |n| {
        charged += n;
        true
    };
    let mut d = Dec::bounded(&section, &mut grant);
    take_ledger(&mut d).unwrap();
    d.finish().unwrap();
    assert!(charged >= std::mem::size_of::<PiFork>() as u64);
    let base = PiLedger::default();
    assert_eq!(
        std::mem::size_of::<PiLedger>(),
        std::mem::size_of::<BTreeMap<String, PiUsageDedupState>>() + 8
    );
    let mut fork = base.clone();
    fork.note_header(&fork_header(Some(PARENT_CANARY), FORK_TIME));
    let extra = std::mem::size_of::<PiFork>()
        + std::mem::align_of::<PiFork>()
        + fork
            .fork
            .as_ref()
            .unwrap()
            .parent_ref
            .as_ref()
            .unwrap()
            .capacity();
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

/// [format] Pi fork accounting and durable body contract.
#[test]
fn fork_parent_membership_is_full_read_only_and_never_retained() {
    use crate::local_resource_diagnostics::cache_lifecycle;
    for known in [false, true] {
        let mut ledger = PiLedger::default();
        ledger.note_header(&fork_header(Some(PARENT_CANARY), FORK_TIME));
        let (_, counts) = cache_lifecycle::observe(|| {
            assert!(ledger.skip_fork_copy(&fork_usage(
                "message",
                "old",
                "2026-10-27T05:00:00Z",
                10
            )));
            ledger.finish_fork_read(|parent| {
                assert_eq!(parent, PARENT_CANARY);
                known
            });
            // The parent value ends with the Full read. Even another skipped
            // entry cannot recreate a parent membership count during Tail.
            assert!(ledger.skip_fork_copy(&fork_usage(
                "message",
                "tail-old",
                "2026-10-27T05:00:00Z",
                10
            )));
            ledger.finish_fork_read(|_| panic!("Tail must not acquire parent history"));
        });
        assert_eq!(counts.pi_fork_copies_skipped_entries, 2);
        assert_eq!(counts.pi_fork_parent_unseen, u64::from(!known));
        assert!(ledger.fork.as_ref().unwrap().parent_ref.is_none());
    }
}

/// [format] Pi fork accounting and durable body contract.
#[test]
fn fork_section_semantics_agree_between_verify_and_decode() {
    let reduction = reduction(BTreeMap::new());
    let original = body(&reduction).unwrap();
    let prefix = original.len() - section(&BTreeMap::new()).len();
    let mut e = Enc::bytes(RECORD_BYTES);
    PiSection::put_borrowed(&mut e, &BTreeMap::new(), &false, &Some(1)).unwrap();
    let bad = [&original[..prefix], &e.into_bytes()].concat();
    assert_eq!(verify_without_allocation(&bad), Err(Corrupt));
    assert!(take_body(&mut Dec::new(&bad)).is_err());
}

/// [regress] Pi fork accounting and durable body contract.
#[test]
fn copied_top_level_usage_keeps_the_model_for_owned_summaries() {
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
