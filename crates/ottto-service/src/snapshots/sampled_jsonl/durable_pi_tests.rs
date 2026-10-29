//! Pi body codec controls on synthetic ledgers: byte identity with the
//! back-patched framing, pinned section bytes, the decode allowance, the
//! ledger cap and the section guards.
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
    accumulator.seen_pi_usage_keys = keys;
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
    e.section(SECTION_TAG, |e| PiSection::put_borrowed(e, keys))
        .unwrap();
    e.into_bytes()
}

/// The branch's framing: the whole reduction with the ledger moved out, then
/// a section whose zeroed u64 length was patched after its bytes. No cap.
fn back_patched(reduction: &CachedJsonlReduction) -> Vec<u8> {
    let mut e = Enc::bytes(RECORD_BYTES);
    e.with_pi_ledger(|e| reduction.put(e)).unwrap();
    Rederive::default().put(&mut e).unwrap();
    let mut out = e.into_bytes();
    out.push(1);
    let start = out.len();
    out.extend([0_u8; 8]);
    let mut e = Enc::bytes(RECORD_BYTES);
    PiSection::put_borrowed(&mut e, &reduction.accumulator.seen_pi_usage_keys).unwrap();
    out.extend(e.into_bytes());
    let len = (out.len() - start - 8) as u64;
    out[start..start + 8].copy_from_slice(&len.to_le_bytes());
    out
}

fn verify_without_allocation(body: &[u8]) -> Result<(), Corrupt> {
    let (result, stats) =
        crate::retry_allocation_probe::measure_caller_thread(|| verify_body(&mut Dec::new(body)));
    assert_eq!(stats.allocations, 0, "{stats:?}");
    result
}

fn take_section(d: &mut Dec<'_>) -> Result<PiSection, Corrupt> {
    d.section(SECTION_TAG, PiSection::take)
}

/// E1-2: the count-pass length writes the back-patched bytes exactly, and a
/// decoded body re-encodes to the same bytes.
#[test]
fn count_pass_section_is_byte_identical_and_round_trips() {
    let original = reduction(ledger());
    assert!(original
        .accumulator
        .seen_pi_usage_keys
        .values()
        .any(|state| !state.message.is_empty()
            && !state.message_end.is_empty()
            && !state.paired_digests.is_empty()));
    let bytes = body(&original).unwrap();
    assert_eq!(bytes, back_patched(&original));
    let mut count = Enc::count(usize::MAX);
    put(&mut count, &original, &Rederive::default()).unwrap();
    assert_eq!(count.counted(), bytes.len());
    assert_eq!(verify_without_allocation(&bytes), Ok(()));
    let decoded = take_body(&mut Dec::new(&bytes)).unwrap();
    assert_eq!(
        format!("{:?}", decoded.reduction.accumulator.seen_pi_usage_keys),
        format!("{:?}", original.accumulator.seen_pi_usage_keys)
    );
    let mut again = Enc::bytes(RECORD_BYTES);
    put(&mut again, &decoded.reduction, &decoded.rederive).unwrap();
    assert_eq!(again.into_bytes(), bytes);
}

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
        &[1_u8, 101, 0, 0, 0, 0, 0, 0, 0, 1][..],
        &[0x11; 32],
        &[1],
        &[0x22; 32],
        &[1, 0, 1],
        &[0x33; 32],
    ]
    .concat();
    assert_eq!(section(&keys), golden);
    assert!(body(&reduction(keys)).unwrap().ends_with(&golden));
}

/// E1-4: the ledger charges the decode allowance before it allocates, and a
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
    assert_eq!(body(&over), Err(Refuse::NonEmpty(PI_LEDGER_CAP)));
    // A record that carries one key too many anyway is corrupt (T14), refused
    // before the ledger asks the allowance for anything.
    let forged = back_patched(&over);
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
                e.with_pi_ledger(|e| {
                    pi.put(e)?;
                    Err::<(), _>(Refuse::TooLarge)
                }),
                Err(Refuse::TooLarge)
            ),
            _ => assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _ = e.with_pi_ledger::<()>(|e| {
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
    other
        .accumulator
        .provider_skills
        .insert("synthetic-skill".into());
    assert_eq!(
        body(&other),
        Err(Refuse::NonEmpty("SnapshotAccumulator.provider_skills"))
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

#[test]
fn corrupt_truncated_or_misframed_sections_are_refused() {
    let keys = ledger();
    let bytes = body(&reduction(keys.clone())).unwrap();
    let section = section(&keys);
    let at = bytes.len() - section.len();
    let refused = |candidate: &[u8]| {
        assert_eq!(verify_without_allocation(candidate), Err(Corrupt));
        assert!(take_body(&mut Dec::new(candidate)).is_err());
    };
    // Truncated anywhere, including a body with no section at all.
    for end in 0..bytes.len() {
        refused(&bytes[..end]);
    }
    // Trailing bytes, or the section twice.
    refused(&[&bytes[..], &[0_u8]].concat());
    refused(&[&bytes[..], &section].concat());
    // A wrong tag, a length one short or one long, or past usize.
    let mut wrong_tag = bytes.clone();
    wrong_tag[at] = 2;
    refused(&wrong_tag);
    let content = (section.len() - 9) as u64;
    for len in [content - 1, content + 1, u64::MAX] {
        let mut wrong_len = bytes.clone();
        wrong_len[at + 1..at + 9].copy_from_slice(&len.to_le_bytes());
        refused(&wrong_len);
    }
    // A length that covers one extra byte the ledger does not consume.
    let mut long = bytes.clone();
    long[at + 1..at + 9].copy_from_slice(&(content + 1).to_le_bytes());
    long.push(0);
    refused(&long);
    // A duplicated ledger key.
    let (key, state) = keys.into_iter().next().unwrap();
    let mut e = Enc::bytes(RECORD_BYTES);
    e.section(SECTION_TAG, |e| {
        e.varint(2)?;
        for _ in 0..2 {
            key.put_h(e, "fixture")?;
            state.put(e)?;
        }
        Ok(())
    })
    .unwrap();
    refused(&[&bytes[..at], &e.into_bytes()].concat());
    // Taking the section is not enough: the end check needs the refill.
    let mut d = Dec::new(&bytes);
    d.require_section();
    CachedJsonlReduction::take(&mut d).unwrap();
    Rederive::take(&mut d).unwrap();
    take_ledger(&mut d).unwrap();
    assert_eq!(d.ended(), Err(Corrupt));
    d.refilled_section();
    assert_eq!(d.finish(), Ok(()));
}

#[test]
fn section_count_write_length_mismatch_refuses_on_every_sink() {
    for shorter in [false, true] {
        for mut e in [
            Enc::bytes(RECORD_BYTES),
            Enc::count(RECORD_BYTES),
            Enc::hash("synthetic-section"),
        ] {
            let pass = std::cell::Cell::new(0);
            assert_eq!(
                e.section(SECTION_TAG, |e| {
                    pass.set(pass.get() + 1);
                    let len = if shorter { 3 - pass.get() } else { pass.get() };
                    e.raw(&[0, 0][..len])
                }),
                Err(Refuse::TooLarge)
            );
        }
    }
}

/// SOURCE condition 1: every ledger key and digest is 64-char lower hex.
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
