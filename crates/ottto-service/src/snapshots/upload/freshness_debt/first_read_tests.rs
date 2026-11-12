//! `first_read` V1 against the shared wire fixture (the server reads the same
//! bytes): member classes, coverage from obstructions, the block's wire form.
use super::*;
use crate::snapshots::state_v2::FirstReadCounts as Counts;
use sha2::{Digest, Sha256};

const FIXTURE: &str = include_str!("../../../../../../fixtures/collector-status/first-read-v1.json");
/// The fixture both sides pin; a change is a wire change on both.
const FIXTURE_SHA256: &str = "12ca19c08da99e532eb279c061686335229d5199a1f032f52acbbae3ab684699";

fn fixture() -> serde_json::Value {
    serde_json::from_str(FIXTURE).expect("first-read wire fixture")
}

fn ms(instant: &serde_json::Value) -> Option<u64> {
    let text = instant.as_str()?;
    let at = time::OffsetDateTime::parse(text, &time::format_description::well_known::Rfc3339)
        .expect("fixture instant");
    Some(u64::try_from(at.unix_timestamp_nanos() / 1_000_000).unwrap())
}

fn base_anchor_ms() -> u64 {
    ms(&fixture()["base"]["anchor_at"]).unwrap()
}

#[test]
fn fixture_bytes_are_the_pinned_wire_fixture() {
    let digest = Sha256::digest(FIXTURE.as_bytes());
    let hex = digest.iter().map(|b| format!("{b:02x}")).collect::<String>();
    assert_eq!(hex, FIXTURE_SHA256);
}

/// Every fixture `member` case: the class the daemon assigns.
#[test]
fn member_classes_follow_the_fixture() {
    let anchor_ms = base_anchor_ms();
    let mut seen = 0;
    for case in fixture()["cases"].as_array().unwrap() {
        let Some(member) = case.get("member") else {
            continue;
        };
        let flag = |name: &str| member.get(name).and_then(|v| v.as_bool()) == Some(true);
        // Proof removes import debt: an exact receipt for every extent, the
        // existing zero-use evidence, or a proved zero length.
        let proof = flag("exact_all_extents")
            || member.get("no_upload_required").is_some()
            || flag("zero_length_proved");
        let mut reason_bits = 0;
        if flag("unread") {
            reason_bits |= UNREAD;
        }
        if flag("other_hold") {
            reason_bits |= HELD_REVISION;
        }
        let owed = (!proof).then_some(DebtSummary {
            earliest_unacked_change_at: Some(anchor_ms - 1),
            lower_bound: true,
            reason_bits,
            disposition: None,
        });
        let inputs = Inputs {
            unknown: flag("unknown"),
            owed,
            proof,
            policy: flag("policy"),
            mtime_ms: Some(anchor_ms - DAY_MS),
            bytes: 10,
        };
        let class = observe(anchor_ms, anchor_ms, &inputs, None)
            .expect("an import member is admitted")
            .member
            .class;
        let expected = match case["class"].as_str().unwrap() {
            "failed" => Class::Failed,
            "done" => Class::Done,
            "held" => Class::Held,
            "owed" => Class::Owed,
            other => panic!("unknown class {other}"),
        };
        assert_eq!(class, expected, "{}", case["id"]);
        seen += 1;
    }
    assert_eq!(seen, 6);
}

/// Every fixture case with `obstructions` and an expected `complete_since`.
#[test]
fn complete_since_follows_the_fixture_obstructions() {
    let fixture = fixture();
    let anchor_ms = base_anchor_ms();
    let now_ms = anchor_ms + 1000;
    let mut seen = 0;
    for case in fixture["cases"].as_array().unwrap() {
        let Some(obstructions) = case.get("obstructions").and_then(|v| v.as_array()) else {
            continue;
        };
        let expected = case["expect"]
            .get("complete_since")
            .or_else(|| case["patch"].get("complete_since"))
            .map(ms);
        let mut summary = Summary {
            anchor_at_ms: anchor_ms,
            certified_at_ms: Some(anchor_ms),
            ..Summary::default()
        };
        for obstruction in obstructions {
            let witness = ms(&obstruction["at"]);
            summary.counts.obstruct[usize::from(bucket(anchor_ms, witness, now_ms))] += 1;
        }
        if let Some(expected) = expected {
            assert_eq!(complete_since(&summary), expected, "{}", case["id"]);
            seen += 1;
        }
    }
    assert_eq!(seen, 7);
    // Before the listing is certified there is no suffix.
    let uncertified = Summary {
        anchor_at_ms: anchor_ms,
        ..Summary::default()
    };
    assert_eq!(complete_since(&uncertified), None);
}

/// The fixture `base` block (partition) is exactly what the daemon sends for
/// the same committed totals.
#[test]
fn block_matches_the_fixture_base() {
    let fixture = fixture();
    let anchor_ms = base_anchor_ms();
    let mut counts = Counts::default();
    for class in [Class::Done, Class::Held, Class::ExcludedPolicy, Class::Owed] {
        let member = Member {
            class,
            bucket: (FIRST_READ_BUCKETS - 1) as u8,
            bytes: 100,
        };
        counts = counts_with(counts, member);
    }
    let summary = Summary {
        anchor_at_ms: anchor_ms,
        certified_at_ms: Some(anchor_ms),
        counts,
        sources_enabled: 0,
        done_at_ms: None,
    };
    let block = block(&summary, anchor_ms, 0b111);
    assert_eq!(serde_json::to_value(&block).unwrap(), fixture["base"]);
}

/// Counts after adding `member`, through the store's own tally.
fn counts_with(mut counts: Counts, member: Member) -> Counts {
    counts.add_for_test(member);
    counts
}

/// While open `computed_at` strictly increases and the live promise is sent
/// (with the envelope source); once frozen the block is the same bytes.
#[test]
fn open_block_increases_and_frozen_block_repeats() {
    let anchor_ms = base_anchor_ms();
    let mut state = Blocks {
        namespace: "ns".to_owned(),
        sources: Some(bit(SnapshotSource::Codex)),
        ..Blocks::default()
    };
    let open = Summary {
        anchor_at_ms: anchor_ms,
        sources_enabled: bit(SnapshotSource::Pi),
        ..Summary::default()
    };
    state.summaries.insert(SnapshotSource::ClaudeCode.api_slug(), open);
    let first = state.block("ns", SnapshotSource::ClaudeCode, anchor_ms + 5).unwrap();
    let second = state.block("ns", SnapshotSource::ClaudeCode, anchor_ms + 5).unwrap();
    assert!(second.computed_at > first.computed_at);
    assert_eq!(first.sources_enabled, ["claude_code", "codex"]);
    assert!(!first.done && !first.listing_complete && first.complete_since.is_none());
    assert!(state.block("other", SnapshotSource::ClaudeCode, anchor_ms).is_none());

    let frozen = Summary {
        certified_at_ms: Some(anchor_ms),
        done_at_ms: Some(anchor_ms + 9),
        ..open
    };
    state.summaries.insert(SnapshotSource::ClaudeCode.api_slug(), frozen);
    let terminal = state.block("ns", SnapshotSource::ClaudeCode, anchor_ms + 50).unwrap();
    let again = state.block("ns", SnapshotSource::ClaudeCode, anchor_ms + 99).unwrap();
    assert_eq!(terminal, again);
    assert!(terminal.done);
    assert_eq!(terminal.computed_at, instant(anchor_ms + 9));
    // The frozen promise, plus the envelope source.
    assert_eq!(terminal.sources_enabled, ["claude_code", "pi"]);
    assert_eq!(terminal.complete_since, Some(instant(boundaries(anchor_ms)[0])));
}

#[test]
fn instants_are_utc_milliseconds() {
    assert_eq!(instant(0), "1970-01-01T00:00:00.000Z");
    assert_eq!(instant(base_anchor_ms() + 7), "2026-11-12T12:00:00.007Z");
}

/// Import debt is debt from before the anchor (or a lower bound); a file
/// whose only debt is a change after the anchor is not admitted, but an
/// existing member with such debt is reclassified, never dropped.
#[test]
fn live_only_debt_is_not_admitted_but_members_stay() {
    let anchor_ms = base_anchor_ms();
    let live = Inputs {
        unknown: false,
        owed: Some(DebtSummary {
            earliest_unacked_change_at: Some(anchor_ms + 1),
            lower_bound: false,
            reason_bits: UNREAD,
            disposition: None,
        }),
        proof: false,
        policy: false,
        mtime_ms: Some(anchor_ms + 1),
        bytes: 5,
    };
    assert!(observe(anchor_ms, anchor_ms + 10, &live, None).is_none());
    let prior = Member {
        class: Class::Owed,
        bucket: 4,
        bytes: 5,
    };
    let kept = observe(anchor_ms, anchor_ms + 10, &live, Some(prior)).unwrap();
    assert!(kept.debt_gone, "its import debt left");
    // A pre-anchor file that grew after the anchor stays import debt.
    let grown = Inputs {
        owed: Some(DebtSummary {
            lower_bound: true,
            ..live.owed.unwrap()
        }),
        ..live
    };
    let member = observe(anchor_ms, anchor_ms + 10, &grown, None).unwrap();
    assert_eq!(member.member.class, Class::Owed);
    assert!(!member.debt_gone);
}

#[test]
fn buckets_follow_the_boundaries() {
    let anchor_ms = base_anchor_ms();
    let [b60, b30, b14, b7] = boundaries(anchor_ms);
    let now = anchor_ms + 1;
    assert_eq!(bucket(anchor_ms, Some(b60 - 1), now), 0);
    assert_eq!(bucket(anchor_ms, Some(b60), now), 1);
    assert_eq!(bucket(anchor_ms, Some(b30), now), 2);
    assert_eq!(bucket(anchor_ms, Some(b14), now), 3);
    assert_eq!(bucket(anchor_ms, Some(b7), now), 4);
    assert_eq!(bucket(anchor_ms, Some(anchor_ms), now), 4);
    assert_eq!(bucket(anchor_ms, None, now), 4);
    assert_eq!(bucket(anchor_ms, Some(now + 1), now), 4);
}
