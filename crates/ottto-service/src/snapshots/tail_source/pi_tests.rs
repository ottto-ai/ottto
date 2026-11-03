//! The Pi Tail codec on real parses of synthetic transcripts: every field
//! home round-trips, including the usage ledger, the hourly usage buckets,
//! the accepted totals and the fork state; missing or inconsistent state is a
//! reconstruction cause.
use super::super::seam::TailBase;
use super::*;
use crate::snapshots::sampled_jsonl::CachedJsonlReduction;
use crate::snapshots::sampled_scan::transition_fixture::native_cold as fixture;
use crate::snapshots::state_v2::{Change, StagedFile};
use crate::transcript_acquisition::{ReadMode, Scope};
use serde_json::json;
use std::sync::atomic::{AtomicUsize, Ordering};

const NOW: u64 = 1_790_000_000;
const SESSION: &str = "synthetic-pi-tail-session";

/// A header (naming `parent` when set), a user prompt, then `responses`
/// assistant turns a minute apart, each with its own response id. The first
/// `paired` turns are repeated as `message_end`, which pairs them.
fn lines(responses: usize, paired: usize, parent: Option<&str>) -> Vec<String> {
    let at = |minute: usize| format!("2026-10-27T{:02}:{:02}:00Z", 6 + minute / 60, minute % 60);
    let mut lines = vec![
        json!({"type":"session","version":3,"id":SESSION,"timestamp":at(0),
            "cwd":"/tmp/tail-pi","parentSession":parent})
        .to_string(),
        json!({"type":"message","id":"u0","parentId":null,"timestamp":at(0),
            "message":{"role":"user","content":[{"type":"text","text":"please review the change"}],
                "timestamp":1793080800000u64}})
        .to_string(),
    ];
    for i in 0..responses {
        let turn = json!({"type":"message","id":format!("a{i:04}"),"parentId":"u0",
            "timestamp":at(i + 1),"message":{"role":"assistant","provider":"openai",
                "model":"gpt-5.4","api":"openai-responses","timestamp":at(i + 1),
                "responseId":format!("response-{i:04}"),"stopReason":"stop",
                "content":[{"type":"text","text":"Synthetic answer."}],
                "usage":{"input":10 + i,"output":2,"cacheRead":3,"cacheWrite":4,
                    "totalTokens":19 + i,"cost":{"total":0.001}}}});
        lines.push(turn.to_string());
        if i < paired {
            let mut end = turn;
            end["type"] = json!("message_end");
            lines.push(end.to_string());
        }
    }
    lines
}

/// A cold positioned Full read: the PRE-finalization reduction and the
/// checkpoint's certificate.
fn parse(lines: &[String]) -> (CachedJsonlReduction, DurableCertificate) {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let dir = std::env::temp_dir().join(format!(
        "ottto-tail-pi-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("session.jsonl");
    std::fs::write(&path, lines.join("\n") + "\n").unwrap();
    let scope = Scope("tail-pi-codec".into());
    let mut parser = fixture::parser(
        SnapshotSource::Pi,
        &path,
        File::open(&path).unwrap(),
        apply_pi_line,
    );
    let mode = parser.prepare_acquisition(None, &scope, None, NOW).unwrap();
    assert!(matches!(mode, ReadMode::Full(_)));
    let (reduction, checkpoint) = fixture::finish_record(&mut parser, &scope, NOW);
    std::fs::remove_dir_all(&dir).unwrap();
    (reduction, checkpoint.durable_certificate(0).unwrap())
}

fn identity() -> HeadIdentity {
    let root = Path::new("/home/projects");
    HeadIdentity::new(
        Path::new("/state/pi-scan-index.json"),
        SnapshotSource::Pi,
        root,
        &root.join("session.jsonl"),
        false,
    )
}

/// A complete stage: an empty base's `Reset`.
fn stage_full(
    view: &PreFinalization<'_>,
    certificate: &DurableCertificate,
    id: &HeadIdentity,
) -> StagedFile {
    TailBase::default()
        .stage::<Pi>(view, certificate, id, Change::Reset)
        .unwrap()
        .expect("a reset always stages")
}

fn stage(reduction: &CachedJsonlReduction, certificate: &DurableCertificate) -> StagedFile {
    let (acc, report, scalars) = reduction.finish_view();
    let view = PreFinalization::new(acc, report, scalars);
    stage_full(&view, certificate, &identity())
}

fn copy(staged: &StagedFile) -> StagedFile {
    StagedFile {
        revision: staged.revision,
        head: staged.head.clone(),
        collections: staged.collections.clone(),
        pages: staged.pages.clone(),
        obsolete: staged.obsolete.clone(),
        change: staged.change,
    }
}

/// Head first, then every page in key order, then the codec contract.
fn load(
    staged: &StagedFile,
    into: &mut SnapshotAccumulator,
) -> Result<DecodedHead, ReconstructCause> {
    let head = Pi::decode_head(staged.revision, &staged.head, into)?;
    for (&(collection, page), bytes) in &staged.pages {
        Pi::decode_page(collection, page, bytes, into)?;
    }
    Pi::validate_loaded(into, &staged.collections)?;
    Ok(head)
}

/// [format] Every Pi field home round-trips: the ledger across a page
/// boundary with paired keys, the usage buckets by hour, the accepted totals
/// and the fork state; content only as session facts.
#[test]
fn every_pi_field_home_round_trips_through_head_and_pages() {
    let (reduction, certificate) = parse(&lines(300, 3, Some("synthetic-parent.jsonl")));
    let staged = stage(&reduction, &certificate);
    let (acc, _, _) = reduction.finish_view();
    assert_eq!(Pi::SOURCE, acc.source);
    assert_eq!(Pi::finish_field_nonempty(acc), None);
    let ledger = &acc.seen_pi_usage_keys;
    assert_eq!(ledger.usage_keys().len(), 300);
    assert_eq!(
        ledger
            .usage_keys()
            .values()
            .filter(|state| !state.paired_digests.is_empty())
            .count(),
        3
    );
    assert!(matches!(ledger.fork_parts(), (true, Some(_))));
    assert_eq!(acc.accepted_usage_totals.request_count, 300);
    let pages = |collection: Collection| {
        staged
            .pages
            .keys()
            .filter(|(stored, _)| *stored == collection)
            .count()
    };
    // Pi sets no title before finish: first prompt and workspace facts only.
    assert_eq!(
        [
            Collection::PiUsageKeys,
            Collection::UsageHours,
            Collection::SessionFacts
        ]
        .map(pages),
        [2, 6, 2]
    );
    let contents: [&[u8]; 2] = [b"please review", b"/tmp/tail-pi"];
    let holds =
        |value: &[u8], content: &[u8]| value.windows(content.len()).any(|window| window == content);
    for (key, value) in std::iter::once((None, &staged.head))
        .chain(staged.pages.iter().map(|(key, value)| (Some(key), value)))
    {
        if key.is_some_and(|(collection, _)| *collection == Collection::SessionFacts) {
            continue;
        }
        for content in contents {
            assert!(!holds(value, content), "content outside the session facts");
        }
    }
    for (slot, content) in [(1, contents[0]), (2, contents[1])] {
        assert!(holds(
            &staged.pages[&(Collection::SessionFacts, slot)],
            content
        ));
    }

    let mut loaded = SnapshotAccumulator::new(SnapshotSource::Pi);
    let head = load(&staged, &mut loaded).unwrap();
    assert_eq!(head.certificate, certificate);
    assert_eq!(
        (
            &loaded.workspace_path,
            &loaded.first_prompt_material,
            &loaded.first_prompt_title
        ),
        (
            &acc.workspace_path,
            &acc.first_prompt_material,
            &acc.first_prompt_title
        )
    );
    assert_eq!(
        loaded.seen_pi_usage_keys.fork_parts(),
        acc.seen_pi_usage_keys.fork_parts()
    );
    assert!(loaded.accepted_usage_totals == acc.accepted_usage_totals);

    // The loaded state encodes to exactly the stored head and pages.
    let view = PreFinalization::new(&loaded, &head.report, head.scalars);
    let again = stage_full(&view, &head.certificate, &identity());
    assert_eq!(
        (
            again.revision,
            &again.head,
            &again.pages,
            &again.collections
        ),
        (
            staged.revision,
            &staged.head,
            &staged.pages,
            &staged.collections
        )
    );

    let mut live = acc.clone();
    live.account_identifier_hash = Some("a".repeat(64));
    assert_eq!(
        Pi::finish_field_nonempty(&live),
        Some("account_identifier_hash")
    );
}

/// [format] Missing or inconsistent stored state is a reconstruction cause,
/// never a default-empty success; empty required collections are staged.
#[test]
fn missing_or_inconsistent_pi_state_is_a_reconstruction() {
    let (reduction, certificate) = parse(&lines(300, 0, None));
    let staged = stage(&reduction, &certificate);
    let fresh = || SnapshotAccumulator::new(SnapshotSource::Pi);
    let load_edited = |edit: &dyn Fn(&mut StagedFile)| {
        let mut edited = copy(&staged);
        edit(&mut edited);
        load(&edited, &mut fresh()).map(|_| ())
    };
    assert_eq!(load_edited(&|_| {}), Ok(()));
    assert_eq!(
        load_edited(&|staged| {
            staged.pages.remove(&(Collection::PiUsageKeys, 1));
        }),
        Err(ReconstructCause::Incomplete)
    );
    assert_eq!(
        load_edited(&|staged| {
            staged.collections.remove(&Collection::UsageHours);
        }),
        Err(ReconstructCause::Incomplete)
    );
    assert_eq!(
        load_edited(&|staged| staged.revision = 0),
        Err(ReconstructCause::Incompatible)
    );
    let mut loaded = fresh();
    Pi::decode_head(staged.revision, &staged.head, &mut loaded).unwrap();
    assert_eq!(
        Pi::decode_page(
            Collection::PiUsageKeys,
            1,
            &staged.pages[&(Collection::PiUsageKeys, 1)],
            &mut loaded
        ),
        Err(ReconstructCause::Corrupt)
    );

    // A key with no recorded occurrence breaks the reducer's fact.
    let (mut emptied, certificate) = parse(&lines(2, 0, None));
    emptied
        .accumulator_for_test()
        .seen_pi_usage_keys
        .usage_keys_mut()
        .insert("0".repeat(64), PiUsageDedupState::default());
    let staged = stage(&emptied, &certificate);
    assert_eq!(
        load(&staged, &mut fresh()).map(|_| ()),
        Err(ReconstructCause::Corrupt)
    );
    // Nor an unmatched count of zero: a later pairing would underflow it.
    let (mut zeroed, certificate) = parse(&lines(2, 0, None));
    let mut state = PiUsageDedupState::default();
    state.message.insert("1".repeat(64), 0);
    zeroed
        .accumulator_for_test()
        .seen_pi_usage_keys
        .usage_keys_mut()
        .insert("0".repeat(64), state);
    let staged = stage(&zeroed, &certificate);
    assert_eq!(
        load(&staged, &mut fresh()).map(|_| ()),
        Err(ReconstructCause::Corrupt)
    );

    // A header time without a parent never comes from the reducer.
    let (mut orphan, certificate) = parse(&lines(2, 0, None));
    orphan.accumulator_for_test().seen_pi_usage_keys.fork = Some(Box::new(PiFork {
        has_parent: false,
        header_nanos: Some(1),
    }));
    let staged = stage(&orphan, &certificate);
    assert_eq!(
        Pi::decode_head(staged.revision, &staged.head, &mut fresh()).map(|_| ()),
        Err(ReconstructCause::Corrupt)
    );

    // No usage: both usage collections are still staged, empty and without
    // pages.
    let (quiet, certificate) = parse(&lines(0, 0, None));
    let staged = stage(&quiet, &certificate);
    for collection in [Collection::PiUsageKeys, Collection::UsageHours] {
        assert_eq!(staged.collections[&collection].elements, 0);
        assert!(!staged.pages.keys().any(|(stored, _)| *stored == collection));
    }
    let mut edited = copy(&staged);
    load(&edited, &mut fresh()).unwrap();
    edited.collections.remove(&Collection::PiUsageKeys);
    assert_eq!(
        load(&edited, &mut fresh()).map(|_| ()),
        Err(ReconstructCause::Incomplete)
    );
}
