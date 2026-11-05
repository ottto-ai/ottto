//! The fixed-size arrays in the stored Claude Tail head are stored with
//! their length (`GrownArray`): a head written before a build appended a
//! slot loads as a hit, with the new slot at its neutral value; a stored
//! array longer than this build's is a counted corrupt reconstruction. The
//! slot lists are append-only, and the head and page layout is pinned, so a
//! drift fails here and forces a deliberate revision decision.
use super::super::claude::{tests::lines, Claude};
use super::super::seam::tests::{route, Route};
use super::tests::{counted, loaded};
use super::*;
use crate::durable_tail_codec::{Durable, Enc, Shape};
use crate::snapshots::claude_context_file_birth::retired_writer_bytes_for_test;
use crate::snapshots::session_start::SessionStartState;
use sha2::{Digest, Sha256};

/// Slots in the retired writer array.
const N: usize = 2;
/// The latest stored line, as Unix nanos.
const LATEST: i64 = 1_792_000_000_123_456_789;

/// The retired writer field as this build writes it: an empty certificate.
fn neutral_writer() -> Vec<u8> {
    retired_writer_bytes_for_test(i64::MIN, &[i64::MIN], N)
}

/// Replaces the one occurrence of `from` in `head` with `to`.
fn splice(head: &mut Vec<u8>, from: &[u8], to: &[u8]) {
    let found: Vec<usize> = head
        .windows(from.len())
        .enumerate()
        .filter(|(_, window)| *window == from)
        .map(|(at, _)| at)
        .collect();
    let &[at] = &found[..] else {
        panic!("the stored field occurs once, found {}", found.len());
    };
    *head = [&head[..at], to, &head[at + from.len()..]].concat();
}

/// A first completion of `lines(3)` as `name`. `prepare` sets state at PRE
/// and returns the stored bytes to replace and their replacement; the edited
/// head is staged and committed.
fn committed_spliced(
    route: &mut Route,
    name: &str,
    prepare: impl FnOnce(&mut SnapshotAccumulator) -> (Vec<u8>, Vec<u8>),
) -> (PathBuf, String) {
    let mut edit = None;
    let (mut tail, _native) = route.complete(name, &lines(3), None, |acc| {
        edit = Some(prepare(acc));
    });
    let key = tail.key_for_test().to_owned();
    let mut staged = tail.take_staged_for_test();
    let (from, to) = edit.expect("PRE ran");
    splice(&mut staged.head, &from, &to);
    state_v2::stage_tail(&route.path, &key, staged).unwrap();
    route.save(false);
    (route.dir.join(name), key)
}

/// The committed head of `key`, decoded.
fn decoded(route: &Route, key: &str) -> SnapshotAccumulator {
    let head = route.head(key).unwrap();
    let mut acc = SnapshotAccumulator::new(SnapshotSource::ClaudeCode);
    Claude::decode_head(head.revision, &head.body, &mut acc).unwrap();
    acc
}

/// The current lengths of `parts` and `requests`.
fn opening_lens(state: &SessionStartState) -> (usize, usize) {
    (
        state.parts_for_test().len(),
        state.requests_present_for_test().len(),
    )
}

/// [format] The retired writer certificate stays in the head layout: a head
/// that stored one (of either slot count) loads as a hit, the stored value
/// is dropped, and the next encode writes the empty certificate.
#[test]
fn a_stored_writer_certificate_loads_as_a_hit_and_is_dropped() {
    let mut route = route();
    for (name, slots) in [("one-writer.jsonl", N - 1), ("two-writers.jsonl", N)] {
        let stored = retired_writer_bytes_for_test(LATEST, &[LATEST - 1, i64::MIN], slots);
        let (path, key) =
            committed_spliced(&mut route, name, |_| (neutral_writer(), stored.clone()));
        let (load, records) = loaded(&route, &path, &key);
        assert!(matches!(load, Load::Reused(..)), "{name}");
        assert_eq!(counted(&records), ("hit".into(), vec![]), "{name}");
        let acc = decoded(&route, &key);
        let again = round_trips(&acc.claude_file_birth);
        let contains = |field: &[u8]| again.windows(field.len()).any(|w| w == field);
        assert!(contains(&neutral_writer()), "{name}: written empty");
        assert!(!contains(&stored), "{name}: the stored value is dropped");
    }
}

/// [behaviour] Opening `parts` and `requests` stored by a build with one
/// slot fewer load as a hit; the appended slot is 0 (part not seen) or
/// `None` (request not seen), the `Default` a fresh state starts from.
#[test]
fn opening_arrays_from_a_shorter_build_are_a_hit_with_neutral_new_slots() {
    let mut route = route();
    for (name, parts_shorter) in [("parts.jsonl", true), ("requests.jsonl", false)] {
        let mut stored = (Vec::new(), Vec::new());
        let (path, key) = committed_spliced(&mut route, name, |acc| {
            let state = &mut acc.session_start;
            state.set_grown_for_test();
            stored = (state.parts_for_test(), state.requests_present_for_test());
            let (parts, requests) = opening_lens(state);
            let now = state.grown_bytes_for_test(parts, requests);
            let old = state.grown_bytes_for_test(parts - 1, requests - 1);
            if parts_shorter {
                (now.0, old.0)
            } else {
                (now.1, old.1)
            }
        });
        let (load, records) = loaded(&route, &path, &key);
        assert!(matches!(load, Load::Reused(..)), "{name}");
        assert_eq!(counted(&records), ("hit".into(), vec![]), "{name}");
        let acc = decoded(&route, &key);
        let state = &acc.session_start;
        let (mut parts, mut requests) = stored;
        if parts_shorter {
            *parts.last_mut().unwrap() = 0;
        } else {
            *requests.last_mut().unwrap() = false;
        }
        assert_eq!(state.parts_for_test(), parts, "{name}");
        assert_eq!(state.requests_present_for_test(), requests, "{name}");
    }
}

/// [behaviour] A stored array longer than this build's is a counted corrupt
/// reconstruction, then a Full.
#[test]
fn a_longer_stored_array_is_a_counted_corrupt_reconstruction() {
    let mut route = route();
    type Longer = fn(&mut SnapshotAccumulator) -> (Vec<u8>, Vec<u8>);
    let cases: [(&str, Longer); 3] = [
        ("writers.jsonl", |_| {
            (
                neutral_writer(),
                retired_writer_bytes_for_test(LATEST, &[i64::MIN], N + 1),
            )
        }),
        ("parts.jsonl", |acc| {
            let state = &mut acc.session_start;
            state.set_grown_for_test();
            let (parts, requests) = opening_lens(state);
            (
                state.grown_bytes_for_test(parts, requests).0,
                state.grown_bytes_for_test(parts + 1, requests).0,
            )
        }),
        ("requests.jsonl", |acc| {
            let state = &mut acc.session_start;
            state.set_grown_for_test();
            let (parts, requests) = opening_lens(state);
            (
                state.grown_bytes_for_test(parts, requests).1,
                state.grown_bytes_for_test(parts, requests + 1).1,
            )
        }),
    ];
    for (name, longer) in cases {
        let (path, key) = committed_spliced(&mut route, name, longer);
        let (load, records) = loaded(&route, &path, &key);
        assert!(matches!(load, Load::Cold(_)), "{name}");
        assert_eq!(
            counted(&records),
            ("error".into(), vec!["corrupt".into()]),
            "{name}"
        );
    }
}

/// `value` put, taken back and put again: the same bytes both times.
fn round_trips<T: Durable>(value: &T) -> Vec<u8> {
    let put = |value: &T| {
        Enc::count_write(1 << 20, |e| {
            e.with_moved_field("OpeningCall.files", |e| value.put(e))
        })
        .unwrap()
    };
    let first = put(value);
    let mut d = crate::durable_tail_codec::Dec::new(&first);
    let back = T::take(&mut d).unwrap();
    d.finish().unwrap();
    assert_eq!(put(&back), first);
    first
}

/// [behaviour] The current shape round-trips byte-identical: the stored head
/// holds each array as its length then its slots, and encode, decode,
/// encode gives the same bytes.
#[test]
fn the_current_shape_round_trips_byte_identical() {
    let route = route();
    let mut stored = None;
    let (mut tail, _native) = route.complete("a.jsonl", &lines(3), None, |acc| {
        acc.session_start.set_grown_for_test();
        let (parts, requests) = opening_lens(&acc.session_start);
        let (parts, requests) = acc.session_start.grown_bytes_for_test(parts, requests);
        stored = Some((neutral_writer(), parts, requests));
    });
    let head = tail.take_staged_for_test().head;
    let (writer, parts, requests) = stored.expect("PRE ran");
    let once = |within: &[u8], field: &[u8]| {
        within.windows(field.len()).filter(|w| *w == field).count() == 1
    };
    for field in [&writer, &parts, &requests] {
        assert!(
            once(&head, field),
            "each array once, its length then its slots"
        );
    }
    let mut acc = SnapshotAccumulator::new(SnapshotSource::ClaudeCode);
    Claude::decode_head(Claude::REDUCTION_REVISION, &head, &mut acc).unwrap();
    assert!(once(&round_trips(&acc.claude_file_birth), &writer));
    let start = round_trips(&acc.session_start);
    assert!(once(&start, &parts) && once(&start, &requests));
}

/// [money] Append-only pin: `Part` is stored by position, so the listed
/// prefix never changes.
#[test]
fn stored_slot_lists_are_append_only() {
    let parts = SessionStartState::part_order_for_test();
    assert!(
        parts.starts_with(&[
            "Tools",
            "System",
            "Instructions",
            "Memory",
            "Skills",
            "Agents",
            "McpNames",
            "McpInstructions",
            "HooksEnv",
            "Prompt",
            "Other",
        ]),
        "{parts:?}"
    );
}

/// The Claude head and page layout in shape text: the envelope, the
/// selectors, every head field by class (nested types once each), then each
/// collection's geometry and element types.
fn claude_layout() -> String {
    let mut s = Shape::default();
    s.push("HeadIdentity{H binding;digest32;N capture;bool;H key_epoch;digest32;}");
    crate::transcript_acquisition::DurableCertificate::shape(&mut s);
    JsonlReadReport::shape(&mut s);
    <(usize, usize, bool)>::shape(&mut s);
    ClaudeSelectorTable::shape(&mut s);
    super::super::shape_fields(&mut s);
    for spec in Claude::collections() {
        s.push(&format!(
            "{:?} {:?} g={}",
            spec.collection, spec.shape, spec.g
        ));
    }
    String::shape(&mut s);
    ClaudeResponseObservation::shape(&mut s);
    ClaudeCompactionObservation::shape(&mut s);
    <(String, String, String)>::shape(&mut s);
    u64::shape(&mut s);
    // These ignored Codex-only markers store no Claude bytes. Keep the
    // Claude descriptor (and its pin) identical to main's shared shape.
    s.text()
        .replace(
            "I codex_dictionary_slots: crate::snapshots::codex_dictionary_slots::CodexDictionarySlots;",
            "",
        )
        .replace("I codex_sidecar_binding: Option<String>;", "")
}

/// The Codex head envelope, trailer, collection geometry, page elements and
/// full-content prelude fact. An appended grown-array slot keeps this shape.
fn codex_layout() -> String {
    let mut s = Shape::default();
    s.push("HeadIdentity{H binding;digest32;N capture;bool;H key_epoch;digest32;}");
    crate::transcript_acquisition::DurableCertificate::shape(&mut s);
    JsonlReadReport::shape(&mut s);
    <(usize, usize, bool)>::shape(&mut s);
    super::super::shape_fields(&mut s);
    super::super::codex::shape_layout(&mut s);
    s.text().to_owned()
}

const CODEX_LAYOUT_SHA256: &str =
    "07cecaf1a3d9559ba0e0c5c972c209d52549df484e8870b0d6b19cbad5e164f0";

/// [format] Codex's persisted head, pages and prelude fact have one layout pin.
#[test]
fn the_codex_head_page_and_prelude_layout_is_pinned() {
    let layout = codex_layout();
    let digest: String = Sha256::digest(layout.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    assert_eq!(
        digest, CODEX_LAYOUT_SHA256,
        "the Codex Tail layout changed; layout:\n{layout}"
    );
    assert!(layout.contains("G block_chars;[len];u64;"));
}

/// SHA-256 of `claude_layout()`. A change here is a layout change: decide
/// whether old heads still decode (a `G` append does), or bump
/// `Claude::REDUCTION_REVISION`, then update this pin.
// The binding is an ignored head field stored in Workspace v2; existing head
// bytes and Workspace v1 still decode without a reduction-revision change.
const CLAUDE_LAYOUT_SHA256: &str =
    "5d82dc2635e8104fc735492a148252575cdb503322e05552b5440c50ec06d7e9";

/// [money] Any drift of the stored Claude head or page layout fails here.
#[test]
fn the_claude_head_and_page_layout_is_pinned() {
    let layout = claude_layout();
    let digest: String = Sha256::digest(layout.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    assert_eq!(
        digest, CLAUDE_LAYOUT_SHA256,
        "the Claude Tail layout changed; layout:\n{layout}"
    );
    assert!(layout.contains("ClaudeOwnWriters;{N latest;i64;G others;[len];i64;}"));
    assert!(layout.contains("G parts;[len];u64;"));
    assert!(layout.contains("G requests;[len];Option<;OpeningRequest;"));
}
