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
use crate::snapshots::claude_context_file_birth::KNOWN_COPY_WRITERS;
use crate::snapshots::session_start::SessionStartState;
use sha2::{Digest, Sha256};

/// Slots in this build's writer array.
const N: usize = KNOWN_COPY_WRITERS.len();
/// The latest stored line, as Unix nanos.
const LATEST: i64 = 1_792_000_000_123_456_789;

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

/// [money] A head stored before the last writer was appended loads as a
/// hit. The appended slot takes the stored `latest`, so a stored certificate
/// stays (all stored lines by an already-listed writer) and no stored line
/// is certified as the appended writer's own (lines of a then-unlisted
/// version moved every listed slot, so they read as another writer's).
#[test]
fn a_head_from_before_an_appended_writer_is_a_hit_that_keeps_its_certificate() {
    let mut route = route();
    let cutoff = i128::from(LATEST) - 1;
    // (file, slot 0 as stored, certified from `cutoff`)
    for (name, first, certified) in [
        ("listed-writer.jsonl", i64::MIN, true),
        ("other-writer.jsonl", LATEST, false),
    ] {
        let mut others = [LATEST; N];
        others[0] = first;
        let (path, key) = committed_spliced(&mut route, name, |acc| {
            let birth = &mut acc.claude_file_birth;
            birth.set_writer_for_test(LATEST, others);
            assert_eq!(birth.writer_certified_from_for_test(cutoff), certified);
            (
                birth.writer_bytes_for_test(N),
                birth.writer_bytes_for_test(N - 1),
            )
        });
        let (load, records) = loaded(&route, &path, &key);
        assert!(matches!(load, Load::Reused(..)), "{name}");
        assert_eq!(counted(&records), ("hit".into(), vec![]), "{name}");
        let acc = decoded(&route, &key);
        let birth = &acc.claude_file_birth;
        let (latest, decoded_others) = birth.writer_for_test();
        assert_eq!(latest, LATEST, "{name}");
        assert_eq!(decoded_others[..N - 1], others[..N - 1], "{name}");
        assert_eq!(decoded_others[N - 1], LATEST, "{name}: the stored latest");
        assert_eq!(
            birth.writer_certified_from_for_test(cutoff),
            certified,
            "{name}: the stored certificate is unchanged"
        );
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
        ("writers.jsonl", |acc| {
            let birth = &mut acc.claude_file_birth;
            birth.set_writer_for_test(LATEST, [i64::MIN; N]);
            (
                birth.writer_bytes_for_test(N),
                birth.writer_bytes_for_test(N + 1),
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
        let mut e = Enc::bytes(1 << 20);
        e.with_moved_field("OpeningCall.files", |e| value.put(e))
            .unwrap();
        e.into_bytes()
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
        let mut others = [LATEST; N];
        others[0] = i64::MIN;
        acc.claude_file_birth.set_writer_for_test(LATEST, others);
        acc.session_start.set_grown_for_test();
        let (parts, requests) = opening_lens(&acc.session_start);
        let (parts, requests) = acc.session_start.grown_bytes_for_test(parts, requests);
        stored = Some((
            acc.claude_file_birth.writer_bytes_for_test(N),
            parts,
            requests,
        ));
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

/// [money] Append-only pins. `KNOWN_COPY_WRITERS` is frozen (an append
/// re-enables a copy route); a stored head keeps writers by position, so the
/// listed prefix never changes. `Part` is stored by position too.
#[test]
fn stored_slot_lists_are_append_only() {
    assert!(
        KNOWN_COPY_WRITERS.starts_with(&["2.1.309", "2.1.310"]),
        "{KNOWN_COPY_WRITERS:?}"
    );
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
    s.text().to_owned()
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
    "eb8d23b04ff749971fa3fd272e5ee2a58f4b864d3e3d7f6115f8ec233c0231c8";

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
// The Codex dictionary and sidecar-binding `I` markers store no Claude bytes.
// Removing those markers reproduces the original pin; Claude's revision stays.
const CLAUDE_LAYOUT_SHA256: &str =
    "d53a827373fa276a4abb196e29f92f50600dda236cc95935deb146f1003beb2f";

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
