//! A destination's first production load, durable save and restarted Tail.
use super::super::claude::Claude;
use super::super::codex::Codex;
use super::super::load::Load;
use super::super::pi::Pi;
use super::tests::{scope, Route, NOW};
use super::transition_tests::{self as transition, FixtureSource};
use super::*;
use crate::snapshots::scan_index_persistence::Source;

impl FixtureSource for Pi {
    const INDEX: Source = Source::Pi;
    const APPLY: fn(&serde_json::Value, &mut SnapshotAccumulator) = apply_pi_line;
    fn name() -> String {
        "session.jsonl".into()
    }
    fn lines(size: usize) -> Vec<String> {
        super::super::pi::tests::lines(size, 0, None)
    }
}

/// [regress] A fresh destination commits its first Tail before a restart;
/// an unchanged pass reads nothing and an append reads only its suffix.
#[test]
fn fresh_destination_first_cycle_keeps_tail_across_restart() {
    fn check<S: FixtureSource>() {
        for presence in ["missing-parent", "missing-root", "present-v1"] {
            let scratch = crate::test_scratch::ScratchDir::canonical("fresh-destination-tail");
            let dir = scratch.to_path_buf();
            let path = dir
                .join("snapshots/destinations")
                .join("b".repeat(64))
                .join(format!("{}-test-scan-index.json", S::SOURCE.api_slug()));
            if presence != "missing-parent" {
                std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            }
            if presence == "present-v1" {
                std::fs::write(&path, serde_json::to_vec(&ScanIndex::default()).unwrap()).unwrap();
            }
            let index = ScanIndex::load_for_snapshot_source(&path, S::SOURCE, &dir).unwrap();
            assert!(
                index.v2().persistence_v2.is_some(),
                "before first collection"
            );
            let mut route = Route {
                _session: None,
                dir,
                path,
                index,
            };
            let transcript = route.dir.join(S::name());
            let lines = S::lines(3);
            let more = S::lines(4);
            let prefix = lines.iter().zip(&more).take_while(|(a, b)| a == b).count();
            let lines = &lines[..prefix];
            std::fs::write(&transcript, lines.join("\n") + "\n").unwrap();
            let (tail, native) = transition::complete::<S>(&route, &transcript, None, |_| {});
            let key = tail.key.clone();
            assert!(tail.publish(&native));
            route
                .index
                .accepted_snapshot_fingerprints
                .insert("a".repeat(64));
            route.index.save(&route.path).unwrap();
            assert!(state_v2::tail_head_keys(&route.index)
                .unwrap()
                .contains(&key));
            let accepted = route.index.accepted_snapshot_fingerprints.clone();
            // End the old pass and close its connection, as the crash fixtures
            // do; the completed save, rather than an in-memory stage, is custody.
            drop(state_v2::BaselineRelease::new(&route.path, &route.index));
            state_v2::invalidate_tree(&route.dir).unwrap();
            route.index =
                ScanIndex::load_for_snapshot_source(&route.path, S::SOURCE, &route.dir).unwrap();
            assert_eq!(route.index.accepted_snapshot_fingerprints, accepted);
            let unrouted = super::super::counters::total("tail_bootstrap_full", "unrouted");
            let sealed = std::fs::metadata(&transcript).unwrap().len();
            for append in [false, true] {
                if append {
                    // Preserve the opened object and every prefix byte.
                    let suffix = more[prefix..].join("\n") + "\n";
                    std::fs::OpenOptions::new()
                        .append(true)
                        .open(&transcript)
                        .unwrap()
                        .write_all(suffix.as_bytes())
                        .unwrap();
                }
                let Load::Reused(taken, Some(base)) =
                    transition::load_at::<S>(&route, &transcript, &key)
                else {
                    panic!("first saved Tail survives for {:?}/{presence}", S::SOURCE);
                };
                let mut parser = transition::open::<S>(&transcript);
                let mode = parser
                    .prepare_acquisition_owned(Some(taken), &scope(), None, NOW)
                    .unwrap();
                if append {
                    assert!(matches!(mode, ReadMode::Tail));
                    assert_eq!(
                        parser.reader.acquisition.as_ref().unwrap().start_offset(),
                        sealed
                    );
                    while !parser.step().unwrap() {}
                    assert_eq!(
                        parser.reader.consumed_bytes(),
                        std::fs::metadata(&transcript).unwrap().len() - sealed
                    );
                    let (tail, native) =
                        transition::finish::<S>(&route, &transcript, parser, Some(base), |_| {});
                    assert!(tail.publish(&native));
                    let mut cold = transition::open::<S>(&transcript);
                    cold.prepare_acquisition(None, &scope(), None, NOW).unwrap();
                    while !cold.step().unwrap() {}
                    let (_, expected) =
                        transition::finish::<S>(&route, &transcript, cold, None, |_| {});
                    assert_eq!(
                        serde_json::to_value(native.unwrap().snapshots).unwrap(),
                        serde_json::to_value(expected.unwrap().snapshots).unwrap()
                    );
                } else {
                    assert!(matches!(mode, ReadMode::Unchanged));
                    assert_eq!(parser.reader.consumed_bytes(), 0);
                }
                assert_eq!(
                    super::super::counters::total("tail_bootstrap_full", "unrouted"),
                    unrouted
                );
            }
        }
    }
    check::<Claude>();
    check::<Codex>();
    check::<Pi>();
}
