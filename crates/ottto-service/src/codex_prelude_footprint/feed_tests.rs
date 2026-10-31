use super::*;
use crate::test_scratch::ScratchDir;
use std::mem::{align_of, size_of};

fn views(dir: &Path, count: usize) -> Vec<FileView> {
    (0..count)
        .map(|i| {
            let path = dir.join(format!("file{i}"));
            fs::write(&path, b"").unwrap();
            let (object, _) = FileObject::of(&fs::File::open(path).unwrap()).unwrap();
            FileView {
                source: SnapshotSource::Codex,
                object,
                mtime: Some(SystemTime::now()),
                mode: DeliveryMode::Full,
                root: Some(0),
                start: 0,
            }
        })
        .collect()
}

fn done(cwd: String, text: usize) -> State {
    State::Done(
        Box::new(CodexPrelude {
            cwd: Some(cwd),
            complete: true,
            first_input_tokens: Some(7),
            agents_md: Some(LoadedAgentsMd {
                directory: Some("/workspace".into()),
                text: "a".repeat(text),
            }),
            skills_body: Some("s".repeat(text / 2)),
            ..CodexPrelude::default()
        }),
        false,
    )
}

// Independent field/capacity oracle: no Counter, heap_bound, Entry::heap_bytes,
// Feed::bytes or metrics. Include the actual retained strings and Box layouts.
fn prelude_alloc(p: &CodexPrelude) -> usize {
    p.cwd.as_ref().map_or(0, String::capacity)
        + p.model.as_ref().map_or(0, String::capacity)
        + p.skills_body.as_ref().map_or(0, String::capacity)
        + p.agents_md.as_ref().map_or(0, |a| {
            a.text.capacity() + a.directory.as_ref().map_or(0, String::capacity)
        })
}
fn payload_alloc(e: &Entry) -> usize {
    e.home.capacity()
        + match &e.state {
            State::Unseen => 0,
            // Box accounting includes one alignment unit of allocator slack.
            State::Done(p, _) => {
                size_of::<CodexPrelude>() + align_of::<CodexPrelude>() + prelude_alloc(p)
            }
            State::Pending(o) => {
                size_of::<Observation>()
                    + align_of::<Observation>()
                    + prelude_alloc(&o.parser.prelude)
                    + o.parser.session_id.as_ref().map_or(0, String::capacity)
            }
        }
}
fn assert_allocations(f: &Feed) {
    let payload = f
        .files
        .iter()
        .map(|(_, e)| {
            let expected = payload_alloc(e);
            assert_eq!(e.bytes, expected, "cached charge must match owned fields");
            expected
        })
        .sum::<usize>();
    assert_eq!(f.payload_bytes, payload);
    let scopes = f.scopes.capacity() * size_of::<(String, String)>()
        + f.scopes
            .iter()
            .map(|(k, v)| k.capacity() + v.capacity())
            .sum::<usize>();
    assert_eq!(f.scope_bytes, scopes);
    // SwissTable buckets round to a power of two; include control bytes and
    // alignment separately. This native-layout estimate is not malloc/RSS.
    let buckets = if f.positions.capacity() == 0 {
        0
    } else {
        f.positions.capacity().next_power_of_two()
    };
    let table = buckets * (size_of::<(FileObject, usize)>() + 1) + usize::from(buckets > 0) * 32;
    let retained = size_of::<Feed>()
        + payload
        + scopes
        + f.files.capacity() * size_of::<(FileObject, Entry)>()
        + table;
    assert!(
        retained <= 4 * 1024 * 1024,
        "independent retained allocation estimate {retained}"
    );
    assert_eq!(f.positions.len(), f.files.len());
    for (i, (object, _)) in f.files.iter().enumerate() {
        assert_eq!(f.positions.get(object), Some(&i));
    }
}

#[test]
fn large_small_mix_has_independent_charges_and_byte_pressure_below_count_caps() {
    let dir = ScratchDir::new("prelude-mixed-layout");
    let files = views(&dir, 160);
    let mut f = Feed::default();
    for (i, view) in files.iter().enumerate() {
        let state = match i % 3 {
            0 => done(format!("/cwd/{i}"), 96 * 1024),
            1 => done(format!("/cwd/{i}"), 3),
            _ => State::Pending(Box::new(Observation {
                parser: CodexPreludeParser {
                    prelude: CodexPrelude {
                        skills_body: Some("p".repeat(96 * 1024)),
                        ..CodexPrelude::default()
                    },
                    session_id: Some("pending".into()),
                    ..CodexPreludeParser::default()
                },
                rows: 2,
                next: 42,
                terminal: false,
                capped: false,
            })),
        };
        f.put(view, dir.to_path_buf(), state);
        assert_allocations(&f);
    }
    assert!(f.evicted > 0);
    assert!(
        files.len() < 512,
        "byte pressure precedes even the scope count cap"
    );
    assert!(f
        .files
        .iter()
        .any(|(_, e)| matches!(e.state, State::Pending(_))));
    assert!(f
        .files
        .iter()
        .any(|(_, e)| matches!(e.state, State::Done(_, _))));
    let survivors = f.files.iter().map(|(id, _)| *id).collect::<Vec<_>>();
    for object in survivors {
        let view = files.iter().find(|v| v.object == object).unwrap();
        f.put(view, dir.to_path_buf(), done("/updated".into(), 1));
        let e = &f.files[*f.positions.get(&object).unwrap()].1;
        assert!(matches!(&e.state, State::Done(p, _) if p.cwd.as_deref() == Some("/updated")));
        assert_allocations(&f);
    }
}

#[test]
fn unseen_and_small_done_pressure_leave_survivors_updateable() {
    let dir = ScratchDir::new("prelude-small-pressure");
    let files = views(&dir, 1100);
    for unseen in [true, false] {
        let mut f = Feed::default();
        for (i, view) in files.iter().enumerate() {
            let state = if unseen {
                State::Unseen
            } else {
                done(format!("/cwd/{i}"), 0)
            };
            f.put(view, PathBuf::from("h".repeat(4096)), state);
            assert_allocations(&f);
        }
        assert!(f.evicted > 0, "pressure with unseen={unseen}");
        assert!(f
            .files
            .iter()
            .all(|(_, e)| matches!(e.state, State::Unseen) == unseen));
        let survivors = f
            .files
            .iter()
            .rev()
            .take(8)
            .map(|(id, _)| *id)
            .collect::<Vec<_>>();
        assert_eq!(survivors.len(), 8);
        for object in survivors {
            let view = files.iter().find(|v| v.object == object).unwrap();
            f.put(view, PathBuf::from("short"), done("/survivor".into(), 0));
            let e = &f.files[*f.positions.get(&object).unwrap()].1;
            assert!(matches!(&e.state, State::Done(p, _) if p.cwd.as_deref() == Some("/survivor")));
            assert_allocations(&f);
        }
    }
}

#[test]
fn scope_cache_at_512_and_513_is_pruned_and_charged() {
    let dir = ScratchDir::new("prelude-scope-boundary");
    let files = views(&dir, 513);
    for count in [512, 513] {
        let feed = CodexPreludeFeed::default();
        for (i, view) in files.iter().take(count).enumerate() {
            feed.lock()
                .put(view, dir.to_path_buf(), done(format!("/cwd/{i}"), 0));
        }
        feed.remember_scopes(
            (0..count)
                .map(|i| (format!("/cwd/{i}"), format!("{i:064x}")))
                .collect(),
        );
        let (_, scopes) = feed.snapshot(SystemTime::now());
        assert_eq!(scopes.len(), 512);
        assert_eq!(
            scopes
                .iter()
                .map(|(cwd, _)| cwd)
                .collect::<BTreeSet<_>>()
                .len(),
            512
        );
        assert_eq!(scopes[511].0, "/cwd/511");
        assert!(!scopes.iter().any(|(cwd, _)| cwd == "/cwd/512"));
        let f = feed.lock();
        assert_eq!(f.scopes.len(), 512);
        assert_eq!(f.evicted, 0);
        assert_allocations(&f);
    }
}

#[test]
fn churn_expiry_to_empty_releases_capacities_highwater_and_payloads() {
    let dir = ScratchDir::new("prelude-expiry-empty");
    let files = views(&dir, 160);
    let feed = CodexPreludeFeed::default();
    for view in &files {
        feed.lock()
            .put(view, dir.to_path_buf(), done("/cwd".into(), 64 * 1024));
    }
    feed.remember_scopes(vec![("/cwd".into(), "x".repeat(64))]);
    {
        let mut f = feed.lock();
        assert!(f.evicted > 0);
        assert!(!f.files.is_empty());
        assert!(f.table_slots > 8);
        assert!(f.files.capacity() > 8);
        assert_allocations(&f);
        for (_, e) in &mut f.files {
            e.mtime = SystemTime::UNIX_EPOCH;
        }
    }
    assert!(feed.snapshot(SystemTime::now()).0.is_empty());
    feed.remember_scopes(Vec::new());
    let f = feed.lock();
    assert!(f.files.is_empty());
    assert!(f.positions.is_empty());
    assert!(f.scopes.is_empty());
    assert_eq!(f.files.capacity(), 0);
    assert_eq!(f.positions.capacity(), 0);
    assert_eq!(f.scopes.capacity(), 0);
    assert_eq!(f.table_slots, 0);
    assert_eq!(f.payload_bytes, 0);
    assert_eq!(f.scope_bytes, 0);
    assert_allocations(&f);
}

#[test]
fn root_pairs_check_the_budget_before_copy_and_keep_no_partial_snapshot() {
    let feed = Arc::new(CodexPreludeFeed::default());
    let limit = (16 * 1024 - 64 - size_of::<(PathBuf, PathBuf)>()) / 2;
    let within = PathBuf::from("r".repeat(limit)); // canonicalize fails: lexical fallback
    let over = PathBuf::from("r".repeat(limit + 1));
    let observer = feed.observer(std::slice::from_ref(&within));
    assert_eq!(observer.root_ordinal(&within, &[]), Some(0));
    let observer = feed.observer(std::slice::from_ref(&over));
    assert_eq!(observer.root_ordinal(&over, &[]), None);
    let many = vec![PathBuf::from("r"); 400];
    assert_eq!(feed.observer(&many).root_ordinal(&many[0], &[]), None);
}

impl CodexPreludeFeed {
    pub(crate) fn done_for_test(&self) -> Vec<Start> {
        self.snapshot(SystemTime::now()).0
    }
}
