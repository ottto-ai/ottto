//! Copy decisions on native folds, literal bodies and the saved index.
use super::*;
use crate::snapshot_sync::tests::{
    claude_money_e2_pipeline_tests::money_equivalence_tests::{corpus, input_clock, ReceiptBody},
    permanent_finish_pipeline_tests::once_credit_oracle_tests::money_equivalence_tests::emit_money,
};
use crate::snapshots::claude_money_birth_store::LocationKey;
use crate::snapshots::e2_pipeline_scan_fixture::{
    accepted_origin_hashes_for_test, route_of, upload_context_receipt_earned_for_test,
};
use e2::{money_mark as mark, pipeline_test_observer as observe};
use serde_json::Value;

const FIXTURE: &str = "claude_copy_decision_rows";
const EARLY: &str = "2026-08-02T07:00:00Z";
const LATE_NOTE: &str = "2026-08-02T08:06:10Z";
const KNOWN_IDS: &[&str] = &["a", "b", "c", "d", "r1", "r2", "agent-own"];

#[derive(Clone, Copy)]
enum Ack {
    Exact,
    Local,
    Unstored,
    UsageIdentical,
    Dominated,
}

impl Ack {
    fn answer(
        self,
        items: &[&SnapshotItem],
    ) -> Result<crate::snapshot_client::SnapshotBatchResponse> {
        let mut reply = ack(items)?;
        match self {
            Self::Exact => {}
            Self::Local => unreachable!("this page is saved without attempting upload"),
            Self::Unstored | Self::UsageIdentical | Self::Dominated => {
                for mut reference in std::mem::take(&mut reply.accepted_entities) {
                    reference.unchanged_basis = match self {
                        Self::UsageIdentical => Some("usage_identical".into()),
                        Self::Dominated => Some("dominated_by_head".into()),
                        _ => None,
                    };
                    if matches!(self, Self::Unstored) {
                        reference.body_witness_version = None;
                        reference.body_witness_digest = None;
                        reference.head_challenge =
                            reference.head_etag.take().map(|_| "c".repeat(64));
                        reply.accepted -= 1;
                        reply.sessions_reconciled -= 1;
                        reply.conflict_entities.push(reference);
                    } else {
                        reply.unchanged_entities.push(reference);
                    }
                }
            }
        }
        Ok(reply)
    }
}

type Groups = BTreeMap<(String, String), BTreeSet<String>>;

#[derive(Debug, PartialEq, Eq)]
struct Decision {
    groups: Groups,
    counted: BTreeSet<String>,
    main_copy: bool,
}

#[derive(Debug, PartialEq)]
struct Literal {
    session: String,
    counted: BTreeSet<(String, String)>,
    requests: u64,
    removed: u64,
    removed_usage: Value,
    disclosed: u64,
    marks: u8,
    last: String,
    grains: Vec<Value>,
}

#[derive(Default)]
struct Expected<'a> {
    literals: Vec<Literal>,
    groups: &'a [(&'a str, &'a str, &'a [&'a str])],
    holds: &'a [(&'a str, u64)],
    pending: &'a [&'a str],
}

/// Literal wire grain for the fixture's model and cache shape.
fn grain(at: &str, first: &str, last: &str, tokens: u64, count: u64, unproven: bool) -> Value {
    let mut row = json!({
        "model": "claude-haiku-4-5", "input_tokens": tokens, "output_tokens": tokens,
        "cache_read_tokens": 3 * count, "cache_creation_5m_tokens": 5 * count,
        "cache_creation_1h_tokens": 2 * count, "reasoning_output_tokens": 0,
        "request_count": count, "selector_context": {}, "selector_sources": {}
    });
    if unproven {
        row["copy_unproven"] = json!(true);
    }
    json!([at, first, last, row])
}

fn removed_usage(count: u64) -> Value {
    json!({
        "input_tokens": 10 * count, "output_tokens": 10 * count, "cache_read_tokens": 3 * count,
        "cache_creation_5m_tokens": 5 * count, "cache_creation_1h_tokens": 2 * count,
        "reasoning_output_tokens": 0, "unattributed_total_tokens": 0
    })
}

fn literal(
    session: &str,
    counted: &[(&str, &str)],
    removed: u64,
    disclosed: u64,
    last: &str,
    mut grains: Vec<Value>,
) -> Literal {
    grains.sort_by_key(Value::to_string);
    Literal {
        session: session.into(),
        counted: counted
            .iter()
            .map(|&(f, id)| (f.into(), id.into()))
            .collect(),
        requests: counted.len() as u64,
        removed,
        removed_usage: removed_usage(removed),
        disclosed,
        marks: mark::ESTIMATED
            | if removed > 0 { mark::COPY } else { 0 }
            | if disclosed > 0 { mark::DISCLOSED } else { 0 },
        last: last.into(),
        grains,
    }
}

struct Rows {
    corpus: Corpus,
    name: &'static str,
    paths: BTreeMap<&'static str, PathBuf>,
    inputs: BTreeMap<String, Vec<u8>>,
    bodies: Vec<ReceiptBody>,
    failures: Vec<String>,
}

impl Rows {
    fn new(name: &'static str) -> Self {
        Self {
            corpus: corpus(&format!("{FIXTURE}-{name}")),
            name,
            paths: BTreeMap::new(),
            inputs: BTreeMap::new(),
            bodies: Vec::new(),
            failures: Vec::new(),
        }
    }

    fn write(&mut self, alias: &'static str, relative: &str, text: &str, birth: &str) {
        let path = self.corpus.write_at(relative, text, birth);
        input_clock(&path);
        self.inputs.insert(
            format!("{}/{}/{relative}", self.name, self.inputs.len()),
            text.as_bytes().to_vec(),
        );
        self.paths.insert(alias, path);
    }

    fn loc(&self, alias: &str) -> LocationKey {
        location_key(&self.key(alias))
    }

    fn key(&self, alias: &str) -> String {
        self.paths[alias].to_string_lossy().into_owned()
    }

    fn alias(&self, loc: LocationKey) -> String {
        self.paths
            .iter()
            .find_map(|(&alias, path)| {
                (location_key(&path.to_string_lossy()) == loc).then_some(alias)
            })
            .unwrap_or("<unexpected location>")
            .into()
    }

    fn id(hash: u64) -> String {
        KNOWN_IDS
            .iter()
            .find(|id| claude_request_hash(id) == hash)
            .copied()
            .unwrap_or("<unexpected request>")
            .into()
    }

    fn equal<T: std::fmt::Debug + PartialEq>(
        &mut self,
        phase: &str,
        field: &str,
        actual: T,
        expected: T,
    ) {
        if actual != expected {
            self.failures.push(format!(
                "{} / {phase} / {field}\n  actual: {actual:?}\n  expected: {expected:?}",
                self.name
            ));
        }
    }

    fn groups(&self, index: &ScanIndex) -> Groups {
        self.paths
            .keys()
            .flat_map(|&alias| {
                index
                    .claude_copy_removals
                    .get(self.loc(alias))
                    .iter()
                    .map(move |(holder, ids)| {
                        (
                            (alias.to_owned(), self.alias(*holder)),
                            ids.iter().copied().map(Self::id).collect(),
                        )
                    })
            })
            .collect()
    }

    fn pending(&self, index: &ScanIndex) -> BTreeSet<String> {
        self.paths
            .keys()
            .filter(|&&alias| index.claude_copy_removals.pending(self.loc(alias)))
            .map(|&alias| alias.to_owned())
            .collect()
    }

    fn emitted(&self, item: &SnapshotItem) -> Literal {
        let mut grains = item
            .usage_buckets
            .iter()
            .flat_map(|bucket| {
                bucket.model_usage.iter().map(|row| {
                    json!([
                        bucket.bucket_start,
                        bucket.first_activity_at,
                        bucket.last_activity_at,
                        row
                    ])
                })
            })
            .collect::<Vec<_>>();
        grains.sort_by_key(Value::to_string);
        Literal {
            session: item.source_session_id.clone(),
            counted: item
                .request_contributions
                .iter()
                .flat_map(|(location, ids)| {
                    ids.iter()
                        .map(move |&hash| (self.alias(*location), Self::id(hash)))
                })
                .collect(),
            requests: item.request_count,
            removed: item.removed_request_count.expect("literal request body"),
            removed_usage: serde_json::to_value(&item.removed_usage).unwrap(),
            disclosed: observe::disclosed(std::slice::from_ref(item)),
            marks: e2::money_marks(item),
            last: item.source_last_activity_at.clone().unwrap_or_default(),
            grains,
        }
    }

    fn raw(&self, index: ScanIndex, files: &[&str], scanner: &E2ScanFixture) -> Page {
        let hints = files
            .iter()
            .map(|&alias| self.paths[alias].clone())
            .collect::<Vec<_>>();
        let mut page = self.corpus.raw(scanner, index, 100, true, &hints);
        let wanted = files
            .iter()
            .map(|&alias| self.loc(alias))
            .collect::<BTreeSet<_>>();
        // Some schedules separate acquisition from decision-page membership.
        page.scan.snapshots.retain(|item| {
            item.claude_money
                .as_deref()
                .and_then(e2::FileFold::location_key)
                .is_some_and(|location| wanted.contains(&location))
        });
        let folded = page
            .scan
            .snapshots
            .iter()
            .map(|item| {
                self.alias(
                    item.claude_money
                        .as_deref()
                        .unwrap()
                        .location_key()
                        .unwrap(),
                )
            })
            .collect::<BTreeSet<_>>();
        assert_eq!(
            folded,
            files.iter().map(|&f| f.into()).collect(),
            "{}: scheduled native folds",
            self.name
        );
        page
    }

    fn decisions(
        &mut self,
        phase: &str,
        items: &[SnapshotItem],
        index: &ScanIndex,
    ) -> BTreeMap<String, Decision> {
        let mut items = items.to_vec();
        let mut next = index.clone();
        let holders = unobserved(|| {
            let (updates, holders) =
                observe::capture_holders(|| e2::decide_page_copies(&mut items, index, None));
            updates.apply(&mut next);
            holders
        });
        let groups = self.groups(&next);
        items
            .iter()
            .filter_map(|item| {
                let location = item.claude_money.as_deref()?.location_key()?;
                let file = self.alias(location);
                if let Some(first) = holders.get(&location) {
                    let key = self.key(&file);
                    if index
                        .claude_request_census_for_test()
                        .get(&key)
                        .is_some_and(|r| r.proves_scan())
                    {
                        let selected =
                            e2::copied_file_holders_for_test(index, std::iter::once(key.as_str()));
                        let selected = selected.get(&key).map(|key| self.alias(location_key(key)));
                        let page = first.map(|holder| self.alias(holder));
                        self.equal(
                            phase,
                            &format!("{file} earliest holder (selector / page)"),
                            selected,
                            page,
                        );
                    }
                }
                let file_groups = groups
                    .iter()
                    .filter(|((copy, _), _)| copy == &file)
                    .map(|(location, ids)| (location.clone(), ids.clone()))
                    .collect();
                Some((
                    file,
                    Decision {
                        groups: file_groups,
                        counted: observe::counted_ids(item),
                        main_copy: holders.contains_key(&location),
                    },
                ))
            })
            .collect()
    }

    fn compare_save(
        &mut self,
        phase: &str,
        file: &str,
        original: &Decision,
        replay: &[SnapshotItem],
        saved: &ScanIndex,
    ) {
        let mut active = saved.clone();
        active.activate_upload_context("e2-synthetic-destination".into());
        let redecided = self.decisions(phase, replay, &active);
        let rerun = &redecided[file];
        self.equal(
            phase,
            &format!(
                "{file} save mark / change in decision (before: {original:?}, replay: {rerun:?})"
            ),
            active.claude_copy_removals.pending(self.loc(file)),
            original.groups != rerun.groups || original.counted != rerun.counted,
        );
    }

    fn step(
        &mut self,
        phase: &str,
        mut page: Page,
        answer: Ack,
        mut expected: Expected<'_>,
    ) -> ScanIndex {
        let native = page.scan.snapshots.clone();
        let decisions = self.decisions(phase, &native, &page.index);
        page.enrich(&self.corpus);
        let mut actual = page
            .scan
            .snapshots
            .iter()
            .filter(|item| crate::snapshots::claude_request_money::is_request_owned_literal(item))
            .map(|item| self.emitted(item))
            .collect::<Vec<_>>();
        actual.sort_by(|a, b| a.session.cmp(&b.session));
        expected.literals.sort_by(|a, b| a.session.cmp(&b.session));
        self.equal(phase, "literal rows", actual, expected.literals);
        let holds = page
            .disposition
            .request_owned_hold_reasons
            .iter()
            .filter(|(_, n)| **n != 0)
            .map(|(&why, &n)| (why, n))
            .collect::<BTreeMap<_, _>>();
        self.equal(
            phase,
            "holds",
            holds,
            expected.holds.iter().copied().collect(),
        );
        let before = page.committed.clone();
        let saved = if matches!(answer, Ack::Local) {
            page.finish();
            self.corpus.reload(&mut page.index)
        } else {
            let (saved, sent, progress, wire) =
                send_with_answer(&self.corpus, &before, page, |items| answer.answer(items));
            if !matches!(answer, Ack::Exact) {
                self.equal(
                    phase,
                    "unstored body ACKs",
                    progress.fresh_context_body_acks.len(),
                    0,
                );
            }
            if !wire.is_empty() {
                self.bodies.push(ReceiptBody::new(
                    serde_json::to_vec(&wire).unwrap(),
                    SnapshotSource::ClaudeCode,
                    sent,
                ));
            }
            saved
        };
        self.check_saved(phase, &saved, expected.groups, expected.pending);
        for (file, decision) in &decisions {
            if decision.main_copy && saved.files.contains_key(&self.key(file)) {
                self.compare_save(phase, file, decision, &native, &saved);
            }
        }
        saved
    }

    fn check_saved(
        &mut self,
        phase: &str,
        index: &ScanIndex,
        groups: &[(&str, &str, &[&str])],
        pending: &[&str],
    ) {
        self.equal(
            phase,
            "saved removal groups",
            self.groups(index),
            groups
                .iter()
                .map(|&(copy, holder, ids)| {
                    (
                        (copy.into(), holder.into()),
                        ids.iter().map(|&id| id.into()).collect(),
                    )
                })
                .collect(),
        );
        self.equal(
            phase,
            "saved re-check marks",
            self.pending(index),
            pending.iter().map(|&alias| alias.into()).collect(),
        );
    }
}

fn holder_row() -> Literal {
    literal(
        ROOT,
        &[("holder", "a")],
        0,
        0,
        A.1,
        vec![grain(EARLY, A.1, A.1, 10, 1, false)],
    )
}

fn copy_removed() -> Literal {
    literal(
        COPY,
        &[("copy", "c")],
        1,
        0,
        C.1,
        vec![grain(EARLY, C.1, C.1, 10, 1, false)],
    )
}

fn copy_disclosed() -> Literal {
    literal(
        COPY,
        &[("copy", "a"), ("copy", "c")],
        0,
        1,
        C.1,
        vec![grain(EARLY, A.1, C.1, 20, 2, false)],
    )
}

const REMOVED_A: &[(&str, &str, &[&str])] = &[("copy", "holder", &["a"])];

fn write_holder(rows: &mut Rows) {
    rows.write("holder", &file(ROOT), &resumed(ROOT, &[A]), EARLY);
}

fn write_copy(rows: &mut Rows, text: &str) {
    rows.write("copy", &file(COPY), text, BORN);
}

fn scan(rows: &Rows, index: ScanIndex, files: &[&str]) -> Page {
    let scanner = E2ScanFixture::clocked_collection();
    if let Some(route) = route_of(&index) {
        scanner.on_committed_route(&route);
    }
    rows.raw(index, files, &scanner)
}

fn earlier_holder(name: &'static str, ack: Ack) -> Rows {
    let mut rows = Rows::new(name);
    write_holder(&mut rows);
    let holder = scan(&rows, ScanIndex::default(), &["holder"]);
    let index = rows.step(
        "holder before copy",
        holder,
        ack,
        Expected {
            literals: vec![holder_row()],
            ..Expected::default()
        },
    );
    rows.equal(
        "holder before copy",
        "accepted request a",
        has(&index, &rows.paths["holder"], "a"),
        matches!(ack, Ack::Exact),
    );
    let index = cold_restart(index);
    write_copy(&mut rows, &resumed(COPY, &[A, C]));
    let copy = scan(&rows, index, &["copy"]);
    rows.step(
        "copy after restart",
        copy,
        Ack::Exact,
        Expected {
            literals: vec![copy_removed()],
            groups: REMOVED_A,
            ..Expected::default()
        },
    );
    rows
}

fn late_holder(name: &'static str, ack: Ack, mark_copy: bool) -> Rows {
    let mut rows = Rows::new(name);
    write_copy(&mut rows, &resumed(COPY, &[A, C]));
    let copy = scan(&rows, ScanIndex::default(), &["copy"]);
    let native = copy.scan.snapshots.clone();
    let reference = rows.decisions("initial decision", &native, &copy.index);
    let index = rows.step(
        "count copy first",
        copy,
        Ack::Exact,
        Expected {
            literals: vec![copy_disclosed()],
            ..Expected::default()
        },
    );
    let index = cold_restart(index);
    write_holder(&mut rows);
    let holder = scan(&rows, index, &["holder"]);
    let index = rows.step(
        "save later holder",
        holder,
        ack,
        Expected {
            literals: vec![holder_row()],
            pending: if mark_copy { &["copy"] } else { &[] },
            ..Expected::default()
        },
    );
    rows.equal(
        "save later holder",
        "accepted request a",
        has(&index, &rows.paths["holder"], "a"),
        matches!(ack, Ack::Exact),
    );
    let mut active = index.clone();
    active.activate_upload_context("e2-synthetic-destination".into());
    rows.equal(
        "save later holder",
        "holder exact receipt",
        upload_context_receipt_earned_for_test(&active, &rows.paths["holder"]),
        matches!(ack, Ack::Exact),
    );
    rows.compare_save(
        "later holder save",
        "copy",
        &reference["copy"],
        &native,
        &index,
    );
    if mark_copy {
        let mut index = index;
        let files = if matches!(ack, Ack::Exact) {
            // Positive trace sidecars put the two families in separate chunks.
            rows.corpus.evidence_for(ROOT, &[], &[trace("a", "")]);
            rows.corpus
                .evidence_for(COPY, &[], &[trace_for(COPY, "c", "")]);
            owe(&mut index);
            &["holder", "copy"][..]
        } else {
            &["copy"][..]
        };
        let correction = scan(&rows, index, files);
        let before = crate::snapshot_sync::evidence_chunks_for_test();
        let mut literals = vec![copy_removed()];
        if files.len() == 2 {
            literals.push(holder_row());
        }
        rows.step(
            "correction consumes mark",
            correction,
            Ack::Exact,
            Expected {
                literals,
                groups: REMOVED_A,
                ..Expected::default()
            },
        );
        rows.equal(
            "correction consumes mark",
            "evidence chunks",
            crate::snapshot_sync::evidence_chunks_for_test() - before,
            files.len(),
        );
    }
    rows
}

#[derive(Clone, Copy)]
enum HolderLoss {
    DeleteAccepted,
    DeleteLocal,
    Retire,
    Lossy,
}

fn holder_loss(name: &'static str, loss: HolderLoss) -> Rows {
    let mut rows = Rows::new(name);
    write_holder(&mut rows);
    let holder = scan(&rows, ScanIndex::default(), &["holder"]);
    let index = rows.step(
        "seed holder",
        holder,
        if matches!(loss, HolderLoss::DeleteLocal) {
            Ack::Local
        } else {
            Ack::Exact
        },
        Expected {
            literals: vec![holder_row()],
            ..Expected::default()
        },
    );
    write_copy(&mut rows, &resumed(COPY, &[A, C]));
    let copy = scan(&rows, index, &["copy"]);
    let native = copy.scan.snapshots.clone();
    let reference = rows.decisions("initial decision", &native, &copy.index);
    let mut index = rows.step(
        "save removal",
        copy,
        Ack::Exact,
        Expected {
            literals: vec![copy_removed()],
            groups: REMOVED_A,
            ..Expected::default()
        },
    );
    index.activate_upload_context("e2-synthetic-destination".into());
    match loss {
        HolderLoss::DeleteAccepted | HolderLoss::DeleteLocal => {
            std::fs::remove_file(&rows.paths["holder"]).unwrap();
            delete_holder_for_test(&mut index, &rows.key("holder"));
        }
        HolderLoss::Retire => observe::retire_census(&mut index, &file(ROOT)),
        HolderLoss::Lossy => observe::lossy_census(&mut index, &file(ROOT), &["b"]),
    }
    let index = rows.corpus.reload(&mut index);
    let removed = !matches!(loss, HolderLoss::DeleteLocal);
    rows.check_saved(
        "save holder loss",
        &index,
        if removed { REMOVED_A } else { &[] },
        if removed { &[] } else { &["copy"] },
    );
    rows.compare_save(
        "save holder loss",
        "copy",
        &reference["copy"],
        &native,
        &index,
    );
    let mut index = cold_restart(index);
    owe(&mut index);
    let copy = scan(&rows, index, &["copy"]);
    rows.step(
        "copy after restart",
        copy,
        Ack::Exact,
        Expected {
            literals: vec![if removed {
                copy_removed()
            } else {
                copy_disclosed()
            }],
            groups: if removed { REMOVED_A } else { &[] },
            ..Expected::default()
        },
    );
    rows
}

fn retired_parent() -> Rows {
    let mut rows = Rows::new("retired_named_parent");
    write_holder(&mut rows);
    let holder = scan(&rows, ScanIndex::default(), &["holder"]);
    let mut index = rows.step(
        "accept parent",
        holder,
        Ack::Exact,
        Expected {
            literals: vec![holder_row()],
            ..Expected::default()
        },
    );
    observe::retire_census(&mut index, &file(ROOT));
    let index = rows.corpus.reload(&mut index);
    write_copy(&mut rows, &(fork_ref(COPY, ROOT) + &resumed(COPY, &[A])));
    let page = scan(&rows, index, &["copy"]);
    rows.step(
        "all-copy named branch",
        page,
        Ack::Exact,
        Expected {
            literals: vec![literal(COPY, &[], 1, 0, "2026-08-02T07:03:00Z", vec![])],
            groups: REMOVED_A,
            ..Expected::default()
        },
    );
    rows
}

fn fresh_destination() -> Rows {
    let mut rows = Rows::new("fresh_destination_unstored");
    write_holder(&mut rows);
    let holder = scan(&rows, ScanIndex::default(), &["holder"]);
    let mut index = rows.step(
        "old destination accepts holder",
        holder,
        Ack::Exact,
        Expected {
            literals: vec![holder_row()],
            ..Expected::default()
        },
    );
    assert!(has(&index, &rows.paths["holder"], "a"));
    index.stamp_entity_upload_context_acks(
        "fresh-synthetic-destination",
        &BTreeMap::new(),
        &BTreeMap::new(),
    );
    owe(&mut index);
    let holder = scan(&rows, index, &["holder"]);
    let mut index = rows.step(
        "new destination does not store the holder",
        holder,
        Ack::UsageIdentical,
        Expected {
            literals: vec![holder_row()],
            ..Expected::default()
        },
    );
    assert!(!has(&index, &rows.paths["holder"], "a"));
    index.activate_upload_context("e2-synthetic-destination".into());
    // A refused predecessor offered on the new destination has no local body
    // to lend. Keep its census to distinguish observation from acceptance.
    index
        .file_snapshot_fingerprints
        .get_mut(&rows.key("holder"))
        .unwrap()
        .clear();
    let index = rows.corpus.reload(&mut index);
    write_copy(&mut rows, &resumed(COPY, &[A, C]));
    let page = scan(&rows, index, &["copy"]);
    rows.step(
        "fresh destination copy",
        page,
        Ack::Exact,
        Expected {
            literals: vec![copy_disclosed()],
            ..Expected::default()
        },
    );
    rows
}

fn twins(name: &'static str, distinct: bool, absent: bool) -> Rows {
    let mut rows = Rows::new(name);
    rows.write(
        "holder",
        &format!("first/{}", file(ROOT)),
        &resumed(ROOT, &[A]),
        EARLY,
    );
    let second = if distinct { B } else { A };
    rows.write(
        "twin",
        &format!("second/{}", file(ROOT)),
        &resumed(ROOT, &[second]),
        "2026-08-02T06:59:00Z",
    );
    let mut page = scan(&rows, ScanIndex::default(), &["holder", "twin"]);
    if absent {
        page.scan.snapshots.retain(|item| {
            item.claude_money.as_deref().unwrap().location_key() == Some(rows.loc("holder"))
        });
    }
    let row = match (distinct, absent) {
        (true, false) => vec![literal(
            ROOT,
            &[("holder", "a"), ("twin", "b")],
            0,
            0,
            B.1,
            vec![grain(EARLY, A.1, B.1, 20, 2, false)],
        )],
        (true, true) => vec![],
        (false, false) => vec![literal(
            ROOT,
            &[("twin", "a")],
            1,
            0,
            A.1,
            vec![grain(EARLY, A.1, A.1, 10, 1, false)],
        )],
        (false, true) => vec![holder_row()],
    };
    rows.step(
        "path twin decision",
        page,
        Ack::Exact,
        Expected {
            literals: row,
            holds: if distinct && absent {
                &[
                    ("absent_twin", 1),
                    ("known_twin_paths", 2),
                    ("staged_twin_paths", 1),
                ]
            } else {
                &[]
            },
            ..Expected::default()
        },
    );
    rows
}

fn latest_clock() -> Rows {
    let mut rows = Rows::new("summed_session_latest_clock");
    rows.write(
        "holder",
        &format!("first/{}", file(ROOT)),
        &resumed(ROOT, &[A]),
        EARLY,
    );
    let later_note = json!({"type":"user","sessionId":ROOT,"timestamp":LATE_NOTE,
        "message":{"role":"user","content":"later"}});
    rows.write(
        "twin",
        &format!("second/{}", file(ROOT)),
        &(resumed(ROOT, &[B]) + &later_note.to_string() + "\n"),
        EARLY,
    );
    let mut page = scan(&rows, ScanIndex::default(), &["holder", "twin"]);
    // The early file is the carrier even if filesystem order is reversed.
    page.scan.snapshots.sort_by_key(|item| {
        item.claude_money.as_deref().unwrap().location_key() != Some(rows.loc("holder"))
    });
    rows.step(
        "summed into the earlier carrier",
        page,
        Ack::Exact,
        Expected {
            literals: vec![literal(
                ROOT,
                &[("holder", "a"), ("twin", "b")],
                0,
                0,
                LATE_NOTE,
                vec![grain(EARLY, A.1, B.1, 20, 2, false)],
            )],
            ..Expected::default()
        },
    );
    rows
}

fn idless_copy() -> Rows {
    let mut rows = Rows::new("idless_prefix_restored_and_disclosed");
    let mut old: Value = serde_json::from_str(&line(COPY, "idless", A.1, 10)).unwrap();
    old.as_object_mut().unwrap().remove("requestId");
    write_copy(&mut rows, &(old.to_string() + "\n" + &resumed(COPY, &[C])));
    let mut index = ScanIndex::default();
    index.copy_unproven_enabled = true;
    let page = scan(&rows, index, &["copy"]);
    let mut expected = literal(
        COPY,
        &[("copy", "c")],
        0,
        1,
        C.1,
        vec![
            grain(EARLY, A.1, C.1, 10, 1, true),
            grain(EARLY, A.1, C.1, 10, 1, false),
        ],
    );
    expected.requests = 2;
    rows.step(
        "id-less prefix",
        page,
        Ack::Exact,
        Expected {
            literals: vec![expected],
            ..Expected::default()
        },
    );
    rows
}

#[derive(Clone, Copy)]
enum SameSession {
    RuleA,
    OnlyNewerOwned,
    HolderOffPage,
    AcceptedSum,
}

fn same_session(name: &'static str, variant: SameSession) -> Rows {
    let mut rows = Rows::new(name);
    let text = resumed(ROOT, &[A, C]);
    rows.write("copy", &format!("resume/{}", file(ROOT)), &text, BORN);
    let page = scan(&rows, ScanIndex::default(), &["copy"]);
    let initial = rows.decisions("initial decision", &page.scan.snapshots, &page.index);
    let mut counted = copy_disclosed();
    counted.session = ROOT.into();
    let mut index = rows.step(
        "only resume present",
        page,
        Ack::Exact,
        Expected {
            literals: vec![counted],
            ..Expected::default()
        },
    );

    rows.write(
        "holder",
        &format!("origin/{}", file(ROOT)),
        &resumed(ROOT, &[A]),
        EARLY,
    );
    owe(&mut index);
    let page = scan(&rows, index, &["holder", "copy"]);
    let mut replay = page.scan.snapshots.clone();
    if matches!(variant, SameSession::HolderOffPage) {
        replay.retain(|item| {
            item.claude_money.as_deref().unwrap().location_key() == Some(rows.loc("copy"))
        });
    }
    match variant {
        SameSession::RuleA => {
            rows.step(
                "co-read both paths",
                page,
                Ack::Exact,
                Expected {
                    literals: vec![literal(
                        ROOT,
                        &[("holder", "a"), ("copy", "c")],
                        1,
                        0,
                        C.1,
                        vec![grain(EARLY, A.1, C.1, 20, 2, false)],
                    )],
                    groups: REMOVED_A,
                    ..Expected::default()
                },
            );
        }
        SameSession::OnlyNewerOwned | SameSession::HolderOffPage => {
            let off_page = matches!(variant, SameSession::HolderOffPage);
            // Only the resume owns a local body in the one-owner schedule.
            let mut next = page.index;
            if off_page {
                accepted_origin_hashes_for_test(
                    &mut next,
                    &rows.key("holder"),
                    ROOT,
                    &[claude_request_hash("a")],
                );
            } else {
                next.file_snapshot_fingerprints.remove(&rows.key("holder"));
                hold_claude_account_for_test(&mut next, &rows.key("holder"));
            }
            let index = rows.corpus.reload(&mut next);
            rows.check_saved(
                "holder facts save",
                &index,
                &[],
                if off_page { &["copy"] } else { &[] },
            );
            rows.compare_save(
                "holder facts save",
                "copy",
                &initial["copy"],
                &replay,
                &index,
            );
            // Check the live page as well. This arm has a positive earlier
            // census but checks a different definition of admissible holder.
            if off_page {
                owe(&mut next);
                let page = scan(&rows, next, &["copy"]);
                rows.step(
                    "omit earlier path",
                    page,
                    Ack::Local,
                    Expected {
                        holds: &[
                            ("absent_twin", 1),
                            ("known_twin_paths", 2),
                            ("staged_twin_paths", 1),
                        ],
                        ..Expected::default()
                    },
                );
            }
        }
        SameSession::AcceptedSum => {
            let mut index = rows.step(
                "ACK summed contributor rows",
                page,
                Ack::Exact,
                Expected {
                    literals: vec![literal(
                        ROOT,
                        &[("holder", "a"), ("copy", "c")],
                        1,
                        0,
                        C.1,
                        vec![grain(EARLY, A.1, C.1, 20, 2, false)],
                    )],
                    groups: REMOVED_A,
                    ..Expected::default()
                },
            );
            rows.equal(
                "ACK summed contributor rows",
                "exact earlier contribution",
                has(&index, &rows.paths["holder"], "a"),
                true,
            );
            // Restore the holder census without changing the accepted sum.
            let holder = rows.key("holder");
            let census = index
                .claude_request_census_for_test()
                .get(&holder)
                .unwrap()
                .clone();
            index.claude_copy_removals.forget(rows.loc("copy"));
            index
                .claude_money_birth_store
                .set_money_marks(&rows.key("copy"), mark::DISCLOSED);
            index.claude_request_census_mut_for_test().remove(&holder);
            let mut index = rows.corpus.reload(&mut index);
            let before = rows.decisions("accepted sum with census gap", &replay, &index);
            index
                .claude_request_census_mut_for_test()
                .insert(holder, census);
            index.activate_upload_context("e2-synthetic-destination".into());
            let index = rows.corpus.reload(&mut index);
            rows.check_saved("restore accepted contributor census", &index, &[], &[]);
            rows.compare_save(
                "restore accepted contributor census",
                "copy",
                &before["copy"],
                &replay,
                &index,
            );
        }
    }
    rows
}

fn carrier(name: &'static str, hold_on_page: bool) -> Rows {
    let (c, mut index, [holder, copy, twin]) = settled_content_carrier(true);
    let mut rows = Rows {
        corpus: c,
        name,
        paths: BTreeMap::from([("holder", holder), ("copy", copy), ("twin", twin)]),
        inputs: BTreeMap::new(),
        bodies: Vec::new(),
        failures: Vec::new(),
    };
    for path in rows.paths.values() {
        let relative = path
            .strip_prefix(&rows.corpus.root)
            .unwrap()
            .to_string_lossy();
        rows.inputs
            .insert(format!("{name}/{relative}"), std::fs::read(path).unwrap());
    }
    index.upload_context_proof.request_contributions.clear();
    index = rows.corpus.reload(&mut index);
    index.activate_upload_context("e2-synthetic-destination".into());
    rows.equal(
        "carrier without accepted request rows",
        "main group owned",
        e2::carrier_group_owned_for_test(&index, &rows.key("holder")),
        true,
    );
    rows.write("later", &file(THIRD), &resumed(THIRD, &[A, D]), BORN);
    if hold_on_page {
        owe(&mut index);
    }
    let files = if hold_on_page {
        &["holder", "later"][..]
    } else {
        &["later"][..]
    };
    let page = scan(&rows, index, files);
    let native = page.scan.snapshots.clone();
    let first = rows.decisions("carrier page decision", &native, &page.index);
    let mut index = rows.step(
        "carrier ownership",
        page,
        Ack::Exact,
        Expected {
            literals: vec![if hold_on_page {
                literal(
                    THIRD,
                    &[("later", "a"), ("later", "d")],
                    0,
                    1,
                    D.1,
                    vec![grain(EARLY, A.1, D.1, 20, 2, false)],
                )
            } else {
                literal(
                    THIRD,
                    &[("later", "d")],
                    1,
                    0,
                    D.1,
                    vec![grain(EARLY, D.1, D.1, 10, 1, false)],
                )
            }],
            groups: if hold_on_page {
                REMOVED_A
            } else {
                &[("copy", "holder", &["a"]), ("later", "holder", &["a"])]
            },
            holds: if hold_on_page {
                &[("absent_content_twin", 1), ("absent_twin", 1)]
            } else {
                &[]
            },
            ..Expected::default()
        },
    );
    if !hold_on_page {
        index.activate_upload_context("e2-synthetic-destination".into());
        crate::snapshots::e2_pipeline_scan_fixture::non_tail_carrier_observation_for_test(
            &index,
            &rows.paths["twin"],
        );
        let index = rows.corpus.reload(&mut index);
        rows.check_saved(
            "carrier loses group",
            &index,
            &[],
            &["copy", "holder", "later"],
        );
        rows.compare_save(
            "carrier loses group",
            "later",
            &first["later"],
            &native,
            &index,
        );
    }
    rows
}

fn version_five() -> Rows {
    let mut rows = Rows::new("settled_counted_copy_rule_five");
    write_copy(&mut rows, &resumed(COPY, &[A, C]));
    let page = scan(&rows, ScanIndex::default(), &["copy"]);
    let native = page.scan.snapshots.clone();
    let before = rows.decisions("settled counted copy", &native, &page.index);
    let mut index = rows.step(
        "settled counted copy",
        page,
        Ack::Exact,
        Expected {
            literals: vec![copy_disclosed()],
            ..Expected::default()
        },
    );
    let copy = rows.key("copy");
    let census = index
        .claude_request_census_mut_for_test()
        .take(&copy)
        .unwrap();
    write_holder(&mut rows);
    let page = scan(&rows, index, &["holder"]);
    let mut index = rows.step(
        "ACK holder while copy census is absent",
        page,
        Ack::Exact,
        Expected {
            literals: vec![holder_row()],
            ..Expected::default()
        },
    );
    index
        .claude_request_census_mut_for_test()
        .insert(copy, census);
    index.claude_money_birth_store.set_money_rule_version(4);
    let mut index = rows.corpus.reload(&mut index);
    rows.check_saved("restore census", &index, &[], &[]);
    index.activate_upload_context("e2-synthetic-destination".into());
    e2::apply_money_rules(&mut index);
    rows.equal(
        "run rule five",
        "money-rule version",
        index.claude_money_birth_store.money_rule_version(),
        5,
    );
    let index = rows.corpus.reload(&mut index);
    rows.check_saved("publish rule five", &index, &[], &["copy"]);
    rows.compare_save(
        "publish rule five",
        "copy",
        &before["copy"],
        &native,
        &index,
    );
    let page = scan(&rows, index, &["copy"]);
    let mut index = rows.step(
        "consume one correction",
        page,
        Ack::Exact,
        Expected {
            literals: vec![copy_removed()],
            groups: REMOVED_A,
            ..Expected::default()
        },
    );
    index.activate_upload_context("e2-synthetic-destination".into());
    e2::apply_money_rules(&mut index);
    rows.check_saved("version already current", &index, REMOVED_A, &[]);
    rows
}

fn cutoff(name: &'static str, copy_day: &str, prove: bool) -> Rows {
    let mut rows = Rows::new(name);
    let own = format!("{copy_day}T07:03:10Z");
    let birth = format!("{copy_day}T07:03:00Z");
    let hour = format!("{copy_day}T07:00:00Z");
    write_holder(&mut rows);
    if prove {
        rows.write(
            "copy",
            &format!("resume/{}", file(ROOT)),
            &resumed(ROOT, &[A, ("c", &own, RESUME_WRITER)]),
            &birth,
        );
        let mut page = scan(&rows, ScanIndex::default(), &["holder", "copy"]);
        page.scan.snapshots.sort_by_key(|item| {
            item.claude_money.as_deref().unwrap().location_key() != Some(rows.loc("copy"))
        });
        page.index
            .claude_request_census_mut_for_test()
            .remove(&rows.key("holder"));
        let after_cutoff = copy_day == "2026-11-04";
        let mut ids = vec![("holder", "a"), ("copy", "c")];
        if !after_cutoff {
            ids.push(("copy", "a"));
        }
        let copies = if after_cutoff { 1 } else { 2 };
        rows.step(
            "page-only same-session proof",
            page,
            Ack::Exact,
            Expected {
                literals: vec![literal(
                    ROOT,
                    &ids,
                    u64::from(after_cutoff),
                    u64::from(!after_cutoff),
                    &own,
                    vec![
                        grain(EARLY, A.1, A.1, 10 * copies, copies, false),
                        grain(&hour, &own, &own, 10, 1, false),
                    ],
                )],
                ..Expected::default()
            },
        );
        return rows;
    }
    let page = scan(&rows, ScanIndex::default(), &["holder"]);
    let mut index = rows.step(
        "accept early holder",
        page,
        Ack::Exact,
        Expected {
            literals: vec![holder_row()],
            ..Expected::default()
        },
    );
    // Model an installed predecessor with only the old copy mark and
    // no saved groups or positive earlier holder for this request.
    let seed = ("b", B.1, OLD_WRITER);
    rows.write(
        "copy",
        &file(COPY),
        &resumed(COPY, &[seed, ("c", &own, RESUME_WRITER)]),
        &birth,
    );
    let page = scan(&rows, index, &["copy"]);
    index = rows.step(
        "settle unproven prefix",
        page,
        Ack::Exact,
        Expected {
            literals: vec![literal(
                COPY,
                &[("copy", "b"), ("copy", "c")],
                0,
                1,
                &own,
                vec![
                    grain(EARLY, B.1, B.1, 10, 1, false),
                    grain(&hour, &own, &own, 10, 1, false),
                ],
            )],
            ..Expected::default()
        },
    );
    index
        .claude_money_birth_store
        .set_money_marks(&rows.key("copy"), mark::COPY);
    let grown = format!("{copy_day}T07:04:20Z");
    rows.write(
        "copy",
        &file(COPY),
        &resumed(
            COPY,
            &[
                seed,
                ("c", &own, RESUME_WRITER),
                ("d", &grown, RESUME_WRITER),
            ],
        ),
        &birth,
    );
    let page = scan(&rows, index, &["copy"]);
    rows.step(
        "accepted copy without grandfather proof",
        page,
        Ack::Exact,
        Expected {
            literals: vec![literal(
                COPY,
                &[("copy", "b"), ("copy", "c"), ("copy", "d")],
                0,
                1,
                &grown,
                vec![
                    grain(EARLY, B.1, B.1, 10, 1, false),
                    grain(&hour, &own, &grown, 20, 2, false),
                ],
            )],
            ..Expected::default()
        },
    );
    rows
}

fn forked_agent(name: &'static str, witness: &str) -> Rows {
    let mut rows = Rows::new(name);
    let agent = format!("{ROOT}_agent-001");
    write_holder(&mut rows);
    let index = if witness == "page" {
        ScanIndex::default()
    } else {
        let page = scan(&rows, ScanIndex::default(), &["holder"]);
        rows.step(
            "seed family root",
            page,
            Ack::Exact,
            Expected {
                literals: vec![holder_row()],
                ..Expected::default()
            },
        )
    };
    rows.write(
        "agent",
        &format!("{ROOT}/subagents/agent-001.jsonl"),
        &resumed(ROOT, &[A, ("agent-own", C.1, RESUME_WRITER)]),
        EARLY,
    );
    let scanner = E2ScanFixture::with_subagent_births();
    if let Some(route) = route_of(&index) {
        scanner.on_committed_route(&route);
    }
    let mut page = rows.raw(
        index,
        if witness == "page" {
            &["holder", "agent"]
        } else {
            &["agent"]
        },
        &scanner,
    );
    if witness == "missing" {
        observe::forget_census(&mut page.index, &file(ROOT));
    }
    let mut bodies = vec![if witness == "missing" {
        literal(
            &agent,
            &[("agent", "a"), ("agent", "agent-own")],
            0,
            0,
            C.1,
            vec![grain(EARLY, A.1, C.1, 20, 2, false)],
        )
    } else {
        literal(
            &agent,
            &[("agent", "agent-own")],
            1,
            0,
            C.1,
            vec![grain(EARLY, C.1, C.1, 10, 1, false)],
        )
    }];
    if witness == "page" {
        bodies.push(holder_row());
    }
    rows.step(
        "child's first response",
        page,
        Ack::Exact,
        Expected {
            literals: bodies,
            ..Expected::default()
        },
    );
    rows
}

fn covered_only() -> Rows {
    let mut rows = Rows::new("covered_only_path_has_no_body");
    write_holder(&mut rows);
    let page = scan(&rows, ScanIndex::default(), &["holder"]);
    let mut index = rows.step(
        "accept original",
        page,
        Ack::Exact,
        Expected {
            literals: vec![holder_row()],
            ..Expected::default()
        },
    );
    rows.write(
        "copy",
        &format!("moved/{}", file(ROOT)),
        &resumed(ROOT, &[A]),
        BORN,
    );
    owe(&mut index);
    let mut page = scan(&rows, index, &["copy", "holder"]);
    page.scan.snapshots.retain(|item| {
        item.claude_money.as_deref().unwrap().location_key() == Some(rows.loc("copy"))
    });
    // Unlink the still-accepted holder so only the covered path can emit.
    std::fs::remove_file(&rows.paths["holder"]).unwrap();
    rows.step(
        "only the covered path is on page",
        page,
        Ack::Local,
        Expected {
            groups: REMOVED_A,
            ..Expected::default()
        },
    );
    rows
}

fn ambiguous_duplicate() -> Rows {
    let mut rows = Rows::new("ambiguous_copied_duplicate");
    let mut duplicate: Value = serde_json::from_str(&line(COPY, "a", A.1, 20)).unwrap();
    duplicate["message"]["id"] = json!("independent-response");
    write_copy(
        &mut rows,
        &(resumed(COPY, &[A]) + &duplicate.to_string() + "\n" + &resumed(COPY, &[C])),
    );
    let page = scan(&rows, ScanIndex::default(), &["copy"]);
    rows.step(
        "cannot restore an unproved duplicate",
        page,
        Ack::Local,
        Expected {
            holds: &[
                ("uncertified", 1),
                ("uncertified_by=ambiguous_duplicate", 1),
            ],
            ..Expected::default()
        },
    );
    rows
}

fn subagent_twins(name: &'static str, day: &str, after_cutoff: bool) -> Rows {
    let mut rows = Rows::new(name);
    let agent = format!("{ROOT}_agent-001");
    let first = format!("{day}T07:01:00Z");
    let repeat = format!("{day}T07:02:50Z");
    let slack = format!("{day}T07:02:59.886Z");
    let own = format!("{day}T07:03:10Z");
    let hour = format!("{day}T07:00:00Z");
    rows.write("holder", &file(ROOT), &resumed(ROOT, &[A]), EARLY);
    rows.write(
        "early",
        &format!("{ROOT}/subagents/agent-001.jsonl"),
        &resumed(
            ROOT,
            &[
                ("r1", &first, OLD_WRITER),
                ("r2", &repeat, OLD_WRITER),
                ("b", &slack, OLD_WRITER),
            ],
        ),
        EARLY,
    );
    rows.write(
        "late",
        &format!("other/{ROOT}/subagents/agent-001.jsonl"),
        &resumed(
            ROOT,
            &[
                ("r1", &first, OLD_WRITER),
                ("b", &slack, OLD_WRITER),
                ("agent-own", &own, RESUME_WRITER),
                ("r2", &repeat, OLD_WRITER),
            ],
        ),
        &format!("{day}T07:03:00Z"),
    );
    let mut index = ScanIndex::default();
    for file in ["early", "late"] {
        index.claude_money_birth_store.record_observation(
            &agent,
            &rows.key(file),
            rows.corpus.births[&rows.paths[file]],
        );
    }
    let mut page = rows.raw(
        index,
        &["holder", "early", "late"],
        &E2ScanFixture::with_subagent_births(),
    );
    page.scan.snapshots.sort_by_key(|item| {
        item.claude_money.as_deref().unwrap().location_key() != Some(rows.loc("late"))
    });
    let mut counted = vec![
        ("early", "r1"),
        ("early", "r2"),
        ("early", "b"),
        ("late", "agent-own"),
    ];
    if !after_cutoff {
        counted.push(("late", "r2"));
    }
    let (removed, disclosed, tokens, requests) = if after_cutoff {
        (3, 0, 40, 4)
    } else {
        (2, 1, 50, 5)
    };
    rows.step(
        "child paths and slack tail",
        page,
        Ack::Exact,
        Expected {
            literals: vec![
                holder_row(),
                literal(
                    &agent,
                    &counted,
                    removed,
                    disclosed,
                    &own,
                    vec![grain(&hour, &first, &own, tokens, requests, false)],
                ),
            ],
            ..Expected::default()
        },
    );
    rows
}

#[test]
#[serial(client_report)]
fn full_copy_decision_rows() {
    if !crate::heap_layout_bound::layout_supported() {
        println!("MONEY_EQUIVALENCE {FIXTURE} UNEXECUTED: native retained layout unavailable");
        return;
    }
    with_e2(|| {
        with_scan_clock(nanos("2026-11-07T08:00:00Z") as u64 / 1_000_000_000, || {
            let rows = [
                earlier_holder("accepted_holder_before_copy", Ack::Exact),
                earlier_holder("local_holder_before_copy", Ack::Local),
                late_holder("accepted_holder_after_copy", Ack::Exact, true),
                late_holder("unstored_holder_after_copy", Ack::Unstored, false),
                late_holder(
                    "usage_identical_holder_after_copy",
                    Ack::UsageIdentical,
                    true,
                ),
                late_holder("dominated_holder_after_copy", Ack::Dominated, true),
                holder_loss("deleted_accepted_holder", HolderLoss::DeleteAccepted),
                holder_loss("deleted_local_holder", HolderLoss::DeleteLocal),
                holder_loss("retired_holder_keeps_saved_group", HolderLoss::Retire),
                holder_loss("lossy_holder_keeps_saved_group", HolderLoss::Lossy),
                retired_parent(),
                fresh_destination(),
                twins("cloned_main_requests", false, false),
                twins("distinct_twin_requests", true, false),
                twins("absent_path_twin_holds", true, true),
                twins("redundant_absent_path_twin_releases", false, true),
                latest_clock(),
                idless_copy(),
                same_session("resumed_rule_a_both_paths", SameSession::RuleA),
                same_session(
                    "own_session_acceptance_one_owned_location",
                    SameSession::OnlyNewerOwned,
                ),
                same_session(
                    "resumed_same_session_holder_off_page",
                    SameSession::HolderOffPage,
                ),
                same_session("holder_already_in_accepted_sum", SameSession::AcceptedSum),
                carrier("empty_main_carried_by_twin", false),
                carrier("content_held_holder_on_page", true),
                version_five(),
                cutoff("before_copy_proof_cutoff", "2026-11-03", true),
                cutoff("after_copy_proof_cutoff", "2026-11-04", true),
                cutoff("no_accepted_copy_grandfather", "2026-11-03", false),
                forked_agent("forked_agent_root_on_page", "page"),
                forked_agent("forked_agent_root_in_census", "census"),
                forked_agent("forked_agent_without_witness", "missing"),
                covered_only(),
                ambiguous_duplicate(),
                subagent_twins("subagent_before_request_cutoff", "2026-11-04", false),
                subagent_twins("subagent_after_request_cutoff", "2026-11-05", true),
            ];
            let mut bodies = Vec::new();
            let mut inputs = BTreeMap::new();
            let mut failures = Vec::new();
            for row in rows {
                bodies.extend(row.bodies);
                inputs.extend(row.inputs);
                failures.extend(row.failures);
            }
            assert!(
                failures.is_empty(),
                "copy decision rows:\n{}",
                failures.join("\n")
            );
            emit_money(FIXTURE, bodies, inputs);
        })
    });
}
