// Copy decisions on native folds, literal bodies and the saved index.
use super::*;
use crate::snapshot_sync::tests::claude_money_e2_pipeline_tests::money_equivalence_tests::{
    corpus, input_clock, receipt_with_output, ReceiptBody,
};
use crate::snapshots::claude_money_birth_store::LocationKey;
use crate::snapshots::e2_pipeline_scan_fixture::{
    accepted_origin_hashes_for_test, route_of, upload_context_receipt_earned_for_test,
};
use e2::{money_mark as mark, pipeline_test_observer as observe};
use serde_json::Value;

const FIXTURE: &str = "claude_copy_decision_rows";

/// The table's synthetic inputs and its receipt, for the money comparison.
fn emit_money(name: &str, bodies: Vec<ReceiptBody>, inputs: BTreeMap<String, Vec<u8>>) {
    if let Some(out) = std::env::var_os("OTTTO_MONEY_EQUIVALENCE_OUTPUT") {
        std::fs::create_dir_all(&out).unwrap();
        std::fs::write(
            PathBuf::from(out).join(format!("{name}.inputs")),
            crate::canonical_json::canonicalize(&serde_json::to_value(inputs).unwrap()).unwrap(),
        )
        .unwrap();
    }
    receipt_with_output(
        name,
        &bodies,
        "OTTTO_MONEY_EQUIVALENCE_OUTPUT",
        "MONEY_EQUIVALENCE",
    );
}
const EARLY: &str = "2026-08-02T07:00:00Z";
const LATE_NOTE: &str = "2026-08-02T08:06:10Z";
const KNOWN_IDS: &[&str] = &["a", "b", "c", "d", "e", "r1", "r2", "agent-own"];
/// A later resume's own turn, after `LATER_BORN`.
const E: (&str, &str, &str) = ("e", "2026-08-02T07:07:10Z", RESUME_WRITER);
const LATER_BORN: &str = "2026-08-02T07:04:00Z";

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

thread_local! {
    /// (failures, agreement checks) of the row that is running. Kept outside
    /// the row so a failed fixture premise does not lose what it already found.
    static NOTES: std::cell::RefCell<(Vec<String>, Vec<String>)> =
        const { std::cell::RefCell::new((Vec::new(), Vec::new())) };
}

fn check(line: String) {
    NOTES.with_borrow_mut(|notes| notes.1.push(line));
}

/// The two answers of one agreement check.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Answers {
    /// The earliest holder the census selector names, and the earliest
    /// holder whose current proof the page decision takes.
    Holder {
        selector: Option<&'static str>,
        page: Option<&'static str>,
    },
    /// Whether the save marked the file, and whether deciding the same page
    /// again on the saved index changes its groups or counted requests.
    Save { marked: bool, changes: bool },
}

impl Answers {
    fn agree(&self) -> bool {
        match self {
            Self::Holder { selector, page } => selector == page,
            Self::Save { marked, changes } => marked == changes,
        }
    }
}

/// A place where the two answers differ today, and why. Every other check
/// must agree; a listed difference that stops differing fails as well.
struct Differs {
    phase: &'static str,
    file: &'static str,
    answers: Answers,
    why: &'static str,
    met: bool,
}

/// The selector reads committed files only.
const ONLY_ON_PAGE: &str = "the holder is only on this page; the selector reads committed files";
/// Rule A and Rule B skip a hash that a stored removal already keeps.
const STORED_REUSED: &str = "a stored removal is reused; the page asks for no new proof";
/// The page filter on a resumed copy's own session.
const OFF_PAGE: &str =
    "a resumed copy takes its own session's earlier file only from the page; the selector names it";
/// The page counts a main whose summed body a content twin carries as owned.
const CARRIED: &str =
    "a content twin carries the main's summed body: owned for the page, not for the selector";
/// A withheld page leaves its session owed; nothing is marked for it.
const HELD_READ_AGAIN: &str =
    "the page withholds the session, which stays owed and is read again with both files";
/// The page accepts a session when any of its files is owned.
const ANY_FILE_OWNED: &str =
    "the page accepts a session when any of its files is owned; the others ask each file";
/// A save selects a path twin whose counted request an earlier twin's
/// accepted row also counts; the page takes that twin only from the page.
const TWIN_SELECTED_OFF_PAGE: &str =
    "the save selects a path twin counting an earlier twin's accepted request; the page lacks that twin";

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
    differs: Vec<Differs>,
}

impl Rows {
    fn new(name: &'static str) -> Self {
        Self {
            corpus: corpus(&format!("{FIXTURE}-{name}")),
            name,
            paths: BTreeMap::new(),
            inputs: BTreeMap::new(),
            bodies: Vec::new(),
            differs: Vec::new(),
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

    fn label(&self, loc: LocationKey) -> &'static str {
        self.paths
            .iter()
            .find_map(|(&alias, path)| {
                (location_key(&path.to_string_lossy()) == loc).then_some(alias)
            })
            .unwrap_or("<unexpected location>")
    }

    fn alias(&self, loc: LocationKey) -> String {
        self.label(loc).into()
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
            let failure = format!(
                "{} / {phase} / {field}\n  actual: {actual:?}\n  expected: {expected:?}",
                self.name
            );
            NOTES.with_borrow_mut(|notes| notes.0.push(failure));
        }
    }

    /// Declares one difference between the two answers at `phase` for `file`.
    fn differs(
        &mut self,
        phase: &'static str,
        file: &'static str,
        answers: Answers,
        why: &'static str,
    ) {
        self.differs.push(Differs {
            phase,
            file,
            answers,
            why,
            met: false,
        });
    }

    fn agreement(&mut self, phase: &str, file: &str, answers: Answers) {
        let holder = matches!(answers, Answers::Holder { .. });
        let known = self.differs.iter_mut().find(|known| {
            known.phase == phase
                && known.file == file
                && matches!(known.answers, Answers::Holder { .. }) == holder
        });
        let (expected, why) = match known {
            Some(known) => {
                known.met = true;
                (known.answers == answers, known.why)
            }
            None => (answers.agree(), "must agree"),
        };
        check(format!(
            "{} / {phase} / {file}: {answers:?} ({why})",
            self.name
        ));
        if !expected {
            let failure = format!(
                "{} / {phase} / {file}\n  answers: {answers:?}\n  expected: {why}",
                self.name
            );
            NOTES.with_borrow_mut(|notes| notes.0.push(failure));
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
            removed_usage: serde_json::to_value(item.removed_usage).unwrap(),
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
                        let selector = selected.get(&key).map(|key| self.label(location_key(key)));
                        let page = first.map(|holder| self.label(holder));
                        self.agreement(phase, &file, Answers::Holder { selector, page });
                    } else {
                        check(format!(
                            "{} / {phase} / {file}: no selector check, the copy has no census that proves its scan",
                            self.name
                        ));
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
        let redecided = self.decisions(
            &format!("{phase}, replayed after the save"),
            replay,
            &active,
        );
        let rerun = &redecided[file];
        let marked = active.claude_copy_removals.pending(self.loc(file));
        let changed = original.groups != rerun.groups || original.counted != rerun.counted;
        self.agreement(
            phase,
            file,
            Answers::Save {
                marked,
                changes: changed,
            },
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
/// One of a session's two paths is missing from the page.
const ABSENT_PATH: &[(&str, u64)] = &[
    ("absent_twin", 1),
    ("known_twin_paths", 2),
    ("staged_twin_paths", 1),
];
/// The settled carrier fixture: the copy and the content twin each removed
/// one request on the main's proof.
const CARRIED_GROUPS: &[(&str, &str, &[&str])] =
    &[("copy", "holder", &["a"]), ("twin", "holder", &["b"])];
const CARRIED_AND_LATER: &[(&str, &str, &[&str])] = &[
    ("copy", "holder", &["a"]),
    ("later", "holder", &["a"]),
    ("twin", "holder", &["b"]),
];

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

/// A holder saved after its copy was counted. Only an exact receipt makes it a
/// proof: a body the server did not store stays held, so it owns nothing.
fn late_holder(name: &'static str, ack: Ack) -> Rows {
    let mark_copy = matches!(ack, Ack::Exact);
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
        // Positive trace sidecars put the two families in separate chunks.
        rows.corpus.evidence_for(ROOT, &[], &[trace("a", "")]);
        rows.corpus
            .evidence_for(COPY, &[], &[trace_for(COPY, "c", "")]);
        owe(&mut index);
        let files = &["holder", "copy"][..];
        let correction = scan(&rows, index, files);
        let before = crate::snapshot_sync::evidence_chunks_for_test();
        let literals = vec![copy_removed(), holder_row()];
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
    let saved = rows.corpus.reload(&mut index);
    drop(index);
    let index = saved;
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

fn retired_parent(name: &'static str) -> Rows {
    let mut rows = Rows::new(name);
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

fn fresh_destination(name: &'static str) -> Rows {
    let mut rows = Rows::new(name);
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

fn latest_clock(name: &'static str) -> Rows {
    let mut rows = Rows::new(name);
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

fn idless_copy(name: &'static str) -> Rows {
    let mut rows = Rows::new(name);
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
    OnlyNewerOwned,
    HolderOffPage,
}

fn same_session(name: &'static str, variant: SameSession) -> Rows {
    let mut rows = Rows::new(name);
    let holder = Some("holder");
    let (page_only, selector_only) = (
        Answers::Holder {
            selector: None,
            page: holder,
        },
        Answers::Holder {
            selector: holder,
            page: None,
        },
    );
    match variant {
        SameSession::OnlyNewerOwned => {
            rows.differs(
                "holder facts save, replayed after the save",
                "copy",
                page_only,
                ANY_FILE_OWNED,
            );
            // The save leaves the copy unmarked although deciding the page
            // again removes its prefix. Recorded as today's answer.
            rows.differs(
                "holder facts save",
                "copy",
                Answers::Save {
                    marked: false,
                    changes: true,
                },
                ANY_FILE_OWNED,
            );
        }
        SameSession::HolderOffPage => {
            for phase in [
                "holder facts save, replayed after the save",
                "omit earlier path",
                "omit earlier path, replayed after the save",
            ] {
                rows.differs(phase, "copy", selector_only.clone(), OFF_PAGE);
            }
            // The earlier file's accepted row also counts `a`, so the save
            // selects the resume once; a page without that file decides it
            // the same. Recorded as today's answer.
            rows.differs(
                "holder facts save",
                "copy",
                Answers::Save {
                    marked: true,
                    changes: false,
                },
                TWIN_SELECTED_OFF_PAGE,
            );
        }
    }
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
            let marked: &[&str] = if off_page { &["copy"] } else { &[] };
            rows.check_saved("holder facts save", &index, &[], marked);
            rows.compare_save(
                "holder facts save",
                "copy",
                &initial["copy"],
                &replay,
                &index,
            );
            // The live page agrees: a resumed copy takes its own session's
            // earlier file as proof only when that file is on the page. Its
            // prefix counts, disclosed, and the earlier file adds nothing the
            // page lacks, so the session is not held for it.
            if off_page {
                owe(&mut next);
                let page = scan(&rows, next, &["copy"]);
                let mut counted = copy_disclosed();
                counted.session = ROOT.into();
                rows.step(
                    "omit earlier path",
                    page,
                    Ack::Local,
                    Expected {
                        literals: vec![counted],
                        ..Expected::default()
                    },
                );
            }
        }
    }
    rows
}

/// Passes over one session's original and its resume, where one
/// file is owned and the other is not.
#[derive(Clone, Copy)]
enum Pass {
    /// The original is decided on a page without the resume, so the session
    /// is held; the next pass reads both.
    OlderHeldAlone,
    /// Both are read and saved before any acknowledgement; `resume_first`
    /// chooses which file carries the summed body.
    AckPending { resume_first: bool },
    /// Both settle with an exact acknowledgement, then the resume is read
    /// again on a page without the original.
    ResumeReadAgain,
}

fn same_session_pass(name: &'static str, pass: Pass) -> Rows {
    let mut rows = Rows::new(name);
    let holder = Some("holder");
    let page_only = Answers::Holder {
        selector: None,
        page: holder,
    };
    let stored = Answers::Holder {
        selector: holder,
        page: None,
    };
    let reused: &[&'static str] = match pass {
        Pass::OlderHeldAlone => {
            // While the page withholds the session neither file is owned,
            // so the save marks nothing. Once that hold is gone a page with
            // both files removes the prefix: the next pass below does, with
            // no mark. Recorded as today's answer.
            rows.differs(
                "original alone",
                "copy",
                Answers::Save {
                    marked: false,
                    changes: true,
                },
                HELD_READ_AGAIN,
            );
            &["next pass reads both, replayed after the save"]
        }
        Pass::AckPending { resume_first } => {
            rows.differs(
                "both read, acknowledgement pending",
                "copy",
                page_only,
                ONLY_ON_PAGE,
            );
            if resume_first {
                &["next pass reads both, replayed after the save"]
            } else {
                &[
                    "both read, acknowledgement pending, replayed after the save",
                    "next pass reads both",
                    "next pass reads both, replayed after the save",
                ]
            }
        }
        Pass::ResumeReadAgain => {
            rows.differs("both settle", "copy", page_only, ONLY_ON_PAGE);
            &[
                "both settle, replayed after the save",
                "resume read again alone",
                "resume read again alone, replayed after the save",
            ]
        }
    };
    for &phase in reused {
        rows.differs(phase, "copy", stored.clone(), STORED_REUSED);
    }
    rows.write(
        "copy",
        &format!("resume/{}", file(ROOT)),
        &resumed(ROOT, &[A, C]),
        BORN,
    );
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
    let summed = || {
        literal(
            ROOT,
            &[("holder", "a"), ("copy", "c")],
            1,
            0,
            C.1,
            vec![grain(EARLY, A.1, C.1, 20, 2, false)],
        )
    };
    let mut page = scan(&rows, index, &["holder", "copy"]);
    let both = page.scan.snapshots.clone();
    let first = |rows: &Rows, alias: &str| {
        let wanted = Some(rows.loc(alias));
        move |item: &SnapshotItem| item.claude_money.as_deref().unwrap().location_key() != wanted
    };
    let mut index = match pass {
        Pass::OlderHeldAlone => {
            let holder = Some(rows.loc("holder"));
            page.scan
                .snapshots
                .retain(|item| item.claude_money.as_deref().unwrap().location_key() == holder);
            let index = rows.step(
                "original alone",
                page,
                Ack::Local,
                Expected {
                    holds: ABSENT_PATH,
                    ..Expected::default()
                },
            );
            // What a page with both files would decide on this saved index.
            rows.compare_save("original alone", "copy", &initial["copy"], &both, &index);
            index
        }
        Pass::AckPending { resume_first } => {
            page.scan
                .snapshots
                .sort_by_key(first(&rows, if resume_first { "copy" } else { "holder" }));
            rows.step(
                "both read, acknowledgement pending",
                page,
                Ack::Local,
                Expected {
                    literals: vec![summed()],
                    groups: REMOVED_A,
                    ..Expected::default()
                },
            )
        }
        Pass::ResumeReadAgain => rows.step(
            "both settle",
            page,
            Ack::Exact,
            Expected {
                literals: vec![summed()],
                groups: REMOVED_A,
                ..Expected::default()
            },
        ),
    };
    // The held session is still owed: the next pass reads both files without
    // any new cause.
    if !matches!(pass, Pass::OlderHeldAlone) {
        owe(&mut index);
    }
    if matches!(pass, Pass::ResumeReadAgain) {
        // A read of the resume alone, as a same-bytes touch of it causes: it
        // still excludes a request, so it cannot stand in for the original
        // and the session is held. Today's answer, not a guard.
        let page = scan(&rows, index, &["copy"]);
        rows.step(
            "resume read again alone",
            page,
            Ack::Local,
            Expected {
                groups: REMOVED_A,
                holds: ABSENT_PATH,
                ..Expected::default()
            },
        );
    } else {
        let page = scan(&rows, index, &["holder", "copy"]);
        rows.step(
            "next pass reads both",
            page,
            Ack::Exact,
            Expected {
                literals: vec![summed()],
                groups: REMOVED_A,
                ..Expected::default()
            },
        );
    }
    rows
}

/// A settled main whose summed session body a content twin carries, and a
/// copy that removed a request on that main's proof.
fn carried_main(name: &'static str) -> (Rows, ScanIndex) {
    let (c, index, [holder, copy, twin]) = settled_content_carrier(true);
    let mut rows = Rows {
        corpus: c,
        name,
        paths: BTreeMap::from([("holder", holder), ("copy", copy), ("twin", twin)]),
        inputs: BTreeMap::new(),
        bodies: Vec::new(),
        differs: Vec::new(),
    };
    for path in rows.paths.values() {
        let relative = path
            .strip_prefix(&rows.corpus.root)
            .unwrap()
            .to_string_lossy();
        rows.inputs
            .insert(format!("{name}/{relative}"), std::fs::read(path).unwrap());
    }
    (rows, index)
}

/// The summed body moves from the twin to the main's own file. The main is
/// read again; the copy that relies on it stays settled.
fn carrier_transfer(name: &'static str) -> Rows {
    let (mut rows, index) = carried_main(name);
    rows.check_saved("carried main", &index, CARRIED_GROUPS, &[]);
    let (holder, twin) = (rows.key("holder"), rows.key("twin"));
    let mut next = index.clone();
    next.confirmed_empty_files.remove(&holder);
    next.file_snapshot_fingerprints
        .insert(holder, BTreeSet::from(["own-body".to_owned()]));
    e2::reconcile_carrier_images_for_test(&index, &mut next, |keys, committed| {
        if committed && keys.contains(&twin.as_str()) {
            BTreeMap::from([(twin.clone(), ROOT.to_owned())])
        } else {
            BTreeMap::new()
        }
    });
    rows.check_saved(
        "main carries its own body",
        &next,
        CARRIED_GROUPS,
        &["holder"],
    );
    rows
}

fn carrier(name: &'static str, hold_on_page: bool) -> Rows {
    let (mut rows, mut index) = carried_main(name);
    if !hold_on_page {
        for phase in [
            "carrier page decision",
            "carrier ownership",
            "carrier ownership, replayed after the save",
        ] {
            let answers = Answers::Holder {
                selector: None,
                page: Some("holder"),
            };
            rows.differs(phase, "later", answers, CARRIED);
        }
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
    rows.write("later", &file(THIRD), &resumed(THIRD, &[A, E]), LATER_BORN);
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
                    &[("later", "a"), ("later", "e")],
                    0,
                    1,
                    E.1,
                    vec![grain(EARLY, A.1, E.1, 20, 2, false)],
                )
            } else {
                literal(
                    THIRD,
                    &[("later", "e")],
                    1,
                    0,
                    E.1,
                    vec![grain(EARLY, E.1, E.1, 10, 1, false)],
                )
            }],
            groups: if hold_on_page {
                CARRIED_GROUPS
            } else {
                CARRIED_AND_LATER
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
            // The groups stay until each marked file is read again.
            CARRIED_AND_LATER,
            &["copy", "holder", "later", "twin"],
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

fn version_five(name: &'static str) -> Rows {
    let mut rows = Rows::new(name);
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
    // Only one witness at a time: the root's fold on the page, or its
    // census record, or neither.
    if witness != "census" {
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
            // The dropped first response keeps its place in the hour's span.
            vec![grain(EARLY, A.1, C.1, 10, 1, false)],
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

fn covered_only(name: &'static str) -> Rows {
    let mut rows = Rows::new(name);
    rows.differs(
        "only the covered path is on page, replayed after the save",
        "copy",
        Answers::Holder {
            selector: Some("holder"),
            page: None,
        },
        STORED_REUSED,
    );
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

fn ambiguous_duplicate(name: &'static str) -> Rows {
    let mut rows = Rows::new(name);
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

#[derive(Default)]
struct Table {
    bodies: Vec<ReceiptBody>,
    inputs: BTreeMap<String, Vec<u8>>,
    failures: Vec<String>,
    checks: Vec<String>,
}

impl Table {
    /// A row whose fixture premise fails is reported with the others; it does
    /// not hide them.
    fn row(&mut self, name: &'static str, build: impl FnOnce(&'static str) -> Rows) {
        let row = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| build(name)));
        let (failures, checks) = NOTES.take();
        self.failures.extend(failures);
        self.checks.extend(checks);
        match row {
            Ok(row) => {
                self.failures
                    .extend(row.differs.iter().filter(|known| !known.met).map(|known| {
                        format!(
                            "{name} / {} / {}\n  listed difference never checked: {}",
                            known.phase, known.file, known.why
                        )
                    }));
                self.bodies.extend(row.bodies);
                self.inputs.extend(row.inputs);
            }
            Err(panic) => {
                let why = panic
                    .downcast_ref::<String>()
                    .map(String::as_str)
                    .or_else(|| panic.downcast_ref::<&str>().copied())
                    .unwrap_or("no message");
                self.failures
                    .push(format!("{name} / fixture premise\n  panic: {why}"));
            }
        }
    }
}

/// Every row of the table, in order.
fn all_rows() -> Table {
    let mut table = Table::default();
    table.row("accepted_holder_before_copy", |name| {
        earlier_holder(name, Ack::Exact)
    });
    table.row("local_holder_before_copy", |name| {
        earlier_holder(name, Ack::Local)
    });
    table.row("accepted_holder_after_copy", |name| {
        late_holder(name, Ack::Exact)
    });
    table.row("unstored_holder_after_copy", |name| {
        late_holder(name, Ack::Unstored)
    });
    table.row("usage_identical_holder_after_copy", |name| {
        late_holder(name, Ack::UsageIdentical)
    });
    table.row("dominated_holder_after_copy", |name| {
        late_holder(name, Ack::Dominated)
    });
    table.row("deleted_accepted_holder", |name| {
        holder_loss(name, HolderLoss::DeleteAccepted)
    });
    table.row("deleted_local_holder", |name| {
        holder_loss(name, HolderLoss::DeleteLocal)
    });
    table.row("retired_holder_keeps_saved_group", |name| {
        holder_loss(name, HolderLoss::Retire)
    });
    table.row("lossy_holder_keeps_saved_group", |name| {
        holder_loss(name, HolderLoss::Lossy)
    });
    table.row("retired_named_parent", retired_parent);
    table.row("fresh_destination_unstored", fresh_destination);
    table.row("cloned_main_requests", |name| twins(name, false, false));
    table.row("distinct_twin_requests", |name| twins(name, true, false));
    table.row("absent_path_twin_holds", |name| twins(name, true, true));
    table.row("redundant_absent_path_twin_releases", |name| {
        twins(name, false, true)
    });
    table.row("summed_session_latest_clock", latest_clock);
    table.row("idless_prefix_restored_and_disclosed", idless_copy);
    table.row("own_session_acceptance_one_owned_location", |name| {
        same_session(name, SameSession::OnlyNewerOwned)
    });
    table.row("resumed_same_session_holder_off_page", |name| {
        same_session(name, SameSession::HolderOffPage)
    });
    table.row("original_decided_alone_then_both", |name| {
        same_session_pass(name, Pass::OlderHeldAlone)
    });
    table.row("both_saved_before_ack_original_carries", |name| {
        same_session_pass(
            name,
            Pass::AckPending {
                resume_first: false,
            },
        )
    });
    table.row("both_saved_before_ack_resume_carries", |name| {
        same_session_pass(name, Pass::AckPending { resume_first: true })
    });
    table.row("resume_read_again_without_original", |name| {
        same_session_pass(name, Pass::ResumeReadAgain)
    });
    table.row("empty_main_carried_by_twin", |name| carrier(name, false));
    table.row("content_held_holder_on_page", |name| carrier(name, true));
    table.row("carrier_transfer_keeps_copy_settled", carrier_transfer);
    table.row("settled_counted_copy_rule_five", version_five);
    table.row("before_copy_proof_cutoff", |name| {
        cutoff(name, "2026-11-03", true)
    });
    table.row("after_copy_proof_cutoff", |name| {
        cutoff(name, "2026-11-04", true)
    });
    table.row("no_accepted_copy_grandfather", |name| {
        cutoff(name, "2026-11-03", false)
    });
    table.row("forked_agent_root_on_page", |name| {
        forked_agent(name, "page")
    });
    table.row("forked_agent_root_in_census", |name| {
        forked_agent(name, "census")
    });
    table.row("forked_agent_without_witness", |name| {
        forked_agent(name, "missing")
    });
    table.row("covered_only_path_has_no_body", covered_only);
    table.row("ambiguous_copied_duplicate", ambiguous_duplicate);
    table.row("subagent_before_request_cutoff", |name| {
        subagent_twins(name, "2026-11-04", false)
    });
    table.row("subagent_after_request_cutoff", |name| {
        subagent_twins(name, "2026-11-05", true)
    });
    table
}

/// Agreement comparisons each row makes: selector against page, save against
/// page. A comparison that stops running fails the table like a wrong answer.
const COMPARISONS: &[(&str, usize, usize)] = &[
    ("accepted_holder_before_copy", 2, 1),
    ("local_holder_before_copy", 2, 1),
    ("accepted_holder_after_copy", 6, 3),
    ("unstored_holder_after_copy", 4, 2),
    ("usage_identical_holder_after_copy", 4, 2),
    ("dominated_holder_after_copy", 4, 2),
    ("deleted_accepted_holder", 6, 3),
    ("deleted_local_holder", 6, 3),
    ("retired_holder_keeps_saved_group", 6, 3),
    ("lossy_holder_keeps_saved_group", 6, 3),
    ("retired_named_parent", 2, 1),
    ("fresh_destination_unstored", 2, 1),
    ("cloned_main_requests", 0, 0),
    ("distinct_twin_requests", 0, 0),
    ("absent_path_twin_holds", 0, 0),
    ("redundant_absent_path_twin_releases", 0, 0),
    ("summed_session_latest_clock", 0, 0),
    ("idless_prefix_restored_and_disclosed", 2, 1),
    ("own_session_acceptance_one_owned_location", 4, 2),
    ("resumed_same_session_holder_off_page", 6, 3),
    ("original_decided_alone_then_both", 6, 3),
    ("both_saved_before_ack_original_carries", 7, 3),
    ("both_saved_before_ack_resume_carries", 7, 3),
    ("resume_read_again_without_original", 7, 3),
    ("empty_main_carried_by_twin", 4, 2),
    ("content_held_holder_on_page", 3, 1),
    ("carrier_transfer_keeps_copy_settled", 0, 0),
    ("settled_counted_copy_rule_five", 6, 3),
    ("before_copy_proof_cutoff", 2, 1),
    ("after_copy_proof_cutoff", 2, 1),
    ("no_accepted_copy_grandfather", 4, 2),
    ("forked_agent_root_on_page", 0, 0),
    ("forked_agent_root_in_census", 0, 0),
    ("forked_agent_without_witness", 0, 0),
    ("covered_only_path_has_no_body", 2, 1),
    ("ambiguous_copied_duplicate", 2, 1),
    ("subagent_before_request_cutoff", 0, 0),
    ("subagent_after_request_cutoff", 0, 0),
];

#[test]
#[serial(client_report)]
fn full_copy_decision_rows() {
    if !crate::heap_layout_bound::layout_supported() {
        println!("MONEY_EQUIVALENCE {FIXTURE} UNEXECUTED: native retained layout unavailable");
        return;
    }
    with_e2(|| {
        with_scan_clock(nanos("2026-11-07T08:00:00Z") as u64 / 1_000_000_000, || {
            let table = all_rows();
            let Table {
                bodies,
                inputs,
                failures,
                checks,
            } = table;
            for check in &checks {
                println!("COPY_DECISION_CHECK {check}");
            }
            assert!(
                failures.is_empty(),
                "copy decision rows:\n{}",
                failures.join("\n")
            );
            let mut made = BTreeMap::<&str, (usize, usize)>::new();
            for check in &checks {
                let row = check.split(" / ").next().unwrap_or_default();
                if check.contains(": Holder {") {
                    made.entry(row).or_default().0 += 1;
                } else if check.contains(": Save {") {
                    made.entry(row).or_default().1 += 1;
                }
            }
            let mut off = Vec::new();
            for (row, holder, save) in COMPARISONS {
                let did = made.get(*row).copied().unwrap_or_default();
                if did != (*holder, *save) {
                    off.push(format!(
                        "{row}: made {did:?}, planned {:?}",
                        (*holder, *save)
                    ));
                }
            }
            for row in made.keys() {
                if !COMPARISONS.iter().any(|(planned, _, _)| planned == row) {
                    off.push(format!("{row}: not in the plan"));
                }
            }
            assert!(
                off.is_empty(),
                "agreement comparisons by row (selector, save):\n{}",
                off.join("\n")
            );
            emit_money(FIXTURE, bodies, inputs);
        })
    });
}
