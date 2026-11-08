//! Upload progress on a published route as custody rows: two keyed cache maps
//! plus one ledger row, one progress transaction per page, moved in once from
//! the JSON ledger. Each row drives the production pass load, upload/ACK with
//! the production ledger save as its persistence, page save and pass end, and
//! compares the emitted money with cold Full across restarts, COMMIT errors
//! and import crash windows. A receiver credits each exact body once, so a
//! re-offer is visible as a duplicate. Storage expectations come last in each
//! row, so a failure before them is a money failure.
use super::*;
use crate::snapshots::state_v2 as v2;
use rusqlite::OptionalExtension;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const SOURCES: [SnapshotSource; 3] = [SOURCE, SnapshotSource::Codex, SnapshotSource::Pi];

fn namespace() -> String {
    "a".repeat(64)
}

fn progress_path(index_path: &Path) -> PathBuf {
    snapshot_upload_progress_path(index_path)
}

fn sibling(index_path: &Path, suffix: &str) -> PathBuf {
    let mut name = index_path.as_os_str().to_owned();
    name.push(suffix);
    name.into()
}

fn receipt(index_path: &Path) -> PathBuf {
    sibling(index_path, ".v2-ack-receipt")
}

fn failed_import(index_path: &Path) -> PathBuf {
    sibling(
        index_path,
        &format!(".v2-ack-receipt.failed-import-{}", "c".repeat(64)),
    )
}

fn write_owned(path: &Path, bytes: &[u8]) {
    ottto_core::write_owner_only_file_atomic(path, bytes).unwrap();
}

fn db_source(source: SnapshotSource) -> Source {
    match source {
        SnapshotSource::ClaudeCode => Source::Claude,
        SnapshotSource::Codex => Source::Codex,
        SnapshotSource::Pi => Source::Pi,
    }
}

/// The production pass load: the route's index, then its upload progress.
fn load(
    source: SnapshotSource,
    c: &Corpus,
    index_path: &Path,
) -> Result<(ScanIndex, SnapshotUploadProgress)> {
    let (index, _, mut progress) = load_source_checkpoints(
        index_path,
        &progress_path(index_path),
        source,
        &c.support,
        &namespace(),
        snapshot_quarantine_witness(source),
    )?;
    progress
        .accepted_identity_buckets
        .bind_test_key(Some([0x42; 32]));
    Ok((index, progress))
}

/// Every durable progress field, as the ledger and both maps hold them.
fn durable(progress: &SnapshotUploadProgress) -> Value {
    serde_json::to_value(progress).unwrap()
}

fn without_generation(mut value: Value) -> Value {
    value.as_object_mut().unwrap().remove("generation");
    value
}

/// The destination: it credits each entity's latest exact body once. A
/// re-offer of a credited body is a duplicate and moves no credit.
#[derive(Default)]
struct Receiver {
    bodies: BTreeMap<String, String>,
    credit: BTreeMap<String, u64>,
    duplicates: usize,
}

impl Receiver {
    fn respond(
        &mut self,
        batch: &[SnapshotItem],
    ) -> Result<crate::snapshot_client::SnapshotBatchResponse> {
        for item in batch {
            let witness = snapshot_upload_body_witness(item);
            if self.bodies.get(&item.snapshot_fingerprint) == Some(&witness) {
                self.duplicates += 1;
                continue;
            }
            self.bodies
                .insert(item.snapshot_fingerprint.clone(), witness);
            self.credit
                .insert(item.source_session_id.clone(), item.request_count);
        }
        ack(batch)
    }
}

/// The production upload of `page` to `receiver`, persisting each ACK with
/// the production ledger save.
fn send_to(
    source: SnapshotSource,
    page: &Page,
    progress: &mut SnapshotUploadProgress,
    index_path: &Path,
    receiver: &mut Receiver,
) -> (Result<ResumableUploadResult>, RouteResult) {
    let path = progress_path(index_path);
    send_with(
        source,
        page,
        progress,
        |batch| receiver.respond(batch),
        |progress| progress.save(&path),
    )
}

/// The production pass end after an exact ACK: the page's ledger, then the
/// graph, then the pass-end ledger save.
fn settle(page: &mut Page, progress: &mut SnapshotUploadProgress, index_path: &Path) {
    let path = progress_path(index_path);
    progress.save(&path).unwrap();
    page.index
        .record_accepted_snapshot_fingerprints(&progress.accepted_fingerprints);
    accept_upload_context_acks_for_test(
        &mut page.index,
        &page.scan.snapshots,
        &progress.fresh_context_body_acks,
    );
    page.index.save(index_path).unwrap();
    progress.finish_cycle(&path).unwrap();
}

/// The graph never settles an ACK the committed ledger does not hold.
fn assert_graph_behind_ledger(index: &ScanIndex, progress: &SnapshotUploadProgress) {
    let ahead = index
        .accepted_snapshot_fingerprints_for_test()
        .difference(&progress.accepted_fingerprints)
        .collect::<Vec<_>>();
    assert!(
        ahead.is_empty(),
        "graph settled ACKs past the ledger: {ahead:?}"
    );
}

/// A restart of a settled route reads no transcript byte and emits nothing.
fn assert_quiet(source: SnapshotSource, c: &Corpus, index: ScanIndex) -> Page {
    let ((quiet, bytes), samples) = crate::transcript_acquisition::capture_sample_reads(|| {
        fixture::observe_consumed(|| native_page(source, c, index, 100, true))
    });
    assert!(quiet.scan.snapshots.is_empty(), "{source:?}: quiet restart");
    assert_eq!(quiet.modes.0, 0, "{source:?}: quiet restart read Full");
    assert_eq!(
        bytes, 0,
        "{source:?}: settled restart consumes no transcript"
    );
    if source == SOURCE {
        assert!(samples.is_empty());
        let mut control = accept(source, &quiet);
        control.mode = Mode::Restart;
        control.io = fixture::IoBytes {
            consumed: bytes,
            cheap_checks: Some(0),
            anchor_reads: Some(0),
            other_reads: Some(0),
            ..Default::default()
        };
        money_oracle::assert_quiet_restart_zero_bytes(&control);
    }
    quiet
}

/// The post-ACK placement ledger of `sessions`, as `send` observes it.
fn placement(progress: &SnapshotUploadProgress, sessions: impl Iterator<Item = String>) -> Value {
    serde_json::to_value(
        sessions
            .map(|session| {
                let buckets = progress.accepted_identity_buckets.get(&session);
                (session, serde_json::to_value(buckets).unwrap())
            })
            .collect::<BTreeMap<_, _>>(),
    )
    .unwrap()
}

/// What the custody store holds for the route's upload progress.
#[derive(Debug)]
struct Rows {
    capability: Option<u64>,
    generation: Option<u64>,
    import: Option<Value>,
    cache_state: usize,
    cache_head: usize,
    ledger: bool,
}

fn store(index_path: &Path) -> rusqlite::Connection {
    let conn = rusqlite::Connection::open(sibling(index_path, ".v2.sqlite")).unwrap();
    conn.busy_timeout(std::time::Duration::from_secs(5))
        .unwrap();
    conn
}

fn control(conn: &rusqlite::Connection, name: &str) -> Option<Value> {
    conn.query_row("SELECT value FROM control WHERE name=?1", [name], |row| {
        row.get::<_, Vec<u8>>(0)
    })
    .optional()
    .unwrap()
    .map(|bytes| serde_json::from_slice(&bytes).unwrap())
}

fn rows(index_path: &Path) -> Rows {
    let conn = store(index_path);
    let count = |sql: &str, kind: &str| -> usize {
        let n: i64 = conn.query_row(sql, [kind], |row| row.get(0)).unwrap();
        usize::try_from(n).unwrap()
    };
    let members = "SELECT count(*) FROM records WHERE kind=?1 AND position=1";
    Rows {
        capability: control(&conn, "minimum_writer_capability").and_then(|v| v.as_u64()),
        generation: control(&conn, "progress_generation").and_then(|v| v.as_u64()),
        import: control(&conn, "progress_import"),
        cache_state: count(members, "progress.cache_state"),
        cache_head: count(members, "progress.cache_head"),
        ledger: count(
            "SELECT count(*) FROM records WHERE kind=?1 AND key_bytes=x'' AND position=1",
            "progress.ledger",
        ) == 1,
    }
}

type StoredKey = (String, Vec<u8>, i64);
type RowDigests = (Option<Value>, BTreeMap<StoredKey, Vec<u8>>);

/// Every durable progress row by key with its value digest, and the CAS value.
fn row_digests(index_path: &Path) -> RowDigests {
    let conn = store(index_path);
    let mut stmt = conn
        .prepare(
            "SELECT kind,key_bytes,position,value_digest FROM records \
             WHERE kind LIKE 'progress.%' ORDER BY kind,key_bytes,position",
        )
        .unwrap();
    let rows = stmt
        .query_map([], |row| -> rusqlite::Result<(StoredKey, Vec<u8>)> {
            Ok(((row.get(0)?, row.get(1)?, row.get(2)?), row.get(3)?))
        })
        .unwrap()
        .map(Result::unwrap)
        .collect();
    (control(&conn, "progress_generation"), rows)
}

/// The route's progress lives in rows only: capability 6, the import
/// marker, the RAM generation as the CAS value, every keyed member of RAM, and
/// no JSON ledger, ACK receipt or failed-import copy beside the index.
fn assert_rows_custody(index_path: &Path, progress: &SnapshotUploadProgress) {
    let rows = rows(index_path);
    assert_eq!(
        rows.capability,
        Some(6),
        "progress rows need writer capability 6"
    );
    assert!(
        rows.import.is_some(),
        "the import marker is committed: {rows:?}"
    );
    assert_eq!(
        rows.generation.unwrap_or(0),
        progress.generation,
        "RAM generation is the committed progress CAS value"
    );
    assert!(rows.ledger, "one ledger row");
    assert_eq!(rows.cache_state, progress.accepted_cache_states.len());
    assert_eq!(rows.cache_head, progress.accepted_cache_heads.len());
    assert_leftovers_purged(index_path);
}

fn assert_leftovers_purged(index_path: &Path) {
    for path in [
        progress_path(index_path),
        receipt(index_path),
        failed_import(index_path),
    ] {
        assert!(!path.exists(), "{} is purged", path.display());
    }
    // A leftover the load read and refused would be renamed, not purged.
    let parent = index_path.parent().unwrap();
    let read = std::fs::read_dir(parent)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|name| name.contains("corrupt"))
        .collect::<Vec<_>>();
    assert!(read.is_empty(), "a leftover was read: {read:?}");
}

/// Synthetic keyed cache evidence beside the real ACKs.
fn seed_keyed(progress: &mut SnapshotUploadProgress, n: u32) {
    let key = cache_session_key(&format!("progress-rows-{n}"));
    progress
        .accepted_cache_heads
        .insert(key.clone(), format!("{n:064x}"));
    progress
        .accepted_cache_states
        .insert(key, json!({ "observations": [] }));
}

/// A stored Claude identity body: `rows` are (bucket hour, account, evidence
/// basis or None for a gap, side-call parts).
fn identity_body(session: &str, rows: &[(u8, char, Option<&str>, bool)]) -> Value {
    let mut evidence = Vec::new();
    let mut buckets = BTreeMap::<String, Vec<Value>>::new();
    for (n, (hour, account, basis, side)) in rows.iter().enumerate() {
        evidence.push(match basis {
            Some(basis) => json!({"identity_basis": basis,
                "provider_workspace_hash": account.to_string().repeat(64)}),
            None => json!({}),
        });
        let login = account.to_string().repeat(64);
        let mut row = json!({"model": format!("claude-synthetic-{n}"), "evidence_ref": n,
            "account_identifier_hash": login});
        if *side {
            // A side call: one row's request split over two tagged parts.
            row["identity_parts"] = json!([
                {"evidence_ref": n, "account_identifier_hash": login},
                {"evidence_ref": 0, "account_identifier_hash": "b".repeat(64)},
            ]);
        }
        buckets
            .entry(format!("2026-09-01T{hour:02}:00:00Z"))
            .or_default()
            .push(row);
    }
    json!({"source_session_id": session, "snapshot_fingerprint": cache_session_key(session),
        "provenance": {"collector": crate::snapshots::claude_request_identity::COLLECTOR},
        "request_evidence": evidence,
        "usage_buckets": buckets.into_iter()
            .map(|(start, rows)| json!({"bucket_start": start, "model_usage": rows}))
            .collect::<Vec<_>>()})
}

/// Every named money map of the ledger holds an entry: refusals, quarantine,
/// body contexts and identity placement over two accounts, a switch, a side
/// call, an evidence gap and a tagged row.
fn seed_money_maps(progress: &mut SnapshotUploadProgress) {
    let accepted = progress
        .accepted_fingerprints
        .iter()
        .next()
        .expect("a real ACK")
        .clone();
    progress
        .accepted_body_contexts
        .insert(accepted, "d".repeat(64));
    let refused = "e1".repeat(32);
    progress.permanent_rejections.insert(
        refused,
        PermanentSnapshotRejection {
            body_witness: "e2".repeat(32),
            exposure: None,
            revisions: BTreeMap::new(),
            reason: crate::upload_receipts::RejectedUsageReason::Other,
            reoffer: None,
        },
    );
    let quarantined = "e3".repeat(32);
    let retry = quarantine_retry_after(&quarantined);
    progress.quarantine_retryable_body(&quarantined, &"e4".repeat(32), retry);
    let switch = identity_body(
        "progress-rows-switch",
        &[
            (10, 'a', Some("telemetry_login"), false),
            (11, 'b', Some("telemetry_login"), false),
        ],
    );
    let side = identity_body(
        "progress-rows-side-call",
        &[
            (10, 'a', Some("telemetry_login"), true),
            (10, 'c', None, false),
        ],
    );
    for body in [switch, side] {
        progress.record_cache_state(&body, false).unwrap();
    }
}

fn assert_money_maps(progress: &SnapshotUploadProgress) {
    assert!(!progress.accepted_fingerprints.is_empty(), "real ACKs");
    assert!(!progress.accepted_body_contexts.is_empty(), "contexts");
    assert!(!progress.permanent_rejections.is_empty(), "refusals");
    assert!(!progress.quarantined_fingerprints.is_empty(), "quarantine");
    for (session, shares) in [("progress-rows-switch", 2), ("progress-rows-side-call", 1)] {
        let buckets = progress.accepted_identity_buckets.get(session);
        assert!(
            buckets.is_some_and(|buckets| buckets.len() >= shares),
            "{session}: identity placement"
        );
    }
}

/// A route whose pre-publication JSON ledger carries real ACKs, keyed cache
/// evidence and every money map: the progress-import input. `generation`
/// rewrites the JSON generation, as an older save would have left it. Returns
/// the published session, its exact JSON bytes and the JSON branch's own load
/// of those bytes (the oracle).
fn published_with_json_ledger(
    source: SnapshotSource,
    c: &Corpus,
    generation: Option<u64>,
) -> (StateV2ColdSession, Vec<u8>, SnapshotUploadProgress) {
    let dir = c.base.join("state");
    let index_path = dir
        .join("snapshots/destinations")
        .join(namespace())
        .join(format!("{}-synthetic-scan-index.json", source.api_slug()));
    std::fs::create_dir_all(index_path.parent().unwrap()).unwrap();
    let path = progress_path(&index_path);
    // Before publication the ledger is today's JSON: uploads keep saving it.
    let mut progress =
        SnapshotUploadProgress::load(&path, &namespace(), snapshot_quarantine_witness(source))
            .unwrap();
    progress
        .accepted_identity_buckets
        .bind_test_key(Some([0x42; 32]));
    let mut page = native_page(source, c, ScanIndex::default(), 100, false);
    let (status, _) = send_with(source, &page, &mut progress, ack, |progress| {
        progress.save(&path)
    });
    assert_eq!(status.unwrap(), ResumableUploadResult::Completed);
    for n in 1..=3 {
        seed_keyed(&mut progress, n);
    }
    seed_money_maps(&mut progress);
    progress.save(&path).unwrap();
    let mut bytes = std::fs::read(&path).unwrap();
    if let Some(generation) = generation {
        let mut value: Value = serde_json::from_slice(&bytes).unwrap();
        value["generation"] = json!(generation);
        bytes = serde_json::to_vec(&value).unwrap();
        std::fs::write(path.as_path(), &bytes).unwrap();
    }
    page.index
        .record_accepted_snapshot_fingerprints(&progress.accepted_fingerprints);
    accept_upload_context_acks_for_test(
        &mut page.index,
        &page.scan.snapshots,
        &progress.fresh_context_body_acks,
    );
    let (session, _) =
        StateV2ColdSession::publish_with_progress(db_source(source), &page.index, &dir, &bytes);
    assert_eq!(session.path(), index_path.as_path());
    let oracle = json_oracle(c, &bytes, source);
    assert!(
        oracle.accepted_cache_heads.len() >= 3 && oracle.accepted_cache_states.len() >= 3,
        "keyed evidence"
    );
    assert_money_maps(&oracle);
    (session, bytes, oracle)
}

/// Today's JSON branch loading `bytes` elsewhere.
fn json_oracle(c: &Corpus, bytes: &[u8], source: SnapshotSource) -> SnapshotUploadProgress {
    static COPIES: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let n = COPIES.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let copy = c.base.join(format!("oracle/{n}-upload-progress.json"));
    std::fs::create_dir_all(copy.parent().unwrap()).unwrap();
    std::fs::write(&copy, bytes).unwrap();
    let mut oracle =
        SnapshotUploadProgress::load(&copy, &namespace(), snapshot_quarantine_witness(source))
            .unwrap();
    oracle
        .accepted_identity_buckets
        .bind_test_key(Some([0x42; 32]));
    std::fs::remove_file(&copy).unwrap();
    oracle
}

/// The import moved exactly the JSON ledger into rows at progress generation
/// 1, under a marker naming those bytes and their original generation.
fn assert_imported(
    index_path: &Path,
    imported: &SnapshotUploadProgress,
    bytes: &[u8],
    oracle: &SnapshotUploadProgress,
) {
    // Identity placement moves to one identity row per session, stamped with
    // the imported P; the ledger keeps only their scope.
    let hints = |progress: &SnapshotUploadProgress| {
        let mut value = without_generation(durable(progress));
        let fields = value.as_object_mut().unwrap();
        fields.remove("accepted_identity_scope");
        fields
            .remove("accepted_identity_buckets")
            .unwrap_or_default()
    };
    let (mut ours, theirs) = (without_generation(durable(imported)), hints(oracle));
    assert!(hints(imported).is_null(), "no hint stays resident");
    ours.as_object_mut()
        .unwrap()
        .remove("accepted_identity_scope");
    let mut expected = without_generation(durable(oracle));
    expected
        .as_object_mut()
        .unwrap()
        .remove("accepted_identity_buckets");
    assert_eq!(ours, expected, "the rows carry every JSON field");
    assert_money_maps(imported);
    let names = theirs
        .as_object()
        .unwrap()
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    assert!(!names.is_empty(), "identity placement to move");
    let rows = imported.rows.as_ref().unwrap();
    let stored = rows
        .read_points::<crate::snapshots::ProgressPoint<Value>>(&names, |_, _| true)
        .unwrap();
    for (name, hint) in theirs.as_object().unwrap() {
        let point = &stored[name];
        assert_eq!(point.progress_generation, 1, "stamped with the imported P");
        assert_eq!(&point.accepted, hint, "the identity row is the JSON hint");
    }
    let ledger = imported.clone().ledger_row().unwrap();
    assert!(ledger.get("accepted_identity_buckets").is_none());
    assert!(ledger.get("accepted_identity_scope").is_some(), "the scope");
    for keyed in [
        "accepted_cache_states",
        "accepted_cache_heads",
        "generation",
    ] {
        assert!(ledger.get(keyed).is_none(), "{keyed} is not in the ledger");
    }
    assert_rows_custody(index_path, imported);
    let rows = rows(index_path);
    assert_eq!(rows.generation, Some(1), "the import commits P 0 -> 1");
    assert_eq!(imported.generation, 1, "RAM holds the imported P");
    let marker = rows.import.unwrap();
    assert_eq!(
        marker["sha256"],
        json!(crate::hex::encode(&Sha256::digest(bytes))),
        "the marker names the imported bytes"
    );
    assert_eq!(
        marker["generation"],
        json!(oracle.generation),
        "the marker keeps the JSON generation"
    );
}

fn published(source: SnapshotSource, c: &Corpus) -> StateV2ColdSession {
    StateV2ColdSession::publish(
        db_source(source),
        &ScanIndex::default(),
        &c.base.join("state"),
    )
    .0
}

/// [money] On a published route, for every source: the first page's upload
/// equals cold Full, a restart restores the exact ledger and emits nothing,
/// and an appended turn re-emits every session, never smaller than cold Full.
/// The ledger then lives in rows alone.
#[test]
#[serial]
fn progress_rows_route_equals_cold_full_across_restart_and_append() {
    with_e2(|| {
        let mut settled = Vec::new();
        for source in SOURCES {
            let (c, paths) = native_corpus_in(
                corpus(&format!("progress-rows-route-{}", source.api_slug())),
                source,
                &SESSIONS,
            );
            let session = published(source, &c);
            let path = session.path();
            // Cold Full over its own ledger: the ACK history (accepted
            // identity bucket sequence) the route's ledger must match.
            let mut reference = super::progress(source);
            let cold_page = native_page(source, &c, ScanIndex::default(), 100, false);
            let (status, cold) = send(source, &cold_page, &mut reference, ack);
            assert_eq!(status.unwrap(), ResumableUploadResult::Completed);
            assert_eq!(cold.snapshots.len(), 3, "nonempty cold control");

            let (index, mut progress) = load(source, &c, path).unwrap();
            let mut page = native_page(source, &c, index, 100, true);
            let mut receiver = Receiver::default();
            let (status, first) = send_to(source, &page, &mut progress, path, &mut receiver);
            assert_eq!(status.unwrap(), ResumableUploadResult::Completed);
            money_oracle::assert_equivalent(&cold, &first);
            settle(&mut page, &mut progress, path);
            let ram = durable(&progress);
            drop((page, progress));

            let (index, restored) = load(source, &c, path).unwrap();
            assert_eq!(
                durable(&restored),
                ram,
                "{source:?}: restart restores the ledger"
            );
            let quiet = assert_quiet(source, &c, index);

            for (path, session) in paths.iter().zip(SESSIONS) {
                append(path, &response_line(source, session, 2));
            }
            let cold_page = native_page(source, &c, ScanIndex::default(), 100, false);
            let (status, cold) = send(source, &cold_page, &mut reference, ack);
            assert_eq!(status.unwrap(), ResumableUploadResult::Completed);
            let mut progress = restored;
            let mut page = native_page(source, &c, quiet.index, 100, true);
            let (status, mut again) = send_to(source, &page, &mut progress, path, &mut receiver);
            assert_eq!(status.unwrap(), ResumableUploadResult::Completed);
            again.mode = Mode::Restart;
            money_oracle::assert_equivalent(&cold, &again);
            for entity in &SESSIONS {
                money_oracle::assert_no_smaller_reemit(entity, &first, &again, &cold, false);
            }
            assert_eq!(receiver.duplicates, 0, "every offer was a new body");
            settle(&mut page, &mut progress, path);
            let ram = durable(&progress);
            drop(page);
            let (index, restored) = load(source, &c, path).unwrap();
            assert_eq!(durable(&restored), ram);
            assert_quiet(source, &c, index);
            settled.push((path.to_owned(), restored, session, c));
        }
        // Storage last: every source's money half has run first.
        for (path, restored, _, _) in &settled {
            assert_rows_custody(path, restored);
            // A page with no changed row commits nothing: no transaction, no P.
            v2::take_progress_pages_for_test();
            let mut idle = restored.clone();
            idle.save(&progress_path(path)).unwrap();
            let pages = v2::take_progress_pages_for_test();
            assert_eq!(
                (
                    pages.committed,
                    pages.unchanged,
                    pages.not_published,
                    pages.reload
                ),
                (0, 1, 0, 0),
                "an unchanged page"
            );
            assert_eq!(rows(path).generation, Some(restored.generation));
        }
    });
}

/// [money] For every source, a pass split over two pages with a partial
/// checkpoint between them emits the same second page whether or not the
/// daemon restarts between the pages. The pages emit disjoint entities and
/// together carry cold Full's money and placement.
#[test]
#[serial]
fn progress_rows_restart_between_pages_equals_in_ram_pages() {
    with_e2(|| {
        let mut second_pages = Vec::new();
        for source in SOURCES {
            for restart in [false, true] {
                let (c, _) = native_corpus_in(
                    corpus(&format!(
                        "progress-rows-pages-{}-{restart}",
                        source.api_slug()
                    )),
                    source,
                    &SESSIONS,
                );
                let session = published(source, &c);
                let path = session.path();
                let cold = accept(
                    source,
                    &native_page(source, &c, ScanIndex::default(), 100, false),
                );
                let (index, mut progress) = load(source, &c, path).unwrap();
                let first = native_page(source, &c, index, 2, true);
                assert!(!first.scan.census_complete, "a retained traversal");
                let mut receiver = Receiver::default();
                let (status, page_one) =
                    send_to(source, &first, &mut progress, path, &mut receiver);
                assert_eq!(status.unwrap(), ResumableUploadResult::Completed);
                let mut owed = checkpoint_partial_snapshot_index_with_audit_release(
                    &first.index,
                    &first.committed,
                    &progress,
                    &first.scan.snapshots,
                    Some(&first.scan),
                    &BTreeSet::new(),
                    path,
                    &progress_path(path),
                    || Ok(()),
                    None,
                    None,
                    None,
                    Default::default(),
                )
                .unwrap();
                if restart {
                    drop((first, progress));
                    (owed, progress) = load(source, &c, path).unwrap();
                }
                v2::release_collection_page_limit_for_test(&owed);
                let mut second = native_page(source, &c, owed, 100, true);
                let (status, mut page_two) =
                    send_to(source, &second, &mut progress, path, &mut receiver);
                assert_eq!(status.unwrap(), ResumableUploadResult::Completed);
                page_two.mode = if restart { Mode::Restart } else { Mode::Ram };
                assert_eq!(receiver.duplicates, 0, "no entity is offered twice");
                let mut both = page_one.clone();
                for (entity, body) in &page_two.snapshots {
                    assert!(
                        both.snapshots
                            .insert(entity.clone(), body.clone())
                            .is_none(),
                        "{source:?}: {entity} emitted on both pages"
                    );
                }
                both.accepted_identity_buckets =
                    Some(placement(&progress, both.snapshots.keys().cloned()));
                let mut differences = Vec::new();
                money_oracle::entity_differences(&cold, &both, &mut differences);
                assert!(differences.is_empty(), "{}", differences.join("\n"));
                money_oracle::assert_placement_equivalent(&cold, &both);
                settle(&mut second, &mut progress, path);
                let ram = durable(&progress);
                drop(second);
                let (index, restored) = load(source, &c, path).unwrap();
                assert_eq!(durable(&restored), ram);
                assert_quiet(source, &c, index);
                second_pages.push((page_two, path.to_owned(), restored, session, c));
            }
        }
        // Page two's money after a restart equals page two in RAM: the same
        // entities, totals and placement. Codex receipt-ownership evidence is
        // per-process tier-replay bookkeeping, not money, and is not compared.
        for pair in second_pages.chunks(2) {
            let (in_ram, restarted) = (&pair[0].0, &pair[1].0);
            assert_eq!(
                in_ram.snapshots.keys().collect::<Vec<_>>(),
                restarted.snapshots.keys().collect::<Vec<_>>()
            );
            let mut differences = Vec::new();
            money_oracle::entity_differences(in_ram, restarted, &mut differences);
            assert!(differences.is_empty(), "{}", differences.join("\n"));
        }
        for (_, path, restored, _, _) in &second_pages {
            assert_rows_custody(path, restored);
        }
    });
}

/// Insert synthetic 3, update synthetic 1, delete synthetic 2 in both keyed
/// maps, and change the ledger: every progress row kind is dirty.
fn dirty(progress: &mut SnapshotUploadProgress) {
    seed_keyed(progress, 3);
    let one = cache_session_key("progress-rows-1");
    progress
        .accepted_cache_heads
        .insert(one.clone(), "d".repeat(64));
    progress
        .accepted_cache_states
        .insert(one, json!({ "observations": [{"updated": true}] }));
    let two = cache_session_key("progress-rows-2");
    progress.accepted_cache_heads.remove(&two);
    progress.accepted_cache_states.remove(&two);
    progress.historical_replay_generation = Some("progress-rows-dirty".into());
}

/// [money] For every source, a page COMMIT that fails without publishing,
/// after an exact ACK and with both keyed maps and the ledger dirty, leaves
/// every durable row as it was and RAM as it is. Retried from the same RAM it
/// writes every row. Retried after a crash, the reload holds the old rows and
/// the pass re-offers the exact request bytes, which the receiver already
/// credited: a duplicate that moves no credit.
#[test]
#[serial]
fn progress_rows_commit_error_keeps_ram_and_retry_writes_every_row() {
    with_e2(|| {
        for source in SOURCES {
            for same_ram in [true, false] {
                let (c, _) = native_corpus_in(
                    corpus(&format!(
                        "progress-rows-commit-error-{}-{same_ram}",
                        source.api_slug()
                    )),
                    source,
                    &SESSIONS,
                );
                let session = published(source, &c);
                let path = session.path();
                let cold = accept(
                    source,
                    &native_page(source, &c, ScanIndex::default(), 100, false),
                );
                let (index, mut progress) = load(source, &c, path).unwrap();
                seed_keyed(&mut progress, 1);
                seed_keyed(&mut progress, 2);
                progress.save(&progress_path(path)).unwrap();
                let committed = durable(&progress);
                dirty(&mut progress);
                let before = row_digests(path);

                let mut page = native_page(source, &c, index, 100, true);
                let mut receiver = Receiver::default();
                v2::fail_next_progress_commit_for_test(&page.committed, None);
                let (status, first) = send_to(source, &page, &mut progress, path, &mut receiver);
                assert!(status.is_err(), "{source:?}: the page COMMIT fails");
                money_oracle::assert_equivalent(&cold, &first);
                assert!(
                    progress
                        .accepted_cache_heads
                        .contains_key(&cache_session_key("progress-rows-3")),
                    "RAM keeps the dirty rows"
                );
                assert_eq!(row_digests(path), before, "NotPublished leaves every row");
                let credit = receiver.credit.clone();

                if same_ram {
                    settle(&mut page, &mut progress, path);
                    assert_ne!(row_digests(path).1, before.1, "the retry wrote the rows");
                } else {
                    drop((page, progress));
                    let (index, mut restored) = load(source, &c, path).unwrap();
                    assert_eq!(
                        durable(&restored),
                        committed,
                        "the reload holds the old rows"
                    );
                    assert_graph_behind_ledger(&index, &restored);
                    dirty(&mut restored);
                    page = native_page(source, &c, index, 100, true);
                    let (status, again) =
                        send_to(source, &page, &mut restored, path, &mut receiver);
                    assert_eq!(status.unwrap(), ResumableUploadResult::Completed);
                    assert_eq!(
                        again.batches, first.batches,
                        "the exact bytes are re-offered"
                    );
                    assert_eq!(receiver.duplicates, first.snapshots.len());
                    assert_eq!(receiver.credit, credit, "a duplicate moves no credit");
                    progress = restored;
                    settle(&mut page, &mut progress, path);
                }
                let ram = durable(&progress);
                drop(page);
                let (index, restored) = load(source, &c, path).unwrap();
                assert_eq!(durable(&restored), ram, "the retry wrote every row");
                assert_quiet(source, &c, index);
                assert_rows_custody(path, &restored);
            }
        }
    });
}

/// [money] A page COMMIT that becomes durable but reports an error
/// (Published) and one whose outcome is unknown (Ambiguous: another writer
/// moved the CAS) both stop the pass and reload. After Published the reload
/// holds the ACKs and nothing is offered again; after Ambiguous the pass
/// re-offers the exact request bytes, a receiver duplicate. Either way the
/// settled route equals cold Full and restarts quietly.
#[test]
#[serial]
fn progress_rows_published_or_ambiguous_commit_reloads_and_reoffers_exactly() {
    with_e2(|| {
        for published_arm in [true, false] {
            let (c, _) = native_corpus_in(
                corpus(&format!("progress-rows-reload-{published_arm}")),
                SOURCE,
                &SESSIONS,
            );
            let session = published(SOURCE, &c);
            let path = session.path();
            let cold = accept(
                SOURCE,
                &native_page(SOURCE, &c, ScanIndex::default(), 100, false),
            );
            let (index, mut progress) = load(SOURCE, &c, path).unwrap();
            let page = native_page(SOURCE, &c, index, 100, true);
            let before = rows(path).generation.unwrap_or(0);
            if published_arm {
                v2::lose_next_progress_commit_reply_for_test(&page.committed);
            } else {
                v2::fail_next_progress_commit_for_test(&page.committed, Some(before + 5));
            }
            let mut receiver = Receiver::default();
            let (status, first) = send_to(SOURCE, &page, &mut progress, path, &mut receiver);
            assert!(status.is_err(), "the page stops and reloads");
            money_oracle::assert_equivalent(&cold, &first);
            let acked = without_generation(durable(&progress));
            let credit = receiver.credit.clone();
            drop((page, progress));

            let (index, mut progress) = load(SOURCE, &c, path).unwrap();
            assert_graph_behind_ledger(&index, &progress);
            let reloaded = progress.generation;
            let mut page = native_page(SOURCE, &c, index, 100, true);
            let (status, again) = send_to(SOURCE, &page, &mut progress, path, &mut receiver);
            assert_eq!(status.unwrap(), ResumableUploadResult::Completed);
            if published_arm {
                assert_eq!(reloaded, before + 1, "the durable page");
                assert_eq!(progress.generation, before + 1, "nothing more to commit");
                assert!(
                    again.batches.is_empty(),
                    "committed ACKs are not re-offered"
                );
                assert_eq!(without_generation(durable(&progress)), acked);
            } else {
                assert_eq!(reloaded, before + 5, "the reload reads the committed CAS");
                assert_eq!(
                    progress.generation,
                    before + 6,
                    "the re-offered page commits on it"
                );
                assert_eq!(
                    again.batches, first.batches,
                    "the exact bytes are re-offered"
                );
                assert_eq!(receiver.duplicates, first.snapshots.len());
            }
            assert_eq!(
                receiver.credit, credit,
                "the receiver credited each body once"
            );
            settle(&mut page, &mut progress, path);
            let ram = durable(&progress);
            drop(page);
            let (index, restored) = load(SOURCE, &c, path).unwrap();
            assert_eq!(durable(&restored), ram);
            assert_quiet(SOURCE, &c, index);
            assert_rows_custody(path, &restored);
        }
    });
}

/// [money] With the production ledger save as the upload's persistence: a
/// crash between the ACK and the page COMMIT re-offers the exact bytes once
/// (a receiver duplicate), and a crash after the COMMIT but before the graph
/// save offers nothing again and settles from the ledger. In both windows the
/// reloaded graph never settles more than the committed ledger.
#[test]
#[serial]
fn progress_rows_crash_windows_never_let_the_graph_outrun_the_ledger() {
    with_e2(|| {
        for committed in [false, true] {
            let (c, _) = native_corpus_in(
                corpus(&format!("progress-rows-crash-{committed}")),
                SOURCE,
                &SESSIONS,
            );
            let session = published(SOURCE, &c);
            let path = session.path();
            let cold = accept(
                SOURCE,
                &native_page(SOURCE, &c, ScanIndex::default(), 100, false),
            );
            let (index, mut progress) = load(SOURCE, &c, path).unwrap();
            let page = native_page(SOURCE, &c, index, 100, true);
            if !committed {
                v2::fail_next_progress_commit_for_test(&page.committed, None);
            }
            let mut receiver = Receiver::default();
            let (status, first) = send_to(SOURCE, &page, &mut progress, path, &mut receiver);
            assert_eq!(status.is_ok(), committed, "the ACK's page COMMIT");
            money_oracle::assert_equivalent(&cold, &first);
            let credit = receiver.credit.clone();
            // The crash: neither the graph save nor the pass end runs.
            drop((page, progress));

            let (index, mut progress) = load(SOURCE, &c, path).unwrap();
            assert_graph_behind_ledger(&index, &progress);
            assert_eq!(
                progress.accepted_fingerprints.is_empty(),
                !committed,
                "the ledger holds exactly the committed ACKs"
            );
            let mut page = native_page(SOURCE, &c, index, 100, true);
            let (status, again) = send_to(SOURCE, &page, &mut progress, path, &mut receiver);
            assert_eq!(status.unwrap(), ResumableUploadResult::Completed);
            if committed {
                assert!(
                    again.batches.is_empty(),
                    "committed ACKs are not re-offered"
                );
            } else {
                assert_eq!(
                    again.batches, first.batches,
                    "the exact bytes are re-offered"
                );
                assert_eq!(receiver.duplicates, first.snapshots.len());
            }
            assert_eq!(receiver.credit, credit, "each body was credited once");
            settle(&mut page, &mut progress, path);
            assert_graph_behind_ledger(&page.index, &progress);
            let ram = durable(&progress);
            drop(page);
            let (index, restored) = load(SOURCE, &c, path).unwrap();
            assert_eq!(durable(&restored), ram);
            assert_quiet(SOURCE, &c, index);
            assert_rows_custody(path, &restored);
        }
    });
}

/// [money] The pass's own graph commits (a partial checkpoint, a claim-only
/// growth save, a mid-pass index save) never make its next progress page
/// reload: page two commits, and no page of the pass reloads.
#[test]
#[serial]
fn progress_rows_own_graph_saves_never_reload_the_next_page() {
    with_e2(|| {
        for arm in ["checkpoint", "growth", "save"] {
            let (c, _) = native_corpus_in(
                corpus(&format!("progress-rows-own-save-{arm}")),
                SOURCE,
                &SESSIONS,
            );
            let session = published(SOURCE, &c);
            let path = session.path();
            let cold = accept(
                SOURCE,
                &native_page(SOURCE, &c, ScanIndex::default(), 100, false),
            );
            let (index, mut progress) = load(SOURCE, &c, path).unwrap();
            let mut first = native_page(SOURCE, &c, index, 2, true);
            let mut receiver = Receiver::default();
            v2::take_progress_pages_for_test();
            let (status, page_one) = send_to(SOURCE, &first, &mut progress, path, &mut receiver);
            assert_eq!(status.unwrap(), ResumableUploadResult::Completed);
            let owed = match arm {
                "checkpoint" => checkpoint_partial_snapshot_index_with_audit_release(
                    &first.index,
                    &first.committed,
                    &progress,
                    &first.scan.snapshots,
                    Some(&first.scan),
                    &BTreeSet::new(),
                    path,
                    &progress_path(path),
                    || Ok(()),
                    None,
                    None,
                    None,
                    Default::default(),
                )
                .unwrap(),
                "growth" => {
                    v2::claim_growth_for_test(path, &first.index);
                    first.index
                }
                _ => {
                    first
                        .index
                        .record_accepted_snapshot_fingerprints(&progress.accepted_fingerprints);
                    first.index.save(path).unwrap();
                    first.index
                }
            };
            v2::release_collection_page_limit_for_test(&owed);
            let mut second = native_page(SOURCE, &c, owed, 100, true);
            let (status, page_two) = send_to(SOURCE, &second, &mut progress, path, &mut receiver);
            assert_eq!(status.unwrap(), ResumableUploadResult::Completed);
            let mut both = page_one.clone();
            both.snapshots.extend(page_two.snapshots.clone());
            let mut differences = Vec::new();
            money_oracle::entity_differences(&cold, &both, &mut differences);
            assert!(differences.is_empty(), "{arm}: {}", differences.join("\n"));
            let pages = v2::take_progress_pages_for_test();
            assert_eq!(
                pages.reload, 0,
                "{arm}: an own graph commit reloaded a page"
            );
            assert!(
                pages.committed >= 2,
                "{arm}: both pages committed: {pages:?}"
            );
            settle(&mut second, &mut progress, path);
            let ram = durable(&progress);
            drop(second);
            let (index, restored) = load(SOURCE, &c, path).unwrap();
            assert_eq!(durable(&restored), ram);
            assert_quiet(SOURCE, &c, index);
            assert_rows_custody(path, &restored);
        }
    });
}

/// [money] For every source, uploads before publication keep saving the JSON
/// ledger; the first load after publication imports exactly those bytes,
/// every money map included, at progress generation 1 whatever the JSON
/// generation (0 or many saves), and the route then restarts quietly.
#[test]
#[serial]
fn progress_rows_import_carries_the_pre_publication_json_ledger() {
    with_e2(|| {
        for source in SOURCES {
            for generation in [Some(0), None] {
                let (c, _) = native_corpus_in(
                    corpus(&format!(
                        "progress-rows-import-{}-{generation:?}",
                        source.api_slug()
                    )),
                    source,
                    &SESSIONS,
                );
                let (session, bytes, oracle) = published_with_json_ledger(source, &c, generation);
                if generation.is_none() {
                    assert!(oracle.generation > 1, "several JSON saves");
                }
                let path = session.path();
                let (_, imported) = load(source, &c, path).unwrap();
                assert_imported(path, &imported, &bytes, &oracle);
                let (index, restored) = load(source, &c, path).unwrap();
                assert_eq!(
                    durable(&restored),
                    durable(&imported),
                    "restart reads the rows"
                );
                assert_money_maps(&restored);
                assert_quiet(source, &c, index);
            }
        }
    });
}

/// [money] For every source, an import whose COMMIT fails without publishing
/// leaves the JSON ledger exactly as it was and nothing imported, and holds
/// this pass; the next load imports it at progress generation 1. An import
/// whose COMMIT became durable but reported an error holds this pass too; the
/// next load finds the marker and does not import again.
#[test]
#[serial]
fn progress_rows_import_commit_error_keeps_the_json_and_reimports() {
    with_e2(|| {
        for source in SOURCES {
            for durable_commit in [false, true] {
                let (c, _) = native_corpus_in(
                    corpus(&format!(
                        "progress-rows-import-error-{}-{durable_commit}",
                        source.api_slug()
                    )),
                    source,
                    &SESSIONS,
                );
                let (session, bytes, oracle) = published_with_json_ledger(source, &c, None);
                let path = session.path();
                v2::before_progress_import_for_test(move |index| {
                    if durable_commit {
                        v2::lose_next_progress_commit_reply_for_test(index);
                    } else {
                        v2::fail_next_progress_commit_for_test(index, None);
                    }
                });
                assert!(
                    load(source, &c, path).is_err(),
                    "{source:?}: a failed import COMMIT holds this pass"
                );
                let after = rows(path);
                if durable_commit {
                    assert_eq!(after.generation, Some(1), "the durable import");
                    assert!(after.import.is_some(), "its marker");
                } else {
                    assert_eq!(std::fs::read(progress_path(path)).unwrap(), bytes);
                    assert!(
                        after.import.is_none()
                            && after.generation.is_none()
                            && !after.ledger
                            && after.cache_state + after.cache_head == 0,
                        "nothing imported: {after:?}"
                    );
                }
                let (_, imported) = load(source, &c, path).unwrap();
                assert_imported(path, &imported, &bytes, &oracle);
            }
        }
    });
}

/// [money] After the import COMMIT, before or during the purge: the marker
/// wins, so a JSON ledger, ACK receipt or failed-import copy still beside the
/// index is purged unread (each is malformed: reading it would refuse or
/// quarantine it), and the rows load unchanged. A competing import that
/// completes after this load decided to import is found inside its write
/// transaction and never overwritten.
#[test]
#[serial]
fn progress_rows_import_marker_purges_leftovers_unread() {
    with_e2(|| {
        for json_left in [true, false] {
            let (c, _) = native_corpus_in(
                corpus(&format!("progress-rows-purge-{json_left}")),
                SOURCE,
                &SESSIONS,
            );
            let (session, bytes, oracle) = published_with_json_ledger(SOURCE, &c, None);
            let path = session.path();
            let (_, imported) = load(SOURCE, &c, path).unwrap();
            assert_imported(path, &imported, &bytes, &oracle);
            if json_left {
                write_owned(&progress_path(path), b"\xffnot a ledger");
            }
            write_owned(&receipt(path), b"\xffnot a receipt");
            write_owned(&failed_import(path), b"\xffnot a seal");
            let (_, restored) = load(SOURCE, &c, path).unwrap();
            assert_eq!(
                durable(&restored),
                durable(&imported),
                "leftovers are never read"
            );
            assert_rows_custody(path, &restored);
        }

        let (c, _) = native_corpus_in(corpus("progress-rows-competing-import"), SOURCE, &SESSIONS);
        let (session, _, oracle) = published_with_json_ledger(SOURCE, &c, None);
        let path = session.path();
        let mut competitor = durable(&oracle);
        competitor["generation"] = json!(41);
        competitor["accepted_cache_heads"][cache_session_key("progress-rows-competitor")] =
            json!("f".repeat(64));
        let competitor = serde_json::to_vec(&competitor).unwrap();
        let expected = json_oracle(&c, &competitor, SOURCE);
        let theirs = competitor.clone();
        v2::before_progress_import_for_test(move |index| {
            v2::import_progress_rows_for_test(index, &theirs);
        });
        let (_, loaded) = load(SOURCE, &c, path).unwrap();
        assert_imported(path, &loaded, &competitor, &expected);
    });
}

/// The digest an ACK receipt names its progress bytes by.
fn receipt_digest(bytes: &[u8]) -> Value {
    let mut hash = Sha256::new();
    hash.update(b"ottto.state-v2.ack-progress.v1\0");
    hash.update(bytes);
    json!(hash.finalize().to_vec())
}

/// A legacy ACK receipt whose `next` progress was never renamed over
/// `previous`, as a crash between the receipt and the JSON rename leaves it.
fn receipt_ahead(index_path: &Path, identity: Value, previous: &[u8], next: &[u8]) -> Vec<u8> {
    let generation = |bytes: &[u8]| {
        serde_json::from_slice::<Value>(bytes).unwrap()["generation"]
            .as_u64()
            .unwrap_or(0)
    };
    let scope = json!({"generation": identity["fence_generation"], "identity": identity});
    let value = json!({"version": 1, "scope": scope,
        "previous_generation": generation(previous), "previous_digest": receipt_digest(previous),
        "generation": generation(next), "digest": receipt_digest(next),
        "progress": std::str::from_utf8(next).unwrap()});
    let bytes = serde_json::to_vec(&value).unwrap();
    write_owned(&receipt(index_path), &bytes);
    bytes
}

/// [money] Legacy custody beside a not-yet-imported JSON ledger. A receipt
/// ahead of the JSON holds the exact pending ACK: the import carries the
/// receipt's ledger, never the older JSON. A failed-import seal from an
/// earlier publication attempt (another store id) is purged, and the JSON's
/// ACKs import. Either way no ACK is lost and the leftovers are purged.
#[test]
#[serial]
fn progress_rows_import_keeps_the_pending_ack_of_legacy_custody() {
    with_e2(|| {
        for receipt_arm in [true, false] {
            let (c, _) = native_corpus_in(
                corpus(&format!("progress-rows-legacy-{receipt_arm}")),
                SOURCE,
                &SESSIONS,
            );
            let (session, bytes, oracle) = published_with_json_ledger(SOURCE, &c, None);
            let path = session.path();
            let identity = control(&store(path), "identity").expect("a published identity");
            let (expected, imported_bytes) = if receipt_arm {
                let mut next = durable(&oracle);
                next["generation"] = json!(oracle.generation + 1);
                next["accepted_cache_heads"][cache_session_key("progress-rows-pending")] =
                    json!("a1".repeat(32));
                let next = serde_json::to_vec(&next).unwrap();
                receipt_ahead(path, identity, &bytes, &next);
                (json_oracle(&c, &next, SOURCE), next)
            } else {
                let mut other = identity;
                other["db_id"] = json!("an-earlier-publication-attempt");
                let seal = json!({"version": 1,
                    "scope": {"generation": other["fence_generation"], "identity": other},
                    "previous_generation": oracle.generation, "previous_digest": receipt_digest(&bytes),
                    "generation": oracle.generation, "digest": receipt_digest(&bytes),
                    "progress": std::str::from_utf8(&bytes).unwrap()});
                write_owned(&failed_import(path), &serde_json::to_vec(&seal).unwrap());
                (oracle, bytes)
            };
            let (index, imported) = load(SOURCE, &c, path).unwrap();
            if receipt_arm {
                assert!(imported
                    .accepted_cache_heads
                    .contains_key(&cache_session_key("progress-rows-pending")));
            }
            assert_imported(path, &imported, &imported_bytes, &expected);
            assert_quiet(SOURCE, &c, index);
        }
    });
}

/// One damaged keyed row of a real accepted session.
#[derive(Clone, Copy, Debug)]
enum Damage {
    MissingObservations,
    TooManyRows,
    TooManyBytes,
    BadHead,
}

/// [money] A damaged keyed row of a real accepted session (state without
/// observations, over 512 rows or 655360 bytes; a head that is no hash) is set
/// aside and counted: it stays in the store, out of RAM, every healthy sibling
/// loads, and a restart reads no transcript. The session's next upload carries
/// cold Full's money, and the receiver credits it once.
#[test]
#[serial]
fn progress_rows_damaged_cache_row_is_set_aside_and_the_next_upload_is_full() {
    with_e2(|| {
        for damage in [
            Damage::MissingObservations,
            Damage::TooManyRows,
            Damage::TooManyBytes,
            Damage::BadHead,
        ] {
            let (c, paths) = native_corpus_in(
                corpus(&format!("progress-rows-damage-{damage:?}")),
                SOURCE,
                &SESSIONS,
            );
            let session = published(SOURCE, &c);
            let path = session.path();
            let mut reference = super::progress(SOURCE);
            let cold_page = native_page(SOURCE, &c, ScanIndex::default(), 100, false);
            let (status, _) = send(SOURCE, &cold_page, &mut reference, ack);
            assert_eq!(status.unwrap(), ResumableUploadResult::Completed);
            let (index, mut progress) = load(SOURCE, &c, path).unwrap();
            let mut page = native_page(SOURCE, &c, index, 100, true);
            let mut receiver = Receiver::default();
            let (status, _) = send_to(SOURCE, &page, &mut progress, path, &mut receiver);
            assert_eq!(status.unwrap(), ResumableUploadResult::Completed);
            settle(&mut page, &mut progress, path);
            let healthy = progress.clone();
            drop(page);
            let key = cache_session_key(SESSIONS[0]);
            assert!(
                healthy.accepted_cache_states.contains_key(&key)
                    && healthy.accepted_cache_heads.contains_key(&key),
                "a real accepted session's keyed evidence"
            );

            let (index, _) = load(SOURCE, &c, path).unwrap();
            v2::edit_progress_rows_for_test(path, &index, |states, heads, _| match damage {
                Damage::MissingObservations => {
                    states.insert(key.clone(), json!({ "rows": [] }));
                }
                Damage::TooManyRows => {
                    states.insert(
                        key.clone(),
                        json!({ "observations": (0..513).map(|_| json!({})).collect::<Vec<_>>() }),
                    );
                }
                Damage::TooManyBytes => {
                    states.insert(
                        key.clone(),
                        json!({ "observations": ["x".repeat(700_000)] }),
                    );
                }
                Damage::BadHead => {
                    heads.insert(key.clone(), "not-a-head".into());
                }
            });
            drop(index);
            v2::take_progress_set_aside_for_test();
            let (index, mut progress) = load(SOURCE, &c, path).unwrap();
            assert_eq!(
                v2::take_progress_set_aside_for_test(),
                Some(1),
                "{damage:?}: one row set aside"
            );
            let mut expected = healthy.clone();
            if let Damage::BadHead = damage {
                expected.accepted_cache_heads.remove(&key);
            } else {
                expected.accepted_cache_states.remove(&key);
            }
            assert_eq!(
                without_generation(durable(&progress)),
                without_generation(durable(&expected)),
                "{damage:?}: every healthy row loads"
            );
            let stored = rows(path);
            assert_eq!(
                stored.cache_state + stored.cache_head,
                progress.accepted_cache_states.len() + progress.accepted_cache_heads.len() + 1,
                "the set-aside row stays in the store"
            );
            let quiet = assert_quiet(SOURCE, &c, index);

            for (path, session) in paths.iter().zip(SESSIONS) {
                append(path, &response_line(SOURCE, session, 2));
            }
            let cold_page = native_page(SOURCE, &c, ScanIndex::default(), 100, false);
            let (status, cold) = send(SOURCE, &cold_page, &mut reference, ack);
            assert_eq!(status.unwrap(), ResumableUploadResult::Completed);
            let mut page = native_page(SOURCE, &c, quiet.index, 100, true);
            let (status, again) = send_to(SOURCE, &page, &mut progress, path, &mut receiver);
            assert_eq!(status.unwrap(), ResumableUploadResult::Completed);
            let mut differences = Vec::new();
            money_oracle::entity_differences(&cold, &again, &mut differences);
            assert!(differences.is_empty(), "{}", differences.join("\n"));
            for entity in &SESSIONS {
                assert!(again.snapshots.contains_key(*entity), "{entity} re-emitted");
            }
            assert_eq!(receiver.duplicates, 0, "each new body credited once");
            assert_eq!(
                receiver.credit.values().sum::<u64>(),
                cold.snapshots
                    .values()
                    .map(|body| body["request_count"].as_u64().unwrap())
                    .sum::<u64>(),
                "receiver credit equals cold Full"
            );
            settle(&mut page, &mut progress, path);
            let ram = durable(&progress);
            drop(page);
            let (index, restored) = load(SOURCE, &c, path).unwrap();
            assert_eq!(durable(&restored), ram);
            assert_quiet(SOURCE, &c, index);
        }
    });
}

/// [money] An invalid ledger row holds the whole source with zero uploads, as
/// an invalid JSON ledger does today; so does an invalid JSON ledger awaiting
/// import, which stays as it was and imports nothing.
#[test]
#[serial]
fn progress_rows_invalid_ledger_or_import_json_holds_with_zero_uploads() {
    with_e2(|| {
        let (c, _) = native_corpus_in(corpus("progress-rows-invalid-ledger"), SOURCE, &SESSIONS);
        let (session, _, _) = published_with_json_ledger(SOURCE, &c, None);
        let path = session.path();
        let (index, _) = load(SOURCE, &c, path).unwrap();
        v2::edit_progress_rows_for_test(path, &index, |_, _, ledger| {
            ledger["accepted_fingerprints"] = json!(["not-a-fingerprint"]);
        });
        drop(index);
        let before = row_digests(path);
        assert!(
            load(SOURCE, &c, path).is_err(),
            "an invalid ledger holds the source"
        );
        assert_eq!(row_digests(path), before, "the hold rewrites nothing");

        let (c, _) = native_corpus_in(corpus("progress-rows-invalid-import"), SOURCE, &SESSIONS);
        let (session, bytes, _) = published_with_json_ledger(SOURCE, &c, None);
        let path = session.path();
        let mut invalid: Value = serde_json::from_slice(&bytes).unwrap();
        invalid["accepted_fingerprints"] = json!(["not-a-fingerprint"]);
        let invalid = serde_json::to_vec(&invalid).unwrap();
        std::fs::write(progress_path(path), &invalid).unwrap();
        assert!(
            load(SOURCE, &c, path).is_err(),
            "invalid import JSON holds the source"
        );
        assert_eq!(std::fs::read(progress_path(path)).unwrap(), invalid);
        let after = rows(path);
        assert!(
            after.import.is_none() && !after.ledger,
            "nothing imported: {after:?}"
        );
    });
}

/// [money] Codex's continuation page loads the route's rows: after the
/// import, a malformed ledger left beside the index is never read (reading
/// it would quarantine it), and the continuation's progress equals the rows.
#[test]
#[serial]
fn progress_rows_codex_continuation_loads_the_route_rows() {
    with_e2(|| {
        let source = SnapshotSource::Codex;
        let (c, _) = native_corpus_in(corpus("progress-rows-continuation"), source, &SESSIONS);
        let (session, bytes, oracle) = published_with_json_ledger(source, &c, None);
        let path = session.path();
        let (mut index, mut progress) = load(source, &c, path).unwrap();
        assert_imported(path, &progress, &bytes, &oracle);
        // The ordinary prepare's claim and saves, as the minting cycle ran them.
        let mut backfill = crate::backfill::BackfillState::default();
        crate::backfill::mark_backfill_complete_for_destination(
            &mut backfill,
            source,
            &namespace(),
        );
        crate::backfill::save_backfill_state(&c.support, &backfill).unwrap();
        let _ = index.prepare_snapshot_admission_reoffer(SNAPSHOT_QUARANTINE_RETRY_LIMIT_PER_CYCLE);
        if index.legacy_settlement_ledger_needs_migration() {
            let _ = index.prepare_legacy_settlement_reconciliation(
                source,
                LEGACY_SETTLEMENT_RECONCILE_LIMIT_PER_CYCLE,
            );
        }
        let generation = cycle_replay_generation(source, &namespace());
        let now = reason_reoffer::now_unix_seconds();
        let _ = prepare_upload_progress_for_cycle_with_reoffer(
            &mut progress,
            &index,
            &generation,
            false,
            Some(&reason_reoffer::Scope {
                index: &index,
                now,
                window_start_unix_seconds: now.saturating_sub(30 * 86_400),
            }),
        );
        index.save(path).unwrap();
        progress.save(&progress_path(path)).unwrap();
        let rows_ledger = durable(&progress);
        drop((index, progress));
        write_owned(&progress_path(path), b"\xffnot a ledger");

        let (mut inputs, _feed) = continuation_inputs_for_test(false);
        inputs.index_path = path.to_owned();
        inputs.upload_progress_path = progress_path(path);
        inputs.upload_destination_namespace = namespace();
        let cache = std::sync::Arc::new(crate::snapshots::sampled_scan::SharedCache::default());
        let prepared = prepare_continuation_source(
            &c.base,
            &c.support,
            &cache,
            &mut inputs,
            Some(Duration::from_secs(300)),
            Instant::now() + Duration::from_secs(20),
        )
        .unwrap();
        let prepared = match prepared {
            Ok(prepared) => prepared,
            Err(refusal) => panic!("the continuation refused: {refusal:?}"),
        };
        assert_eq!(
            without_generation(durable(&prepared.upload_progress)),
            without_generation(rows_ledger),
            "the continuation loads the rows"
        );
        drop(prepared);
        assert_leftovers_purged(path);
    });
}
