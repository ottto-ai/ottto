//! Upload progress on a published route as custody rows: two keyed cache maps
//! plus one ledger row, one progress transaction per page, moved in once from
//! the JSON ledger. Each row drives the production pass load, upload/ACK, page
//! save and pass end, and compares the emitted money with cold Full across
//! restarts, COMMIT errors and import crash windows. Storage expectations come
//! last in each row, so a failure before them is a money failure.
use super::*;
use rusqlite::OptionalExtension;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

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

fn failed_import(index_path: &Path) -> PathBuf {
    sibling(
        index_path,
        &format!(".v2-ack-receipt.failed-import-{}", "c".repeat(64)),
    )
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

fn rows(index_path: &Path) -> Rows {
    let conn = rusqlite::Connection::open(sibling(index_path, ".v2.sqlite")).unwrap();
    conn.busy_timeout(std::time::Duration::from_secs(5))
        .unwrap();
    let control = |name: &str| -> Option<Value> {
        conn.query_row("SELECT value FROM control WHERE name=?1", [name], |row| {
            row.get::<_, Vec<u8>>(0)
        })
        .optional()
        .unwrap()
        .map(|bytes| serde_json::from_slice(&bytes).unwrap())
    };
    let count = |sql: &str, kind: &str| -> usize {
        let n: i64 = conn.query_row(sql, [kind], |row| row.get(0)).unwrap();
        usize::try_from(n).unwrap()
    };
    let members = "SELECT count(*) FROM records WHERE kind=?1 AND position=1";
    Rows {
        capability: control("minimum_writer_capability").and_then(|v| v.as_u64()),
        generation: control("progress_generation").and_then(|v| v.as_u64()),
        import: control("progress_import"),
        cache_state: count(members, "progress.cache_state"),
        cache_head: count(members, "progress.cache_head"),
        ledger: count(
            "SELECT count(*) FROM records WHERE kind=?1 AND key_bytes=x'' AND position=1",
            "progress.ledger",
        ) == 1,
    }
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
    for path in [
        progress_path(index_path),
        sibling(index_path, ".v2-ack-receipt"),
        failed_import(index_path),
    ] {
        assert!(!path.exists(), "{} is purged", path.display());
    }
}

/// A route whose pre-publication JSON ledger carries real ACKs and keyed cache
/// evidence: the progress-import input. Returns the published session, its
/// exact JSON bytes and the JSON branch's own load of those bytes (the oracle).
fn published_with_json_ledger(
    source: SnapshotSource,
    c: &Corpus,
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
    let (status, _) = send(source, &page, &mut progress, ack);
    assert_eq!(status.unwrap(), ResumableUploadResult::Completed);
    for n in 1..=3_u32 {
        let key = cache_session_key(&format!("progress-rows-{n}"));
        progress
            .accepted_cache_heads
            .insert(key.clone(), format!("{n:064x}"));
        progress
            .accepted_cache_states
            .insert(key, json!({ "observations": [] }));
    }
    progress.save(&path).unwrap();
    let bytes = std::fs::read(&path).unwrap();
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
    // The oracle: today's JSON branch loading the same bytes elsewhere.
    let copy = c.base.join("oracle/copy-upload-progress.json");
    std::fs::create_dir_all(copy.parent().unwrap()).unwrap();
    std::fs::write(&copy, &bytes).unwrap();
    let oracle =
        SnapshotUploadProgress::load(&copy, &namespace(), snapshot_quarantine_witness(source))
            .unwrap();
    assert!(
        oracle.accepted_cache_heads.len() >= 3 && oracle.accepted_cache_states.len() >= 3,
        "keyed evidence"
    );
    assert!(!oracle.accepted_fingerprints.is_empty(), "real ACKs");
    (session, bytes, oracle)
}

/// The import moved exactly the JSON ledger into rows, under a marker naming
/// those bytes and their generation.
fn assert_imported(
    index_path: &Path,
    imported: &SnapshotUploadProgress,
    bytes: &[u8],
    oracle: &SnapshotUploadProgress,
) {
    assert_eq!(
        without_generation(durable(imported)),
        without_generation(durable(oracle)),
        "the rows carry every JSON field"
    );
    assert_rows_custody(index_path, imported);
    let marker = rows(index_path).import.unwrap();
    assert_eq!(
        marker["sha256"],
        json!(crate::hex::encode(&Sha256::digest(bytes))),
        "the marker names the imported bytes"
    );
    assert_eq!(marker["generation"], json!(oracle.generation));
}

/// [money] On a published route, for every source: the first page's upload
/// equals cold Full, a restart restores the exact ledger and emits nothing,
/// and an appended turn re-emits every session, never smaller than cold Full.
/// The ledger then lives in rows alone.
#[test]
#[serial]
fn progress_rows_route_equals_cold_full_across_restart_and_append() {
    with_e2(|| {
        for source in [SOURCE, SnapshotSource::Codex, SnapshotSource::Pi] {
            let (c, paths) = native_corpus_in(
                corpus(&format!("progress-rows-route-{}", source.api_slug())),
                source,
                &SESSIONS,
            );
            let (session, _) = StateV2ColdSession::publish(
                db_source(source),
                &ScanIndex::default(),
                &c.base.join("state"),
            );
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
            let (status, first) = send(source, &page, &mut progress, ack);
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
            let (status, mut again) = send(source, &page, &mut progress, ack);
            assert_eq!(status.unwrap(), ResumableUploadResult::Completed);
            again.mode = Mode::Restart;
            money_oracle::assert_equivalent(&cold, &again);
            for entity in &SESSIONS {
                money_oracle::assert_no_smaller_reemit(entity, &first, &again, &cold, false);
            }
            settle(&mut page, &mut progress, path);
            let ram = durable(&progress);
            drop(page);
            let (index, restored) = load(source, &c, path).unwrap();
            assert_eq!(durable(&restored), ram);
            assert_quiet(source, &c, index);
            assert_rows_custody(path, &restored);
        }
    });
}

/// [money] A pass split over two pages with a partial checkpoint between them
/// emits the same second page whether or not the daemon restarts between the
/// pages, and the two pages together carry cold Full's money.
#[test]
#[serial]
fn progress_rows_restart_between_pages_equals_in_ram_pages() {
    with_e2(|| {
        let mut second_pages = Vec::new();
        for restart in [false, true] {
            let (c, _) = native_corpus_in(
                corpus(&format!("progress-rows-pages-{restart}")),
                SOURCE,
                &SESSIONS,
            );
            let (session, _) = StateV2ColdSession::publish(
                Source::Claude,
                &ScanIndex::default(),
                &c.base.join("state"),
            );
            let path = session.path();
            let cold = accept(
                SOURCE,
                &native_page(SOURCE, &c, ScanIndex::default(), 100, false),
            );
            let (index, mut progress) = load(SOURCE, &c, path).unwrap();
            let first = native_page(SOURCE, &c, index, 2, true);
            assert!(!first.scan.census_complete, "a retained traversal");
            let (status, page_one) = send(SOURCE, &first, &mut progress, ack);
            assert_eq!(status.unwrap(), ResumableUploadResult::Completed);
            progress.save(&progress_path(path)).unwrap();
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
                (owed, progress) = load(SOURCE, &c, path).unwrap();
            }
            crate::snapshots::state_v2::release_collection_page_limit_for_test(&owed);
            let mut second = native_page(SOURCE, &c, owed, 100, true);
            let (status, mut page_two) = send(SOURCE, &second, &mut progress, ack);
            assert_eq!(status.unwrap(), ResumableUploadResult::Completed);
            page_two.mode = if restart { Mode::Restart } else { Mode::Ram };
            let mut both = page_one.clone();
            both.snapshots.extend(page_two.snapshots.clone());
            let mut differences = Vec::new();
            money_oracle::entity_differences(&cold, &both, &mut differences);
            assert!(differences.is_empty(), "{}", differences.join("\n"));
            settle(&mut second, &mut progress, path);
            let ram = durable(&progress);
            drop(second);
            let (index, restored) = load(SOURCE, &c, path).unwrap();
            assert_eq!(durable(&restored), ram);
            assert_quiet(SOURCE, &c, index);
            second_pages.push((page_two, path.to_owned(), restored, session, c));
        }
        let (in_ram, restarted) = (&second_pages[0], &second_pages[1]);
        money_oracle::assert_equivalent(&in_ram.0, &restarted.0);
        for (_, path, restored, _, _) in &second_pages {
            assert_rows_custody(path, restored);
        }
    });
}

/// [money] A failed page COMMIT that published nothing keeps every ACK in RAM;
/// the retry writes all of them, and a restart equals the in-RAM ledger.
#[test]
#[serial]
fn progress_rows_commit_error_keeps_ram_and_retry_writes_every_row() {
    with_e2(|| {
        for source in [SOURCE, SnapshotSource::Codex, SnapshotSource::Pi] {
            let (c, _) = native_corpus_in(
                corpus(&format!("progress-rows-commit-error-{}", source.api_slug())),
                source,
                &SESSIONS,
            );
            let (session, _) = StateV2ColdSession::publish(
                db_source(source),
                &ScanIndex::default(),
                &c.base.join("state"),
            );
            let path = session.path();
            let cold = accept(
                source,
                &native_page(source, &c, ScanIndex::default(), 100, false),
            );
            let (index, mut progress) = load(source, &c, path).unwrap();
            let mut page = native_page(source, &c, index, 100, true);
            let (status, route) = send(source, &page, &mut progress, ack);
            assert_eq!(status.unwrap(), ResumableUploadResult::Completed);
            money_oracle::assert_equivalent(&cold, &route);
            let acked = durable(&progress);
            let before = rows(path).generation;

            crate::snapshots::state_v2::fail_next_progress_commit_for_test(&page.committed, None);
            assert!(
                progress.save(&progress_path(path)).is_err(),
                "{source:?}: the page COMMIT fails"
            );
            assert_eq!(durable(&progress), acked, "RAM keeps every ACK");
            assert_eq!(rows(path).generation, before, "nothing durable moved");

            settle(&mut page, &mut progress, path);
            let ram = durable(&progress);
            drop(page);
            let (index, restored) = load(source, &c, path).unwrap();
            assert_eq!(durable(&restored), ram, "the retry wrote every row");
            assert_quiet(source, &c, index);
            assert_rows_custody(path, &restored);
        }
    });
}

/// [money] An Ambiguous page COMMIT stops the page and reloads: the next pass
/// re-offers the exact bodies, equal to cold Full and never smaller, and
/// settles them once.
#[test]
#[serial]
fn progress_rows_ambiguous_commit_reloads_and_reoffers_cold_full() {
    with_e2(|| {
        let (c, _) = native_corpus_in(corpus("progress-rows-ambiguous"), SOURCE, &SESSIONS);
        let (session, _) = StateV2ColdSession::publish(
            Source::Claude,
            &ScanIndex::default(),
            &c.base.join("state"),
        );
        let path = session.path();
        let cold = accept(
            SOURCE,
            &native_page(SOURCE, &c, ScanIndex::default(), 100, false),
        );
        let (index, mut progress) = load(SOURCE, &c, path).unwrap();
        let page = native_page(SOURCE, &c, index, 100, true);
        let (status, first) = send(SOURCE, &page, &mut progress, ack);
        assert_eq!(status.unwrap(), ResumableUploadResult::Completed);
        let before = rows(path).generation.unwrap_or(0);

        // Another writer moved the CAS row to a value this commit never wrote.
        crate::snapshots::state_v2::fail_next_progress_commit_for_test(
            &page.committed,
            Some(before + 5),
        );
        assert!(
            progress.save(&progress_path(path)).is_err(),
            "an Ambiguous page stops"
        );
        drop((page, progress));

        let (index, mut progress) = load(SOURCE, &c, path).unwrap();
        assert_eq!(
            progress.generation,
            before + 5,
            "the reload reads the committed CAS"
        );
        let mut page = native_page(SOURCE, &c, index, 100, true);
        let (status, mut again) = send(SOURCE, &page, &mut progress, ack);
        assert_eq!(status.unwrap(), ResumableUploadResult::Completed);
        again.mode = Mode::Restart;
        money_oracle::assert_equivalent(&cold, &again);
        for entity in &SESSIONS {
            money_oracle::assert_no_smaller_reemit(entity, &first, &again, &cold, false);
        }
        settle(&mut page, &mut progress, path);
        let ram = durable(&progress);
        drop(page);
        let (index, restored) = load(SOURCE, &c, path).unwrap();
        assert_eq!(durable(&restored), ram);
        assert_quiet(SOURCE, &c, index);
        assert_rows_custody(path, &restored);
    });
}

/// [money] Uploads before publication keep saving the JSON ledger; the first
/// load after publication imports exactly those bytes, and the route then
/// restarts quietly from rows.
#[test]
#[serial]
fn progress_rows_import_carries_the_pre_publication_json_ledger() {
    with_e2(|| {
        let (c, _) = native_corpus_in(corpus("progress-rows-import"), SOURCE, &SESSIONS);
        let (session, bytes, oracle) = published_with_json_ledger(SOURCE, &c);
        let path = session.path();
        let (_, imported) = load(SOURCE, &c, path).unwrap();
        assert_imported(path, &imported, &bytes, &oracle);
        let (index, restored) = load(SOURCE, &c, path).unwrap();
        assert_eq!(
            durable(&restored),
            durable(&imported),
            "restart reads the rows"
        );
        assert_quiet(SOURCE, &c, index);
    });
}

/// [money] An import whose COMMIT fails leaves the JSON ledger exactly as it
/// was and holds this pass; the next load imports it.
#[test]
#[serial]
fn progress_rows_import_commit_error_keeps_the_json_and_reimports() {
    with_e2(|| {
        let (c, _) = native_corpus_in(corpus("progress-rows-import-error"), SOURCE, &SESSIONS);
        let (session, bytes, oracle) = published_with_json_ledger(SOURCE, &c);
        let path = session.path();
        crate::snapshots::state_v2::before_progress_import_for_test(|index| {
            crate::snapshots::state_v2::fail_next_progress_commit_for_test(index, None);
        });
        assert!(
            load(SOURCE, &c, path).is_err(),
            "a failed import COMMIT holds this pass"
        );
        assert_eq!(std::fs::read(progress_path(path)).unwrap(), bytes);
        let before = rows(path);
        assert!(
            before.import.is_none()
                && before.generation.is_none()
                && !before.ledger
                && before.cache_state + before.cache_head == 0,
            "nothing imported: {before:?}"
        );
        let (_, imported) = load(SOURCE, &c, path).unwrap();
        assert_imported(path, &imported, &bytes, &oracle);
    });
}

/// [money] After the import COMMIT, before or during the purge: the marker
/// wins, so any JSON ledger, ACK receipt or failed-import copy still beside
/// the index is purged unread and the rows load unchanged.
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
            let (session, bytes, oracle) = published_with_json_ledger(SOURCE, &c);
            let path = session.path();
            let (_, imported) = load(SOURCE, &c, path).unwrap();
            assert_imported(path, &imported, &bytes, &oracle);
            if json_left {
                // A valid but different ledger: reading it would change RAM.
                let stale = json!({"schema_version": 3, "generation": 999,
                    "destination_namespace_hash": namespace()});
                std::fs::write(progress_path(path), serde_json::to_vec(&stale).unwrap()).unwrap();
            }
            std::fs::write(sibling(path, ".v2-ack-receipt"), b"{}").unwrap();
            std::fs::write(failed_import(path), b"{}").unwrap();
            let (_, restored) = load(SOURCE, &c, path).unwrap();
            assert_eq!(
                durable(&restored),
                durable(&imported),
                "leftovers are never read"
            );
            assert_rows_custody(path, &restored);
        }
    });
}

/// [money] An invalid keyed cache row is set aside: it stays in the store,
/// out of RAM, and a later page leaves it alone; the rest of the ledger loads.
/// An invalid ledger row holds the whole source, as an invalid JSON ledger
/// does today.
#[test]
#[serial]
fn progress_rows_invalid_cache_row_is_set_aside_and_invalid_ledger_holds() {
    with_e2(|| {
        let (c, _) = native_corpus_in(corpus("progress-rows-invalid"), SOURCE, &SESSIONS);
        let (session, _, oracle) = published_with_json_ledger(SOURCE, &c);
        let path = session.path();
        let (index, _) = load(SOURCE, &c, path).unwrap();
        crate::snapshots::state_v2::edit_progress_rows_for_test(path, &index, |states, _, _| {
            states.insert("not-a-session-key".into(), json!({ "observations": [] }));
        });
        drop(index);
        let (_, mut progress) = load(SOURCE, &c, path).unwrap();
        assert!(!progress
            .accepted_cache_states
            .contains_key("not-a-session-key"));
        assert_eq!(
            without_generation(durable(&progress)),
            without_generation(durable(&oracle)),
            "every valid row still loads"
        );
        assert_eq!(
            rows(path).cache_state,
            oracle.accepted_cache_states.len() + 1
        );
        progress
            .accepted_cache_heads
            .insert(cache_session_key("progress-rows-later"), "d".repeat(64));
        progress.save(&progress_path(path)).unwrap();
        assert_eq!(
            rows(path).cache_state,
            oracle.accepted_cache_states.len() + 1,
            "a later page leaves the set-aside row in place"
        );
        drop(progress);

        let (index, _) = load(SOURCE, &c, path).unwrap();
        crate::snapshots::state_v2::edit_progress_rows_for_test(path, &index, |_, _, ledger| {
            ledger["accepted_fingerprints"] = json!(["not-a-fingerprint"]);
        });
        drop(index);
        assert!(
            load(SOURCE, &c, path).is_err(),
            "an invalid ledger holds the source"
        );
    });
}
