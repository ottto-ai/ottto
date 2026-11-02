//! Reader closure uses synthetic files only. A refusal produces no body.
use super::*;
use crate::local_resource_diagnostics::capture;
use codex_compressed_input::{compressed_input_credit, is_compressed_codex_rollout};

thread_local! {
    static ACTIVITY: std::cell::Cell<(usize, usize)> = const { std::cell::Cell::new((0, 0)) };
}
pub(super) fn decoder_constructed() {
    ACTIVITY.with(|counts| {
        let (d, p) = counts.get();
        counts.set((d + 1, p));
    });
}
pub(super) fn jsonl_parse_attempted() {
    ACTIVITY.with(|counts| {
        let (d, p) = counts.get();
        counts.set((d, p + 1));
    });
}
/// Counters are cumulative process totals; captures isolate this thread's events.
pub(super) fn assert_refused<T>(cause: CodexZstCause, run: impl FnOnce() -> T) -> T {
    let before = ACTIVITY.with(std::cell::Cell::get);
    let (result, rows) = capture(run);
    assert_eq!(
        ACTIVITY.with(std::cell::Cell::get),
        before,
        "no decoder or JSONL parse"
    );
    let key = serde_json::to_value(cause).unwrap();
    let key = key.as_str().unwrap();
    let totals = rows
        .iter()
        .filter(|row| row["stage"] == "codex_zst_refused")
        .map(|row| {
            row["counts"]["codex_zst_refused"][key]
                .as_u64()
                .expect("named cause counter")
        })
        .collect::<Vec<_>>();
    assert!(!totals.is_empty());
    assert!(totals[0] > 0);
    for pair in totals.windows(2) {
        assert!(pair[1] > pair[0]);
    }
    result
}

pub(super) fn candidate(path: &Path) -> CandidateFile {
    CandidateFile {
        physical_identity: None,
        scan_root: path.parent().unwrap().to_owned(),
        path: path.to_owned(),
        size_bytes: 0,
        modified_unix_seconds: 0,
        modified_unix_nanos: 0,
        source_file_fingerprint: String::new(),
        legacy_source_file_fingerprint: String::new(),
        legacy_config_reconciliation_required: false,
        opened_object_identity: String::new(),
        fingerprint_changed_nanos: 0,
        fingerprint_birth_nanos: 0,
        withheld_content_stamp: None,
    }
}

#[test]
fn compressed_reader_families_refuse_without_parsing_or_emitting_a_body() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    let root = crate::test_scratch::private_dir("codex-zst-closure");
    let path = root.join("rollout-synthetic.jsonl.zst");
    // Valid JSON under the archive suffix catches accidental plain parsing too.
    fs::write(
        &path,
        b"{\"type\":\"session_meta\",\"payload\":{\"id\":\"synthetic\"}}\n",
    )
    .unwrap();
    let member = candidate(&path);
    let file = || File::open(&path).unwrap();
    assert_refused(CodexZstCause::CompatibilityUnfunded, || {
        assert!(parse_codex_jsonl_file(&path, "2026-10-28T10:00:00Z", "fixture".into()).is_err());
        assert!(parse_codex_jsonl_file(&path, "2026-10-28T10:00:00Z", "fixture".into()).is_err());
    });
    assert_refused(CodexZstCause::ReplayNotAuthorized, || {
        assert!(
            reopen_for_replay(SnapshotSource::Codex, &member, &OpenedInput::plain(file())).is_err()
        );
    });
    assert_refused(CodexZstCause::ParentSideUnsupported, || {
        assert!(check_parent_side_input(&member, None).is_err());
        assert!(check_parent_side_input(&member, Some(&OpenedInput::plain(file()))).is_err());
    });
    assert_refused(CodexZstCause::ProofParentUnsupported, || {
        assert!(CodexProofReader::parent("fixture".into(), path.clone(), file(), 1).is_err());
    });
    assert_refused(CodexZstCause::ProofChildUnsupported, || {
        assert!(CodexProofReader::child("fixture".into(), path.clone(), file()).is_err());
    });
    assert_refused(CodexZstCause::HeaderUnfunded, || {
        assert!(codex_file_join::header_reduction_witness(&member).is_err());
    });
    assert_refused(CodexZstCause::PhysicalOffsetUnsupported, || {
        assert!(sampled_scan::codex_cursor::LiveWitness::read(&path, &file(), 8).is_none());
    });
    let mut directories = codex_file_join::DirectoryCensus::new();
    directories.observe(&root, &fs::metadata(&root).unwrap());
    let inventory_paths = BTreeSet::from([local_index_key(&path)]);
    let mut inventory = codex_file_join::HeaderInventory::new(
        std::slice::from_ref(&root),
        &inventory_paths,
        Some(&directories),
    );
    assert_refused(CodexZstCause::HeaderUnfunded, || {
        while !inventory.step(&CodexTitleMetadata::default()) {}
        assert!(inventory.headers.is_empty());
        assert!(inventory.refused.contains_key(&local_index_key(&path)));
    });
    let paths = BTreeSet::from([local_index_key(&path)]);
    let roots = [root.clone()];
    let census = CodexParentCensus::new(&roots, &paths);
    assert_refused(CodexZstCause::ParentLedgerUnbound, || {
        assert!(codex_parent_open_match_witnessed(
            census,
            CodexCensusMatch::One(paths.first().unwrap())
        )
        .is_err());
        assert!(codex_parent_open_match_retained(
            census,
            CodexCensusMatch::One(paths.first().unwrap()),
            &sampled_scan::SharedCache::default()
        )
        .is_err());
    });
    let source = SnapshotSource::Codex;
    let index = ScanIndex::default();
    let scope = crate::transcript_acquisition::Scope("fixture".into());
    let interpretation =
        sampled_scan::durable_tail::Interpretation::of(source, "fixture", &index, false, &scope);
    assert_refused(CodexZstCause::DurableTailUnsupported, || {
        assert!(matches!(
            sampled_scan::SharedCache::default().durable_restore(
                source,
                "fixture",
                &path,
                &scope,
                &mut file(),
                &index,
                &interpretation
            ),
            sampled_scan::durable_tail::RestoreOutcome::Miss(_)
        ));
    });
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn predicate_covers_opened_compression_and_leaves_plain_physical_samples_legal() {
    let root = crate::test_scratch::private_dir("codex-zst-opened-closure");
    let path = root.join("rollout.jsonl");
    fs::write(&path, b"{\"n\":1}\n").unwrap();
    let mut physical = File::open(&path).unwrap();
    let plain = OpenedInput::plain(physical.try_clone().unwrap());
    assert!(!is_compressed_codex_rollout(Some(&path), Some(&plain)));
    let (_, rows) = capture(|| {
        refuse_compressed_codex(
            Some(&path),
            Some(&plain),
            CodexZstCause::ReplayNotAuthorized,
        )
        .unwrap();
        assert!(sampled_scan::codex_cursor::LiveWitness::read(&path, &physical, 8).is_some());
    });
    assert!(rows.is_empty());
    let archive = root.join("rollout.jsonl.zst");
    fs::write(
        &archive,
        zstd::stream::encode_all(&b"{\"n\":1}\n"[..], 1).unwrap(),
    )
    .unwrap();
    physical = File::open(&archive).unwrap();
    assert!(
        read_opened_content_samples(&mut physical, fs::metadata(&archive).unwrap().len()).is_ok()
    );
    let input =
        OpenedInput::compressed(physical, 1024, compressed_input_credit().unwrap()).unwrap();
    assert!(is_compressed_codex_rollout(Some(&path), Some(&input)));
    let mut parser = OwnedJsonlParser::new_opened(
        input,
        &path,
        SnapshotSource::Codex,
        apply_codex_line,
        None,
        None,
        None,
        false,
    )
    .unwrap();
    assert_refused(CodexZstCause::PhysicalOffsetUnsupported, || {
        assert!(parser
            .prepare_acquisition(
                None,
                &crate::transcript_acquisition::Scope("fixture".into()),
                None,
                1
            )
            .is_err());
        assert!(parser.reader.acquisition.is_none());
        assert_eq!(parser.reader.consumed_bytes(), 0);
    });
    fs::remove_dir_all(root).unwrap();
}
