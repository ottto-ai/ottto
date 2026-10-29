//! Synthetic real-loader/store controls. No provider data or second oracle.
use super::*;
use crate::locked_state_dir::LockedStateDir;
use crate::snapshots::ScanIndex;

struct Fixture {
    dir: PathBuf,
    index_path: PathBuf,
    index: ScanIndex,
    writer: Option<LockedStateDir>,
}
impl Fixture {
    fn new(name: &str) -> Self {
        take_counts();
        let dir = crate::test_scratch::private_dir(name);
        let state = dir.join("state");
        let writer = Some(LockedStateDir::acquire(&state).unwrap());
        let index_path = state.join("index.json");
        let mut index = ScanIndex::default();
        index.save(&index_path).unwrap();
        Self {
            dir,
            index_path,
            index,
            writer,
        }
    }
    fn reader(&self) -> Reader {
        Reader::new(
            &self.dir,
            &self.index_path,
            "synthetic",
            self.index.generation,
        )
    }
    fn write(&self, session: &str, api: &[u8], trace: &[u8]) {
        for (kind, bytes) in [(Kind::Api, api), (Kind::Trace, trace)] {
            let path = kind.path(&self.dir, session);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, bytes).unwrap();
        }
    }
    fn append(&self, kind: Kind, bytes: &[u8]) {
        OpenOptions::new()
            .append(true)
            .open(kind.path(&self.dir, "scope"))
            .unwrap()
            .write_all(bytes)
            .unwrap();
    }
    fn save(&mut self, reader: &mut Reader) {
        self.index.save(&self.index_path).unwrap();
        reader
            .write_after_save(self.writer.as_ref().unwrap(), &self.index)
            .unwrap();
    }
    fn restart(&mut self) -> Reader {
        self.writer.take();
        self.writer = Some(LockedStateDir::acquire(self.index_path.parent().unwrap()).unwrap());
        self.index = ScanIndex::load(&self.index_path).unwrap();
        self.reader()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        API_BEFORE_OPEN.with(|hook| {
            hook.borrow_mut().take();
        });
        API_AFTER_READ.with(|hook| {
            hook.borrow_mut().take();
        });
        store::test_hooks::set_before_rename(None);
        store::test_hooks::set_before_dir_sync(None);
        self.writer.take();
        fs::remove_dir_all(&self.dir).unwrap();
    }
}
fn sign_api(row: &mut ClaudeLocalOtelEvidence) {
    row.fingerprint.clear();
    row.fingerprint = format!(
        "sha256:{:x}",
        Sha256::digest(serde_json::to_vec(&*row).unwrap())
    );
}
fn sign_trace(row: &mut ClaudeTraceOwnershipEvidence) {
    row.fingerprint.clear();
    row.fingerprint = format!(
        "sha256:{:x}",
        Sha256::digest(serde_json::to_vec(&*row).unwrap())
    );
}
fn api_row(request: &str) -> ClaudeLocalOtelEvidence {
    let mut row = ClaudeLocalOtelEvidence {
        capture_revision: API_REQUEST_CAPTURE_REVISION.into(),
        session_id: "scope".into(),
        request_id: request.into(),
        input_tokens: 17,
        output_tokens: 9,
        request_count: 1,
        cost_usd_micros: Some(123),
        observed_at: "2026-01-01T00:00:00Z".into(),
        ..Default::default()
    };
    sign_api(&mut row);
    row
}
fn trace_row(request: &str) -> ClaudeTraceOwnershipEvidence {
    let mut row = ClaudeTraceOwnershipEvidence {
        capture_revision: TRACE_OWNERSHIP_CAPTURE_REVISION.into(),
        session_id: "scope".into(),
        request_id: request.into(),
        observed_at: "2026-01-01T00:00:00Z".into(),
        ..Default::default()
    };
    sign_trace(&mut row);
    row
}
fn line<T: Serialize>(row: &T) -> Vec<u8> {
    let mut bytes = serde_json::to_vec(row).unwrap();
    bytes.push(b'\n');
    bytes
}
fn bytes(request: &str) -> (Vec<u8>, Vec<u8>) {
    (line(&api_row(request)), line(&trace_row(request)))
}
fn frozen(api: &[u8], trace: &[u8]) -> Reports {
    let (rows, health) = crate::claude_local_otel::decoder_tests::baseline_api(api).into_output();
    let evidence = if rows.is_empty() {
        BTreeMap::new()
    } else {
        BTreeMap::from([("scope".into(), rows)])
    };
    let (rows, mut trace) =
        crate::claude_local_otel::decoder_tests::baseline_trace(trace).into_output();
    if !rows.is_empty() {
        trace.evidence.insert("scope".into(), rows);
    }
    (ClaudeLocalOtelLoadReport { evidence, health }, trace)
}
fn load(reader: Reader, dir: &Path) -> (Reader, Reports) {
    with_reader(reader, || {
        (
            load_claude_api_request_evidence_report(dir, ["scope".into()]),
            load_claude_trace_ownership_evidence(dir, ["scope".into()]),
        )
    })
}
fn body_bytes(reader: &Reader) -> (u64, u64) {
    (reader.counts[0].bytes_read, reader.counts[1].bytes_read)
}

#[test]
fn loader_full_append_tail_store_restart_equals_frozen_whole_file() {
    let mut fixture = Fixture::new("sidecar-durable-e2e");
    let (mut api, mut trace) = bytes("first");
    fixture.write("scope", &api, &trace);
    let (mut reader, cold) = load(fixture.reader(), &fixture.dir);
    assert_eq!(cold, frozen(&api, &trace));
    assert_eq!(cold.0.evidence["scope"].len(), 1);
    assert!(cold.0.health.is_complete() && cold.1.is_complete());
    assert_eq!(body_bytes(&reader), (api.len() as u64, trace.len() as u64));
    fixture.save(&mut reader);
    assert!(reader.pending_sessions().is_empty());
    let (a, t) = bytes("late");
    fixture.append(Kind::Api, &a);
    fixture.append(Kind::Trace, &t);
    api.extend(&a);
    trace.extend(&t);
    reader.begin_pass();
    let (mut reader, tail) = load(reader, &fixture.dir);
    assert_eq!(tail, frozen(&api, &trace));
    assert_eq!(tail.0.evidence["scope"].len(), 2);
    assert_eq!(tail.1.evidence["scope"].len(), 2);
    assert_eq!(body_bytes(&reader), (a.len() as u64, t.len() as u64));
    fixture.save(&mut reader);
    drop(reader);
    for _ in 0..2 {
        let (mut reader, actual) = load(fixture.restart(), &fixture.dir);
        assert_eq!(actual, tail);
        assert_eq!(actual, frozen(&api, &trace));
        assert_eq!(body_bytes(&reader), (0, 0));
        assert!(reader
            .counts
            .iter()
            .all(|counts| counts.reuse_hits > 0 && counts.guard_bytes > 0));
        fixture.save(&mut reader);
    }
}

#[test]
fn every_byte_append_preserves_sealed_projection_and_quiet_fragment_zero_body() {
    let mut fixture = Fixture::new("sidecar-byte-splits");
    let mut api_row = api_row("split");
    api_row.model = "synthetic-é\"\\\n".into();
    sign_api(&mut api_row);
    let (mut api, mut trace) = (line(&api_row), line(&trace_row("split")));
    api.insert(api.len() - 1, b'\r');
    trace.insert(trace.len() - 1, b'\r');
    fixture.write("scope", b"", b"");
    let (mut reader, empty) = load(fixture.reader(), &fixture.dir);
    assert_eq!(empty, frozen(b"", b""));
    for (kind, bytes) in [(Kind::Api, &api), (Kind::Trace, &trace)] {
        for byte in bytes {
            fixture.append(kind, &[*byte]);
            let (next, _) = load(reader, &fixture.dir);
            reader = next;
            let slot = &reader.entries["scope"].pair;
            let certificate = match kind {
                Kind::Api => slot.api.certificate.as_ref().unwrap(),
                Kind::Trace => slot.trace.certificate.as_ref().unwrap(),
            };
            assert!(certificate.sealed_offset <= certificate.length);
            reader.begin_pass();
            let (next, reports) = load(reader, &fixture.dir);
            reader = next;
            assert_eq!(body_bytes(&reader), (0, 0), "quiet fragment reread");
            if certificate_fragment(&reader, kind) {
                let complete = match kind {
                    Kind::Api => reports.0.health.is_complete(),
                    Kind::Trace => reports.1.is_complete(),
                };
                assert!(!complete, "even valid JSON at EOF is held until LF");
            }
        }
    }
    let (mut reader, reports) = load(reader, &fixture.dir);
    assert_eq!(reports, frozen(&api, &trace));
    assert_eq!(
        reader.entries["scope"]
            .pair
            .api
            .certificate
            .as_ref()
            .unwrap()
            .sealed_offset,
        api.len() as u64
    );
    assert_eq!(
        reader.entries["scope"]
            .pair
            .trace
            .certificate
            .as_ref()
            .unwrap()
            .sealed_offset,
        trace.len() as u64
    );
    fixture.save(&mut reader);
    let (reader, reports) = load(fixture.restart(), &fixture.dir);
    assert_eq!(reports, frozen(&api, &trace));
    assert_eq!(body_bytes(&reader), (0, 0));
}
fn certificate_fragment(reader: &Reader, kind: Kind) -> bool {
    let pair = &reader.entries["scope"].pair;
    let cert = match kind {
        Kind::Api => pair.api.certificate.as_ref(),
        Kind::Trace => pair.trace.certificate.as_ref(),
    }
    .unwrap();
    cert.sealed_offset < cert.length
}

#[test]
fn bootstrap_is_paced_and_store_failure_never_renews_it() {
    let mut fixture = Fixture::new("sidecar-bootstrap-paced");
    let (api, trace) = bytes("first");
    fixture.write("scope", &api, &trace);
    let mut reader = fixture.reader();
    reader.bootstrap_left = api.len() as u64;
    let (mut reader, reports) = load(reader, &fixture.dir);
    assert!(reports.0.health.is_complete());
    assert!(!reports.1.is_complete());
    assert_eq!(body_bytes(&reader), (api.len() as u64, 0));
    assert_eq!(reader.counts[1].bootstrap_deferred, 2);
    store::test_hooks::set_before_rename(Some(Box::new(|_, _| {
        Err(io::Error::other("synthetic write failure"))
    })));
    fixture.save(&mut reader);
    assert_eq!(reader.pending_sessions(), BTreeSet::from(["scope".into()]));
    reader.begin_pass();
    let (mut reader, reports) = load(reader, &fixture.dir);
    assert_eq!(reports, frozen(&api, &trace));
    assert_eq!(body_bytes(&reader), (0, trace.len() as u64));
    assert_eq!(reader.counts[0].bootstraps, 0);
    assert_eq!(reader.counts[1].bootstraps, 1);
    store::test_hooks::set_before_rename(None);
    fixture.save(&mut reader);
    assert!(reader.pending_sessions().is_empty());
}

#[test]
fn growth_while_failing_remains_selected_past_window_and_recovers_suffix() {
    let mut fixture = Fixture::new("sidecar-no-drop");
    let (mut api, mut trace) = bytes("first");
    fixture.write("scope", &api, &trace);
    let (mut reader, _) = load(fixture.reader(), &fixture.dir);
    fixture.save(&mut reader);
    let (a, t) = bytes("late");
    fixture.append(Kind::Api, &a);
    fixture.append(Kind::Trace, &t);
    api.extend(&a);
    trace.extend(&t);
    let saved = fixture.dir.join("held-api.jsonl");
    let path = evidence_path(&fixture.dir, "scope");
    fs::rename(&path, &saved).unwrap();
    let idle_since = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1);
    File::options()
        .write(true)
        .open(&saved)
        .unwrap()
        .set_times(fs::FileTimes::new().set_modified(idle_since))
        .unwrap();
    assert_eq!(
        fs::metadata(&saved).unwrap().modified().unwrap(),
        idle_since
    );
    for _ in 0..3 {
        reader.load("scope").unwrap();
    }
    assert!(reader.counts[0].persistent_failures > 0);
    assert!(reader.pending_sessions().contains("scope"));
    fixture.save(&mut reader);
    // Idle past W: eligibility deliberately offers no age parameter. Restore
    // a persisted pending owner with no normal discovery candidates.
    drop(reader);
    let mut reader = fixture.restart();
    reader.restore_pending().unwrap();
    let selected = reader.pending_sessions();
    assert_eq!(selected, BTreeSet::from(["scope".into()]));
    fs::rename(saved, path).unwrap();
    reader.begin_pass();
    for session in selected {
        assert_eq!(reader.load(&session).unwrap(), frozen(&api, &trace));
    }
    assert_eq!(
        body_bytes(&reader),
        (a.len() as u64, 0),
        "trace suffix was saved while API failed"
    );
    fixture.save(&mut reader);
    assert!(reader.pending_sessions().is_empty());
}

#[test]
fn failed_write_keeps_disk_offset_and_retries_without_source_reacquisition() {
    let mut fixture = Fixture::new("sidecar-write-custody");
    let (api, trace) = bytes("first");
    fixture.write("scope", &api, &trace);
    let (mut reader, _) = load(fixture.reader(), &fixture.dir);
    fixture.save(&mut reader);
    let (a, t) = bytes("late");
    fixture.append(Kind::Api, &a);
    fixture.append(Kind::Trace, &t);
    let (mut reader, expected) = load(reader, &fixture.dir);
    store::test_hooks::set_before_rename(Some(Box::new(|_, _| {
        Err(io::Error::other("synthetic rename"))
    })));
    for _ in 0..3 {
        fixture.save(&mut reader);
    }
    assert!(reader.counts[0].persistent_failures > 0);
    let mut disk = fixture.reader();
    let old = disk.restore("scope").unwrap();
    assert_eq!(old.api.certificate.unwrap().sealed_offset, api.len() as u64);
    assert_eq!(
        old.trace.certificate.unwrap().sealed_offset,
        trace.len() as u64
    );
    reader.begin_pass();
    let (mut reader, actual) = load(reader, &fixture.dir);
    assert_eq!(actual, expected);
    assert_eq!(body_bytes(&reader), (0, 0));
    store::test_hooks::set_before_rename(None);
    fixture.save(&mut reader);
    let (reader, actual) = load(fixture.restart(), &fixture.dir);
    assert_eq!(actual, expected);
    assert_eq!(body_bytes(&reader), (0, 0));
}

#[test]
fn replacement_truncation_head_and_boundary_edits_rebuild_without_predecessor_rows() {
    for mutation in ["replace", "truncate", "head", "boundary"] {
        let mut fixture = Fixture::new("sidecar-proved-mutation");
        let mut api = Vec::new();
        for ordinal in 0..64 {
            api.extend(line(&api_row(&format!("before-{ordinal}"))));
        }
        let trace = bytes("trace").1;
        assert!(api.len() > 3 * crate::transcript_acquisition::SAMPLE_BYTES);
        fixture.write("scope", &api, &trace);
        let (mut reader, _) = load(fixture.reader(), &fixture.dir);
        fixture.save(&mut reader);
        let path = evidence_path(&fixture.dir, "scope");
        let modified = fs::metadata(&path).unwrap().modified().unwrap();
        match mutation {
            "replace" => {
                let moved = fixture.dir.join("new-api.jsonl");
                api = bytes("replacement").0;
                fs::write(&moved, &api).unwrap();
                fs::rename(moved, &path).unwrap();
            }
            "truncate" => {
                api = bytes("truncated").0;
                fs::write(&path, &api).unwrap();
            }
            "head" => {
                let offset = api
                    .windows(17)
                    .position(|value| value == b"\"input_tokens\":17")
                    .unwrap();
                api[offset + 16] = b'8';
                fs::write(&path, &api).unwrap();
            }
            "boundary" => {
                let offset = api
                    .windows(17)
                    .rposition(|value| value == b"\"input_tokens\":17")
                    .unwrap();
                api[offset + 16] = b'8';
                fs::write(&path, &api).unwrap();
            }
            _ => unreachable!(),
        }
        File::options()
            .write(true)
            .open(&path)
            .unwrap()
            .set_times(fs::FileTimes::new().set_modified(modified))
            .unwrap();
        reader.begin_pass();
        let (mut reader, actual) = load(reader, &fixture.dir);
        assert_eq!(actual, frozen(&api, &trace), "{mutation}");
        assert_eq!(reader.counts[0].rewrite_rebuilds, 1, "{mutation}");
        assert_eq!(body_bytes(&reader), (api.len() as u64, 0));
        fixture.save(&mut reader);
        let (reader, actual) = load(fixture.restart(), &fixture.dir);
        assert_eq!(actual, frozen(&api, &trace));
        assert_eq!(body_bytes(&reader), (0, 0));
    }
}

#[test]
fn late_api_trace_both_orders_and_identity_upgrade_replay_equal_frozen() {
    for trace_first in [false, true] {
        let mut fixture = Fixture::new("sidecar-late-order");
        let (mut api, mut trace) = bytes("upgrade");
        fixture.write("scope", &api, &trace);
        let (mut reader, _) = load(fixture.reader(), &fixture.dir);
        assert_eq!(
            joined(&reader.load("scope").unwrap().0),
            vec!["upgrade".to_owned()]
        );
        fixture.save(&mut reader);
        let (a, t) = bytes("late");
        let (first, second, first_bytes, second_bytes) = if trace_first {
            (Kind::Trace, Kind::Api, &t, &a)
        } else {
            (Kind::Api, Kind::Trace, &a, &t)
        };
        fixture.append(first, first_bytes);
        if trace_first {
            trace.extend(&t);
        } else {
            api.extend(&a);
        }
        let (mut reader, actual) = load(reader, &fixture.dir);
        assert_eq!(actual, frozen(&api, &trace));
        fixture.save(&mut reader);
        fixture.append(second, second_bytes);
        if trace_first {
            api.extend(&a);
        } else {
            trace.extend(&t);
        }
        let (mut reader, actual) = load(reader, &fixture.dir);
        assert_eq!(actual, frozen(&api, &trace));
        fixture.save(&mut reader);
        let mut richer = api_row("upgrade");
        richer.request_identity = Some(ClaudeRequestIdentityEvidence {
            identity_hash_scheme: "synthetic".into(),
            account: identity_missing(),
            organization: identity_missing(),
            disposition: ClaudeIdentityDisposition::Missing,
        });
        sign_api(&mut richer);
        let upgrade = line(&richer);
        fixture.append(Kind::Api, &upgrade);
        api.extend(upgrade);
        let replay = line(&api_row("upgrade"));
        fixture.append(Kind::Api, &replay);
        api.extend(replay);
        let (mut reader, actual) = load(reader, &fixture.dir);
        assert_eq!(actual, frozen(&api, &trace));
        assert_eq!(actual.0.evidence["scope"].len(), 2);
        assert_eq!(
            joined(&actual.0),
            vec!["upgrade".to_owned(), "late".to_owned()]
        );
        assert!(actual.0.evidence["scope"][0].request_identity.is_some());
        fixture.save(&mut reader);
        let (reader, actual) = load(fixture.restart(), &fixture.dir);
        assert_eq!(actual, frozen(&api, &trace));
        assert_eq!(body_bytes(&reader), (0, 0));
    }
}
fn joined(report: &ClaudeLocalOtelLoadReport) -> Vec<String> {
    use crate::telemetry_attach::{join, Attachment, Holders, SessionReport};
    let mut requests = Vec::new();
    let counts = join(
        SessionReport {
            rows: &report.evidence["scope"],
            complete: report.health.is_complete(),
            duplicate_keys: &report.health.conflicting_request_ids,
        },
        |id| Holders::One(id.to_owned()),
        |row, owner| &row.request_id == owner,
        |attachment| {
            let Attachment::Matched { row, .. } = attachment else {
                panic!("synthetic single holder must attach");
            };
            requests.push(row.request_id.clone());
        },
    );
    assert!(counts.complete);
    assert_eq!(counts.matched, report.evidence["scope"].len());
    requests
}
fn identity_missing() -> ClaudeIdentityAttributeEvidence {
    ClaudeIdentityAttributeEvidence {
        origin: ClaudeIdentityAttributeOrigin::Missing,
        disposition: ClaudeIdentityDisposition::Missing,
        resource_hash: None,
        log_record_hash: None,
    }
}

#[test]
fn paid_real_loader_and_ordinary_projection_parity() {
    if !crate::heap_layout_bound::layout_supported() {
        eprintln!("UNEXECUTED durable sidecar paid parity: unsupported layout");
        return;
    }
    let mut fixture = Fixture::new("sidecar-paid-parity");
    let (api, trace) = bytes("paid");
    fixture.write("scope", &api, &trace);
    let (mut reader, expected) = load(fixture.reader(), &fixture.dir);
    fixture.save(&mut reader);
    let roots = BTreeSet::from(["scope".into()]);
    let (reader, ()) = with_reader(fixture.restart(), || {
        let mut paid = PaidReservation::from_remainder(Some(256 * 1024 * 1024), 0, 0).unwrap();
        let actual = ClaudeApiEvidenceRead::load_paid_for_roots(&fixture.dir, &roots, &mut paid, 0)
            .expect("paid restored API");
        assert_eq!(actual.evidence, expected.0.evidence);
        assert!(actual.session_report("scope").unwrap().complete);
        let (trace, _) = load_claude_trace_paid(&fixture.dir, "scope", &mut paid, 0)
            .expect("paid restored trace");
        assert_eq!(trace, expected.1);
    });
    assert_eq!(body_bytes(&reader), (0, 0));
}

#[test]
fn codec_views_protect_each_others_records_from_gc_and_overwrite() {
    let mut fixture = Fixture::new("sidecar-codec-row-protection");
    let (api, trace) = bytes("first");
    fixture.write("scope", &api, &trace);
    let (mut reader, _) = load(fixture.reader(), &fixture.dir);
    fixture.save(&mut reader);
    let key = reader.binding("scope").key;
    let mut native = DurableTailStore::new(
        store::store_dir_for_index(&fixture.index_path),
        DurableSource::ClaudeCode,
    );
    assert!(matches!(
        native.read(&key),
        ReadOutcome::Refused(store::Refusal::Unknown)
    ));
    native
        .gc(
            fixture.writer.as_ref().unwrap(),
            &reader.context,
            &codec::allowlist(),
            &BTreeMap::new(),
        )
        .unwrap();
    assert!(native.inventory().unwrap().contains(&key));
    let mut proposed = reader.store.read(&key);
    let ReadOutcome::Found(record) = &mut proposed else {
        panic!("real sidecar record");
    };
    let batch = native
        .write_after_save(
            fixture.writer.as_ref().unwrap(),
            fixture.index.generation,
            vec![record.record.clone()],
        )
        .unwrap();
    assert_eq!(batch.written, 0);
    let restored = reader.restore("scope").unwrap();
    assert_eq!(reports(&restored), frozen(&api, &trace));
    const NATIVE: &str = "8d141d534b95e2c5ac6a2e6d8e5ca45f3a852038fa456f5f3216c14bf84e943c";
    let native_allowlist: [u8; 32] = std::array::from_fn(|index| {
        u8::from_str_radix(&NATIVE[index * 2..index * 2 + 2], 16).unwrap()
    });
    let mut binding = reader.binding("scope");
    binding.key = store::key_digest(DurableSource::ClaudeCode, "synthetic-native");
    let native_key = binding.key;
    let pending = store::PendingRecord {
        binding,
        certificate: restored.api.certificate.unwrap(),
        allowlist: native_allowlist,
        body: crate::snapshots::durable_store_fixture_body(
            crate::snapshots::SnapshotSource::ClaudeCode,
            1,
            1,
        ),
    };
    assert_eq!(
        native
            .write_after_save(
                fixture.writer.as_ref().unwrap(),
                fixture.index.generation,
                vec![pending]
            )
            .unwrap()
            .written,
        1
    );
    assert!(matches!(
        reader.store.read(&native_key),
        ReadOutcome::Refused(store::Refusal::Unknown)
    ));
    let keep = BTreeMap::from([(key, Some(reader.binding("scope").scope))]);
    reader
        .store
        .gc(
            fixture.writer.as_ref().unwrap(),
            &reader.context,
            &codec::allowlist(),
            &keep,
        )
        .unwrap();
    assert_eq!(
        reader.store.inventory().unwrap(),
        BTreeSet::from([key, native_key])
    );
}

#[test]
fn codec_has_no_raw_fragment_or_runtime_fingerprint_memo() {
    let fixture = Fixture::new("sidecar-codec-privacy");
    let (mut api, trace) = bytes("first");
    api.extend(b"RAW_FRAGMENT_CANARY private/prompt");
    fixture.write("scope", &api, &trace);
    let (reader, reports) = load(fixture.reader(), &fixture.dir);
    assert!(!reports.0.health.is_complete());
    assert!(reader.entries["scope"].pair.api.state.rows[0]
        .fingerprint_check
        .get_or_check(|| true));
    let encoded = codec::encode(&reader.entries["scope"].pair).unwrap();
    assert!(!encoded
        .windows(b"RAW_FRAGMENT_CANARY".len())
        .any(|bytes| bytes == b"RAW_FRAGMENT_CANARY"));
    assert!(codec::verify(&encoded));
    let restored = codec::decode(&encoded).unwrap();
    assert!(
        !restored.api.state.rows[0]
            .fingerprint_check
            .get_or_check(|| false),
        "runtime fingerprint memo must reset on restore"
    );
    assert_eq!(restored, reader.entries["scope"].pair);
}

pub(super) fn prepared_fixture(check: impl FnOnce(&Path, &Reports)) {
    let mut fixture = Fixture::new("sidecar-prepared-parity");
    let (api, trace) = bytes("prepared");
    fixture.write("scope", &api, &trace);
    let (mut reader, expected) = load(fixture.reader(), &fixture.dir);
    fixture.save(&mut reader);
    drop(reader);
    let (reader, ()) = with_reader(fixture.restart(), || check(&fixture.dir, &expected));
    assert_eq!(
        body_bytes(&reader),
        (0, 0),
        "prepared consumes restored projection"
    );
}

#[test]
fn post_rename_directory_sync_failure_is_retried_even_on_clean_memo() {
    let mut fixture = Fixture::new("sidecar-directory-sync");
    let (api, trace) = bytes("first");
    fixture.write("scope", &api, &trace);
    let (mut reader, _) = load(fixture.reader(), &fixture.dir);
    store::test_hooks::set_before_dir_sync(Some(Box::new(|_| {
        Err(io::Error::other("synthetic directory sync"))
    })));
    fixture.save(&mut reader);
    assert!(reader.sync_owed);
    assert!(reader.pending_sessions().contains("scope"));
    let calls = std::rc::Rc::new(std::cell::Cell::new(0));
    let counted = calls.clone();
    store::test_hooks::set_before_dir_sync(Some(Box::new(move |_| {
        counted.set(counted.get() + 1);
        Ok(())
    })));
    reader.begin_pass();
    let (mut reader, actual) = load(reader, &fixture.dir);
    assert_eq!(actual, frozen(&api, &trace));
    assert_eq!(body_bytes(&reader), (0, 0));
    fixture.save(&mut reader);
    assert!(
        calls.get() > 0,
        "clean memo must not skip the owed directory sync"
    );
    assert!(!reader.sync_owed);
    assert!(reader.pending_sessions().is_empty());
    store::test_hooks::set_before_dir_sync(None);
    let (reader, actual) = load(fixture.restart(), &fixture.dir);
    assert_eq!(actual, frozen(&api, &trace));
    assert_eq!(body_bytes(&reader), (0, 0));
}

#[test]
fn sealed_health_and_continuation_maps_survive_tail_and_restore() {
    let mut fixture = Fixture::new("sidecar-content-health");
    let (mut api, mut trace) = bytes("conflict");
    api.extend(b"{broken\n\xff\n");
    trace.extend(b"{broken\n\xff\n");
    fixture.write("scope", &api, &trace);
    let (mut reader, report) = load(fixture.reader(), &fixture.dir);
    assert_eq!(report, frozen(&api, &trace));
    assert_eq!(report.0.health.malformed_lines, 1);
    assert_eq!(report.0.health.unreadable_lines, 1);
    assert_eq!(report.1.malformed_lines, 1);
    assert_eq!(report.1.unreadable_lines, 1);
    fixture.save(&mut reader);
    let mut conflicting = api_row("conflict");
    conflicting.output_tokens = 11;
    sign_api(&mut conflicting);
    let a = line(&conflicting);
    let mut different_trace = trace_row("conflict");
    different_trace.agent_id = "other-agent".into();
    sign_trace(&mut different_trace);
    let t = line(&different_trace);
    fixture.append(Kind::Api, &a);
    fixture.append(Kind::Trace, &t);
    api.extend(a);
    trace.extend(t);
    let (mut reader, report) = load(reader, &fixture.dir);
    assert_eq!(report, frozen(&api, &trace));
    assert_eq!(
        report.0.health.conflicting_request_ids,
        BTreeSet::from(["conflict".into()])
    );
    assert_eq!(
        report.1.conflicting_request_ids,
        BTreeSet::from(["conflict".into()])
    );
    fixture.save(&mut reader);
    let (reader, report) = load(fixture.restart(), &fixture.dir);
    assert_eq!(report, frozen(&api, &trace));
    assert_eq!(body_bytes(&reader), (0, 0));
}

#[test]
fn sparse_resource_carrier_contains_counts_and_persistent_failure_alarm_only() {
    let mut fixture = Fixture::new("sidecar-counter-carrier");
    let (api, trace) = bytes("first");
    fixture.write("scope", &api, &trace);
    let (mut reader, _) = load(fixture.reader(), &fixture.dir);
    store::test_hooks::set_before_rename(Some(Box::new(|_, _| {
        Err(io::Error::other("synthetic failure"))
    })));
    for _ in 0..3 {
        fixture.save(&mut reader);
    }
    let (_, records) = crate::local_resource_diagnostics::capture(|| {
        crate::local_resource_diagnostics::source_finish("claude_code", || Ok(()))
    });
    assert_eq!(records.len(), 1);
    let counts = records[0]["counts"].as_object().unwrap();
    assert_eq!(records[0]["stage"], "source_finish");
    assert_eq!(counts["sidecar_read_alarm"], 1);
    assert!(counts["sidecar_api_bytes_read"].as_u64().unwrap() > 0);
    assert!(
        counts["sidecar_trace_persistent_failures"]
            .as_u64()
            .unwrap()
            > 0
    );
    assert!(counts
        .values()
        .all(|value| value.as_u64().is_some_and(|value| value > 0)));
    let text = serde_json::to_string(counts).unwrap();
    assert!(!text.contains("scope"));
    assert!(!text.contains("local-otel"));
    assert!(
        take_counts().is_empty(),
        "drained once on the existing carrier"
    );
}

#[test]
fn unknown_representation_keeps_owner_pending_and_never_reacquires_or_overwrites() {
    let mut fixture = Fixture::new("sidecar-unknown-protection");
    let (api, trace) = bytes("first");
    fixture.write("scope", &api, &trace);
    let (mut reader, _) = load(fixture.reader(), &fixture.dir);
    fixture.save(&mut reader);
    let key = reader.binding("scope").key;
    let name: String = key.iter().map(|byte| format!("{byte:02x}")).collect();
    let path = reader.store.dir().join(format!("{name}.rec"));
    let mut unknown = fs::read(&path).unwrap();
    unknown[10] ^= 0xff; // header before trailer: unknown allowlist stays U.
    fs::write(&path, &unknown).unwrap();
    drop(reader);
    let mut reader = fixture.restart();
    for _ in 0..3 {
        assert!(reader.load("scope").is_err());
    }
    assert_eq!(body_bytes(&reader), (0, 0));
    assert_eq!(reader.pending_sessions(), BTreeSet::from(["scope".into()]));
    assert!(reader.counts[0].persistent_failures > 0);
    fixture.save(&mut reader);
    assert_eq!(fs::read(path).unwrap(), unknown);
}

#[test]
fn api_generation_witness_is_the_acquired_generation_not_a_later_stat() {
    let fixture = Fixture::new("sidecar-api-generation-race");
    let (mut api, trace) = bytes("first");
    fixture.write("scope", &api, &trace);
    let (append, _) = bytes("late");
    let injected = append.clone();
    API_AFTER_READ.with(|hook| {
        *hook.borrow_mut() = Some(Box::new(move |path| {
            OpenOptions::new()
                .append(true)
                .open(path)
                .unwrap()
                .write_all(&injected)
                .unwrap();
        }))
    });
    let (_, ()) = with_reader(fixture.reader(), || {
        let mut read = ClaudeApiEvidenceRead::load(&fixture.dir, ["scope".into()]).unwrap();
        assert_eq!(read.evidence["scope"].len(), 1);
        assert_eq!(
            fs::metadata(evidence_path(&fixture.dir, "scope"))
                .unwrap()
                .len(),
            (api.len() + append.len()) as u64
        );
        assert!(!read.strict_generation_matches(&fixture.dir, "scope"));
        api.extend(&append);
        let strict = read.take_strict_report(&fixture.dir, "scope");
        assert_eq!(strict, frozen(&api, &trace).0);
        assert_eq!(strict.evidence["scope"].len(), 2);
    });
}

#[test]
fn fatal_api_directory_or_open_error_vetoes_the_whole_permissive_cohort() {
    for directory in [true, false] {
        let fixture = Fixture::new("sidecar-cohort-error-veto");
        let (api, trace) = bytes("first");
        fixture.write("scope", &api, &trace);
        if directory {
            let bad = evidence_path(&fixture.dir, "bad");
            fs::create_dir_all(bad).unwrap();
            assert!(
                ClaudeApiEvidenceRead::load(&fixture.dir, ["scope".into(), "bad".into()]).is_err()
            );
            let (_, result) = with_reader(fixture.reader(), || {
                ClaudeApiEvidenceRead::load(&fixture.dir, ["scope".into(), "bad".into()])
            });
            assert!(result.is_err(), "healthy rows cannot hide a fatal API path");
        } else {
            fixture.write("bad", &api, &trace);
            let held = fixture.dir.join("after-stat-api.jsonl");
            API_BEFORE_OPEN.with(|hook| {
                *hook.borrow_mut() = Some(Box::new(move |path| {
                    fs::rename(path, held).unwrap();
                }))
            });
            let (_, result) = with_reader(fixture.reader(), || {
                ClaudeApiEvidenceRead::load(&fixture.dir, ["bad".into(), "scope".into()])
            });
            assert!(
                result.is_err(),
                "stat success followed by open failure stays fatal"
            );
        }
    }
}

#[test]
fn crash_after_suffix_decode_before_save_replays_each_fingerprint_once() {
    const CHILD: &str = "OTTTO_SIDECAR_CRASH_FIXTURE";
    if let Some(dir) = std::env::var_os(CHILD) {
        let dir = PathBuf::from(dir);
        let state = dir.join("state");
        let _writer = LockedStateDir::acquire(&state).unwrap();
        let index_path = state.join("index.json");
        let index = ScanIndex::load(&index_path).unwrap();
        let reader = Reader::new(&dir, &index_path, "synthetic", index.generation);
        let (reader, actual) = load(reader, &dir);
        assert_eq!(actual.0.evidence["scope"].len(), 2);
        assert_eq!(actual.1.evidence["scope"].len(), 2);
        assert!(reader.counts[0].bytes_read > 0);
        let mut marker = File::create(dir.join("decoded-before-offset-save")).unwrap();
        marker
            .write_all(b"two unique rows; suffix decoded; no save")
            .unwrap();
        marker.sync_all().unwrap();
        // SAFETY: this isolated child owns its fixture and only kills itself.
        unsafe {
            libc::raise(libc::SIGKILL);
        }
        panic!("SIGKILL returned");
    }
    let mut fixture = Fixture::new("sidecar-crash-dedupe");
    let (mut api, mut trace) = bytes("first");
    fixture.write("scope", &api, &trace);
    let (mut reader, _) = load(fixture.reader(), &fixture.dir);
    fixture.save(&mut reader);
    // Repeated rows straddle the committed offset. The old fingerprint must
    // be restored, and crash replay of the new row must not add another row.
    let (a, t) = bytes("late");
    let (replay_api, replay_trace) = (api.clone(), trace.clone());
    for (kind, replay, new) in [
        (Kind::Api, &replay_api, &a),
        (Kind::Trace, &replay_trace, &t),
    ] {
        fixture.append(kind, replay);
        fixture.append(kind, new);
    }
    api.extend(&replay_api);
    api.extend(&a);
    trace.extend(&replay_trace);
    trace.extend(&t);
    drop(reader);
    fixture.writer.take();
    let name = std::thread::current().name().unwrap().to_owned();
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .arg("--exact")
        .arg(name)
        .arg("--nocapture")
        .env(CHILD, &fixture.dir)
        .status()
        .unwrap();
    use std::os::unix::process::ExitStatusExt;
    assert_eq!(status.signal(), Some(libc::SIGKILL));
    assert_eq!(
        fs::read(fixture.dir.join("decoded-before-offset-save")).unwrap(),
        b"two unique rows; suffix decoded; no save"
    );
    let (mut reader, actual) = load(fixture.restart(), &fixture.dir);
    assert_eq!(actual, frozen(&api, &trace));
    assert_eq!(actual.0.evidence["scope"].len(), 2);
    assert_eq!(actual.1.evidence["scope"].len(), 2);
    assert_eq!(
        body_bytes(&reader),
        (
            (replay_api.len() + a.len()) as u64,
            (replay_trace.len() + t.len()) as u64
        )
    );
    fixture.save(&mut reader);
    let (reader, actual) = load(fixture.restart(), &fixture.dir);
    assert_eq!(actual, frozen(&api, &trace));
    assert_eq!(body_bytes(&reader), (0, 0));
}
