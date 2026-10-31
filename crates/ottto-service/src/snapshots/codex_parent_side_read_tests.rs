//! U1a-2a G-sites 9–29: P's singleton side read through the real Codex
//! scan, against a control page without the request (U-T60 (h), U-T64(a)),
//! plus the due and charge terms (row 5, G7) and the exit rows (row 29).
//! Fixtures are synthetic Codex rollouts; nothing comes from a provider
//! account.
use super::*;
use crate::local_resource_diagnostics::codex_side_lifecycle::{observe, Counts};
use sampled_scan::side_ledger::{parent_of, GateOpen, LedgerKey, LedgerTag};
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};

const NOW: &str = "2026-10-07T12:00:00Z";
const SESSION: &str = "019fa111-2222-7333-8444-555555555555";
const NS: u128 = 0x5e1d;
static NEXT: AtomicU64 = AtomicU64::new(0);

struct Root {
    dir: PathBuf,
    root: PathBuf,
}
impl Root {
    /// One rollout P: a session header and `lines` token counts. `tail` is
    /// appended as is (an unterminated final row when it has no newline).
    fn new(lines: u64, tail: &[u8]) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "ottto-u1a2a-side-read-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, AtomicOrdering::Relaxed)
        ));
        let root = dir.join("home/.codex/sessions");
        fs::create_dir_all(&root).unwrap();
        let fixture = Self { dir, root };
        let mut body = line(json!({"timestamp": "2026-10-07T10:00:00Z",
            "type": "session_meta", "payload": {"id": SESSION}}));
        for n in 1..=lines {
            body.extend(token(n));
        }
        body.extend_from_slice(tail);
        fs::write(fixture.file(), body).unwrap();
        fixture
    }
    fn file(&self) -> PathBuf {
        self.root
            .join(format!("rollout-2026-10-07T10-00-00-{SESSION}.jsonl"))
    }
    fn key(&self) -> String {
        local_index_key(&self.file())
    }
    fn at(&self) -> SideNow {
        side_now(&File::open(self.file()).unwrap()).expect("stamp")
    }
}
impl Drop for Root {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

fn line(value: serde_json::Value) -> Vec<u8> {
    let mut line = serde_json::to_vec(&value).unwrap();
    line.push(b'\n');
    line
}

fn token(n: u64) -> Vec<u8> {
    line(
        json!({"timestamp": "2026-10-07T10:30:00Z", "type": "event_msg",
        "payload": {"type": "token_count", "info": {"model": "fixture-model",
        "total_token_usage": {"input_tokens": n * 100, "cached_input_tokens": n * 50,
            "output_tokens": n * 10},
        "last_token_usage": {"input_tokens": 100, "cached_input_tokens": 50,
            "output_tokens": 10}}}}),
    )
}

/// The pass's index file (never opened: only the proof holder binds to it).
const INDEX_PATH: &str = "/nonexistent/u1a2a-side-read-index.json";

fn pass(side_allowed: bool) -> CodexSidePass {
    CodexSidePass {
        ns: NS,
        gate: GateOpen {
            side_allowed,
            first_in_process: false,
        },
        index_path: PathBuf::from(INDEX_PATH),
        kind: CodexPageKind::Ordinary,
    }
}

/// One sampled Codex page stepped to completion, then the collector's
/// post-policy finalization.
fn page(
    fixture: &Root,
    index: ScanIndex,
    cache: &Arc<sampled_scan::SharedCache>,
    pass: Option<CodexSidePass>,
) -> (ScanIndex, SourceScanResult) {
    let mut scan = OwnedSourceScan::new(
        SnapshotSource::Codex,
        std::slice::from_ref(&fixture.root),
        index,
        NOW,
        BACKFILL_WINDOW_DAYS,
        10,
        false,
        None,
        &[],
        false,
        true,
    )
    .with_sampled_acquisition(
        Arc::clone(cache),
        crate::transcript_acquisition::Scope("side-read-fixture".into()),
    )
    .with_codex_side_pass(pass);
    for _ in 0..64 {
        match scan.step(None) {
            OwnedSourceScanStep::Pending(next) => scan = next,
            OwnedSourceScanStep::Complete {
                mut index, scan, ..
            } => {
                let mut projected = scan.clone();
                apply_upload_policy(
                    SnapshotSource::Codex,
                    &mut projected.snapshots,
                    SnapshotUploadPolicy::default(),
                );
                finalize_scan_after_policy(SnapshotSource::Codex, &mut projected, &mut index);
                let accepted = projected
                    .snapshots
                    .iter()
                    .map(|snapshot| snapshot.snapshot_fingerprint.clone())
                    .collect();
                index.record_accepted_snapshot_fingerprints(&accepted);
                return (index, scan);
            }
        }
    }
    panic!("the page did not finish");
}

/// Main's state of an index: every field but P's side state.
fn main_state(index: &ScanIndex) -> serde_json::Value {
    let mut value = serde_json::to_value(index).unwrap();
    let object = value.as_object_mut().unwrap();
    for key in [
        "codex_parent_side",
        "codex_parent_side_requests",
        "codex_parent_side_generation",
    ] {
        object.remove(key);
    }
    value
}

/// Main's result of a page, without the page-budget diagnostics (the side
/// read's transient budget use, design rev 13 §6.2.1).
fn main_result(scan: &SourceScanResult) -> String {
    let mut scan = scan.clone();
    scan.local_codex_diagnostics = None;
    format!("{scan:?}")
}

/// A loaded, unchanged P (main skips it), and a cache whose state is that
/// page's.
fn settled_page(fixture: &Root) -> (ScanIndex, Arc<sampled_scan::SharedCache>) {
    let cache = Arc::new(sampled_scan::SharedCache::default());
    let (index, first) = page(fixture, ScanIndex::default(), &cache, Some(pass(true)));
    assert!(!first.snapshots.is_empty(), "page 1 parsed P");
    assert!(
        index.codex_parent_side.is_empty(),
        "P is not live: no record"
    );
    (index, cache)
}

fn request_for(fixture: &Root, needed: u64) -> SideRequest {
    SideRequest::created(fixture.at(), needed, 0, 0)
}

fn ledger_entry(
    cache: &sampled_scan::SharedCache,
    fixture: &Root,
) -> Option<sampled_scan::side_ledger::LedgerEntry> {
    let at = fixture.at();
    cache
        .side_ledger()
        .get(&LedgerKey {
            ns: NS,
            p: parent_of(&fixture.key()),
            dev: at.dev_ino.0,
            ino: at.dev_ino.1,
        })
        .copied()
}

#[test]
#[cfg_attr(
    not(any(target_os = "macos", target_os = "linux")),
    ignore = "needs macOS heap layout"
)]
fn a_due_singleton_side_read_writes_only_ps_side_state() {
    let fixture = Root::new(3, b"");
    let len = fixture.at().size;
    let (settled, cache) = settled_page(&fixture);
    let mut treated_index = settled.clone();
    treated_index
        .codex_parent_side_requests
        .insert(fixture.key(), request_for(&fixture, len));

    // The control page: the same index and cache without the request.
    let (control_index, control) = page(&fixture, settled, &cache, Some(pass(true)));
    let retained = cache.retained_sealed_offset(&fixture.key());
    let ((treated_index, treated), counts) =
        observe(|| page(&fixture, treated_index, &cache, Some(pass(true))));
    let treated_cache = &cache;

    // U-T64(a): main's index, result and retained copy are byte-equal.
    assert_eq!(main_state(&treated_index), main_state(&control_index));
    assert_eq!(main_result(&treated), main_result(&control));
    assert!(control.snapshots.is_empty(), "main skipped the unchanged P");
    assert_eq!(
        cache.retained_sealed_offset(&fixture.key()),
        retained,
        "G7 takes no retained copy"
    );
    // Row 1: a settled, sealed record covering `needed`; the request is
    // cured into the record's stub and the ledger mirrors `Removed`.
    let record = treated_index
        .codex_parent_side
        .get(&fixture.key())
        .expect("P's side record");
    assert_eq!(record.verdict, SideVerdict::Settled);
    assert_eq!(record.seal.sealed_offset(), len);
    assert_eq!(record.parsed.dev_ino(), fixture.at().dev_ino);
    assert!(treated_index.codex_parent_side_requests.is_empty());
    let entry = ledger_entry(treated_cache, &fixture).expect("G7 created the entry");
    assert_eq!(entry.tag, LedgerTag::Removed);
    assert_eq!(entry.attempts, 1);
    let pace = record.pace.expect("the stub");
    assert_eq!(pace.not_before_unix_seconds, entry.stub_not_before);
    assert_eq!(pace.attempts_floor, SIDE_REQUEST_EVICT_ATTEMPTS - 1);
    assert_eq!(
        counts,
        Counts {
            side_reads_started: 1,
            side_reads_ended: 1,
            side_records_written: 1,
            ..Counts::default()
        }
    );

    // Steady state: no request, so the next page reads nothing of P.
    let (_, counts) = observe(|| page(&fixture, treated_index, treated_cache, Some(pass(true))));
    assert_eq!(counts.side_reads_started, 0);
}

#[test]
#[cfg_attr(
    not(any(target_os = "macos", target_os = "linux")),
    ignore = "needs macOS heap layout"
)]
fn an_unsealed_settled_read_tombstones_and_writes_no_record() {
    // An unterminated final row: the native EOF applies it, so the
    // certificate's sealed offset is short of the held length.
    let fixture = Root::new(2, br#"{"timestamp":"2026-10-07T10:31:00Z","type":"event_msg","payload":{"type":"agent_message","message":"x"}}"#);
    let len = fixture.at().size;
    let (mut index, cache) = settled_page(&fixture);
    index
        .codex_parent_side_requests
        .insert(fixture.key(), request_for(&fixture, 1));
    let ((index, _), counts) = observe(|| page(&fixture, index, &cache, Some(pass(true))));
    assert_eq!(counts.side_reads_started, 1);
    assert_eq!(counts.side_reads_ended, 1);
    match index.codex_parent_side.get(&fixture.key()) {
        // Row 2: unsealed ∧ settled → no record, `Unsealed` at the length.
        None => {
            let request = index.codex_parent_side_requests[&fixture.key()];
            assert_eq!(request.state, SideRequestState::Unsealed);
            assert_eq!(request.state_extent, len);
            assert_eq!(request.attempts, 1);
            assert_eq!(counts.side_requests_tombstoned, 1);
            assert_eq!(
                ledger_entry(&cache, &fixture).unwrap().tag,
                LedgerTag::Unsealed
            );
        }
        // Row 1 if the tail parsed held instead: the record covers
        // `needed = 1`, so the request was cured.
        Some(record) => {
            assert!(record.seal.sealed_offset() >= 1);
            assert!(!index
                .codex_parent_side_requests
                .contains_key(&fixture.key()));
        }
    }
}

#[test]
fn gates_and_pacing_keep_the_side_read_from_starting() {
    let fixture = Root::new(2, b"");
    let len = fixture.at().size;
    let (index, cache) = settled_page(&fixture);
    let with = |request: SideRequest| {
        let mut index = index.clone();
        index
            .codex_parent_side_requests
            .insert(fixture.key(), request);
        index
    };
    // The outage gate: a namespace whose last pass did not save.
    let ((after, _), counts) = observe(|| {
        page(
            &fixture,
            with(request_for(&fixture, len)),
            &cache,
            Some(pass(false)),
        )
    });
    assert_eq!(counts.side_reads_started, 0);
    assert!(counts.side_not_due >= 1);
    assert_eq!(
        after.codex_parent_side_requests[&fixture.key()],
        request_for(&fixture, len),
        "an uncharged wait writes nothing"
    );
    // No pass (another source or no C14): never a side read.
    let (_, counts) = observe(|| page(&fixture, with(request_for(&fixture, len)), &cache, None));
    assert_eq!(counts.side_reads_started, 0);
    // Backoff: `not_before` in the future.
    let mut paced = request_for(&fixture, len);
    paced.not_before_unix_seconds = u64::MAX;
    let (_, counts) = observe(|| page(&fixture, with(paced), &cache, Some(pass(true))));
    assert_eq!(counts.side_reads_started, 0);
    // Needed past P's length: not due.
    let (_, counts) = observe(|| {
        page(
            &fixture,
            with(request_for(&fixture, len + 1)),
            &cache,
            Some(pass(true)),
        )
    });
    assert_eq!(counts.side_reads_started, 0);
    // A worn `Live` request is evicted by the due, in both stores' terms.
    let mut worn = request_for(&fixture, len);
    worn.attempts = SIDE_REQUEST_EVICT_ATTEMPTS;
    worn.attempt_extent = len - 1;
    let ((after, _), counts) = observe(|| page(&fixture, with(worn), &cache, Some(pass(true))));
    assert_eq!(counts.side_reads_started, 0);
    assert_eq!(counts.side_requests_tombstoned, 1);
    let evicted = after.codex_parent_side_requests[&fixture.key()];
    assert_eq!(evicted.state, SideRequestState::Evicted);
    assert_eq!(evicted.state_extent, len - 1);
    // A 2a singleton only: P over the singleton budget stays main's Skip.
    sampled_scan::codex_cursor::with_test_limits(1 << 20, len - 1, 64, || {
        let (_, counts) = observe(|| {
            page(
                &fixture,
                with(request_for(&fixture, len)),
                &cache,
                Some(pass(true)),
            )
        });
        assert_eq!(counts.side_reads_started, 0);
    });
}

#[test]
fn a_full_ledger_refuses_the_charge_and_nothing_is_written() {
    let fixture = Root::new(2, b"");
    let len = fixture.at().size;
    let (mut index, cache) = settled_page(&fixture);
    // Every slot is the caller's own namespace, which is never evicted.
    cache.side_ledger().fill_for_test(NS);
    index
        .codex_parent_side_requests
        .insert(fixture.key(), request_for(&fixture, len));
    let ((after, _), counts) = observe(|| page(&fixture, index, &cache, Some(pass(true))));
    assert_eq!(counts.side_reads_started, 0);
    assert!(counts.side_not_due >= 1);
    assert_eq!(
        after.codex_parent_side_requests[&fixture.key()],
        request_for(&fixture, len)
    );
    assert!(ledger_entry(&cache, &fixture).is_none());
}

/// Stage 1 (parent r79): a continuation page is never side-due and never
/// charges G7, whatever its gate: a worn request is not tombstoned by its
/// due check (no write, no count) and a due one is not charged (no ledger
/// entry). The same request on an ordinary page is the control.
#[test]
#[cfg_attr(
    not(any(target_os = "macos", target_os = "linux")),
    ignore = "needs macOS heap layout"
)]
fn a_continuation_page_is_never_due_and_charges_nothing() {
    let fixture = Root::new(1, b"");
    let at = fixture.at();
    let cache = sampled_scan::SharedCache::default();
    let continuation = CodexSidePass {
        kind: CodexPageKind::Continuation,
        ..pass(true)
    };
    let mut worn = request_for(&fixture, at.size);
    worn.attempts = SIDE_REQUEST_EVICT_ATTEMPTS;
    let mut index = ScanIndex::default();
    index.codex_parent_side_requests.insert(fixture.key(), worn);
    let (due, counts) = observe(|| {
        index.codex_parent_side_request_due(
            &fixture.key(),
            at,
            1_000,
            &cache,
            &continuation,
            || -> SideDueTerms { unreachable!("a continuation reads no due terms") },
        )
    });
    assert!(!due);
    assert_eq!(counts, Counts::default(), "nothing counted");
    assert_eq!(index.codex_parent_side_requests[&fixture.key()], worn);
    assert!(ledger_entry(&cache, &fixture).is_none());
    // G7: a request the ordinary page would charge.
    let request = request_for(&fixture, at.size);
    index
        .codex_parent_side_requests
        .insert(fixture.key(), request);
    assert_eq!(
        index.charge_codex_parent_side_read(&fixture.key(), at, 1_000, &cache, &continuation),
        None
    );
    assert_eq!(index.codex_parent_side_requests[&fixture.key()], request);
    assert!(ledger_entry(&cache, &fixture).is_none());
    // The control: an ordinary page charges it, and tombstones the worn one.
    assert_eq!(
        index.charge_codex_parent_side_read(&fixture.key(), at, 1_000, &cache, &pass(true)),
        Some(1)
    );
    assert!(ledger_entry(&cache, &fixture).is_some());
    let mut worn_index = ScanIndex::default();
    worn_index
        .codex_parent_side_requests
        .insert(fixture.key(), worn);
    let fresh = sampled_scan::SharedCache::default();
    let (due, counts) = observe(|| {
        worn_index.codex_parent_side_request_due(
            &fixture.key(),
            at,
            1_000,
            &fresh,
            &pass(true),
            || -> SideDueTerms { unreachable!("a worn request is not due") },
        )
    });
    assert!(!due);
    assert_eq!(counts.side_requests_tombstoned, 1);
    assert_eq!(
        worn_index.codex_parent_side_requests[&fixture.key()].state,
        SideRequestState::Evicted
    );
}

#[test]
#[cfg_attr(
    not(any(target_os = "macos", target_os = "linux")),
    ignore = "needs macOS heap layout"
)]
fn the_exit_rows_write_the_record_or_the_tombstone_in_both_stores() {
    let fixture = Root::new(1, b"");
    let at = fixture.at();
    let charged = |index: &mut ScanIndex, cache: &sampled_scan::SharedCache| {
        index
            .codex_parent_side_requests
            .insert(fixture.key(), request_for(&fixture, at.size));
        index
            .charge_codex_parent_side_read(&fixture.key(), at, 1_000, cache, &pass(true))
            .expect("charged");
    };
    // Row 5: data loss → `Lossy` at the attempt's extent.
    let cache = sampled_scan::SharedCache::default();
    let side = Some((&cache, NS));
    let mut index = ScanIndex::default();
    charged(&mut index, &cache);
    let (_, counts) = observe(|| {
        index.finish_codex_parent_side_read(&fixture.key(), at.dev_ino, SideReadEnd::Lossy, side)
    });
    assert_eq!(counts.side_requests_tombstoned, 1);
    let lossy = index.codex_parent_side_requests[&fixture.key()];
    assert_eq!(lossy.state, SideRequestState::Lossy);
    assert_eq!(lossy.state_extent, at.size);
    assert_eq!(
        ledger_entry(&cache, &fixture).unwrap().tag,
        LedgerTag::Lossy
    );
    // Row 6: nothing beyond the charge.
    let cache = sampled_scan::SharedCache::default();
    let side = Some((&cache, NS));
    let mut index = ScanIndex::default();
    charged(&mut index, &cache);
    let before = index.codex_parent_side_requests[&fixture.key()];
    let (_, counts) = observe(|| {
        index.finish_codex_parent_side_read(&fixture.key(), at.dev_ino, SideReadEnd::Failed, side)
    });
    assert_eq!(counts, Counts::default());
    assert_eq!(index.codex_parent_side_requests[&fixture.key()], before);
    assert!(index.codex_parent_side.is_empty());
}

#[test]
#[cfg_attr(
    not(any(target_os = "macos", target_os = "linux")),
    ignore = "needs macOS heap layout"
)]
fn due_side_read_preserves_future_exact_body_cooldown_and_settlement() {
    let fixture = Root::new(3, b"");
    let (mut settled, cache) = settled_page(&fixture);
    let fingerprint = settled.file_snapshot_fingerprints[&fixture.key()]
        .iter()
        .next()
        .unwrap()
        .clone();
    let body = "synthetic-refused-body";
    let now = time::OffsetDateTime::parse(NOW, &time::format_description::well_known::Rfc3339)
        .unwrap()
        .unix_timestamp() as u64;
    let deadline = now + 86_400;
    let mut record = snapshot_quarantine_record(SnapshotSource::Codex);
    record.retry_after_unix_seconds = 0; // ordinary retry is due; only the exact-body cooldown defers it
    record.upload_body_witness = Some(body.into());
    settled.accepted_snapshot_fingerprints.remove(&fingerprint);
    settled
        .quarantined_snapshot_fingerprints
        .insert(fingerprint.clone(), record.clone());
    settled.activate_quarantine_witness_for_test(SnapshotSource::Codex);
    settled.activate_reason_reoffer_cooldowns(BTreeMap::from([(fingerprint.clone(), body.into())]));
    assert!(settled.reason_reoffer_conflict_is_deferred(&fingerprint, body));
    assert_eq!(settled.reason_reoffer_cooldown_deferred_count(), 1);
    let mut treated = settled.clone();
    treated
        .codex_parent_side_requests
        .insert(fixture.key(), request_for(&fixture, fixture.at().size));
    let (control_index, control) = page(&fixture, settled, &cache, Some(pass(true)));
    let ((treated_index, treated), counts) =
        observe(|| page(&fixture, treated, &cache, Some(pass(true))));
    assert_eq!(
        counts.side_reads_started, 1,
        "the due side request really ran"
    );
    assert!(
        control.snapshots.is_empty(),
        "ordinary selection skips the unchanged cooldown body"
    );
    assert_eq!(main_result(&treated), main_result(&control));
    assert_eq!(main_state(&treated_index), main_state(&control_index));
    for index in [&control_index, &treated_index] {
        assert!(index.reason_reoffer_conflict_is_deferred(&fingerprint, body));
        assert_eq!(index.reason_reoffer_cooldown_deferred_count(), 1);
        assert!(
            crate::snapshot_sync::retained_refusal_settles_for_test(
                index,
                &fingerprint,
                record.clone(),
                body,
                now,
                deadline
            ),
            "future reservation remains nonblocking for settlement"
        );
        assert!(
            !crate::snapshot_sync::retained_refusal_settles_for_test(
                index,
                &fingerprint,
                record.clone(),
                body,
                deadline,
                deadline
            ),
            "the same retained refusal blocks at its actual deadline"
        );
    }
    assert_eq!(
        treated_index.codex_parent_side[&fixture.key()].verdict,
        SideVerdict::Settled
    );
    assert!(treated_index.codex_parent_side_requests.is_empty());
}
