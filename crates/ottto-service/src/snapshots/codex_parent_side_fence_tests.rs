//! U1a-2a row 6: the side fence (object test, record consumption, request
//! path, coverage, the one admission and its refusal routing, the re-arm
//! table). Fixtures are synthetic bytes; nothing comes from a provider
//! account.
use super::*;
use crate::local_resource_diagnostics::codex_side_lifecycle::{observe, Counts};
use crate::transcript_acquisition::{FullReason, PrefixSeal, SAMPLE_BYTES};
use sampled_scan::codex_cursor::OpenStamp;
use sampled_scan::side_ledger::{namespace_of, parent_of, LedgerEntry, LedgerKey, LedgerTag};
use std::os::unix::fs::{FileExt, PermissionsExt};

/// The sweep's clock in these tests: past every fixture pace's `not_before`.
const SWEEP_NOW: u64 = 1_800_000_000;

const KEY: &str = "/s/rollout-parent.jsonl";

struct Parent {
    path: PathBuf,
    file: File,
}

impl Parent {
    fn new(name: &str, len: usize) -> Self {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "ottto-u1a2a-fence-{name}-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("parent.jsonl");
        let bytes = (0..len)
            .map(|at| b'a' + (at % 23) as u8)
            .collect::<Vec<_>>();
        fs::write(&path, bytes).unwrap();
        let file = File::open(&path).unwrap();
        Self { path, file }
    }

    fn len(&self) -> u64 {
        self.file.metadata().unwrap().len()
    }

    fn dev_ino(&self) -> (u64, u64) {
        let metadata = self.file.metadata().unwrap();
        (metadata.dev(), metadata.ino())
    }

    fn ctime(&self) -> (i64, i64) {
        let metadata = self.file.metadata().unwrap();
        (metadata.ctime(), metadata.ctime_nsec())
    }

    fn writer(&self) -> File {
        fs::OpenOptions::new().write(true).open(&self.path).unwrap()
    }

    fn append(&self, bytes: &[u8]) {
        let len = self.len();
        self.writer().write_all_at(bytes, len).unwrap();
    }

    /// A ctime-only change (bytes and size kept).
    fn touch_ctime(&self) {
        std::thread::sleep(std::time::Duration::from_millis(20));
        let mode = self.file.metadata().unwrap().permissions().mode();
        fs::set_permissions(&self.path, fs::Permissions::from_mode(mode ^ 0o004)).unwrap();
    }

    /// A same-size edit outside both sealed windows that moves mtime: the
    /// samples still match (Q-U28's cheap distinction cannot see it).
    fn rewrite_middle(&self, at: u64) {
        let mut byte = [0_u8];
        self.file.read_exact_at(&mut byte, at).unwrap();
        byte[0] = if byte[0] == b'#' { b'%' } else { b'#' };
        self.writer().write_all_at(&byte, at).unwrap();
        self.writer()
            .set_modified(UNIX_EPOCH + std::time::Duration::from_secs(1_600_000_000))
            .unwrap();
    }

    /// A same-size edit inside the sealed head window.
    fn rewrite_head(&self) {
        std::thread::sleep(std::time::Duration::from_millis(20));
        self.writer().write_all_at(b"#", 0).unwrap();
    }

    /// The side seal of the file as it is now, sealed at its length, the
    /// way `Checkpoint::seal_as` mints it.
    fn seal(&self, verified: u64, scope: &str) -> PrefixSeal {
        let metadata = self.file.metadata().unwrap();
        let len = metadata.len();
        let window = len.min(SAMPLE_BYTES as u64);
        let digest = |offset: u64| {
            let mut bytes = vec![0; window as usize];
            self.file.read_exact_at(&mut bytes, offset).unwrap();
            Sha256::digest(&bytes)
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        };
        serde_json::from_value(serde_json::json!({
            "stamp": {
                "length": len,
                "device": metadata.dev(),
                "inode": metadata.ino(),
                "modified": [metadata.mtime(), metadata.mtime_nsec()],
                "changed": [metadata.ctime(), metadata.ctime_nsec()],
            },
            "scope": scope,
            "sample_len": window,
            "head_sha256": digest(0),
            "boundary_sha256": digest(len - window),
            "verified_unix_seconds": verified,
            "sealed_unix_seconds": verified,
        }))
        .unwrap()
    }

    fn record(&self, verdict: SideVerdict, verified: u64) -> CodexParentSide {
        CodexParentSide {
            verdict,
            seal: self.seal(verified, &codex_parent_side_scope().0),
            parsed: OpenStamp::capture(&self.file).unwrap(),
            pace: None,
            generation: 1,
            referenced_epoch: 0,
        }
    }

    fn request(&self, state: SideRequestState, attempts: u8) -> SideRequest {
        SideRequest {
            dev_ino: self.dev_ino(),
            needed_extent: 100,
            state,
            state_extent: self.len(),
            state_ctime: self.ctime(),
            attempt_extent: self.len(),
            attempt_ctime: self.ctime(),
            attempts,
            not_before_unix_seconds: 4242,
            needed_charge: None,
            referenced_epoch: 0,
        }
    }

    fn fence(&mut self, index: &mut ScanIndex, needed: u64, now: u64) -> (SideFence, Counts) {
        observe(|| index.codex_parent_side_fence(KEY, &mut self.file, needed, now, None))
    }
}

fn now() -> u64 {
    sampled_scan::now_seconds()
}

fn with_record(record: CodexParentSide) -> ScanIndex {
    let mut index = ScanIndex::default();
    index.codex_parent_side.insert(KEY.into(), record);
    index
}

/// Admission is the one predicate on a same-object, settled record that
/// covers `needed`: unchanged and grown-inside-the-horizon P admit and write
/// nothing; a held record, step 5 on an unchanged P and P over main's cap
/// refuse without arming anything; step 5 on a grown P arms the request.
#[test]
fn the_fence_admits_only_a_settled_covering_record_and_writes_nothing_then() {
    let mut parent = Parent::new("admit", 10_000);
    let now = now();
    let len = parent.len();
    let mut index = with_record(parent.record(SideVerdict::Settled, now));
    let before = serde_json::to_value(&index).unwrap();
    for needed in [0, 1, len] {
        let (fenced, counts) = parent.fence(&mut index, needed, now);
        assert_eq!(fenced, SideFence::Admitted, "needed={needed}");
        assert_eq!(counts, Counts::default());
    }
    assert_eq!(serde_json::to_value(&index).unwrap(), before);

    // Step 5, P unchanged: stale, nothing armed.
    assert_eq!(parent.fence(&mut index, len + 1, now).0, SideFence::Stale);
    assert!(index.codex_parent_side_requests.is_empty());

    // P grew inside the horizon: the seal admits its prefix (`Tail`).
    parent.append(b"{\"appended\":true}\n");
    assert_eq!(parent.fence(&mut index, len, now).0, SideFence::Admitted);
    assert!(index.codex_parent_side_requests.is_empty());
    // Step 5, P grown: the request is armed (`Live{0}`, no stub).
    assert_eq!(parent.fence(&mut index, len + 1, now).0, SideFence::Stale);
    let request = index.codex_parent_side_requests[KEY];
    assert_eq!(request.state, SideRequestState::Live);
    assert_eq!((request.attempts, request.needed_extent), (0, len + 1));
    assert_eq!(request.dev_ino, parent.dev_ino());
    assert_eq!(request.state_extent, parent.len());

    // A held record refuses as held and arms nothing.
    let held = SideVerdict::Held {
        lineage: true,
        cause: 3,
    };
    let mut index = with_record(parent.record(held, now));
    assert_eq!(
        parent.fence(&mut index, 1, now).0,
        SideFence::Held {
            lineage: true,
            cause: 3
        }
    );
    assert!(index.codex_parent_side_requests.is_empty());

    // Over main's cap: no side state at all.
    parent
        .writer()
        .set_len(MAX_CODEX_JSONL_FILE_BYTES + 1)
        .unwrap();
    assert_eq!(parent.fence(&mut index, 1, now).0, SideFence::FileCapHeld);
    assert!(index.codex_parent_side_requests.is_empty());
    assert!(index.codex_parent_side.contains_key(KEY));
}

/// With no record the fence takes the request path: create `Live{0}`, or
/// `Live{6, stub}` from a same-object `Removed` ledger stub; an existing
/// request keeps its counters (`needed = max`), and the growth cure sets
/// `attempts = 6` with `not_before` unchanged for a tombstone past
/// `state_extent` or a worn `Live` past `attempt_extent`.
#[test]
fn without_a_record_the_fence_creates_or_cures_the_request_by_growth() {
    let mut parent = Parent::new("request", 9_000);
    let now = now();
    let mut index = ScanIndex::default();
    let (fenced, counts) = parent.fence(&mut index, 500, now);
    assert_eq!(fenced, SideFence::Unknown);
    assert_eq!(counts, Counts::default(), "a create is not a re-arm");
    assert_eq!(
        index.codex_parent_side_requests[KEY],
        SideRequest::created(
            SideNow {
                dev_ino: parent.dev_ino(),
                size: parent.len(),
                ctime: parent.ctime(),
            },
            500,
            0,
            0
        )
    );
    // A later fence keeps the state and raises `needed` only.
    let mut charged = index.codex_parent_side_requests[KEY];
    charged.attempts = 3;
    charged.not_before_unix_seconds = 77;
    index.codex_parent_side_requests.insert(KEY.into(), charged);
    parent.fence(&mut index, 200, now);
    assert_eq!(index.codex_parent_side_requests[KEY], charged);
    parent.fence(&mut index, 900, now);
    assert_eq!(index.codex_parent_side_requests[KEY].needed_extent, 900);

    // Growth cure, both rows; an ungrown tombstone or worn `Live` stays.
    for (state, attempts) in [
        (SideRequestState::Evicted, 7),
        (SideRequestState::Lossy, 2),
        (SideRequestState::Unsealed, 2),
        (SideRequestState::Short { covered: 10 }, 2),
        (SideRequestState::Live, 7),
    ] {
        let request = parent.request(state, attempts);
        let mut index = ScanIndex::default();
        index.codex_parent_side_requests.insert(KEY.into(), request);
        parent.fence(&mut index, 1, now);
        assert_eq!(
            index.codex_parent_side_requests[KEY].state, state,
            "{state:?} ungrown"
        );
        parent.append(b"x");
        let (_, counts) = parent.fence(&mut index, 1, now);
        let cured = index.codex_parent_side_requests[KEY];
        assert_eq!(cured.state, SideRequestState::Live, "{state:?}");
        assert_eq!(cured.attempts, SIDE_REQUEST_EVICT_ATTEMPTS - 1, "{state:?}");
        assert_eq!(cured.not_before_unix_seconds, 4242, "{state:?}");
        assert_eq!(
            counts.side_requests_rearmed, 0,
            "a growth cure is not a re-arm"
        );
    }
}

/// The routing table: `AuditDue`, `ClockChanged` and `ScopeChanged` refuse
/// into the paced request path (counted per fence). On a grown P it is the
/// fence's growth branch; on a non-grown P the rev 18.2 re-arm table, each
/// state change counted once.
#[test]
fn seal_refusals_route_to_the_request_path_and_the_rearm_table() {
    let mut parent = Parent::new("route", 9_000);
    let now = now();
    let len = parent.len();
    let past = now - crate::transcript_acquisition::AUDIT_INTERVAL_SECONDS - 1;

    // Grown past the horizon: `AuditDue`, the growth branch creates `Live{0}`.
    let mut index = with_record(parent.record(SideVerdict::Settled, past));
    parent.append(b"{\"later\":1}\n");
    let (fenced, counts) = parent.fence(&mut index, len, now);
    assert_eq!(fenced, SideFence::Refused(FullReason::AuditDue));
    assert_eq!((counts.side_refusals, counts.side_requests_rearmed), (1, 0));
    assert_eq!(index.codex_parent_side_requests[KEY].attempts, 0);
    assert!(index.codex_parent_side.contains_key(KEY), "kept");

    // Non-grown: a regressed clock and another scope refuse.
    let mut parent = Parent::new("route-flat", 9_000);
    let len = parent.len();
    let mut index = with_record(parent.record(SideVerdict::Settled, now + 600));
    assert_eq!(
        parent.fence(&mut index, len, now).0,
        SideFence::Refused(FullReason::ClockChanged)
    );
    let mut scoped = parent.record(SideVerdict::Settled, now);
    scoped.seal = parent.seal(now, "another scope");
    let mut index = with_record(scoped);
    let (fenced, counts) = parent.fence(&mut index, len, now);
    assert_eq!(fenced, SideFence::Refused(FullReason::ScopeChanged));
    assert_eq!((counts.side_refusals, counts.side_requests_rearmed), (1, 1));
    assert_eq!(index.codex_parent_side_requests[KEY].attempts, 0, "no stub");

    // The re-arm table on a non-grown P (`ClockChanged` each time).
    let refuse = |parent: &mut Parent, request: Option<SideRequest>, pace: Option<SidePace>| {
        let mut record = parent.record(SideVerdict::Settled, now + 600);
        record.pace = pace;
        let mut index = with_record(record);
        if let Some(request) = request {
            index.codex_parent_side_requests.insert(KEY.into(), request);
        }
        let (fenced, counts) = parent.fence(&mut index, 1, now);
        assert_eq!(fenced, SideFence::Refused(FullReason::ClockChanged));
        (index.codex_parent_side_requests.get(KEY).copied(), counts)
    };
    let stub = SidePace {
        not_before_unix_seconds: 999,
        attempts_floor: 6,
    };
    let (created, counts) = refuse(&mut parent, None, Some(stub));
    let created = created.unwrap();
    assert_eq!(
        (created.attempts, created.not_before_unix_seconds),
        (6, 999)
    );
    assert_eq!(counts.side_requests_rearmed, 1);
    let evicted = parent.request(SideRequestState::Evicted, 7);
    let (rearmed, counts) = refuse(&mut parent, Some(evicted), None);
    let rearmed = rearmed.unwrap();
    assert_eq!(rearmed.state, SideRequestState::Live);
    assert_eq!(
        (rearmed.attempts, rearmed.not_before_unix_seconds),
        (6, 4242)
    );
    assert_eq!(counts.side_requests_rearmed, 1);
    let worn = parent.request(SideRequestState::Live, 7);
    assert_eq!(refuse(&mut parent, Some(worn), None).0.unwrap().attempts, 6);
    let pending = parent.request(SideRequestState::Live, 3);
    let (kept, counts) = refuse(&mut parent, Some(pending), None);
    assert_eq!(kept.unwrap(), pending);
    assert_eq!(counts.side_requests_rearmed, 0, "already pending");
    // Byte-determined tombstones re-arm only on a changed (ctime, size).
    for state in [
        SideRequestState::Lossy,
        SideRequestState::Unsealed,
        SideRequestState::Short { covered: 10 },
    ] {
        let tombstone = parent.request(state, 2);
        let (kept, counts) = refuse(&mut parent, Some(tombstone), None);
        assert_eq!(kept.unwrap(), tombstone, "{state:?} on the same stamp");
        assert_eq!(counts.side_requests_rearmed, 0);
        let mut moved = tombstone;
        moved.attempt_ctime.1 = moved.attempt_ctime.1.wrapping_add(1);
        let (rearmed, counts) = refuse(&mut parent, Some(moved), None);
        let rearmed = rearmed.unwrap();
        assert_eq!(rearmed.state, SideRequestState::Live, "{state:?}");
        assert_eq!(rearmed.attempts, 6);
        assert_eq!(counts.side_requests_rearmed, 1);
    }
}

/// Q-U28 at admission: a ctime-only change refuses `SameSizeEdit` (a
/// parent seal and its parsed-stamp guard keep the exact stamp, E1 S3 C1),
/// the samples match, so it is the same object and takes the request path.
/// A same-size rewrite between the sealed windows that moves mtime also
/// matches both samples: refused `SameSizeEdit` and re-requested, never
/// admitted. Both keep the held FD's position. A same-size rewrite of a
/// sealed window is a new object that consumes the record and restarts the
/// request.
#[test]
fn a_ctime_only_change_is_the_same_object_and_a_rewrite_consumes_the_record() {
    let mut parent = Parent::new("q-u28", 9_000);
    let now = now();
    let len = parent.len();
    let mut index = with_record(parent.record(SideVerdict::Settled, now));
    parent.touch_ctime();
    parent.file.seek(SeekFrom::Start(123)).unwrap();
    let (fenced, counts) = parent.fence(&mut index, len, now);
    assert_eq!(
        fenced,
        SideFence::Refused(FullReason::SameSizeEdit),
        "ctime only"
    );
    assert_eq!(counts.side_refusals, 1);
    assert!(index.codex_parent_side.contains_key(KEY), "same object");
    assert_eq!(index.codex_parent_side_requests[KEY].attempts, 0);
    assert_eq!(parent.file.stream_position().unwrap(), 123, "position kept");

    let mut index = with_record(parent.record(SideVerdict::Settled, now));
    parent.rewrite_middle(SAMPLE_BYTES as u64 + 100);
    let (fenced, counts) = parent.fence(&mut index, len, now);
    assert_eq!(fenced, SideFence::Refused(FullReason::SameSizeEdit));
    assert_eq!(counts.side_refusals, 1);
    assert!(index.codex_parent_side.contains_key(KEY), "same object");
    let requested = index.codex_parent_side_requests[KEY];
    assert_eq!(
        (requested.state, requested.attempts, requested.dev_ino),
        (SideRequestState::Live, 0, parent.dev_ino()),
        "re-requested"
    );
    assert_eq!(parent.file.stream_position().unwrap(), 123, "position kept");

    let mut index = with_record(parent.record(SideVerdict::Settled, now));
    let mut charged = parent.request(SideRequestState::Lossy, 4);
    charged.state_extent = len;
    index.codex_parent_side_requests.insert(KEY.into(), charged);
    parent.rewrite_head();
    let (fenced, counts) = parent.fence(&mut index, len, now);
    assert_eq!(fenced, SideFence::Unknown);
    assert_eq!(counts.side_requests_rearmed, 1, "new_object{{rewrite}}");
    assert!(!index.codex_parent_side.contains_key(KEY), "consumed");
    let restarted = index.codex_parent_side_requests[KEY];
    assert_eq!(restarted.state, SideRequestState::Live);
    assert_eq!(
        (restarted.attempts, restarted.not_before_unix_seconds),
        (0, 0)
    );
    assert_eq!(restarted.state_ctime, parent.ctime());
}

/// R1-M1: one fence reads the record's sealed windows at most once. On the
/// `SameSizeEdit` path with changed samples, the guard and the `_` arm
/// share one `samples_match`.
#[test]
fn a_same_size_edit_with_changed_samples_reads_them_once() {
    let mut parent = Parent::new("samples-once", 9_000);
    let now = now();
    let len = parent.len();
    let mut index = with_record(parent.record(SideVerdict::Settled, now));
    parent.rewrite_head();
    crate::transcript_acquisition::samples_match_calls();
    let (fenced, _) = parent.fence(&mut index, len, now);
    assert_eq!(fenced, SideFence::Unknown, "a rewrite consumes the record");
    assert!(!index.codex_parent_side.contains_key(KEY));
    assert_eq!(crate::transcript_acquisition::samples_match_calls(), 1);
}

/// R2-M3: the epoch prune moves a charged `Live` request's pacing onto P's
/// same-object record first, so the next reference re-arms with attempts
/// ≥ the pruned ones (never a fresh ladder); with no such record the
/// request is kept.
#[test]
fn an_epoch_pruned_request_rearms_with_at_least_its_attempts() {
    let mut parent = Parent::new("epoch-prune", 9_000);
    let now = now();
    // The fence refuses this record (`ClockChanged`): the request path decides.
    let mut record = parent.record(SideVerdict::Settled, now + 600);
    record.referenced_epoch = 10;
    let charged = SideRequest {
        referenced_epoch: 1,
        ..parent.request(SideRequestState::Live, 3)
    };
    let mut index = with_record(record);
    index.codex_parent_proof_wrap_epoch = 10;
    index.codex_parent_side_requests.insert(KEY.into(), charged);
    assert_eq!(
        index
            .sweep_codex_parent_side(false, None, SWEEP_NOW)
            .requests_pruned,
        1
    );
    assert!(index.codex_parent_side_requests.is_empty());
    let (fenced, _) = parent.fence(&mut index, 1, now);
    assert_eq!(fenced, SideFence::Refused(FullReason::ClockChanged));
    let rearmed = index.codex_parent_side_requests[KEY];
    assert!(rearmed.attempts >= charged.attempts, "{rearmed:?}");
    assert_eq!(
        rearmed.not_before_unix_seconds,
        charged.not_before_unix_seconds
    );

    // Fix round 2 (DM2): unreferenced for 3+ wraps, the record keeps the
    // pruned pacing (its pace is active), so the re-reference re-arms at
    // the floor with the same `not_before`, never `Live{0}`.
    let mut record = parent.record(SideVerdict::Settled, now + 600);
    record.referenced_epoch = 10;
    let mut index = with_record(record);
    index.codex_parent_proof_wrap_epoch = 10;
    index.codex_parent_side_requests.insert(KEY.into(), charged);
    assert_eq!(
        index
            .sweep_codex_parent_side(false, None, now)
            .requests_pruned,
        1
    );
    for wrap in 11..=14 {
        index.codex_parent_proof_wrap_epoch = wrap;
        assert_eq!(
            index
                .sweep_codex_parent_side(false, None, now)
                .records_pruned,
            0,
            "wrap {wrap}"
        );
    }
    assert!(index.codex_parent_side.contains_key(KEY));
    let (fenced, _) = parent.fence(&mut index, 1, now);
    assert_eq!(fenced, SideFence::Refused(FullReason::ClockChanged));
    let rearmed = index.codex_parent_side_requests[KEY];
    assert!(
        rearmed.attempts >= SIDE_REQUEST_EVICT_ATTEMPTS - 1,
        "{rearmed:?}"
    );
    assert_eq!(
        rearmed.not_before_unix_seconds,
        charged.not_before_unix_seconds
    );

    let mut index = ScanIndex {
        codex_parent_proof_wrap_epoch: 10,
        ..ScanIndex::default()
    };
    index.codex_parent_side_requests.insert(KEY.into(), charged);
    assert_eq!(
        index
            .sweep_codex_parent_side(false, None, SWEEP_NOW)
            .requests_pruned,
        0
    );
    assert_eq!(index.codex_parent_side_requests[KEY], charged);
}

/// The request-side object test: a shrink below `state_extent`, or a record
/// for another object, is a new object (record consumed, request
/// restarted); a same-size ctime change with matching record samples only
/// moves `state_ctime`; with no record it is counted and changes nothing.
#[test]
fn the_request_side_object_test_restarts_on_a_shrink_and_moves_state_ctime_on_q_u28() {
    let mut parent = Parent::new("shrink", 9_000);
    let now = now();
    let mut index = with_record(parent.record(SideVerdict::Settled, now));
    index
        .codex_parent_side_requests
        .insert(KEY.into(), parent.request(SideRequestState::Evicted, 7));
    parent.writer().set_len(8_000).unwrap();
    assert_eq!(parent.fence(&mut index, 1, now).0, SideFence::Unknown);
    assert!(!index.codex_parent_side.contains_key(KEY));
    let restarted = index.codex_parent_side_requests[KEY];
    assert_eq!(
        (restarted.state, restarted.attempts, restarted.state_extent),
        (SideRequestState::Live, 0, 8_000)
    );

    // Same size, ctime moved, samples equal: `state_ctime` follows.
    let mut parent = Parent::new("ctime", 9_000);
    let record = parent.record(SideVerdict::Settled, now);
    let request = parent.request(SideRequestState::Evicted, 7);
    let mut index = with_record(record.clone());
    index.codex_parent_side_requests.insert(KEY.into(), request);
    parent.touch_ctime();
    parent.fence(&mut index, 1, now);
    let moved = index.codex_parent_side_requests[KEY];
    assert_eq!(moved.state_ctime, parent.ctime());
    assert_eq!(
        SideRequest {
            state_ctime: request.state_ctime,
            ..moved
        },
        SideRequest {
            state: SideRequestState::Live,
            attempts: 6,
            ..request
        },
        "the ctime-only refusal re-arms the evicted request once"
    );
    assert!(index.codex_parent_side.contains_key(KEY));

    // No record: counted (`ctime_only`), nothing else.
    let mut index = ScanIndex::default();
    let mut stale = moved;
    stale.state_ctime.1 = stale.state_ctime.1.wrapping_add(1);
    stale.state = SideRequestState::Lossy;
    index.codex_parent_side_requests.insert(KEY.into(), stale);
    let (fenced, counts) = parent.fence(&mut index, 1, now);
    assert_eq!(fenced, SideFence::Unknown);
    assert_eq!(counts.side_refusals, 1);
    assert_eq!(index.codex_parent_side_requests[KEY], stale);
}

/// A replace (another inode at P's key): the record is consumed, the old
/// key's ledger entry ends its generation (`Gone`), and the request
/// restarts for the new object. When the current key already has a ledger
/// entry, that entry is the request and its charge is not reset. Every
/// request write is mirrored only into an existing entry.
#[test]
fn a_replace_ends_the_old_keys_generation_and_a_current_entry_keeps_its_charge() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let now = now();
    let old = Parent::new("replace-old", 9_000);
    let mut new = Parent::new("replace-new", 9_500);
    let cache = sampled_scan::SharedCache::default();
    let ns = namespace_of(Path::new("/idx/fence.json"));
    let key = |parent: &Parent| LedgerKey {
        ns,
        p: parent_of(KEY),
        dev: parent.dev_ino().0,
        ino: parent.dev_ino().1,
    };
    let old_request = old.request(SideRequestState::Live, 3);
    cache
        .side_ledger()
        .charge(key(&old), LedgerEntry::of_request(&old_request), now)
        .unwrap();
    let mut index = with_record(old.record(SideVerdict::Settled, now));
    index
        .codex_parent_side_requests
        .insert(KEY.into(), old_request);
    let fenced = index.codex_parent_side_fence(KEY, &mut new.file, 1, now, Some((&cache, ns)));
    assert_eq!(fenced, SideFence::Unknown);
    assert!(!index.codex_parent_side.contains_key(KEY));
    let restarted = index.codex_parent_side_requests[KEY];
    assert_eq!((restarted.dev_ino, restarted.attempts), (new.dev_ino(), 0));
    let ledger = cache.side_ledger();
    assert_eq!(ledger.get(&key(&old)).unwrap().tag, LedgerTag::Gone);
    assert!(ledger.get(&key(&new)).is_none(), "only G7 creates entries");
    drop(ledger);

    // The current key's entry is the request: a stale record of the old
    // object is consumed, the entry's charge stays.
    let charged = new.request(SideRequestState::Live, 5);
    cache
        .side_ledger()
        .charge(key(&new), LedgerEntry::of_request(&charged), now)
        .unwrap();
    let mut index = with_record(old.record(SideVerdict::Settled, now));
    index
        .codex_parent_side_requests
        .insert(KEY.into(), old.request(SideRequestState::Evicted, 7));
    let stamped = cache.side_ledger().get(&key(&new)).copied();
    let fenced = index.codex_parent_side_fence(KEY, &mut new.file, 1, now, Some((&cache, ns)));
    assert_eq!(fenced, SideFence::Unknown);
    assert!(!index.codex_parent_side.contains_key(KEY));
    assert_eq!(
        index.codex_parent_side_requests[KEY], charged,
        "hydrated, not reset"
    );
    assert_eq!(
        cache.side_ledger().get(&key(&new)).copied(),
        stamped,
        "an unchanged projection is not re-stamped"
    );
    // A cure is mirrored into the existing entry in the same step.
    new.append(b"grown");
    let mut worn = charged;
    worn.attempts = 7;
    cache
        .side_ledger()
        .write_existing(&key(&new), LedgerEntry::of_request(&worn));
    index.codex_parent_side_fence(KEY, &mut new.file, 1, now, Some((&cache, ns)));
    let cured = index.codex_parent_side_requests[KEY];
    assert_eq!(cured.attempts, 6);
    assert!(LedgerEntry::of_request(&cured)
        .same_projection(cache.side_ledger().get(&key(&new)).unwrap()));
}

fn main_parse(parent: &Parent, verdict: SideVerdict, unsealed: bool) -> SideMainParse {
    SideMainParse {
        seal: parent.seal(now(), &codex_parent_side_scope().0),
        parsed: OpenStamp::capture(&parent.file).unwrap(),
        verdict,
        unsealed,
    }
}

/// Row 8: main's writer. Unsealed ∧ settled writes nothing; a record is
/// created only while P is live (a child's ref, a request, an owed proof),
/// and updated whenever it exists. A create or a verdict change takes
/// `++codex_parent_side_generation`; the wrap epoch follows a create or a
/// live update. Each write is counted.
#[test]
fn main_writes_p_side_record_only_when_live_or_present() {
    let parent = Parent::new("writer", 9_000);
    let ids = ["019a0000-0000-7000-8000-00000000000a".to_owned()];
    let held = SideVerdict::Held {
        lineage: false,
        cause: CAUSE_NO_EVIDENCE,
    };
    let mut index = ScanIndex {
        codex_parent_proof_wrap_epoch: 4,
        ..ScanIndex::default()
    };
    let write = |index: &mut ScanIndex, parse| {
        observe(|| index.write_codex_parent_side_from_main(KEY, &ids, parse, None))
    };
    // Not live: nothing.
    let (written, counts) = write(&mut index, main_parse(&parent, SideVerdict::Settled, false));
    assert!(!written);
    assert_eq!(counts, Counts::default());
    assert!(index.codex_parent_side.is_empty());
    // A child's ref names P: created.
    index.codex_parent_ownership_refs.insert(ids[0].clone());
    // Unsealed and settled: nothing, even when live.
    assert!(!write(&mut index, main_parse(&parent, SideVerdict::Settled, true)).0);
    // A group certificate that gave no unsealed bit is unsealed
    // (increment-14 disclosure 4): a settled group write is then refused.
    assert!(codex_group_side_unsealed(None));
    assert!(!codex_group_side_unsealed(Some(false)));
    let missing = codex_group_side_unsealed(None);
    assert!(
        !write(
            &mut index,
            main_parse(&parent, SideVerdict::Settled, missing)
        )
        .0
    );
    let (written, counts) = write(&mut index, main_parse(&parent, SideVerdict::Settled, false));
    assert!(written);
    assert_eq!(counts.side_records_written, 1);
    let created = index.codex_parent_side[KEY].clone();
    assert_eq!(created.verdict, SideVerdict::Settled);
    assert_eq!((created.generation, created.referenced_epoch), (1, 4));
    assert_eq!(created.parsed, OpenStamp::capture(&parent.file).unwrap());
    assert!(created.seal.scope_is(&codex_parent_side_scope()));
    // The same verdict keeps the generation; a change takes a new one, and
    // unsealed ∧ held still writes.
    index.codex_parent_proof_wrap_epoch = 5;
    write(&mut index, main_parse(&parent, SideVerdict::Settled, false));
    assert_eq!(index.codex_parent_side[KEY].generation, 1);
    assert_eq!(index.codex_parent_side[KEY].referenced_epoch, 5);
    assert!(write(&mut index, main_parse(&parent, held, true)).0);
    assert_eq!(index.codex_parent_side[KEY].verdict, held);
    assert_eq!(index.codex_parent_side[KEY].generation, 2);
    // No longer live: an existing record is still updated, its epoch kept.
    index.codex_parent_ownership_refs.clear();
    index.codex_parent_proof_wrap_epoch = 9;
    assert!(write(&mut index, main_parse(&parent, SideVerdict::Settled, false)).0);
    let updated = &index.codex_parent_side[KEY];
    assert_eq!((updated.generation, updated.referenced_epoch), (3, 5));
}

/// Row 8 cure: a same-object request the parse covers is removed and its
/// pacing becomes the record's stub (`{not_before, 6}`, never loosened);
/// the current key's ledger entry mirrors `Removed` with that stub. A
/// request needing more than the seal covers, or for another object,
/// stays.
#[test]
fn main_cures_a_covered_request_into_the_records_stub_and_mirrors_removed() {
    let parent = Parent::new("cure", 9_000);
    let len = parent.len();
    let ids: [String; 0] = [];
    let mut request = parent.request(SideRequestState::Lossy, 3);
    request.needed_extent = len + 1;
    let mut index = ScanIndex::default();
    index.codex_parent_side_requests.insert(KEY.into(), request);
    // Live through its request; not covered: the request stays.
    assert!(index.write_codex_parent_side_from_main(
        KEY,
        &ids,
        main_parse(&parent, SideVerdict::Settled, false),
        None,
    ));
    assert_eq!(index.codex_parent_side_requests[KEY], request);
    assert_eq!(index.codex_parent_side[KEY].pace, None);
    // Another object's request stays too.
    let mut other = request;
    other.dev_ino.1 = other.dev_ino.1.wrapping_add(1);
    other.needed_extent = 1;
    index.codex_parent_side_requests.insert(KEY.into(), other);
    index.write_codex_parent_side_from_main(
        KEY,
        &ids,
        main_parse(&parent, SideVerdict::Settled, false),
        None,
    );
    assert_eq!(index.codex_parent_side_requests[KEY], other);

    // Covered, with the current key's ledger entry as the view.
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let cache = sampled_scan::SharedCache::default();
    let ns = namespace_of(Path::new("/idx/writer.json"));
    let key = LedgerKey {
        ns,
        p: parent_of(KEY),
        dev: parent.dev_ino().0,
        ino: parent.dev_ino().1,
    };
    let mut charged = parent.request(SideRequestState::Live, 2);
    charged.needed_extent = len;
    charged.not_before_unix_seconds = 5555;
    cache
        .side_ledger()
        .charge(key, LedgerEntry::of_request(&charged), now())
        .unwrap();
    let mut index = ScanIndex::default();
    index.codex_parent_side_requests.insert(KEY.into(), request);
    let mut record = parent.record(SideVerdict::Settled, now());
    record.pace = Some(SidePace {
        not_before_unix_seconds: 9999,
        attempts_floor: 6,
    });
    index.codex_parent_side.insert(KEY.into(), record);
    assert!(index.write_codex_parent_side_from_main(
        KEY,
        &ids,
        main_parse(&parent, SideVerdict::Settled, false),
        Some((&cache, ns)),
    ));
    assert!(!index.codex_parent_side_requests.contains_key(KEY), "cured");
    assert_eq!(
        index.codex_parent_side[KEY].pace,
        Some(SidePace {
            not_before_unix_seconds: 9999,
            attempts_floor: 6,
        }),
        "max(existing, stub)"
    );
    let entry = *cache.side_ledger().get(&key).unwrap();
    assert_eq!(
        (entry.tag, entry.stub_not_before),
        (LedgerTag::Removed, 5555)
    );
}

/// cc row 7: a terminal disclosure refreshes P's existing record to held
/// and never creates one. A verdict change takes a new generation; the wrap
/// epoch follows only while P is live; an unchanged, not-live record is
/// left alone and nothing is counted.
#[test]
fn a_terminal_disclosure_refreshes_an_existing_record_to_held_only() {
    let parent = Parent::new("disclosed", 9_000);
    let ids = ["019a0000-0000-7000-8000-00000000000b".to_owned()];
    let held = SideVerdict::Held {
        lineage: true,
        cause: CAUSE_NO_EVIDENCE,
    };
    let refresh = |index: &mut ScanIndex| {
        observe(|| index.refresh_codex_parent_side_held(KEY, &ids, true, CAUSE_NO_EVIDENCE))
    };
    // No record: nothing is created, even while live.
    let mut index = ScanIndex {
        codex_parent_proof_wrap_epoch: 4,
        ..ScanIndex::default()
    };
    index.codex_parent_ownership_refs.insert(ids[0].clone());
    let (written, counts) = refresh(&mut index);
    assert!(!written);
    assert_eq!(counts, Counts::default());
    assert!(index.codex_parent_side.is_empty());
    // Update-only hides no owed work: without a record the next use of P
    // is `Unknown` and arms P's request, as without the disclosure.
    let mut fenced = Parent::new("disclosed-absent", 9_000);
    assert_eq!(fenced.fence(&mut index, 1, now()).0, SideFence::Unknown);
    assert_eq!(
        index.codex_parent_side_requests[KEY].state,
        SideRequestState::Live
    );
    // Not live: the verdict flips and takes a new generation; the epoch is kept.
    let mut index = with_record(parent.record(SideVerdict::Settled, now()));
    index.codex_parent_proof_wrap_epoch = 4;
    index.codex_parent_side_generation = 1;
    let (written, counts) = refresh(&mut index);
    assert!(written);
    assert_eq!(counts.side_records_written, 1);
    let record = &index.codex_parent_side[KEY];
    assert_eq!(record.verdict, held);
    assert_eq!((record.generation, record.referenced_epoch), (2, 0));
    // The same verdict, still not live: nothing.
    assert_eq!(refresh(&mut index), (false, Counts::default()));
    // Live: the epoch follows; the generation is kept.
    index.codex_parent_ownership_refs.insert(ids[0].clone());
    assert!(refresh(&mut index).0);
    let record = &index.codex_parent_side[KEY];
    assert_eq!((record.generation, record.referenced_epoch), (2, 4));
    assert_eq!(refresh(&mut index), (false, Counts::default()));
}

/// D6(b): every fence use is a child's reference to P: the request it arms
/// takes the wrap epoch, and a later use (no other write) refreshes it.
/// The ledger projection carries no epoch, so its stamp is kept.
#[test]
fn a_fence_use_stamps_the_request_with_the_wrap_epoch() {
    let mut parent = Parent::new("epoch", 9_000);
    let now = now();
    let mut index = ScanIndex {
        codex_parent_proof_wrap_epoch: 5,
        ..ScanIndex::default()
    };
    assert_eq!(parent.fence(&mut index, 500, now).0, SideFence::Unknown);
    let armed = index.codex_parent_side_requests[KEY];
    assert_eq!(armed.referenced_epoch, 5);
    index.codex_parent_proof_wrap_epoch = 9;
    assert_eq!(parent.fence(&mut index, 500, now).0, SideFence::Unknown);
    assert_eq!(
        index.codex_parent_side_requests[KEY],
        SideRequest {
            referenced_epoch: 9,
            ..armed
        }
    );
    assert_eq!(
        sampled_scan::side_ledger::LedgerEntry::of_request(&armed),
        sampled_scan::side_ledger::LedgerEntry::of_request(&index.codex_parent_side_requests[KEY])
    );
}
