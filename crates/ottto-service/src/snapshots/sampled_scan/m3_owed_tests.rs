//! Q11/N10 tests use the real shared spent owner and physical read adapter.
//! Integrated native/debt/money qualification belongs to the transition driver.
use super::*;
use crate::transcript_acquisition::ReadPlan;
use std::io::{BufReader, Read, Seek, SeekFrom, Write};
use std::time::{Duration, Instant};

thread_local! {
    static PHYSICAL: std::cell::RefCell<Vec<(RetailGrant, u64, usize)>> = const {
        std::cell::RefCell::new(Vec::new())
    };
}

pub(super) fn observe_retail(grant: RetailGrant, offset: u64, bytes: usize) {
    PHYSICAL.with(|reads| reads.borrow_mut().push((grant, offset, bytes)));
}

fn physical() -> Vec<(RetailGrant, u64, usize)> {
    PHYSICAL.with(|reads| std::mem::take(&mut *reads.borrow_mut()))
}

struct Fixture {
    root: PathBuf,
    checkpoint: Checkpoint,
    file: File,
    cache: SharedCache,
}
impl Fixture {
    fn new() -> Self {
        let root = crate::test_scratch::private_dir("m3-q11-n10");
        let path = root.join("source.jsonl");
        std::fs::write(&path, b"{\"n\":1}\n").unwrap();
        let scope = Scope("n10-original-scope".into());
        let mut file = File::open(&path).unwrap();
        let mut plan = ReadPlan::prepare(&mut file, None, &scope, None, 1_800_000_000).unwrap();
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).unwrap();
        plan.observe_complete_records(&bytes).unwrap();
        let checkpoint = plan
            .commit_after_native_completion(&file, &scope, 1_800_000_000)
            .unwrap();
        std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(b"{\"n\":2}\n")
            .unwrap();
        file.seek(SeekFrom::Start(checkpoint.sealed_offset()))
            .unwrap();
        let cache = SharedCache::default();
        cache.durable_begin_pass(
            SnapshotSource::ClaudeCode,
            &root.join("index.json"),
            &Scope("n10-namespace".into()),
            false,
        );
        physical();
        Self {
            root,
            checkpoint,
            file,
            cache,
        }
    }

    fn begin(&self, now: Instant) -> Result<RetailAttempt, RetailHold> {
        self.cache.begin_retail(
            SnapshotSource::ClaudeCode,
            "same-index-key",
            &self.checkpoint,
            &self.file,
            self.file.metadata().unwrap().len(),
            now,
        )
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.root).unwrap();
    }
}

/// [money] m3 p4b q11 n10 physical byte budget.
#[test]
fn m3_p4b_q11_n10_physical_byte_budget() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    let mut f = Fixture::new();
    let now = Instant::now();
    let suffix = f.file.metadata().unwrap().len() - f.checkpoint.sealed_offset();
    let mut first = f.begin(now).unwrap();
    assert_eq!(first.grant(), RetailGrant::Process);
    // Only one parser byte is consumed. BufReader prefetches the entire suffix;
    // the below-buffer adapter counts those successful physical syscall bytes.
    {
        let mut reader = BufReader::with_capacity(4096, first.accounted(&mut f.file));
        let mut one = [0];
        reader.read_exact(&mut one).unwrap();
    }
    first.finish();
    assert_eq!(
        physical(),
        vec![(
            RetailGrant::Process,
            f.checkpoint.sealed_offset(),
            suffix as usize
        )]
    );
    assert!(matches!(f.begin(now), Err(RetailHold::Exhausted)));
    let almost = now
        .checked_add(RETAIL_DAILY - Duration::from_nanos(1))
        .unwrap();
    assert!(matches!(f.begin(almost), Err(RetailHold::Exhausted)));
    let tomorrow = now.checked_add(RETAIL_DAILY).unwrap();
    let mut daily = f.begin(tomorrow).unwrap();
    assert_eq!(daily.grant(), RetailGrant::Daily);
    f.file
        .seek(SeekFrom::Start(f.checkpoint.sealed_offset()))
        .unwrap();
    let mut bytes = [0; 4096];
    assert_eq!(
        daily.read(&mut f.file, &mut bytes).unwrap(),
        suffix as usize
    );
    daily.finish();
    assert_eq!(
        physical(),
        vec![(
            RetailGrant::Daily,
            f.checkpoint.sealed_offset(),
            suffix as usize
        )]
    );
    assert!(matches!(f.begin(tomorrow), Err(RetailHold::Exhausted)));
}

/// [money] n10 pacing eviction allows growth without evicting spent authority.
#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "pacing tree admission requires the qualified native heap layout"
)]
fn n10_pacing_eviction_allows_growth_without_evicting_spent_authority() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    let f = Fixture::new();
    let now = Instant::now();
    f.begin(now).unwrap().finish();
    let digest = store::key_digest(DurableSource::ClaudeCode, "same-index-key");
    let prior = f.cache.durable().unwrap().retail_spent[&digest].spent;
    for n in 0..2 * store::MAX_RECORDS {
        assert!(f.cache.retail_full(
            &format!("paced-{n}"),
            &f.file,
            f.checkpoint.sealed_offset(),
            std::time::SystemTime::UNIX_EPOCH + Duration::from_secs(1_800_000_000 + n as u64)
        ));
    }
    let ((), _) = crate::local_resource_diagnostics::capture(|| {
        f.cache.durable_alarm(SnapshotSource::ClaudeCode);
    });
    // Eviction is emitted by the admission that evicts, not by durable_alarm.
    let ((), alarms) = crate::local_resource_diagnostics::capture(|| {
        assert!(f.cache.retail_full(
            "new-growing-key",
            &f.file,
            f.checkpoint.sealed_offset(),
            std::time::SystemTime::UNIX_EPOCH
                + Duration::from_secs(1_800_000_000 + 2 * store::MAX_RECORDS as u64)
        ));
        f.cache.durable_alarm(SnapshotSource::ClaudeCode);
    });
    let pace = alarms
        .iter()
        .filter_map(|alarm| alarm["counts"].get("pace_evicted"))
        .collect::<Vec<_>>();
    assert_eq!(pace, vec![&serde_json::json!([1, 1])]);
    let stores = f.cache.durable().unwrap();
    assert_eq!(stores.retail_spent[&digest].spent, prior);
    assert_eq!(stores.retail_spent.len(), 1);
    assert_eq!(stores.retail_full_at.len(), 2 * store::MAX_RECORDS);
    assert!(!stores
        .retail_full_at
        .contains_key(&store::key_digest(DurableSource::ClaudeCode, "paced-0")));
    drop(stores);
    assert!(matches!(
        f.begin(now + Duration::from_secs(1000)),
        Err(RetailHold::Exhausted)
    ));
    assert!(physical().is_empty());
}
