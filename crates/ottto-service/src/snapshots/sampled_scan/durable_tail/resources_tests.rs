//! M3 r7 resources: prepaid key-map layout, P1-1 restore-pending authority,
//! freed authorityless custody, debt outside custody, index-sized pass maps,
//! the P2 restored head budget and the Codex refused stale record. Every row
//! drives the real `Stores` owner; nothing here is a production entry point.
use super::*;
use crate::transcript_acquisition::ReadPlan;
use std::io::{Read, Write};
use std::time::{Duration, Instant};

const CLAUDE: SnapshotSource = SnapshotSource::ClaudeCode;

fn digest(key: &str) -> store::Digest32 {
    store::key_digest(DurableSource::ClaudeCode, key)
}

/// A one-line checkpoint whose file then grew by one more line.
fn grown(name: &str) -> (PathBuf, Checkpoint, File) {
    let root = crate::test_scratch::private_dir(name);
    let path = root.join("source.jsonl");
    std::fs::write(&path, b"{\"n\":1}\n").unwrap();
    let scope = Scope("r7-scope".into());
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
    (root, checkpoint, file)
}

fn entry() -> ScanIndexEntry {
    serde_json::from_value(serde_json::json!({
        "size_bytes":1,"modified_unix_seconds":1,"source_file_fingerprint":"fp"
    }))
    .unwrap()
}

#[test]
fn r7_every_key_map_node_fits_its_prepaid_charge() {
    // r6 put the D3 hold in the A0-h node and pushed it past 1024 bytes,
    // which would refuse every Q11 grant and strict check as unfunded.
    assert!(custody_node_bytes().unwrap() <= 1024, "A0-h custody node");
    assert!(
        super::owed::key_debt_node_bytes().unwrap() <= 1024,
        "debt/hold node"
    );
    assert!(
        restore_pending_node_bytes().unwrap() <= 1024,
        "pending node"
    );
    assert_eq!(
        KEY_RESERVE_BYTES,
        2 * (RESTORE_PENDING_KEYS + 1) * 1024,
        "both M3 maps prepay a retained root"
    );
    assert_eq!(STORES_RESIDENT_BOUND, 1_978_368);
}

#[test]
fn p1_1_zero_old_byte_restore_spends_pending_never_custody() {
    let (root, checkpoint, file) = grown("r7-p1-1-pending");
    let sealed = checkpoint.sealed_offset();
    let end = file.metadata().unwrap().len();
    let cache = SharedCache::default();
    let begin = |key: &str, at| cache.begin_retail(CLAUDE, key, &checkpoint, &file, sealed, at);
    let now = Instant::now();
    let first = begin("k", now).unwrap();
    assert_eq!(first.grant(), RetailGrant::Process);
    first.finish();
    {
        let stores = cache.durable().unwrap();
        assert!(stores.retail_spent.is_empty(), "no never-evicted A0-h node");
        assert_eq!(stores.restore_pending[&digest("k")].high, end);
        assert_eq!(
            (stores.counters.retail_keys, stores.counters.retail_attempts),
            (1, 1)
        );
    }
    // The same stale certificate again re-reads behind the pending high
    // water: promoted with its original grant time, then Daily-gated.
    assert!(matches!(
        begin("k", now + Duration::from_secs(1)),
        Err(RetailHold::Exhausted)
    ));
    {
        let stores = cache.durable().unwrap();
        assert!(stores.restore_pending.is_empty());
        assert_eq!(stores.retail_spent[&digest("k")].spent, Some((end, now)));
    }
    let daily = begin("k", now + RETAIL_DAILY).unwrap();
    assert_eq!(daily.grant(), RetailGrant::Daily);
    daily.finish();
    // A write or receipt at the high water frees a pending grant; a shorter
    // certificate does not.
    begin("w", now).unwrap().finish();
    {
        let mut stores = cache.durable().unwrap();
        stores.release_restore_pending(&digest("w"), end - 1);
        assert!(stores.restore_pending.contains_key(&digest("w")));
        stores.release_restore_pending(&digest("w"), end);
        assert!(!stores.restore_pending.contains_key(&digest("w")));
        assert_eq!(stores.retail_spent.len(), 1, "only the promoted key");
    }
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn p1_1_pending_overflow_reads_through_the_paced_full_and_never_evicts() {
    let (root, checkpoint, file) = grown("r7-p1-1-overflow");
    let sealed = checkpoint.sealed_offset();
    let cache = SharedCache::default();
    cache.durable_begin_pass(
        CLAUDE,
        &root.join("index.json"),
        &Scope("r7-ns".into()),
        false,
    );
    let begin = |key: &str, at| cache.begin_retail(CLAUDE, key, &checkpoint, &file, sealed, at);
    let now = Instant::now();
    for n in 0..RESTORE_PENDING_KEYS {
        begin(&format!("p{n}"), now).unwrap().finish();
    }
    assert!(matches!(begin("new", now), Err(RetailHold::AccountingLost)));
    {
        let stores = cache.durable().unwrap();
        assert_eq!(stores.counters.ineligible["retail_pending_overflow"], 1);
        assert!(!stores
            .counters
            .ineligible
            .contains_key("retail_pending_expired"));
        assert_eq!(stores.restore_pending.len(), RESTORE_PENDING_KEYS);
        assert!(
            stores.retail_spent.is_empty(),
            "overflow never takes custody"
        );
        let slot = stores.slots[DurableSource::ClaudeCode.slot()].as_ref();
        assert!(
            slot.is_some_and(|slot| slot.store.disabled().is_none()),
            "overflow never disables the store"
        );
    }
    // The caller's existing counted Full reads the grown file instead.
    assert!(cache.retail_full("new", &file, sealed, SystemTime::now()));
    // A day later the day-old grants are reclaimed, never a younger one.
    let later = begin("new", now + RETAIL_DAILY).unwrap();
    assert_eq!(later.grant(), RetailGrant::Process);
    later.finish();
    let stores = cache.durable().unwrap();
    assert_eq!(
        stores.counters.ineligible["retail_pending_expired"],
        RESTORE_PENDING_KEYS as u64
    );
    assert_eq!(stores.restore_pending.len(), 1);
    drop(stores);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn authorityless_custody_is_freed_and_authority_is_kept() {
    let root = crate::test_scratch::private_dir("r7-custody-free");
    let cache = SharedCache::default();
    let now = Instant::now();
    {
        let mut stores = cache.durable().unwrap();
        assert!(stores.fund_key(digest("idle")));
        assert!(stores.fund_key(digest("spent")));
        stores.retail_spent.get_mut(&digest("spent")).unwrap().spent = Some((1, now));
        stores.release_idle_custody(&digest("idle"));
        stores.release_idle_custody(&digest("spent"));
        assert!(!stores.retail_spent.contains_key(&digest("idle")));
        assert!(stores.retail_spent.contains_key(&digest("spent")));
        // A strict check funded mid-pass and left without a witness.
        assert!(stores.fund_key(digest("idle")));
    }
    cache.durable_begin_pass(
        CLAUDE,
        &root.join("index.json"),
        &Scope("r7-ns".into()),
        false,
    );
    let stores = cache.durable().unwrap();
    assert_eq!(stores.retail_spent.len(), 1);
    assert_eq!(stores.retail_spent[&digest("spent")].spent, Some((1, now)));
    drop(stores);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn debt_and_holds_live_outside_custody_and_overflow_stays_conservative() {
    use super::owed::OwedMark;
    let claude = DurableSource::ClaudeCode;
    let cache = SharedCache::default();
    let mut stores = cache.durable().unwrap();
    for n in 0..store::MAX_RECORDS {
        stores.set_owed(digest(&format!("d{n}")), OwedMark::Owed(claude));
    }
    assert!(stores.retail_spent.is_empty());
    assert_eq!(stores.key_debt.len(), store::MAX_RECORDS);
    assert!(!stores.owed_overflow[claude.slot()]);
    // No node is free: the source-wide conservative bit, never an eviction.
    stores.set_owed(digest("late"), OwedMark::Hold(claude));
    assert!(stores.owed_overflow[claude.slot()]);
    assert_eq!(stores.owed_mark(&digest("d0")), OwedMark::Owed(claude));
    assert_eq!(stores.counters.ineligible["key_debt_unfunded"], 1);
    // A discharged key frees its node.
    stores.clear_owed(digest("d0"));
    assert_eq!(stores.key_debt.len(), store::MAX_RECORDS - 1);
    stores.clear_source_owed(claude);
    assert!(stores.key_debt.is_empty());
    assert!(!stores.owed_overflow[claude.slot()]);
}

#[test]
fn pass_maps_follow_the_committed_index_and_count_overflow() {
    let root = crate::test_scratch::private_dir("r7-pass-maps");
    let cache = SharedCache::default();
    cache.durable_begin_pass(
        CLAUDE,
        &root.join("index.json"),
        &Scope("r7-ns".into()),
        false,
    );
    let scope = Scope("r7-file".into());
    let floor = 2 * store::MAX_RECORDS;
    for n in 0..floor {
        let key = format!("k{n}");
        cache.durable_note_scope(CLAUDE, &key, &scope);
        cache.durable_note_selection(&key, "fp");
        cache.durable_touch(&key);
    }
    let over = |cache: &SharedCache| {
        cache.durable_note_scope(CLAUDE, "over", &scope);
        cache.durable_note_selection("over", "fp");
        cache.durable_touch("over");
    };
    over(&cache);
    {
        let mut stores = cache.durable().unwrap();
        for map in ["decided", "selected", "touched"] {
            assert_eq!(
                stores.counters.ineligible[&*format!("pass_overflow.{map}")],
                1,
                "{map}"
            );
        }
        assert!(!stores.touched.contains("over"));
        // A large committed index sizes the same maps; nothing is dropped.
        let mut index = ScanIndex::default();
        for n in 0..1_000 {
            index.files.insert(format!("i{n}"), entry());
        }
        stores.note_indexed(DurableSource::ClaudeCode, &index);
    }
    over(&cache);
    let stores = cache.durable().unwrap();
    let slot = stores.slots[DurableSource::ClaudeCode.slot()]
        .as_ref()
        .unwrap();
    assert!(slot.decided.contains_key("over"));
    assert!(stores.touched.contains("over"));
    assert_eq!(stores.selected.get("over").map(String::as_str), Some("fp"));
    assert_eq!(stores.counters.ineligible["pass_overflow.touched"], 1);
    drop(stores);
    std::fs::remove_dir_all(root).unwrap();
}

fn certificate(path: &Path, scope: &Scope) -> DurableCertificate {
    let mut file = File::open(path).unwrap();
    let mut plan = ReadPlan::prepare(&mut file, None, scope, None, 1_800_000_000).unwrap();
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).unwrap();
    plan.observe_complete_records(&bytes).unwrap();
    plan.commit_after_native_completion(&file, scope, 1_800_000_000)
        .unwrap()
        .durable_certificate(birth_unix_nanos(&std::fs::metadata(path).unwrap()))
        .unwrap()
}

fn native_reduction(path: &Path, scope: &Scope) -> CachedJsonlReduction {
    let mut parser = OwnedJsonlParser::new(
        File::open(path).unwrap(),
        path,
        CLAUDE,
        apply_claude_code_line,
        None,
        None,
        None,
        false,
        true,
    )
    .unwrap();
    parser
        .prepare_acquisition(None, scope, None, 1_800_000_000)
        .unwrap();
    while !parser.step().unwrap() {}
    parser.durable_test_reduction_copy()
}

/// The production restore with the enabled workspace obligation: a pass
/// whose head budget cannot cover this extent refuses before content input
/// and counts it; the next pass's budget admits and charges the exact extent.
#[test]
#[cfg_attr(not(target_os = "macos"), ignore = "validated native decode layout")]
fn p2_restored_head_reread_is_bounded_per_pass_and_counted() {
    if !crate::test_isolation::run_here() {
        return;
    }
    assert!(crate::heap_layout_bound::layout_supported());
    let root = crate::test_scratch::ScratchDir::new("r7-p2-head");
    let path = root.join("source.jsonl");
    std::fs::write(
        &path,
        b"{\"type\":\"progress\",\"cwd\":\"/tmp/synthetic-workspace\"}\n",
    )
    .unwrap();
    let scope = Scope("r7-content".into());
    let body = codec::encode(
        &native_reduction(&path, &scope),
        store::BODY_BYTES,
        jsonl_line_cap() as u64,
    )
    .unwrap();
    let binding = store::tests::binding("account", "scope", ("fp-a", None));
    let expected = Expected {
        binding: binding.clone(),
        committed_generation: 1,
    };
    let record = store::DurableRecord {
        wire: None,
        envelope_audit_debt: None,
        format: store::FORMAT_VERSION,
        index_generation: 1,
        record: PendingRecord {
            acquisition: None,
            binding,
            certificate: certificate(&path, &scope),
            body,
            allowlist: codec::allowlist_digest(CLAUDE),
        },
    };
    let head = std::fs::metadata(&path).unwrap().len();
    let cache = SharedCache::default();
    let restore = || {
        let store::LeaseWait::Granted(mut lease) = cache.acquire_prepared_transfer(CLAUDE) else {
            panic!("owner")
        };
        let result = cache
            .durable_restore_record(
                CLAUDE,
                &record,
                &expected,
                &path,
                &scope,
                &mut File::open(&path).unwrap(),
                &mut lease,
            )
            .map(|(_, _, receipt)| receipt.head_bytes);
        lease.release();
        result
    };
    let slot = DurableSource::ClaudeCode.slot();
    cache.durable().unwrap().rederive_spent[slot] = REDERIVE_PASS_BYTES - head + 1;
    let before = rederive_head_bytes_total(CLAUDE);
    assert!(matches!(
        restore(),
        Err(Failure::Resource("rederive_budget"))
    ));
    assert_eq!(
        rederive_head_bytes_total(CLAUDE),
        before,
        "a refused restore reads no head byte"
    );
    assert_eq!(cache.durable().unwrap().counters.rederive_budget, [1, head]);
    assert_eq!(
        MissClass::Resource("rederive_budget").label(),
        "resource_full.rederive_budget"
    );
    cache.durable_begin_pass(
        CLAUDE,
        &root.join("index.json"),
        &Scope("r7-ns".into()),
        false,
    );
    assert_eq!(restore().ok(), Some(head));
    assert_eq!(cache.durable().unwrap().rederive_spent[slot], head);
    assert!(rederive_head_bytes_total(CLAUDE) - before >= head);
}

/// SOURCE cond. 5 carrier without a new field: a Codex selection cleared
/// over a record not proved absent (the D3 strict-rebind store is disabled)
/// counts a stale refusal and takes one paced Full under its own cause.
#[test]
fn codex_cleared_selection_over_a_surviving_record_is_refused_and_paced() {
    let root = crate::test_scratch::private_dir("r7-codex-stale-selection");
    let path = root.join("fixture.jsonl");
    std::fs::write(&path, b"{}\n").unwrap();
    let source = SnapshotSource::Codex;
    let key = "r7-codex-key".to_string();
    let namespace = Scope("r7-codex".into());
    let scope = Scope("r7-codex-file".into());
    let mut index = ScanIndex::default();
    index.files.insert(key.clone(), entry());
    index
        .files
        .get_mut(&key)
        .unwrap()
        .source_file_fingerprint
        .clear();
    let cache = SharedCache::default();
    cache.durable_begin_pass(source, &root.join("index.json"), &namespace, false);
    let attempt = || {
        let interpretation = Interpretation::of(source, &key, &index, false, &namespace);
        cache.durable_restore(
            source,
            &key,
            &path,
            &scope,
            &mut File::open(&path).unwrap(),
            &index,
            &interpretation,
        )
    };
    let label = |outcome: RestoreOutcome| match outcome {
        RestoreOutcome::Miss(class) => class.label(),
        RestoreOutcome::Pending => "pending",
        _ => panic!("expected a typed miss or pending"),
    };
    // Proved absent: the plain selection-clear Miss, no refusal.
    assert_eq!(label(attempt()), "ineligible.selection_cleared");
    cache
        .durable()
        .unwrap()
        .slot(DurableSource::Codex)
        .as_mut()
        .unwrap()
        .store
        .disable("r7_strict_rebind");
    assert_eq!(
        label(attempt()),
        "ineligible.selection_cleared.stale_record"
    );
    assert_eq!(
        label(attempt()),
        "ineligible.selection_cleared.stale_record",
        "a page deferral must not spend the Full permission"
    );
    assert!(cache.start_stale_selection_full(source, &key, &File::open(&path).unwrap()));
    assert_eq!(
        label(attempt()),
        "pending",
        "paced once per actual Full start"
    );
    let (counts, disk) = cache.durable_counters(source).unwrap();
    assert_eq!(disk.stale_record_refused, 3);
    assert_eq!(counts.ineligible["selection_cleared"], 4);
    assert_eq!(counts.ineligible["selection_cleared.stale_record_full"], 1);
    assert_eq!(
        counts.ineligible["selection_cleared.stale_record_full.paced"],
        1
    );
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn native_debt_reservation_refuses_before_io_and_preserves_every_funded_hold() {
    use super::owed::OwedMark;
    let cache = SharedCache::default();
    let mut stores = cache.durable().unwrap();
    for n in 0..store::MAX_RECORDS {
        let key = digest(&format!("reserved-{n}"));
        assert!(stores.fund_debt(key).is_some());
        stores.hold_key(key, Some(((1, n as u64 + 1, 3), 17)));
    }
    assert_eq!(stores.holds().count(), store::MAX_RECORDS);
    assert!(stores.fund_debt(digest("unstarted")).is_none());
    assert_eq!(stores.holds().count(), store::MAX_RECORDS);
    assert!(stores.owed_overflow.iter().all(|bit| !bit));
    assert!(stores.retail_spent.is_empty());
    assert_eq!(stores.counters.ineligible["key_debt_unfunded"], 1);
    assert_eq!(
        stores.counters.d3[super::write_ahead::D3_HOLD_UNFUNDED],
        0,
        "no unfunded hold created"
    );
    // Existing-key settlement always retains its reserved node at capacity.
    let key = digest("reserved-0");
    assert!(stores.fund_debt(key).is_some());
    stores.set_owed(key, OwedMark::Hold(DurableSource::ClaudeCode));
    assert!(stores.hold(&key).is_some());
}

#[test]
fn overflow_preserves_discovery_without_forcing_quiet_keys_to_parse() {
    use super::owed::{OwedMark, OwedQuery};
    let cache = SharedCache::default();
    {
        let mut stores = cache.durable().unwrap();
        for n in 0..store::MAX_RECORDS {
            stores.set_owed(
                digest(&format!("overflow-{n}")),
                OwedMark::Owed(DurableSource::Codex),
            );
        }
        stores.set_owed(digest("unfunded"), OwedMark::Hold(DurableSource::Codex));
        assert!(stores.owed_overflow[DurableSource::Codex.slot()]);
    }
    assert!(matches!(
        cache.owed_before_skip(SnapshotSource::Codex, "quiet-unrelated"),
        OwedQuery::None
    ));
    assert!(cache.owes_discovery(SnapshotSource::Codex, "quiet-unrelated"));
    assert!(cache.owes_discovery(SnapshotSource::Codex, "unfunded"));
}
