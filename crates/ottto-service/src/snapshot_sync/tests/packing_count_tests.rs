use serde_json::{json, Value};
use std::io::Write;

#[derive(Clone, Serialize)]
struct PackingItem {
    fingerprint: String,
    payload: Value,
    ordinal: usize,
    #[serde(skip)]
    class: bool,
}

fn item(ordinal: usize, payload: Value, class: bool) -> PackingItem {
    PackingItem {
        fingerprint: format!("{ordinal:064x}"),
        payload,
        ordinal,
        class,
    }
}

// Frozen buffer-based packing from the previous main implementation. Keep its
// serialization and retained bodies independent of the counting writer under
// test. Actual upload callbacks below are compared with this old-path oracle.
type PreviousPending = BTreeMap<String, (usize, Vec<u8>, String)>;

fn previous_pending(items: &[PackingItem], progress: &SnapshotUploadProgress) -> PreviousPending {
    let mut pending = BTreeMap::new();
    for (index, item) in items.iter().enumerate() {
        let witness = item.fingerprint.clone();
        if progress.contains_body(&item.fingerprint, &witness) {
            continue;
        }
        if let std::collections::btree_map::Entry::Vacant(entry) =
            pending.entry(item.fingerprint.clone())
        {
            entry.insert((index, serde_json::to_vec(item).unwrap(), witness));
        }
    }
    pending
}

fn previous_batches(items: &[PackingItem], progress: &SnapshotUploadProgress) -> Vec<Vec<usize>> {
    let mut batches = Vec::new();
    let mut batch = Vec::new();
    let mut bytes = 2usize;
    let mut class = None;
    // Bodies are grouped by request class (stable within a class) before the
    // count and byte cuts, so each class travels in its own requests.
    let mut pending = previous_pending(items, progress)
        .into_values()
        .collect::<Vec<_>>();
    pending.sort_by_key(|(index, _, _)| items[*index].class);
    for (index, body, _) in pending {
        let item_bytes = body.len().saturating_add(1);
        let item_class = items[index].class;
        if !batch.is_empty()
            && (batch.len() == SNAPSHOT_BATCH_LIMIT
                || bytes.saturating_add(item_bytes) > SNAPSHOT_BATCH_MAX_BYTES
                || class != Some(item_class))
        {
            batches.push(std::mem::take(&mut batch));
            bytes = 2;
        }
        class = Some(item_class);
        batch.push(items[index].ordinal);
        bytes = bytes.saturating_add(item_bytes);
    }
    if !batch.is_empty() {
        batches.push(batch);
    }
    batches
}

fn actual_batches(
    items: &[PackingItem],
    mut progress: SnapshotUploadProgress,
) -> (Vec<Vec<usize>>, u64) {
    let mut batches = Vec::new();
    let mut accepted = 0;
    let result = upload_resumable_batches_with_literal_families(
        items,
        &unique_poison_scope(),
        &mut progress,
        &mut accepted,
        |item| item.fingerprint.as_str(),
        |item| item.fingerprint.clone(),
        |_| None,
        |item| u8::from(item.class),
        |_| None,
        &mut InplaceRetryBudget::default(),
        |batch| {
            batches.push(batch.iter().map(|item| item.ordinal).collect());
            Ok(accept_batch_with(batch, |item| item.fingerprint.as_str()))
        },
        |_| Ok(()),
    )
    .unwrap();
    assert_eq!(result, ResumableUploadResult::Completed);
    (batches, accepted)
}

fn assert_previous_oracle(
    items: &[PackingItem],
    progress: SnapshotUploadProgress,
) -> Vec<Vec<usize>> {
    let expected = previous_batches(items, &progress);
    let (actual, accepted) = actual_batches(items, progress);
    assert_eq!(actual, expected);
    assert_eq!(accepted, actual.iter().map(Vec::len).sum::<usize>() as u64);
    actual
}

#[test]
fn snapshot_packing_count_matches_json_oracle_and_actual_duplicate_class_uploads() {
    let nested = json!({
        "control": "\u{0}\n\r\t\"\\",
        "unicode": "שלום 🦀 café \u{2028}",
        "nested": [null, true, -123, 3.25, {"escaped/key": ["a", "b"]}]
    });
    for payload in [
        nested.clone(),
        json!(""),
        json!([]),
        json!({}),
        json!(1e100),
    ] {
        let value = item(0, payload, false);
        let (counted, allocation) = crate::retry_allocation_probe::measure(|| {
            snapshot_packing_json_length(&value).unwrap()
        });
        assert_eq!(counted, serde_json::to_vec(&value).unwrap().len());
        assert_eq!(allocation.allocations, 0);
    }
    let mut first = item(2, nested, true);
    first.ordinal = 20;
    let mut duplicate = first.clone();
    duplicate.ordinal = 200;
    duplicate.payload = json!("observation-only difference".repeat(100));
    let items = vec![
        first,
        item(0, json!("first by fingerprint"), false),
        duplicate,
        item(1, json!([1, 2, 3]), false),
        item(3, json!(false), true),
        item(4, json!(null), false),
    ];
    let actual = assert_previous_oracle(&items, test_upload_progress());
    assert_eq!(actual, vec![vec![0, 1, 4], vec![20, 3]]);

    let mut progress = test_upload_progress();
    progress
        .accepted_fingerprints
        .insert(items[1].fingerprint.clone());
    progress
        .accepted_body_witnesses
        .insert(items[1].fingerprint.clone(), items[1].fingerprint.clone());
    assert_eq!(
        assert_previous_oracle(&items, progress),
        vec![vec![1, 4], vec![20, 3]]
    );
    assert!(assert_previous_oracle(&[], test_upload_progress()).is_empty());
}

#[test]
fn snapshot_packing_count_preserves_exact_byte_count_and_oversize_boundaries() {
    let mut first = item(0, json!(""), false);
    let second = item(1, json!("small"), false);
    let empty_first_size = serde_json::to_vec(&first).unwrap().len();
    let second_size = serde_json::to_vec(&second).unwrap().len();
    let exact_payload_size = SNAPSHOT_BATCH_MAX_BYTES - 2 - 2 - empty_first_size - second_size;
    first.payload = json!("x".repeat(exact_payload_size));
    assert_eq!(
        2 + serde_json::to_vec(&first).unwrap().len() + 1 + second_size + 1,
        SNAPSHOT_BATCH_MAX_BYTES
    );
    assert_eq!(
        assert_previous_oracle(&[first.clone(), second.clone()], test_upload_progress()),
        vec![vec![0, 1]]
    );
    first.payload = json!("x".repeat(exact_payload_size + 1));
    assert_eq!(
        assert_previous_oracle(&[first.clone(), second.clone()], test_upload_progress()),
        vec![vec![0], vec![1]]
    );
    first.payload = json!("x".repeat(SNAPSHOT_BATCH_MAX_BYTES + 1));
    assert_eq!(
        assert_previous_oracle(&[first, second], test_upload_progress()),
        vec![vec![0], vec![1]]
    );

    let items = (0..51)
        .rev()
        .map(|n| item(n, json!("tiny"), false))
        .collect::<Vec<_>>();
    let batches = assert_previous_oracle(&items, test_upload_progress());
    assert_eq!(batches, vec![(0..50).collect::<Vec<_>>(), vec![50]]);
    assert_eq!(SNAPSHOT_BATCH_LIMIT, 50);
}

/// [behaviour] A receiver-sized 3 MiB item exceeds the packing target, passes
/// the unchanged 4 MiB wire bound and ships alone between small items.
#[test]
fn advertised_cap_single_item_ships_alone() {
    let mut large = item(1, json!(""), false);
    let framing = serde_json::to_vec(&large).unwrap().len();
    large.payload = json!("x".repeat(3_145_728 - framing));
    assert_eq!(serde_json::to_vec(&large).unwrap().len(), 3_145_728);
    assert!(
        serde_json::to_vec(&large).unwrap().len() < crate::snapshots::MAX_SNAPSHOT_BATCH_WIRE_BYTES
    );
    let (batches, accepted) = actual_batches(
        &[
            item(0, json!("before"), false),
            large,
            item(2, json!("after"), false),
        ],
        test_upload_progress(),
    );
    assert_eq!(batches, vec![vec![0], vec![1], vec![2]]);
    assert_eq!(accepted, 3);
}

#[derive(Clone)]
struct FailingPackingItem {
    fingerprint: String,
    prefix: String,
}
impl Serialize for FailingPackingItem {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("FailingPackingItem", 2)?;
        state.serialize_field("prefix", &self.prefix)?;
        Err(serde::ser::Error::custom("synthetic failure after prefix"))
    }
}

#[test]
fn snapshot_packing_count_serialization_failure_keeps_local_error_and_no_upload() {
    // Failure after an oversize prefix must not be hidden by an early size cap.
    let item = FailingPackingItem {
        fingerprint: "f".repeat(64),
        prefix: "x".repeat(SNAPSHOT_BATCH_MAX_BYTES + 1),
    };
    assert!(serde_json::to_vec(&item).is_err());
    assert!(snapshot_packing_json_length(&item).is_err());
    let mut progress = test_upload_progress();
    let before = serde_json::to_vec(&progress).unwrap();
    let mut accepted = 0;
    let mut uploads = 0;
    let mut saves = 0;
    let error = upload_resumable_batches_with_literal_families(
        &[item],
        &unique_poison_scope(),
        &mut progress,
        &mut accepted,
        |item| item.fingerprint.as_str(),
        |item| item.fingerprint.clone(),
        |_| None,
        |_| 0,
        |_| None,
        &mut InplaceRetryBudget::default(),
        |_| {
            uploads += 1;
            panic!("oversize projection must not be uploaded")
        },
        |_| {
            saves += 1;
            Ok(())
        },
    )
    .unwrap_err();
    assert_eq!(
        error
            .downcast_ref::<SnapshotLocalStateRejected>()
            .unwrap()
            .operation,
        "serialize snapshot for batch packing"
    );
    assert_eq!(
        snapshot_upload_error_class(&error),
        Some(SnapshotUploadErrorClass::LocalState)
    );
    assert_eq!((uploads, saves, accepted), (0, 0, 0));
    assert_eq!(serde_json::to_vec(&progress).unwrap(), before);
}

#[test]
fn snapshot_packing_count_refuses_length_overflow_without_wrapping() {
    let mut length = SnapshotPackingLength {
        bytes: usize::MAX - 1,
    };
    assert_eq!(length.write(b"x").unwrap(), 1);
    assert_eq!(length.bytes, usize::MAX);
    assert_eq!(
        length.write(b"x").unwrap_err().kind(),
        std::io::ErrorKind::InvalidData
    );
    assert_eq!(length.bytes, usize::MAX);
    assert_eq!(length.write(&[]).unwrap(), 0);
}

// ---- counted request positions at the item cap ------------------------------

fn counted_request(snapshots: Vec<&SnapshotItem>) -> SnapshotBatchRequest<&SnapshotItem> {
    crate::snapshot_sync::upload::snapshot_batch_request(
        SnapshotSource::Codex,
        "machine",
        snapshots,
        SnapshotUploadPolicy::default(),
        crate::client_report::ClientReport::empty(),
    )
}

/// Each body's wire bytes in `request`, its semantic envelope included: what
/// the item preflight measures.
fn counted_wire_sizes(request: &SnapshotBatchRequest<&SnapshotItem>) -> Vec<usize> {
    let wire = serde_json::to_value(request).unwrap();
    wire["snapshots"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| serde_json::to_vec(item).unwrap().len())
        .collect()
}

/// The Codex cache fixture body, with or without its cache patch and with no
/// counted request position, padded to `room` wire bytes under the item cap.
fn counted_cap_body(cache: bool, room: usize) -> SnapshotItem {
    let cap = crate::snapshots::MAX_SNAPSHOT_ITEM_WIRE_BYTES;
    let mut item = crate::snapshots::cache_adapter_tests::cache_fixture_item();
    assert!(item
        .cache_observations
        .as_ref()
        .is_some_and(|patch| !patch.operations.is_empty()));
    if !cache {
        item.cache_observations = None;
    }
    crate::snapshots::clear_counted_request_positions(&mut item);
    let pad = |item: &mut SnapshotItem, chars: usize| {
        item.session_display_name = Some("x".repeat(chars));
        item.snapshot_fingerprint =
            crate::snapshots::snapshot_fingerprint(SnapshotSource::Codex, item);
        counted_wire_sizes(&counted_request(vec![&*item]))[0]
    };
    let bare = pad(&mut item, 0);
    assert_eq!(pad(&mut item, cap - room - bare), cap - room);
    item
}

/// `item` with a counted request total 45 wire bytes wide.
fn with_counted_total(item: &SnapshotItem) -> SnapshotItem {
    let mut item = item.clone();
    item.context_request_count = Some(u64::MAX);
    item
}

/// The ledger a pass leaves: ACKs, witnesses and every owed or held body.
fn counted_ledger(progress: &SnapshotUploadProgress) -> Value {
    json!({
        "accepted": progress.accepted_fingerprints,
        "witnesses": progress.accepted_body_witnesses,
        "cache_states": progress.accepted_cache_states,
        "pending_cache_heads": progress.pending_cache_heads,
        "quarantined": progress.quarantined_fingerprints,
        "permanent": progress.permanent_rejections,
    })
}

/// One pass over `items` through the real selector, packer and ACK
/// settlement, each POST behind the production item preflight: the bodies
/// each POST sent, and the ledger after.
fn counted_pass(
    items: &[SnapshotItem],
    mut progress: SnapshotUploadProgress,
) -> (Vec<Vec<SnapshotItem>>, SnapshotUploadProgress) {
    let cap = crate::snapshots::MAX_SNAPSHOT_ITEM_WIRE_BYTES;
    let mut posts = Vec::new();
    let mut accepted = 0;
    let result = upload_resumable_batches_with_literal_families(
        items,
        &unique_poison_scope(),
        &mut progress,
        &mut accepted,
        |item| item.snapshot_fingerprint.as_str(),
        snapshot_upload_body_witness,
        |_| None,
        |_| 0,
        |_| None,
        &mut InplaceRetryBudget::default(),
        |batch| {
            let request = counted_request(batch.to_vec());
            crate::snapshot_sync::upload::preflight_snapshot_request(&request, cap, |sent, _| {
                // The bytes the POST carries: every body within the cap.
                assert!(counted_wire_sizes(sent).iter().all(|bytes| *bytes <= cap));
                posts.push(sent.snapshots.iter().copied().cloned().collect());
                Ok(accept_batch_with(batch, |item| item.snapshot_fingerprint.as_str()))
            })
        },
        |_| Ok(()),
    )
    .unwrap();
    assert_eq!(result, ResumableUploadResult::Completed);
    (posts, progress)
}

/// [money] [behaviour] Through the real selector, packer and item preflight,
/// for a Codex body with and without a cache patch that fits the item cap
/// only without its counted request positions: one POST sends it without
/// them and otherwise unchanged (cache patch, fingerprint, witness), a small
/// sibling in the same POST keeps its positions, and the ledger is the one
/// the undecorated bodies leave. A body accepted before and now decorated
/// only with positions is not offered at all.
#[test]
fn counted_positions_at_the_item_cap_never_refuse_or_offer() {
    let cap = crate::snapshots::MAX_SNAPSHOT_ITEM_WIRE_BYTES;
    for (label, cache) in [("cache patch", true), ("no cache patch", false)] {
        let plain = counted_cap_body(cache, 16);
        let charted = with_counted_total(&plain);
        assert_eq!(
            crate::snapshots::snapshot_fingerprint(SnapshotSource::Codex, &charted),
            plain.snapshot_fingerprint,
            "{label}: positions stay outside the fingerprint"
        );
        let refused = |item: &SnapshotItem| {
            let request = counted_request(vec![item]);
            crate::snapshots::snapshot_items_refused_at(&request, cap, |_| true)
        };
        assert!(refused(&plain).is_empty(), "{label}");
        assert_eq!(refused(&charted), [0], "{label}: only the positions cross");
        let mut sibling = crate::snapshots::cache_adapter_tests::cache_fixture_item();
        sibling.source_session_id = "00000000-0000-7000-8000-000000000002".into();
        sibling.snapshot_fingerprint =
            crate::snapshots::snapshot_fingerprint(SnapshotSource::Codex, &sibling);
        let small = with_counted_total(&sibling);

        let (plain_posts, plain_ledger) =
            counted_pass(&[plain.clone(), sibling.clone()], test_upload_progress());
        let (posts, ledger) =
            counted_pass(&[charted.clone(), small.clone()], test_upload_progress());
        assert_eq!(plain_posts.len(), 1, "{label}");
        assert_eq!(posts.len(), 1, "{label}: one POST, no refusal");
        let sent = |fingerprint: &str| {
            posts[0]
                .iter()
                .find(|item| item.snapshot_fingerprint == fingerprint)
                .unwrap()
                .clone()
        };
        let big = sent(&plain.snapshot_fingerprint);
        assert!(!crate::snapshots::has_counted_request_positions(&big), "{label}");
        assert_eq!(
            serde_json::to_value(&big).unwrap(),
            serde_json::to_value(&plain).unwrap(),
            "{label}: every other byte stays"
        );
        assert_eq!(big.cache_observations.is_some(), cache, "{label}");
        assert_eq!(
            snapshot_upload_body_witness(&big),
            snapshot_upload_body_witness(&charted),
            "{label}"
        );
        assert_eq!(
            sent(&sibling.snapshot_fingerprint).context_request_count,
            Some(u64::MAX),
            "{label}: a body under the cap keeps its positions"
        );
        assert_eq!(
            counted_ledger(&ledger),
            counted_ledger(&plain_ledger),
            "{label}"
        );

        // Accepted before; decorated only with positions now: no offer.
        let (posts, again) = counted_pass(&[charted, small], plain_ledger.clone());
        assert!(posts.is_empty(), "{label}");
        assert_eq!(
            counted_ledger(&again),
            counted_ledger(&plain_ledger),
            "{label}"
        );
    }
}

/// [behaviour] A body over the item cap even without its counted request
/// positions is still refused at the preflight and never sent.
#[test]
fn counted_positions_never_hide_an_item_cap_refusal() {
    let cap = crate::snapshots::MAX_SNAPSHOT_ITEM_WIRE_BYTES;
    let mut over = with_counted_total(&counted_cap_body(true, 0));
    let title = over.session_display_name.take().unwrap_or_default();
    over.session_display_name = Some(title + &"x".repeat(64));
    over.snapshot_fingerprint =
        crate::snapshots::snapshot_fingerprint(SnapshotSource::Codex, &over);
    let request = counted_request(vec![&over]);
    let send = |_: &SnapshotBatchRequest<&SnapshotItem>, _: usize| -> Result<()> {
        panic!("a refused body was sent")
    };
    let error =
        crate::snapshot_sync::upload::preflight_snapshot_request(&request, cap, send).unwrap_err();
    assert!(error
        .downcast_ref::<crate::snapshot_sync::upload::SnapshotBatchPreflightRejected>()
        .is_some());
}
