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
    for (index, body, _) in previous_pending(items, progress).into_values() {
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
    let result = upload_resumable_batches_with_body_witness_partitioned(
        items,
        &unique_poison_scope(),
        &mut progress,
        &mut accepted,
        |item| item.fingerprint.as_str(),
        |item| item.fingerprint.clone(),
        |_| None,
        |item| item.class,
        &mut InplaceRetryBudget::default(),
        |batch| {
            batches.push(batch.iter().map(|item| item.ordinal).collect());
            Ok(accepted_batch(batch.len()))
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
    assert_eq!(actual, vec![vec![0, 1], vec![20, 3], vec![4]]);

    let mut progress = test_upload_progress();
    progress
        .accepted_fingerprints
        .insert(items[1].fingerprint.clone());
    progress
        .accepted_body_witnesses
        .insert(items[1].fingerprint.clone(), items[1].fingerprint.clone());
    assert_eq!(
        assert_previous_oracle(&items, progress),
        vec![vec![1], vec![20, 3], vec![4]]
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
    let error = upload_resumable_batches_with_body_witness_partitioned(
        &[item],
        &unique_poison_scope(),
        &mut progress,
        &mut accepted,
        |item| item.fingerprint.as_str(),
        |item| item.fingerprint.clone(),
        |_| None,
        |_| false,
        &mut InplaceRetryBudget::default(),
        |_| {
            uploads += 1;
            Ok(accepted_batch(0))
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
