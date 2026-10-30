//! Portable helper controls; no layout-supported or macOS gate.
use super::*;
use crate::heap_layout_bound::HeapLayoutBound;
use std::fs::File;

const PROMPT: &str = "Inspect synthetic restore behavior";
const WORKSPACE: &str = "/synthetic/private-carried-workspace";

fn accumulator(source: SnapshotSource) -> SnapshotAccumulator {
    let mut acc = SnapshotAccumulator::new(source);
    acc.workspace_path = Some(PathBuf::from(WORKSPACE));
    acc.first_prompt_material = Some(PROMPT.to_owned());
    acc.first_prompt_title = first_prompt_display_title(source, PROMPT.to_owned());
    acc.durable_marks.workspace = Some(1);
    acc.durable_marks.first_prompt = Some(1);
    acc
}
fn decoded(acc: &SnapshotAccumulator) -> Decoded {
    Decoded {
        reduction: CachedJsonlReduction {
            accumulator: SnapshotAccumulator::new(acc.source),
            report: JsonlReadReport::default(),
            recognized_usage_drop_count: 0,
            positive_recognized_usage_count: 0,
            positive_usage_evidence: false,
        },
        rederive: Rederive {
            workspace: Some(workspace_digest(acc).unwrap()),
            first_prompt: Some(first_prompt_digest(acc).unwrap()),
            ..Default::default()
        },
    }
}
fn carried(acc: &SnapshotAccumulator) -> CarriedUploaded {
    CarriedUploaded::from_upload(
        acc,
        UploadedLiterals::from_wire(Some(WORKSPACE), Some(PROMPT)),
    )
    .unwrap()
}
fn roundtrip(value: &CarriedUploaded) -> CarriedUploaded {
    let bytes = Enc::count_write(8192, |e| value.put(e)).unwrap();
    let mut verify = Dec::new(&bytes);
    CarriedUploaded::verify(&mut verify).unwrap();
    verify.finish().unwrap();
    let mut allowance = |_| true;
    let mut d = Dec::bounded(&bytes, &mut allowance);
    let restored = CarriedUploaded::take(&mut d).unwrap();
    d.finish().unwrap();
    restored
}

#[test]
fn carried_pl_restores_same_fields_without_any_input() {
    for source in [
        SnapshotSource::Pi,
        SnapshotSource::ClaudeCode,
        SnapshotSource::Codex,
    ] {
        // Claude/Codex exercise only the shared helper: production remains None.
        let acc = accumulator(source);
        let carried = roundtrip(&carried(&acc));
        let decoded = decoded(&acc);
        let charge = decoded.content_charge(Some(&carried)).unwrap();
        assert!(charge > 0, "literal copies are funded, not input");
        let mut heap = crate::heap_layout_bound::Counter::new(8192);
        carried.heap_bound(&mut heap).unwrap();
        assert!(heap.bytes >= WORKSPACE.len() + PROMPT.len());
        // Empty source cannot satisfy either existing head-read obligation.
        let (restored, receipt) = decoded
            .rederive_content(&File::open("/dev/null").unwrap(), Some(&carried))
            .unwrap();
        assert_eq!(receipt, RederiveReceipt::default());
        assert_eq!(restored.accumulator.workspace_path, acc.workspace_path);
        assert_eq!(
            restored.accumulator.first_prompt_material,
            acc.first_prompt_material
        );
        assert_eq!(
            restored.accumulator.first_prompt_title,
            acc.first_prompt_title
        );
    }
}

#[test]
fn carried_pl_mismatch_is_counted_and_refuses_before_read() {
    let acc = accumulator(SnapshotSource::Pi);
    let good = carried(&acc);
    for field in 0..3 {
        let mut decoded = decoded(&acc);
        match field {
            0 => decoded.rederive.workspace = Some([0; 32]),
            1 => decoded.rederive.first_prompt = Some([0; 32]),
            _ => {
                // An exact material value with a different original title must
                // also refuse: the legacy H obligation covers BOTH fields.
                let mut different = accumulator(SnapshotSource::Pi);
                different.first_prompt_title = Some("Different synthetic title".into());
                decoded.rederive.first_prompt = Some(first_prompt_digest(&different).unwrap());
            }
        }
        decoded.content_charge(Some(&good)).unwrap();
        let before = MISMATCH[source_slot(acc.source)].load(Ordering::Relaxed);
        assert!(matches!(
            decoded.rederive_content(&File::open("/dev/null").unwrap(), Some(&good)),
            Err(Refuse::NotRederivable("carried_digest"))
        ));
        assert!(MISMATCH[source_slot(acc.source)].load(Ordering::Relaxed) > before);
    }
}

#[test]
fn carried_pl_absent_and_nonuploaded_values_keep_legacy_obligations() {
    let acc = accumulator(SnapshotSource::Pi);
    let absent =
        CarriedUploaded::from_upload(&acc, UploadedLiterals::from_wire(None, None)).unwrap();
    assert!(!absent.has_workspace() && !absent.has_prompt());
    assert!(decoded(&acc).content_charge(None).is_err());
    assert!(decoded(&acc).content_charge(Some(&absent)).is_err());
    let changed = CarriedUploaded::from_upload(
        &acc,
        UploadedLiterals::from_wire(Some("redacted"), Some("Inspect")),
    )
    .unwrap();
    assert!(
        !changed.has_workspace() && !changed.has_prompt(),
        "never copy more than wire"
    );
    assert!(decoded(&acc).content_charge(Some(&changed)).is_err());
    // No upload -> no producer obligation. A carried value must never invent
    // a field where the consent-filtered record has no obligation.
    let mut none = decoded(&acc);
    none.rederive = Rederive::default();
    let (restored, receipt) = none
        .rederive_content(&File::open("/dev/null").unwrap(), Some(&carried(&acc)))
        .unwrap();
    assert!(restored.accumulator.workspace_path.is_none());
    assert!(restored.accumulator.first_prompt_material.is_none());
    assert_eq!(receipt, RederiveReceipt::default());
}

#[test]
fn carried_pl_purge_is_idempotent_counted_and_cannot_restore_old_literals() {
    let acc = accumulator(SnapshotSource::Pi);
    let mut literals = carried(&acc);
    let before = PURGED[source_slot(acc.source)].load(Ordering::Relaxed);
    assert!(literals.purge_carried_literals(acc.source));
    assert!(PURGED[source_slot(acc.source)].load(Ordering::Relaxed) > before);
    assert!(!literals.purge_carried_literals(acc.source));
    let purged = roundtrip(&literals);
    assert!(!purged.has_workspace() && !purged.has_prompt());
    // Stale obligations are not silently excused and cannot recover a prompt.
    assert!(decoded(&acc).content_charge(Some(&purged)).is_err());
    let mut next_save = decoded(&acc);
    next_save.rederive = Rederive::default(); // producer's consent-filtered save
    let (restored, receipt) = next_save
        .rederive_content(&File::open("/dev/null").unwrap(), Some(&purged))
        .unwrap();
    assert!(restored.accumulator.first_prompt_material.is_none());
    assert!(restored.accumulator.workspace_path.is_none());
    assert_eq!(receipt, RederiveReceipt::default());
}

#[test]
fn carried_pl_debug_exposes_lengths_only_and_shared_pins_have_no_pl_section() {
    let acc = accumulator(SnapshotSource::Pi);
    let debug = format!("{:?}", carried(&acc));
    assert!(!debug.contains(PROMPT) && !debug.contains(WORKSPACE));
    assert!(!debug.contains("Inspect") && !debug.contains("synthetic"));
    assert!(debug.contains("workspace_bytes") && debug.contains("first_prompt_bytes"));
    assert!(
        !shape_text().contains("CarriedUploaded"),
        "A_C/A_X do not reach this codec"
    );
    let mut shape = Shape::default();
    CarriedUploaded::shape(&mut shape);
    assert!(shape.text().contains("PL workspace"));
    assert!(shape.text().contains("PL first_prompt"));
    assert!(!shape.text().contains(PROMPT) && !shape.text().contains(WORKSPACE));
}

#[test]
fn carried_pl_decode_checks_both_byte_caps_before_any_allocation() {
    for (workspace, cap) in [(true, WORKSPACE_CAP), (false, FIRST_PROMPT_CAP)] {
        for size in [cap, cap + 1] {
            let text = "x".repeat(size);
            let mut e = Enc::bytes(cap + 32);
            if !workspace {
                e.varint(0).unwrap();
            }
            e.varint(1).unwrap();
            e.len_prefixed(text.as_bytes()).unwrap();
            if workspace {
                e.varint(0).unwrap();
            }
            let bytes = e.into_bytes();
            let mut verify = Dec::new(&bytes);
            assert_eq!(CarriedUploaded::verify(&mut verify).is_ok(), size == cap);
            let mut charges = 0;
            let mut allowance = |n| {
                charges += n;
                true
            };
            let mut d = Dec::bounded(&bytes, &mut allowance);
            let result = CarriedUploaded::take(&mut d);
            assert_eq!(result.is_ok(), size == cap);
            if size > cap {
                assert_eq!(charges, 0, "over-cap never allocates");
            } else {
                assert_eq!(charges, size as u64);
            }
        }
    }
    // Bounds count UTF-8 bytes, never characters or lossy/truncated prefixes.
    let mut acc = accumulator(SnapshotSource::Pi);
    acc.first_prompt_material = Some("é".repeat(FIRST_PROMPT_CAP / 2 + 1));
    assert!(matches!(
        CarriedUploaded::from_upload(
            &acc,
            UploadedLiterals::from_wire(None, acc.first_prompt_material.as_deref())
        ),
        Err(Refuse::TooLarge)
    ));
    let mut denied = |_| false;
    let bytes =
        Enc::count_write(8192, |e| carried(&accumulator(SnapshotSource::Pi)).put(e)).unwrap();
    let mut d = Dec::bounded(&bytes, &mut denied);
    let result = CarriedUploaded::take(&mut d);
    assert!(matches!(
        d.outcome(result),
        Err(crate::durable_tail_codec::DecodeFailure::Budget)
    ));
    // A path cannot accidentally become persisted through the ordinary codec.
    assert!(PathBuf::from(WORKSPACE).put(&mut Enc::bytes(8192)).is_err());
}
