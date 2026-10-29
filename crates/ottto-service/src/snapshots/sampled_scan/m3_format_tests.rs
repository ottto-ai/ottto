//! Format envelope tests use the production writer, classifier, reader and GC.
//! These are separate from genuine archived-old-writer and native money fixtures.
use super::*;
use crate::durable_tail_store::{
    self as store, AcquisitionFields, Binding, DurableSource, PendingRecord, ReadOutcome, Refusal,
};
use crate::locked_state_dir::test_locks;
use crate::snapshots::{AcquisitionProtocol, ImmutableCounting};
use crate::transcript_acquisition::{birth_unix_nanos, DurableCertificate, ReadPlan};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::File;
use std::io::Read;
use std::path::Path;

fn certificate(path: &Path) -> DurableCertificate {
    let scope = Scope("m3-format-fixture".into());
    let mut file = File::open(path).unwrap();
    let mut plan = ReadPlan::prepare(&mut file, None, &scope, None, 1_800_000_000).unwrap();
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).unwrap();
    plan.observe_complete_records(&bytes).unwrap();
    plan.commit_after_native_completion(&file, &scope, 1_800_000_000)
        .unwrap()
        .durable_certificate(birth_unix_nanos(&file.metadata().unwrap()))
        .unwrap()
}
fn pending(
    source: DurableSource,
    key: &str,
    certificate: &DurableCertificate,
    v3: bool,
) -> PendingRecord {
    PendingRecord {
        binding: Binding {
            source,
            key: store::key_digest(source, key),
            context: store::context_digest("m3-format-tests", None),
            scope: [7; 32],
            entry: if v3 {
                [0; 32]
            } else {
                store::entry_digest("v1-fp", Some("v1-body"))
            },
        },
        certificate: certificate.clone(),
        body: crate::snapshots::durable_store_fixture_body(source.properties().snapshot, 9, 63),
        allowlist: source.properties().allowlist(),
        acquisition: v3.then_some(AcquisitionFields {
            acquired_revision: 17,
            protocol: AcquisitionProtocol::Legacy,
        }),
    }
}
fn path(dir: &Path, key: &store::Digest32) -> std::path::PathBuf {
    let hex: String = key.iter().map(|b| format!("{b:02x}")).collect();
    dir.join(format!("{hex}.rec"))
}
fn found(outcome: ReadOutcome) -> store::DurableRecord {
    match outcome {
        ReadOutcome::Found(record) => *record,
        other => panic!("expected real disk restore: {other:?}"),
    }
}
fn resign(bytes: &mut [u8]) {
    let end = bytes.len() - 32;
    let trailer = Sha256::digest(&bytes[..end]);
    bytes[end..].copy_from_slice(&trailer);
}

#[test]
fn m3_p4a_source_table_admits_exact_triples_without_repinning_body() {
    let rows = crate::snapshots::durable_sources::SOURCES;
    assert_eq!(rows.len(), 2);
    for (slot, row) in rows.iter().enumerate() {
        assert_eq!(row.source.slot(), slot);
        assert_eq!(row.tag as usize, slot + 1);
        assert_eq!(
            row.write_format, 1,
            "P4a preserves the original writer until native activation"
        );
        assert_eq!(row.representations.len(), 2);
        let pin = row.allowlist();
        assert_eq!(
            row.representation(1, &pin).unwrap().header_bytes,
            store::HEADER_BYTES
        );
        assert_eq!(
            row.representation(3, &pin).unwrap().header_bytes,
            store::HEADER_V3_BYTES
        );
        assert!(row.representation(2, &pin).is_none());
        assert!(row.representation(4, &pin).is_none());
        assert!(row.representation(3, &[0; 32]).is_none());
        assert_eq!(
            row.representation(1, &pin).unwrap().allowlist_pin,
            row.representation(3, &pin).unwrap().allowlist_pin
        );
    }
}

#[test]
fn m3_p4a_wire_offsets_generation_and_mixed_restart_twice() {
    let root = crate::test_scratch::private_dir("ottto-m3-mixed-envelope");
    let lock = test_locks::hold(&root);
    let transcript = root.join("fixture.jsonl");
    std::fs::write(&transcript, b"{\"n\":1}\n").unwrap();
    let cert = certificate(&transcript);
    for row in crate::snapshots::durable_sources::SOURCES {
        let dir = root.join(row.snapshot.api_slug());
        let mut store = store::DurableTailStore::new(dir.clone(), row.source);
        let old = pending(row.source, "v1", &cert, false);
        let new = pending(row.source, "v3", &cert, true);
        let old_key = old.binding.key;
        let new_key = new.binding.key;
        let body = new.body.clone();
        let old_len = old.body.len() + store::HEADER_BYTES + 32;
        let new_len = body.len() + store::HEADER_V3_BYTES + 32;
        let receipt = store.write_after_save(lock, 81, 0, vec![old, new]).unwrap();
        assert_eq!(receipt.written, 2);
        let old_wire = std::fs::read(path(&dir, &old_key)).unwrap();
        let new_wire = std::fs::read(path(&dir, &new_key)).unwrap();
        assert_eq!(old_wire.len(), old_len);
        assert_eq!(new_wire.len(), new_len);
        assert_eq!(&new_wire[8..10], &3u16.to_le_bytes());
        assert_eq!(&new_wire[43..75], &new_key);
        assert_eq!(&new_wire[139..171], &[0; 32]);
        assert_eq!(&new_wire[171..179], &81u64.to_le_bytes());
        assert_eq!(&new_wire[179..187], &17u64.to_le_bytes());
        assert_eq!(new_wire[187], 0);
        assert_eq!(
            &new_wire[store::HEADER_V3_BYTES..new_wire.len() - 32],
            &body
        );
        let keep = BTreeMap::from([(old_key, None), (new_key, None)]);
        let context = store::context_digest("m3-format-tests", None);
        for _ in 0..2 {
            drop(store);
            store = store::DurableTailStore::new(dir.clone(), row.source);
            let mut records = Vec::new();
            for key in [old_key, new_key] {
                let record = found(store.read(&key));
                assert!(!record.record.body.is_empty());
                assert!(record.wire.is_some());
                let expected = store::Expected {
                    binding: record.record.binding.clone(),
                    committed_generation: 0,
                };
                if key == new_key {
                    assert_eq!(record.format, 3);
                    assert_eq!(record.record.acquisition.unwrap().acquired_revision, 17);
                    assert!(record.eligible(&expected).is_ok());
                    for generation in [0, 81, 999] {
                        let expected = store::Expected {
                            binding: record.record.binding.clone(),
                            committed_generation: generation,
                        };
                        assert!(record.eligible(&expected).is_ok());
                        store.authorize(&record, &expected);
                    }
                } else {
                    assert_eq!(record.format, 1);
                    assert!(record.record.acquisition.is_none());
                    store.authorize(
                        &record,
                        &store::Expected {
                            binding: record.record.binding.clone(),
                            committed_generation: 81,
                        },
                    );
                }
                records.push(record);
            }
            let before = store.counters().gc_bytes_read;
            store.gc(lock, &context, &keep).unwrap();
            assert_eq!(
                store.counters().gc_bytes_read - before,
                (store::HEADER_BYTES + store::HEADER_V3_BYTES) as u64
            );
            assert_eq!(std::fs::read(path(&dir, &old_key)).unwrap(), old_wire);
            assert_eq!(std::fs::read(path(&dir, &new_key)).unwrap(), new_wire);
            assert_eq!(records.len(), 2);
        }
    }
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn m3_p4a_v3_dispatch_lengths_and_unknown_survivors() {
    let root = crate::test_scratch::private_dir("ottto-m3-dispatch");
    let lock = test_locks::hold(&root);
    let transcript = root.join("fixture.jsonl");
    std::fs::write(&transcript, b"{\"n\":1}\n").unwrap();
    let cert = certificate(&transcript);
    for row in crate::snapshots::durable_sources::SOURCES {
        let dir = root.join(row.snapshot.api_slug());
        let record = pending(row.source, "v3", &cert, true);
        let key = record.binding.key;
        let file = path(&dir, &key);
        let mut store = store::DurableTailStore::new(dir.clone(), row.source);
        assert_eq!(
            store
                .write_after_save(lock, 2, 0, vec![record])
                .unwrap()
                .written,
            1
        );
        let original = std::fs::read(&file).unwrap();
        for (at, byte, expected) in [
            (187, 2, Refusal::Corrupt),
            (139, 1, Refusal::Corrupt),
            (10, 0, Refusal::Unknown),
            (8, 2, Refusal::Unknown),
            (8, 4, Refusal::NewerFormat),
            (42, 99, Refusal::Unknown),
        ] {
            let mut changed = original.clone();
            changed[at] = byte;
            resign(&mut changed);
            std::fs::write(&file, &changed).unwrap();
            let mut cold = store::DurableTailStore::new(dir.clone(), row.source);
            assert_eq!(cold.read(&key), ReadOutcome::Refused(expected));
            if expected != Refusal::Corrupt {
                cold.gc(lock, &[0; 32], &BTreeMap::new()).unwrap();
                assert_eq!(std::fs::read(&file).unwrap(), changed);
            }
        }
        for end in [43, 179, 180, 187, store::HEADER_V3_BYTES - 1] {
            std::fs::write(&file, &original[..end]).unwrap();
            let mut cold = store::DurableTailStore::new(dir.clone(), row.source);
            assert_eq!(cold.read(&key), ReadOutcome::Refused(Refusal::Corrupt));
        }
        let mut future = original.clone();
        future[8..10].copy_from_slice(&4u16.to_le_bytes());
        future.resize(store::RECORD_BYTES + store::HEADER_V3_BYTES + 33, 0);
        std::fs::write(&file, &future).unwrap();
        let mut cold = store::DurableTailStore::new(dir.clone(), row.source);
        assert_eq!(cold.read(&key), ReadOutcome::Refused(Refusal::NewerFormat));
        assert_eq!(cold.counters().guard_header_bytes, 43);
        cold.gc(lock, &[0; 32], &BTreeMap::new()).unwrap();
        assert_eq!(std::fs::read(&file).unwrap(), future);
    }
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn m3_p4a_scope_formula_uses_canonical_counting_and_distinct_domain() {
    let acc = SnapshotAccumulator::new(SnapshotSource::ClaudeCode);
    let c = ImmutableCounting::from_accumulator(&acc).unwrap();
    let allowlist = DurableSource::ClaudeCode.properties().allowlist();
    let v3 = store::scope_digest_v3("F", &allowlist, "identity", c.bytes());
    assert_ne!(
        v3,
        store::scope_digest_for(1, "F", &allowlist, "identity", "none")
    );
    for other in [
        store::scope_digest_v3("F2", &allowlist, "identity", c.bytes()),
        store::scope_digest_v3("F", &[0; 32], "identity", c.bytes()),
        store::scope_digest_v3("F", &allowlist, "identity2", c.bytes()),
    ] {
        assert_ne!(v3, other);
    }
    let mut changed = *c.bytes();
    changed[2] = 1;
    assert_ne!(
        v3,
        store::scope_digest_v3("F", &allowlist, "identity", &changed)
    );
    assert_ne!(
        store::replay_scope_digest(&v3, 17, 19, 1, false),
        store::replay_scope_digest(&v3, 18, 19, 1, false)
    );
}
