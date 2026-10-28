//! V2 carriers and old-writer envelopes, on real private files and the real lock.
use super::tests::*;
use super::*;

#[test]
fn v2_markers_precede_every_ordinary_mutation_even_without_a_warm_memo() {
    for mark in [0, 1, 2] {
        for seam in ["read", "gc", "budget", "overwrite", "invalidate", "fresh"] {
            for damaged in [false, true] {
                let scratch = Scratch::new();
                let lock = crate::locked_state_dir::LockedStateDir::acquire(&scratch.root).unwrap();
                let path = scratch.transcript("t.jsonl", b"{}\n");
                let b = binding("acct", "scope", ("fp", None));
                let mut record = pending(b.clone(), certificate(&path), 1);
                record.metadata.mark = mark;
                if mark != 0 {
                    record.metadata.recovery_object = object(&record.certificate);
                    record.metadata.recovery_digest = digest("test-recovery:v1", &[b"candidate"]);
                }
                scratch
                    .store()
                    .write_after_save(&lock, 1, vec![record.clone()])
                    .unwrap();
                let disk = record_file(&scratch.store(), &b.key);
                let mut bytes = fs::read(&disk).unwrap();
                if damaged {
                    let end = bytes.len() - 1;
                    bytes[end] ^= 1;
                    put_record(&disk, &bytes);
                }
                let mut cold = scratch.store();
                match seam {
                    "read" => {
                        let _ = cold.read(&b.key, &placeholder_allowlist());
                    }
                    "gc" | "fresh" => {
                        cold.gc(&lock, &[0; 32], &placeholder_allowlist(), &BTreeMap::new())
                            .unwrap();
                    }
                    "invalidate" => {
                        cold.remove_keys(&lock, &BTreeSet::from([b.key])).unwrap();
                    }
                    _ => {
                        let mut next = pending(b.clone(), record.certificate.clone(), 2);
                        if seam == "budget" {
                            next.body.resize(RECORD_BYTES, 0);
                        }
                        cold.write_after_save(&lock, 2, vec![next]).unwrap();
                    }
                }
                if mark == 0 {
                    continue;
                } // unmarked deletion/rebuild controls covered below
                if mark == 2 && seam == "overwrite" && !damaged {
                    let read = found(scratch.store().read(&b.key, &placeholder_allowlist()));
                    assert_eq!(read.index_generation, 2);
                    assert_eq!(read.record.metadata.mark, 2);
                    assert_eq!(
                        read.record.metadata.recovery_object,
                        record.metadata.recovery_object
                    );
                    assert_eq!(
                        read.record.metadata.recovery_digest,
                        record.metadata.recovery_digest
                    );
                } else {
                    assert_eq!(
                        fs::read(&disk).unwrap(),
                        bytes,
                        "{mark} {seam} damaged={damaged}"
                    );
                }
                let live = Some((object(&record.certificate), record.metadata.namespace));
                assert_eq!(
                    scratch.store().hold(&b.key, live),
                    if mark == 1 {
                        Some(Refusal::RecoveryOpen)
                    } else if damaged {
                        Some(Refusal::SpentCarrier)
                    } else {
                        None
                    }
                );
                // A Spent carrier holds a replaced inode or another namespace.
                if mark == 2 && !damaged {
                    for changed in [
                        Some(([7, 8, 9], record.metadata.namespace)),
                        Some((object(&record.certificate), [1; 32])),
                    ] {
                        assert_eq!(
                            scratch.store().hold(&b.key, changed),
                            Some(Refusal::SpentCarrier)
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn spent_replacement_and_reuse_inheritance_are_object_namespace_and_scope_bound() {
    for reuse in [0, 1, 2] {
        for change in ["same", "object", "namespace", "scope"] {
            let scratch = Scratch::new();
            let lock = crate::locked_state_dir::LockedStateDir::acquire(&scratch.root).unwrap();
            let path = scratch.transcript("t.jsonl", b"{}\n");
            let b = binding("acct", "scope", ("fp", None));
            let mut old = pending(b.clone(), certificate(&path), 1);
            old.metadata.reuse_814 = reuse;
            old.metadata.mark = 2;
            old.metadata.recovery_object = object(&old.certificate);
            old.metadata.recovery_digest = [3; 32];
            scratch
                .store()
                .write_after_save(&lock, 1, vec![old.clone()])
                .unwrap();
            let disk = record_file(&scratch.store(), &b.key);
            let bytes = fs::read(&disk).unwrap();
            let mut next = pending(b.clone(), old.certificate.clone(), 2);
            match change {
                "object" => next.certificate.inode += 1,
                "namespace" => next.metadata.namespace = [1; 32],
                "scope" => next.binding.scope = [2; 32],
                _ => {}
            }
            let mut cold = scratch.store();
            let receipt = cold.write_after_save(&lock, 2, vec![next]).unwrap();
            if matches!(change, "object" | "namespace") {
                assert_eq!(receipt.written, 0);
                assert_eq!(cold.counters().store_write_skipped[2], 1);
                assert_eq!(fs::read(disk).unwrap(), bytes);
            } else {
                let next = found(scratch.store().read(&b.key, &placeholder_allowlist()));
                assert_eq!(next.record.metadata.mark, 2);
                assert_eq!(next.record.metadata.recovery_digest, [3; 32]);
                assert_eq!(
                    next.record.metadata.reuse_814,
                    if change == "same" { reuse } else { 0 }
                );
                assert_eq!(next.record.metadata.protocol, 0);
            }
        }
    }
}

#[test]
fn v2_identity_and_optional_sections_are_structurally_verified() {
    let scratch = Scratch::new();
    let lock = crate::locked_state_dir::LockedStateDir::acquire(&scratch.root).unwrap();
    let path = scratch.transcript("t.jsonl", b"{}\n");
    let b = binding("acct", "scope", ("fp", None));
    let record = pending(b.clone(), certificate(&path), 1);
    scratch
        .store()
        .write_after_save(&lock, 1, vec![record])
        .unwrap();
    let disk = record_file(&scratch.store(), &b.key);
    let good = fs::read(&disk).unwrap();
    assert_eq!(good.len() - placeholder_body(1, 7).len() - 32, HEADER_BYTES);
    for offset in [211, 235, 293, HEADER_BYTES - 7, HEADER_BYTES - 8] {
        let mut bad = good.clone();
        bad[offset] ^= 4;
        let end = bad.len() - 32;
        let hash = Sha256::digest(&bad[..end]);
        bad[end..].copy_from_slice(&hash);
        put_record(&disk, &bad);
        assert_eq!(
            scratch.store().read(&b.key, &placeholder_allowlist()),
            ReadOutcome::Refused(Refusal::Corrupt),
            "offset={offset}"
        );
        assert_eq!(fs::read(&disk).unwrap(), bad);
    }
}

#[test]
fn both_pinned_v1_writers_decode_and_drop_only_the_retired_debt() {
    for pin in ["72205c6c", "ffc6c846"] {
        let scratch = Scratch::new();
        let path = scratch.transcript("t.jsonl", b"{}\n");
        let b = binding("acct", "scope", ("fp", None));
        let mut record = pending(b.clone(), certificate(&path), 1);
        record.certificate.audit_debt_unix_seconds = Some(42);
        let bytes = pinned_v1_bytes(&record, 7);
        let decoded = decode(&bytes, &placeholder_allowlist()).unwrap();
        assert_eq!(decoded.format, 1, "{pin}");
        assert_eq!(decoded.index_generation, 7);
        assert_eq!(decoded.record.body, record.body);
        assert_eq!(decoded.record.certificate.audit_debt_unix_seconds, None);
        assert_eq!(
            decoded.record.certificate.verified_unix_seconds,
            record.certificate.verified_unix_seconds
        );
        assert_eq!(decoded.record.metadata, Metadata::default());
    }
}
