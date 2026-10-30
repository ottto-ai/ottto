use super::*;

fn retired(source: DurableSource) -> Digest32 {
    parse_hex_digest(match source {
        DurableSource::ClaudeCode => {
            "8d141d534b95e2c5ac6a2e6d8e5ca45f3a852038fa456f5f3216c14bf84e943c"
        }
        DurableSource::Codex => "02206079405b58944e1d6d4d0ed3768c2acb39444d5278f1ba86725a723534a1",
    })
    .unwrap()
}
fn item(source: DurableSource, path: &Path, n: u64) -> PendingRecord {
    let mut b = binding("account", "scope", ("accepted", None));
    b.source = source;
    b.key = key_digest(source, INDEX_KEY);
    let mut record = pending(b, certificate(path), n);
    record.allowlist = source.properties().allowlist();
    record.body =
        crate::snapshots::durable_store_fixture_body(source.properties().snapshot, n, n * 7);
    record
}

/// [format] repin classification is exact source format pin and never decodes old body.
#[test]
fn repin_classification_is_exact_source_format_pin_and_never_decodes_old_body() {
    for source in [DurableSource::ClaudeCode, DurableSource::Codex] {
        for arm in [
            "retired",
            "other_pin",
            "other_source_pin",
            "format_2",
            "future",
        ] {
            let scratch = Scratch::new();
            let path = scratch.transcript("t.jsonl", b"{}\n");
            let mut record = item(source, &path, 1);
            record.allowlist = retired(source);
            if arm == "other_pin" {
                record.allowlist[0] ^= 1;
            }
            if arm == "other_source_pin" {
                record.allowlist = retired(if source == DurableSource::Codex {
                    DurableSource::ClaudeCode
                } else {
                    DurableSource::Codex
                });
            }
            // The body is deliberately not the current codec. Classification
            // grants no body decode, and still binds the envelope checksum.
            record.body = b"opaque retired body".to_vec();
            let mut bytes = pinned_v1_bytes(&record, 1);
            if arm == "format_2" {
                bytes[8..10].copy_from_slice(&2u16.to_le_bytes());
            }
            if arm == "future" {
                bytes[8..10].copy_from_slice(&4u16.to_le_bytes());
            }
            let mut store =
                DurableTailStore::new(store_dir_for_index(&scratch.index_path()), source);
            let _lock = crate::locked_state_dir::test_locks::hold(&scratch.root);
            ensure_private_dir(store.dir()).unwrap();
            let disk = record_file(&store, &record.binding.key);
            put_record(&disk, &bytes);
            let reason = if arm == "retired" {
                Refusal::Repin
            } else if arm == "future" {
                Refusal::NewerFormat
            } else {
                Refusal::Unknown
            };
            assert_eq!(
                store.full_hold(&record.binding.key, false),
                Some(reason),
                "{arm}"
            );
            assert!(matches!(store.read(&record.binding.key),ReadOutcome::Refused(r) if r==reason));
            assert_eq!(fs::read(disk).unwrap(), bytes);
            assert!(
                source
                    .properties()
                    .representation(1, &retired(source))
                    .is_none(),
                "retired is not a restore representation"
            );
        }
    }
}

/// [format] repin exact retirement follows durable successor and retries sync without input.
#[test]
fn repin_exact_retirement_follows_durable_successor_and_retries_sync_without_input() {
    for source in [DurableSource::ClaudeCode, DurableSource::Codex] {
        let _reset = ResetFaults;
        let scratch = Scratch::new();
        let lock = crate::locked_state_dir::test_locks::hold(&scratch.root);
        let path = scratch.transcript("t.jsonl", b"{}\n");
        let mut old = item(source, &path, 1);
        old.allowlist = retired(source);
        let mut store = DurableTailStore::new(store_dir_for_index(&scratch.index_path()), source);
        ensure_private_dir(store.dir()).unwrap();
        let disk = record_file(&store, &old.binding.key);
        let bytes = pinned_v1_bytes(&old, 1);
        put_record(&disk, &bytes);
        let (proof, _) = store
            .repin_witness(&old.binding.key, &old.binding.context, 1)
            .unwrap();
        assert_eq!(fs::read(&disk).unwrap(), bytes, "witness never retires");
        assert!(store.authorize_repin(&proof));
        let successor = item(source, &path, 2);
        assert_eq!(
            store
                .write_after_save(lock, 2, 0, vec![successor])
                .unwrap()
                .written,
            1
        );
        let successor_bytes = fs::read(&disk).unwrap();
        assert_ne!(successor_bytes, bytes);
        let mut sync_due = true;
        test_hooks::set_before_dir_sync(Some(Box::new(|_| {
            Err(io::Error::other("retire fsync fault"))
        })));
        assert!(matches!(
            store.retire_exact(lock, &proof, &mut sync_due),
            RetireOutcome::Retry
        ));
        assert!(sync_due);
        assert_eq!(fs::read(&disk).unwrap(), successor_bytes);
        test_hooks::set_before_dir_sync(None);
        assert!(matches!(
            store.retire_exact(lock, &proof, &mut sync_due),
            RetireOutcome::Superseded
        ));
        assert!(!sync_due);
        assert_eq!(
            fs::read(&disk).unwrap(),
            successor_bytes,
            "exact old proof never deletes successor"
        );
        // A restarted owner sees the new pin, not another re-pin permission.
        let mut restarted = DurableTailStore::new(store.dir().to_path_buf(), source);
        assert!(matches!(
            restarted.read(&old.binding.key),
            ReadOutcome::Found(_)
        ));
    }
}

/// [format] repin unknown or newer survivor never retires under an old proof.
#[test]
fn repin_unknown_or_newer_survivor_never_retires_under_an_old_proof() {
    for future in [false, true] {
        let scratch = Scratch::new();
        let lock = crate::locked_state_dir::test_locks::hold(&scratch.root);
        let path = scratch.transcript("t.jsonl", b"{}\n");
        let source = DurableSource::ClaudeCode;
        let mut old = item(source, &path, 1);
        old.allowlist = retired(source);
        let mut store = scratch.store();
        ensure_private_dir(store.dir()).unwrap();
        let disk = record_file(&store, &old.binding.key);
        put_record(&disk, &pinned_v1_bytes(&old, 1));
        let (proof, _) = store
            .repin_witness(&old.binding.key, &old.binding.context, 1)
            .unwrap();
        let mut unknown = pinned_v1_bytes(&old, 2);
        if future {
            unknown[8..10].copy_from_slice(&4u16.to_le_bytes());
        } else {
            unknown[10] ^= 1;
        }
        put_record(&disk, &unknown);
        let mut sync_due = true;
        assert!(matches!(
            store.retire_exact(lock, &proof, &mut sync_due),
            RetireOutcome::Retry
        ));
        assert!(sync_due);
        assert_eq!(fs::read(&disk).unwrap(), unknown);
    }
}
