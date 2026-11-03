//! Physical Tail format cases, using the real SQLite transaction codec.
use super::*;

fn random(len: usize) -> Vec<u8> {
    let mut n = 0x1234_5678_9abc_def0_u64;
    (0..len)
        .map(|_| {
            n ^= n << 13;
            n ^= n >> 7;
            n ^= n << 17;
            n as u8
        })
        .collect()
}

/// [format] Only shrinking values at or above 512 bytes use v3. Raw MAGIC
/// is opaque, and digests authenticate physical bytes for both versions.
#[test]
fn inline_threshold_and_physical_digest() {
    let scratch = crate::test_scratch::ScratchDir::canonical("tail-inline-codec");
    let mut db = sqlite::Sqlite::create_import(&scratch.join("index.v2.sqlite.import")).unwrap();
    let mut tx = db.begin(TxnMode::Write).unwrap();
    let key = row("tail.page.responses", b"file", 0).unwrap();
    for len in [511, 512, 513] {
        for compressible in [false, true] {
            let mut raw = if compressible {
                vec![0; len]
            } else {
                random(len)
            };
            raw[..4].copy_from_slice(codec::MAGIC);
            let h = write_value(&mut tx, b"file", 1, 0, &key, &raw).unwrap();
            let version = if compressible && len >= 512 {
                ZSTD_INLINE
            } else {
                INLINE
            };
            assert_eq!(h.value_version, version);
            assert_eq!(read_value(&mut tx, b"file", 1, 0, &h).unwrap(), raw);
            let mut stored = Vec::new();
            tx.read_value(&h, &mut stored).unwrap();
            let mut hash = value_digest_start(version);
            hash.update(&stored);
            assert_eq!(h.digest, integrity(hash));
            if version == ZSTD_INLINE {
                assert!(stored.len() < len);
            } else {
                assert_eq!(stored, raw);
            }
        }
    }
}

/// [format] Raw geometry survives compression; mixed raw/v3 fragments expand
/// before the manifest length/SHA check. Missing or mismatched parts refuse.
#[test]
fn raw_fragment_geometry_and_manifest_integrity() {
    let scratch = crate::test_scratch::ScratchDir::canonical("tail-fragment-codec");
    let mut db = sqlite::Sqlite::create_import(&scratch.join("index.v2.sqlite.import")).unwrap();
    let mut tx = db.begin(TxnMode::Write).unwrap();
    let key = row("tail.page.responses", b"file", 0).unwrap();
    for len in [FRAG_BYTES - 1, FRAG_BYTES, FRAG_BYTES + 1] {
        let raw = vec![0; len];
        let h = write_value(&mut tx, b"file", 1, 0, &key, &raw).unwrap();
        assert_eq!(
            h.value_version,
            if len > FRAG_BYTES {
                FRAGMENTED
            } else {
                ZSTD_INLINE
            }
        );
        assert_eq!(read_value(&mut tx, b"file", 1, 0, &h).unwrap(), raw);
        let parts = tx
            .scan_record_key(
                &RecordKind::parse(FRAG).unwrap(),
                &frag_key(b"file", 1, 0),
                None,
                8,
            )
            .unwrap();
        if len <= FRAG_BYTES {
            assert!(parts.is_empty());
            continue;
        }
        assert_eq!(h.len, 48);
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[0].value_version, ZSTD_INLINE);
        assert_eq!(parts[1].value_version, INLINE);
        let mut manifest = Vec::new();
        tx.read_value(&h, &mut manifest).unwrap();
        assert_eq!(&manifest[..8], &(len as u64).to_be_bytes());
        assert_eq!(&manifest[8..16], &2_u64.to_be_bytes());
        assert_eq!(&manifest[16..], Sha256::digest(&raw).as_slice());
        manifest[16] ^= 1;
        let bad = put(&mut tx, &key, FRAGMENTED, &manifest).unwrap();
        assert!(read_value(&mut tx, b"file", 1, 0, &bad).is_err());
        let restored = write_value(&mut tx, b"file", 1, 0, &key, &raw).unwrap();
        tx.delete(&parts[1].key).unwrap();
        assert!(read_value(&mut tx, b"file", 1, 0, &restored).is_err());
        // Preserve the version-2 reader for old all-raw fragments too.
        put(&mut tx, &parts[0].key, INLINE, &raw[..FRAG_BYTES]).unwrap();
        put(&mut tx, &parts[1].key, INLINE, &raw[FRAG_BYTES..]).unwrap();
        assert_eq!(read_value(&mut tx, b"file", 1, 0, &restored).unwrap(), raw);
    }
    let h = write_value(&mut tx, b"file", 1, 0, &key, b"small").unwrap();
    assert_eq!(read_value(&mut tx, b"file", 1, 0, &h).unwrap(), b"small");
    assert!(tx
        .scan_kind(&RecordKind::parse(FRAG).unwrap(), None, 8)
        .unwrap()
        .is_empty());
}

/// [behaviour] Restating identical compressed bytes performs no physical
/// UPDATE; an untouched old raw row remains raw until explicitly restated.
#[test]
fn unchanged_compressed_rewrite_does_not_churn_rows() {
    let scratch = crate::test_scratch::ScratchDir::canonical("tail-no-churn");
    let path = scratch.join("index.v2.sqlite.import");
    let mut db = sqlite::Sqlite::create_import(&path).unwrap();
    let conn = rusqlite::Connection::open(&path).unwrap();
    conn.execute_batch(
        "CREATE TRIGGER unchanged_tail_update BEFORE UPDATE ON records
        WHEN old.kind LIKE 'tail.%' AND old.value_version = new.value_version
        AND old.value_digest = new.value_digest
        BEGIN SELECT RAISE(ABORT, 'unchanged Tail row updated'); END;",
    )
    .unwrap();
    let mut tx = db.begin(TxnMode::Write).unwrap();
    let key = row("tail.page.responses", b"file", 0).unwrap();
    let old_key = row("tail.page.responses", b"file", 1).unwrap();
    let raw = vec![0; 2048];
    let old = put(&mut tx, &old_key, INLINE, &raw).unwrap();
    let h = write_value(&mut tx, b"file", 1, 0, &key, &raw).unwrap();
    assert_eq!(h.value_version, ZSTD_INLINE);
    assert_eq!(write_value(&mut tx, b"file", 1, 0, &key, &raw).unwrap(), h);
    assert_eq!(tx.get(&old_key).unwrap().unwrap(), old);
    assert_eq!(read_value(&mut tx, b"file", 1, 1, &old).unwrap(), raw);
}
