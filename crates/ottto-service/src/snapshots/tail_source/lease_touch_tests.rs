//! Durable admission of retention touches, with real samples and native readers.
use super::super::claude::Claude;
use super::super::codex::Codex;
use super::super::load::{load, Load};
use super::super::pi::Pi;
use super::super::seam::tests::{route_for, scope, stage_reduction, Route, NOW};
use super::transition_tests::{open, FixtureSource};
use super::*;
use crate::snapshots::sampled_scan::transition_fixture::{native_cold, observe_consumed};
use crate::snapshots::tests::manifest_index_entry;
use crate::transcript_acquisition::{
    birth_unix_nanos, capture_sample_reads, DurableCertificate, ReadMode,
};
use std::io::{Seek, SeekFrom, Write};
use std::os::unix::fs::MetadataExt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

fn touch(path: &Path, at: SystemTime) {
    File::options()
        .write(true)
        .open(path)
        .unwrap()
        .set_times(std::fs::FileTimes::new().set_accessed(at).set_modified(at))
        .unwrap();
}

fn seed<S: FixtureSource>(
    edit: impl FnOnce(&mut DurableCertificate, &mut ScanIndexEntry),
) -> (Route, PathBuf, String) {
    let mut route = route_for(S::INDEX);
    let path = route.dir.join(S::name());
    let body = S::lines(3).join("\n")
        + "\n"
        + &serde_json::json!({"padding": "x".repeat(24_000)}).to_string()
        + "\n";
    std::fs::write(&path, body).unwrap();
    touch(&path, SystemTime::now() - Duration::from_secs(20 * 86400));
    let metadata = std::fs::metadata(&path).unwrap();
    let mut parser = open::<S>(&path);
    parser
        .prepare_acquisition(None, &scope(), None, NOW)
        .unwrap();
    let (reduction, checkpoint) = native_cold::finish_record(&mut parser, &scope(), NOW);
    let mut cert = checkpoint
        .durable_certificate(birth_unix_nanos(&metadata))
        .unwrap();
    assert_ne!(cert.birth_nanos, 0, "fixture requires known birth");
    let mut entry = manifest_index_entry(None);
    entry.size_bytes = metadata.len();
    entry.modified_unix_seconds = metadata.mtime() as u64;
    entry.modified_unix_nanos =
        Some(metadata.mtime() as u64 * 1_000_000_000 + metadata.mtime_nsec() as u64);
    entry.opened_changed_nanos =
        metadata.ctime() as u64 * 1_000_000_000 + metadata.ctime_nsec() as u64;
    entry.opened_birth_nanos = cert.birth_nanos;
    edit(&mut cert, &mut entry);
    let id = HeadIdentity::new(&route.path, S::SOURCE, &route.dir, &path, false);
    let staged = stage_reduction::<S>(&reduction, &cert, &id);
    let key = local_index_key(&path);
    state_v2::stage_tail(&route.path, &key, staged).unwrap();
    route.index.files.insert(key.clone(), entry);
    route.save(false);
    touch(&path, SystemTime::now() - Duration::from_secs(7 * 86400));
    (route, path, key)
}

fn loaded<S: FixtureSource>(route: &Route, path: &Path, key: &str) -> Load {
    let mut fresh = super::super::codex::tests::candidate(path);
    fresh.fingerprint_birth_nanos = birth_unix_nanos(&std::fs::metadata(path).unwrap());
    load::<S>(
        &route.index,
        &route.path,
        key,
        &HeadIdentity::new(&route.path, S::SOURCE, &route.dir, path, false),
        &mut File::open(path).unwrap(),
        &scope(),
        &fresh,
        &open::<S>(path).accumulator,
    )
}

fn reused<S: FixtureSource>() {
    let (route, path, key) = seed::<S>(|_, _| {});
    let ((load, consumed), samples) =
        capture_sample_reads(|| observe_consumed(|| loaded::<S>(&route, &path, &key)));
    let Load::Reused(taken, _) = load else {
        panic!("lease touch must reuse its committed head");
    };
    assert_eq!(consumed, 0);
    let sampled: usize = samples
        .iter()
        .map(|read| read.result.as_ref().unwrap())
        .sum();
    assert_eq!(
        sampled, 8192,
        "actual admission windows, separate from native metrics"
    );
    let mut parser = open::<S>(&path);
    let mode = parser
        .prepare_acquisition(Some(taken), &scope(), None, NOW)
        .unwrap();
    assert_eq!(mode, ReadMode::Unchanged);
    assert_eq!(parser.reader.consumed_bytes(), 0);
}

/// [behaviour] All three codecs use the same bounded durable touch admission.
#[test]
fn lease_touch_reuses_stored_tail_for_each_source() {
    reused::<Claude>();
    reused::<Codex>();
    reused::<Pi>();
}

/// [behaviour] Missing, mismatched or clamped birth and stale read bindings fail closed.
#[test]
fn lease_touch_requires_the_certificates_own_known_birth_and_read() {
    type Damage = fn(&mut DurableCertificate, &mut ScanIndexEntry);
    let cases: [(&str, Damage); 6] = [
        ("no ctime", |_, e| e.opened_changed_nanos = 0),
        ("unknown births", |c, e| {
            c.birth_nanos = 0;
            e.opened_birth_nanos = 0;
        }),
        ("wrong entry birth", |_, e| e.opened_birth_nanos += 1),
        ("stale mtime", |_, e| {
            *e.modified_unix_nanos.as_mut().unwrap() -= 1;
        }),
        ("stale length", |_, e| e.size_bytes += 1),
        ("unknown certificate birth", |c, _| c.birth_nanos = 0),
    ];
    for (name, damage) in cases {
        let (route, path, key) = seed::<Claude>(damage);
        assert!(
            matches!(
                loaded::<Claude>(&route, &path, &key),
                Load::Cold(Some(FullReason::SameSizeEdit))
            ),
            "{name}"
        );
    }
    let (route, path, key) = seed::<Claude>(|c, e| {
        c.birth_nanos += 1;
        e.opened_birth_nanos = c.birth_nanos;
    });
    let birth = birth_unix_nanos(&std::fs::metadata(&path).unwrap());
    touch(&path, UNIX_EPOCH + Duration::from_nanos(birth));
    assert!(matches!(
        loaded::<Claude>(&route, &path, &key),
        Load::Cold(Some(FullReason::SameSizeEdit))
    ));
}

/// [behaviour] A first touch outside the bound and an ordinary later write still read Full.
#[test]
fn fresh_mtime_and_same_size_write_still_read_full() {
    for write in [false, true] {
        let (route, path, key) = seed::<Claude>(|_, _| {});
        if write {
            let mut file = File::options().write(true).open(&path).unwrap();
            file.seek(SeekFrom::Start(12_000)).unwrap();
            file.write_all(b"y").unwrap();
        }
        let after = route.index.files[&key].opened_changed_nanos + 1_000_000_000;
        touch(&path, UNIX_EPOCH + Duration::from_nanos(after));
        assert!(matches!(
            loaded::<Claude>(&route, &path, &key),
            Load::Cold(Some(FullReason::SameSizeEdit))
        ));
    }
}

/// [behaviour] The existing digest guards still reject backdated edits in either window.
#[test]
fn backdated_window_edits_still_read_full() {
    for head in [true, false] {
        let (route, path, key) = seed::<Claude>(|_, _| {});
        let bytes = std::fs::read(&path).unwrap();
        let offset = if head {
            bytes.iter().position(|b| *b == b'x').unwrap() as u64
        } else {
            bytes.len() as u64 - 100
        };
        assert!(offset < 4096 || offset > bytes.len() as u64 - 4096);
        let mut file = File::options().write(true).open(&path).unwrap();
        file.seek(SeekFrom::Start(offset)).unwrap();
        file.write_all(b"y").unwrap();
        touch(&path, SystemTime::now() - Duration::from_secs(7 * 86400));
        let reason = if head {
            FullReason::HeadChanged
        } else {
            FullReason::BoundaryChanged
        };
        assert!(
            matches!(loaded::<Claude>(&route, &path, &key), Load::Cold(Some(actual)) if actual == reason)
        );
    }
}

/// [behaviour] An append retains the old prefix offset; an unsealed EOF still Tails.
#[test]
fn a_touch_keeps_append_and_unsealed_tail_semantics() {
    for unsealed in [false, true] {
        let (mut route, path, key) = seed::<Claude>(|_, _| {});
        let sealed = std::fs::metadata(&path).unwrap().len();
        if unsealed {
            // Re-certify a partial record without advancing its sealed prefix.
            File::options()
                .append(true)
                .open(&path)
                .unwrap()
                .write_all(b"{\"padding\":")
                .unwrap();
            let mut parser = open::<Claude>(&path);
            parser
                .prepare_acquisition(None, &scope(), None, NOW)
                .unwrap();
            let (reduction, checkpoint) = native_cold::finish_record(&mut parser, &scope(), NOW);
            let metadata = std::fs::metadata(&path).unwrap();
            let cert = checkpoint
                .durable_certificate(birth_unix_nanos(&metadata))
                .unwrap();
            let id = HeadIdentity::new(&route.path, Claude::SOURCE, &route.dir, &path, false);
            state_v2::stage_tail(
                &route.path,
                &key,
                stage_reduction::<Claude>(&reduction, &cert, &id),
            )
            .unwrap();
            let entry = route.index.files.get_mut(&key).unwrap();
            entry.size_bytes = metadata.len();
            entry.modified_unix_nanos =
                Some(metadata.mtime() as u64 * 1_000_000_000 + metadata.mtime_nsec() as u64);
            entry.opened_changed_nanos =
                metadata.ctime() as u64 * 1_000_000_000 + metadata.ctime_nsec() as u64;
            route.save(false);
            touch(&path, SystemTime::now() - Duration::from_secs(7 * 86400));
        } else {
            File::options()
                .append(true)
                .open(&path)
                .unwrap()
                .write_all(b"{\"padding\":1}\n")
                .unwrap();
        }
        let Load::Reused(taken, _) = loaded::<Claude>(&route, &path, &key) else {
            panic!("stored prefix must survive");
        };
        let mut parser = open::<Claude>(&path);
        assert_eq!(
            parser
                .prepare_acquisition(Some(taken), &scope(), None, NOW)
                .unwrap(),
            ReadMode::Tail
        );
        assert_eq!(
            parser.reader.acquisition.as_ref().unwrap().start_offset(),
            sealed
        );
    }
}
