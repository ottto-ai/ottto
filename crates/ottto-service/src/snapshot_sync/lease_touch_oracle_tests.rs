// A retention touch on the native disk route versus a cold Full, including placement.
use super::*;
use crate::snapshots::sampled_scan::transition_fixture::{money_oracle, observe_consumed, Mode};
use crate::transcript_acquisition::FullReason;
use std::time::{Duration, SystemTime};

fn lease_time(path: &Path, days_ago: u64) {
    let at = SystemTime::now() - Duration::from_secs(days_ago * 86400);
    std::fs::File::options()
        .write(true)
        .open(path)
        .unwrap()
        .set_times(std::fs::FileTimes::new().set_accessed(at).set_modified(at))
        .unwrap();
}

/// [money] A forward mtime touch restores the same whole body and account placement
/// as cold Full, then settles to Skip; subsequent touches and appends still converge.
#[test]
fn lease_touch_disk_restore_matches_cold_full_without_transcript_reads() {
    with_e2(|| {
        let mut c = Corpus::new("lease-touch-money-oracle");
        let root = c.root(
            ROOT,
            &(line(ROOT, "r1", AT, 10)
                + &line(ROOT, "r2", "2026-08-02T07:00:20Z", 20)
                + &line(ROOT, "gap", "2026-08-02T07:00:25Z", 12)
                + &serde_json::json!({"padding": "x".repeat(24_000)}).to_string()
                + "\n"),
        );
        c.evidence(
            &[
                api_login(ROOT, "r1", 10, '1', Some('7')),
                api_login(ROOT, "r2", 20, '2', Some('8')),
                api_login(ROOT, "side", 5, '2', Some('8')),
            ],
            &[
                trace_for(ROOT, "r1", ""),
                trace_for(ROOT, "r2", ""),
                trace_for(ROOT, "side", ""),
            ],
        );
        lease_time(&root, 20);
        let disk = Disk::new(&c);
        let first_owner = E2ScanFixture::capturing_identity();
        disk.begin(&first_owner, SnapshotSource::ClaudeCode);
        let mut first = c.raw(&first_owner, ScanIndex::default(), 100, true, &[]);
        first.enrich(&c);
        first.finish();
        let progress = e2_progress();
        let prior_money = mixed_route(&first, &progress, Mode::ColdFull);
        assert_eq!(
            first.scan.snapshots[0].input_tokens, 47,
            "side call and evidence gap count"
        );
        let identity = serde_json::to_value(&first.scan.snapshots[0]).unwrap();
        let tags = serde_json::to_string(&identity["model_usage"]).unwrap();
        assert!(
            tags.contains(&"1".repeat(64)) && tags.contains(&"2".repeat(64)),
            "two tagged accounts and a mid-session switch: {tags}"
        );
        // Commit the certified reduction before delivery. The touched pass
        // emits its whole body and earns the receipt used by the quiet pass.
        let mut index = disk.commit(&first.cache, SnapshotSource::ClaudeCode, &mut first.index);

        // A new process sees a retention renewal: old mtime < new mtime <= stored ctime.
        lease_time(&root, 7);
        let owner = E2ScanFixture::capturing_identity();
        disk.begin(&owner, SnapshotSource::ClaudeCode);
        let (mut touched, consumed) =
            observe_consumed(|| c.raw(&owner, index.clone(), 100, true, &[]));
        assert_eq!(
            consumed, 0,
            "certified lease touch must not reread the transcript"
        );
        assert_eq!(owner.full_reasons()[FullReason::SameSizeEdit.slot()], 0);
        assert_eq!(touched.modes, (0, 0, 1));
        touched.enrich(&c);
        touched.finish();
        let restored = mixed_route(&touched, &progress, Mode::DiskRestore);
        let mut cold = c.raw(&E2ScanFixture::capturing_identity(), index, 100, true, &[]);
        cold.enrich(&c);
        cold.finish();
        let full = mixed_route(&cold, &progress, Mode::ColdFull);
        money_oracle::assert_equivalent(&full, &restored);
        money_oracle::assert_no_smaller_reemit(ROOT, &prior_money, &restored, &full, false);
        accept_page(&mut touched);
        index = disk.commit(
            &touched.cache,
            SnapshotSource::ClaudeCode,
            &mut touched.index,
        );

        let (mut quiet, consumed) = observe_consumed(|| c.raw(&owner, index, 100, true, &[]));
        quiet.enrich(&c);
        quiet.finish();
        assert_eq!(consumed, 0, "third pass is Skip");
        assert_eq!(quiet.scan.scanned_file_count, 0, "no forced family reparse");
        assert!(
            quiet.scan.snapshots.is_empty(),
            "no identity hold or re-emission"
        );
        assert!(
            quiet
                .disposition
                .request_owned_hold_reasons
                .values()
                .all(|count| *count == 0),
            "no identity hold"
        );
        index = disk.commit(&quiet.cache, SnapshotSource::ClaudeCode, &mut quiet.index);

        lease_time(&root, 6);
        let (mut second_touch, consumed) =
            observe_consumed(|| c.raw(&owner, index, 100, true, &[]));
        assert_eq!(consumed, 0);
        assert_eq!(second_touch.modes, (0, 0, 1));
        second_touch.enrich(&c);
        second_touch.finish();
        accept_page(&mut second_touch);
        index = disk.commit(
            &second_touch.cache,
            SnapshotSource::ClaudeCode,
            &mut second_touch.index,
        );
        append(&root, &line(ROOT, "later", "2026-08-02T07:00:30Z", 6));
        let suffix = line(ROOT, "later", "2026-08-02T07:00:30Z", 6).len() as u64;
        let (mut grown, consumed) = observe_consumed(|| c.raw(&owner, index, 100, true, &[]));
        assert_eq!(grown.modes, (0, 1, 0));
        assert_eq!(consumed, suffix, "append reads only its suffix");
        grown.enrich(&c);
        grown.finish();
    });
}
