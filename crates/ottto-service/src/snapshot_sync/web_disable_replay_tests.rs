// [money] Web disable, then an explicit install, both heard on the health
// heartbeat: the local copy is erased, and the cold replay re-offers the same
// keys and bodies with the same post-ACK account placement.
use super::*;
use crate::snapshot_sync::source_control::{apply, response_for_test};
use crate::snapshot_sync::{enabled_snapshot_sources_in, erase_disabled_sources};

#[test]
fn web_disable_then_install_replays_the_same_money_and_placement() {
    with_e2(|| {
        let (c, path) = claude_corpus("side_owner");
        second_account(&c, &path);
        input_clock(&path);
        let page = |prior| {
            let scanner = E2ScanFixture::with_identity_capture(true);
            let mut page = c.raw(&scanner, prior, 100, false, &[]);
            page.enrich(&c);
            page.finish();
            page
        };
        let device = ottto_core::LocalDeviceBinding {
            device_id: "device".into(),
            machine_id: Some("otm_test".into()),
            sources: vec!["claude_code".into()],
        };
        let heard = |revision, state| {
            let response = response_for_test("device", "claude_code", revision, state);
            apply(&c.support, "device", &response)
        };
        let cache = crate::snapshots::sampled_scan::SharedCache::default();
        let local = "support/snapshots/claude_code-scan-index-v3.json";

        let mut first = page(ScanIndex::default());
        c.reload_in(&mut first.index, local);
        assert!(
            c.base.join(local).exists(),
            "positive control: a local copy"
        );
        assert!(heard(1, "disabled"));
        assert!(enabled_snapshot_sources_in(&device, &c.support).is_empty());
        erase_disabled_sources(&c.support, &cache);
        assert!(!c.base.join(local).exists(), "local copy erased");
        assert!(heard(2, "enabled"));
        erase_disabled_sources(&c.support, &cache);
        assert_eq!(
            enabled_snapshot_sources_in(&device, &c.support),
            vec![SnapshotSource::ClaudeCode]
        );
        let reloaded = ScanIndex::load(&c.base.join(local)).unwrap();
        assert!(reloaded.files.is_empty(), "the replay starts cold");
        let second = page(reloaded);

        let accepted = |page: &Page| {
            page.scan
                .snapshots
                .iter()
                .map(|item| {
                    let witness = snapshot_upload_body_witness(item);
                    (item.snapshot_fingerprint.clone(), witness)
                })
                .collect::<std::collections::BTreeMap<_, _>>()
        };
        assert_eq!(
            accepted(&first),
            accepted(&second),
            "same keys and bodies: the receiver settles unchanged, no double count"
        );
        let accounts = first
            .scan
            .snapshots
            .iter()
            .flat_map(|item| {
                item.model_usage
                    .iter()
                    .chain(item.usage_buckets.iter().flat_map(|b| &b.model_usage))
            })
            .flat_map(|row| {
                row.account_identifier_hash.iter().chain(
                    row.identity_parts
                        .iter()
                        .flatten()
                        .filter_map(|part| part.account_identifier_hash.as_ref()),
                )
            })
            .collect::<std::collections::BTreeSet<_>>();
        assert!(accounts.len() >= 2, "positive control: two accounts placed");
        let [before, after] = [&first, &second].map(routed);
        crate::snapshots::sampled_scan::transition_fixture::money_oracle::assert_equivalent(
            &before, &after,
        );
    });
}
