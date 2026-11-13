// A true replacement of all-copy subagent twins, next to the device-renumber arm.

/// [money] A device renumber keeps the certificate, but a true replacement
/// (a new inode at the same path) still refuses it: both twins read Full as
/// replaced, and the 26 copied pairs still count once.
#[cfg(unix)]
#[test]
fn subagent_all_copy_twins_true_replace_reads_full_and_conserves() {
    with_e2(|| {
        let (c, paths, index) = pair("subagent-copied-true-replace");
        let (mut replaced, _) = legacy(&c, index.clone());
        for path in &paths {
            let swap = path.with_extension("swap");
            std::fs::copy(path, &swap).unwrap();
            std::fs::rename(&swap, path).unwrap();
        }
        owe(&mut replaced);
        let scanner = E2ScanFixture::with_subagent_births();
        let mut page = ready(&c, &scanner, replaced, 100, true);
        page.finish();
        let item = body(&page, &member()).unwrap();
        assert_eq!((item.request_count, item.output_tokens), (26, 11_525));
        assert_eq!(item.removed_request_count, Some(26));
        assert!(
            scanner.full_reasons()[crate::transcript_acquisition::FullReason::Replaced.slot()] >= 2,
            "both replaced twins read Full"
        );
        let mut expected = ready(
            &c,
            &E2ScanFixture::with_subagent_births(),
            index,
            100,
            false,
        );
        expected.finish();
        let expected = captured(&expected, Mode::ColdFull);
        money_oracle::assert_equivalent(&expected, &captured(&page, Mode::Restart));
    });
}
