// A true replacement of all-copy subagent twins, next to the device-renumber arm.

/// [money] A device renumber keeps the certificate, but a true replacement
/// (a new inode at the same path) still refuses it as replaced; the page
/// reads both twins Full and the 26 copied pairs still count once.
#[cfg(unix)]
#[test]
fn subagent_all_copy_twins_true_replace_reads_full_and_conserves() {
    with_e2(|| {
        let (c, paths, index) = pair("subagent-copied-true-replace");
        let (mut replaced, _) = legacy(&c, index.clone());
        let restore = |index: &ScanIndex, path: &PathBuf| {
            crate::snapshots::e2_pipeline_scan_fixture::claude_certificate_restore_for_test(
                index,
                &path.to_string_lossy(),
            )
        };
        for path in &paths {
            assert_eq!(restore(&replaced, path), Ok(()), "the same object");
            let swap = path.with_extension("swap");
            std::fs::copy(path, &swap).unwrap();
            std::fs::rename(&swap, path).unwrap();
            assert_eq!(
                restore(&replaced, path),
                Err(crate::transcript_acquisition::CertificateRefusal::Changed(
                    crate::transcript_acquisition::FullReason::Replaced
                )),
                "a new inode at the path is a replacement"
            );
        }
        owe(&mut replaced);
        let mut page = ready(
            &c,
            &E2ScanFixture::with_subagent_births(),
            replaced,
            100,
            true,
        );
        page.finish();
        let item = body(&page, &member()).unwrap();
        assert_eq!((item.request_count, item.output_tokens), (26, 11_525));
        assert_eq!(item.removed_request_count, Some(26));
        assert!(page.modes.0 >= 2, "both replaced twins read Full");
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
