use super::*;

/// [behaviour] Small-route sheds preserve Retry-After seconds, dates and absence.
#[test]
#[serial(env, source_cadences)]
fn activity_hint_sheds_preserve_retry_after() {
    use std::net::TcpListener;
    for (status, header, expected) in [
        (408, "Retry-After: 60\r\n", Some(60)),
        (
            429,
            "Retry-After: Sun, 26 Jul 2099 10:02:00 GMT\r\n",
            Some(1800),
        ),
        (503, "", None),
        (503, "Retry-After: invalid\r\n", None),
    ] {
        clear_source_upload_deadlines_for_test();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = SnapshotApiClient::new(format!("http://{}", listener.local_addr().unwrap()));
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let _ = read_complete_http_request(&mut stream);
            write!(
                stream,
                "HTTP/1.1 {status} Error\r\n{header}Content-Length: 0\r\nConnection: close\r\n\r\n"
            )
            .unwrap();
        });
        let error = small_source_upload(SnapshotSource::Pi, || client.get_activity_hint("relay"))
            .err()
            .expect("shed error");
        let shed = error.downcast_ref::<UploadShed>().unwrap();
        assert_eq!(shed.status, status);
        assert_eq!(shed.retry_after.map(|v| v.as_secs()), expected);
        assert_eq!(source_shed_streaks().lock().unwrap().get("pi"), Some(&1));
        server.join().unwrap();
    }
    clear_source_upload_deadlines_for_test();
}

/// [behaviour] A multi-item 413 reuses bounded splitting; a cutoff keeps the remainder owed.
#[test]
fn batch_413_splits_and_preserves_cutoffs() {
    for reject_children in [false, true] {
        let items = test_fingerprints(32);
        let mut progress = test_upload_progress();
        let mut accepted = 0;
        let mut attempts = Vec::new();
        let result = upload_resumable_batches(
            &items,
            &unique_poison_scope(),
            &mut progress,
            &mut accepted,
            String::as_str,
            |batch| {
                attempts.push(batch.len());
                if batch.len() > 1 && (reject_children || batch.len() == items.len()) {
                    Err(anyhow::Error::new(UploadFailureDiagnostics::for_http_test(
                        "local snapshot upload",
                        "snapshot_batch",
                        413,
                        false,
                    )))
                } else {
                    Ok(accepted_batch(batch.len()))
                }
            },
            |_| Ok(()),
        );
        if reject_children {
            assert!(result.is_err());
            assert_eq!(attempts, [32, 16, 8, 4, 2, 1, 1, 2, 1, 1, 4]);
            assert_eq!(accepted, 4);
            let retried = upload_resumable_batches(
                &items,
                &unique_poison_scope(),
                &mut progress,
                &mut accepted,
                String::as_str,
                |batch| Ok(accepted_batch(batch.len())),
                |_| Ok(()),
            );
            assert_eq!(retried.unwrap(), ResumableUploadResult::Completed);
            assert_eq!(accepted, items.len() as u64);
            assert!(progress.quarantined_fingerprints.is_empty());
        } else {
            assert_eq!(result.unwrap(), ResumableUploadResult::Completed);
            assert_eq!(attempts, [32, 16, 16]);
            assert_eq!(accepted, 32);
            assert_eq!(progress.accepted_fingerprints.len(), 32);
        }
    }
}
