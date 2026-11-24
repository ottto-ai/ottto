use super::*;

/// [behaviour] Header sheds keep the server floor while sustained refusal
/// uses the existing randomized ladder. A successful upload resets the streak.
#[test]
#[serial(source_cadences, source_upload_deadlines)]
fn repeated_header_sheds_climb_the_ladder_without_retrying_early() {
    clear_source_upload_deadlines_for_test();
    for source in [
        SnapshotSource::ClaudeCode,
        SnapshotSource::Codex,
        SnapshotSource::Pi,
    ] {
        let header = Duration::from_secs(60);
        let first = note_shed_and_backoff(source, Some(header));
        assert!((header..=Duration::from_secs(72)).contains(&first));
        for attempt in 1..=6 {
            let wait = note_shed_and_backoff(source, Some(header));
            let ceiling = (SHED_BACKOFF_BASE * (1 << attempt))
                .min(crate::snapshot_client::MAX_HONOURED_RETRY_AFTER);
            assert!((header..=ceiling.max(Duration::from_secs(72))).contains(&wait));
        }
        // A saturated ladder draw must sometimes exceed header-only jitter.
        // 64 draws also pass with the documented entropy-failure midpoint.
        assert!(
            (0..64).any(|_| note_shed_and_backoff(source, Some(header)) > Duration::from_secs(72))
        );
        let cap = crate::snapshot_client::MAX_HONOURED_RETRY_AFTER;
        assert_eq!(note_shed_and_backoff(source, Some(cap)), cap);
        clear_shed_streak(source);
        assert!(note_shed_and_backoff(source, Some(header)) <= Duration::from_secs(72));
    }
    clear_source_upload_deadlines_for_test();
}

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
        defer_source_uploads(SnapshotSource::Pi, Duration::from_secs(600));
        let previous_deadline = source_upload_deadlines().lock().unwrap()["pi"];
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
        assert!(source_upload_deadlines().lock().unwrap()["pi"] >= previous_deadline);
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
                    Ok(accept_fingerprints(batch))
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
                |batch| Ok(accept_fingerprints(batch)),
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

/// All shed callers latch collection status immediately, without waiting for a prepare skip.
#[test]
fn source_collection_latches_the_effective_shed_deadline_at_the_setter() {
    if !crate::test_isolation::run_here() {
        return;
    }
    use ottto_protocol::SourceCollectionState::ServerBackoff;
    crate::scan_clock::with_clock(0, || {
        for source in SNAPSHOT_SOURCES {
            let wall = "2026-11-15T10:00:00Z";
            defer_source_uploads(source, Duration::from_secs(600));
            assert!(
                collection_health(source, true, wall).is_none(),
                "no collection yet"
            );
            start_collection_health(source);
            assert_eq!(
                collection_health(source, true, wall).unwrap().state,
                ServerBackoff
            );
            defer_source_uploads(source, Duration::from_secs(1800));
            defer_source_uploads(source, Duration::from_secs(60));
            let status = collection_health(source, true, wall).unwrap();
            assert_eq!(status.state, ServerBackoff);
            assert_eq!(status.until.as_deref(), Some("2026-11-15T10:30:00Z"));
            assert!(status.last_scan_at.is_none());
            assert!(collection_health(source, false, wall).is_none());
        }
    });
}
