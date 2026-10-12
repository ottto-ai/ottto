//! Same-contract and resource evidence from synthetic input, in isolated child
//! test processes. Ignored resource probes run only in the explicit CI step.
use super::*;
use std::cell::Cell;
use std::io::{BufReader, Read};

thread_local! {
    static READ_BYTES: Cell<u64> = const { Cell::new(0) };
}

fn wide_window() -> DateWindow {
    DateWindow {
        floor: Date::from_calendar_date(2026, Month::October, 4).unwrap(),
        today: Date::from_calendar_date(2026, Month::October, 5).unwrap(),
    }
}

struct CountedFile(fs::File);
impl Read for CountedFile {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        let size = self.0.read(bytes)?;
        READ_BYTES.with(|cell| cell.set(cell.get() + size as u64));
        Ok(size)
    }
}

fn payload(report: &WorkspaceReport, source: &str) -> Value {
    let request = build_request(
        report,
        Path::new("/synthetic/workspace"),
        "synthetic",
        source,
        false,
    );
    match request {
        Some(mut request) => {
            request.captured_at = "2026-10-05T12:00:00Z".into();
            serde_json::to_value(request).unwrap()
        }
        None => Value::Null,
    }
}

fn parse_baseline(
    case: &parity_fixtures::Case,
    path: &Path,
    report: &mut WorkspaceReport,
) -> std::io::Result<()> {
    if case.claude {
        parity_baseline::parse_claude_session(path, report, wide_window().today, !case.exclude)
    } else {
        parity_baseline::parse_codex_session(path, report, wide_window().today)
    }
}

#[test]
fn all_fifteen_complete_payloads_match_whole_file_oracle() {
    let mut charge = 0u64;
    for case in parity_fixtures::cases() {
        let path = temp_path(case.name);
        fs::write(&path, &case.bytes).unwrap();
        let mut before = WorkspaceReport::new(wide_window());
        let mut after = WorkspaceReport::new(wide_window());
        let baseline = parse_baseline(&case, &path, &mut before);
        READ_BYTES.with(|cell| cell.set(0));
        let candidate = parse_session_reader(
            BufReader::new(CountedFile(fs::File::open(&path).unwrap())),
            &path,
            &mut after,
            wide_window().today,
            case.claude,
            !case.exclude,
        );
        assert_eq!(
            baseline.as_ref().err().map(|e| e.kind()),
            candidate.as_ref().err().map(|e| e.kind()),
            "{}",
            case.name
        );
        let source = if case.claude { "claude-code" } else { "codex" };
        assert_eq!(
            payload(&before, source),
            payload(&after, source),
            "{}",
            case.name
        );
        // Every successful parse must consume exactly the file body once. For
        // failed UTF-8 cases charge a conservative complete-file bound instead.
        if candidate.is_ok() {
            assert_eq!(
                READ_BYTES.with(Cell::get),
                case.bytes.len() as u64,
                "{}",
                case.name
            );
        }
        charge += 2 * case.bytes.len() as u64;
        fs::remove_file(path).unwrap();
    }
    assert!(charge < 32 * 1024 * 1024);
}

#[test]
fn late_utf8_and_read_errors_do_not_commit_partial_facts() {
    let row = b"{\"type\":\"attachment\",\"attachment\":{\"content\":\"valid\"}}\n";
    for claude in [true, false] {
        let row = if claude {
            row.as_slice()
        } else {
            b"{\"payload\":{\"type\":\"function_call_output\",\"output\":\"valid\"}}\n".as_slice()
        };
        let mut bytes = row.to_vec();
        bytes.extend_from_slice(b"\xff\n");
        let mut report = WorkspaceReport::new(wide_window());
        let error = parse_session_reader(
            std::io::Cursor::new(bytes),
            Path::new("fixture.jsonl"),
            &mut report,
            wide_window().today,
            claude,
            true,
        )
        .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert!(report.daily.is_empty() && report.files.is_empty() && report.sessions.is_empty());
    }
    struct FailAfterRow {
        bytes: std::io::Cursor<Vec<u8>>,
    }
    impl Read for FailAfterRow {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            if self.bytes.position() == self.bytes.get_ref().len() as u64 {
                Err(std::io::Error::other("synthetic read failure"))
            } else {
                self.bytes.read(buffer)
            }
        }
    }
    let mut report = WorkspaceReport::new(wide_window());
    assert!(parse_session_reader(
        BufReader::new(FailAfterRow {
            bytes: std::io::Cursor::new(row.to_vec())
        }),
        Path::new("fixture.jsonl"),
        &mut report,
        wide_window().today,
        true,
        true
    )
    .is_err());
    assert!(report.daily.is_empty() && report.files.is_empty() && report.sessions.is_empty());
}

#[test]
fn replacement_during_read_refuses_new_report_and_preserves_cache() {
    let directory = crate::test_scratch::ScratchDir::new("composition-read-fence");
    let path = directory.join("fixture.jsonl");
    fs::write(
        &path,
        b"{\"type\":\"attachment\",\"attachment\":{\"content\":\"valid\"}}\n",
    )
    .unwrap();
    let scan = cache_scan(&path);
    let signature = test_signature(&scan);
    let cache_file = directory.join("cache.json");
    write_cache(&cache_file, &test_cache(&scan, wide_window()));
    let original_cache = fs::read(&cache_file).unwrap();
    let changed_path = path.clone();
    let old_path = directory.join("opened-file");
    FILE_READ_HOOK.with(|cell| {
        assert!(cell.borrow().is_none());
        *cell.borrow_mut() = Some(FileReadHook {
            path: path.clone(),
            callback: Box::new(move || {
                fs::rename(&changed_path, &old_path).unwrap();
                fs::write(&changed_path, b"replacement").unwrap();
            }),
        });
    });
    assert!(build_report_for_scan(
        &scan,
        &signature,
        SnapshotSource::ClaudeCode,
        wide_window(),
        Instant::now() + Duration::from_secs(30)
    )
    .is_none());
    FILE_READ_HOOK.with(|cell| {
        assert!(
            cell.borrow().is_none(),
            "actual read hook must have been consumed"
        )
    });
    assert_eq!(fs::read(&cache_file).unwrap(), original_cache);
}

#[cfg(unix)]
fn cpu_seconds() -> f64 {
    let mut usage = std::mem::MaybeUninit::<libc::rusage>::uninit();
    assert_eq!(
        unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) },
        0
    );
    let usage = unsafe { usage.assume_init() };
    (usage.ru_utime.tv_sec + usage.ru_stime.tv_sec) as f64
        + (usage.ru_utime.tv_usec + usage.ru_stime.tv_usec) as f64 / 1_000_000.0
}

#[cfg(unix)]
#[test]
#[ignore = "isolated child entry point for bounded synthetic resource receipt"]
fn resource_sample() {
    let name = std::env::var("OTTTO_COMPOSITION_SAMPLE_CASE").unwrap();
    let baseline = std::env::var("OTTTO_COMPOSITION_SAMPLE_MODE").unwrap() == "baseline";
    let case = parity_fixtures::cases()
        .into_iter()
        .find(|c| c.name == name)
        .unwrap();
    // The directory is isolated per subprocess but the basename is identical:
    // missing provider session metadata legitimately falls back to that name.
    // Keep the identity input equal instead of normalizing session hashes away.
    let directory = crate::test_scratch::private_dir("composition-resource-sample");
    let path = directory.join(format!("{}.jsonl", case.name));
    fs::write(&path, &case.bytes).unwrap();
    let mut report = WorkspaceReport::new(wide_window());
    READ_BYTES.with(|cell| cell.set(0));
    let ((outcome, wall_seconds, cpu_delta), heap) = crate::retry_allocation_probe::measure(|| {
        let cpu = cpu_seconds();
        let wall = Instant::now();
        let outcome = if baseline {
            parse_baseline(&case, &path, &mut report)
        } else {
            parse_session_reader(
                BufReader::new(CountedFile(fs::File::open(&path).unwrap())),
                &path,
                &mut report,
                wide_window().today,
                case.claude,
                !case.exclude,
            )
        };
        (outcome, wall.elapsed().as_secs_f64(), cpu_seconds() - cpu)
    });
    let source = if case.claude { "claude-code" } else { "codex" };
    let request = payload(&report, source);
    let serialized_bytes = serde_json::to_vec(&request).unwrap().len();
    let actual_candidate_reads = READ_BYTES.with(Cell::get);
    if !baseline && outcome.is_ok() {
        assert_eq!(actual_candidate_reads, case.bytes.len() as u64);
    }
    println!(
        "COMPOSITION_SAMPLE {}",
        json!({
            "case":name,"mode":if baseline {"baseline"} else {"candidate"},
            "error":outcome.err().map(|e|format!("{:?}",e.kind())),"payload":request,
            "parse_cpu_seconds":cpu_delta,"parse_wall_seconds":wall_seconds,
            "requested_heap_peak_bytes":heap.requested_peak,"retained_report_heap_bytes":heap.requested_live,
        "requested_heap_peak_with_overlap_bytes":heap.requested_peak_with_overlap,
        "usable_heap_peak_bytes":heap.usable_peak,
            "serialized_payload_bytes":serialized_bytes,"source_bytes":case.bytes.len(),
            "candidate_read_bytes":if baseline {Value::Null} else {json!(actual_candidate_reads)},
            "read_charge_upper_bound_bytes":case.bytes.len(),
        })
    );
    fs::remove_file(path).unwrap();
    fs::remove_dir(directory).unwrap();
}

#[cfg(unix)]
#[test]
#[ignore = "CI-only bounded parity/resource experiment; no live input"]
fn compact_resource_receipt() {
    let cases = parity_fixtures::cases();
    let mut charge = 0u64;
    let mut observations = Vec::new();
    for case in cases {
        for repetition in 0..case.repetitions {
            let mut pair = Vec::new();
            let modes = if repetition % 2 == 0 {
                ["baseline", "candidate"]
            } else {
                ["candidate", "baseline"]
            };
            for mode in modes {
                charge += case.bytes.len() as u64;
                assert!(
                    charge <= 64 * 1024 * 1024,
                    "bounded synthetic sample read charge"
                );
                let output = std::process::Command::new(std::env::current_exe().unwrap())
                    .args([
                        "--exact",
                        "context_composition::tests::parity_resource::resource_sample",
                        "--ignored",
                        "--nocapture",
                        "--test-threads=1",
                    ])
                    .env("OTTTO_COMPOSITION_SAMPLE_CASE", case.name)
                    .env("OTTTO_COMPOSITION_SAMPLE_MODE", mode)
                    .output()
                    .unwrap();
                assert!(
                    output.status.success(),
                    "{}",
                    String::from_utf8_lossy(&output.stderr)
                );
                let stdout = String::from_utf8(output.stdout).unwrap();
                let marker = "COMPOSITION_SAMPLE ";
                let text = stdout
                    .lines()
                    .find_map(|line| line.find(marker).map(|i| &line[i + marker.len()..]))
                    .expect("one executed sample required");
                let result: Value = serde_json::from_str(text).unwrap();
                pair.push(result.clone());
                observations.push(result);
            }
            assert_eq!(pair[0]["payload"], pair[1]["payload"], "{}", case.name);
            assert_eq!(pair[0]["error"], pair[1]["error"], "{}", case.name);
            assert_eq!(
                pair[0]["source_bytes"], pair[1]["source_bytes"],
                "{}",
                case.name
            );
            assert_eq!(
                pair[0]["serialized_payload_bytes"], pair[1]["serialized_payload_bytes"],
                "{}",
                case.name
            );
        }
    }
    println!(
        "COMPOSITION_RESOURCE_RECEIPT {}",
        json!({
            "scope":"synthetic-only, same-profile isolated parser processes; not installed RSS or physical disk reads",
            "all_fields_equal":true,"read_charge_upper_bound_bytes":charge,
            "normal_parity_upper_bound_bytes":32*1024*1024,
            "total_proof_budget_bytes":128*1024*1024,
            "source_read_accounting":"baseline whole-file logical bound; candidate successful-read bytes counted; failed cases charged full length",
            "allocator":"requested Rust allocations on parsing thread, excludes allocator overhead/mmap/RSS",
            "observations":observations,
        })
    );
}
