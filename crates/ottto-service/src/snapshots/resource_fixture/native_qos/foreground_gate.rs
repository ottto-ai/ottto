//! Operator-only paired latency gate. This stays under native_qos so Linux's
//! resource calibration excludes it while still compiling the portable body.
use super::*;
use std::io::{Read, Seek, SeekFrom};
use std::time::{Duration, Instant};

const PERIOD: Duration = Duration::from_millis(50);
const MIB: f64 = 1024.0 * 1024.0;

fn usage() -> (u64, u64) {
    crate::local_resource_diagnostics::resource_gate_usage().expect("getrusage required")
}
fn thread_cpu() -> f64 {
    let mut time: libc::timespec = unsafe { std::mem::zeroed() };
    // CLOCK_THREAD_CPUTIME_ID measures this importer, independently of the probe.
    assert_eq!(
        unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, &mut time) },
        0
    );
    time.tv_sec as f64 + time.tv_nsec as f64 / 1e9
}
fn energy() -> Option<u64> {
    #[cfg(target_os = "macos")]
    {
        let mut info: libc::rusage_info_v4 = unsafe { std::mem::zeroed() };
        // SAFETY: v4 buffer and flavor match the system ABI. Billed energy is nJ.
        if unsafe { libc::proc_pid_rusage(libc::getpid(), 4, (&raw mut info).cast()) } == 0 {
            return (info.ri_billed_energy > 0).then_some(info.ri_billed_energy);
        }
    }
    None
}
fn energy_delta(before: Option<u64>, after: Option<u64>) -> Option<f64> {
    after
        .zip(before)
        .and_then(|(a, b)| a.checked_sub(b))
        .map(|n| n as f64 / 1e9)
}
fn display_energy(value: Option<f64>) -> String {
    value.map_or_else(|| "unavailable".into(), |n| format!("{n:.6}"))
}
fn percentile(values: &mut [f64], percent: usize) -> f64 {
    assert!(!values.is_empty());
    values.sort_unstable_by(f64::total_cmp);
    values[(values.len() * percent).div_ceil(100) - 1]
}
#[derive(Default)]
struct Latencies {
    cpu: Vec<f64>,
    io: Vec<f64>,
    late: Vec<f64>,
}
impl Latencies {
    fn report(&mut self, phase: usize, on: bool) -> [f64; 2] {
        let mut p95 = [0.0; 2];
        for (i, (unit, samples)) in [("cpu", &mut self.cpu), ("io", &mut self.io)]
            .into_iter()
            .enumerate()
        {
            let p50 = percentile(samples, 50);
            p95[i] = percentile(samples, 95);
            let p99 = percentile(samples, 99);
            println!("resource_native_first_import_phase phase={phase} on={on} unit={unit} samples={} p50_ms={p50:.6} p95_ms={:.6} p99_ms={p99:.6}", samples.len(), p95[i]);
        }
        println!(
            "resource_native_first_import_schedule phase={phase} lateness_p95_ms={:.6}",
            percentile(&mut self.late, 95)
        );
        p95
    }
}
fn foreground(path: &Path, seconds: u64, ready: std::sync::mpsc::SyncSender<Instant>) -> Latencies {
    let _qos = schedule::native_set_qos(0x19); // QOS_CLASS_USER_INITIATED
    assert_eq!(schedule::native_qos().0, 0x19);
    let cpu = vec![0x5a; 1024 * 1024];
    let io = vec![0xa5; 256 * 1024];
    let mut readback = vec![0; io.len()];
    let mut file = fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .read(true)
        .write(true)
        .open(path)
        .unwrap();
    let mut samples = Latencies::default();
    let start = Instant::now();
    ready.send(start).unwrap();
    // Fixed sample count: never omit a slow unit or reset the 50-ms schedule.
    for n in 0..seconds * 20 {
        let due = start + PERIOD * u32::try_from(n).unwrap();
        std::thread::sleep(due.saturating_duration_since(Instant::now()));
        let began = Instant::now();
        samples
            .late
            .push(began.duration_since(due).as_secs_f64() * 1000.0);
        std::hint::black_box(Sha256::digest(std::hint::black_box(&cpu)));
        // Include CPU dispatch delay: descheduling cannot improve the receipt.
        samples.cpu.push(due.elapsed().as_secs_f64() * 1000.0);
        let began = Instant::now();
        file.seek(SeekFrom::Start(0)).unwrap();
        file.write_all(&io).unwrap();
        file.sync_all().unwrap();
        file.seek(SeekFrom::Start(0)).unwrap();
        file.read_exact(&mut readback).unwrap();
        assert_eq!(io, readback);
        samples.io.push(began.elapsed().as_secs_f64() * 1000.0);
    }
    std::thread::sleep(
        (start + Duration::from_secs(seconds)).saturating_duration_since(Instant::now()),
    );
    samples
}
fn ratios(phases: &[[f64; 2]], unit: usize) -> [f64; 3] {
    std::array::from_fn(|pair| {
        let on = pair * 2 + 1;
        // Six phases have no trailing off: the final on uses its sole adjacent off.
        let off = if on + 1 < phases.len() {
            (phases[on - 1][unit] + phases[on + 1][unit]) / 2.0
        } else {
            phases[on - 1][unit]
        };
        assert!(off > 0.0 && off.is_finite());
        phases[on][unit] / off
    })
}

/// [behaviour] Native foreground latency under real byte-bound first-import pages.
#[test]
#[ignore = "release operator native macOS PR gate only; never merge_group"]
fn resource_native_first_import_foreground_gate() {
    assert_eq!(std::env::consts::OS, "macos", "native Mac required");
    let pr = std::env::var("OTTTO_RESOURCE_QOS_PR").expect("validated PR binding required");
    assert!(pr.parse::<u64>().is_ok_and(|n| n > 0));
    let head = std::env::var("OTTTO_RESOURCE_QOS_HEAD").expect("validated PR head required");
    assert!(head.len() == 40 && head.bytes().all(|b| b.is_ascii_hexdigit()));
    if let Ok(event) = std::env::var("GITHUB_EVENT_NAME") {
        assert_eq!(event, "pull_request");
    }
    let seconds = std::env::var("OTTTO_RESOURCE_GATE_PHASE_SECONDS")
        .map(|s| {
            s.parse::<u64>()
                .expect("phase duration must be integer seconds")
        })
        .unwrap_or(120);
    assert!((1..=3600).contains(&seconds));
    schedule::native_worker(|| {
        // At default D: 2048 x 16 MiB = 32 GiB, streamed in bounded buffers.
        // A depleted or otherwise non-byte-bound corpus aborts, never earns PASS.
        let files = usize::try_from((seconds * 2048).div_ceil(120).max(64)).unwrap();
        let corpus = Corpus::generate_sized([0, files, 0], Some(16 * 1024 * 1024));
        println!("resource_native_first_import_setup files={files} bytes={} phase_seconds={seconds} samples_per_unit_per_phase={} smoke={}", corpus.manifest.bytes[1], seconds * 20, seconds != 120);
        let _default = schedule::native_set_qos(0x15);
        let mut driver = Driver::new(&corpus, 1);
        schedule::with_power("ac", || {
            // Real warm-up page establishes first-import byte exhaustion before
            // the first paced entry. No delivery transport/client exists in Driver:
            // exact_acks_for_test and the in-process ledger settle its outputs.
            driver.page(2000);
            assert!(driver.last_byte_bound_first_import);
            let mut phases = Vec::new();
            let (mut pages, mut cpu, mut wall, mut joules) = (0u64, 0.0, 0.0, Some(0.0));
            let mut rss = usage().1;
            for phase in 0..6 {
                let on = phase % 2 == 1;
                let ((mut samples, process_cpu, importer_cpu, elapsed, billed), completed) =
                    std::thread::scope(|scope| {
                        let (send, receive) = std::sync::mpsc::sync_channel(0);
                        let path = corpus.support.join("foreground-probe.bin");
                        let probe = scope.spawn(move || foreground(&path, seconds, send));
                        let start = receive.recv().unwrap();
                        let before = usage().0;
                        let thread_before = thread_cpu();
                        let energy_before = energy();
                        let mut completed = 0;
                        while on && start.elapsed() < Duration::from_secs(seconds) {
                            with_scan_clock(EPOCH + 2000, || {
                                schedule::finished_first_import(SOURCES[1], true)
                            });
                            // The production request policy must leave no waiting gap.
                            with_scan_clock(EPOCH + 2000, || assert!(schedule::due(SOURCES[1])));
                            let trace = observed(&mut driver, 2000);
                            assert!(
                                matches(&trace, SOURCES[1], 0x11),
                                "UTILITY entry required: {trace:?}"
                            );
                            assert!(
                                driver.last_byte_bound_first_import,
                                "corpus depleted or page ceased to be byte-bound"
                            );
                            completed += 1;
                        }
                        if !on {
                            std::thread::sleep(
                                (start + Duration::from_secs(seconds))
                                    .saturating_duration_since(Instant::now()),
                            );
                        }
                        let elapsed = start.elapsed().as_secs_f64();
                        let importer_cpu = thread_cpu() - thread_before;
                        let billed = energy_delta(energy_before, energy());
                        let after = usage();
                        rss = rss.max(after.1);
                        (
                            (
                                probe.join().unwrap(),
                                (after.0 - before) as f64 / 1e6,
                                importer_cpu,
                                elapsed,
                                billed,
                            ),
                            completed,
                        )
                    });
                assert!(!on || completed > 0, "no importer page completed");
                phases.push(samples.report(phase, on));
                println!("resource_native_first_import_metrics phase={phase} on={on} process_cpu_s={process_cpu:.6} importer_cpu_share={:.6} rss_max_mib={:.3} energy_j={} pages={completed} wall_s={elapsed:.6} thermal=unavailable->unavailable", importer_cpu / elapsed, rss as f64 / MIB, display_energy(billed));
                if on {
                    pages += completed;
                    cpu += importer_cpu;
                    wall += elapsed;
                    joules = joules.zip(billed).map(|(a, b)| a + b);
                }
            }
            let cpu_ratio = percentile(&mut ratios(&phases, 0), 50);
            let io_ratio = percentile(&mut ratios(&phases, 1), 50);
            let rss_mib = rss.max(usage().1) as f64 / MIB;
            let pass = cpu_ratio <= 1.05 && io_ratio <= 1.05 && rss_mib <= 500.0;
            println!("resource_native_first_import_gate pr={pr} head={head} cpu_p95_ratio={cpu_ratio:.6} io_p95_ratio={io_ratio:.6} rss_max_mib={rss_mib:.3} importer_cpu_share={:.6} energy_j={} pages={pages} thermal=unavailable->unavailable verdict={}", cpu / wall, display_energy(joules), if pass { "pass" } else { "fail" });
            assert!(pass, "paired foreground latency/RSS gate failed");
        });
    });
}
