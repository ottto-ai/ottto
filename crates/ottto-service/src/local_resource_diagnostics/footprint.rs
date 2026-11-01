//! Bounded, process-wide footprint samples for local prepare/finish diagnostics.
use super::StateV2Memory;
use serde::Serialize;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::time::Duration;

const INTERVAL: Duration = Duration::from_millis(50);
const SLOTS: usize = 16;
const UNKNOWN: u64 = u64::MAX;
type Slots = [Option<Arc<Counters>>; SLOTS];

#[derive(Debug, Default, Serialize)]
pub(super) struct Observation {
    #[serde(skip_serializing_if = "Option::is_none")]
    stage_peak_footprint_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    stage_start_footprint_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    stage_end_footprint_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    footprint_samples: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    footprint_sample_failures: Option<u64>,
    #[serde(skip)]
    memory_end: StateV2Memory,
    #[serde(skip)]
    memory_peak: StateV2Memory,
}

#[derive(Debug)]
struct Metric {
    start: Option<u64>,
    end: AtomicU64,
    peak: AtomicU64,
    samples: AtomicU64,
    failures: AtomicU64,
}
impl Metric {
    fn new(start: Option<u64>) -> Self {
        let counters = Self {
            start,
            end: AtomicU64::new(UNKNOWN),
            peak: AtomicU64::new(0),
            samples: AtomicU64::new(0),
            failures: AtomicU64::new(0),
        };
        counters.record(start);
        counters
    }
    fn record(&self, sample: Option<u64>) {
        if let Some(bytes) = sample {
            self.peak.fetch_max(bytes, Relaxed);
            self.samples.fetch_add(1, Relaxed);
        } else {
            self.failures.fetch_add(1, Relaxed);
        }
    }
    fn observation(&self) -> Observation {
        let samples = self.samples.load(Relaxed);
        let end = self.end.load(Relaxed);
        Observation {
            stage_peak_footprint_bytes: (samples > 0).then(|| self.peak.load(Relaxed)),
            stage_start_footprint_bytes: self.start,
            stage_end_footprint_bytes: (end != UNKNOWN).then_some(end),
            footprint_samples: (samples > 0).then_some(samples),
            footprint_sample_failures: Some(self.failures.load(Relaxed)),
            ..Default::default()
        }
    }
}

#[derive(Debug)]
struct Counters {
    primary: Metric,
    resident: Metric,
    physical: Metric,
}
impl Counters {
    fn new(sample: StateV2Memory) -> Self {
        Self {
            primary: Metric::new(sample.phys_footprint_bytes.or(sample.rss_bytes)),
            resident: Metric::new(sample.rss_bytes),
            physical: Metric::new(sample.phys_footprint_bytes),
        }
    }
    fn record(&self, sample: StateV2Memory) {
        self.primary
            .record(sample.phys_footprint_bytes.or(sample.rss_bytes));
        self.resident.record(sample.rss_bytes);
        self.physical.record(sample.phys_footprint_bytes);
    }
    fn finish(&self, sample: StateV2Memory) {
        self.primary.end.store(
            sample
                .phys_footprint_bytes
                .or(sample.rss_bytes)
                .unwrap_or(UNKNOWN),
            Relaxed,
        );
        self.resident
            .end
            .store(sample.rss_bytes.unwrap_or(UNKNOWN), Relaxed);
        self.physical
            .end
            .store(sample.phys_footprint_bytes.unwrap_or(UNKNOWN), Relaxed);
        self.record(sample);
    }
    fn observation(&self) -> Observation {
        let resident = self.resident.observation();
        let physical = self.physical.observation();
        Observation {
            memory_end: StateV2Memory {
                rss_bytes: resident.stage_end_footprint_bytes,
                phys_footprint_bytes: physical.stage_end_footprint_bytes,
            },
            memory_peak: StateV2Memory {
                rss_bytes: resident.stage_peak_footprint_bytes,
                phys_footprint_bytes: physical.stage_peak_footprint_bytes,
            },
            ..self.primary.observation()
        }
    }
}

#[derive(Debug)]
struct Sampler {
    slots: Mutex<Slots>,
    wake: Condvar,
    read: fn() -> StateV2Memory,
}
impl Sampler {
    fn new(read: fn() -> StateV2Memory) -> Self {
        Self {
            slots: Mutex::new(std::array::from_fn(|_| None)),
            wake: Condvar::new(),
            read,
        }
    }
    fn spawn(read: fn() -> StateV2Memory) -> Option<Arc<Self>> {
        let sampler = Arc::new(Self::new(read));
        let worker = sampler.clone();
        std::thread::Builder::new()
            .name("stage-footprint".into())
            .spawn(move || worker.run())
            .ok()?;
        Some(sampler)
    }
    fn run(&self) {
        let Ok(mut slots) = self.slots.lock() else {
            return;
        };
        loop {
            while slots.iter().all(Option::is_none) {
                let Ok(guard) = self.wake.wait(slots) else {
                    return;
                };
                slots = guard;
            }
            let Ok((guard, elapsed)) = self.wake.wait_timeout(slots, INTERVAL) else {
                return;
            };
            slots = guard;
            if elapsed.timed_out() {
                drop(slots);
                self.sample();
                let Ok(guard) = self.slots.lock() else {
                    return;
                };
                slots = guard;
            }
        }
    }
    /// The OS read runs outside the registry lock, so a slow reader never
    /// delays stage entry or exit. The sample lands only on stages that were
    /// open before the read and are still open after it.
    fn sample(&self) {
        let Some(open) = self.slots.lock().ok().map(|slots| slots.clone()) else {
            return;
        };
        if open.iter().all(Option::is_none) {
            return;
        }
        let sample = (self.read)();
        let Ok(slots) = self.slots.lock() else {
            return;
        };
        for (now, before) in slots.iter().zip(open.iter()) {
            if let (Some(now), Some(before)) = (now, before) {
                if Arc::ptr_eq(now, before) {
                    now.record(sample);
                }
            }
        }
    }
    fn begin(self: &Arc<Self>) -> Option<Stage> {
        let start = (self.read)();
        let mut slots = self.slots.lock().ok()?;
        let idle = slots.iter().all(Option::is_none);
        let index = slots.iter().position(Option::is_none)?;
        let counters = Arc::new(Counters::new(start));
        slots[index] = Some(counters.clone());
        if idle {
            self.wake.notify_one();
        }
        Some(Stage {
            sampler: self.clone(),
            index,
            counters,
        })
    }
}

/// Removing the slot and taking the endpoint share the sampling lock, so no
/// periodic sample can land outside this stage. Drop also closes panic paths.
#[derive(Debug)]
pub(super) struct Stage {
    sampler: Arc<Sampler>,
    index: usize,
    counters: Arc<Counters>,
}
impl Stage {
    pub(super) fn begin() -> Option<Self> {
        static SAMPLER: OnceLock<Option<Arc<Sampler>>> = OnceLock::new();
        SAMPLER
            .get_or_init(|| Sampler::spawn(current))
            .as_ref()?
            .begin()
    }
    pub(super) fn finish(&self) -> Observation {
        let open = |slots: &Slots| {
            slots[self.index]
                .as_ref()
                .is_some_and(|c| Arc::ptr_eq(c, &self.counters))
        };
        // Read the endpoint outside the registry lock; close under it.
        let still_open = self.sampler.slots.lock().is_ok_and(|slots| open(&slots));
        if still_open {
            let end = (self.sampler.read)();
            if let Ok(mut slots) = self.sampler.slots.lock() {
                if open(&slots) {
                    self.counters.finish(end);
                    slots[self.index] = None;
                }
            }
        }
        self.counters.observation()
    }
}
impl Drop for Stage {
    fn drop(&mut self) {
        self.finish();
    }
}

// A refused slot/thread start is an unavailable diagnostic attempt, never a
// reason to fail or delay source work. No retry or unbounded probe registry.
pub(super) fn unavailable() -> Observation {
    Observation {
        footprint_sample_failures: Some(1),
        ..Default::default()
    }
}

#[cfg(target_os = "macos")]
pub(super) fn current() -> StateV2Memory {
    #[repr(C)]
    #[derive(Default)]
    struct TaskVmInfo {
        virtual_size: u64,
        region_count: i32,
        page_size: i32,
        resident_size: u64,
        remaining: [u64; 15],
        phys_footprint: u64,
    }
    extern "C" {
        static mach_task_self_: libc::mach_port_t;
    }
    let mut vm = TaskVmInfo::default();
    let words = (std::mem::size_of::<TaskVmInfo>() / 4) as u32;
    let mut count = words;
    // SAFETY: task_info receives writable, correctly sized prefix buffers.
    unsafe {
        if libc::task_info(
            mach_task_self_,
            22,
            (&mut vm as *mut TaskVmInfo).cast(),
            &mut count,
        ) == 0
            && count >= 6
        {
            return StateV2Memory {
                rss_bytes: Some(vm.resident_size),
                phys_footprint_bytes: (count >= words).then_some(vm.phys_footprint),
            };
        }
        let mut basic = std::mem::zeroed::<libc::mach_task_basic_info>();
        let mut count = libc::MACH_TASK_BASIC_INFO_COUNT;
        if libc::task_info(
            mach_task_self_,
            libc::MACH_TASK_BASIC_INFO,
            (&mut basic as *mut libc::mach_task_basic_info).cast(),
            &mut count,
        ) == 0
            && count >= libc::MACH_TASK_BASIC_INFO_COUNT
        {
            return StateV2Memory {
                rss_bytes: Some(basic.resident_size),
                phys_footprint_bytes: None,
            };
        }
    }
    StateV2Memory::default()
}
#[cfg(target_os = "linux")]
pub(super) fn current() -> StateV2Memory {
    let rss_bytes = (|| {
        let statm = std::fs::read_to_string("/proc/self/statm").ok()?;
        let resident = statm.split_whitespace().nth(1)?.parse::<u64>().ok()?;
        // SAFETY: sysconf has no pointer arguments.
        let page_size = u64::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) }).ok()?;
        resident.checked_mul(page_size).filter(|_| page_size > 0)
    })();
    StateV2Memory {
        rss_bytes,
        phys_footprint_bytes: None,
    }
}
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub(super) fn current() -> StateV2Memory {
    StateV2Memory::default()
}

impl Observation {
    pub(super) fn memory(&self) -> (StateV2Memory, StateV2Memory) {
        (self.memory_end, self.memory_peak)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn sample(bytes: Option<u64>) -> StateV2Memory {
        StateV2Memory {
            rss_bytes: bytes,
            phys_footprint_bytes: None,
        }
    }

    #[test]
    fn slow_reader_never_holds_the_registry_lock() {
        static IN_READ: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
        static RELEASE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
        fn read() -> StateV2Memory {
            IN_READ.store(true, Relaxed);
            while !RELEASE.load(Relaxed) {
                std::thread::sleep(Duration::from_millis(1));
            }
            sample(Some(10))
        }
        let sampler = Arc::new(Sampler::new(|| sample(Some(10))));
        let stage = sampler.begin().unwrap();
        let slow = Arc::new(Sampler {
            slots: Mutex::new(sampler.slots.lock().unwrap().clone()),
            wake: Condvar::new(),
            read,
        });
        struct Release(Option<std::thread::JoinHandle<()>>);
        impl Drop for Release {
            fn drop(&mut self) {
                RELEASE.store(true, Relaxed);
                if let Some(handle) = self.0.take() {
                    let _ = handle.join();
                }
            }
        }
        let worker = slow.clone();
        // Released and joined on every exit, including a failed assertion.
        let release = Release(Some(std::thread::spawn(move || worker.sample())));
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while !IN_READ.load(Relaxed) && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(1));
        }
        assert!(IN_READ.load(Relaxed));
        // The registry stays free for stage entry/exit during the OS read.
        assert!(slow.slots.try_lock().is_ok());
        slow.slots.lock().unwrap()[stage.index] = None;
        drop(release);
        // The stage closed mid-read, so the late sample never lands on it.
        assert_eq!(stage.counters.primary.samples.load(Relaxed), 1);
        drop(stage);
    }

    #[test]
    fn unavailable_samples_are_unknown_and_counted() {
        let sampler = Arc::new(Sampler::new(|| sample(None)));
        let stage = sampler.begin().unwrap();
        sampler.sample();
        let observation = stage.finish();
        assert!(observation.stage_start_footprint_bytes.is_none());
        assert!(observation.stage_peak_footprint_bytes.is_none());
        assert!(observation.stage_end_footprint_bytes.is_none());
        assert!(observation.footprint_samples.is_none());
        assert_eq!(observation.footprint_sample_failures, Some(3));
        assert_eq!(unavailable().footprint_sample_failures, Some(1));
    }

    #[test]
    fn overlapping_stages_have_independent_peaks_and_endpoints() {
        fn read() -> StateV2Memory {
            static NEXT: AtomicU64 = AtomicU64::new(10);
            sample(Some(NEXT.fetch_add(10, Relaxed)))
        }
        let sampler = Arc::new(Sampler::new(read));
        let first = sampler.begin().unwrap(); // 10
        let second = sampler.begin().unwrap(); // 20
        sampler.sample(); // 30, both
        let first_row = first.finish(); // 40
        sampler.sample(); // 50, second only
        let second_row = second.finish(); // 60
        assert_eq!(first_row.stage_start_footprint_bytes, Some(10));
        assert_eq!(first_row.stage_peak_footprint_bytes, Some(40));
        assert_eq!(first_row.stage_end_footprint_bytes, Some(40));
        assert_eq!(first_row.footprint_samples, Some(3));
        assert_eq!(second_row.stage_start_footprint_bytes, Some(20));
        assert_eq!(second_row.stage_peak_footprint_bytes, Some(60));
        assert_eq!(second_row.footprint_samples, Some(4));
        // Reusing a slot must not let a finished guard close its successor.
        let third = sampler.begin().unwrap();
        drop(first);
        assert!(sampler.slots.lock().unwrap()[third.index].is_some());
        for row in [first_row, second_row, third.finish()] {
            assert!(row.stage_peak_footprint_bytes >= row.stage_start_footprint_bytes);
            assert!(row.stage_peak_footprint_bytes >= row.stage_end_footprint_bytes);
        }
    }

    #[test]
    fn periodic_peak_survives_lower_end_and_partial_reader_failure() {
        let sampler = Arc::new(Sampler::new(|| sample(Some(10))));
        let stage = sampler.begin().unwrap();
        stage.counters.record(sample(Some(100)));
        stage.counters.record(sample(None));
        let row = stage.finish();
        assert_eq!(row.stage_peak_footprint_bytes, Some(100));
        assert_eq!(row.stage_start_footprint_bytes, Some(10));
        assert_eq!(row.stage_end_footprint_bytes, Some(10));
        assert_eq!(row.footprint_samples, Some(3));
        assert_eq!(row.footprint_sample_failures, Some(1));
    }

    #[test]
    fn slots_are_bounded_and_unwinding_releases_them() {
        let sampler = Arc::new(Sampler::new(|| sample(Some(10))));
        let mut stages: Vec<_> = (0..SLOTS).map(|_| sampler.begin().unwrap()).collect();
        assert!(sampler.begin().is_none());
        stages.pop();
        assert!(std::panic::catch_unwind(|| {
            let _stage = sampler.begin().unwrap();
            panic!("synthetic stage failure");
        })
        .is_err());
        assert!(sampler.begin().is_some());
        drop(stages);
        assert!(sampler.slots.lock().unwrap().iter().all(Option::is_none));
    }

    #[test]
    fn background_sampler_parks_and_stops_counting_after_end() {
        static READS: AtomicU64 = AtomicU64::new(0);
        fn read() -> StateV2Memory {
            READS.fetch_add(1, Relaxed);
            sample(Some(100))
        }
        let sampler = Sampler::spawn(read).unwrap();
        let stage = sampler.begin().unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while stage.counters.primary.samples.load(Relaxed) < 3
            && std::time::Instant::now() < deadline
        {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(stage.counters.primary.samples.load(Relaxed) >= 3);
        let ended = stage.finish().footprint_samples;
        let reads = READS.load(Relaxed);
        std::thread::sleep(INTERVAL * 3);
        assert_eq!(stage.finish().footprint_samples, ended);
        assert_eq!(READS.load(Relaxed), reads);
        // The one test worker remains parked until the test process exits.
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn native_reader_returns_current_bytes() {
        assert!(current().rss_bytes.is_some_and(|bytes| bytes > 0));
    }
}
