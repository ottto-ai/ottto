//! Counts/bytes/times only. Reuse #799 and its bounded process sampler.
use super::*;
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, SystemTime};

#[derive(Default, Serialize)]
struct Stats {
    events: BTreeMap<&'static str, u64>,
    labels: BTreeMap<&'static str, BTreeMap<String, u64>>,
    latest: BTreeMap<&'static str, serde_json::Value>,
    cpu_per_pass_us: Distribution,
    rss_bytes: Rss,
    import_peak_rss_bytes: Option<u64>,
    v1_load_peak_rss_bytes: Option<u64>,
    import_exceeds_v1_load: Option<bool>,
    comparison_same_process_corpus: bool,
    #[serde(skip)]
    v1_path: Option<std::path::PathBuf>,
}
#[derive(Default, Serialize)]
struct Rss {
    steady: Option<u64>,
    peak: Option<u64>,
}
#[derive(Default, Serialize)]
struct Distribution {
    p50: Option<u64>,
    p95: Option<u64>,
    max: Option<u64>,
    #[serde(skip)]
    samples: Vec<u64>,
    #[serde(skip)]
    cursor: usize,
}
impl Distribution {
    fn observe(&mut self, n: u64) {
        if self.samples.len() < 128 {
            self.samples.push(n);
        } else {
            self.samples[self.cursor] = n;
        }
        self.cursor = (self.cursor + 1) % 128;
        let mut sorted = self.samples.clone();
        sorted.sort_unstable();
        self.p50 = Some(sorted[(sorted.len() * 50).div_ceil(100) - 1]);
        self.p95 = Some(sorted[(sorted.len() * 95).div_ceil(100) - 1]);
        self.max = Some(self.max.unwrap_or(0).max(n));
    }
}
fn stats() -> &'static Mutex<Stats> {
    static STATS: OnceLock<Mutex<Stats>> = OnceLock::new();
    STATS.get_or_init(|| Mutex::new(Stats::default()))
}
pub(super) fn event(name: &'static str, value: &impl Serialize) {
    if let Ok(mut stats) = stats().lock() {
        let count = stats.events.entry(name).or_default();
        *count = count.saturating_add(1);
        if let Ok(value) = serde_json::to_value(value) {
            if let Some(label) = value.as_str().filter(|s| s.len() <= 64) {
                let counts = stats.labels.entry(name).or_default();
                if counts.contains_key(label) || counts.len() < 64 {
                    let count = counts.entry(label.to_owned()).or_default();
                    *count = count.saturating_add(1);
                }
            }
            stats.latest.insert(name, value);
        }
        crate::local_resource_diagnostics::claude_state_v2(&*stats);
    }
}
#[derive(Clone, Copy)]
pub(super) enum Kind {
    Save,
    Hydrate,
    Import,
    V1,
}
pub(in super::super) struct Stage {
    kind: Kind,
    probe: crate::local_resource_diagnostics::StateV2Probe,
    path: Option<std::path::PathBuf>,
    finished: bool,
}
impl Stage {
    pub(super) fn new(kind: Kind) -> Self {
        Self {
            kind,
            probe: crate::local_resource_diagnostics::StateV2Probe::begin(),
            path: None,
            finished: false,
        }
    }
    pub(in super::super) fn v1(path: &Path) -> Option<Self> {
        // OFF has no probe/thread/allocation side effects. Only opted-in Claude
        // paths have route state before the mapper pauses the conversion.
        if !super::runtime::observed(path) {
            return None;
        }
        let mut stage = Self::new(Kind::V1);
        stage.path = Some(path.to_owned());
        Some(stage)
    }
    pub(in super::super) fn finish(mut self) {
        self.record();
    }
    fn record(&mut self) {
        if self.finished {
            return;
        }
        self.finished = true;
        let (cpu, steady, peak) = self.probe.finish();
        if let Ok(mut stats) = stats().lock() {
            match self.kind {
                Kind::V1 => {
                    stats.v1_load_peak_rss_bytes = peak;
                    stats.v1_path = self.path.take();
                }
                Kind::Import => {
                    stats.import_peak_rss_bytes = peak;
                    stats.comparison_same_process_corpus = self
                        .path
                        .as_ref()
                        .is_some_and(|p| stats.v1_path.as_ref() == Some(p));
                    stats.import_exceeds_v1_load = if stats.comparison_same_process_corpus {
                        peak.zip(stats.v1_load_peak_rss_bytes).map(|(a, b)| a > b)
                    } else {
                        None
                    };
                }
                Kind::Save | Kind::Hydrate => {
                    if let Some(cpu) = cpu {
                        stats.cpu_per_pass_us.observe(cpu);
                    }
                    stats.rss_bytes.steady = steady;
                    stats.rss_bytes.peak = stats.rss_bytes.peak.into_iter().chain(peak).max();
                }
            }
            crate::local_resource_diagnostics::claude_state_v2(&*stats);
        }
    }
    pub(super) fn import(path: &Path) -> Self {
        let mut stage = Self::new(Kind::Import);
        stage.path = Some(path.to_owned());
        stage
    }
}
impl Drop for Stage {
    fn drop(&mut self) {
        self.record();
    }
}

pub(super) fn baseline(path: &Path) {
    let age = std::fs::metadata(super::fence::sibling(path, ".v1-readonly"))
        .ok()
        .and_then(|m| m.modified().ok())
        .and_then(|t| SystemTime::now().duration_since(t).ok());
    event("baseline_age_s", &age.map(|d| d.as_secs()));
    event(
        "baseline_14day_escalation_alarm",
        &age.map(|age| age >= Duration::from_secs(14 * 86400)),
    );
}
