//! Test adapter for the real cadence/account-switch owners; no alternate policy.
use super::*;
use continuation::PlatformState;
thread_local! {
    static POWER: std::cell::Cell<Option<PlatformState>> = const { std::cell::Cell::new(None) };
}
pub(super) fn test_power() -> Option<PlatformState> {
    POWER.with(std::cell::Cell::get)
}
pub(crate) fn with_power<T>(power: &str, run: impl FnOnce() -> T) -> T {
    struct Reset {
        power: Option<PlatformState>,
        cadences: BTreeMap<&'static str, SourceCadence>,
    }
    impl Drop for Reset {
        fn drop(&mut self) {
            POWER.with(|p| p.set(self.power));
            *source_cadences().lock().unwrap() = std::mem::take(&mut self.cadences);
        }
    }
    let power = match power {
        "ac" => PlatformState::Allowed,
        "battery" => PlatformState::Battery,
        "lpm" => PlatformState::Refused,
        "unknown" => PlatformState::Unknown,
        _ => panic!("power"),
    };
    let _reset = Reset {
        power: POWER.with(|p| p.replace(Some(power))),
        cadences: std::mem::take(&mut *source_cadences().lock().unwrap()),
    };
    run()
}
pub(crate) fn due(source: SnapshotSource) -> bool {
    source_cadence_wait(source).is_none()
}
pub(crate) fn event(source: SnapshotSource) {
    with_source_cadence(source, |c| c.record_file_event(crate::scan_clock::now())).unwrap();
}
pub(crate) fn finished(source: SnapshotSource, uploaded: u64, paced: bool) {
    with_source_cadence(source, |c| {
        c.record_scan_success(crate::scan_clock::now(), uploaded)
    })
    .unwrap();
    if paced {
        continuation::request_resident_scan(source);
    }
}
pub(crate) struct Switch(ClaudeAccountSwitchProbe);
impl Switch {
    pub(crate) fn new() -> Self {
        Self(ClaudeAccountSwitchProbe::default())
    }
    pub(crate) fn observe(&mut self, value: &str) -> bool {
        if !self
            .0
            .observe(crate::scan_clock::now(), || Some(value.to_owned()))
        {
            return false;
        }
        with_source_cadence(SnapshotSource::ClaudeCode, |c| {
            c.record_account_switch(crate::scan_clock::now())
        })
        .unwrap();
        true
    }
}
pub(crate) fn needs_pacing(scan: &SourceScanResult) -> bool {
    continuation::resident_scan_requested(scan)
}
