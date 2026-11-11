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

#[cfg(target_os = "macos")]
pub(crate) fn native_source_qos(
    source: SnapshotSource,
) -> Option<continuation::MacPlatformSignals> {
    continuation::paced_source_qos(source, continuation::resident_background)
}
#[cfg(target_os = "macos")]
pub(crate) fn native_qos() -> (u32, i32) {
    continuation::resource_qos().expect("native QoS observation missing")
}
#[cfg(target_os = "macos")]
pub(crate) struct NativeQos((u32, i32));
#[cfg(target_os = "macos")]
impl Drop for NativeQos {
    fn drop(&mut self) {
        assert!(continuation::resource_set_qos(
            if self.0 .0 == 0 { 0x15 } else { self.0 .0 },
            self.0 .1
        ));
    }
}
#[cfg(target_os = "macos")]
pub(crate) fn native_set_qos(class: u32) -> NativeQos {
    let prior = native_qos();
    assert!(continuation::resource_set_qos(class, 0));
    NativeQos(prior)
}
#[cfg(target_os = "macos")]
pub(crate) fn native_background() -> continuation::MacPlatformSignals {
    continuation::MacPlatformSignals::background()
        .expect("native background QoS observation missing")
}
#[cfg(target_os = "macos")]
pub(crate) fn native_worker<T: Send>(run: impl FnOnce() -> T + Send) -> T {
    std::thread::scope(|scope| {
        std::thread::Builder::new()
            .name("resource-qos-pr".into())
            .stack_size(SNAPSHOT_SYNC_WORKER_STACK_BYTES)
            .spawn_scoped(scope, run)
            .unwrap()
            .join()
            .unwrap()
    })
}
