#[cfg(target_os = "macos")]
use ottto_core::user_launchctl_domain;
use ottto_core::MACOS_LEGACY_LAUNCH_AGENT_LABEL;
use serde::Serialize;
#[cfg(target_os = "macos")]
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
#[cfg(target_os = "macos")]
use std::process::{Command, Stdio};

#[cfg(target_os = "macos")]
const LAUNCHCTL: &str = "/bin/launchctl";
pub const LEGACY_SMAPP_SERVICE_PLIST_NAME: &str = "net.ottto.locald.plist";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetiredService {
    pub label: &'static str,
    pub smapp_service_plist_name: &'static str,
}

const RETIRED_SERVICES: &[RetiredService] = &[RetiredService {
    label: MACOS_LEGACY_LAUNCH_AGENT_LABEL,
    smapp_service_plist_name: LEGACY_SMAPP_SERVICE_PLIST_NAME,
}];

pub fn retired_services() -> &'static [RetiredService] {
    RETIRED_SERVICES
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SMAppServiceState {
    Unavailable,
    NotRegistered,
    Enabled,
    RequiresApproval,
    NotFound,
}

impl SMAppServiceState {
    fn is_registered(self) -> bool {
        matches!(self, Self::Enabled | Self::RequiresApproval)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct LegacyServiceCleanupReport {
    pub found: usize,
    pub removed: usize,
    pub smappservice_deregistered: usize,
    pub launchctl_disabled: usize,
    pub launchctl_booted_out: usize,
    pub plists_removed: usize,
    pub failures: usize,
}

pub trait LegacyServiceControl {
    fn smapp_service_state(&mut self, plist_name: &str) -> io::Result<SMAppServiceState>;
    fn unregister_smapp_service(&mut self, plist_name: &str) -> io::Result<bool>;
    fn launchctl_loaded(&mut self, target: &str) -> io::Result<bool>;
    fn launchctl_disable(&mut self, target: &str) -> io::Result<bool>;
    fn launchctl_bootout(&mut self, target: &str) -> io::Result<bool>;
    fn plist_exists(&mut self, path: &Path) -> bool;
    fn remove_plist(&mut self, path: &Path) -> io::Result<()>;
}

#[cfg(target_os = "macos")]
pub fn cleanup_legacy_services(home: &Path) -> LegacyServiceCleanupReport {
    let mut control = SystemLegacyServiceControl;
    let report = cleanup_legacy_services_with(&mut control, home, user_launchctl_domain().as_str());
    if report.found > 0 {
        eprintln!(
            "legacy_service_cleanup found={} removed={} smappservice_deregistered={} \
             launchctl_disabled={} launchctl_booted_out={} plists_removed={} failures={} \
             labels={}",
            report.found,
            report.removed,
            report.smappservice_deregistered,
            report.launchctl_disabled,
            report.launchctl_booted_out,
            report.plists_removed,
            report.failures,
            retired_services()
                .iter()
                .map(|service| service.label)
                .collect::<Vec<_>>()
                .join(",")
        );
    }
    report
}

#[cfg(not(target_os = "macos"))]
pub fn cleanup_legacy_services(_home: &Path) -> LegacyServiceCleanupReport {
    LegacyServiceCleanupReport::default()
}

pub fn cleanup_legacy_services_with<C: LegacyServiceControl>(
    control: &mut C,
    home: &Path,
    launchctl_domain: &str,
) -> LegacyServiceCleanupReport {
    let mut report = LegacyServiceCleanupReport::default();

    for service in retired_services() {
        let plist_path = legacy_launch_agent_path(home, service.label);
        let smapp_state = match control.smapp_service_state(service.smapp_service_plist_name) {
            Ok(state) => state,
            Err(_) => {
                report.failures += 1;
                SMAppServiceState::Unavailable
            }
        };
        let smapp_registered = smapp_state.is_registered();
        let target = format!("{launchctl_domain}/{}", service.label);
        let loaded = match control.launchctl_loaded(&target) {
            Ok(loaded) => loaded,
            Err(_) => {
                report.failures += 1;
                false
            }
        };
        let plist_exists = control.plist_exists(&plist_path);

        if !smapp_registered && !loaded && !plist_exists {
            continue;
        }
        report.found += 1;

        let mut smappservice_deregistered = false;
        if smapp_registered {
            match control.unregister_smapp_service(service.smapp_service_plist_name) {
                Ok(true) => {
                    report.smappservice_deregistered += 1;
                    smappservice_deregistered = true;
                }
                Ok(false) | Err(_) => report.failures += 1,
            }
        }

        let launchctl_disabled = match control.launchctl_disable(&target) {
            Ok(true) => {
                report.launchctl_disabled += 1;
                true
            }
            Ok(false) | Err(_) => {
                report.failures += 1;
                false
            }
        };
        let launchctl_booted_out = match control.launchctl_bootout(&target) {
            Ok(true) => {
                report.launchctl_booted_out += 1;
                true
            }
            // SMAppService unregister kills the job asynchronously, so the
            // fallback can legitimately race with launchd removing it.
            Ok(false) if !loaded || smappservice_deregistered => false,
            Ok(false) | Err(_) => {
                report.failures += 1;
                false
            }
        };
        let plist_removed = if plist_exists {
            match control.remove_plist(&plist_path) {
                Ok(()) => {
                    report.plists_removed += 1;
                    true
                }
                Err(_) => {
                    report.failures += 1;
                    false
                }
            }
        } else {
            true
        };

        let fallback_removed =
            launchctl_disabled && (!loaded || launchctl_booted_out) && plist_removed;
        if plist_removed && (smappservice_deregistered || fallback_removed) {
            report.removed += 1;
        }
    }

    report
}

pub fn legacy_launch_agent_path(home: &Path, label: &str) -> PathBuf {
    home.join("Library")
        .join("LaunchAgents")
        .join(format!("{label}.plist"))
}

#[cfg(target_os = "macos")]
struct SystemLegacyServiceControl;

#[cfg(target_os = "macos")]
impl LegacyServiceControl for SystemLegacyServiceControl {
    fn smapp_service_state(&mut self, plist_name: &str) -> io::Result<SMAppServiceState> {
        system_smapp_service_state(plist_name)
    }

    fn unregister_smapp_service(&mut self, plist_name: &str) -> io::Result<bool> {
        system_unregister_smapp_service(plist_name)
    }

    fn launchctl_loaded(&mut self, target: &str) -> io::Result<bool> {
        command_succeeded(LAUNCHCTL, &["print", target])
    }

    fn launchctl_disable(&mut self, target: &str) -> io::Result<bool> {
        command_succeeded(LAUNCHCTL, &["disable", target])
    }

    fn launchctl_bootout(&mut self, target: &str) -> io::Result<bool> {
        command_succeeded(LAUNCHCTL, &["bootout", target])
    }

    fn plist_exists(&mut self, path: &Path) -> bool {
        path.exists()
    }

    fn remove_plist(&mut self, path: &Path) -> io::Result<()> {
        fs::remove_file(path)
    }
}

#[cfg(target_os = "macos")]
fn command_succeeded(program: &str, args: &[&str]) -> io::Result<bool> {
    Command::new(program)
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
}

#[cfg(target_os = "macos")]
extern "C" {
    fn ottto_legacy_smappservice_status(plist_name: *const std::os::raw::c_char) -> i32;
    fn ottto_unregister_legacy_smappservice(plist_name: *const std::os::raw::c_char) -> i32;
}

#[cfg(target_os = "macos")]
fn system_smapp_service_state(plist_name: &str) -> io::Result<SMAppServiceState> {
    use std::ffi::CString;

    let plist_name = CString::new(plist_name)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "plist name contains NUL"))?;
    let status = unsafe { ottto_legacy_smappservice_status(plist_name.as_ptr()) };
    Ok(match status {
        0 => SMAppServiceState::NotRegistered,
        1 => SMAppServiceState::Enabled,
        2 => SMAppServiceState::RequiresApproval,
        3 => SMAppServiceState::NotFound,
        _ => SMAppServiceState::Unavailable,
    })
}

#[cfg(target_os = "macos")]
fn system_unregister_smapp_service(plist_name: &str) -> io::Result<bool> {
    use std::ffi::CString;

    let plist_name = CString::new(plist_name)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "plist name contains NUL"))?;
    Ok(unsafe { ottto_unregister_legacy_smappservice(plist_name.as_ptr()) } == 1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ottto_core::MACOS_LAUNCH_AGENT_LABEL;
    use std::collections::{BTreeMap, BTreeSet};

    #[derive(Default)]
    struct MockControl {
        smapp_states: BTreeMap<String, SMAppServiceState>,
        loaded_targets: BTreeSet<String>,
        plists: BTreeSet<PathBuf>,
        calls: Vec<String>,
        action_success: bool,
        remove_success: Option<bool>,
    }

    impl LegacyServiceControl for MockControl {
        fn smapp_service_state(&mut self, plist_name: &str) -> io::Result<SMAppServiceState> {
            self.calls.push(format!("smapp_status:{plist_name}"));
            Ok(self
                .smapp_states
                .get(plist_name)
                .copied()
                .unwrap_or(SMAppServiceState::NotFound))
        }

        fn unregister_smapp_service(&mut self, plist_name: &str) -> io::Result<bool> {
            self.calls.push(format!("smapp_unregister:{plist_name}"));
            if self.action_success {
                self.smapp_states
                    .insert(plist_name.to_string(), SMAppServiceState::NotRegistered);
            }
            Ok(self.action_success)
        }

        fn launchctl_loaded(&mut self, target: &str) -> io::Result<bool> {
            self.calls.push(format!("launchctl_print:{target}"));
            Ok(self.loaded_targets.contains(target))
        }

        fn launchctl_disable(&mut self, target: &str) -> io::Result<bool> {
            self.calls.push(format!("launchctl_disable:{target}"));
            Ok(self.action_success)
        }

        fn launchctl_bootout(&mut self, target: &str) -> io::Result<bool> {
            self.calls.push(format!("launchctl_bootout:{target}"));
            if self.action_success {
                self.loaded_targets.remove(target);
            }
            Ok(self.action_success)
        }

        fn plist_exists(&mut self, path: &Path) -> bool {
            self.calls.push(format!("plist_exists:{}", path.display()));
            self.plists.contains(path)
        }

        fn remove_plist(&mut self, path: &Path) -> io::Result<()> {
            self.calls.push(format!("remove_plist:{}", path.display()));
            if self.remove_success.unwrap_or(self.action_success) {
                self.plists.remove(path);
                Ok(())
            } else {
                Err(io::Error::other("mock remove failure"))
            }
        }
    }

    #[test]
    fn retired_label_decision_is_explicit_and_excludes_current_service() {
        let labels = retired_services()
            .iter()
            .map(|service| service.label)
            .collect::<Vec<_>>();

        assert_eq!(labels, vec![MACOS_LEGACY_LAUNCH_AGENT_LABEL]);
        assert!(!labels.contains(&MACOS_LAUNCH_AGENT_LABEL));
    }

    #[test]
    fn registered_legacy_service_uses_smappservice_and_launchctl_fallback() {
        let mut control = MockControl {
            action_success: true,
            ..MockControl::default()
        };
        control.smapp_states.insert(
            LEGACY_SMAPP_SERVICE_PLIST_NAME.to_string(),
            SMAppServiceState::Enabled,
        );
        control
            .loaded_targets
            .insert("gui/501/net.ottto.locald".to_string());

        let report =
            cleanup_legacy_services_with(&mut control, Path::new("/Users/test"), "gui/501");

        assert_eq!(
            report,
            LegacyServiceCleanupReport {
                found: 1,
                removed: 1,
                smappservice_deregistered: 1,
                launchctl_disabled: 1,
                launchctl_booted_out: 1,
                plists_removed: 0,
                failures: 0,
            }
        );
        assert!(control
            .calls
            .contains(&"smapp_unregister:net.ottto.locald.plist".to_string()));
        assert!(control
            .calls
            .contains(&"launchctl_disable:gui/501/net.ottto.locald".to_string()));
        assert!(control
            .calls
            .contains(&"launchctl_bootout:gui/501/net.ottto.locald".to_string()));
    }

    #[test]
    fn launchctl_and_plist_fallback_work_without_smappservice() {
        let mut control = MockControl {
            action_success: true,
            ..MockControl::default()
        };
        control.smapp_states.insert(
            LEGACY_SMAPP_SERVICE_PLIST_NAME.to_string(),
            SMAppServiceState::Unavailable,
        );
        control
            .loaded_targets
            .insert("gui/501/net.ottto.locald".to_string());
        control.plists.insert(PathBuf::from(
            "/Users/test/Library/LaunchAgents/net.ottto.locald.plist",
        ));

        let report =
            cleanup_legacy_services_with(&mut control, Path::new("/Users/test"), "gui/501");

        assert_eq!(report.found, 1);
        assert_eq!(report.removed, 1);
        assert_eq!(report.smappservice_deregistered, 0);
        assert_eq!(report.launchctl_disabled, 1);
        assert_eq!(report.launchctl_booted_out, 1);
        assert_eq!(report.plists_removed, 1);
        assert_eq!(report.failures, 0);
    }

    #[test]
    fn cleanup_is_idempotent_after_legacy_registration_is_removed() {
        let mut control = MockControl {
            action_success: true,
            ..MockControl::default()
        };
        control.smapp_states.insert(
            LEGACY_SMAPP_SERVICE_PLIST_NAME.to_string(),
            SMAppServiceState::Enabled,
        );

        let first = cleanup_legacy_services_with(&mut control, Path::new("/Users/test"), "gui/501");
        let action_count = control.calls.len();
        let second =
            cleanup_legacy_services_with(&mut control, Path::new("/Users/test"), "gui/501");

        assert_eq!(first.found, 1);
        assert_eq!(first.removed, 1);
        assert_eq!(second.found, 0);
        assert_eq!(second.removed, 0);
        assert_eq!(
            control.calls[action_count..]
                .iter()
                .filter(|call| {
                    call.starts_with("smapp_unregister")
                        || call.starts_with("launchctl_disable")
                        || call.starts_with("launchctl_bootout")
                        || call.starts_with("remove_plist")
                })
                .count(),
            0
        );
    }

    #[test]
    fn persistent_legacy_plist_prevents_a_removed_result() {
        let legacy_plist = PathBuf::from("/Users/test/Library/LaunchAgents/net.ottto.locald.plist");
        let mut control = MockControl {
            action_success: true,
            remove_success: Some(false),
            ..MockControl::default()
        };
        control.smapp_states.insert(
            LEGACY_SMAPP_SERVICE_PLIST_NAME.to_string(),
            SMAppServiceState::Enabled,
        );
        control.plists.insert(legacy_plist);

        let report =
            cleanup_legacy_services_with(&mut control, Path::new("/Users/test"), "gui/501");

        assert_eq!(report.found, 1);
        assert_eq!(report.smappservice_deregistered, 1);
        assert_eq!(report.removed, 0);
        assert_eq!(report.failures, 1);
    }

    #[test]
    fn current_service_is_never_touched_when_no_retired_evidence_exists() {
        let mut control = MockControl {
            action_success: true,
            ..MockControl::default()
        };

        let report =
            cleanup_legacy_services_with(&mut control, Path::new("/Users/test"), "gui/501");

        assert_eq!(report, LegacyServiceCleanupReport::default());
        assert!(control
            .calls
            .iter()
            .all(|call| !call.contains(MACOS_LAUNCH_AGENT_LABEL)));
    }
}
