//! Unix primitives shared by the daemon preflight and the terminal handoff.
use ottto_protocol::{SessionLaunchBlockReasonV1 as Reason, SessionLaunchExecPlanV1};
use std::path::PathBuf;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LaunchUser {
    pub home: PathBuf,
    pub name: String,
}

/// Never use inherited HOME/USER/LOGNAME to select an account's default home.
#[cfg(unix)]
pub fn launch_user() -> Option<LaunchUser> {
    use std::ffi::CStr;
    let mut record = std::mem::MaybeUninit::<libc::passwd>::uninit();
    let mut buffer = vec![0u8; 64 * 1024];
    let mut found = std::ptr::null_mut();
    let result = unsafe {
        libc::getpwuid_r(
            libc::geteuid(),
            record.as_mut_ptr(),
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            &mut found,
        )
    };
    if result != 0 || found.is_null() {
        return None;
    }
    let record = unsafe { record.assume_init() };
    if record.pw_dir.is_null() || record.pw_name.is_null() {
        return None;
    }
    let home = unsafe { CStr::from_ptr(record.pw_dir) }.to_str().ok()?;
    let name = unsafe { CStr::from_ptr(record.pw_name) }.to_str().ok()?;
    if !std::path::Path::new(home).is_absolute() || name.is_empty() {
        return None;
    }
    Some(LaunchUser {
        home: home.into(),
        name: name.into(),
    })
}

#[cfg(not(unix))]
pub fn launch_user() -> Option<LaunchUser> {
    None
}

/// Shell quoting is used only for a pinned executable path, never agent argv
/// or a folder. Control characters are rejected before rendering.
pub fn quote_launch_executable(path: &str) -> Option<String> {
    if !std::path::Path::new(path).is_absolute() || path.chars().any(char::is_control) {
        return None;
    }
    Some(format!("'{}'", path.replace('\'', "'\\''")))
}

/// On success this does not return. A directory descriptor is held through
/// fstat/fchdir/exec, so replacing the pathname cannot redirect the launch.
#[cfg(unix)]
pub fn execute_launch_plan(plan: &SessionLaunchExecPlanV1) -> Reason {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    use std::os::unix::process::CommandExt;
    let (Some(program), Some(argv), Some(cwd), Some(dev), Some(ino), Some(unset), Some(set)) = (
        &plan.program,
        &plan.argv,
        &plan.cwd,
        plan.cwd_dev,
        plan.cwd_ino,
        &plan.env_unset,
        &plan.env_set,
    ) else {
        return Reason::Unknown;
    };
    if !std::path::Path::new(program).is_absolute() || !std::path::Path::new(cwd).is_absolute() {
        return Reason::Unknown;
    }
    let Ok(dir) = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(cwd)
    else {
        return Reason::ChdirFailed;
    };
    let Ok(metadata) = dir.metadata() else {
        return Reason::ChdirFailed;
    };
    if metadata.dev() != dev || metadata.ino() != ino {
        return Reason::FolderChanged;
    }
    if unsafe { libc::fchdir(dir.as_raw_fd()) } != 0 {
        return Reason::ChdirFailed;
    }
    let Some(user) = launch_user() else {
        return Reason::ExecFailed;
    };
    let mut command = std::process::Command::new(program);
    command.args(argv);
    for key in unset {
        command.env_remove(key);
    }
    command
        .envs(set)
        .env("HOME", user.home)
        .env("USER", &user.name)
        .env("LOGNAME", user.name)
        .env("PWD", cwd)
        .env_remove("OTTTO_CONTROL_TOKEN");
    let _ = command.exec();
    Reason::ExecFailed
}

#[cfg(not(unix))]
pub fn execute_launch_plan(_: &SessionLaunchExecPlanV1) -> Reason {
    Reason::ExecFailed
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn executable_quote_rejects_lines_and_keeps_metacharacters_literal() {
        assert_eq!(
            quote_launch_executable("/a '$(x)`雪"),
            Some("'/a '\\''$(x)`雪'".into())
        );
        assert!(quote_launch_executable("/a\nb").is_none());
        assert!(quote_launch_executable("relative").is_none());
    }
    #[test]
    fn missing_exec_fields_are_inert() {
        assert_eq!(
            execute_launch_plan(&SessionLaunchExecPlanV1::default()),
            Reason::Unknown
        );
    }
}
