use std::env;
use std::ffi::OsString;
use std::path::PathBuf;

const COMMAND_SEARCH_PATH_ENV: &str = "OTTTO_COMMAND_SEARCH_PATH";

pub(crate) fn executable_path(program: &str) -> Option<PathBuf> {
    executable_search_dirs().into_iter().find_map(|dir| {
        let candidate = dir.join(program);
        if candidate.is_file() {
            Some(candidate)
        } else {
            None
        }
    })
}

pub(crate) fn path_env() -> Option<OsString> {
    if let Some(path_var) = env::var_os(COMMAND_SEARCH_PATH_ENV) {
        return path_env_from_override(Some(path_var));
    }
    path_env_from(env::var_os("PATH"), env::var_os("HOME"))
}

fn executable_search_dirs() -> Vec<PathBuf> {
    if let Some(path_var) = env::var_os(COMMAND_SEARCH_PATH_ENV) {
        return executable_search_dirs_from(Some(path_var), None, false);
    }
    executable_search_dirs_from(env::var_os("PATH"), env::var_os("HOME"), true)
}

fn path_env_from(path_var: Option<OsString>, home: Option<OsString>) -> Option<OsString> {
    env::join_paths(executable_search_dirs_from(path_var, home, true)).ok()
}

fn path_env_from_override(path_var: Option<OsString>) -> Option<OsString> {
    env::join_paths(path_var.map(|value| executable_search_dirs_from(Some(value), None, false))?)
        .ok()
}

fn executable_search_dirs_from(
    path_var: Option<OsString>,
    home: Option<OsString>,
    include_default_dirs: bool,
) -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    if let Some(path_var) = path_var {
        for dir in env::split_paths(&path_var) {
            push_unique(&mut dirs, dir);
        }
    }
    if let Some(home) = home {
        if !home.as_os_str().is_empty() {
            push_unique(&mut dirs, PathBuf::from(home).join(".local/bin"));
        }
    }
    if include_default_dirs {
        for dir in [
            "/opt/homebrew/bin",
            "/usr/local/bin",
            "/usr/bin",
            "/bin",
            "/usr/sbin",
            "/sbin",
        ] {
            push_unique(&mut dirs, PathBuf::from(dir));
        }
    }
    dirs
}

fn push_unique(dirs: &mut Vec<PathBuf>, dir: PathBuf) {
    if !dirs.iter().any(|existing| existing == &dir) {
        dirs.push(dir);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn path_env_includes_launchd_safe_cli_locations() {
        let path_env = path_env_from(
            Some(OsString::from("/usr/bin:/bin")),
            Some(OsString::from("/Users/tester")),
        )
        .expect("path env");
        let dirs = env::split_paths(&path_env).collect::<Vec<_>>();

        assert_eq!(dirs.first(), Some(&PathBuf::from("/usr/bin")));
        assert!(dirs.contains(&PathBuf::from("/Users/tester/.local/bin")));
        assert!(dirs.contains(&PathBuf::from("/opt/homebrew/bin")));
        assert!(dirs.contains(&PathBuf::from("/usr/local/bin")));
    }

    #[test]
    fn path_env_deduplicates_candidate_dirs() {
        let path_env = path_env_from(
            Some(OsString::from(
                "/opt/homebrew/bin:/usr/bin:/opt/homebrew/bin",
            )),
            None,
        )
        .expect("path env");
        let dirs = env::split_paths(&path_env).collect::<Vec<_>>();

        assert_eq!(
            dirs.iter()
                .filter(|dir| dir.as_path() == Path::new("/opt/homebrew/bin"))
                .count(),
            1
        );
    }

    #[test]
    fn command_search_override_does_not_append_default_dirs() {
        let override_path = OsString::from("/tmp/ottto-only-bin");

        let dirs = executable_search_dirs_from(Some(override_path.clone()), None, false);
        assert_eq!(dirs, vec![PathBuf::from("/tmp/ottto-only-bin")]);

        let path_env = path_env_from_override(Some(override_path)).expect("path env");
        let dirs = env::split_paths(&path_env).collect::<Vec<_>>();
        assert_eq!(dirs, vec![PathBuf::from("/tmp/ottto-only-bin")]);
    }
}
