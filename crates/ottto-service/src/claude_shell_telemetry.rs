//! Read-only shell-profile diagnostics. Values never enter the health model.
use crate::agent_configs::fence::{FENCE_END, FENCE_START};
use ottto_protocol::{HealthGrade, HealthProblem, SourceHealth, SourceKind, StableProblemCode};
use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::io::{self, Read};
use std::path::Path;

pub(crate) const CODE: &str = "claude_shell_profile_telemetry_override";
const TITLE: &str = "Claude shell profile telemetry override";
const PROFILES: &[&str] = &[
    ".zshenv",
    ".zprofile",
    ".zshrc",
    ".zlogin",
    ".bash_profile",
    ".bashrc",
    ".profile",
];
pub(crate) fn is_problem(problem: &HealthProblem) -> bool {
    problem.code == StableProblemCode::Unknown && problem.title == TITLE
}

#[derive(Default)]
struct Profile {
    label: String,
    lines: usize,
    names: BTreeSet<String>,
    destinations: BTreeSet<&'static str>,
    header_present: bool,
    telemetry_enabled: bool,
    unknown: bool,
}

impl Profile {
    fn observe(&mut self, name: &str, value: &str, relay_port: Option<u16>) -> bool {
        if !(name.starts_with("OTEL_") || name == "CLAUDE_CODE_ENABLE_TELEMETRY")
            || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
        {
            return false;
        }
        self.names.insert(name.to_owned());
        self.telemetry_enabled |= name == "CLAUDE_CODE_ENABLE_TELEMETRY" && value == "1";
        self.header_present |= name == "OTEL_EXPORTER_OTLP_HEADERS";
        if name == "OTEL_EXPORTER_OTLP_ENDPOINT" {
            self.destinations.insert(destination(value, relay_port));
        }
        true
    }
}

fn destination(value: &str, relay_port: Option<u16>) -> &'static str {
    if value.contains(['$', '`', '\\']) {
        return "unparseable";
    }
    // Parsing only: no call/send, DNS lookup, socket or listener probe.
    let Ok(parsed) = ureq::get(value).request_url() else {
        return "unparseable";
    };
    let url = parsed.as_url();
    if !matches!(url.scheme(), "http" | "https") {
        return "unparseable";
    }
    let host = url.host_str().unwrap_or("").trim_matches(['[', ']']);
    let loopback = host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback());
    if !loopback {
        return "remote";
    }
    if relay_port.is_some() && url.port_or_known_default() == relay_port {
        "ottto_relay"
    } else {
        "other_loopback"
    }
}

// Literal tokens for shell export assignments only.
// Unclosed quotes/continuations are Unknown; shell expressions are never run.
fn words(line: &str) -> Option<Vec<String>> {
    let mut words = Vec::new();
    let mut word = String::new();
    let mut quote = None;
    let mut escape = false;
    for c in line.chars() {
        if escape {
            word.push(c);
            escape = false;
            continue;
        }
        if c == '\\' && quote != Some('\'') {
            escape = true;
            word.push(c);
            continue;
        }
        if let Some(q) = quote {
            if c == q {
                quote = None;
            } else {
                word.push(c);
            }
        } else if c == '\'' || c == '"' {
            quote = Some(c);
        } else if c == '#' && word.is_empty() {
            break;
        } else if c.is_whitespace() {
            if !word.is_empty() {
                words.push(std::mem::take(&mut word));
            }
        } else {
            word.push(c);
        }
    }
    if quote.is_some() || escape {
        return None;
    }
    if !word.is_empty() {
        words.push(word);
    }
    Some(words)
}

fn inspect(path: &Path, label: &str, relay_port: Option<u16>) -> Profile {
    let mut profile = Profile {
        label: label.into(),
        ..Default::default()
    };
    let read = || -> io::Result<Vec<u8>> {
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC);
        }
        let mut file = options.open(path)?;
        let before = file.metadata()?;
        if !before.is_file() {
            return Err(io::Error::other("not a regular profile"));
        }
        let mut body = Vec::new();
        file.read_to_end(&mut body)?;
        let after = file.metadata()?;
        if before.len() != after.len() || before.modified()? != after.modified()? {
            return Err(io::Error::other("profile changed"));
        }
        Ok(body)
    };
    let body = match read() {
        Ok(body) => body,
        Err(e)
            if e.kind() == io::ErrorKind::NotFound
                && fs::symlink_metadata(path)
                    .is_err_and(|e| e.kind() == io::ErrorKind::NotFound) =>
        {
            return profile
        }
        Err(_) => {
            profile.unknown = true;
            return profile;
        }
    };
    let body = String::from_utf8_lossy(&body);
    let mut fenced = false;
    for line in body.lines() {
        if line.trim() == FENCE_START {
            profile.unknown |= fenced;
            fenced = true;
            continue;
        }
        if line.trim() == FENCE_END {
            profile.unknown |= !fenced;
            fenced = false;
            continue;
        }
        if fenced {
            continue;
        }
        let Some(tokens) = words(line) else {
            profile.unknown |=
                line.contains("OTEL_") || line.contains("CLAUDE_CODE_ENABLE_TELEMETRY");
            continue;
        };
        let mut found = false;
        if tokens.first().is_some_and(|token| token == "export") {
            for token in &tokens[1..] {
                if let Some((name, value)) = token.split_once('=') {
                    found |= profile.observe(name, value, relay_port);
                }
            }
        }
        profile.lines += usize::from(found);
    }
    profile.unknown |= fenced;
    profile
}

fn finding(home: Option<&Path>, relay_port: Option<u16>) -> Option<HealthProblem> {
    let Some(home) = home else {
        return Some(HealthProblem { code: StableProblemCode::Unknown, title: TITLE.into(), detail: "Shell profile check: unknown. Home directory unavailable. Run Verify again when profiles are readable.".into(), retryable: true });
    };
    let mut profiles = PROFILES
        .iter()
        .map(|label| inspect(&home.join(label), label, relay_port))
        .collect::<Vec<_>>();
    profiles.retain(|p| p.lines > 0 || p.unknown);
    if profiles.is_empty() {
        return None;
    }
    if !profiles.iter().any(|p| p.lines > 0) {
        let labels = profiles
            .iter()
            .map(|p| p.label.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        return Some(HealthProblem {
            code: StableProblemCode::Unknown,
            title: TITLE.into(),
            detail: format!(
                "Shell profile check: unknown; could not read {labels}; run Verify again."
            ),
            retryable: true,
        });
    }
    let unknown = profiles.iter().any(|p| p.unknown);
    let files = profiles
        .iter()
        .map(|p| {
            format!(
                "{}: {} lines: {}; destinations={}; header_present={}; telemetry_enabled_literal_present={}; read={}",
                p.label,
                p.lines,
                p.names.iter().cloned().collect::<Vec<_>>().join(", "),
                p.destinations.iter().copied().collect::<Vec<_>>().join(", "),
                p.header_present,
                p.telemetry_enabled,
                if p.unknown { "unknown" } else { "complete" }
            )
        })
        .collect::<Vec<_>>()
        .join("; ");
    let detail = format!("Claude Desktop may inherit telemetry settings from your shell profile (files={}: {}). Shell profile check: {}. other_loopback means a port that is not Ottto's relay; remote means elsewhere. These settings can prevent Ottto from receiving these sessions. Remove or comment out those lines, then quit and reopen Claude Desktop and start a new session. Unreadable profiles need a new Verify check. Ottto leaves these profile lines unchanged.", profiles.len(), files, if unknown { "unknown" } else { "complete" });
    Some(HealthProblem {
        code: StableProblemCode::Unknown,
        title: TITLE.into(),
        detail,
        retryable: true,
    })
}

pub(crate) fn apply(health: &mut SourceHealth, finding: Option<HealthProblem>) {
    if health.source != SourceKind::ClaudeCode {
        return;
    }
    let had_finding = health.problems.iter().any(is_problem);
    health.problems.retain(|problem| !is_problem(problem));
    if had_finding && health.problems.is_empty() && health.grade == HealthGrade::Warning {
        health.grade = HealthGrade::Ok;
    }
    if let Some(problem) = finding {
        health.problems.push(problem);
        if health.grade == HealthGrade::Ok {
            health.grade = HealthGrade::Warning;
        }
    }
}

pub(crate) fn problem(
    source: &SourceKind,
    relay: &ottto_protocol::RelayState,
) -> Option<HealthProblem> {
    if *source != SourceKind::ClaudeCode {
        return None;
    }
    let home = crate::snapshot_sync::home_dir().ok();
    let port = relay
        .endpoint
        .as_deref()
        .and_then(crate::otlp_relay::local_relay_port_from_endpoint);
    finding(home.as_deref(), port)
}

#[cfg(test)]
mod tests {
    use super::*;

    const OBSERVED_EXPORTS: &str = concat!(
        "export CLAUDE_CODE_ENABLE_TELEMETRY=1\n",
        "export OTEL_LOGS_EXPORTER=otlp\n",
        "export OTEL_METRICS_EXPORTER=otlp\n",
        "export OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf\n",
        "export OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4318\n",
        "export OTEL_EXPORTER_OTLP_HEADERS='Authorization=synthetic-secret'\n"
    );

    /// [regress] Inline telemetry exports are reported without serializing values.
    #[test]
    fn shell_telemetry_profile_finding_is_names_and_classes_only() {
        let home = crate::test_scratch::ScratchDir::new("shell-telemetry");
        let body = OBSERVED_EXPORTS;
        fs::write(home.join(".zshrc"), body).unwrap();
        let problem = finding(Some(&home), Some(43119)).unwrap();
        assert!(is_problem(&problem));
        assert!(problem.detail.starts_with("Claude Desktop may inherit"));
        assert_eq!(crate::local_health_problem_code_slug(&problem), CODE);
        let wire = serde_json::to_string(&problem).unwrap();
        for safe in [
            "files=1",
            ".zshrc: 6 lines",
            "OTEL_LOGS_EXPORTER",
            "other_loopback",
            "header_present=true",
            "telemetry_enabled_literal_present=true",
        ] {
            assert!(wire.contains(safe), "missing {safe}");
        }
        for value in [
            "localhost",
            "4318",
            "Authorization",
            "synthetic-secret",
            "http/protobuf",
            "=otlp",
            home.to_str().unwrap(),
        ] {
            assert!(!wire.contains(value), "leaked profile value");
        }
        assert_eq!(fs::read_to_string(home.join(".zshrc")).unwrap(), body);
        let mut health: SourceHealth = serde_json::from_value(serde_json::json!({
            "source": "claude_code", "descriptor": crate::source_descriptor(&SourceKind::ClaudeCode),
            "state": "healthy", "grade": "ok", "account_binding": {},
            "config": {"discovered": true, "drift": []}, "problems": [], "recommended_actions": []
        })).unwrap();
        // A successful source/config observation stays healthy with one advisory.
        apply(&mut health, Some(problem.clone()));
        apply(&mut health, Some(problem));
        assert_eq!(health.state, ottto_protocol::SourceState::Healthy);
        assert_eq!(health.grade, HealthGrade::Warning);
        assert_eq!(health.problems.len(), 1);
        apply(&mut health, None);
        assert!(health.problems.is_empty());
        assert_eq!(health.grade, HealthGrade::Ok);
    }

    /// [behaviour] Managed fences are excluded and unreadable profiles remain Unknown.
    #[test]
    fn shell_telemetry_fences_and_unknown() {
        let home = crate::test_scratch::ScratchDir::new("shell-profile-classes");
        fs::write(home.join(".zshrc"), format!("{FENCE_START}\nexport OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4318\n{FENCE_END}\n")).unwrap();
        assert!(finding(Some(&home), Some(43119)).is_none());
        // A directory exercises an unreadable profile, including when tests run as root.
        fs::create_dir(home.join(".bashrc")).unwrap();
        let unknown = finding(Some(&home), Some(43119)).unwrap();
        assert_eq!(
            unknown.detail,
            "Shell profile check: unknown; could not read .bashrc; run Verify again."
        );
    }

    /// [regress] A non-UTF-8 comment must not hide the observed telemetry exports.
    #[test]
    fn shell_telemetry_scans_non_utf8_profile() {
        let home = crate::test_scratch::ScratchDir::new("shell-profile-encoding");
        let mut bytes = OBSERVED_EXPORTS.as_bytes().to_vec();
        bytes.extend_from_slice(b"# Latin-1 comment: \xe9\n");
        fs::write(home.join(".zshrc"), bytes).unwrap();
        let problem = finding(Some(&home), Some(43119)).unwrap();
        for expected in [
            ".zshrc: 6 lines",
            "other_loopback",
            "header_present=true",
            "telemetry_enabled_literal_present=true",
            "read=complete",
        ] {
            assert!(problem.detail.contains(expected), "missing {expected}");
        }
    }
}
