//! Read-only shell-profile diagnostics. Values never enter the health model.
use crate::agent_configs::fence::{FENCE_END, FENCE_START};
use ottto_protocol::{HealthGrade, HealthProblem, SourceHealth, SourceKind, StableProblemCode};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::{self, Read};
use std::path::Path;
use std::sync::atomic::{AtomicU8, Ordering};

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
    ".config/fish/config.fish",
];
// Only the most recent Desktop fold's closed verdict survives. SDK folds do
// not provide Desktop evidence. No session identities, rows or history retained.
static CAPTURE: AtomicU8 = AtomicU8::new(0);

pub(crate) fn note_capture(requests: usize, missing: bool, unknown: bool) {
    if requests > 0 {
        CAPTURE.store(
            if unknown {
                3
            } else if missing {
                1
            } else {
                2
            },
            Ordering::Relaxed,
        );
    }
}

fn capture_label() -> &'static str {
    match CAPTURE.load(Ordering::Relaxed) {
        1 => "observed_missing",
        2 => "observed_received",
        3 => "unknown",
        _ => "untested",
    }
}

pub(crate) fn is_problem(problem: &HealthProblem) -> bool {
    problem.code == StableProblemCode::Unknown && problem.title == TITLE
}

#[derive(Default)]
struct Profile {
    label: String,
    lines: usize,
    names: BTreeSet<String>,
    destinations: BTreeMap<String, BTreeSet<&'static str>>,
    header_present: bool,
    telemetry: BTreeSet<&'static str>,
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
        if name == "CLAUDE_CODE_ENABLE_TELEMETRY" {
            self.telemetry.insert(match value {
                "0" => "disabled",
                "1" => "enabled",
                _ => "unknown",
            });
        }
        if name == "OTEL_EXPORTER_OTLP_HEADERS"
            || (name.starts_with("OTEL_EXPORTER_OTLP_") && name.ends_with("_HEADERS"))
        {
            self.header_present = true;
        }
        if name == "OTEL_EXPORTER_OTLP_ENDPOINT"
            || (name.starts_with("OTEL_EXPORTER_OTLP_") && name.ends_with("_ENDPOINT"))
        {
            self.destinations
                .entry(name.to_owned())
                .or_default()
                .insert(destination(value, relay_port));
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

// Literal tokens only, sufficient for export assignments and fish set -gx.
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
        } else if c.is_whitespace() || c == ';' {
            if !word.is_empty() {
                words.push(std::mem::take(&mut word));
            }
            if c == ';' {
                words.push(";".into());
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
    let read = || -> io::Result<String> {
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
        let mut body = String::new();
        file.read_to_string(&mut body)?;
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
        for command in tokens.split(|token| token == ";") {
            if command.first().is_some_and(|token| token == "export") {
                for token in &command[1..] {
                    if let Some((name, value)) = token.split_once('=') {
                        found |= profile.observe(name, value, relay_port);
                    }
                }
            } else if command.len() >= 4
                && command[0] == "set"
                && matches!(command[1].as_str(), "-gx" | "-xg")
            {
                found |= profile.observe(&command[2], &command[3], relay_port);
            }
        }
        profile.lines += usize::from(found);
    }
    profile.unknown |= fenced;
    profile
}

fn finding(home: Option<&Path>, relay_port: Option<u16>, capture: &str) -> Option<HealthProblem> {
    let Some(home) = home else {
        return Some(HealthProblem { code: StableProblemCode::Unknown, title: TITLE.into(), detail: "Shell profile check: unknown; Desktop capture: unknown. Home directory unavailable. Run Verify again when profiles are readable.".into(), retryable: true });
    };
    let mut profiles = PROFILES
        .iter()
        .map(|label| inspect(&home.join(label), label, relay_port))
        .collect::<Vec<_>>();
    let fish_dir = home.join(".config/fish/conf.d");
    match fs::read_dir(&fish_dir) {
        Ok(entries) => {
            for entry in entries {
                match entry {
                    Ok(entry) if entry.path().extension().is_some_and(|ext| ext == "fish") => {
                        // Dynamic file names are not safe diagnostic labels.
                        let label = format!(
                            ".config/fish/conf.d/*.fish #{}",
                            profiles.len() - PROFILES.len() + 1
                        );
                        profiles.push(inspect(&entry.path(), &label, relay_port));
                    }
                    Ok(_) => {}
                    Err(_) => profiles.push(Profile {
                        label: ".config/fish/conf.d".into(),
                        unknown: true,
                        ..Default::default()
                    }),
                }
            }
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(_) => profiles.push(Profile {
            label: ".config/fish/conf.d".into(),
            unknown: true,
            ..Default::default()
        }),
    }
    profiles.retain(|p| p.lines > 0 || p.unknown);
    if profiles.is_empty() {
        return None;
    }
    let unknown = profiles.iter().any(|p| p.unknown);
    let files = profiles
        .iter()
        .map(|p| {
            format!(
                "{}: {} lines: {}; destinations={}; header_present={}; telemetry={}; read={}",
                p.label,
                p.lines,
                p.names.iter().cloned().collect::<Vec<_>>().join(", "),
                p.destinations
                    .iter()
                    .map(|(name, classes)| format!(
                        "{}:{}",
                        name,
                        classes.iter().copied().collect::<Vec<_>>().join(",")
                    ))
                    .collect::<Vec<_>>()
                    .join(", "),
                p.header_present,
                p.telemetry.iter().copied().collect::<Vec<_>>().join(", "),
                if p.unknown { "unknown" } else { "complete" }
            )
        })
        .collect::<Vec<_>>()
        .join("; ");
    let detail = format!("Claude Desktop inherits telemetry settings from your shell profile (files={}: {}). Shell profile check: {}; Desktop capture: {}. other_loopback means a port that is not Ottto's relay; remote means elsewhere. These settings can prevent Ottto from receiving these sessions. Remove or comment out those lines, then quit and reopen Claude Desktop and start a new session. Unreadable profiles need a new Verify check. Ottto leaves these profile lines unchanged.", profiles.len(), files, if unknown { "unknown" } else { "complete" }, if unknown { "unknown" } else { capture });
    Some(HealthProblem {
        code: StableProblemCode::Unknown,
        title: TITLE.into(),
        detail,
        retryable: true,
    })
}

pub(crate) fn project(health: &mut SourceHealth, relay: &ottto_protocol::RelayState) {
    if health.source != SourceKind::ClaudeCode {
        return;
    }
    apply(health, problem(relay));
}

pub(crate) fn apply(health: &mut SourceHealth, finding: Option<HealthProblem>) {
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

pub(crate) fn problem(relay: &ottto_protocol::RelayState) -> Option<HealthProblem> {
    let home = crate::snapshot_sync::home_dir().ok();
    let port = relay
        .endpoint
        .as_deref()
        .and_then(crate::otlp_relay::local_relay_port_from_endpoint);
    finding(home.as_deref(), port, capture_label())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// [regress] Inline telemetry exports are reported without serializing values.
    #[test]
    fn shell_telemetry_profile_finding_is_names_and_classes_only() {
        let home = crate::test_scratch::ScratchDir::new("shell-telemetry");
        let body = concat!(
            "export CLAUDE_CODE_ENABLE_TELEMETRY=1\n",
            "export OTEL_LOGS_EXPORTER=otlp\n",
            "export OTEL_METRICS_EXPORTER=otlp\n",
            "export OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf\n",
            "export OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4318\n",
            "export OTEL_EXPORTER_OTLP_HEADERS='Authorization=synthetic-secret'\n"
        );
        fs::write(home.join(".zshrc"), body).unwrap();
        let problem = finding(Some(&home), Some(43119), "observed_missing").unwrap();
        assert!(is_problem(&problem));
        assert_eq!(crate::local_health_problem_code_slug(&problem), CODE);
        let wire = serde_json::to_string(&problem).unwrap();
        for safe in [
            "files=1",
            ".zshrc: 6 lines",
            "OTEL_LOGS_EXPORTER",
            "other_loopback",
            "header_present=true",
            "telemetry=enabled",
            "observed_missing",
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
    }

    /// [behaviour] Managed fences are excluded; literals are classified, failures Unknown.
    #[test]
    fn shell_telemetry_fences_disabled_fish_and_unknown() {
        let home = crate::test_scratch::ScratchDir::new("shell-profile-classes");
        fs::write(home.join(".zshrc"), format!("{FENCE_START}\nexport OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4318\n{FENCE_END}\n")).unwrap();
        assert!(finding(Some(&home), Some(43119), "untested").is_none());
        fs::write(
            home.join(".profile"),
            "export CLAUDE_CODE_ENABLE_TELEMETRY=0\n",
        )
        .unwrap();
        let problem = finding(Some(&home), Some(43119), "untested").unwrap();
        assert!(problem.detail.contains("telemetry=disabled"));
        assert!(problem.detail.contains("Desktop capture: untested"));
        fs::create_dir_all(home.join(".config/fish/conf.d")).unwrap();
        fs::write(
            home.join(".config/fish/conf.d/private-name.fish"),
            "set -gx OTEL_EXPORTER_OTLP_LOGS_ENDPOINT https://private-collector.example/v1/logs\n",
        )
        .unwrap();
        let problem = finding(Some(&home), Some(43119), "untested").unwrap();
        assert!(problem
            .detail
            .contains("OTEL_EXPORTER_OTLP_LOGS_ENDPOINT:remote"));
        assert!(!problem.detail.contains("private-"));
        // A directory deterministically exercises an unreadable profile, even as root.
        fs::create_dir(home.join(".bashrc")).unwrap();
        let unknown = finding(Some(&home), Some(43119), "observed_missing").unwrap();
        assert!(unknown.detail.contains(".bashrc: 0 lines"));
        assert!(unknown
            .detail
            .contains("Shell profile check: unknown; Desktop capture: unknown"));
        for (endpoint, expected) in [
            ("http://127.0.0.1:43119/v1/logs", "ottto_relay"),
            ("http://[::1]:4318", "other_loopback"),
            ("https://collector.example", "remote"),
            ("$ENDPOINT", "unparseable"),
        ] {
            assert_eq!(destination(endpoint, Some(43119)), expected);
        }
    }
    /// [behaviour] Known absence is missing capture; malformed evidence is Unknown.
    #[test]
    fn shell_telemetry_capture_evidence_is_complete_or_unknown() {
        let support = crate::test_scratch::ScratchDir::new("shell-capture");
        let absent = crate::claude_local_otel::ClaudeApiEvidenceRead::load(
            &support,
            ["synthetic-root".into()],
        )
        .unwrap();
        let report = absent.capture_report("synthetic-root").unwrap();
        assert!(report.complete && report.rows.is_empty());
        assert!(absent.capture_report("outside-cohort").is_none());
        let dir = support.join("local-otel/claude-code-effort");
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join(format!(
                "{}.jsonl",
                crate::claude_local_otel::telemetry_stem("synthetic-root")
            )),
            "broken\n",
        )
        .unwrap();
        let broken = crate::claude_local_otel::ClaudeApiEvidenceRead::load(
            &support,
            ["synthetic-root".into()],
        )
        .unwrap();
        assert!(!broken.capture_report("synthetic-root").unwrap().complete);
    }
}
