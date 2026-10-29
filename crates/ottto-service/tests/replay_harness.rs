//! Synthetic child-process checks. Never reads provider state or starts serve.
#![cfg(unix)]
use serde_json::{json, Value};
use std::fs;
use std::io::Write;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::os::unix::process::ExitStatusExt;
use std::path::PathBuf;
use std::process::{Command, Output};

const CANARY: &str = "synthetic-private-content-canary";
const SESSION: &str = "synthetic-private-session-canary";
struct Fixture {
    base: PathBuf,
    clone: PathBuf,
    support: PathBuf,
    root: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let base = std::env::temp_dir().join(format!(
            "replay-{}-{}",
            std::process::id(),
            ottto_core::generate_control_token().unwrap()
        ));
        let clone = base.join("clone");
        let support = base.join("scratch");
        let root = clone.join("claude/project");
        for dir in [&base, &clone, &support, &root] {
            fs::create_dir_all(dir).unwrap();
            fs::set_permissions(dir, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let fixture = Self {
            base,
            clone,
            support,
            root,
        };
        fixture.manifest(json!({"claude":[fixture.clone.join("claude")], "codex":[], "pi":[]}));
        fixture.append(1, 10);
        fixture
    }
    fn manifest(&self, value: Value) {
        fs::write(self.clone.join("roots.json"), value.to_string()).unwrap();
    }
    fn append(&self, n: u64, tokens: u64) {
        let now = time::OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap();
        let row = json!({"type":"assistant", "sessionId":SESSION, "uuid":format!("u{n}"), "requestId":format!("req{n}"), "timestamp":now,
            "cwd":self.base.join(CANARY), "message":{"id":format!("msg{n}"), "model":"claude-sonnet-4-6", "role":"assistant", "content":[{"type":"text","text":CANARY}], "usage":{"input_tokens":tokens,"output_tokens":2}}});
        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.root.join(format!("{SESSION}.jsonl")))
            .unwrap();
        writeln!(file, "{row}").unwrap();
    }
    fn command(&self, pass: &str) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_ottto-service"));
        command
            .args(["replay-harness", "--support-dir"])
            .arg(&self.support)
            .arg("--roots-manifest")
            .arg(self.clone.join("roots.json"))
            .args(["--pass", pass, "--out"])
            .arg(self.support.join(format!("{pass}.jsonl")))
            .env("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &self.support)
            .env("OTTTO_SERVICE_SECRET_FALLBACK_DIR", &self.support)
            .env_remove("OTTTO_API_BASE_URL");
        command
    }
    fn run(&self, pass: &str) -> Vec<Value> {
        let output = self.command(pass).output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        self.assert_private(&output);
        self.rows(pass)
    }
    fn assert_private(&self, output: &Output) {
        for text in [
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        ] {
            for forbidden in [CANARY, SESSION, self.base.to_str().unwrap()] {
                assert!(!text.contains(forbidden), "raw output: {text}");
            }
        }
    }
    fn rows(&self, pass: &str) -> Vec<Value> {
        let text = fs::read_to_string(self.support.join(format!("{pass}.jsonl"))).unwrap();
        for forbidden in [CANARY, SESSION, self.base.to_str().unwrap()] {
            assert!(!text.contains(forbidden), "raw JSONL");
        }
        text.lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }
    fn refused(&self, mut command: Command) {
        let output = command.output().unwrap();
        assert_eq!(
            output.status.code(),
            Some(2),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        self.assert_private(&output);
        assert!(!self.support.join(".replay-harness").exists());
        assert!(!self.support.join("P0.jsonl").exists());
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.base).unwrap();
    }
}
fn totals(rows: &[Value]) -> &Value {
    rows.iter()
        .find(|row| row["kind"] == "pass_totals")
        .expect("completed pass")
}
fn session(rows: &[Value]) -> &Value {
    rows.iter()
        .rev()
        .find(|row| row["kind"] == "session")
        .expect("emitted session")
}

#[test]
fn refuses_mismatched_or_missing_scratch_support() {
    let f = Fixture::new();
    let mut command = f.command("P0");
    command.env("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &f.clone);
    f.refused(command);
    let mut command = f.command("P0");
    command.env_remove("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR");
    f.refused(command);
}
#[test]
fn refuses_existing_daemon_state() {
    let f = Fixture::new();
    fs::write(f.support.join("account.json"), "{}").unwrap();
    f.refused(f.command("P0"));
}
#[test]
fn refuses_root_outside_clone_and_nested_symlink() {
    let f = Fixture::new();
    f.manifest(json!({"claude":[f.support],"codex":[],"pi":[]}));
    f.refused(f.command("P0"));
    f.manifest(json!({"claude":[f.clone.join("claude")],"codex":[],"pi":[]}));
    symlink(&f.support, f.root.join("escape")).unwrap();
    f.refused(f.command("P0"));
}
#[test]
fn refuses_external_api_and_unowned_loopback() {
    let f = Fixture::new();
    for url in ["https://example.invalid", "http://127.0.0.1:1"] {
        let mut command = f.command("P0");
        command.env("OTTTO_API_BASE_URL", url);
        f.refused(command);
    }
}
#[test]
fn refuses_missing_and_external_secret_fallback() {
    let f = Fixture::new();
    let mut command = f.command("P0");
    command.env_remove("OTTTO_SERVICE_SECRET_FALLBACK_DIR");
    f.refused(command);
    let mut command = f.command("P0");
    command.env("OTTTO_SERVICE_SECRET_FALLBACK_DIR", &f.clone);
    f.refused(command);
}
#[test]
fn synthetic_cold_quiet_growth_kill_and_restart() {
    let f = Fixture::new();
    let cold = f.run("P0");
    assert!(totals(&cold)["full_reads"].as_u64().unwrap() > 0);
    assert_eq!(session(&cold)["entity_count"], 1);
    assert_eq!(
        session(&cold)["blinded_session_hash"]
            .as_str()
            .unwrap()
            .len(),
        64
    );
    assert_eq!(
        session(&cold)["emitted_body_digest"]
            .as_str()
            .unwrap()
            .len(),
        64
    );
    let quiet = f.run("P1");
    assert_eq!(totals(&quiet)["full_reads"], 0);
    assert_eq!(totals(&quiet)["tail_reads"], 0);
    assert!(totals(&quiet)["restored"].as_u64().unwrap() > 0);
    assert!(!quiet.iter().any(|row| row["kind"] == "session"));
    f.append(2, 20);
    let growth = f.run("P2");
    assert_eq!(totals(&growth)["full_reads"], 0);
    assert!(totals(&growth)["tail_reads"].as_u64().unwrap() > 0);
    assert_eq!(
        session(&cold)["blinded_session_hash"],
        session(&growth)["blinded_session_hash"]
    );
    assert_ne!(
        session(&cold)["emitted_body_digest"],
        session(&growth)["emitted_body_digest"]
    );
    f.append(3, 30);
    let killed = f
        .command("P3")
        .args(["--kill-after-pages", "1"])
        .output()
        .unwrap();
    assert_eq!(killed.status.signal(), Some(libc::SIGKILL));
    let before_restart = f.rows("P3");
    assert!(before_restart
        .iter()
        .any(|row| row["kind"] == "page_finished"));
    assert!(!before_restart
        .iter()
        .any(|row| row["kind"] == "pass_totals"));
    assert_eq!(
        session(&growth)["blinded_session_hash"],
        session(&before_restart)["blinded_session_hash"]
    );
    let restart = f.run("P3");
    assert_eq!(totals(&restart)["full_reads"], 0);
    assert_eq!(totals(&restart)["tail_reads"], 0);
    assert!(restart.iter().any(|row| row["kind"] == "local_resources"));
    // Independent fresh scratch uses the same production cycle over the final
    // synthetic transcript; cumulative money must equal the restarted chain.
    let fresh = Fixture::new();
    fs::copy(
        f.root.join(format!("{SESSION}.jsonl")),
        fresh.root.join(format!("{SESSION}.jsonl")),
    )
    .unwrap();
    let oracle = fresh.run("P0");
    assert_eq!(
        session(&before_restart)["token_totals"],
        session(&oracle)["token_totals"]
    );
}
#[test]
fn command_is_hidden() {
    let output = Command::new(env!("CARGO_BIN_EXE_ottto-service"))
        .arg("--help")
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(!String::from_utf8(output.stdout)
        .unwrap()
        .contains("replay-harness"));
}

#[test]
fn refuses_live_support_even_with_matching_environment() {
    let f = Fixture::new();
    let home = f.base.join("fake-home");
    let live = home.join("Library/Application Support/Ottto");
    fs::create_dir_all(&live).unwrap();
    fs::set_permissions(&live, fs::Permissions::from_mode(0o700)).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_ottto-service"))
        .args(["replay-harness", "--support-dir"])
        .arg(&live)
        .arg("--roots-manifest")
        .arg(f.clone.join("roots.json"))
        .args(["--pass", "P0", "--out"])
        .arg(live.join("P0.jsonl"))
        .env("HOME", &home)
        .env("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &live)
        .env("OTTTO_SERVICE_SECRET_FALLBACK_DIR", &live)
        .env_remove("OTTTO_API_BASE_URL")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(fs::read_dir(live).unwrap().count(), 0);
}

#[test]
fn kill_after_first_source_leaves_second_source_for_restart() {
    let f = Fixture::new();
    let pi = f.clone.join("pi");
    fs::create_dir(&pi).unwrap();
    let now = time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap();
    let header = json!({"type":"session", "id":"synthetic-pi-session", "timestamp":now});
    let usage = json!({"type":"message", "message":{"role":"assistant", "model":"gpt-5.4", "provider":"openai", "responseId":"fixture-response", "timestamp":now, "usage":{"input":12,"output":4,"cost":{"total":0.001}}}});
    fs::write(pi.join("synthetic.jsonl"), format!("{header}\n{usage}\n")).unwrap();
    f.manifest(json!({"claude":[f.clone.join("claude")], "codex":[], "pi":[pi]}));
    let killed = f
        .command("P3")
        .args(["--kill-after-pages", "1"])
        .output()
        .unwrap();
    assert_eq!(killed.status.signal(), Some(libc::SIGKILL));
    let partial = f.rows("P3");
    assert_eq!(
        partial
            .iter()
            .filter(|r| r["kind"] == "page_finished")
            .count(),
        1
    );
    assert!(!partial.iter().any(|r| r["source"] == "pi"));
    let resumed = f.run("P3");
    let pi = resumed
        .iter()
        .find(|r| r["kind"] == "session" && r["source"] == "pi")
        .expect("unprocessed source emitted after crash");
    assert_eq!(pi["token_totals"]["input_tokens"], 12);
    assert_eq!(totals(&resumed)["pages"], 2);
}

#[test]
fn supplied_hold_back_inventory_is_validated_and_counted() {
    let f = Fixture::new();
    let inventory = f.clone.join("hold-back.json");
    fs::write(
        &inventory,
        json!({"files":[format!("claude/project/{SESSION}.jsonl")]}).to_string(),
    )
    .unwrap();
    let output = f
        .command("P0")
        .arg("--hold-back")
        .arg(inventory)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(f.rows("P0")[0]["held_files"], 1);
}

#[test]
fn refuses_physical_targets_of_live_provider_and_support_symlinks() {
    for provider in [".claude", "Library/Application Support/Ottto"] {
        let f = Fixture::new();
        let home = f.base.join("fake-home");
        let live = home.join(provider);
        fs::create_dir_all(live.parent().unwrap()).unwrap();
        let target = if provider == ".claude" {
            &f.clone
        } else {
            &f.support
        };
        symlink(target, &live).unwrap();
        let mut command = f.command("P0");
        command.env("HOME", &home);
        f.refused(command);
    }
}

#[test]
fn refuses_oversized_marker_and_blinding_key_without_allocating_them() {
    for name in [".replay-harness", "replay-blinding-key"] {
        let f = Fixture::new();
        fs::write(
            f.support.join(".replay-harness"),
            b"ottto isolated replay v1\n",
        )
        .unwrap();
        let file = fs::File::create(f.support.join(name)).unwrap();
        file.set_len(64 * 1024 * 1024).unwrap();
        let output = f.command("P0").output().unwrap();
        let expected = if name == ".replay-harness" { 2 } else { 3 };
        assert_eq!(output.status.code(), Some(expected));
        f.assert_private(&output);
    }
}
