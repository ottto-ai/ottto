use super::*;

/// Only a shell argv recorder runs: no provider executable or credentials.
#[test]
fn claude_smoke_child_receives_fresh_reserved_id_and_persistence_and_exporter_settings() {
    let mut ids = std::collections::BTreeSet::new();
    for _ in 0..2 {
        let command = smoke_command(&SourceKind::ClaudeCode);
        assert_eq!(command.program, "claude");
        let output = std::process::Command::new("/bin/sh")
            .args(["-c", "printf '%s\\n' \"$@\"", "smoke-argv-stub"])
            .args(&command.args)
            .output()
            .unwrap();
        assert!(output.status.success());
        let output = String::from_utf8(output.stdout).unwrap();
        let args = output.lines().collect::<Vec<_>>();
        assert!(args.contains(&"--no-session-persistence"));
        let id = args[args.iter().position(|arg| *arg == "--session-id").unwrap() + 1];
        assert!(crate::claude_spawn_gate::is_internal_session_id(id));
        assert!(ids.insert(id.to_owned()));
        let settings = args[args.iter().position(|arg| *arg == "--settings").unwrap() + 1];
        let value: serde_json::Value = serde_json::from_str(settings).unwrap();
        for signal in [
            "OTEL_LOGS_EXPORTER",
            "OTEL_TRACES_EXPORTER",
            "OTEL_METRICS_EXPORTER",
        ] {
            assert_eq!(value["env"][signal], "none");
        }
    }
}
