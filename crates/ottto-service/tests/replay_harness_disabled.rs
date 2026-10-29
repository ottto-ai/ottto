//! The installed/default binary must reject the development-only reader.
#![cfg(not(feature = "replay-harness"))]

#[test]
fn default_binary_has_no_replay_command() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_ottto-service"))
        .args(["replay-harness", "--help"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("unrecognized subcommand"));
    assert!(output.stdout.is_empty());
}
