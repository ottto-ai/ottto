use super::*;

/// [regress] A subagent file and a project named `projects` map to one folder.
#[test]
fn transcript_paths_map_to_their_config_dir_key() {
    let slot = home_key(Path::new("/Users/someone/.claude-slot"));
    assert_eq!(home_key(Path::new("/Users/someone/.claude-slot/")), slot);
    for transcript in [
        "/Users/someone/.claude-slot/projects/-Users-someone-repo/session.jsonl",
        "/Users/someone/.claude-slot/projects/-Users-someone-projects/session/subagents/agent-a.jsonl",
    ] {
        assert_eq!(transcript_home_key(Path::new(transcript)), Some(slot));
    }
    assert_ne!(
        transcript_home_key(Path::new(
            "/Users/someone/.claude/projects/-x/session.jsonl"
        )),
        Some(slot)
    );
    assert_eq!(
        transcript_home_key(Path::new("/tmp/loose/session.jsonl")),
        None
    );
}
