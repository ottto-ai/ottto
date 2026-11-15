// The Codex login-identity rows of the shared transition matrix (T1-T10 and
// the bind-path row). Included inside the money-equivalence pipeline fixture.
// Status comes from real scratch homes, never injected tuples: a synthetic-JWT
// `auth.json` plus provider readings saved by the production save path, read
// back as the status lane does. Each page then rechecks the bindings
// (`current_codex_home_bindings`) and binds (`bind_session_accounts_with_mixed`)
// as the daemon's scan step does.
use super::*;
use crate::agent_status::codex_login_oracle_support::{self as status, ProviderRead};
use crate::agent_status::AgentStatusCollection;
use crate::snapshots::sampled_scan::transition_fixture::{
    self as fixture, money_oracle, Mode, RouteResult,
};
use serde_json::json;

// NOT COVERED here: T4 drives the production save path with an injected read
// (the provider boundary is agent_status's
// `codex_probe_confirms_no_identity_when_the_login_switches_during_the_read`);
// T5's same-login reader sharing needs the quota scheduler, so it is checked
// at the binding level only; T7's launch block is covered by the launch tests.
// `Disk` has no durable-restore arm apart from a restarted owner over the
// committed route, so `Mode::DiskRestore` is not driven separately here.

const LIVE: i64 = 30 * 86_400;
const EXPIRED: i64 = -3_600;
const SIX_HOURS: u64 = 6 * 60 * 60;

/// While held, the command search finds no `codex`: the status collection
/// runs no CLI against the scratch homes.
struct NoCodexCli {
    previous: Option<std::ffi::OsString>,
    _empty: crate::test_scratch::ScratchDir,
}

fn no_codex_cli() -> NoCodexCli {
    let empty = crate::test_scratch::ScratchDir::new("codex-login-no-cli");
    let previous = std::env::var_os("OTTTO_COMMAND_SEARCH_PATH");
    unsafe { std::env::set_var("OTTTO_COMMAND_SEARCH_PATH", empty.as_os_str()) };
    NoCodexCli {
        previous,
        _empty: empty,
    }
}

impl Drop for NoCodexCli {
    fn drop(&mut self) {
        match self.previous.take() {
            Some(previous) => unsafe { std::env::set_var("OTTTO_COMMAND_SEARCH_PATH", previous) },
            None => unsafe { std::env::remove_var("OTTTO_COMMAND_SEARCH_PATH") },
        }
    }
}

fn hash(kind: &str, raw: &str) -> String {
    ottto_core::billing_identity_hash("openai", kind, raw).unwrap()
}

fn clock(at: &str) -> std::time::SystemTime {
    let at = OffsetDateTime::parse(at, &Rfc3339)
        .unwrap()
        .unix_timestamp();
    std::time::UNIX_EPOCH + std::time::Duration::from_secs(at as u64)
}

fn jwt(user: &str, workspace: &str, lifetime: i64) -> String {
    let expires_at = OffsetDateTime::now_utc().unix_timestamp() + lifetime;
    crate::agent_status::tests::synthetic_codex_jwt(user, workspace, "synthetic", "pro", expires_at)
}

/// A managed home (owner-only, canonical) with a config and no login yet.
fn home(root: &Path, name: &str) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let home = root.join(name);
    crate::test_scratch::create_private_dir(&home).unwrap();
    std::fs::create_dir(home.join("sessions")).unwrap();
    let config = home.join("config.toml");
    std::fs::write(&config, "model = \"gpt-5.2\"\n").unwrap();
    std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o600)).unwrap();
    home
}

/// `user` signed in to `workspace`: id and access tokens living `id` and
/// `access` seconds from now, `auth.json` last written at `modified`.
fn sign_in(home: &Path, user: &str, workspace: &str, (id, access): (i64, i64), modified: &str) {
    use std::os::unix::fs::PermissionsExt;
    let auth = home.join("auth.json");
    let tokens = json!({"access_token":jwt(user, workspace, access),
        "id_token":jwt(user, workspace, id)});
    let body = json!({"tokens":tokens,"account_id":workspace}).to_string();
    std::fs::write(&auth, body).unwrap();
    std::fs::set_permissions(&auth, std::fs::Permissions::from_mode(0o600)).unwrap();
    let file = std::fs::File::options().write(true).open(&auth).unwrap();
    file.set_modified(clock(modified)).unwrap();
}

/// A read that validated `user` in `workspace`, `age` seconds ago.
fn bound(user: &str, workspace: &str, age: u64) -> ProviderRead {
    ProviderRead::Bound(hash("account", user), hash("workspace", workspace), age)
}

fn read(home: &Path, read: ProviderRead) {
    status::save_read(home, || {}, read);
}

fn sid(n: usize) -> String {
    format!("{:08x}-f36e-4cbc-a5bb-50fc66430ba5", 0x5000_0000 + n)
}

/// One turn of `session` at `start`'s minute; every row records a ChatGPT
/// login, so only the home's binding can name its owner.
fn rows(session: &str, start: &str, turn: &str, tokens: u64) -> String {
    let at = |second: u8| format!("{}{second:02}Z", &start[..17]);
    let usage = json!({"input_tokens":tokens,"cached_input_tokens":0,"output_tokens":2,
        "reasoning_output_tokens":0,"total_tokens":tokens + 2});
    [
        json!({"type":"event_msg","timestamp":at(1),"payload":{"type":"task_started","turn_id":turn}}),
        json!({"type":"token_usage_record","timestamp":at(2),"payload":{"thread_id":session,
            "turn_id":turn,"response_id":turn,"auth_mode":"chatgpt","usage":usage,
            "thread_token_usage":usage}}),
        json!({"type":"event_msg","timestamp":at(3),"payload":{"type":"token_count","info":{
            "model":"gpt-5.2","auth_mode":"chatgpt","last_token_usage":usage,
            "total_token_usage":usage}}}),
        json!({"type":"event_msg","timestamp":at(4),"payload":{"type":"task_complete","turn_id":turn}}),
    ]
    .iter()
    .map(|line| line.to_string() + "\n")
    .collect()
}

/// A session file: (path, id, start).
type Session = (PathBuf, String, String);
/// Each emitted session's owner.
type Owners = BTreeMap<String, Option<String>>;

/// Session `id` started in `home` at `at`, with one turn.
fn start(home: &Path, id: &str, at: &str) -> Session {
    write_session(home, id, at, json!({}))
}

/// A side call: a subagent session `parent` spawned in the same home at `at`,
/// headed as Codex heads a spawned thread (no copied history).
fn side_call(home: &Path, id: &str, parent: &str, at: &str) -> Session {
    let source = json!({"subagent":{"thread_spawn":{"parent_thread_id":parent,"depth":1}}});
    write_session(
        home,
        id,
        at,
        json!({"thread_source":"subagent","source":source}),
    )
}

fn write_session(home: &Path, id: &str, at: &str, header: serde_json::Value) -> Session {
    let stamp = at.replace(':', "-");
    let path = home.join(format!("sessions/rollout-{}-{id}.jsonl", &stamp[..19]));
    let mut payload = json!({"id":id,"timestamp":at});
    for (key, value) in header.as_object().unwrap() {
        payload[key] = value.clone();
    }
    let header = json!({"type":"session_meta","timestamp":at,"payload":payload});
    std::fs::write(
        &path,
        header.to_string() + "\n" + &rows(id, at, "turn-a", 10),
    )
    .unwrap();
    input_clock(&path);
    (path, id.to_string(), at.to_string())
}

fn grow(sessions: &[Session]) {
    grow_by(sessions, "turn-b", 20);
}

fn grow_by(sessions: &[Session], turn: &str, tokens: u64) {
    for (path, id, at) in sessions {
        append(path, &rows(id, at, turn, tokens));
        input_clock(path);
    }
}

/// One page: the scan, then the daemon's bind step over the status the lane
/// collected before it.
fn page(
    scanner: &E2ScanFixture,
    support: &Path,
    roots: &[PathBuf],
    prior: ScanIndex,
    collected: &AgentStatusCollection,
) -> (ScanIndex, SourceScanResult, (usize, usize, usize)) {
    let source = SnapshotSource::Codex;
    let prior = crate::snapshots::e2_pipeline_scan_fixture::route_for_test(
        source,
        Some(scanner.cache.as_ref()),
        prior,
    );
    let (mut index, mut scan, modes) = scanner.scan_other(source, roots, support, prior, true);
    // snapshot_sync: recheck after the scan, then bind.
    let current = crate::agent_status_refresh::current_codex_home_bindings(collected);
    index.bind_session_accounts_with_mixed(
        source,
        "e2-synthetic-machine",
        &mut scan.snapshots,
        &current,
        (&[], &mut [0; 9]),
        &Default::default(),
    );
    apply_upload_policy(source, &mut scan.snapshots, SnapshotUploadPolicy::default());
    finalize_scan_after_policy(source, &mut scan, &mut index);
    scan.finish_codex_capture_boundary(&mut index);
    (index, scan, modes)
}

/// Each emitted session's one row owner.
fn tags(scan: &SourceScanResult) -> Owners {
    let mut tags = BTreeMap::new();
    for item in &scan.snapshots {
        let mut rows = item.model_usage.iter().chain(
            item.usage_buckets
                .iter()
                .flat_map(|bucket| bucket.model_usage.iter()),
        );
        let owner = rows
            .next()
            .expect("usage rows")
            .account_identifier_hash
            .clone();
        assert!(rows.all(|row| row.account_identifier_hash == owner));
        tags.insert(item.source_session_id.clone(), owner);
    }
    tags
}

/// A page's index and scan.
type Scanned = (ScanIndex, SourceScanResult);

/// `page`'s ACKs land and the daemon commits it; with `walk`, the saved
/// indexed walk a quiet restart resumes from.
fn commit_page(
    disk: &Disk,
    scanner: &E2ScanFixture,
    (mut index, scan): Scanned,
    walk: Option<&[PathBuf]>,
) -> ScanIndex {
    let source = SnapshotSource::Codex;
    index.record_accepted_snapshot_fingerprints(
        &scan
            .snapshots
            .iter()
            .map(|s| s.snapshot_fingerprint.clone())
            .collect(),
    );
    if let Some(roots) = walk {
        crate::snapshots::e2_pipeline_scan_fixture::retain_indexed_walk_for_test(
            &mut index,
            source,
            roots,
            "2026-10-27T08:00:00Z",
            183,
        );
    }
    let committed = disk.commit(&scanner.cache, source, &mut index);
    assert!(
        scan.snapshots
            .iter()
            .all(|s| { committed.accepted_snapshot_fingerprint_recorded(&s.snapshot_fingerprint) }),
        "the page's ACKs are saved"
    );
    committed
}

/// The first page on a fresh owner, accepted and committed.
fn first_page(
    c: &Corpus,
    disk: &mut Disk,
    roots: &[PathBuf],
    collected: &AgentStatusCollection,
) -> (E2ScanFixture, ScanIndex, Owners) {
    let scanner = disk.owner(SnapshotSource::Codex);
    let (live, first, _) = page(&scanner, &c.support, roots, ScanIndex::default(), collected);
    let owners = tags(&first);
    let prior = commit_page(disk, &scanner, (live, first), None);
    (scanner, prior, owners)
}

/// After a changed transition: the warm owner's page (`ram`) is accepted and
/// committed; a restarted owner over the unchanged transcripts then opens
/// none, reads no byte and emits nothing. Returns the committed index.
fn quiet_restart(
    c: &Corpus,
    disk: &mut Disk,
    scanner: &E2ScanFixture,
    roots: &[PathBuf],
    ram: Scanned,
    collected: &AgentStatusCollection,
) -> ScanIndex {
    let source = SnapshotSource::Codex;
    let settled = commit_page(disk, scanner, ram, Some(roots));
    let restarted = disk.owner(source);
    let opens = crate::snapshots::all_transcript_opens_for_test();
    let ((_, quiet_scan, modes), consumed) = fixture::observe_consumed(|| {
        page(&restarted, &c.support, roots, settled.clone(), collected)
    });
    assert!(quiet_scan.snapshots.is_empty(), "no re-emission");
    let measured = (crate::snapshots::all_transcript_opens_for_test() == opens).then_some(0);
    let mut quiet = RouteResult::emitted(Mode::Restart, source, Vec::new(), &[]);
    quiet.modes = modes;
    quiet.io = fixture::IoBytes {
        consumed,
        cheap_checks: measured,
        anchor_reads: measured,
        other_reads: measured,
        ..Default::default()
    };
    money_oracle::assert_quiet_restart_zero_bytes(&quiet);
    settled
}

/// The next page on cold Full, a restarted owner and the current owner's
/// Tail, each equal to cold Full in money and placement; cold's owners; and
/// the current owner's page, for the commit after it.
fn routes(
    c: &Corpus,
    disk: &mut Disk,
    scanner: &E2ScanFixture,
    roots: &[PathBuf],
    prior: &ScanIndex,
    collected: &AgentStatusCollection,
) -> (Vec<RouteResult>, Owners, Scanned) {
    let source = SnapshotSource::Codex;
    let cold = page(
        &E2ScanFixture::default(),
        &c.support,
        roots,
        prior.clone(),
        collected,
    );
    let owner = disk.owner(source);
    let restart = page(&owner, &c.support, roots, prior.clone(), collected);
    disk.begin(scanner, source);
    let ram = page(scanner, &c.support, roots, prior.clone(), collected);
    assert_eq!((cold.2 .1, cold.2 .2), (0, 0), "cold Full");
    assert!(
        restart.2 .1 > 0 && ram.2 .1 > 0,
        "Tail from committed heads"
    );
    let owners = tags(&cold.1);
    let route =
        |mode: Mode,
         (index, scan, modes): &(ScanIndex, SourceScanResult, (usize, usize, usize))| {
            let wire = vec![other_wire(source, scan)];
            let mut route = RouteResult::emitted(mode, source, wire, &scan.snapshots);
            route.codex_evidence = fixture::codex_evidence(index, scan);
            route.modes = *modes;
            route
        };
    let routes = vec![
        route(Mode::ColdFull, &cold),
        route(Mode::Restart, &restart),
        route(Mode::Ram, &ram),
    ];
    for other in &routes[1..] {
        money_oracle::assert_equivalent(&routes[0], other);
    }
    (routes, owners, (ram.0, ram.1))
}

/// A row: `setup` before the first page; `change` before the second page's
/// status read; `between` after it, before the bind. `expect`: owner of the
/// old session (07:00) after pages 1 and 2, and of the new one (07:45).
struct Row {
    tag: &'static str,
    setup: fn(&Path, &str),
    change: fn(&Path, &str),
    between: fn(&Path, &str),
    expect: [Option<char>; 3],
}

/// `tag`'s login `who`: user `<tag>-<who>` in workspace `ws-<tag>-<who>`.
fn login(home: &Path, tag: &str, who: char, life: (i64, i64), modified: &str) {
    sign_in(
        home,
        &format!("{tag}-{who}"),
        &format!("ws-{tag}-{who}"),
        life,
        modified,
    );
}

fn read_as(home: &Path, tag: &str, who: char, age: u64) {
    read(
        home,
        bound(&format!("{tag}-{who}"), &format!("ws-{tag}-{who}"), age),
    );
}

/// Access expired, file unchanged since a read that validated `a`.
fn carried(home: &Path, tag: &str) {
    login(home, tag, 'a', (EXPIRED, -60), "2026-10-27T06:00:00Z");
    read_as(home, tag, 'a', 60);
}

fn live(home: &Path, tag: &str) {
    login(home, tag, 'a', (LIVE, LIVE), "2026-10-27T06:00:00Z");
    read_as(home, tag, 'a', 60);
}

fn same(_: &Path, _: &str) {}

/// Pre-change saved bytes for `tag`'s login `a`: a success, then a newer
/// failure saved with no binding and `refresh_held`, as an older release
/// wrote them. `auth.json` must already be written.
fn pinned_saved(home: &Path, tag: &str) -> serde_json::Value {
    let metadata = std::fs::metadata(home.join("auth.json")).unwrap();
    let modified = metadata.modified().unwrap();
    let modified = modified.duration_since(std::time::UNIX_EPOCH).unwrap();
    let auth = json!({"modified_secs":modified.as_secs(),
        "modified_nanos":modified.subsec_nanos(),"len":metadata.len()});
    let account = hash("account", &format!("{tag}-a"));
    let workspace = hash("workspace", &format!("ws-{tag}-a"));
    let now = OffsetDateTime::now_utc().unix_timestamp() as u64;
    json!({"schema_version":1,"home_key":"{home_key}",
        "reading":{"observed_at_epoch_seconds":now - 600,
            "login":{"binding":format!("{account}:{workspace}"),"auth":auth},
            "identity":{"account_identifier_hash":account,
                "workspace_identifier_hash":workspace},
            "provider_account_signed_in":true,"plan_type":"pro",
            "quota_windows":[],"credit_balances":[],"credential_read_failed":false},
        "last_attempt_at_epoch_seconds":now - 60,"last_attempt_login":{"auth":auth},
        "last_failure":{"at_epoch_seconds":now - 60,
            "message":"Codex app-server account read failed.",
            "login":{"auth":auth},"refresh_held":true}})
}

/// T8's setup: id token expired, access live; the pinned bytes saved.
fn pinned_failure(home: &Path, tag: &str) {
    login(home, tag, 'a', (EXPIRED, LIVE), "2026-10-27T06:00:00Z");
    status::write_saved(home, &pinned_saved(home, tag).to_string());
}

const ROWS: &[Row] = &[
    // T1: id expired, access live, file unchanged: sessions after the
    // auth write only.
    Row {
        tag: "t1",
        setup: |home, tag| {
            login(home, tag, 'a', (EXPIRED, LIVE), "2026-10-27T07:10:00Z");
            read_as(home, tag, 'a', 60);
        },
        change: same,
        between: same,
        expect: [None, None, Some('a')],
    },
    // T2: access expired, file unchanged, latest read ok: carried, as T1.
    Row {
        tag: "t2",
        setup: carried,
        change: same,
        between: same,
        expect: [Some('a'), Some('a'), Some('a')],
    },
    // T3: rewritten to B (expired, no read yet): never A after it.
    Row {
        tag: "t3r",
        setup: carried,
        change: |home, tag| login(home, tag, 'b', (EXPIRED, -60), "2026-10-27T07:30:00Z"),
        between: same,
        expect: [Some('a'), Some('a'), None],
    },
    // T3: unreadable (permission only; the witness is unchanged).
    Row {
        tag: "t3u",
        setup: carried,
        change: |home, _| {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::Permissions::from_mode(0o644);
            std::fs::set_permissions(home.join("auth.json"), mode).unwrap();
        },
        between: same,
        expect: [Some('a'), Some('a'), None],
    },
    // T3: contradictory: names B under an unchanged witness (same length,
    // same modification time).
    Row {
        tag: "t3c",
        setup: carried,
        change: |home, tag| {
            let len = || std::fs::metadata(home.join("auth.json")).unwrap().len();
            let before = len();
            login(home, tag, 'b', (EXPIRED, -60), "2026-10-27T06:00:00Z");
            assert_eq!(len(), before, "the witness must stay unchanged");
        },
        between: same,
        expect: [Some('a'), Some('a'), None],
    },
    // T4: A -> B inside one read: nothing saved; the next read is B.
    Row {
        tag: "t4",
        setup: |home, tag| {
            login(home, tag, 'a', (LIVE, LIVE), "2026-10-27T06:00:00Z");
            let switch = || login(home, tag, 'b', (LIVE, LIVE), "2026-10-27T07:30:00Z");
            let a = bound(&format!("{tag}-a"), &format!("ws-{tag}-a"), 0);
            status::save_read(home, switch, a);
        },
        change: |home, tag| read_as(home, tag, 'b', 0),
        between: same,
        expect: [None, None, Some('b')],
    },
    // T6: refresh off, no reads: carried until the 6 h cap, then none.
    Row {
        tag: "t6",
        setup: |home, tag| {
            login(home, tag, 'a', (EXPIRED, -60), "2026-10-27T06:00:00Z");
            read_as(home, tag, 'a', SIX_HOURS - 900);
        },
        change: |home, tag| read_as(home, tag, 'a', SIX_HOURS + 60),
        between: same,
        expect: [Some('a'), Some('a'), None],
    },
    // T7: dead login (account:null / auth_rejected): no new owner.
    Row {
        tag: "t7",
        setup: live,
        change: |home, _| read(home, ProviderRead::DeadLogin),
        between: same,
        expect: [Some('a'), Some('a'), None],
    },
    // T8: upgrade from pinned pre-change bytes: a newer failure saved with
    // no binding (id expired then) is still served, not the older success.
    Row {
        tag: "t8",
        setup: pinned_failure,
        change: same,
        between: same,
        expect: [None, None, None],
    },
    // (a): a rewrite between the status read and the bind drops the binding,
    // even for the same login; the persisted owner stays.
    Row {
        tag: "ta",
        setup: live,
        change: same,
        between: |home, tag| login(home, tag, 'a', (LIVE, LIVE), "2026-10-27T06:30:00Z"),
        expect: [Some('a'), Some('a'), None],
    },
];

/// [money] Each login-identity row, bound through the daemon's real status
/// and bind path, owns exactly the sessions its row names on every route.
#[test]
#[serial_test::serial]
fn codex_login_identity_rows_bind_through_the_status_lane() {
    if !supported("codex_login_identity_rows") {
        return;
    }
    let _cutover = crate::snapshots::TestCutover::set(0);
    let _no_cli = no_codex_cli();
    let c = corpus("transition-codex-login-identity-rows");
    let mut disk = Disk::with_route(&c, SnapshotSource::Codex);
    let root = crate::test_scratch::ScratchDir::canonical("codex-login-rows");
    let homes = ROWS
        .iter()
        .map(|row| home(&root, row.tag))
        .collect::<Vec<_>>();
    let roots = homes.iter().map(|h| h.join("sessions")).collect::<Vec<_>>();
    let owner = |row: &Row, who: Option<char>| {
        who.map(|who| hash("account", &format!("{}-{who}", row.tag)))
    };
    let mut old = Vec::new();
    for (index, (row, home)) in ROWS.iter().zip(&homes).enumerate() {
        (row.setup)(home, row.tag);
        old.push(start(home, &sid(2 * index), "2026-10-27T07:00:00Z"));
    }
    let collected = status::collection(&homes);
    let (scanner, prior, first) = first_page(&c, &mut disk, &roots, &collected);
    for (index, (row, home)) in ROWS.iter().zip(&homes).enumerate() {
        assert_eq!(
            first[&sid(2 * index)],
            owner(row, row.expect[0]),
            "{} page 1",
            row.tag
        );
        (row.change)(home, row.tag);
        start(home, &sid(2 * index + 1), "2026-10-27T07:45:00Z");
    }
    grow(&old);
    let collected = status::collection(&homes);
    for (row, home) in ROWS.iter().zip(&homes) {
        (row.between)(home, row.tag);
    }
    let (_, owners, ram) = routes(&c, &mut disk, &scanner, &roots, &prior, &collected);
    // Every row's change (T3's rewrites, (a)'s rewrite before the bind) left
    // the transcripts alone: a restart over the committed page reads nothing.
    quiet_restart(&c, &mut disk, &scanner, &roots, ram, &collected);
    for (index, row) in ROWS.iter().enumerate() {
        assert_eq!(
            owners[&sid(2 * index)],
            owner(row, row.expect[1]),
            "{} old",
            row.tag
        );
        assert_eq!(
            owners[&sid(2 * index + 1)],
            owner(row, row.expect[2]),
            "{} new",
            row.tag
        );
    }
}

/// [money] The positive control: two accounts, one user in two workspaces
/// (T5), a read gap that recovers on the same file (T9), and a `codex login`
/// switch in the middle of a session (T10). Its parent spawns side calls in
/// the same home before the switch (owned as the parent) and after it (owned
/// by the new login), both through the home's binding. Every route equals
/// cold Full; a restart after the switch reads nothing; swapped owners fail
/// the comparator.
#[test]
#[serial_test::serial]
fn codex_login_switch_gap_and_twin_workspaces_match_cold_full() {
    if !supported("codex_login_switch_gap_and_twin_workspaces") {
        return;
    }
    let _cutover = crate::snapshots::TestCutover::set(0);
    let _no_cli = no_codex_cli();
    let c = corpus("transition-codex-login-identity-matrix");
    let mut disk = Disk::with_route(&c, SnapshotSource::Codex);
    let root = crate::test_scratch::ScratchDir::canonical("codex-login-matrix");
    let homes = ["switch", "gap", "twin"].map(|name| home(&root, name));
    let [switch, gap, twin] = &homes;
    let roots = homes.iter().map(|h| h.join("sessions")).collect::<Vec<_>>();
    let six = "2026-10-27T06:00:00Z";
    sign_in(switch, "m-u", "m-w1", (EXPIRED, LIVE), six);
    read(switch, bound("m-u", "m-w1", 60));
    sign_in(gap, "m-v", "m-wv", (EXPIRED, LIVE), six);
    read(gap, bound("m-v", "m-wv", 120));
    read(gap, ProviderRead::Failed);
    sign_in(twin, "m-u", "m-w2", (EXPIRED, LIVE), six);
    read(twin, bound("m-u", "m-w2", 60));
    let [s1, s2, s3, s4, s5] = [0, 1, 2, 3, 4].map(|n| sid(100 + n));
    let sessions = [
        start(switch, &s1, "2026-10-27T07:00:00Z"),
        start(gap, &s2, "2026-10-27T07:00:00Z"),
        start(twin, &s3, "2026-10-27T07:00:00Z"),
        side_call(switch, &s5, &s1, "2026-10-27T07:05:00Z"),
    ];
    let collected = status::collection(homes.as_slice());
    // T5: one user, two workspaces, two homes: two bindings, never shared.
    let bindings = collected
        .codex_home_bindings
        .iter()
        .map(|b| {
            (
                b.home.clone(),
                (
                    b.account_identifier_hash.clone(),
                    b.workspace_identifier_hash.clone(),
                ),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let pair = |user: &str, workspace: &str| (hash("account", user), hash("workspace", workspace));
    assert_eq!(bindings.len(), 2, "the gap home is not bound");
    assert_eq!(bindings[switch], pair("m-u", "m-w1"));
    assert_eq!(bindings[twin], pair("m-u", "m-w2"));
    let [u, v, b] = ["m-u", "m-v", "m-b"].map(|user| Some(hash("account", user)));
    let (scanner, prior, first) = first_page(&c, &mut disk, &roots, &collected);
    let expected = BTreeMap::from([
        (s1.clone(), u.clone()),
        (s2.clone(), None),
        (s3.clone(), u.clone()),
        (s5.clone(), u.clone()),
    ]);
    assert_eq!(
        first, expected,
        "page 1: the gap leaves its session untagged"
    );
    // T10: `codex login` rewrites the switch home mid-session; T9: the gap
    // home's next read succeeds on the same file.
    sign_in(switch, "m-b", "m-wb", (LIVE, LIVE), "2026-10-27T07:30:00Z");
    read(switch, bound("m-b", "m-wb", 0));
    read(gap, bound("m-v", "m-wv", 0));
    grow(&sessions);
    side_call(switch, &s4, &s1, "2026-10-27T07:45:00Z");
    let collected = status::collection(homes.as_slice());
    let (routes, owners, ram) = routes(&c, &mut disk, &scanner, &roots, &prior, &collected);
    let expected = BTreeMap::from([
        (s1.clone(), u.clone()),
        (s2.clone(), v),
        (s3, u.clone()),
        (s4.clone(), b),
        (s5, u),
    ]);
    assert_eq!(
        owners, expected,
        "first writer keeps A; the gap recovers; B after"
    );
    for other in &routes[1..] {
        money_oracle::assert_no_smaller_reemit(&s2, &routes[0], other, &routes[0], false);
        money_oracle::assert_placement_equivalent(&routes[0], other);
    }
    let mut wrong = routes[1].clone();
    let [one, four] =
        [&s1, &s4].map(|s| wrong.snapshots[s]["model_usage"][0]["account_identifier_hash"].clone());
    for (session, owner) in [(&s1, four), (&s4, one)] {
        for row in wrong.snapshots.get_mut(session).unwrap()["model_usage"]
            .as_array_mut()
            .unwrap()
        {
            row["account_identifier_hash"] = owner.clone();
        }
    }
    assert!(std::panic::catch_unwind(|| {
        money_oracle::assert_placement_equivalent(&routes[0], &wrong)
    })
    .is_err());
    quiet_restart(&c, &mut disk, &scanner, &roots, ram, &collected);
}

/// [money] T8, interrupted: over the pinned pre-change bytes (a success,
/// then a newer failure with `refresh_held`), a save stops after writing its
/// temp file (holding that older success alone) and before the rename; the
/// process restarts. Before and after the next completed save (another
/// failure), the failure is served, never the older success, and every route
/// equals cold Full. A second home's login is the tagged control.
#[test]
#[serial_test::serial]
fn codex_interrupted_save_then_restart_still_serves_the_failure() {
    if !supported("codex_interrupted_save_then_restart") {
        return;
    }
    let _cutover = crate::snapshots::TestCutover::set(0);
    let _no_cli = no_codex_cli();
    let c = corpus("transition-codex-login-interrupted-save");
    let mut disk = Disk::with_route(&c, SnapshotSource::Codex);
    let root = crate::test_scratch::ScratchDir::canonical("codex-login-interrupted");
    let homes = ["t8i", "ctl"].map(|name| home(&root, name));
    let [held, control] = &homes;
    let roots = homes.iter().map(|h| h.join("sessions")).collect::<Vec<_>>();
    pinned_failure(held, "t8i");
    live(control, "ctl");
    let mut sessions = vec![
        start(held, &sid(200), "2026-10-27T07:00:00Z"),
        start(control, &sid(201), "2026-10-27T07:00:00Z"),
    ];
    let a = Some(hash("account", "ctl-a"));
    let collected = status::collection(homes.as_slice());
    let (scanner, prior, first) = first_page(&c, &mut disk, &roots, &collected);
    assert_eq!(
        first,
        BTreeMap::from([(sid(200), None), (sid(201), a.clone())])
    );
    let pinned = status::saved_bytes(held);
    let mut success = pinned_saved(held, "t8i");
    success.as_object_mut().unwrap().remove("last_failure");
    status::interrupt_save(held, &success.to_string());
    // Each served state: the held home has no binding; the control keeps its.
    let served = |collected: &AgentStatusCollection| {
        let bound = collected
            .codex_home_bindings
            .iter()
            .map(|b| b.home.clone())
            .collect::<Vec<_>>();
        assert_eq!(bound, vec![control.clone()], "the failure is served");
    };
    let expected = BTreeMap::from([(sid(200), None), (sid(201), a), (sid(202), None)]);
    // The restarted status lane reads the saved file (no attempt in memory).
    let collected = status::collection(homes.as_slice());
    served(&collected);
    grow(&sessions);
    sessions.push(start(held, &sid(202), "2026-10-27T07:45:00Z"));
    let (_, owners, ram) = routes(&c, &mut disk, &scanner, &roots, &prior, &collected);
    assert_eq!(owners, expected, "before the next completed save");
    let prior = commit_page(&disk, &scanner, ram, None);
    read(held, ProviderRead::Failed);
    assert_ne!(status::saved_bytes(held), pinned, "the next save completed");
    let collected = status::collection(homes.as_slice());
    served(&collected);
    grow_by(&sessions, "turn-c", 40);
    let (_, owners, _) = routes(&c, &mut disk, &scanner, &roots, &prior, &collected);
    assert_eq!(owners, expected, "after the next completed save");
}
