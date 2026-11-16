//! Idle logins: the local activity map, the 22 h cadence and its retry.

use super::accounts::{expected_identity, USER, WORKSPACE};
use super::all_logins::{grant_key, slot_login, ScopedReader, SECOND_WORKSPACE};
use super::*;
use crate::snapshots::{SessionAccountEvidence, SnapshotItem, SnapshotSource};
use account_activity::{ActivityStore, Page};
use logins::{CoverageHomes, LoginDiscovery};

const SECOND_USER: &str = "user-idle-second-private";
const HOUR: u64 = 60 * 60;
/// Read-to-read spacing on a 30 minute tick: the band plus one tick.
const SIX_HOUR_BAND: std::ops::RangeInclusive<u64> = (5 * HOUR + 45 * 60)..=(6 * HOUR + 45 * 60);
const DAILY_BAND: std::ops::RangeInclusive<u64> = (21 * HOUR + 45 * 60)..=(22 * HOUR + 45 * 60);
/// The deadline itself: the band around 6 h or 22 h.
const SIX_HOUR_DUE: std::ops::RangeInclusive<u64> = (5 * HOUR + 45 * 60)..=(6 * HOUR + 15 * 60);
const DAILY_DUE: std::ops::RangeInclusive<u64> = (21 * HOUR + 45 * 60)..=(22 * HOUR + 15 * 60);

fn at(seconds: u64) -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(i64::try_from(seconds).expect("seconds")).expect("instant")
}

fn t0() -> u64 {
    unix_seconds(now())
}

fn wall_clock() -> u64 {
    unix_seconds(OffsetDateTime::now_utc())
}

fn identified(user: &str, workspace: &str, slot: bool) -> CodexLogin {
    let mut login = if slot {
        slot_login(workspace)
    } else {
        login_with_scope(workspace)
    };
    login.identity = Some(expected_identity(user, workspace));
    login
}

/// A Codex session created by `user` in `workspace`, last active at `last`.
fn session(user: &str, workspace: &str, last: Option<u64>) -> SnapshotItem {
    let identity = expected_identity(user, workspace);
    SnapshotItem {
        session_account_evidence: Some(SessionAccountEvidence {
            provider: "openai",
            account_identifier_hash: Some(identity.account_identifier_hash),
            provider_workspace_hash: Some(identity.provider_workspace_hash),
            identity_hash_scheme: "provider-sha256:v1",
            evidence_source: "codex_creator_header:v1",
            identity_disposition: None,
            source_created_at: None,
        }),
        source_last_activity_at: last.map(|last| timestamp(at(last))),
        ..SnapshotItem::default()
    }
}

/// A session with no creator pair: display or plan attribution only.
fn unattributed(last: u64) -> SnapshotItem {
    SnapshotItem {
        source_last_activity_at: Some(timestamp(at(last))),
        ..SnapshotItem::default()
    }
}

/// One Mac: consent, the collector's stores and the scanned homes.
struct Mac {
    collector: Collector,
    store: ActivityStore,
    homes: Vec<PathBuf>,
}

impl Mac {
    fn new(name: &str) -> Self {
        Self::with(collector(name))
    }

    /// The collector's files laid out under a support directory, so the
    /// snapshot cycle's hooks write the same map.
    fn in_support(support: &Path) -> Self {
        let dir = support.join(GRANT_DIR);
        Self::with(Collector::new(
            GrantStore::new(dir.join(GRANT_FILE)),
            StateStore::new(dir.join(STATE_FILE)),
            dir.join(SENTINEL_FILE),
        ))
    }

    fn with(collector: Collector) -> Self {
        enabled(&collector);
        let store = ActivityStore::beside(collector.state_path());
        Self {
            collector,
            store,
            homes: vec![
                PathBuf::from("/fixture/codex-home"),
                PathBuf::from("/fixture/codex-slot"),
            ],
        }
    }

    /// A loss-free, current page completing its own generation, started a
    /// minute before `now`.
    fn page<'a>(&'a self, now: u64, snapshots: &'a [SnapshotItem]) -> Page<'a> {
        Page {
            snapshots,
            homes: &self.homes,
            loss_free: true,
            current: true,
            census_complete: true,
            window_end: Some(now - 60),
            window_days: 3,
        }
    }

    fn fold_page(&self, page: &Page<'_>, now: u64) {
        account_activity::fold(&self.store, self.collector.grants(), page, now);
    }

    fn fold(&self, now: u64, snapshots: &[SnapshotItem]) {
        self.fold_page(&self.page(now, snapshots), now);
    }

    /// Hourly empty pages over `[from, to]`.
    fn observe(&self, from: u64, to: u64) {
        let mut now = from;
        while now <= to {
            self.fold(now, &[]);
            now += HOUR;
        }
    }

    fn discovery(&self, logins: Vec<CodexLogin>) -> LoginDiscovery {
        let mut discovery = discovered(&self.collector, logins);
        discovery.coverage_homes = CoverageHomes(self.homes.clone());
        discovery.codex_scan_enabled = true;
        discovery
    }

    fn binding(&self) -> StateBinding {
        let grant = self
            .collector
            .grants()
            .load()
            .expect("load")
            .expect("grant");
        StateBinding::of(grant.backend_binding.as_ref().expect("binding"))
    }

    fn idle(&self, discovery: &LoginDiscovery, login: &CodexLogin, now: u64) -> bool {
        account_activity::idle(
            self.store.load_trusted().as_ref(),
            discovery,
            &self.binding(),
            t0(),
            login.identity.as_ref(),
            now,
        )
    }

    fn raw(&self) -> Value {
        serde_json::from_slice(&fs::read(self.store_path()).expect("map bytes")).expect("map json")
    }

    fn store_path(&self) -> PathBuf {
        self.collector
            .state_path()
            .with_file_name(account_activity::ACTIVITY_FILE)
    }

    fn entry(&self, scope: &str) -> CollectorState {
        let grant = self
            .collector
            .grants()
            .load()
            .expect("load")
            .expect("grant");
        let key = grant_key(&self.collector);
        self.collector.state.load(&state_identity_for_account(
            &grant,
            &opaque_key(&key, scope),
            false,
        ))
    }

    /// Ticks every 30 minutes over `[from, to)`, folding a page before each
    /// with `sessions(now)`. Returns every login's read times by ordinal.
    fn simulate(
        &self,
        discovery: &LoginDiscovery,
        reader: &dyn ProviderDailyUsageReader,
        (from, to): (u64, u64),
        sessions: impl Fn(u64) -> Vec<SnapshotItem>,
    ) -> BTreeMap<usize, Vec<u64>> {
        let transport = RecordingTransport::default();
        let mut reads = BTreeMap::<usize, Vec<u64>>::new();
        let mut now = from;
        while now < to {
            self.fold(now, &sessions(now));
            let instant = at(now);
            let cycle =
                self.collector
                    .run_tick(&runtime(), discovery, reader, &transport, &move || instant);
            for account in cycle.accounts.iter().filter(|a| a.reason == Some("ok")) {
                reads.entry(account.ordinal).or_default().push(now);
            }
            now += 30 * 60;
        }
        reads
    }
}

fn gaps(times: &[u64]) -> Vec<(u64, u64)> {
    times
        .windows(2)
        .map(|pair| (pair[0], pair[1] - pair[0]))
        .collect()
}

/// [behaviour] A login whose account made no session for 72 h of complete
/// observation is read about every 22 h; a busy login stays at 6 h. Each
/// login's reads follow its own band, before and after.
#[test]
fn an_account_unused_for_72_hours_is_read_about_daily() {
    let mac = Mac::new("idle-cadence");
    let quiet = identified(USER, WORKSPACE, false);
    let busy = identified(SECOND_USER, SECOND_WORKSPACE, true);
    let discovery = mac.discovery(vec![quiet, busy]);
    let reader = ScopedReader::distinct();
    let start = t0();
    let reads = mac.simulate(&discovery, &reader, (start, start + 6 * 24 * HOUR), |now| {
        vec![session(SECOND_USER, SECOND_WORKSPACE, Some(now - 60))]
    });
    for (from, gap) in gaps(&reads[&1]) {
        if from + gap <= start + 72 * HOUR {
            assert!(SIX_HOUR_BAND.contains(&gap), "quiet before 72 h: {gap}");
        } else if from >= start + 72 * HOUR {
            assert!(DAILY_BAND.contains(&gap), "quiet after 72 h: {gap}");
        }
    }
    assert!(gaps(&reads[&2])
        .iter()
        .all(|(_, gap)| SIX_HOUR_BAND.contains(gap)));
    assert!(reads[&1].len() + 6 < reads[&2].len());
}

/// [behaviour] Quiet then active again: a new session for one account puts
/// only that login back on the 6 h band; an unattributed session puts every
/// login there. Activity blocks idleness until strictly older than 72 h;
/// 72 h of observation is exactly enough. A reversed clock fails open.
#[test]
fn quiet_then_active_again_and_the_72_hour_boundaries() {
    let mac = Mac::new("quiet-then-active");
    let first = identified(USER, WORKSPACE, false);
    let second = identified(SECOND_USER, SECOND_WORKSPACE, true);
    let discovery = mac.discovery(vec![first.clone(), second.clone()]);
    let start = t0();
    mac.observe(start, start + 72 * HOUR);
    assert!(!mac.idle(&discovery, &first, start + 72 * HOUR - 1));
    assert!(mac.idle(&discovery, &first, start + 72 * HOUR));

    // Through the collector: both quiet, then the first is active again.
    let reader = ScopedReader::distinct();
    let resumed = start + 80 * HOUR;
    let reads = mac.simulate(
        &discovery,
        &reader,
        (start + 73 * HOUR, resumed + 30 * HOUR),
        |now| {
            if now == resumed {
                vec![session(USER, WORKSPACE, Some(now))]
            } else {
                Vec::new()
            }
        },
    );
    let after = |ordinal: usize| {
        let times = &reads[&ordinal];
        let last_before = times.iter().copied().filter(|time| *time < resumed).max();
        let first_after = times.iter().copied().find(|time| *time >= resumed);
        (
            last_before.expect("read before"),
            first_after.expect("read after"),
        )
    };
    // Idle since the first tick; the session brings the first login back:
    // read at once (its 6 h band has passed), then every 6 h.
    let (before, next) = after(1);
    assert!(next - before < *DAILY_BAND.start(), "active again");
    assert_eq!(next, resumed);
    assert!(gaps(&reads[&1])
        .iter()
        .filter(|(from, _)| *from >= resumed)
        .all(|(_, gap)| SIX_HOUR_BAND.contains(gap)));
    let (before, next) = after(2);
    assert!(
        DAILY_BAND.contains(&(next - before)),
        "the other stays slow"
    );

    // The boundary: activity exactly 72 h old still blocks.
    let active_at = resumed;
    mac.observe(resumed + 31 * HOUR, active_at + 72 * HOUR);
    assert!(!mac.idle(&discovery, &first, active_at + 72 * HOUR));
    assert!(mac.idle(&discovery, &first, active_at + 72 * HOUR + 1));
    assert!(mac.idle(&discovery, &second, active_at + 72 * HOUR));
    // A clock behind the map's own times fails open.
    assert!(!mac.idle(&discovery, &second, active_at + 72 * HOUR - 600));

    let unknown = active_at + 72 * HOUR + HOUR;
    mac.fold(unknown, &[unattributed(unknown - 60)]);
    assert!(!mac.idle(&discovery, &first, unknown));
    assert!(!mac.idle(&discovery, &second, unknown));
}

/// [behaviour] A page gap over 2 h, a resumed generation, a stop or a lossy
/// page makes every login active until a complete, loss-free generation that
/// started after it; the 72 h clock is not restarted.
#[test]
fn a_gap_needs_a_clean_generation_started_after_it() {
    let login = identified(USER, WORKSPACE, false);
    for (case, gap_hours) in [
        ("short", 1),
        ("overnight", 8),
        ("over 72 h", 100),
        ("repeated", 3),
    ] {
        let mac = Mac::new("gap-recovery");
        let discovery = mac.discovery(vec![login.clone()]);
        let start = t0();
        mac.observe(start, start + 80 * HOUR);
        let back = start + 80 * HOUR + gap_hours * HOUR + if gap_hours == 1 { 30 * 60 } else { 0 };
        // The page after the gap continues a generation begun before it.
        let mut resumed = mac.page(back, &[]);
        resumed.window_end = Some(start + 80 * HOUR - 60);
        mac.fold_page(&resumed, back);
        if case == "short" {
            assert!(mac.idle(&discovery, &login, back), "{case}");
            continue;
        }
        assert!(!mac.idle(&discovery, &login, back), "{case}: barrier");
        let mut back = back;
        if case == "repeated" {
            back += 3 * HOUR;
            mac.fold(back, &[]);
            assert!(
                !mac.idle(&discovery, &login, back),
                "{case}: second barrier"
            );
        }
        mac.fold(back + HOUR, &[]);
        assert!(
            mac.idle(&discovery, &login, back + HOUR),
            "{case}: no new 72 h wait"
        );
    }

    // A generation running across a barrier never anchors, even complete.
    let mac = Mac::new("gap-running-generation");
    let discovery = mac.discovery(vec![login.clone()]);
    let start = t0();
    mac.observe(start, start + 80 * HOUR);
    let running = start + 80 * HOUR + 10 * 60;
    let mut page = mac.page(running + 60, &[]);
    page.census_complete = false;
    mac.fold_page(&page, running + 60);
    let lossy = running + HOUR;
    let mut page = mac.page(lossy, &[]);
    page.window_end = Some(running);
    page.census_complete = false;
    page.loss_free = false;
    mac.fold_page(&page, lossy);
    let done = lossy + HOUR;
    let mut page = mac.page(done, &[]);
    page.window_end = Some(running);
    mac.fold_page(&page, done);
    assert!(!mac.idle(&discovery, &login, done));
    mac.fold(done + HOUR, &[]);
    assert!(mac.idle(&discovery, &login, done + HOUR));
}

/// [behaviour] A paused, ungranted or not yet resumed Codex scan never
/// proves idleness; a policy stop (written once) or a resume is a barrier
/// written by the snapshot cycle's own hooks, until a later generation.
#[test]
fn a_paused_or_resumed_codex_scan_is_never_idle() {
    let support = temp_dir("idle-stop-paths");
    let mac = Mac::in_support(&support);
    let login = identified(USER, WORKSPACE, false);
    let mut discovery = mac.discovery(vec![login.clone()]);
    let start = wall_clock();
    mac.observe(start - 80 * HOUR, start);
    let idle_at = |discovery: &LoginDiscovery, now: u64| {
        account_activity::idle(
            mac.store.load_trusted().as_ref(),
            discovery,
            &mac.binding(),
            start - 80 * HOUR,
            login.identity.as_ref(),
            now,
        )
    };
    assert!(idle_at(&discovery, wall_clock()));

    let device = |sources: &[&str]| ottto_core::LocalDeviceBinding {
        device_id: INSTALLATION_ID.to_string(),
        machine_id: None,
        sources: sources.iter().map(|source| source.to_string()).collect(),
    };
    type Pause = fn(&Path);
    let disable = |support: &Path| {
        crate::snapshot_sync::disable_snapshot_source(support, SnapshotSource::Codex).unwrap()
    };
    let cases: [(&str, &[&str], Pause); 5] = [
        ("enabled", &["codex"], |_| {}),
        ("local disable or heartbeat OFF", &["codex"], disable),
        ("reconnect pending", &["codex"], |support| {
            crate::snapshot_sync::disable_snapshot_source(support, SnapshotSource::Codex).unwrap();
            crate::snapshot_sync::reconnect_snapshot_source(support, SnapshotSource::Codex)
                .unwrap();
        }),
        ("unreadable marker", &["codex"], |support| {
            let marker = support.join("snapshots").join("codex.source-disabled");
            fs::create_dir_all(&marker).unwrap();
        }),
        ("dropped from the device grant", &[], |_| {}),
    ];
    for (case, sources, pause) in cases {
        let scratch = temp_dir("idle-pause-marker");
        pause(&scratch);
        discovery.codex_scan_enabled =
            crate::snapshot_sync::enabled_snapshot_sources_in(&device(sources), &scratch)
                .contains(&SnapshotSource::Codex);
        assert_eq!(
            idle_at(&discovery, wall_clock()),
            case == "enabled",
            "{case}"
        );
    }
    discovery.codex_scan_enabled = true;

    // A policy stop: one barrier, written once.
    account_activity::note_policy_stop(&support);
    assert!(!idle_at(&discovery, wall_clock()), "policy stop");
    let bytes = fs::read(mac.store_path()).unwrap();
    account_activity::note_policy_stop(&support);
    assert_eq!(fs::read(mac.store_path()).unwrap(), bytes, "written once");
    let later = wall_clock() + 120;
    mac.fold(later, &[]);
    assert!(idle_at(&discovery, later), "a generation after the stop");

    // Pause and resume between two ticks: the resume hook leaves a barrier.
    crate::snapshot_sync::disable_snapshot_source(&support, SnapshotSource::Codex).unwrap();
    crate::snapshot_sync::reconnect_snapshot_source(&support, SnapshotSource::Codex).unwrap();
    crate::snapshot_sync::resume_reconnected_sources(&support);
    assert!(!idle_at(&discovery, wall_clock()), "resume");
    let later = wall_clock() + 240;
    mac.fold(later, &[]);
    assert!(idle_at(&discovery, later), "a generation after the resume");
}

/// [behaviour] Consent lost writes no observation and deletes nothing; its
/// return, or a new epoch, restarts the 72 h clock. Each Mac root keeps its
/// own map.
#[test]
fn consent_loss_and_a_new_epoch_restart_the_observation() {
    let login = identified(USER, WORKSPACE, false);
    for case in ["consent lost and back", "new epoch"] {
        let mac = Mac::new("idle-consent");
        let discovery = mac.discovery(vec![login.clone()]);
        let start = t0();
        mac.fold(start, &[session(USER, WORKSPACE, Some(start - 60))]);
        mac.observe(start + HOUR, start + 80 * HOUR);
        assert!(mac.idle(&discovery, &login, start + 80 * HOUR), "{case}");
        let back = start + 81 * HOUR;
        if case == "consent lost and back" {
            let grant = fs::read(mac.collector.grants().path()).unwrap();
            fs::remove_file(mac.collector.grants().path()).unwrap();
            mac.fold(back, &[session(SECOND_USER, SECOND_WORKSPACE, Some(back))]);
            let raw = mac.raw();
            assert_eq!(raw["binding"], Value::Null, "{case}: proof dropped");
            assert_eq!(raw["anchor"], Value::Null);
            assert_eq!(
                raw["activity"].as_object().map(|map| map.len()),
                Some(1),
                "kept, none added"
            );
            fs::write(mac.collector.grants().path(), grant).unwrap();
        } else {
            let local = mac.collector.grants().load().unwrap().unwrap();
            mac.collector
                .grants()
                .bind_backend_grant(&grant_response(&local, "enabled", 2), INSTALLATION_ID)
                .unwrap();
        }
        mac.observe(back, back + 71 * HOUR);
        assert!(
            !mac.idle(&discovery, &login, back + 71 * HOUR),
            "{case}: full reset"
        );
        mac.observe(back + 72 * HOUR, back + 72 * HOUR);
        assert!(
            mac.idle(&discovery, &login, back + 72 * HOUR),
            "{case}: 72 h later"
        );
    }

    // Two roots with different consent never share a map.
    let first = Mac::new("idle-root-first");
    let second = Mac::new("idle-root-second");
    let local = second.collector.grants().load().unwrap().unwrap();
    second
        .collector
        .grants()
        .bind_backend_grant(&grant_response(&local, "enabled", 2), INSTALLATION_ID)
        .unwrap();
    first.observe(t0(), t0() + 80 * HOUR);
    assert!(second.store.load_trusted().is_none());
    second.fold(
        t0() + 80 * HOUR,
        &[session(USER, WORKSPACE, Some(t0() + 80 * HOUR))],
    );
    let discovery = first.discovery(vec![login.clone()]);
    assert!(first.idle(&discovery, &login, t0() + 80 * HOUR));
}

/// [format] Entries expire 90 days after their time and are pruned by later
/// permitted folds, also empty ones; while collection is stopped expired
/// entries stay in the file until the next permitted fold.
#[test]
fn retention_prunes_only_on_a_permitted_fold() {
    let mac = Mac::new("idle-retention");
    let start = t0();
    let day = 24 * HOUR;
    mac.fold(
        start,
        &[session(USER, WORKSPACE, Some(start)), unattributed(start)],
    );
    mac.fold(start + 90 * day, &[]);
    assert_eq!(
        mac.raw()["activity"].as_object().unwrap().len(),
        1,
        "exactly 90 days"
    );

    let grant = fs::read(mac.collector.grants().path()).unwrap();
    fs::remove_file(mac.collector.grants().path()).unwrap();
    mac.fold(start + 91 * day, &[]);
    let raw = mac.raw();
    assert_eq!(
        raw["activity"].as_object().unwrap().len(),
        1,
        "kept while stopped"
    );
    assert!(raw["unattributed_at"].is_u64());
    fs::write(mac.collector.grants().path(), grant).unwrap();
    mac.fold(start + 92 * day, &[]);
    let raw = mac.raw();
    assert!(
        raw["activity"].as_object().unwrap().is_empty(),
        "pruned on resume"
    );
    assert_eq!(raw["unattributed_at"], Value::Null);
}

/// [behaviour] Only the login's own creator pair counts: a slot pair, the
/// same user in another workspace, rows past any display limit, unknown or
/// future times. No pair (display or plan attribution only) keeps every
/// login active; an unidentified login is never idle.
#[test]
fn only_a_login_s_own_creator_pair_marks_it_active() {
    let own = identified(USER, WORKSPACE, false);
    let slot = identified(SECOND_USER, SECOND_WORKSPACE, true);
    let other_workspace = identified(USER, SECOND_WORKSPACE, true);
    let unidentified = login_with_scope("acct-unidentified-private");
    type Sessions = fn(u64) -> Vec<SnapshotItem>;
    let cases: [(&str, Sessions, [bool; 3]); 6] = [
        ("no sessions", |_| Vec::new(), [true, true, true]),
        (
            "slot creator pair",
            |now| vec![session(SECOND_USER, SECOND_WORKSPACE, Some(now))],
            [true, false, true],
        ),
        (
            "same user, other workspace",
            |now| vec![session(USER, SECOND_WORKSPACE, Some(now))],
            [true, true, false],
        ),
        (
            "beyond a 100 row list",
            |now| {
                let mut sessions = (0..150)
                    .map(|n| session(&format!("user-{n}"), WORKSPACE, Some(now)))
                    .collect::<Vec<_>>();
                sessions.push(session(USER, WORKSPACE, Some(now)));
                sessions
            },
            [false, true, true],
        ),
        (
            "unknown or future time",
            |now| {
                vec![
                    session(USER, WORKSPACE, None),
                    session(SECOND_USER, SECOND_WORKSPACE, Some(now + HOUR)),
                ]
            },
            [false, false, true],
        ),
        (
            "display or plan attribution only",
            |now| vec![unattributed(now)],
            [false, false, false],
        ),
    ];
    for (case, sessions, expected) in cases {
        let mac = Mac::new("idle-attribution");
        let logins = vec![
            own.clone(),
            slot.clone(),
            other_workspace.clone(),
            unidentified.clone(),
        ];
        let discovery = mac.discovery(logins);
        let start = t0();
        mac.observe(start, start + 79 * HOUR);
        let now = start + 80 * HOUR;
        mac.fold(now, &sessions(now));
        let idle = [&own, &slot, &other_workspace].map(|login| mac.idle(&discovery, login, now));
        assert_eq!(idle, expected, "{case}");
        assert!(
            !mac.idle(&discovery, &unidentified, now),
            "{case}: unidentified"
        );
    }
}

/// [behaviour] Every proof input must hold: a clean generation covering every
/// discovered home over at least 3 days, a complete discovery, a fresh and
/// current last page.
#[test]
fn an_idle_proof_needs_full_coverage_and_a_three_day_horizon() {
    let login = identified(USER, WORKSPACE, false);
    let cases = [
        "healthy",
        "a home outside the generation",
        "discovery incomplete",
        "a lossy page",
        "a deferred page",
        "a 2 day window",
        "no page for over 2 h",
    ];
    for case in cases {
        let mac = Mac::new("idle-coverage");
        let mut discovery = mac.discovery(vec![login.clone()]);
        let start = t0();
        mac.observe(start, start + 50 * HOUR);
        let (from, now) = (start + 51 * HOUR, start + 80 * HOUR);
        match case {
            "a home outside the generation" => {
                mac.observe(from, now);
                discovery
                    .coverage_homes
                    .0
                    .push(PathBuf::from("/fixture/codex-unscanned"));
            }
            "discovery incomplete" => {
                mac.observe(from, now);
                discovery.complete = false;
            }
            "a lossy page" | "a deferred page" => {
                mac.observe(from, now - HOUR);
                let mut page = mac.page(now, &[]);
                if case == "a lossy page" {
                    page.loss_free = false;
                } else {
                    page.current = false;
                    page.census_complete = false;
                }
                mac.fold_page(&page, now);
            }
            "a 2 day window" => mac.observe_with(from, now, |page| page.window_days = 2),
            "no page for over 2 h" => mac.observe(from, now - 3 * HOUR),
            _ => mac.observe(from, now),
        }
        assert_eq!(
            mac.idle(&discovery, &login, now),
            case == "healthy",
            "{case}"
        );
    }

    // One generation over 23 h of pages; a root change on one page keeps it
    // from anchoring.
    for dropped in [false, true] {
        let mac = Mac::new("idle-root-change");
        let discovery = mac.discovery(vec![login.clone()]);
        let start = t0();
        mac.observe(start, start + 50 * HOUR);
        let (from, done) = (start + 51 * HOUR, start + 74 * HOUR);
        let mut page_at = from;
        while page_at <= done {
            let mut page = mac.page(page_at, &[]);
            page.window_end = Some(from - 60);
            page.census_complete = page_at == done;
            if dropped && page_at == from + 10 * HOUR {
                page.homes = &mac.homes[..1];
            }
            mac.fold_page(&page, page_at);
            page_at += HOUR;
        }
        assert_eq!(
            mac.idle(&discovery, &login, done),
            !dropped,
            "dropped={dropped}"
        );
    }

    // Discovery keeps every home it was given in coverage: absent and
    // expired sign-ins, and a home deduplicated into another's login.
    let mac = Mac::new("idle-discovery-coverage");
    let scratch = crate::test_scratch::ScratchDir::canonical("pdr-idle-coverage");
    let auth = super::accounts::auth(
        &super::accounts::jwt(Some(USER), Some(WORKSPACE), super::accounts::live()),
        None,
        WORKSPACE,
    );
    let expired_auth = super::accounts::auth(
        &super::accounts::jwt(Some(USER), Some(WORKSPACE), super::accounts::expired()),
        None,
        WORKSPACE,
    );
    let homes = [
        super::accounts::home_with(&scratch, "default", Some(&auth), 0o600),
        super::accounts::home_with(&scratch, "absent", None, 0o600),
        super::accounts::home_with(&scratch, "expired", Some(&expired_auth), 0o600),
        super::accounts::home_with(&scratch, "duplicate", Some(&auth), 0o600),
    ];
    let found = logins::discover(
        homes
            .iter()
            .enumerate()
            .map(|(index, home)| crate::agent_status::DailyReferenceHome {
                slot_id: (index > 0).then(|| format!("slot-{index}")),
                home: home.clone(),
                trust: ottto_core::CodexHomeTrust::Managed,
                registered_pair: None,
            })
            .collect(),
        true,
        &grant_key(&mac.collector),
        t0(),
    );
    assert_eq!(found.coverage_homes.0, homes.to_vec());
    assert!(!found.codex_scan_enabled);
    let debug = format!("{found:?}");
    assert!(!debug.contains(&*homes[0].to_string_lossy()), "{debug}");
}

impl Mac {
    /// Hourly pages over `[from, to]`, each shaped by `shape`.
    fn observe_with(&self, from: u64, to: u64, shape: impl Fn(&mut Page<'_>)) {
        let mut now = from;
        while now <= to {
            let mut page = self.page(now, &[]);
            shape(&mut page);
            self.fold_page(&page, now);
            now += HOUR;
        }
    }
}

/// [money] An idle login's failed read is retried at the 6 h band whatever
/// failed after admission; a success, or a suppressed identical series, is
/// next due at the idle band. An excluded login stays unread.
#[test]
fn every_failed_idle_read_is_retried_at_six_hours() {
    let login = identified(USER, WORKSPACE, false);
    type Reader = Box<dyn ProviderDailyUsageReader>;
    type Transport = Box<dyn DailyReferenceTransport>;
    let answer = |payload: Value| -> Reader { Box::new(StaticReader::new(payload)) };
    let failing =
        |error: ProviderReadError| -> Reader { Box::new(FailingReader::new(vec![error])) };
    let rejecting = |error: UploadError| -> Transport { Box::new(RejectingTransport::new(error)) };
    let unused = || -> Transport { Box::new(ForbiddenTransport) };
    let exits: Vec<(&str, Reader, Transport)> = vec![
        (
            "ok",
            answer(poisoned_payload()),
            Box::new(RecordingTransport::default()),
        ),
        (
            "provider unavailable",
            failing(ProviderReadError::Transient("fixture".into())),
            unused(),
        ),
        (
            "auth rejected",
            failing(ProviderReadError::AuthRejected(401)),
            unused(),
        ),
        (
            "response shape",
            failing(ProviderReadError::ResponseShape("fixture".into())),
            unused(),
        ),
        (
            "rate limited",
            failing(ProviderReadError::RateLimited),
            unused(),
        ),
        (
            "workspace wide",
            failing(ProviderReadError::WorkspaceWide),
            unused(),
        ),
        (
            "normalize failure",
            answer(json!({"unexpected": true})),
            unused(),
        ),
        (
            "upload unavailable",
            answer(poisoned_payload()),
            rejecting(UploadError::Unavailable("fixture".into())),
        ),
        (
            "not admitted",
            answer(poisoned_payload()),
            rejecting(UploadError::NotAdmitted(403)),
        ),
        (
            "contract rejected",
            answer(poisoned_payload()),
            rejecting(UploadError::ContractRejected(422)),
        ),
        (
            "epoch conflict",
            answer(poisoned_payload()),
            rejecting(UploadError::GrantEpochConflict),
        ),
        (
            "ack invalid",
            answer(poisoned_payload()),
            Box::new(InvalidAckTransport),
        ),
    ];
    for (case, reader, transport) in exits {
        let mac = Mac::new("idle-retry");
        let discovery = mac.discovery(vec![login.clone()]);
        let start = t0();
        let reads = mac.simulate(
            &discovery,
            &StaticReader::new(poisoned_payload()),
            (start, start + 90 * HOUR),
            |_| Vec::new(),
        );
        let last = *reads[&1].last().expect("read");
        let attempt = last + 22 * HOUR + 30 * 60;
        mac.observe(start + 90 * HOUR, attempt);
        let instant = at(attempt);
        let cycle = mac.collector.run_tick(
            &runtime(),
            &discovery,
            reader.as_ref(),
            transport.as_ref(),
            &move || instant,
        );
        assert!(cycle.accounts[0].reason.is_some(), "{case}: attempted");
        let state = mac.entry(ACCOUNT_SCOPE);
        assert_eq!(state.last_fetch_epoch_seconds, attempt, "{case}");
        let due = next_due_at(&state, &state.identity, true) - attempt;
        let band = if case == "ok" {
            DAILY_DUE
        } else {
            SIX_HOUR_DUE
        };
        assert!(band.contains(&due), "{case}: next due in {due}");
    }

    // Suppressed: no success or proof, the retry is cleared with a save.
    let mac = Mac::new("idle-retry-suppressed");
    let other = slot_login(SECOND_WORKSPACE);
    let discovery = mac.discovery(vec![login.clone(), other]);
    let start = t0();
    let reader = StaticReader::new(poisoned_payload());
    mac.simulate(&discovery, &reader, (start, start + 30 * 60), |_| {
        Vec::new()
    });
    let suppressed = mac.entry(SECOND_WORKSPACE);
    assert_eq!(suppressed.last_reason.as_deref(), Some("identical_series"));
    assert_eq!(suppressed.retry_due_epoch_seconds, 0);
    assert_eq!(suppressed.last_success_epoch_seconds, 0);
    assert!(suppressed.proof.is_none());

    // Excluded dominates: never read, idle or not.
    let mac = Mac::new("idle-retry-excluded");
    let discovery = mac.discovery(vec![login.clone()]);
    mac.collector
        .grants()
        .set_account_excluded(&opaque_key(&grant_key(&mac.collector), ACCOUNT_SCOPE), true)
        .unwrap();
    let reads = mac.simulate(
        &discovery,
        &ForbiddenReader,
        (t0(), t0() + 4 * HOUR),
        |_| Vec::new(),
    );
    assert!(reads.is_empty());
}

/// A transport whose acknowledgement names another grant.
struct InvalidAckTransport;

impl DailyReferenceTransport for InvalidAckTransport {
    fn is_configured(&self) -> bool {
        true
    }

    fn send_batch(&self, batch: &Value) -> Result<Value, UploadError> {
        let mut ack = ack_for(batch);
        ack["grant_id"] = json!("00000000-0000-4000-8000-0000000000ff");
        Ok(ack)
    }
}

/// [format] Real schema-2 bytes from before this change load; the new fields
/// default. First-seen is set by the admission or, for a login the tick
/// never reached, by the end-of-tick record. A new entry (a new login, a
/// rebind to a new installation, another build, or a clear and re-enable)
/// reads once at once, then waits only for a generation started after it.
#[test]
fn a_new_collector_entry_reads_once_then_waits_for_a_later_generation() {
    let login = identified(USER, WORKSPACE, false);
    let mac = Mac::new("idle-schema-two");
    let discovery = mac.discovery(vec![login.clone()]);
    let start = t0();
    mac.observe(start, start + 80 * HOUR);
    let grant = mac.collector.grants().load().unwrap().unwrap();
    let key = grant_key(&mac.collector);
    let identity = state_identity_for_account(&grant, &opaque_key(&key, ACCOUNT_SCOPE), false);
    let last = start + 79 * HOUR;
    let bytes = format!(
        r#"{{"schema_version":2,"entries":{{"{identity}":{{"schema_version":2,"identity":"{identity}","last_fetch_epoch_seconds":{last},"last_success_epoch_seconds":{last},"auth_failures":0,"shape_failures":0,"rate_limit_failures":0,"reopen_after_epoch_seconds":0,"opened_by":"","home_kind":"default","last_seen_day":"2026-07-30","last_reason":"ok"}}}}}}"#
    );
    fs::write(mac.collector.state_path(), bytes).unwrap();
    let entry = mac.entry(ACCOUNT_SCOPE);
    assert_eq!(
        (
            entry.first_seen_epoch_seconds,
            entry.retry_due_epoch_seconds
        ),
        (0, 0)
    );
    assert_eq!(entry.last_fetch_epoch_seconds, last);
    let tick_at = start + 80 * HOUR;
    let instant = at(tick_at);
    let cycle = mac.collector.run_tick(
        &runtime(),
        &discovery,
        &ForbiddenReader,
        &ForbiddenTransport,
        &move || instant,
    );
    assert_eq!(cycle.outcome, CycleOutcome::Noop, "not due at 1 h");
    let entry = mac.entry(ACCOUNT_SCOPE);
    assert_eq!(
        entry.first_seen_epoch_seconds, tick_at,
        "set by the end-of-tick record"
    );
    let idle = |now: u64| {
        account_activity::idle(
            mac.store.load_trusted().as_ref(),
            &discovery,
            &mac.binding(),
            entry.first_seen_epoch_seconds,
            login.identity.as_ref(),
            now,
        )
    };
    assert!(!idle(tick_at), "no generation started after it yet");
    mac.fold(tick_at + HOUR, &[]);
    assert!(idle(tick_at + HOUR));

    // A tick that stops before a login still records its first-seen time.
    let mac = Mac::new("idle-first-seen-record");
    let discovery = mac.discovery(vec![login.clone(), slot_login(SECOND_WORKSPACE)]);
    let instant = now();
    mac.collector.run_tick(
        &runtime(),
        &discovery,
        &FailingReader::new(vec![ProviderReadError::RateLimited]),
        &ForbiddenTransport,
        &move || instant,
    );
    let unreached = mac.entry(SECOND_WORKSPACE);
    assert_eq!(unreached.last_fetch_epoch_seconds, 0);
    assert_eq!(unreached.first_seen_epoch_seconds, t0());

    for case in [
        "rebind to a new installation",
        "another build",
        "clear and re-enable",
    ] {
        let mac = Mac::new("idle-new-entry");
        let discovery = mac.discovery(vec![login.clone()]);
        let start = t0();
        let reader = StaticReader::new(poisoned_payload());
        let reads = mac.simulate(&discovery, &reader, (start, start + 90 * HOUR), |_| {
            Vec::new()
        });
        assert!(!reads[&1].is_empty());
        // The old entry is not due yet, so a read at 90 h proves a new entry.
        let old = mac.entry(ACCOUNT_SCOPE);
        let old_due = next_due_at(&old, &old.identity, true);
        let mut runtime = runtime();
        match case {
            "rebind to a new installation" => {
                let mut target = setup();
                target.installation_id = "00000000-0000-4000-8000-000000000091".to_owned();
                let proposal = mac
                    .collector
                    .grants()
                    .prepare_rebind(&target, "hardware-fixture".to_owned())
                    .unwrap()
                    .unwrap();
                let local = mac.collector.grants().load().unwrap().unwrap();
                let mut response = grant_response(&local, "enabled", 1);
                response.installation_id = target.installation_id.clone();
                response.grant_scope_fingerprint = proposal.request.grant_scope_fingerprint.clone();
                mac.collector
                    .grants()
                    .bind_backend_grant_with_rebind(
                        &response,
                        &target.installation_id,
                        Some(&proposal),
                    )
                    .unwrap();
                runtime.installation_id = target.installation_id;
            }
            "another build" => {
                let mut file: Value =
                    serde_json::from_slice(&fs::read(mac.collector.state_path()).unwrap()).unwrap();
                let entries = file["entries"].as_object_mut().unwrap();
                let current = entries.keys().next().cloned().unwrap();
                let entry = entries.remove(&current).unwrap();
                entries.insert("an-older-build-key".to_string(), entry);
                fs::write(
                    mac.collector.state_path(),
                    serde_json::to_vec(&file).unwrap(),
                )
                .unwrap();
            }
            _ => {
                fs::write(&mac.collector.sentinel, b"").unwrap();
                mac.collector.run_tick(
                    &runtime,
                    &discovery,
                    &ForbiddenReader,
                    &ForbiddenTransport,
                    &super::now,
                );
                assert!(!mac.collector.state_path().exists());
                fs::remove_file(&mac.collector.sentinel).unwrap();
            }
        }
        assert!(
            old_due > start + 90 * HOUR,
            "{case}: the old entry is not due"
        );
        // The map is untouched: the 72 h clock and observations carry on.
        assert!(mac.idle(&discovery, &login, start + 90 * HOUR), "{case}");
        let transport = RecordingTransport::default();
        let mut reads = Vec::new();
        let mut now = start + 90 * HOUR;
        while now < start + 120 * HOUR {
            mac.fold(now, &[]);
            let instant = at(now);
            let cycle =
                mac.collector
                    .run_tick(&runtime, &discovery, &reader, &transport, &move || instant);
            if cycle.accounts[0].reason == Some("ok") {
                reads.push(now);
            }
            now += 30 * 60;
        }
        assert_eq!(reads[0], start + 90 * HOUR, "{case}: read at once");
        assert!(
            DAILY_BAND.contains(&(reads[1] - reads[0])),
            "{case}: no new 72 h wait"
        );
    }
}

/// [money] The identical-series skip is kept (pinned): A uploads X, B had
/// uploaded Y, then B returns X and is skipped with no success, proof or
/// retry, and nothing is sent for B. On a later window with A's newer read
/// failed, B uploads.
#[test]
fn an_identical_series_skip_keeps_the_older_series_until_its_owner_fails() {
    let mac = Mac::new("idle-identical-series");
    let second = slot_login(SECOND_WORKSPACE);
    let discovery = mac.discovery(vec![login(), second]);
    let key = grant_key(&mac.collector);
    let transport = RecordingTransport::default();
    let tick = |reader: &dyn ProviderDailyUsageReader, instant: OffsetDateTime| {
        mac.collector
            .run_tick(&runtime(), &discovery, reader, &transport, &move || instant)
    };
    let uploaders = |transport: &RecordingTransport| {
        transport
            .batches
            .borrow()
            .iter()
            .map(|batch| batch["account_fingerprint"].as_str().unwrap().to_string())
            .collect::<BTreeSet<_>>()
    };
    tick(&ScopedReader::distinct(), now());
    assert_eq!(uploaders(&transport).len(), 2, "A uploads X, B uploads Y");
    let uploaded_y = mac.entry(SECOND_WORKSPACE);

    transport.batches.borrow_mut().clear();
    let same = ScopedReader {
        payloads: BTreeMap::new(),
        fallback: poisoned_payload(),
        calls: RefCell::new(Vec::new()),
    };
    tick(&same, now() + TimeDuration::hours(7));
    assert_eq!(
        uploaders(&transport),
        BTreeSet::from([opaque_key(&key, ACCOUNT_SCOPE)])
    );
    let skipped = mac.entry(SECOND_WORKSPACE);
    assert_eq!(skipped.last_reason.as_deref(), Some("identical_series"));
    assert_eq!(
        skipped.last_success_epoch_seconds,
        uploaded_y.last_success_epoch_seconds
    );
    assert_eq!(skipped.last_coverage_end, uploaded_y.last_coverage_end);
    assert!(skipped.proof.is_none());
    assert_eq!(skipped.retry_due_epoch_seconds, 0);

    // A later UTC window; A's newer read fails, so B uploads X.
    transport.batches.borrow_mut().clear();
    let owner_fails = ScopedOutcomeReader {
        failing: ACCOUNT_SCOPE,
        payload: poisoned_payload(),
    };
    tick(&owner_fails, now() + TimeDuration::hours(26));
    assert_eq!(
        uploaders(&transport),
        BTreeSet::from([opaque_key(&key, SECOND_WORKSPACE)])
    );
}

/// Fails for one account and answers `payload` for every other.
struct ScopedOutcomeReader {
    failing: &'static str,
    payload: Value,
}

impl ProviderDailyUsageReader for ScopedOutcomeReader {
    fn fetch_window(
        &self,
        credential: &CodexCredential,
        _start: &str,
        _end: &str,
    ) -> Result<Value, ProviderReadError> {
        if credential.account_scope == self.failing {
            return Err(ProviderReadError::Transient("fixture".into()));
        }
        Ok(self.payload.clone())
    }
}

/// [behaviour] A map this process could not replace is distrusted, so every
/// login is active; the next write is a full reset that alone restores
/// trust. Folds missed under an older build leave the disclosed residual: a
/// gap barrier, then idle again on the next clean generation.
#[test]
fn a_failed_map_write_distrusts_it_until_a_full_reset() {
    let login = identified(USER, WORKSPACE, false);
    let mac = Mac::new("idle-write-failure");
    let discovery = mac.discovery(vec![login.clone()]);
    let start = t0();
    mac.observe(start, start + 80 * HOUR);
    assert!(mac.idle(&discovery, &login, start + 80 * HOUR));

    fs::remove_file(mac.store_path()).unwrap();
    fs::create_dir(mac.store_path()).unwrap();
    mac.fold(start + 81 * HOUR, &[]);
    fs::remove_dir(mac.store_path()).unwrap();
    assert!(mac.store.load_trusted().is_none(), "distrusted");
    mac.fold(start + 82 * HOUR, &[]);
    assert!(
        mac.store.load_trusted().is_some(),
        "trusted after the reset write"
    );
    assert!(
        !mac.idle(&discovery, &login, start + 82 * HOUR),
        "72 h again"
    );
    mac.observe(start + 83 * HOUR, start + 154 * HOUR);
    assert!(mac.idle(&discovery, &login, start + 154 * HOUR));

    // An older build ran for 10 h and consumed a session unseen.
    mac.fold(start + 164 * HOUR, &[]);
    assert!(!mac.idle(&discovery, &login, start + 164 * HOUR));
    mac.fold(start + 165 * HOUR, &[]);
    assert!(
        mac.idle(&discovery, &login, start + 165 * HOUR),
        "disclosed residual"
    );
}

/// [behaviour] Formatted map, discovery and state name no pair, path, grant
/// or key.
#[test]
fn formatted_activity_state_names_no_identifier() {
    let mac = Mac::new("idle-debug");
    let login = identified(USER, WORKSPACE, false);
    let discovery = mac.discovery(vec![login.clone()]);
    let start = t0();
    mac.fold(start, &[session(USER, WORKSPACE, Some(start))]);
    let tick_at = at(start);
    mac.collector.run_tick(
        &runtime(),
        &discovery,
        &StaticReader::new(poisoned_payload()),
        &RecordingTransport::default(),
        &move || tick_at,
    );
    let identity = expected_identity(USER, WORKSPACE);
    let formatted = format!(
        "{:?} {:?} {:?} {:?}",
        mac.store.load_trusted().expect("map"),
        discovery,
        mac.collector.state.load_file(),
        mac.store,
    );
    for secret in [
        identity.account_identifier_hash.as_str(),
        identity.provider_workspace_hash.as_str(),
        "/fixture/codex-home",
        GRANT_ID,
        mac.entry(ACCOUNT_SCOPE).identity.as_str(),
    ] {
        assert!(!formatted.contains(secret), "{formatted}");
    }
}
