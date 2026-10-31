use super::*;
use serial_test::serial;

const T0: u64 = 1_800_000_000;
const SLOT: [u8; 32] = [7; 32];

fn login(n: u8) -> String {
    char::from(b'a' + n).to_string().repeat(64)
}

fn org(n: u8) -> String {
    char::from(b'0' + n).to_string().repeat(64)
}

fn home() -> HomeKey {
    home_key(Path::new("/Users/someone/.claude-slot"))
}

/// Qualified observations of (login 0, org 0) at each offset from `T0`.
fn observed(offsets: &[u64]) -> Ledger {
    let mut ledger = Ledger::default();
    for offset in offsets {
        ledger.observe_at(
            home(),
            SLOT,
            Some(T0 + offset),
            Observation::Qualified {
                login: &login(0),
                org: &org(0),
            },
        );
    }
    ledger
}

fn verdict(ledger: &Ledger, from: u64, to: u64) -> Verdict {
    ledger.verdict(&home(), T0 + from, T0 + to, &org(0))
}

#[test]
fn equal_samples_are_freshness_never_continuity_or_a_login() {
    // Samples A/O at 0, 300 and 600: a request at 450 may have run under B/O
    // during an unseen A→B→A switch. The history therefore never qualifies
    // the window, and its API has no way to return a login.
    let samples = observed(&[0, 300, 600]);
    assert_eq!(verdict(&samples, 0, 450), Verdict::Unqualified);
    assert_eq!(verdict(&samples, 0, 600), Verdict::Unqualified);
    assert_eq!(verdict(&samples, 300, 300), Verdict::Unqualified);
    // A sampled A→B→A inside the window is a conflict, not coverage.
    let mut switched = observed(&[0]);
    for (at, n) in [(300, 1), (600, 0)] {
        switched.observe_at(
            home(),
            SLOT,
            Some(T0 + at),
            Observation::Qualified {
                login: &login(n),
                org: &org(0),
            },
        );
    }
    assert_eq!(verdict(&switched, 0, 600), Verdict::Conflicting);
    assert_eq!(
        verdict(&switched, 0, 100),
        Verdict::Conflicting,
        "B within one gap"
    );
    // Outside the window or past the last sample: nothing spans it.
    assert_eq!(verdict(&samples, 0, 601), Verdict::Unavailable);
    assert_eq!(verdict(&samples, 10, 5), Verdict::Unavailable);
    assert_eq!(
        Ledger::default().verdict(&home(), T0, T0, &org(0)),
        Verdict::Unavailable
    );
    assert_eq!(
        samples.verdict(&[0; 32], T0, T0, &org(0)),
        Verdict::Unavailable
    );
    // A sample near the window naming another organization conflicts.
    assert_eq!(
        samples.verdict(&home(), T0, T0 + 450, &org(1)),
        Verdict::Conflicting
    );
    // A gap of more than two cadences: no run spans the window.
    let gapped = observed(&[0, 300, 901, 1_200]);
    assert_eq!(verdict(&gapped, 0, 1_200), Verdict::Unavailable);
    assert_eq!(verdict(&gapped, 299, 902), Verdict::Unavailable);
    let endpoints = observed(&[0, 3_600]);
    assert_eq!(verdict(&endpoints, 0, 3_600), Verdict::Unavailable);
}

#[test]
fn unavailable_conflict_logout_regression_replacement_and_restart_never_qualify() {
    let qualified = |ledger: &mut Ledger, at: u64, n: u8| {
        ledger.observe_at(
            home(),
            SLOT,
            Some(T0 + at),
            Observation::Qualified {
                login: &login(n),
                org: &org(0),
            },
        )
    };
    // An unavailable observation splits runs even inside one cadence.
    let mut ledger = observed(&[0, 300]);
    ledger.observe_at(home(), SLOT, Some(T0 + 400), Observation::Unavailable);
    qualified(&mut ledger, 600, 0);
    assert_eq!(verdict(&ledger, 0, 600), Verdict::Unavailable);
    // A different login ends the run and conflicts near it.
    let mut ledger = observed(&[0, 300]);
    qualified(&mut ledger, 600, 1);
    assert_eq!(verdict(&ledger, 0, 300), Verdict::Conflicting);
    // A malformed hash is not a qualified sample.
    let mut ledger = observed(&[0]);
    ledger.observe_at(
        home(),
        SLOT,
        Some(T0 + 300),
        Observation::Qualified {
            login: "not-a-hash",
            org: &org(0),
        },
    );
    qualified(&mut ledger, 600, 0);
    assert_eq!(verdict(&ledger, 0, 600), Verdict::Unavailable);
    // No usable time ends the run.
    let mut ledger = observed(&[0, 300]);
    ledger.observe_at(
        home(),
        SLOT,
        None,
        Observation::Qualified {
            login: &login(0),
            org: &org(0),
        },
    );
    qualified(&mut ledger, 600, 0);
    assert_eq!(verdict(&ledger, 0, 600), Verdict::Unavailable);
    // Logout clears the history.
    let mut ledger = observed(&[0, 300, 600]);
    ledger.observe_at(home(), SLOT, Some(T0 + 700), Observation::SignedOut);
    assert_eq!(verdict(&ledger, 0, 0), Verdict::Unavailable);
    assert!(ledger.pairings().next().is_none());
    // Clock regression clears it too; an equal timestamp is only a repeat.
    let mut ledger = observed(&[0, 300, 600]);
    qualified(&mut ledger, 500, 0);
    assert_eq!(verdict(&ledger, 0, 300), Verdict::Unavailable);
    let repeat = observed(&[0, 300, 300]);
    assert_eq!(verdict(&repeat, 0, 300), Verdict::Unqualified);
    // A replacement registration of the same folder starts over.
    let mut ledger = observed(&[0, 300]);
    ledger.observe_at(
        home(),
        [8; 32],
        Some(T0 + 600),
        Observation::Qualified {
            login: &login(0),
            org: &org(0),
        },
    );
    assert_eq!(verdict(&ledger, 0, 600), Verdict::Unavailable);
    // An unknown slot gains nothing from a non-qualified observation, and a
    // restart (a new process) knows neither history nor registration.
    let mut ledger = Ledger::default();
    ledger.observe_at(home(), SLOT, Some(T0), Observation::Unavailable);
    ledger.observe_at(home(), SLOT, Some(T0), Observation::SignedOut);
    assert_eq!(ledger, Ledger::default());
    assert_eq!(ledger.is_registered(&home()), None);
    assert_eq!(ledger.registration(&home(), T0), Registration::Unknown);
    // Registration is what the last pass reported; removal drops history but
    // the loss stays known, so the folder never reads as never registered.
    let other = home_key(Path::new("/synthetic/other"));
    let mut ledger = observed(&[0, 300]);
    ledger.retain(BTreeSet::from([home()]), Some(T0));
    assert_eq!(ledger.is_registered(&home()), Some(true));
    assert_eq!(ledger.registration(&home(), T0), Registration::Registered);
    assert_eq!(
        ledger.registration(&other, T0),
        Registration::NeverRegistered
    );
    assert_eq!(ledger.registration(&other, T0 - 1), Registration::Unknown);
    ledger.retain(BTreeSet::new(), Some(T0 + 600));
    assert_eq!(ledger.is_registered(&home()), Some(false));
    assert_eq!(ledger.registration(&home(), T0), Registration::Unknown);
    assert_eq!(
        ledger.registration(&other, T0),
        Registration::NeverRegistered
    );
    assert_eq!(verdict(&ledger, 0, 300), Verdict::Unavailable);
    // Re-registration clears the loss (the history stays empty); losing more
    // folders than the record holds makes every unregistered folder unknown.
    ledger.retain(BTreeSet::from([home()]), Some(T0 + 900));
    assert_eq!(ledger.lost.len(), 0);
    for n in 0..MAX_LOST {
        ledger.retain(
            BTreeSet::from([home_key(Path::new(&format!("/lost/{n}")))]),
            Some(T0 + 900),
        );
    }
    assert_eq!((ledger.lost.len(), ledger.lost_overflow), (MAX_LOST, false));
    ledger.retain(BTreeSet::new(), Some(T0 + 900));
    assert_eq!((ledger.lost.len(), ledger.lost_overflow), (0, true));
    assert_eq!(ledger.registration(&other, T0), Registration::Unknown);
    assert_eq!(ledger.registration(&home(), T0), Registration::Unknown);
}

#[test]
fn age_entry_slot_and_byte_caps_bound_the_history() {
    // Entries: the oldest run is evicted, and its interval with it.
    let mut ledger = Ledger::default();
    for n in 0..(MAX_SEGMENTS_PER_SLOT as u64 + 3) {
        ledger.observe_at(
            home(),
            SLOT,
            Some(T0 + n * 300),
            Observation::Qualified {
                login: &login((n % 2) as u8),
                org: &org(0),
            },
        );
    }
    assert_eq!(ledger.pairings().count(), MAX_SEGMENTS_PER_SLOT);
    assert_eq!(
        ledger.verdict(&home(), T0, T0, &org(0)),
        Verdict::Unavailable,
        "evicted"
    );

    // The byte cap is a hard backstop even if entry shapes change.
    let mut padded = observed(&[0]);
    padded
        .slots
        .get_mut(&home())
        .unwrap()
        .segments
        .reserve_exact(MAX_BYTES);
    padded.observe_at(
        home(),
        SLOT,
        Some(T0 + 300),
        Observation::Qualified {
            login: &login(0),
            org: &org(0),
        },
    );
    // Over the byte cap, eviction removes coverage rather than keeping it.
    assert_eq!(padded.pairings().count(), 0);
}

#[test]
fn registered_folders_past_the_cap_are_never_proven_unregistered() {
    let keys = (0..=MAX_SLOTS)
        .map(|n| home_key(Path::new(&format!("/slot/{n}"))))
        .collect::<BTreeSet<_>>();
    let absent = home_key(Path::new("/never-registered"));
    let mut ledger = Ledger::default();
    ledger.retain(keys.iter().copied().take(MAX_SLOTS).collect(), Some(T0));
    assert_eq!(
        ledger.registration(&absent, T0),
        Registration::NeverRegistered,
        "control: within the cap absence is proven"
    );
    let mut ledger = Ledger::default();
    ledger.retain(keys.clone(), Some(T0));
    assert!(ledger.retained_bytes() <= MAX_BYTES);
    assert_eq!(
        ledger.registered.as_ref().map(BTreeSet::len),
        Some(MAX_SLOTS)
    );
    for key in &keys {
        assert_ne!(ledger.registration(key, T0), Registration::NeverRegistered);
    }
    assert_eq!(ledger.registration(&absent, T0), Registration::Unknown);
    // A later pass back inside the cap cannot restore proof of absence.
    ledger.retain(keys.into_iter().take(1).collect(), Some(T0 + 300));
    assert_eq!(
        ledger.registration(&absent, T0 + 300),
        Registration::Unknown
    );
}

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

#[test]
#[serial]
fn global_feed_skips_the_default_folder_tracks_registration_and_fails_closed() {
    clear_global_for_test();
    let default_dir = Path::new("/Users/someone/.claude");
    let observe_at = |dir: &str, at: &str| {
        observe(
            "slot-id",
            Some(dir),
            default_dir,
            at,
            Observation::Qualified {
                login: &login(0),
                org: &org(0),
            },
        )
    };
    observe_at("/Users/someone/.claude/", "2027-01-15T08:00:00Z");
    observe_at("/Users/someone/.claude-slot", "2027-01-15T08:00:00Z");
    observe_at("/Users/someone/.claude-slot", "2027-01-15T08:05:00Z");
    observe(
        "slot-id",
        None,
        default_dir,
        "2027-01-15T08:05:00Z",
        Observation::Unavailable,
    );
    let ledger = snapshot().expect("feed available");
    assert_eq!(ledger.slots.len(), 1);
    assert_eq!(ledger.is_registered(&home()), None, "no pass completed yet");
    let start = OffsetDateTime::parse("2027-01-15T08:00:00Z", &Rfc3339)
        .unwrap()
        .unix_timestamp() as u64;
    assert_eq!(
        ledger.verdict(&home(), start, start + 300, &org(0)),
        Verdict::Unqualified
    );

    // The pass records registered folders, never the default one.
    retain_registered(
        ["/Users/someone/.claude-slot", "/Users/someone/.claude"].into_iter(),
        default_dir,
    );
    let ledger = snapshot().expect("feed available");
    assert_eq!(ledger.is_registered(&home()), Some(true));
    assert_eq!(ledger.is_registered(&home_key(default_dir)), Some(false));
    // Slot removal drops the folder's history, never the knowledge of the loss.
    retain_registered(["/Users/someone/other"].into_iter(), default_dir);
    assert_eq!(snapshot_slots(), 0);
    let ledger = snapshot().expect("feed available");
    assert_eq!(
        ledger.registration(&home(), u64::MAX),
        Registration::Unknown
    );

    // A poisoned lock: the producer is a no-op and the consumer sees no feed.
    observe_at("/Users/someone/.claude-slot", "2027-01-15T08:10:00Z");
    poison_global_for_test();
    observe_at("/Users/someone/.claude-slot", "2027-01-15T08:15:00Z");
    retain_registered(std::iter::empty(), default_dir);
    assert!(snapshot().is_none());
    clear_global_for_test();
}

fn snapshot_slots() -> usize {
    snapshot().map_or(0, |ledger| ledger.slots.len())
}
