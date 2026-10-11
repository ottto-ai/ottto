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

fn covered(ledger: &Ledger, from: u64, to: u64) -> Option<(String, String)> {
    ledger
        .covering(&home(), T0 + from, T0 + to)
        .map(|(login, org)| (login.to_string(), org.to_string()))
}

#[test]
fn coverage_is_one_segment_of_consecutive_observations_at_most_two_cadences_apart() {
    let ledger = observed(&[0, 300, 600, 1_200]);
    let expected = Some((login(0), org(0)));
    assert_eq!(covered(&ledger, 0, 1_200), expected);
    assert_eq!(covered(&ledger, 100, 1_100), expected);
    // Nothing before the first or after the last observation is covered: an
    // unobserved interval is never filled in or extended.
    assert_eq!(covered(&ledger, 0, 1_201), None);
    assert_eq!(covered(&ledger, 0, 0), expected);
    assert!(Ledger::default().covering(&home(), T0, T0).is_none());
    assert!(ledger.covering(&home(), T0 + 10, T0 + 5).is_none());
    assert!(ledger.covering(&[0; 32], T0, T0).is_none());

    // A gap of more than two cadences splits coverage; exactly two does not.
    let split = observed(&[0, 300, 901, 1_200]);
    assert_eq!(covered(&split, 0, 300), expected);
    assert_eq!(covered(&split, 901, 1_200), expected);
    assert_eq!(covered(&split, 0, 1_200), None);
    assert_eq!(covered(&split, 299, 902), None);
    // Two equal endpoints across a gap never prove presence in between.
    let endpoints = observed(&[0, 3_600]);
    assert_eq!(covered(&endpoints, 0, 3_600), None);
}

#[test]
fn unavailable_conflict_logout_regression_and_replacement_end_coverage() {
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
    let expected = Some((login(0), org(0)));

    // Unavailable (failed, missing, contradictory or suppressed) splits even
    // inside one cadence.
    let mut ledger = observed(&[0, 300]);
    ledger.observe_at(home(), SLOT, Some(T0 + 400), Observation::Unavailable);
    qualified(&mut ledger, 600, 0);
    assert_eq!(covered(&ledger, 0, 300), expected);
    assert_eq!(covered(&ledger, 0, 600), None);

    // Conflicting identity: a different login ends the segment, and the
    // later segment belongs to that login only.
    let mut ledger = observed(&[0, 300]);
    qualified(&mut ledger, 600, 1);
    qualified(&mut ledger, 900, 0);
    assert_eq!(covered(&ledger, 0, 300), expected);
    assert_eq!(covered(&ledger, 600, 600), Some((login(1), org(0))));
    assert_eq!(covered(&ledger, 0, 900), None);
    assert_eq!(covered(&ledger, 300, 900), None);

    // A malformed hash is not a qualified value.
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
    assert_eq!(covered(&ledger, 0, 600), None);

    // An observation without a usable time ends the segment.
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
    assert_eq!(covered(&ledger, 0, 600), None);

    // Logout clears the slot's whole history.
    let mut ledger = observed(&[0, 300, 600]);
    ledger.observe_at(home(), SLOT, Some(T0 + 700), Observation::SignedOut);
    assert_eq!(covered(&ledger, 0, 0), None);
    assert!(ledger.pairings().next().is_none());

    // Clock regression clears it too.
    let mut ledger = observed(&[0, 300, 600]);
    qualified(&mut ledger, 500, 0);
    assert_eq!(covered(&ledger, 0, 300), None);
    assert_eq!(covered(&ledger, 500, 500), expected);
    // An equal timestamp is a repeat, not a regression.
    let mut ledger = observed(&[0, 300, 300]);
    assert_eq!(covered(&ledger, 0, 300), expected);
    qualified(&mut ledger, 600, 0);
    assert_eq!(covered(&ledger, 0, 600), expected);

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
    assert_eq!(covered(&ledger, 0, 600), None);
    assert_eq!(covered(&ledger, 600, 600), expected);

    // An unknown slot gains nothing from a non-qualified observation, and a
    // restart (a new process) has no history at all.
    let mut ledger = Ledger::default();
    ledger.observe_at(home(), SLOT, Some(T0), Observation::Unavailable);
    ledger.observe_at(home(), SLOT, Some(T0), Observation::SignedOut);
    assert_eq!(ledger, Ledger::default());
}

#[test]
fn age_entry_slot_and_byte_caps_bound_the_history() {
    // Age: nothing older than 30 days survives; a long segment is clamped.
    let mut ledger = observed(&[0, 300]);
    let late = MAX_AGE_SECONDS + 10_000;
    ledger.observe_at(
        home(),
        SLOT,
        Some(T0 + late),
        Observation::Qualified {
            login: &login(1),
            org: &org(0),
        },
    );
    assert_eq!(covered(&ledger, 0, 300), None);
    assert_eq!(ledger.pairings().count(), 1);
    let mut long = Ledger::default();
    let mut at = 0;
    while at <= late {
        long.observe_at(
            home(),
            SLOT,
            Some(T0 + at),
            Observation::Qualified {
                login: &login(0),
                org: &org(0),
            },
        );
        at += 600;
    }
    let last = at - 600;
    let cutoff = last - MAX_AGE_SECONDS;
    assert_eq!(covered(&long, cutoff, last), Some((login(0), org(0))));
    assert_eq!(covered(&long, cutoff - 1, last), None);

    // Entries: the oldest segment is evicted, and its interval with it.
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
    assert_eq!(covered(&ledger, 0, 0), None);
    let newest = (MAX_SEGMENTS_PER_SLOT as u64 + 2) * 300;
    assert!(covered(&ledger, newest, newest).is_some());

    // Slots: at most one history per registered slot.
    let mut ledger = Ledger::default();
    for n in 0..=MAX_SLOTS {
        ledger.observe_at(
            home_key(Path::new(&format!("/slots/{n}"))),
            SLOT,
            Some(T0),
            Observation::Qualified {
                login: &login(0),
                org: &org(0),
            },
        );
    }
    assert_eq!(ledger.slots.len(), MAX_SLOTS);

    // Bytes: the worst case under the entry caps stays within the byte cap.
    let (full, stats) = crate::retry_allocation_probe::measure(|| {
        let mut ledger = Ledger::default();
        for slot in 0..MAX_SLOTS {
            let key = home_key(Path::new(&format!("/slots/{slot}")));
            for n in 0..(MAX_SEGMENTS_PER_SLOT as u64 * 2) {
                ledger.observe_at(
                    key,
                    SLOT,
                    Some(T0 + n * 300),
                    Observation::Qualified {
                        login: &login((n % 2) as u8),
                        org: &org(0),
                    },
                );
            }
        }
        ledger
    });
    let bytes = full.retained_bytes();
    let worst = MAX_SLOTS
        * (std::mem::size_of::<HomeKey>()
            + std::mem::size_of::<SlotHistory>()
            + MAX_SEGMENTS_PER_SLOT * (std::mem::size_of::<Segment>() + 128));
    eprintln!(
        "status coverage worst case: retained_bytes={bytes} declared_worst={worst} \
         allocations={} requested_peak={} segment_inline={} history_inline={}",
        stats.allocations,
        stats.requested_peak,
        std::mem::size_of::<Segment>(),
        std::mem::size_of::<SlotHistory>(),
    );
    assert_eq!(full.pairings().count(), MAX_SLOTS * MAX_SEGMENTS_PER_SLOT);
    assert!(bytes <= worst && worst <= MAX_BYTES, "{bytes} {worst}");

    // One steady-state observation (extending an open segment) allocates
    // nothing; a new segment allocates its two hashes (plus vector growth).
    let mut steady = observed(&[0, 300]);
    let (key, login0, org0, login1) = (home(), login(0), org(0), login(1));
    let ((), extend) = crate::retry_allocation_probe::measure(|| {
        steady.observe_at(
            key,
            SLOT,
            Some(T0 + 600),
            Observation::Qualified {
                login: &login0,
                org: &org0,
            },
        )
    });
    assert_eq!(extend.allocations, 0);
    let ((), split) = crate::retry_allocation_probe::measure(|| {
        steady.observe_at(
            key,
            SLOT,
            Some(T0 + 900),
            Observation::Qualified {
                login: &login1,
                org: &org0,
            },
        )
    });
    assert_eq!(split.allocations, 2);

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
fn global_feed_skips_the_default_folder_drops_removed_slots_and_fails_closed() {
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
    assert!(ledger.covering(&home(), 0, u64::MAX).is_none());
    let start = OffsetDateTime::parse("2027-01-15T08:00:00Z", &Rfc3339)
        .unwrap()
        .unix_timestamp() as u64;
    assert!(ledger.covering(&home(), start, start + 300).is_some());

    // Slot removal drops the folder's history.
    retain_registered(["/Users/someone/other"].into_iter());
    assert_eq!(snapshot_slots(), 0);

    // A poisoned lock: the producer is a no-op and the consumer sees no feed.
    observe_at("/Users/someone/.claude-slot", "2027-01-15T08:10:00Z");
    poison_global_for_test();
    observe_at("/Users/someone/.claude-slot", "2027-01-15T08:15:00Z");
    retain_registered(std::iter::empty());
    assert!(snapshot().is_none());
    clear_global_for_test();
}

fn snapshot_slots() -> usize {
    snapshot().map_or(0, |ledger| ledger.slots.len())
}
