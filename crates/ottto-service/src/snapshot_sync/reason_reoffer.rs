//! Reason-scoped daily re-offer of exact permanent refusals.
//!
//! The backend refuses `original_pair_candidate_unproved` permanently until it
//! can prove the original request pair, so the refused body is offered again at
//! most once per 24 hours. Legacy `other` refusals, which an older daemon wrote
//! for that same reason, get one bounded re-classification offer. The refusal,
//! its body binding and its terminal quarantine stay durable throughout; this
//! extension is local scheduling permission only, never acceptance evidence.
//!
//! Disk form: the containing record keeps the old enum value `other`, so an
//! older daemon still reads, suppresses and never retries the refusal. The
//! optional `reoffer` member carries the exact classification. Its decoder is
//! bounded and isolating: a malformed member disables only this record's
//! retry, never the ledger, its siblings or the refusal itself.

use serde::de::{self, DeserializeSeed, Deserializer, IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde::ser::{SerializeMap, Serializer};
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};

pub(super) const ORIGINAL_PAIR_CANDIDATE_UNPROVED: &str = "original_pair_candidate_unproved";
/// One logical offer per record per day.
pub(super) const REOFFER_INTERVAL_SECONDS: u64 = 86_400;
/// SI clock tolerance: a deadline past now + 24 h + 600 s is skipped and
/// re-clamped to now + 24 h, keeping suppression until the next due cycle.
pub(super) const REOFFER_CLOCK_TOLERANCE_SECONDS: u64 = 600;

const EXTENSION_VERSION: u64 = 1;
const LEGACY_OTHER: &str = "legacy_other_reclassification";
const CLASSIFIED: &str = "classified";
const MAX_MEMBERS: usize = 8;
const MAX_DEPTH: usize = 4;
const MAX_TOKEN_BYTES: usize = 64;
const MAX_NODES: usize = 32;

/// Persisted per-record scheduling state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RefusalReoffer {
    /// Exact `original_pair_candidate_unproved`: next logical offer not before.
    OriginalPair { retry_after_unix_seconds: u64 },
    /// Legacy `other` record whose one-time re-classification offer is
    /// reserved until this time (a crash or unmaterialized lease waits a day).
    LegacyOther { retry_after_unix_seconds: u64 },
    /// Per-record done marker: the server classified this body, or the
    /// extension was unusable. Never re-offered automatically.
    Classified,
}

impl RefusalReoffer {
    pub(super) fn retry_after(self) -> Option<u64> {
        match self {
            Self::OriginalPair {
                retry_after_unix_seconds,
            }
            | Self::LegacyOther {
                retry_after_unix_seconds,
            } => Some(retry_after_unix_seconds),
            Self::Classified => None,
        }
    }

    pub(super) fn with_retry_after(self, retry_after_unix_seconds: u64) -> Self {
        match self {
            Self::OriginalPair { .. } => Self::OriginalPair {
                retry_after_unix_seconds,
            },
            Self::LegacyOther { .. } => Self::LegacyOther {
                retry_after_unix_seconds,
            },
            Self::Classified => Self::Classified,
        }
    }
}

impl crate::heap_layout_bound::HeapLayoutBound for RefusalReoffer {
    fn heap_bound(&self, counter: &mut crate::heap_layout_bound::Counter) -> Option<()> {
        match self {
            Self::OriginalPair { .. } | Self::LegacyOther { .. } | Self::Classified => {
                counter.add(0)
            }
        }
    }
}

/// Process-local count of extensions disabled by the decoder or the clock
/// bound. Count only; never the raw bytes.
static INVALID_EXTENSIONS: AtomicU64 = AtomicU64::new(0);

pub(super) fn note_invalid_extension() {
    INVALID_EXTENSIONS.fetch_add(1, Ordering::Relaxed);
}

static LOGGED_INVALID_EXTENSIONS: AtomicU64 = AtomicU64::new(0);

/// Extensions disabled since the previous summary line.
pub(super) fn take_logged_invalid_extensions() -> usize {
    let total = INVALID_EXTENSIONS.load(Ordering::Relaxed);
    let logged = LOGGED_INVALID_EXTENSIONS.swap(total, Ordering::Relaxed);
    usize::try_from(total.saturating_sub(logged)).unwrap_or(usize::MAX)
}

/// The loaded, committed index and clock that bound one cycle's selection.
pub(super) struct Scope<'a> {
    pub(super) index: &'a crate::snapshots::ScanIndex,
    pub(super) now: u64,
    /// Start of the negotiated upload window. Older records stay disclosed
    /// and counted, not re-offered.
    pub(super) window_start_unix_seconds: u64,
}

/// Local scheduling clock. Tests inject a synthetic wall clock; production
/// reads the system clock. Never authority for acceptance.
pub(super) fn now_unix_seconds() -> u64 {
    #[cfg(test)]
    if let Some(now) =
        super::tests::permanent_finish_pipeline_tests::reason_reoffer_pipeline_tests::clock()
    {
        return now;
    }
    super::current_unix_seconds()
}

pub(super) fn next_offer_after(observed_at: u64) -> u64 {
    observed_at.saturating_add(REOFFER_INTERVAL_SECONDS)
}

/// The latest deadline a valid record may carry at `now`.
pub(super) fn latest_valid_deadline(now: u64) -> u64 {
    now.saturating_add(REOFFER_INTERVAL_SECONDS)
        .saturating_add(REOFFER_CLOCK_TOLERANCE_SECONDS)
}

pub(super) fn serialize<S: Serializer>(
    value: &Option<RefusalReoffer>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    let Some(value) = value else {
        return serializer.serialize_none();
    };
    let (reason, retry_after) = match value {
        RefusalReoffer::OriginalPair {
            retry_after_unix_seconds,
        } => (
            ORIGINAL_PAIR_CANDIDATE_UNPROVED,
            Some(*retry_after_unix_seconds),
        ),
        RefusalReoffer::LegacyOther {
            retry_after_unix_seconds,
        } => (LEGACY_OTHER, Some(*retry_after_unix_seconds)),
        RefusalReoffer::Classified => (CLASSIFIED, None),
    };
    let mut map = serializer.serialize_map(Some(2 + usize::from(retry_after.is_some())))?;
    map.serialize_entry("version", &EXTENSION_VERSION)?;
    map.serialize_entry("reason", reason)?;
    if let Some(retry_after) = retry_after {
        map.serialize_entry("retry_after_unix_seconds", &retry_after)?;
    }
    map.end()
}

/// Missing/null is `None`. Anything else that is not exactly a version-1
/// extension decodes to `Classified`: retry disabled, refusal kept.
pub(super) fn deserialize<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<RefusalReoffer>, D::Error> {
    deserializer.deserialize_any(ExtensionVisitor)
}

#[derive(Default)]
struct Budget {
    nodes: usize,
    invalid: bool,
}

impl Budget {
    fn visit(&mut self, depth: usize) {
        self.nodes += 1;
        if self.nodes > MAX_NODES || depth > MAX_DEPTH {
            self.invalid = true;
        }
    }
}

fn disabled() -> Option<RefusalReoffer> {
    note_invalid_extension();
    Some(RefusalReoffer::Classified)
}

struct ExtensionVisitor;

impl<'de> Visitor<'de> for ExtensionVisitor {
    type Value = Option<RefusalReoffer>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("an optional refusal re-offer extension")
    }

    fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
        Ok(None)
    }

    fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
        Ok(None)
    }

    fn visit_some<D: Deserializer<'de>>(self, deserializer: D) -> Result<Self::Value, D::Error> {
        deserializer.deserialize_any(self)
    }

    fn visit_bool<E: de::Error>(self, _: bool) -> Result<Self::Value, E> {
        Ok(disabled())
    }

    fn visit_i64<E: de::Error>(self, _: i64) -> Result<Self::Value, E> {
        Ok(disabled())
    }

    fn visit_u64<E: de::Error>(self, _: u64) -> Result<Self::Value, E> {
        Ok(disabled())
    }

    fn visit_f64<E: de::Error>(self, _: f64) -> Result<Self::Value, E> {
        Ok(disabled())
    }

    fn visit_str<E: de::Error>(self, _: &str) -> Result<Self::Value, E> {
        Ok(disabled())
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        let mut budget = Budget::default();
        while seq
            .next_element_seed(Skip {
                depth: 1,
                budget: &mut budget,
            })?
            .is_some()
        {}
        Ok(disabled())
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut budget = Budget::default();
        let mut members = 0usize;
        let (mut version, mut reason, mut retry_after) = (None, None, None);
        while let Some(key) = map.next_key_seed(KeySeed)? {
            members += 1;
            budget.visit(1);
            if members > MAX_MEMBERS {
                budget.invalid = true;
            }
            let slot = match key {
                Key::Version => &mut version,
                Key::Reason => &mut reason,
                Key::RetryAfter => &mut retry_after,
                Key::Unknown | Key::Invalid => {
                    if key == Key::Invalid {
                        budget.invalid = true;
                    }
                    map.next_value_seed(Skip {
                        depth: 1,
                        budget: &mut budget,
                    })?;
                    continue;
                }
            };
            let value = map.next_value_seed(ScalarSeed {
                budget: &mut budget,
            })?;
            if slot.replace(value).is_some() {
                // A duplicate required member is ambiguous.
                budget.invalid = true;
            }
        }
        if budget.invalid {
            return Ok(disabled());
        }
        let parsed = match (version, reason, retry_after) {
            (Some(Scalar::U64(EXTENSION_VERSION)), Some(Scalar::Token(token)), retry_after) => {
                match (token, retry_after) {
                    (Token::OriginalPair, Some(Scalar::U64(retry_after_unix_seconds))) => {
                        Some(RefusalReoffer::OriginalPair {
                            retry_after_unix_seconds,
                        })
                    }
                    (Token::LegacyOther, Some(Scalar::U64(retry_after_unix_seconds))) => {
                        Some(RefusalReoffer::LegacyOther {
                            retry_after_unix_seconds,
                        })
                    }
                    (Token::Classified, None) => Some(RefusalReoffer::Classified),
                    _ => None,
                }
            }
            _ => None,
        };
        Ok(parsed.or_else(disabled))
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Key {
    Version,
    Reason,
    RetryAfter,
    Unknown,
    Invalid,
}

struct KeySeed;

impl<'de> DeserializeSeed<'de> for KeySeed {
    type Value = Key;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Key, D::Error> {
        deserializer.deserialize_str(KeyVisitor)
    }
}

struct KeyVisitor;

impl Visitor<'_> for KeyVisitor {
    type Value = Key;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("an extension member name")
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<Key, E> {
        Ok(match value {
            _ if value.len() > MAX_TOKEN_BYTES => Key::Invalid,
            "version" => Key::Version,
            "reason" => Key::Reason,
            "retry_after_unix_seconds" => Key::RetryAfter,
            _ => Key::Unknown,
        })
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Token {
    OriginalPair,
    LegacyOther,
    Classified,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Scalar {
    U64(u64),
    Token(Token),
    Other,
}

struct ScalarSeed<'a> {
    budget: &'a mut Budget,
}

impl<'de> DeserializeSeed<'de> for ScalarSeed<'_> {
    type Value = Scalar;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Scalar, D::Error> {
        deserializer.deserialize_any(ScalarVisitor {
            budget: self.budget,
        })
    }
}

struct ScalarVisitor<'a> {
    budget: &'a mut Budget,
}

impl<'de> Visitor<'de> for ScalarVisitor<'_> {
    type Value = Scalar;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("an extension scalar")
    }

    fn visit_u64<E: de::Error>(self, value: u64) -> Result<Scalar, E> {
        Ok(Scalar::U64(value))
    }

    fn visit_i64<E: de::Error>(self, value: i64) -> Result<Scalar, E> {
        // serde_json reports non-negative integers through visit_u64.
        Ok(u64::try_from(value).map_or(Scalar::Other, Scalar::U64))
    }

    fn visit_f64<E: de::Error>(self, _: f64) -> Result<Scalar, E> {
        Ok(Scalar::Other)
    }

    fn visit_bool<E: de::Error>(self, _: bool) -> Result<Scalar, E> {
        Ok(Scalar::Other)
    }

    fn visit_unit<E: de::Error>(self) -> Result<Scalar, E> {
        Ok(Scalar::Other)
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<Scalar, E> {
        if value.len() > MAX_TOKEN_BYTES {
            self.budget.invalid = true;
            return Ok(Scalar::Other);
        }
        Ok(match value {
            ORIGINAL_PAIR_CANDIDATE_UNPROVED => Scalar::Token(Token::OriginalPair),
            LEGACY_OTHER => Scalar::Token(Token::LegacyOther),
            CLASSIFIED => Scalar::Token(Token::Classified),
            _ => Scalar::Other,
        })
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Scalar, A::Error> {
        let budget = self.budget;
        while seq
            .next_element_seed(Skip {
                depth: 2,
                budget: &mut *budget,
            })?
            .is_some()
        {}
        Ok(Scalar::Other)
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Scalar, A::Error> {
        let budget = self.budget;
        while map
            .next_key_seed(Skip {
                depth: 2,
                budget: &mut *budget,
            })?
            .is_some()
        {
            map.next_value_seed(Skip {
                depth: 2,
                budget: &mut *budget,
            })?;
        }
        Ok(Scalar::Other)
    }
}

/// Consumes one value of unknown shape without retaining it. Within bounds
/// it counts nodes and depth; once out of bounds it marks the extension
/// invalid and consumes the rest with `IgnoredAny`, which allocates nothing.
struct Skip<'a> {
    depth: usize,
    budget: &'a mut Budget,
}

impl<'de> DeserializeSeed<'de> for Skip<'_> {
    type Value = ();

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        if self.budget.invalid {
            deserializer.deserialize_ignored_any(IgnoredAny)?;
            return Ok(());
        }
        deserializer.deserialize_any(SkipVisitor {
            depth: self.depth,
            budget: self.budget,
        })
    }
}

struct SkipVisitor<'a> {
    depth: usize,
    budget: &'a mut Budget,
}

impl<'de> Visitor<'de> for SkipVisitor<'_> {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("any bounded value")
    }

    fn visit_bool<E: de::Error>(self, _: bool) -> Result<(), E> {
        self.budget.visit(self.depth);
        Ok(())
    }

    fn visit_i64<E: de::Error>(self, _: i64) -> Result<(), E> {
        self.budget.visit(self.depth);
        Ok(())
    }

    fn visit_u64<E: de::Error>(self, _: u64) -> Result<(), E> {
        self.budget.visit(self.depth);
        Ok(())
    }

    fn visit_f64<E: de::Error>(self, _: f64) -> Result<(), E> {
        self.budget.visit(self.depth);
        Ok(())
    }

    fn visit_unit<E: de::Error>(self) -> Result<(), E> {
        self.budget.visit(self.depth);
        Ok(())
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<(), E> {
        self.budget.visit(self.depth);
        if value.len() > MAX_TOKEN_BYTES {
            self.budget.invalid = true;
        }
        Ok(())
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<(), A::Error> {
        let budget = self.budget;
        budget.visit(self.depth);
        while seq
            .next_element_seed(Skip {
                depth: self.depth + 1,
                budget: &mut *budget,
            })?
            .is_some()
        {}
        Ok(())
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
        let budget = self.budget;
        budget.visit(self.depth);
        while map
            .next_key_seed(Skip {
                depth: self.depth + 1,
                budget: &mut *budget,
            })?
            .is_some()
        {
            map.next_value_seed(Skip {
                depth: self.depth + 1,
                budget: &mut *budget,
            })?;
        }
        Ok(())
    }
}

impl crate::heap_layout_bound::HeapLayoutBound for ReofferCounts {
    fn heap_bound(&self, counter: &mut crate::heap_layout_bound::Counter) -> Option<()> {
        counter.add(0)
    }
}

/// Per-cycle, entity-grain counters. Content-free: no session ids,
/// fingerprints, account names, body details or paths.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(super) struct ReofferCounts {
    pub(super) due: usize,
    pub(super) selected: usize,
    pub(super) legacy_selected: usize,
    pub(super) attempted: usize,
    pub(super) attempted_bytes: usize,
    pub(super) gate_held: usize,
    pub(super) ineligible_unbound: usize,
    pub(super) clock_bound_skipped: usize,
    pub(super) accepted: usize,
    pub(super) unchanged_unstored: usize,
    pub(super) refused_same: usize,
    pub(super) refused_other: usize,
    pub(super) retryable: usize,
    pub(super) shed: usize,
    pub(super) failed: usize,
    pub(super) not_materialized: usize,
    pub(super) deferred_budget: usize,
    pub(super) outside_policy_window: usize,
    pub(super) invalid_extension: usize,
}

impl ReofferCounts {
    pub(super) fn line(&self, source: &str) -> String {
        format!(
            "snapshot reason_reoffer source={source} reason={ORIGINAL_PAIR_CANDIDATE_UNPROVED} \
             due={} selected={} legacy_selected={} attempted={} attempted_bytes={} gate_held={} ineligible_unbound={} clock_bound_skipped={} accepted={} \
             unchanged_unstored={} refused_same={} refused_other={} retryable={} shed={} \
             failed={} not_materialized={} deferred_budget={} outside_policy_window={} \
             invalid_extension_process={}",
            self.due,
            self.selected,
            self.legacy_selected,
            self.attempted,
            self.attempted_bytes,
            self.gate_held,
            self.ineligible_unbound,
            self.clock_bound_skipped,
            self.accepted,
            self.unchanged_unstored,
            self.refused_same,
            self.refused_other,
            self.retryable,
            self.shed,
            self.failed,
            self.not_materialized,
            self.deferred_budget,
            self.outside_policy_window,
            self.invalid_extension,
        )
    }
}

/// Emit work every cycle, but an unchanged, quiet backlog only once. The
/// decoder counter is process-wide and explicitly labelled that way above.
pub(super) fn should_log(source: &str, counts: &ReofferCounts) -> bool {
    use std::collections::BTreeMap;
    use std::sync::{Mutex, OnceLock};
    static PREVIOUS: OnceLock<Mutex<BTreeMap<String, ReofferCounts>>> = OnceLock::new();
    let mut previous = PREVIOUS.get_or_init(Default::default).lock().unwrap();
    should_log_change(previous.insert(source.to_string(), *counts), counts)
}

pub(super) fn should_log_change(previous: Option<ReofferCounts>, counts: &ReofferCounts) -> bool {
    counts.selected > 0
        || counts.attempted > 0
        || counts.clock_bound_skipped > 0
        || counts.invalid_extension > 0
        || (previous.is_some_and(|old| old != *counts)
            || previous.is_none() && *counts != ReofferCounts::default())
}
