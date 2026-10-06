//! Bounded optional retry state owned by the existing snapshot owner.
//! Activation remains an explicit source-review boundary; no timer or worker.
use anyhow::{anyhow, Result};
use std::time::{Duration, Instant};

pub(crate) const RETENTION: Duration = Duration::from_secs(300);
pub(crate) const NETWORK_TURN: Duration = Duration::from_secs(60);
pub(crate) const ADDITIONAL_BATCH_POSTS: usize = 3;
pub(crate) const RESPONSE_BYTES: usize = 128 * 1024;
pub(crate) const TOKEN_RESPONSE_BYTES: usize = 16 * 1024;
pub(crate) const REQUEST_BYTES: usize = 256 * 1024;
pub(crate) const STATE_NODES: usize = 8192;

/// Reject decoded auxiliary-state amplification before constructing Values or
/// native containers. This visitor borrows unescaped strings; serde's escape
/// scratch is bounded by the already capped input. Ordinary readers are unchanged.
pub(crate) fn state_shape(bytes: &[u8]) -> Result<()> {
    use serde::de::{DeserializeSeed, MapAccess, SeqAccess, Visitor};
    struct Shape<'a> {
        nodes: &'a mut usize,
        depth: usize,
    }
    impl<'de> DeserializeSeed<'de> for Shape<'_> {
        type Value = ();
        fn deserialize<D: serde::Deserializer<'de>>(
            self,
            d: D,
        ) -> std::result::Result<(), D::Error> {
            *self.nodes += 1;
            if *self.nodes > STATE_NODES || self.depth > 64 {
                return Err(serde::de::Error::custom(
                    "optional snapshot state shape cap",
                ));
            }
            d.deserialize_any(self)
        }
    }
    impl<'de> Visitor<'de> for Shape<'_> {
        type Value = ();
        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("bounded optional snapshot state")
        }
        fn visit_bool<E: serde::de::Error>(self, _: bool) -> std::result::Result<(), E> {
            Ok(())
        }
        fn visit_i64<E: serde::de::Error>(self, _: i64) -> std::result::Result<(), E> {
            Ok(())
        }
        fn visit_u64<E: serde::de::Error>(self, _: u64) -> std::result::Result<(), E> {
            Ok(())
        }
        fn visit_f64<E: serde::de::Error>(self, _: f64) -> std::result::Result<(), E> {
            Ok(())
        }
        fn visit_str<E: serde::de::Error>(self, _: &str) -> std::result::Result<(), E> {
            Ok(())
        }
        fn visit_unit<E: serde::de::Error>(self) -> std::result::Result<(), E> {
            Ok(())
        }
        fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> std::result::Result<(), A::Error> {
            while seq
                .next_element_seed(Shape {
                    nodes: &mut *self.nodes,
                    depth: self.depth + 1,
                })?
                .is_some()
            {}
            Ok(())
        }
        fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> std::result::Result<(), A::Error> {
            while map
                .next_key_seed(Shape {
                    nodes: &mut *self.nodes,
                    depth: self.depth + 1,
                })?
                .is_some()
            {
                map.next_value_seed(Shape {
                    nodes: &mut *self.nodes,
                    depth: self.depth + 1,
                })?;
            }
            Ok(())
        }
    }
    let mut decoder = serde_json::Deserializer::from_slice(bytes);
    Shape {
        nodes: &mut 0,
        depth: 0,
    }
    .deserialize(&mut decoder)?;
    decoder.end()?;
    Ok(())
}

pub(crate) fn decode_state<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    state_shape(bytes)?;
    serde_json::from_slice(bytes).map_err(anyhow::Error::from)
}

struct CountJson {
    bytes: usize,
    cap: usize,
}
impl std::io::Write for CountJson {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.bytes = self
            .bytes
            .checked_add(bytes.len())
            .filter(|n| *n <= self.cap)
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "optional snapshot JSON cap",
                )
            })?;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
pub(crate) fn json_fits<T: serde::Serialize + ?Sized>(value: &T, cap: usize) -> bool {
    serde_json::to_writer(CountJson { bytes: 0, cap }, value).is_ok()
}
pub(crate) fn encode_json<T: serde::Serialize>(value: &T, cap: usize) -> Result<Vec<u8>> {
    struct CappedVec {
        bytes: Vec<u8>,
        cap: usize,
    }
    impl std::io::Write for CappedVec {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if self
                .bytes
                .len()
                .checked_add(bytes.len())
                .map_or(true, |n| n > self.cap)
            {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "optional snapshot request cap",
                ));
            }
            self.bytes.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut writer = CappedVec {
        bytes: Vec::with_capacity(4096.min(cap)),
        cap,
    };
    serde_json::to_writer(&mut writer, value)?;
    Ok(writer.bytes)
}

/// One allowance survives every wake, fallback and authentication replay.
/// Starting another turn never replenishes its physical batch POST counter.
#[derive(Debug)]
pub(crate) struct RetryBudget {
    due: Instant,
    expires: Instant,
    turn_deadline: Option<Instant>,
    posts_left: usize,
    gzip_refused: bool,
    #[cfg(test)]
    force_gzip: bool,
}
impl RetryBudget {
    pub(crate) fn after_shed(now: Instant, delay: Duration) -> Option<Self> {
        let expires = now.checked_add(RETENTION)?;
        let due = now.checked_add(delay)?;
        (due < expires).then_some(Self {
            due,
            expires,
            turn_deadline: None,
            posts_left: ADDITIONAL_BATCH_POSTS,
            gzip_refused: false,
            #[cfg(test)]
            force_gzip: false,
        })
    }
    pub(crate) fn gzip_enabled(&self, default: bool) -> bool {
        #[cfg(test)]
        let default = default || self.force_gzip;
        default && !self.gzip_refused
    }
    pub(crate) fn gzip_refused(&mut self) {
        self.gzip_refused = true;
    }
    #[cfg(test)]
    pub(crate) fn force_gzip_for_test(&mut self) {
        self.force_gzip = true;
    }
    pub(crate) fn due(&self) -> Instant {
        self.due
    }
    pub(crate) fn expires(&self) -> Instant {
        self.expires
    }
    pub(crate) fn posts_left(&self) -> usize {
        self.posts_left
    }
    pub(crate) fn enter(&mut self, now: Instant) -> Result<()> {
        if now < self.due
            || now >= self.expires
            || self.posts_left == 0
            || self.turn_deadline.is_some()
        {
            return Err(anyhow!("optional snapshot retry is ineligible"));
        }
        self.turn_deadline = Some(
            now.checked_add(NETWORK_TURN)
                .unwrap_or(self.expires)
                .min(self.expires),
        );
        Ok(())
    }
    pub(crate) fn remaining(&self, now: Instant) -> Result<Duration> {
        self.turn_deadline
            .and_then(|deadline| deadline.checked_duration_since(now))
            .filter(|remaining| !remaining.is_zero())
            .ok_or_else(|| anyhow!("optional snapshot retry network deadline expired"))
    }
    pub(crate) fn deadline(&self) -> Result<Instant> {
        self.remaining(Instant::now())?;
        self.turn_deadline
            .ok_or_else(|| anyhow!("optional snapshot retry has no active deadline"))
    }
    /// Charge before attempting the wire, including gzip fallback and replay.
    pub(crate) fn batch_post(&mut self, now: Instant) -> Result<Duration> {
        let remaining = self.remaining(now)?;
        if self.posts_left == 0 {
            return Err(anyhow!("optional snapshot retry POST allowance exhausted"));
        }
        self.posts_left -= 1;
        Ok(remaining)
    }
    pub(crate) fn defer(&mut self, now: Instant, delay: Duration) -> bool {
        self.turn_deadline = None;
        let Some(due) = now.checked_add(delay) else {
            return false;
        };
        self.due = due;
        due < self.expires && self.posts_left > 0
    }
    /// Shorten the existing wait; do not reanchor its ordinary absolute deadline.
    pub(crate) fn wake_before(&self, ordinary_deadline: Instant) -> Instant {
        self.due.min(ordinary_deadline)
    }
}

/// Bounded read before decoding a competing checkpoint. The same native locks
/// and compare-and-swap remain responsible for settlement authority.
pub(crate) fn read_state(path: &std::path::Path, cap: usize) -> std::io::Result<Vec<u8>> {
    use std::io::Read;
    let mut bytes = Vec::with_capacity(cap.min(4096));
    std::fs::File::open(path)?
        .take(cap as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > cap {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "optional snapshot state exceeds admission limit",
        ));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bounded_retry_budget_preserves_lifetime_posts_and_ordinary_deadline() {
        let now = Instant::now();
        let ordinary = now + RETENTION;
        let mut budget = RetryBudget::after_shed(now, Duration::from_secs(66)).unwrap();
        assert!(budget.enter(now + Duration::from_secs(65)).is_err());
        assert_eq!(budget.wake_before(ordinary), now + Duration::from_secs(66));
        budget.enter(now + Duration::from_secs(66)).unwrap();
        budget.batch_post(now + Duration::from_secs(67)).unwrap();
        budget.batch_post(now + Duration::from_secs(68)).unwrap();
        assert!(budget.defer(now + Duration::from_secs(70), Duration::from_secs(66)));
        assert_eq!(budget.expires(), ordinary);
        budget.enter(now + Duration::from_secs(136)).unwrap();
        budget.batch_post(now + Duration::from_secs(137)).unwrap();
        assert!(budget.batch_post(now + Duration::from_secs(138)).is_err());
        assert!(!budget.defer(now + Duration::from_secs(140), Duration::from_secs(60)));
        assert_eq!(ordinary, now + RETENTION);
    }
    #[test]
    fn bounded_retry_turn_cannot_reset_deadline_or_extend_retention() {
        let now = Instant::now();
        assert!(RetryBudget::after_shed(now, RETENTION).is_none());
        let mut budget = RetryBudget::after_shed(now, Duration::from_secs(299)).unwrap();
        budget.enter(now + Duration::from_secs(299)).unwrap();
        assert!(budget.enter(now + Duration::from_secs(299)).is_err());
        assert_eq!(
            budget.remaining(now + Duration::from_secs(299)).unwrap(),
            Duration::from_secs(1)
        );
        assert!(budget.remaining(now + RETENTION).is_err());
        assert!(!budget.defer(now + Duration::from_secs(299), Duration::from_secs(2)));
    }
}
