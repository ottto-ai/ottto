//! Optional, bounded recovery metadata; never authority for money or receipts.
use super::{ack_retention, is_snapshot_fingerprint, HeadConflictChallenge};
use serde::de::{Deserializer, IgnoredAny, MapAccess, Visitor};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};

static REFUSED: AtomicU64 = AtomicU64::new(0);

pub(super) fn note(reason: &str) {
    let total = REFUSED.fetch_add(1, Ordering::Relaxed).saturating_add(1);
    eprintln!(
        "local snapshot head-CAS recovery metadata refused: reason={reason} count=1 process_total={total}; usage remains held"
    );
    #[cfg(test)]
    REFUSALS.with(|counts| counts.borrow_mut().push(reason.to_string()));
}

#[cfg(test)]
thread_local! {
    pub(super) static REFUSALS: std::cell::RefCell<Vec<String>> = const { std::cell::RefCell::new(Vec::new()) };
}

pub(super) fn deserialize<'de, D>(
    deserializer: D,
) -> Result<BTreeMap<String, HeadConflictChallenge>, D::Error>
where
    D: Deserializer<'de>,
{
    struct Recovery;
    impl<'de> Visitor<'de> for Recovery {
        type Value = BTreeMap<String, HeadConflictChallenge>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("optional head-CAS recovery map")
        }

        fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Self::Value, M::Error> {
            let mut records = BTreeMap::new();
            while let Some(key) = map.next_key::<String>()? {
                if records.len() >= ack_retention::default_ack_capacity()
                    && !records.contains_key(&key)
                {
                    map.next_value::<IgnoredAny>()?;
                    note("capacity_hold");
                    continue;
                }
                let value = map.next_value::<Box<serde_json::value::RawValue>>()?;
                let record = serde_json::from_str::<HeadConflictChallenge>(value.get());
                match record {
                    Ok(record)
                        if is_snapshot_fingerprint(&key)
                            && is_snapshot_fingerprint(&record.challenge)
                            && is_snapshot_fingerprint(&record.stale_revision_v2_hash)
                            && record
                                .snapshot_fingerprint
                                .as_deref()
                                .map_or(true, is_snapshot_fingerprint) =>
                    {
                        records.insert(key, record);
                    }
                    _ => note("invalid_shape"),
                }
            }
            Ok(records)
        }
    }
    // Consume the optional JSON value first. Its own shape/depth errors cannot
    // escape into the containing money ledger's decoder. RawValue uses the
    // existing serde_json raw_value feature and retains no parsed unbounded map.
    let raw = Box::<serde_json::value::RawValue>::deserialize(deserializer)?;
    let mut decoder = serde_json::Deserializer::from_str(raw.get());
    match decoder.deserialize_map(Recovery) {
        Ok(records) => Ok(records),
        Err(_) => {
            note("invalid_shape");
            Ok(BTreeMap::new())
        }
    }
}
