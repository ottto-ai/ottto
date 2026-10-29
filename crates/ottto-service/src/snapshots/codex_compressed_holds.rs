//! Dedicated non-red custody; no acquisition or ACK authority.
use super::*;

/// Called with existing walk metadata; repeated observations are not unique bytes.
pub(super) fn observe_growth(
    source: SnapshotSource,
    files: &BTreeMap<String, ScanIndexEntry>,
    path: &Path,
    length: u64,
) {
    let Some(entry) = files
        .get(&local_index_key(path))
        .filter(|entry| source == SnapshotSource::Codex && entry.codex_compressed_hold.is_some())
    else {
        return;
    };
    if !is_compressed_codex_rollout(Some(path), None) {
        let bytes = length.saturating_sub(entry.size_bytes);
        let over_cap = u64::from(length > max_jsonl_file_bytes(source));
        if bytes != 0 || over_cap != 0 {
            crate::local_resource_diagnostics::codex_held_growth(bytes, over_cap);
        }
    }
}

pub(super) fn deserialize_hold<'de, D: serde::Deserializer<'de>>(
    de: D,
) -> Result<Option<CodexZstCause>, D::Error> {
    struct Hold;
    fn unsupported() -> Option<CodexZstCause> {
        crate::local_resource_diagnostics::codex_zst_held(CodexZstCause::OwnerUnproven);
        Some(CodexZstCause::OwnerUnproven)
    }
    impl<'de> serde::de::Visitor<'de> for Hold {
        type Value = Option<CodexZstCause>;
        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("an optional closed custody cause")
        }
        fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
            Ok(None)
        }
        fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Self::Value, E> {
            if value.len() > 64 {
                return Ok(unsupported());
            }
            Ok(
                CodexZstCause::deserialize(serde::de::value::StrDeserializer::<E>::new(value))
                    .ok()
                    .or_else(unsupported),
            )
        }
        fn visit_bool<E: serde::de::Error>(self, _: bool) -> Result<Self::Value, E> {
            Ok(unsupported())
        }
        fn visit_u64<E: serde::de::Error>(self, _: u64) -> Result<Self::Value, E> {
            Ok(unsupported())
        }
        fn visit_i64<E: serde::de::Error>(self, _: i64) -> Result<Self::Value, E> {
            Ok(unsupported())
        }
        fn visit_f64<E: serde::de::Error>(self, _: f64) -> Result<Self::Value, E> {
            Ok(unsupported())
        }
        fn visit_seq<A: serde::de::SeqAccess<'de>>(
            self,
            mut seq: A,
        ) -> Result<Self::Value, A::Error> {
            while seq.next_element::<serde::de::IgnoredAny>()?.is_some() {}
            Ok(unsupported())
        }
        fn visit_map<A: serde::de::MapAccess<'de>>(
            self,
            mut map: A,
        ) -> Result<Self::Value, A::Error> {
            while map
                .next_entry::<serde::de::IgnoredAny, serde::de::IgnoredAny>()?
                .is_some()
            {}
            Ok(unsupported())
        }
    }
    de.deserialize_any(Hold)
}

impl OwnedSourceScan {
    /// Save only negative decisions for the current paused job before another
    /// byte can be read. Never advances accepted extent, fingerprint or ACK.
    pub(crate) fn persist_custody_decisions(
        &mut self,
        committed: &mut ScanIndex,
        path: &Path,
    ) -> Result<()> {
        if self.source != SnapshotSource::Codex {
            return Ok(());
        }
        let Some(context) = self.sampling.as_ref() else {
            return Ok(());
        };
        while let Some(transaction) = context.cache.custody_decision_to_save(
            &context.namespace,
            &mut self.index,
            committed,
            path,
        )? {
            let d = transaction.decision.as_ref().expect("owned decision");
            // Charge resident escrow + every staging/rollback/working-copy
            // key, set and node BEFORE cloning or mutating either index.
            use crate::heap_layout_bound::{Counter, HeapLayoutBound};
            let mut cost = Counter::new(crate::source_rotation::PARKED_BUDGET);
            let peak = (|| {
                d.heap_bound(&mut cost)?;
                for _ in 0..4 {
                    d.owners.heap_bound(&mut cost)?;
                    d.veto.heap_bound(&mut cost)?;
                    if let Some(owners) = committed.codex_state_only_blocked_by_file.get(&d.key) {
                        owners.heap_bound(&mut cost)?;
                    }
                    cost.add(d.key.len())?;
                    cost.add(crate::heap_layout_bound::tree_node_bytes::<
                        String,
                        ScanIndexEntry,
                    >()?)?;
                    cost.add(crate::heap_layout_bound::tree_node_bytes::<
                        String,
                        BTreeSet<String>,
                    >()?)?;
                }
                cost.add(16384)?;
                Some(cost.bytes)
            })();
            let _funding = peak
                .and_then(|bytes| transaction.fund(bytes))
                .ok_or_else(|| anyhow::anyhow!("custody negative transaction unfunded"))?;
            let mut owners = committed
                .codex_state_only_blocked_by_file
                .get(&d.key)
                .cloned()
                .unwrap_or_default();
            owners.extend(d.owners.iter().cloned());
            let mut added_veto = BTreeSet::new();
            for owner in d.veto.iter().chain(&d.owners) {
                if !committed
                    .codex_state_only_blocked_session_ids
                    .contains(owner)
                {
                    added_veto.insert(owner.clone());
                }
            }
            let existed = committed.files.contains_key(&d.key);
            let previous = committed
                .files
                .entry(d.key.clone())
                .or_default()
                .codex_compressed_hold;
            committed
                .files
                .get_mut(&d.key)
                .expect("present decision")
                .codex_compressed_hold = Some(d.cause);
            let previous_owners = committed
                .codex_state_only_blocked_by_file
                .insert(d.key.clone(), owners);
            committed
                .codex_state_only_blocked_session_ids
                .extend(added_veto.iter().cloned());
            if let Err(error) = committed.save(path) {
                if existed {
                    committed
                        .files
                        .get_mut(&d.key)
                        .expect("present decision")
                        .codex_compressed_hold = previous;
                } else {
                    committed.files.remove(&d.key);
                }
                if let Some(owners) = previous_owners {
                    committed
                        .codex_state_only_blocked_by_file
                        .insert(d.key.clone(), owners);
                } else {
                    committed.codex_state_only_blocked_by_file.remove(&d.key);
                }
                for owner in &added_veto {
                    committed.codex_state_only_blocked_session_ids.remove(owner);
                }
                // Drop restores the entire pending payload, including owner
                // scope, even if this preparation and its job are then lost.
                return Err(error);
            }
            self.index.generation = committed.generation;
            transaction.complete(&mut self.index);
        }
        Ok(())
    }
}
