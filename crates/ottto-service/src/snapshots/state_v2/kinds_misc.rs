//! One existing v1 serde value per misc field; exact opaque holds are separate.
use super::catalogue::scan_index_fields;
use super::*;
use anyhow::{bail, ensure, Context};
use std::collections::{BTreeMap, BTreeSet};
fn field_mode(kind: &str) -> mapper::Members {
    macro_rules! lookup {
        ($f:ident, Misc, (misc $c:ident $mode:ident), [$kind:literal], $h:ident) => {
            if kind == $kind {
                return mapper::Members::$mode;
            }
        };
        ($($t:tt)*) => {};
    }
    scan_index_fields!(each lookup);
    mapper::Members::Field
}
fn write_field<T: Serialize + ?Sized>(
    value: &T,
    slot: &str,
    kind: &str,
    rows: &mut mapper::Rows<'_>,
    cx: &mut KindCx,
) -> Result<()> {
    mapper::field_write(rows, kind, value, field_mode(kind))?;
    cx.presence.entry(slot.into()).or_insert(true);
    Ok(())
}
fn read_field<T: serde::de::DeserializeOwned + Serialize>(
    kind: &str,
    tx: &mut dyn Transaction,
    seed: Option<&mut mapper::Digests>,
) -> Result<T> {
    mapper::field_read(tx, kind, field_mode(kind), seed)
}
#[derive(Serialize, Deserialize, Default)]
struct HoldMetadata {
    provenance: (u128, u64),
    entries: BTreeMap<String, BTreeMap<String, HoldSlot>>,
}
#[derive(Serialize, Deserialize)]
struct HoldSlot {
    owner: Option<(usize, usize)>,
    charge: u64,
}
fn write_holds(index: &ScanIndex, rows: &mut mapper::Rows<'_>) -> Result<()> {
    let mut metadata = HoldMetadata {
        provenance: index.decode_holds.v2_provenance(),
        ..Default::default()
    };
    for (field, key, raw, owner, charge) in index.decode_holds.v2_entries() {
        let kind = format!("raw_hold.{field}");
        ensure!(
            catalogue::group(&kind) == Some(catalogue::Group::Misc),
            "state_v2_misc_unmapped_hold"
        );
        let row_key = RowKey::record(&kind, key.as_bytes(), 0)?;
        rows.raw(row_key, raw)?;
        metadata.entries.entry(field.into()).or_default().insert(
            key.into(),
            HoldSlot {
                owner: owner.map(|r| (r.start, r.end)),
                charge,
            },
        );
    }
    // Internal repair custody is not a field in the original v1 document.
    mapper::field_write(
        rows,
        "v1_field.repair_provenance",
        &metadata,
        mapper::Members::Field,
    )
}
fn read_holds(
    index: &mut ScanIndex,
    txn: &mut dyn Transaction,
    seed: Option<&mut mapper::Digests>,
) -> Result<()> {
    let metadata: HoldMetadata = read_field("v1_field.repair_provenance", txn, seed)?;
    let mut holds = super::super::lenient_decode::Holds::default();
    let mut expected = 0;
    for (field, slots) in metadata.entries {
        let kind = format!("raw_hold.{field}");
        ensure!(
            catalogue::group(&kind) == Some(catalogue::Group::Misc),
            "state_v2_misc_unmapped_hold"
        );
        for (key, slot) in slots {
            let key = RowKey::record(&kind, key.as_bytes().to_vec(), 0)?;
            let h = txn.get(&key)?.context("state_v2_misc_missing_hold")?;
            ensure!(
                h.fixed == Fixed::None
                    && h.value_version == 1
                    && h.len <= slot.charge
                    && slot.charge <= 8 * 1024 * 1024
                    && holds
                        .held_bytes()
                        .checked_add(slot.charge)
                        .is_some_and(|n| n <= 8 * 1024 * 1024),
                "state_v2_misc_hold_admission"
            );
            let mut raw = Vec::new();
            txn.read_value(&h, &mut raw)?;
            let RowKey::Record { key_bytes, .. } = &key else {
                bail!("state_v2_hold_key");
            };
            holds.v2_insert(
                &field,
                std::str::from_utf8(key_bytes)?.into(),
                raw,
                slot.owner.map(|(a, b)| a..b),
                slot.charge,
            )?;
            expected += 1;
        }
    }
    // An extra row cannot silently lose opaque custody merely because its
    // metadata was omitted. Every raw owner must be named exactly once.
    let mut actual = 0;
    for (kind, _) in catalogue::OWNED
        .iter()
        .filter(|(k, _)| k.starts_with("raw_hold."))
    {
        mapper::rows(txn, kind, |_, _| {
            actual += 1;
            Ok(())
        })?;
    }
    ensure!(actual == expected, "state_v2_misc_orphan_hold");
    holds.v2_finish(metadata.provenance);
    index.decode_holds = holds;
    Ok(())
}
fn read_control<T: serde::de::DeserializeOwned + Serialize>(
    name: &str,
    txn: &mut dyn Transaction,
) -> Result<T> {
    let h = txn
        .get(&RowKey::Meta(name.into()))?
        .context("state_v2_misc_missing_control")?;
    ensure!(
        h.len <= CONTROL_BYTES && h.value_version == 1,
        "state_v2_misc_control"
    );
    let mut bytes = Vec::new();
    txn.read_value(&h, &mut bytes)?;
    let value = serde_json::from_slice(&bytes)?;
    Ok(value)
}

pub(super) fn merge_cas_at(
    tx: &mut dyn Transaction,
    working: &mut ScanIndex,
    expected: u64,
) -> Result<()> {
    use super::super::terminal_contract_retry;
    use serde::de::{DeserializeSeed, MapAccess, Visitor};
    let generation: u64 = read_control("generation", tx)?;
    let schema: u16 = read_control("schema_version", tx)?;
    ensure!(
        generation == expected && schema == working.schema_version,
        "state_v2_concurrent_change"
    );
    let mut custody = ScanIndex::default();
    read_holds(&mut custody, tx, None)?;
    custody.schema_version = schema;
    custody.generation = generation;
    custody.accepted_snapshot_fingerprint_ledger_version = read_field(
        "v1_field.accepted_snapshot_fingerprint_ledger_version",
        tx,
        None,
    )?;
    kinds_census::hydrate_cas_controls(tx, &mut custody)?;
    let raw_quarantines: BTreeSet<_> = custody
        .decode_holds
        .v2_entries()
        .filter(|(field, ..)| *field == "quarantined_snapshot_fingerprints")
        .map(|(_, key, ..)| key.to_owned())
        .collect();
    let roots = super::super::lenient_decode::cas_hold_roots(&custody);
    kinds_accounts::hydrate_filtered(
        tx,
        &mut custody,
        &mut KindCx::default(),
        Some((&roots, false)),
    )?;
    kinds_census::hydrate_cas_families(tx, &mut custody, &roots)?;
    super::super::lenient_decode::post_decode_hydrated(&mut custody, "cas", "claude_code")?;

    // Outside held roots, only authority+witness binding affects the repair
    // commitment. Visit one family, never a second full account graph.
    let kind = RecordKind::parse("refusal.authority")?;
    let mut after = None;
    let mut last = None;
    loop {
        let page = tx.scan_kind(&kind, after.as_ref(), 64)?;
        if page.is_empty() {
            break;
        }
        for h in &page {
            let RowKey::Record { key_bytes, .. } = &h.key else {
                bail!("state_v2_cas_authority_key");
            };
            if matches!(&h.key, RowKey::Record { position: 0, .. }) {
                continue;
            }
            let root = kinds_accounts::dependency_family(key_bytes)?;
            if last.as_ref() == Some(&root) {
                continue;
            }
            last = Some(root.clone());
            if roots.contains(&root) {
                continue;
            }
            let one = BTreeSet::from([root]);
            let mut family = ScanIndex::default();
            kinds_accounts::hydrate_filtered(
                tx,
                &mut family,
                &mut KindCx::default(),
                Some((&one, true)),
            )?;
            super::super::lenient_decode::post_decode_hydrated(&mut family, "cas", "claude_code")?;
            super::super::lenient_decode::add_cas_provenance(&mut custody, &family);
        }
        after = page.last().map(|h| h.key.clone());
    }
    struct Claims<'a> {
        target: &'a mut ScanIndex,
        raw: &'a BTreeSet<String>,
        merge: bool,
    }
    impl<'de> Visitor<'de> for Claims<'_> {
        type Value = ();
        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("quarantine map")
        }
        fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> std::result::Result<(), A::Error> {
            while let Some((key, current)) =
                map.next_entry::<String, super::super::SnapshotQuarantineRecord>()?
            {
                if self.raw.contains(&key) {
                    continue;
                }
                let mut current_view = ScanIndex::default();
                current_view
                    .quarantined_snapshot_fingerprints
                    .insert(key.clone(), current);
                super::super::lenient_decode::post_decode_hydrated(
                    &mut current_view,
                    "cas",
                    "claude_code",
                )
                .map_err(serde::de::Error::custom)?;
                if self.merge {
                    if let (Some(working), Some(current)) = (
                        self.target.quarantined_snapshot_fingerprints.get_mut(&key),
                        current_view.quarantined_snapshot_fingerprints.get(&key),
                    ) {
                        terminal_contract_retry::merge_claims(working, current);
                    }
                } else {
                    super::super::lenient_decode::add_cas_provenance(self.target, &current_view);
                }
            }
            Ok(())
        }
    }
    impl<'de> DeserializeSeed<'de> for Claims<'_> {
        type Value = ();
        fn deserialize<D: serde::Deserializer<'de>>(
            self,
            de: D,
        ) -> std::result::Result<(), D::Error> {
            de.deserialize_map(self)
        }
    }
    for merge in [false, true] {
        if merge {
            ensure!(
                custody.decode_holds.same_as(&working.decode_holds)
                    && custody.decode_repairs_match(working),
                "current_index_requires_reload"
            );
            terminal_contract_retry::merge_maps(
                &mut working.quarantined_snapshot_fingerprints,
                &custody.quarantined_snapshot_fingerprints,
            );
        }
        mapper::rows(tx, "refusal.snapshot", |tx, h| {
            let RowKey::Record {
                key_bytes,
                position,
                ..
            } = &h.key
            else {
                bail!("state_v2_cas_key");
            };
            if *position == 0 {
                return Ok(());
            }
            let key = std::str::from_utf8(key_bytes)?;
            let raw = mapper::bytes(tx, &h)?;
            let json = codec::expand(&raw, value_cap(&h.key))?;
            let value: Box<serde_json::value::RawValue> = serde_json::from_slice(&json)?;
            let singleton = BTreeMap::from([(key, value)]);
            let json = serde_json::to_vec(&singleton)?;
            let mut de = serde_json::Deserializer::from_slice(&json);
            Claims {
                target: if merge { &mut *working } else { &mut custody },
                raw: &raw_quarantines,
                merge,
            }
            .deserialize(&mut de)?;
            de.end()?;
            Ok(())
        })?;
    }
    Ok(())
}

pub(super) fn rows(index: &ScanIndex, rows: &mut mapper::Rows<'_>, cx: &mut KindCx) -> Result<()> {
    rows.raw(
        RowKey::Meta("schema_version".into()),
        &serde_json::to_vec(&index.schema_version)?,
    )?;
    macro_rules! save {
        (claude_desktop_store_inventory, $($t:tt)*) => {};
        ($f:ident, Misc, (misc $($c:ident)*), [$kind:literal], $h:ident) => {
            write_field(&index.$f, stringify!($f), $kind, rows, cx)?;
        };
        ($($t:tt)*) => {};
    }
    scan_index_fields!(each save);
    write_holds(index, rows)?;
    rows.raw(
        RowKey::Meta("field_presence".into()),
        &serde_json::to_vec(&cx.presence)?,
    )
}
pub(super) fn hydrate_txn(
    tx: &mut dyn Transaction,
    index: &mut ScanIndex,
    cx: &mut KindCx,
) -> Result<()> {
    index.schema_version = read_control("schema_version", tx)?;
    index.generation = read_control("generation", tx)?;
    cx.presence = read_control("field_presence", tx)?;
    ensure!(
        cx.presence
            .keys()
            // Older authenticated v2 imports recorded this name even when
            // absent in v1. Its metadata remains valid only in this store.
            .all(|s| s == "growth_retention"
                || super::super::lenient_decode::FIELDS.contains(&s.as_str())),
        "state_v2_unknown_presence_field"
    );
    macro_rules! load {
        ($f:ident, Misc, (misc $($c:ident)*), [$kind:literal], $h:ident) => {
            index.$f = read_field($kind, tx, Some(&mut cx.digests))?;
        };
        ($($t:tt)*) => {};
    }
    scan_index_fields!(each load);
    index.archives = std::mem::take(&mut index.archives)
        .into_iter()
        .map(|(key, a)| (key, a.checked()))
        .collect();
    read_holds(index, tx, Some(&mut cx.digests))
}
pub(super) fn references(
    _: &Header,
    _: &dyn Value,
    _: &mut dyn FnMut(&RowKey) -> Result<()>,
) -> Result<()> {
    Ok(())
}
pub(super) fn private_paths(
    h: &Header,
    value: &dyn Value,
    emit: &mut dyn FnMut(&str) -> Result<()>,
) -> Result<()> {
    if let RowKey::Record {
        kind, key_bytes, ..
    } = &h.key
    {
        if kind.name().starts_with("raw_hold.") {
            emit(std::str::from_utf8(key_bytes)?)?;
            let raw = codec::capture(value, value_cap(&h.key))?;
            // Malformed held JSON remains private text too.
            if let Ok(text) = std::str::from_utf8(&raw) {
                emit(text)?;
            }
            return Ok(());
        }
    }
    mapper::private_paths(h, value, emit)
}
