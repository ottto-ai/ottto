//! One existing v1 serde value per misc field; exact opaque holds are separate.
use super::*;
use anyhow::{bail, ensure, Context};
use std::collections::{BTreeMap, BTreeSet};
macro_rules! catalogue {
    ($( $field:ident => ($kind:literal,$mode:ident) ),* $(,)?) => {
        pub(super) const KINDS:&[&str]=&[$($kind,)* "v1_field.repair_provenance","raw_hold.files","raw_hold.growth_retention","raw_hold.claude_account_family_witnesses","raw_hold.claude_account_family_pending","raw_hold.claude_usage_family_witnesses","raw_hold.claude_usage_family_pending","raw_hold.claude_usage_authority_quarantine","raw_hold.quarantined_snapshot_fingerprints",];
        pub(super) fn field_kind(field:&str)->Option<&'static str> { match field { $(stringify!($field)=>Some($kind),)* _=>None } }
        fn field_mode(kind:&str)->mapper::Members { match kind { $($kind=>mapper::Members::$mode,)* _=>mapper::Members::Field } }
        macro_rules! fields { ($apply:ident) => { $($apply!($field,$kind);)* }; }
    };
}
catalogue! {
    upload_context_fingerprint => ("setting.upload_context_fingerprint",Field),
    known_configured_scan_roots => ("v1_field.known_configured_scan_roots",Set),
    legacy_unresolved_root_file_witnesses => ("v1_field.legacy_unresolved_root_file_witnesses",Set),
    codex_state_only_snapshot_fingerprints => ("v1_field.codex_state_only_snapshot_fingerprints",Map),
    codex_state_only_blocked_session_ids => ("v1_field.codex_state_only_blocked_session_ids",Set),
    codex_state_only_blocked_by_file => ("v1_field.codex_state_only_blocked_by_file",Map),
    codex_state_only_blocked_unattributed => ("v1_field.codex_state_only_blocked_unattributed",Set),
    codex_state_only_blocked_legacy => ("v1_field.codex_state_only_blocked_legacy",Set),
    codex_state_only_blocked_attributed => ("v1_field.codex_state_only_blocked_attributed",Field),
    codex_parent_ownership_refs => ("v1_field.codex_parent_ownership_refs",Set),
    codex_parent_ownership_ledgers => ("v1_field.codex_parent_ownership_ledgers",Map),
    codex_parent_side_requests => ("v1_field.codex_parent_side_requests",Map),
    codex_parent_side => ("v1_field.codex_parent_side",Map),
    codex_parent_side_generation => ("v1_field.codex_parent_side_generation",Field),
    codex_parent_proof_wrap_epoch => ("v1_field.codex_parent_proof_wrap_epoch",Field),
    codex_parent_prefix_proofs => ("v1_field.codex_parent_prefix_proofs",Map),
    codex_parent_proof_cursor => ("v1_field.codex_parent_proof_cursor",Field),
    codex_parent_side_cursor => ("v1_field.codex_parent_side_cursor",Field),
    codex_parent_proof_seq => ("v1_field.codex_parent_proof_seq",Field),
    codex_proof_index_incarnation => ("v1_field.codex_proof_index_incarnation",Field),
    claude_duplicate_fence_rearm_attempt => ("scan_state.claude_duplicate_fence_rearm_attempt",Field),
    claude_duplicate_fence_next_full_rearm_unix_seconds => ("scan_state.claude_duplicate_fence_next_full_rearm_unix_seconds",Field),
    claude_full_rearm_progress => ("scan_state.claude_full_rearm_progress",Field),
    claude_request_identity_contract => ("setting.claude_request_identity_contract",Field),
    claude_request_identity_contract_changed => ("setting.claude_request_identity_contract_changed",Field),
    claude_desktop_store_cursor => ("v1_field.claude_desktop_store_cursor",Field),
    claude_desktop_store_upper_bound => ("v1_field.claude_desktop_store_upper_bound",Field),
    claude_desktop_store_sweep_had_errors => ("v1_field.claude_desktop_store_sweep_had_errors",Field),
    claude_desktop_identity_census_complete => ("v1_field.claude_desktop_identity_census_complete",Field),
    claude_desktop_lineage_census_complete => ("v1_field.claude_desktop_lineage_census_complete",Field),
    claude_desktop_census_witness => ("v1_field.claude_desktop_census_witness",Field),
    claude_desktop_store_retry_attempt => ("v1_field.claude_desktop_store_retry_attempt",Field),
    claude_desktop_store_retry_not_before_unix_seconds => ("v1_field.claude_desktop_store_retry_not_before_unix_seconds",Field),
    resume_after_path => ("scan_state.resume_after_path",Field),
    resume_upper_bound_path => ("scan_state.resume_upper_bound_path",Field),
    resume_census_window_end => ("scan_state.resume_census_window_end",Field),
    bounded_sweep_had_unsettled_upload => ("scan_state.bounded_sweep_had_unsettled_upload",Field),
    bounded_sweep_unsettled_causes => ("scan_state.bounded_sweep_unsettled_causes",Field),
    traversal => ("scan_state.traversal",Field),
    claude_stale_family_carry => ("scan_state.claude_stale_family_carry",Field),
    scan_residue_witness => ("scan_state.scan_residue_witness",Field),
    historical_replay_generation => ("setting.historical_replay_generation",Field),
    context_curve_capability_enabled => ("setting.context_curve_capability_enabled",Field),
    context_curve_replay_epoch => ("setting.context_curve_replay_epoch",Field),
    completed_context_curve_replay_generation => ("setting.completed_context_curve_replay_generation",Field),
    accepted_snapshot_fingerprints => ("accepted.entity",Set),
    accepted_snapshot_fingerprint_ledger_version => ("v1_field.accepted_snapshot_fingerprint_ledger_version",Field),
    legacy_settlement_reconcile_after_fingerprint => ("v1_field.legacy_settlement_reconcile_after_fingerprint",Field),
    quarantined_snapshot_fingerprints => ("refusal.snapshot",Map),
    claude_history_cutoff_unix_seconds => ("setting.claude_history_cutoff_unix_seconds",Field),
    claude_history_gate_loaded => ("setting.claude_history_gate_loaded",Field),
    claude_history_move_not_full => ("setting.claude_history_move_not_full",Field),
    claude_history_move_released => ("setting.claude_history_move_released",Field),
    accepted_incidence_pending_census => ("v1_field.accepted_incidence_pending_census",Field),
    accepted_rebuild_incidence => ("accepted.rebuild_incidence",Map),
    accepted_rebuild_pending_since_unix_seconds => ("v1_field.accepted_rebuild_pending_since_unix_seconds",Field),
    accepted_rebuild_last_alarm_unix_seconds => ("v1_field.accepted_rebuild_last_alarm_unix_seconds",Field),
    codex_counting_tombstones => ("v1_field.codex_counting_tombstones",Map),
    codex_counting_evicted_legacy => ("v1_field.codex_counting_evicted_legacy",Field),
    upload_ack_retirement_handoff => ("accepted.ack_handoff",Field),
    held_audit_progress => ("scan_state.held_audit_progress",Field),
    claude_money_birth_store => ("v1_field.birth_store",Field),
    claude_desktop_store_inventory => ("v1_field.claude_desktop_store_inventory",Field),
}
pub(super) const CONTROLS: &[&str] = &["schema_version", "generation"];

fn put_raw(tx: &mut dyn Transaction, cx: &mut KindCx, key: RowKey, raw: &[u8]) -> Result<()> {
    let old = tx.get(&key)?;
    let h = if let Some(h) = old.filter(|h| h.digest == codec::digest(raw)) {
        h
    } else {
        tx.put(RowInput {
            key: &key,
            fixed: &Fixed::None,
            value_version: 1,
            value: &codec::Bytes(raw),
        })?
    };
    cx.misc_rows.insert(key, (h, true));
    Ok(())
}
fn write_field<T: Serialize + ?Sized>(
    value: &T,
    slot: &str,
    kind: &str,
    tx: &mut dyn Transaction,
    cx: &mut KindCx,
) -> Result<()> {
    mapper::field_write(tx, cx, kind, value, field_mode(kind))?;
    cx.presence.entry(slot.into()).or_insert(true);
    Ok(())
}
fn read_field<T: serde::de::DeserializeOwned + Serialize>(
    _: &str,
    kind: &str,
    tx: &mut dyn Transaction,
    cx: &mut KindCx,
) -> Result<T> {
    mapper::field_read(tx, cx, kind, field_mode(kind))
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
fn write_holds(index: &ScanIndex, txn: &mut dyn Transaction, cx: &mut KindCx) -> Result<()> {
    let mut metadata = HoldMetadata {
        provenance: index.decode_holds.v2_provenance(),
        ..Default::default()
    };
    for (field, key, raw, owner, charge) in index.decode_holds.v2_entries() {
        let kind = format!("raw_hold.{field}");
        ensure!(
            KINDS.contains(&kind.as_str()),
            "state_v2_misc_unmapped_hold"
        );
        let row_key = RowKey::record(&kind, key.as_bytes(), 0)?;
        put_raw(txn, cx, row_key, raw)?;
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
        txn,
        cx,
        "v1_field.repair_provenance",
        &metadata,
        mapper::Members::Field,
    )
}
fn read_holds(index: &mut ScanIndex, txn: &mut dyn Transaction, cx: &mut KindCx) -> Result<()> {
    let metadata: HoldMetadata = read_field("decode_holds", "v1_field.repair_provenance", txn, cx)?;
    let mut holds = super::super::lenient_decode::Holds::default();
    let mut expected = 0;
    for (field, slots) in metadata.entries {
        let kind = format!("raw_hold.{field}");
        ensure!(
            KINDS.contains(&kind.as_str()),
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
            cx.misc_rows.insert(key, (h, true));
            expected += 1;
        }
    }
    // An extra row cannot silently lose opaque custody merely because its
    // metadata was omitted. Every raw owner must be named exactly once.
    let mut actual = 0;
    for kind in KINDS.iter().filter(|k| k.starts_with("raw_hold.")) {
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
fn control<T: Serialize>(
    name: &str,
    value: &T,
    txn: &mut dyn Transaction,
    cx: &mut KindCx,
) -> Result<()> {
    put_raw(
        txn,
        cx,
        RowKey::Meta(name.into()),
        &serde_json::to_vec(value)?,
    )?;
    Ok(())
}
fn read_control<T: serde::de::DeserializeOwned + Serialize>(
    name: &str,
    txn: &mut dyn Transaction,
    cx: &mut KindCx,
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
    cx.misc_rows.insert(h.key.clone(), (h, true));
    Ok(value)
}

pub(super) fn merge_cas_at(
    tx: &mut dyn Transaction,
    working: &mut ScanIndex,
    expected: u64,
) -> Result<()> {
    use super::super::terminal_contract_retry;
    use serde::de::{DeserializeSeed, MapAccess, Visitor};
    let mut cx = KindCx::default();
    let generation: u64 = read_control("generation", tx, &mut cx)?;
    let schema: u16 = read_control("schema_version", tx, &mut cx)?;
    ensure!(
        generation == expected && schema == working.schema_version,
        "state_v2_concurrent_change"
    );
    let mut custody = ScanIndex::default();
    read_holds(&mut custody, tx, &mut cx)?;
    custody.schema_version = schema;
    custody.generation = generation;
    custody.accepted_snapshot_fingerprint_ledger_version = read_field(
        "accepted_snapshot_fingerprint_ledger_version",
        "v1_field.accepted_snapshot_fingerprint_ledger_version",
        tx,
        &mut cx,
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

impl KindCx {
    pub(super) fn plan_delta(
        &mut self,
        fields: impl IntoIterator<Item = impl Into<String>>,
    ) -> Result<()> {
        let fields: BTreeSet<String> = fields.into_iter().map(Into::into).collect();
        for field in &fields {
            ensure!(
                CONTROLS.contains(&field.as_str())
                    || field == "decode_holds"
                    || field_kind(field).is_some(),
                "state_v2_misc_unknown_dirty_field"
            );
        }
        self.dirty_fields = Some(fields);
        Ok(())
    }
}
/// Complete field plan derived from the two owner graphs. Hashing is streamed
/// with fixed scratch; no JSON history copy or payload read is used to decide
/// which of the MISC fields the selected graph actually changed.
pub(super) fn dirty_fields(prev: &ScanIndex, next: &ScanIndex) -> Result<BTreeSet<String>> {
    fn commitment(value: &impl Serialize) -> Result<[u8; 32]> {
        use sha2::Digest;
        Ok(
            super::super::serialized_json_digest(value, b"ottto.state-v2.misc-dirty.v1\0")
                .context("state_v2_misc_serialize")?
                .finalize()
                .into(),
        )
    }
    let mut dirty = BTreeSet::new();
    macro_rules! compare {
        (claude_desktop_store_inventory, $kind:literal) => {};
        ($field:ident, $kind:literal) => {
            if commitment(&prev.$field)? != commitment(&next.$field)? {
                dirty.insert(stringify!($field).to_owned());
            }
        };
    }
    fields!(compare);
    if prev.schema_version != next.schema_version {
        dirty.insert("schema_version".into());
    }
    if !prev.decode_holds.same_as(&next.decode_holds)
        || prev.decode_holds.v2_provenance() != next.decode_holds.v2_provenance()
    {
        dirty.insert("decode_holds".into());
    }
    // COMMIT, rather than semantic delta, owns the single generation advance.
    Ok(dirty)
}

pub(super) fn populate(index: &ScanIndex, tx: &mut dyn Transaction, cx: &mut KindCx) -> Result<()> {
    control("schema_version", &index.schema_version, tx, cx)?;
    control("generation", &index.generation, tx, cx)?;
    macro_rules! save {
        (claude_desktop_store_inventory,$kind:literal) => {
            write_field(
                &None::<String>,
                "claude_desktop_store_inventory",
                $kind,
                tx,
                cx,
            )?;
        };
        ($field:ident,$kind:literal) => {
            write_field(&index.$field, stringify!($field), $kind, tx, cx)?;
        };
    }
    fields!(save);
    write_holds(index, tx, cx)?;
    control("field_presence", &cx.presence.clone(), tx, cx)
}
pub(super) fn hydrate_txn(
    tx: &mut dyn Transaction,
    index: &mut ScanIndex,
    cx: &mut KindCx,
) -> Result<()> {
    index.schema_version = read_control("schema_version", tx, cx)?;
    index.generation = read_control("generation", tx, cx)?;
    cx.presence = read_control("field_presence", tx, cx)?;
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
        ($field:ident,$kind:literal) => {
            index.$field = read_field(stringify!($field), $kind, tx, cx)?;
        };
    }
    fields!(load);
    read_holds(index, tx, cx)
}
pub(super) fn delta(
    _prev: &ScanIndex,
    next: &ScanIndex,
    tx: &mut dyn Transaction,
    cx: &mut KindCx,
) -> Result<()> {
    let dirty = cx
        .dirty_fields
        .take()
        .context("state_v2_misc_dirty_plan_required")?;
    macro_rules! save {
        (claude_desktop_store_inventory,$kind:literal) => {};
        ($field:ident,$kind:literal) => {
            if dirty.contains(stringify!($field)) {
                write_field(&next.$field, stringify!($field), $kind, tx, cx)?;
            }
        };
    }
    fields!(save);
    if dirty.contains("schema_version") {
        control("schema_version", &next.schema_version, tx, cx)?;
    }
    if dirty.contains("generation") {
        control("generation", &next.generation, tx, cx)?;
    }
    if dirty.contains("decode_holds") {
        let old: BTreeSet<_> = cx
            .misc_rows
            .keys()
            .filter(|k| matches!(k,RowKey::Record{kind,..} if kind.name().starts_with("raw_hold.")))
            .cloned()
            .collect();
        for k in &old {
            cx.misc_rows.remove(k);
        }
        write_holds(next, tx, cx)?;
        for k in old {
            if !cx.misc_rows.contains_key(&k) {
                tx.delete(&k)?;
            }
        }
    }
    control("field_presence", &cx.presence.clone(), tx, cx)
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

pub(super) fn inventory_field<'de, A: serde::de::MapAccess<'de>>(
    field: &str,
    map: &mut A,
    model: &ScanIndex,
) -> std::result::Result<bool, A::Error> {
    macro_rules! check {
        ($field:ident,$kind:literal) => {
            if field == stringify!($field) {
                codec::check_field(map, &model.$field)?;
                return Ok(true);
            }
        };
    }
    fields!(check);
    match field {
        "schema_version" => codec::check_field(map, &model.schema_version)?,
        "generation" => codec::check_field(map, &model.generation)?,
        _ => return Ok(false),
    }
    Ok(true)
}
