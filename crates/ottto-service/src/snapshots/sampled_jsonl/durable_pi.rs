//! Pi's durable body: the shared reduction with its ledger moved out,
//! `Rederive`, then a plain trailing `PiSection`. A_P binds its field shape.
//! Ledger keys and occurrence digests are H; the fork header time is local L.
//! `parentSession` is never persisted.
use super::*;

/// Response-id keys, not occurrences. Oversized ledgers refuse, never truncate.
pub(crate) const PI_LEDGER_MAX_KEYS: usize = 65_536;

struct PiSection {
    usage_keys: BTreeMap<String, PiUsageDedupState>,
    has_parent: bool,
    header_nanos: Option<i128>,
}
crate::durable_tail_codec::durable_struct!(borrowed PiSection {
    H usage_keys: BTreeMap<String, PiUsageDedupState>,
    N has_parent: bool,
    L header_nanos: Option<i128>,
});

/// What `A_P` adds after the shared shapes.
pub(super) fn shape_extension(shape: &mut Shape) {
    shape.push("ottto-dt-ext:pi-ledger:v1");
    PiSection::shape(shape);
}

/// The Pi body from the borrowed live parts, in `CachedJsonlReduction` field
/// order. The ledger leaves the shared body as the moved `E` field and is
/// written once, into the section, without a clone.
pub(in crate::snapshots) fn put_body(
    e: &mut Enc,
    acc: &SnapshotAccumulator,
    report: &JsonlReadReport,
    scalars: (usize, usize, bool),
    rederive: &Rederive,
) -> Result<(), Refuse> {
    if acc.source != SnapshotSource::Pi {
        return Err(Refuse::NotRederivable("SnapshotAccumulator.source"));
    }
    let keys = acc.seen_pi_usage_keys.usage_keys();
    let (has_parent, header_nanos) = acc.seen_pi_usage_keys.fork_parts();
    if keys.len() > PI_LEDGER_MAX_KEYS {
        return Err(Refuse::TooLarge);
    }
    e.with_moved_field("SnapshotAccumulator.seen_pi_usage_keys", |e| {
        CachedJsonlReduction::put_borrowed(e, acc, report, &scalars.0, &scalars.1, &scalars.2)
    })?;
    rederive.put(e)?;
    PiSection::put_borrowed(e, keys, &has_parent, &header_nanos)
}

/// Structural verification of a Pi body, without allocation. The registry row's
/// walk; the table admits only format 3.
pub(crate) fn verify_body(d: &mut Dec<'_>) -> Result<(), Corrupt> {
    CachedJsonlReduction::verify(d)?;
    Rederive::verify(d)?;
    crate::durable_tail_codec::verify_h_map::<String, PiUsageDedupState>(d, PI_LEDGER_MAX_KEYS)?;
    let has_parent = bool::take(d)?;
    let header_nanos = <Option<i128> as Durable>::take(d)?;
    valid_fork_fields(has_parent, header_nanos)?;
    d.finish()
}

/// Decodes a Pi body. The ledger refills the accumulator before the end check,
/// so absent fields, truncation and trailing bytes are corrupt.
pub(crate) fn take_body(d: &mut Dec<'_>) -> Result<Decoded, Corrupt> {
    let mut reduction = CachedJsonlReduction::take(d)?;
    let rederive = Rederive::take(d)?;
    if reduction.accumulator.source != SnapshotSource::Pi {
        return Err(Corrupt);
    }
    reduction.accumulator.seen_pi_usage_keys = take_ledger(d)?;
    d.finish()?;
    Ok(Decoded {
        reduction,
        rederive,
    })
}

fn take_ledger(d: &mut Dec<'_>) -> Result<PiLedger, Corrupt> {
    let usage_keys = crate::durable_tail_codec::take_h_map(d, PI_LEDGER_MAX_KEYS)?;
    let has_parent = bool::take(d)?;
    let header_nanos = <Option<i128> as Durable>::take(d)?;
    valid_fork_fields(has_parent, header_nanos)?;
    if has_parent {
        // Fund the RAM-only wrapper before allocating it.
        d.slots::<PiFork>(1)?;
    }
    Ok(PiLedger::from_parts(usage_keys, has_parent, header_nanos))
}

fn valid_fork_fields(has_parent: bool, header_nanos: Option<i128>) -> Result<(), Corrupt> {
    (has_parent || header_nanos.is_none())
        .then_some(())
        .ok_or(Corrupt)
}

#[cfg(test)]
#[path = "durable_pi_tests.rs"]
mod tests;
