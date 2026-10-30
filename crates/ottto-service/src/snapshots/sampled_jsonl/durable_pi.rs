//! Pi's durable record body: the shared reduction with the usage ledger moved
//! out, `Rederive`, then one ledger section,
//! `varint 1 ‖ u64 LE length ‖ PiSection`. The section is body-internal: it
//! has no envelope field and no format number. `A_P` binds it through the
//! `ottto-dt-ext:pi-ledger:v1` domain and `PiSection`'s shape. Ledger keys and
//! occurrence digests are SOURCE option A `H` values (64-char lower hex).
//! M-2 adds the fork state's two `N` values: `has_parent` and the header
//! time. `parentSession` itself is never persisted.
use super::*;

/// Response-id keys, not occurrences. Oversized ledgers refuse, never truncate.
pub(crate) const PI_LEDGER_MAX_KEYS: usize = 65_536;

const SECTION_TAG: u64 = 1;

struct PiSection {
    usage_keys: BTreeMap<String, PiUsageDedupState>,
    has_parent: bool,
    header_nanos: Option<i128>,
}
crate::durable_tail_codec::durable_struct!(borrowed PiSection {
    H usage_keys: BTreeMap<String, PiUsageDedupState>,
    N has_parent: bool,
    N header_nanos: Option<i128>,
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
        acc.put(e)?;
        report.put(e)?;
        scalars.0.put(e)?;
        scalars.1.put(e)?;
        scalars.2.put(e)
    })?;
    rederive.put(e)?;
    e.section(SECTION_TAG, |e| {
        PiSection::put_borrowed(e, keys, &has_parent, &header_nanos)
    })
}

/// Header-dispatched Pi verification row; the table admits only format 3.
pub(in crate::snapshots) fn verify(body: &[u8]) -> Result<(), Corrupt> {
    verify_body(&mut Dec::new(body))
}

/// Structural verification of a Pi body, without allocation.
pub(crate) fn verify_body(d: &mut Dec<'_>) -> Result<(), Corrupt> {
    d.require_section();
    CachedJsonlReduction::verify(d)?;
    Rederive::verify(d)?;
    d.section(SECTION_TAG, |d| {
        ledger_bound(d)?;
        <BTreeMap<String, PiUsageDedupState> as crate::durable_tail_codec::HDigest>::verify_h(d)?;
        let has_parent = bool::take(d)?;
        let header_nanos = Option::<i128>::take(d)?;
        valid_fork_fields(has_parent, header_nanos)
    })?;
    d.refilled_section();
    d.ended()
}

/// Decodes a Pi body. The ledger refills the accumulator before the end check,
/// so a section that is absent, short, long or not refilled is corrupt.
pub(crate) fn take_body(d: &mut Dec<'_>) -> Result<Decoded, Corrupt> {
    d.require_section();
    let mut reduction = CachedJsonlReduction::take(d)?;
    let rederive = Rederive::take(d)?;
    if reduction.accumulator.source != SnapshotSource::Pi {
        return Err(Corrupt);
    }
    reduction.accumulator.seen_pi_usage_keys = take_ledger(d)?;
    d.refilled_section();
    d.ended()?;
    Ok(Decoded {
        reduction,
        rederive,
    })
}

fn take_ledger(d: &mut Dec<'_>) -> Result<PiLedger, Corrupt> {
    d.section(SECTION_TAG, |d| {
        ledger_bound(d)?;
        let section = PiSection::take(d)?;
        // Only the writer's two shapes: no parent and no time, or a parent.
        valid_fork_fields(section.has_parent, section.header_nanos)?;
        if section.has_parent {
            // Charge the complete Box before allocating it, including its
            // empty RAM-only fields, through the shared bounded decoder.
            d.slots::<PiFork>(1)?;
        }
        Ok(PiLedger::from_parts(
            section.usage_keys,
            section.has_parent,
            section.header_nanos,
        ))
    })
}

fn valid_fork_fields(has_parent: bool, header_nanos: Option<i128>) -> Result<(), Corrupt> {
    (has_parent || header_nanos.is_none())
        .then_some(())
        .ok_or(Corrupt)
}

/// The key count, checked before the ledger allocates or charges anything.
fn ledger_bound(d: &Dec<'_>) -> Result<(), Corrupt> {
    (d.peek_len()? <= PI_LEDGER_MAX_KEYS)
        .then_some(())
        .ok_or(Corrupt)
}

#[cfg(test)]
#[path = "durable_pi_tests.rs"]
mod tests;
