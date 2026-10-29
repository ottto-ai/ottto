//! Pi's durable record body: the shared reduction with the usage ledger moved
//! out, `Rederive`, then one ledger section,
//! `varint 1 ‖ u64 LE length ‖ PiSection`. The section is body-internal: it
//! has no envelope field and no format number. `A_P` binds it through the
//! `ottto-dt-ext:pi-ledger:v1` domain and `PiSection`'s shape. Ledger keys and
//! occurrence digests are SOURCE option A `H` values (64-char lower hex).
use super::*;

/// Response-id keys, not occurrences. Oversized ledgers refuse, never truncate.
pub(crate) const PI_LEDGER_MAX_KEYS: usize = 65_536;

/// The codec refusal class of a ledger over `PI_LEDGER_MAX_KEYS`.
pub(crate) const PI_LEDGER_CAP: &str = "pi_ledger_cap";

const SECTION_TAG: u64 = 1;

struct PiSection {
    usage_keys: BTreeMap<String, PiUsageDedupState>,
}
crate::durable_tail_codec::durable_struct!(borrowed PiSection {
    H usage_keys: BTreeMap<String, PiUsageDedupState>,
});

/// What `A_P` adds after the shared shapes.
pub(super) fn shape_extension(shape: &mut Shape) {
    shape.push("ottto-dt-ext:pi-ledger:v1");
    PiSection::shape(shape);
}

// E5-PI-B2-SEAM: format-3 codec table, `(3, 3) => A_P` encode row (P4a
// `encode_parts`, inside `Enc::count_write`).
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
    let keys = &acc.seen_pi_usage_keys;
    if keys.len() > PI_LEDGER_MAX_KEYS {
        // Not an E field: only this static class leaves the codec.
        return Err(Refuse::NonEmpty(PI_LEDGER_CAP));
    }
    e.with_pi_ledger(|e| {
        acc.put(e)?;
        report.put(e)?;
        scalars.0.put(e)?;
        scalars.1.put(e)?;
        scalars.2.put(e)
    })?;
    rederive.put(e)?;
    e.section(SECTION_TAG, |e| PiSection::put_borrowed(e, keys))
}

// E5-PI-B2-SEAM: format-3 codec table, `(3, 3) => A_P` verify row (P4a, on the
// header-dispatched source).
/// Structural verification of a Pi body, without allocation.
pub(crate) fn verify_body(d: &mut Dec<'_>) -> Result<(), Corrupt> {
    d.require_section();
    CachedJsonlReduction::verify(d)?;
    Rederive::verify(d)?;
    d.section(SECTION_TAG, |d| {
        ledger_bound(d)?;
        PiSection::verify(d)
    })?;
    d.refilled_section();
    d.ended()
}

// E5-PI-B2-SEAM: format-3 codec table, `(3, 3) => A_P` decode row (P4a, on the
// header-dispatched source; the caller passes 5c1a0b's bounded `Dec` and maps
// `Dec::outcome`).
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

fn take_ledger(d: &mut Dec<'_>) -> Result<BTreeMap<String, PiUsageDedupState>, Corrupt> {
    d.section(SECTION_TAG, |d| {
        ledger_bound(d)?;
        Ok(PiSection::take(d)?.usage_keys)
    })
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
