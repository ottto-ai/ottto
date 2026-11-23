//! The collection window a cycle asks the provider for, and the packing of
//! normalized rows into contract-legal batches.

use super::wire::DailyReferenceRow;
use super::{LOOKBACK_DAYS, MAX_COVERAGE_DAYS, MAX_ROWS_PER_BATCH};
use anyhow::{anyhow, Result};
use std::collections::BTreeMap;
use time::{Duration as TimeDuration, OffsetDateTime};

// ---------------------------------------------------------------------------
// Windows and batching
// ---------------------------------------------------------------------------

pub(super) fn date_string(value: OffsetDateTime) -> String {
    let date = value.date();
    format!(
        "{:04}-{:02}-{:02}",
        date.year(),
        u8::from(date.month()),
        date.day()
    )
}

/// The window a cycle asks the provider for.
///
/// `coverage_end` is the last *complete* UTC day: today is still accumulating,
/// so uploading it would publish a number that is knowably short.
pub fn collection_window(now: OffsetDateTime) -> (String, String) {
    let end = now.to_offset(time::UtcOffset::UTC) - TimeDuration::days(1);
    let start = end - TimeDuration::days(LOOKBACK_DAYS - 1);
    (date_string(start), date_string(end))
}

/// Split normalized rows into contract-legal batches.
///
/// Three properties matter for the backend's coverage envelope, which is one
/// contiguous span: batches go oldest first, consecutive windows **abut
/// exactly** (a closed window ends the day before the next one starts, so a
/// stretch of idle days between two observed days is still declared covered
/// rather than left as a hole), and no day is split across batches. A window
/// that neither overlaps nor abuts the stored envelope would *replace* it, so a
/// hole here would silently discard already-uploaded coverage.
///
/// A single day that alone exceeds the row bound is refused rather than
/// truncated: a silently partial day is a manufactured delta.
pub(super) fn pack_batches(
    rows: Vec<DailyReferenceRow>,
    window_start: &str,
    window_end: &str,
) -> Result<Vec<(String, String, Vec<DailyReferenceRow>)>> {
    if rows.is_empty() {
        // A genuinely idle account still declares the window it observed.
        return Ok(vec![(
            window_start.to_string(),
            window_end.to_string(),
            Vec::new(),
        )]);
    }
    let mut by_day: BTreeMap<String, Vec<DailyReferenceRow>> = BTreeMap::new();
    for row in rows {
        by_day
            .entry(row.provider_day.clone())
            .or_default()
            .push(row);
    }
    if let Some((day, group)) = by_day
        .iter()
        .find(|(_, group)| group.len() > MAX_ROWS_PER_BATCH)
    {
        return Err(anyhow!(
            "provider day {day} normalized to {} rows, beyond the {MAX_ROWS_PER_BATCH} row bound",
            group.len()
        ));
    }

    let mut batches = Vec::new();
    let mut current: Vec<DailyReferenceRow> = Vec::new();
    // The first batch owns the declared window start, so no day Ottto asked
    // about sits outside the envelope it claims to have covered.
    let mut start = window_start.to_string();

    for (day, group) in by_day {
        let overflow_rows = !current.is_empty() && current.len() + group.len() > MAX_ROWS_PER_BATCH;
        // Measured from the declared start, not the first observed day, because
        // the declared window is what the bound applies to.
        let overflow_days = !current.is_empty()
            && !matches!(day_span(&start, &day), Some(span) if span <= MAX_COVERAGE_DAYS);
        if overflow_rows || overflow_days {
            let end = day_before(&day).ok_or_else(|| {
                anyhow!("could not close a coverage window immediately before {day}")
            })?;
            batches.push((start, end, std::mem::take(&mut current)));
            start = day.clone();
        }
        current.extend(group);
    }
    batches.push((start, window_end.to_string(), current));
    Ok(batches)
}

pub(super) fn parse_day(value: &str) -> Option<time::Date> {
    let year: i32 = value.get(0..4)?.parse().ok()?;
    let month: u8 = value.get(5..7)?.parse().ok()?;
    let day: u8 = value.get(8..10)?.parse().ok()?;
    time::Date::from_calendar_date(year, time::Month::try_from(month).ok()?, day).ok()
}

/// Inclusive day span between two `YYYY-MM-DD` days, or `None` when either is
/// not a real calendar day.
pub(super) fn day_span(start: &str, end: &str) -> Option<i64> {
    Some((parse_day(end)? - parse_day(start)?).whole_days() + 1)
}

fn day_before(value: &str) -> Option<String> {
    parse_day(value)?.previous_day().map(|date| {
        format!(
            "{:04}-{:02}-{:02}",
            date.year(),
            u8::from(date.month()),
            date.day()
        )
    })
}
