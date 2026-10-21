//! A few context-size points per current session for the Mac app's Sessions
//! graph. Local only: the points ride `ActiveSession` in the daemon's
//! 15-minute active-session list and are never uploaded (the `SnapshotItem`
//! field is `serde(skip)`).
//!
//! Points come from the same requests as first/peak/last, so the first point
//! is the session's first request and no point exceeds the peak. The last
//! point is the latest request with two rare exceptions: while only the pinned
//! first point exists, a later request in that same second adds no point, and
//! a latest request without a parseable timestamp is never a point. The rule
//! depends only on input order, so a tail pass that continues the retained
//! state yields the same points as a full read:
//! - zero-size requests and requests without a usable timestamp are skipped;
//! - the first point is pinned;
//! - points are unique by time (whole seconds): a request in the tail point's
//!   second replaces the tail, except the pinned first point, which keeps its
//!   second (a later request in that same second adds no point);
//! - inside one 15-minute wall-clock slot the tail point is overwritten by the
//!   newer request unless the change is big (`max(20%, 20K)` tokens), so each
//!   slot keeps its last request, subject to the pinned-first exception above;
//! - on overflow past 64 points, every other middle point is dropped, keeping
//!   the first and the last, so the whole session span stays visible.

use time::{format_description::well_known::Rfc3339, OffsetDateTime};

pub(crate) const LOCAL_CONTEXT_POINT_CAP: usize = 64;
const LOCAL_CONTEXT_POINT_SLOT_SECONDS: u32 = 15 * 60;
const LOCAL_CONTEXT_POINT_BIG_CHANGE_TOKENS: u32 = 20_000;
/// Only items whose last activity is this recent carry points, so a long
/// first pass over old transcripts holds no point lists.
const LOCAL_CONTEXT_POINT_RECENT_SECONDS: i64 = 75 * 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct LocalContextPoint {
    pub(crate) at_unix_seconds: u32,
    pub(crate) prompt_tokens: u32,
}

impl crate::heap_layout_bound::HeapLayoutBound for LocalContextPoint {
    const INLINE_ONLY: bool = true;
    const STABLE_HEAP: bool = true;
    fn heap_bound(&self, c: &mut crate::heap_layout_bound::Counter) -> Option<()> {
        c.add(0)
    }
}

/// Per-accumulator point list, at most `LOCAL_CONTEXT_POINT_CAP` entries of
/// 8 bytes each.
#[derive(Debug, Clone, Default)]
pub(super) struct LocalContextPoints {
    points: Vec<LocalContextPoint>,
}

impl LocalContextPoints {
    pub(super) fn push(&mut self, at: Option<&str>, prompt_tokens: u64) {
        if prompt_tokens == 0 {
            return;
        }
        let Some(at_unix_seconds) = at
            .and_then(|at| OffsetDateTime::parse(at, &Rfc3339).ok())
            .and_then(|at| u32::try_from(at.unix_timestamp()).ok())
        else {
            return;
        };
        let prompt_tokens = u32::try_from(prompt_tokens).unwrap_or(u32::MAX);
        let has_pinned_first_and_tail = self.points.len() >= 2;
        let Some(tail) = self.points.last_mut() else {
            self.points.push(LocalContextPoint {
                at_unix_seconds,
                prompt_tokens,
            });
            return;
        };
        // Out-of-order lines never draw backwards.
        let at_unix_seconds = at_unix_seconds.max(tail.at_unix_seconds);
        let same_second = at_unix_seconds == tail.at_unix_seconds;
        if same_second && !has_pinned_first_and_tail {
            return;
        }
        let same_slot = at_unix_seconds / LOCAL_CONTEXT_POINT_SLOT_SECONDS
            == tail.at_unix_seconds / LOCAL_CONTEXT_POINT_SLOT_SECONDS;
        let big_change = tail.prompt_tokens.abs_diff(prompt_tokens)
            >= (tail.prompt_tokens / 5).max(LOCAL_CONTEXT_POINT_BIG_CHANGE_TOKENS);
        let point = LocalContextPoint {
            at_unix_seconds,
            prompt_tokens,
        };
        if same_second || (has_pinned_first_and_tail && same_slot && !big_change) {
            *tail = point;
            return;
        }
        if self.points.len() == LOCAL_CONTEXT_POINT_CAP {
            self.halve_before_push();
        }
        if self.points.len() == self.points.capacity() {
            // Double, but never past the cap: a retained tail state is a clone
            // whose capacity equals its length, so plain doubling could
            // overshoot 64 and `retain` would never give it back.
            let target = (self.points.capacity() * 2).clamp(4, LOCAL_CONTEXT_POINT_CAP);
            self.points.reserve_exact(target - self.points.len());
        }
        self.points.push(point);
    }

    /// Halves a full list before the new point lands, so the `Vec` never grows
    /// past the cap (capacity stays at 64 x 8 bytes). The result equals
    /// pushing first and then keeping the first, the last and the even indices
    /// of the 65: the new point is the even last index, and the old tail sits
    /// at an odd index, so only the even indices of the current 64 stay.
    fn halve_before_push(&mut self) {
        let mut index = 0;
        self.points.retain(|_| {
            let keep = index % 2 == 0;
            index += 1;
            keep
        });
    }

    /// The points, when the session's last activity is recent at `now`;
    /// otherwise none.
    pub(super) fn into_recent(
        self,
        last_activity_at: Option<&str>,
        now: &str,
    ) -> Vec<LocalContextPoint> {
        let recent = last_activity_at
            .and_then(|last| OffsetDateTime::parse(last, &Rfc3339).ok())
            .zip(OffsetDateTime::parse(now, &Rfc3339).ok())
            .is_some_and(|(last, now)| {
                (now - last).whole_seconds() <= LOCAL_CONTEXT_POINT_RECENT_SECONDS
            });
        if recent {
            self.points
        } else {
            Vec::new()
        }
    }
}

impl crate::heap_layout_bound::HeapLayoutBound for LocalContextPoints {
    const STABLE_HEAP: bool = true;
    fn heap_bound(&self, c: &mut crate::heap_layout_bound::Counter) -> Option<()> {
        c.add(
            self.points
                .capacity()
                .checked_mul(std::mem::size_of::<LocalContextPoint>())?,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: u32 = 1_792_576_800; // 2026-10-21T10:00:00Z, a slot start.

    fn at(seconds: u32) -> String {
        OffsetDateTime::from_unix_timestamp(i64::from(seconds))
            .unwrap()
            .format(&Rfc3339)
            .unwrap()
    }

    fn points(input: &[(u32, u64)]) -> Vec<(u32, u32)> {
        let mut points = LocalContextPoints::default();
        for (offset, tokens) in input {
            points.push(Some(&at(BASE + offset)), *tokens);
        }
        points
            .points
            .iter()
            .map(|point| (point.at_unix_seconds - BASE, point.prompt_tokens))
            .collect()
    }

    #[test]
    fn point_is_eight_bytes() {
        assert_eq!(std::mem::size_of::<LocalContextPoint>(), 8);
        assert_eq!(BASE % LOCAL_CONTEXT_POINT_SLOT_SECONDS, 0);
    }

    #[test]
    fn first_is_pinned_and_each_slot_keeps_its_last_request() {
        assert_eq!(
            points(&[
                (0, 50_000),
                (60, 51_000),
                (120, 52_000),
                (300, 53_000),
                (900, 54_000),
                (1_000, 55_000),
            ]),
            [(0, 50_000), (300, 53_000), (1_000, 55_000)]
        );
    }

    #[test]
    fn big_changes_append_inside_a_slot() {
        // 20K is the floor for small contexts; 20% of 200K is 40K, so the
        // 30K step to 170K overwrites the tail and the 50K drop appends.
        assert_eq!(
            points(&[
                (0, 10_000),
                (10, 11_000),
                (20, 31_000),
                (30, 200_000),
                (40, 170_000),
                (50, 120_000),
            ]),
            [
                (0, 10_000),
                (10, 11_000),
                (20, 31_000),
                (40, 170_000),
                (50, 120_000)
            ]
        );
    }

    #[test]
    fn zero_sizes_and_bad_timestamps_are_skipped() {
        let mut points = LocalContextPoints::default();
        points.push(Some(&at(BASE)), 0);
        points.push(None, 10_000);
        points.push(Some("not a time"), 10_000);
        points.push(Some("1969-12-31T23:59:59Z"), 10_000);
        assert!(points.points.is_empty());
        points.push(Some(&at(BASE)), u64::from(u32::MAX) + 1);
        assert_eq!(points.points[0].prompt_tokens, u32::MAX);
    }

    #[test]
    fn out_of_order_times_clamp_to_the_tail() {
        assert_eq!(
            points(&[(1_000, 10_000), (2_000, 100_000), (100, 300_000)]),
            [(1_000, 10_000), (2_000, 300_000)]
        );
    }

    #[test]
    fn points_stay_unique_by_second() {
        // A replay of the first request and a big change in the first's
        // second add nothing; a big change in the tail's second replaces it.
        assert_eq!(
            points(&[
                (0, 10_000),
                (0, 10_000),
                (0, 90_000),
                (2_000, 20_000),
                (2_000, 200_000),
            ]),
            [(0, 10_000), (2_000, 200_000)]
        );
        let mut points = LocalContextPoints::default();
        points.push(Some("2026-10-21T10:00:00.100Z"), 10_000);
        points.push(Some("2026-10-21T10:00:00.900Z"), 90_000);
        points.push(Some("2026-10-21T10:20:00.100Z"), 20_000);
        points.push(Some("2026-10-21T10:20:00.900Z"), 200_000);
        assert_eq!(
            points
                .points
                .iter()
                .map(|point| (point.at_unix_seconds - BASE, point.prompt_tokens))
                .collect::<Vec<_>>(),
            [(0, 10_000), (1_200, 200_000)]
        );
    }

    #[test]
    fn overflow_halves_and_keeps_first_and_last() {
        // One point per slot: every request appends.
        let input = (0..200)
            .map(|slot| {
                (
                    slot * LOCAL_CONTEXT_POINT_SLOT_SECONDS,
                    1_000 + u64::from(slot),
                )
            })
            .collect::<Vec<_>>();
        // The 65th point leaves the first, the even indices and the new last.
        let first_overflow = points(&input[..=LOCAL_CONTEXT_POINT_CAP]);
        assert_eq!(first_overflow.len(), LOCAL_CONTEXT_POINT_CAP / 2 + 1);
        assert_eq!(
            first_overflow,
            input[..=LOCAL_CONTEXT_POINT_CAP]
                .iter()
                .step_by(2)
                .map(|(offset, tokens)| (*offset, u32::try_from(*tokens).unwrap()))
                .collect::<Vec<_>>()
        );
        let mut seen_max = 0;
        let mut seen_max_capacity = 0;
        let mut points = LocalContextPoints::default();
        for (offset, tokens) in &input {
            points.push(Some(&at(BASE + offset)), *tokens);
            seen_max = seen_max.max(points.points.len());
            seen_max_capacity = seen_max_capacity.max(points.points.capacity());
        }
        assert_eq!(seen_max, LOCAL_CONTEXT_POINT_CAP);
        // The list never reallocates past the cap.
        assert!(seen_max_capacity <= LOCAL_CONTEXT_POINT_CAP);
        assert_eq!(points.points.first().unwrap().prompt_tokens, 1_000);
        assert_eq!(points.points.last().unwrap().prompt_tokens, 1_199);
        assert!(points
            .points
            .windows(2)
            .all(|pair| pair[0].at_unix_seconds < pair[1].at_unix_seconds));

        // A tail pass resumes from a clone (capacity == length) and still
        // never grows past the cap.
        for retained in [5, 33, 40, 63] {
            let mut original = LocalContextPoints::default();
            for (offset, tokens) in &input[..retained] {
                original.push(Some(&at(BASE + offset)), *tokens);
            }
            let mut resumed = original.clone();
            for (offset, tokens) in &input[retained..] {
                resumed.push(Some(&at(BASE + offset)), *tokens);
                assert!(
                    resumed.points.capacity() <= LOCAL_CONTEXT_POINT_CAP,
                    "{retained}"
                );
            }
            assert_eq!(resumed.points, points.points, "{retained}");
        }
    }

    #[test]
    fn points_leave_with_the_recent_window() {
        let mut points = LocalContextPoints::default();
        points.push(Some(&at(BASE)), 10_000);
        let last = at(BASE);
        assert_eq!(
            points
                .clone()
                .into_recent(Some(&last), &at(BASE + 75 * 60))
                .len(),
            1
        );
        assert!(points
            .clone()
            .into_recent(Some(&last), &at(BASE + 75 * 60 + 1))
            .is_empty());
        assert!(points.into_recent(None, &at(BASE)).is_empty());
    }
}
