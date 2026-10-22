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
/// Requests ordered per pass when the fold's owned requests are not already
/// in sequence order (Claude Code's request-id map): about 6 KB of scratch.
pub(super) const LOCAL_CONTEXT_POINT_ORDER_WINDOW: usize = 256;

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
        if local_context_points_recent(last_activity_at, now) {
            self.points
        } else {
            Vec::new()
        }
    }

    /// Points over owned requests given in any order, fed to `push` in
    /// `(sequence, input position)` order: exactly a stable sort by sequence,
    /// so the result equals collecting and sorting the requests, but nothing
    /// grows with the request count. Input already in sequence order (the
    /// strict fold's sorted slice) is fed in one pass. Otherwise each pass
    /// over `requests` selects the next `LOCAL_CONTEXT_POINT_ORDER_WINDOW`
    /// keys after the last one fed, so scratch is that window whatever the
    /// count, for `ceil(n / window)` cheap passes. Claude Code builds its list
    /// this way in the ownership fold from the requests behind
    /// first/peak/last. `point` returns `None` for a request that is not
    /// owned, and is called once per request.
    pub(super) fn from_requests_by_sequence<'a, T, I>(
        requests: I,
        sequence: impl Fn(T) -> u64,
        point: impl Fn(T) -> Option<(Option<&'a str>, u64)>,
    ) -> Vec<LocalContextPoint>
    where
        T: Copy,
        I: Iterator<Item = T> + Clone,
    {
        let mut points = Self::default();
        let mut feed = |request: T| {
            if let Some((at, prompt_tokens)) = point(request) {
                points.push(at, prompt_tokens);
            }
        };
        let mut previous = None;
        let in_order = requests.clone().all(|request| {
            let sequence = sequence(request);
            let in_order = !matches!(previous, Some(previous) if previous > sequence);
            previous = Some(sequence);
            in_order
        });
        if in_order {
            requests.for_each(feed);
            return points.points;
        }
        let mut window = Vec::with_capacity(LOCAL_CONTEXT_POINT_ORDER_WINDOW);
        let mut fed: Option<(u64, usize)> = None;
        loop {
            for (position, request) in requests.clone().enumerate() {
                let key = (sequence(request), position);
                if fed.is_some_and(|fed| key <= fed) {
                    continue;
                }
                if window.len() == LOCAL_CONTEXT_POINT_ORDER_WINDOW {
                    if window.last().is_some_and(|(last, _)| key > *last) {
                        continue;
                    }
                    window.pop();
                }
                let index = window.partition_point(|(kept, _)| *kept < key);
                window.insert(index, (key, request));
                debug_assert!(window.len() <= LOCAL_CONTEXT_POINT_ORDER_WINDOW);
            }
            let full = window.len() == LOCAL_CONTEXT_POINT_ORDER_WINDOW;
            fed = window.last().map(|(key, _)| *key);
            window.drain(..).for_each(|(_, request)| feed(request));
            if !full {
                return points.points;
            }
        }
    }
}

/// Whether a session whose last activity is `last_activity_at` may carry
/// points at `now` (the 75-minute output gate).
pub(super) fn local_context_points_recent(last_activity_at: Option<&str>, now: &str) -> bool {
    last_activity_at
        .and_then(|last| OffsetDateTime::parse(last, &Rfc3339).ok())
        .zip(OffsetDateTime::parse(now, &Rfc3339).ok())
        .is_some_and(|(last, now)| {
            (now - last).whole_seconds() <= LOCAL_CONTEXT_POINT_RECENT_SECONDS
        })
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
        assert!(local_context_points_recent(
            Some(&last),
            &at(BASE + 75 * 60)
        ));
        assert!(!local_context_points_recent(
            Some(&last),
            &at(BASE + 75 * 60 + 1)
        ));
    }

    #[test]
    fn requests_by_sequence_follow_the_same_rule_and_cap() {
        // One request per minute for five hours, big steps every 7 minutes;
        // every third is not owned, and two share a sequence (input order
        // breaks the tie, like the stable sort).
        let requests = (0..300_u32)
            .map(|minute| {
                let tokens: u64 = if minute % 7 == 0 { 400_000 } else { 50_000 };
                (
                    u64::from(minute),
                    at(BASE + minute * 60),
                    tokens,
                    minute % 3 != 1,
                )
            })
            .chain([
                (300, String::from("not a time"), 9, true),
                (301, at(BASE + 300 * 60), 0, true),
                (299, at(BASE + 299 * 60 + 5), 70_000, true),
            ])
            .collect::<Vec<_>>();
        // Oracle: collect, stable-sort by sequence, push the owned ones.
        let oracle = |requests: &[&(u64, String, u64, bool)]| {
            let mut sorted = requests.to_vec();
            sorted.sort_by_key(|(sequence, ..)| *sequence);
            let mut pushed = LocalContextPoints::default();
            for (_, at, tokens, _) in sorted.iter().filter(|(.., own)| *own) {
                pushed.push(Some(at), *tokens);
            }
            pushed.points
        };
        let build = |requests: &[&(u64, String, u64, bool)]| {
            LocalContextPoints::from_requests_by_sequence(
                requests.iter().copied(),
                |(sequence, ..)| *sequence,
                |(_, at, tokens, own)| own.then_some((Some(at.as_str()), *tokens)),
            )
        };
        // In order (one pass), and shuffled (two windows of 256).
        let mut sorted = requests.iter().collect::<Vec<_>>();
        sorted.sort_by_key(|(sequence, ..)| *sequence);
        let in_order = build(&sorted);
        assert_eq!(in_order, oracle(&sorted));
        assert_eq!(
            in_order.last().unwrap().at_unix_seconds,
            BASE + 299 * 60 + 5
        );
        assert_eq!(in_order.last().unwrap().prompt_tokens, 70_000);
        let mut shuffled = requests.iter().collect::<Vec<_>>();
        shuffled.reverse();
        shuffled.rotate_left(97);
        let shuffled = build(&shuffled);
        assert_ne!(shuffled, in_order, "the tie follows input order");
        assert_eq!(
            shuffled,
            oracle(&{
                let mut input = requests.iter().collect::<Vec<_>>();
                input.reverse();
                input.rotate_left(97);
                input
            })
        );
        assert!(shuffled.len() <= LOCAL_CONTEXT_POINT_CAP);
        assert!(shuffled.capacity() <= LOCAL_CONTEXT_POINT_CAP);
        assert_eq!(shuffled.first().unwrap().at_unix_seconds, BASE);
    }
}
