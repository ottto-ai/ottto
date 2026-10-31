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

use std::{cmp::Ordering, collections::BinaryHeap};

use time::{format_description::well_known::Rfc3339, OffsetDateTime};

pub(crate) const LOCAL_CONTEXT_POINT_CAP: usize = 64;
const LOCAL_CONTEXT_POINT_SLOT_SECONDS: u32 = 15 * 60;
const LOCAL_CONTEXT_POINT_BIG_CHANGE_TOKENS: u32 = 20_000;
/// Only items whose last activity is this recent carry points, so a long
/// first pass over old transcripts holds no point lists.
const LOCAL_CONTEXT_POINT_RECENT_SECONDS: i64 = 75 * 60;
/// Requests ordered per pass when the fold's owned requests are not already
/// in sequence order (Claude Code's request-id map): 96 KiB of scratch for
/// reference entries on 64-bit targets. Fold transients have no heap charge
/// site; this allocation is fixed, and retained points are charged below.
pub(super) const LOCAL_CONTEXT_POINT_ORDER_WINDOW: usize = 4096;
pub(super) const LOCAL_CONTEXT_POINT_ORDER_PASSES: usize = 8;

// Payloads need not be ordered. Including position makes every key unique,
// so unstable sorting preserves the old stable sequence-sort tie order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PointOrderKey(u64, usize);

impl Ord for PointOrderKey {
    fn cmp(&self, other: &Self) -> Ordering {
        #[cfg(test)]
        POINT_ORDER_WORK.with(|work| {
            let mut work = work.borrow_mut();
            work.comparisons += 1;
        });
        (self.0, self.1).cmp(&(other.0, other.1))
    }
}

impl PartialOrd for PointOrderKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

struct PointOrderEntry<T> {
    key: PointOrderKey,
    request: T,
}

impl<T> PartialEq for PointOrderEntry<T> {
    fn eq(&self, other: &Self) -> bool {
        self.key == other.key
    }
}

impl<T> Eq for PointOrderEntry<T> {}

impl<T> Ord for PointOrderEntry<T> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.key.cmp(&other.key)
    }
}

impl<T> PartialOrd for PointOrderEntry<T> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[cfg(test)]
#[derive(Default, Clone, Copy)]
struct PointOrderWork {
    comparisons: usize,
    max_update_comparisons: usize,
    max_update_tuple_writes_bound: usize,
    updates: usize,
}

#[cfg(test)]
thread_local! {
    static POINT_ORDER_WORK: std::cell::RefCell<PointOrderWork> =
        std::cell::RefCell::new(PointOrderWork::default());
}

#[cfg(test)]
fn note_point_heap_update(start: usize) {
    POINT_ORDER_WORK.with(|work| {
        let mut work = work.borrow_mut();
        let comparisons = work.comparisons - start;
        work.max_update_comparisons = work.max_update_comparisons.max(comparisons);
        // BinaryHeap push/PeekMut drop use one sift path: each Hole::move_to
        // has a preceding comparison. Add root assignment and hole write-back.
        // Rust moves have no user hook; this is a structural upper bound on
        // tuple writes, not a claim to instrument raw memory copies.
        work.max_update_tuple_writes_bound =
            work.max_update_tuple_writes_bound.max(comparisons + 2);
        work.updates += 1;
    });
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct LocalContextPoint {
    pub(crate) at_unix_seconds: u32,
    pub(crate) prompt_tokens: u32,
}
crate::durable_tail_codec::durable_struct!(LocalContextPoint {
    N at_unix_seconds: u32,
    N prompt_tokens: u32,
});

crate::heap_layout_bound::no_heap!(true; LocalContextPoint);

/// Per-accumulator point list, at most `LOCAL_CONTEXT_POINT_CAP` entries of
/// 8 bytes each.
#[derive(Debug, Clone, Default)]
pub(super) struct LocalContextPoints {
    points: Vec<LocalContextPoint>,
}
crate::durable_tail_codec::durable_struct!(LocalContextPoints {
    N points: Vec<LocalContextPoint>,
});

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

    /// The strict fold already has sequence-ordered requests. Consume them
    /// once, with no ordering scratch or unordered-input budget.
    pub(super) fn from_ordered_requests<'a, T>(
        requests: impl Iterator<Item = T>,
        point: impl Fn(T) -> Option<(Option<&'a str>, u64)>,
    ) -> Vec<LocalContextPoint> {
        let mut points = Self::default();
        for request in requests {
            if let Some((at, prompt_tokens)) = point(request) {
                points.push(at, prompt_tokens);
            }
        }
        points.points
    }

    /// Feed unordered requests in `(sequence, input position)` order, exactly
    /// like the previous stable sort. The exact iterator length is available
    /// without visiting requests. Refuse LOCAL points before any work when
    /// more than eight fixed windows would be needed: no partial curve.
    /// Otherwise visit at most `LOCAL_CONTEXT_POINT_ORDER_PASSES * n` entries
    /// with one fixed window of scratch and call `point` once per request.
    /// Selection uses O(n log W) key comparisons per pass and O(log W) tuple
    /// moves per heap update, then one in-place O(W log W) sort. No insertion
    /// shifts a window-sized suffix.
    pub(super) fn from_requests_by_sequence<'a, T, I>(
        requests: I,
        sequence: impl Fn(T) -> u64,
        point: impl Fn(T) -> Option<(Option<&'a str>, u64)>,
    ) -> Option<Vec<LocalContextPoint>>
    where
        T: Copy,
        I: ExactSizeIterator<Item = T> + Clone,
    {
        let count = requests.len();
        if count > LOCAL_CONTEXT_POINT_ORDER_WINDOW * LOCAL_CONTEXT_POINT_ORDER_PASSES {
            return None;
        }
        let mut points = Self::default();
        if count == 0 {
            return Some(points.points);
        }
        let mut window = BinaryHeap::<PointOrderEntry<T>>::new();
        window.reserve_exact(LOCAL_CONTEXT_POINT_ORDER_WINDOW);
        let mut fed: Option<PointOrderKey> = None;
        // The range is a structural work bound, independent of input order.
        // Use the exact count to avoid an extra empty pass at a full window.
        let passes = count.div_ceil(LOCAL_CONTEXT_POINT_ORDER_WINDOW);
        for _ in 0..passes {
            for (position, request) in requests.clone().enumerate() {
                let key = PointOrderKey(sequence(request), position);
                if fed.is_some_and(|fed| key <= fed) {
                    continue;
                }
                #[cfg(test)]
                let update_start = POINT_ORDER_WORK.with(|work| work.borrow().comparisons);
                let entry = PointOrderEntry { key, request };
                if window.len() < LOCAL_CONTEXT_POINT_ORDER_WINDOW {
                    // Never push at capacity: no allocation after reserve_exact.
                    window.push(entry);
                } else if let Some(mut largest) = window.peek_mut() {
                    if key < largest.key {
                        // Replacing the root sifts down one heap-height path;
                        // no pop/push pair and no linear tuple shifting.
                        *largest = entry;
                    }
                }
                // The PeekMut guard has dropped (and finished sifting).
                #[cfg(test)]
                note_point_heap_update(update_start);
                debug_assert!(window.len() <= LOCAL_CONTEXT_POINT_ORDER_WINDOW);
                debug_assert!(window.capacity() <= LOCAL_CONTEXT_POINT_ORDER_WINDOW);
            }
            fed = window.peek().map(|entry| entry.key);
            let mut selected = window.into_vec();
            selected.sort_unstable();
            for entry in selected.drain(..) {
                if let Some((at, prompt_tokens)) = point(entry.request) {
                    points.push(at, prompt_tokens);
                }
            }
            // Both conversions transfer the same allocation. The drained Vec
            // is empty, so rebuilding the heap neither compares nor moves keys.
            window = BinaryHeap::from(selected);
        }
        Some(points.points)
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
            .expect("within the work budget")
        };
        // Stable sequence order and shuffled order; ties keep input order.
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
    fn assert_heap_work_and_parity(requests: &[(u64, String, u64)]) {
        use std::cell::Cell;
        fn point(request: &(u64, String, u64)) -> Option<(Option<&str>, u64)> {
            (request.0 % 5 != 0).then_some((Some(request.1.as_str()), request.2))
        }
        let count = requests.len();
        let visits = Cell::new(0);
        POINT_ORDER_WORK.with(|work| *work.borrow_mut() = PointOrderWork::default());
        let points = LocalContextPoints::from_requests_by_sequence(
            requests.iter().inspect(|_| visits.set(visits.get() + 1)),
            |request| request.0,
            point,
        )
        .expect("within the work cap");
        let work = POINT_ORDER_WORK.with(|work| *work.borrow());
        let p = LOCAL_CONTEXT_POINT_ORDER_PASSES;
        let w = LOCAL_CONTEXT_POINT_ORDER_WINDOW;
        let l = (w - 1).ilog2() as usize + 1; // ceil(log2 W) = 12
        assert_eq!(visits.get(), count.div_ceil(w) * count);
        assert!(visits.get() <= p * count);
        // All key comparisons count: fed cutoff, root admission, heap sifts
        // and the final in-place sorts. At n=32768 this pins 3,538,944.
        let comparison_bound = p * count * l + p * w * l;
        assert!(
            work.comparisons <= comparison_bound,
            "{} comparisons exceed {comparison_bound} at n={count}",
            work.comparisons
        );
        // One update traverses at most one heap-height path. A push has at
        // most L comparisons; root comparison + sift-down at most 2L+1.
        // Every tuple write on the sift path is charged to a comparison,
        // plus root assignment and hole write-back (<=2L+3 = 27 writes).
        assert!(work.updates > 0);
        assert!(work.max_update_comparisons <= 2 * l + 1);
        assert!(work.max_update_tuple_writes_bound <= 2 * l + 3);
        let mut previous = requests.iter().collect::<Vec<_>>();
        previous.sort_by_key(|request| request.0);
        let mut oracle = LocalContextPoints::default();
        for request in previous {
            if let Some((at, tokens)) = point(request) {
                oracle.push(at, tokens);
            }
        }
        assert_eq!(points, oracle.points);
        assert!(points.len() <= LOCAL_CONTEXT_POINT_CAP);
    }

    #[test]
    fn unordered_work_is_bounded_and_matches_the_previous_stable_sort() {
        use std::cell::Cell;
        let count = LOCAL_CONTEXT_POINT_ORDER_WINDOW * LOCAL_CONTEXT_POINT_ORDER_PASSES;
        // Reverse order forces replacements throughout each full window;
        // ties still follow input position. Enough points for repeated halving.
        let requests = (0..count)
            .rev()
            .map(|index| {
                (
                    index as u64 / 2,
                    at(BASE + index as u32 * 60),
                    index as u64 * 1000,
                )
            })
            .collect::<Vec<_>>();
        assert_heap_work_and_parity(&requests);
        // Increasing keys stress sift-up during initial fill instead.
        let mut ascending = requests.clone();
        ascending.reverse();
        assert_heap_work_and_parity(&ascending);

        // Large streams refuse before traversal, comparison or partial curve.
        for count in [count + 1, 250_000] {
            let visits = Cell::new(0);
            POINT_ORDER_WORK.with(|work| *work.borrow_mut() = PointOrderWork::default());
            let refused = LocalContextPoints::from_requests_by_sequence(
                (0..count).rev().inspect(|_| visits.set(visits.get() + 1)),
                |index| index as u64,
                |_| panic!("refused inputs must not build any points"),
            );
            assert_eq!(refused, None);
            assert_eq!(visits.get(), 0);
            POINT_ORDER_WORK.with(|work| assert_eq!(work.borrow().comparisons, 0));
        }
        assert_eq!(
            LocalContextPoints::from_requests_by_sequence(
                std::iter::empty::<usize>(),
                |index| index as u64,
                |_| None,
            ),
            Some(Vec::new())
        );
    }

    #[test]
    fn heap_selection_matches_previous_points_on_seeded_random_ties() {
        let w = LOCAL_CONTEXT_POINT_ORDER_WINDOW;
        for (count, seed) in [
            (w - 1, 7_u64),
            (w + 1, 31),
            (w * LOCAL_CONTEXT_POINT_ORDER_PASSES, 97),
        ] {
            let mut requests = (0..count)
                .map(|index| {
                    (
                        index as u64 / 3,
                        at(BASE + index as u32 * 60),
                        index as u64 * 1000,
                    )
                })
                .collect::<Vec<_>>();
            // Deterministic Fisher-Yates without a new random dependency.
            let mut random = seed;
            for index in (1..count).rev() {
                random ^= random << 13;
                random ^= random >> 7;
                random ^= random << 17;
                requests.swap(index, (random % (index as u64 + 1)) as usize);
            }
            assert_heap_work_and_parity(&requests);
        }
    }

    #[test]
    fn ordering_scratch_stays_fixed_and_has_no_linear_insertion() {
        assert_eq!(
            std::mem::size_of::<PointOrderEntry<&u64>>(),
            std::mem::size_of::<(u64, usize, &u64)>()
        );
        // The movement bound relies on BinaryHeap's sift operations, not a
        // shifting Vec mutation. Guard that structural part of the contract.
        let source = include_str!("local_context_points.rs");
        let selection = source
            .split("        let mut window = BinaryHeap")
            .nth(1)
            .unwrap()
            .split("        Some(points.points)")
            .next()
            .unwrap();
        assert!(!selection.contains(".insert("));
        assert!(selection.contains("window.reserve_exact(LOCAL_CONTEXT_POINT_ORDER_WINDOW)"));
        assert!(selection.contains("window.push(entry)"));
        assert!(selection.contains("window.peek_mut()"));
        assert!(selection.contains("selected.sort_unstable()"));
    }

    #[test]
    fn strict_ordered_input_is_one_pass_even_above_the_unordered_budget() {
        use std::cell::Cell;
        let count = LOCAL_CONTEXT_POINT_ORDER_WINDOW * LOCAL_CONTEXT_POINT_ORDER_PASSES + 1;
        let visits = Cell::new(0);
        let timestamp = at(BASE);
        let points = LocalContextPoints::from_ordered_requests(
            (0..count).inspect(|_| visits.set(visits.get() + 1)),
            |_| Some((Some(timestamp.as_str()), 100)),
        );
        assert_eq!(visits.get(), count);
        assert_eq!(points.len(), 1);
    }
}
