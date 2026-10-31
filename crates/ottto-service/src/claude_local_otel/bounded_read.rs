//! Optional native-comparison input, never the ordinary evidence loader.
//! Refusal is an optimization miss, not a sidecar-health or usage decision.
use super::*;
use crate::heap_layout_bound::HeapLayoutBound;
use crate::heap_layout_bound::{self, Counter};
use crate::source_rotation::PaidReservation;
use std::mem::size_of;

pub(super) fn path_workspace(support_dir: &Path) -> Option<usize> {
    let full = support_dir
        .as_os_str()
        .len()
        .checked_add(TRACE_STORE_DIR.len().max(STORE_DIR.len()))?
        .checked_add(2 + 64 + ".jsonl".len())?;
    // Canonical join retains the first prefix while cloning/extending it:
    // prefix + old clone + replacement clone (capacity <=2*full).
    // Hex filename formatting's old/new buffers together fit 256 bytes.
    full.checked_add(full)?
        .checked_add(full.checked_mul(2)?)?
        .checked_add(256)
}

/// An opened, complete, immutable input. A stack sentinel detects growth;
/// neither Read::read_to_end nor a growable line reader is used here.
struct Input {
    bytes: Vec<u8>,
    generation: ApiFileGeneration,
}

#[derive(Clone, Copy)]
enum ReadKind {
    Api,
    Trace,
}

impl Input {
    #[cfg(test)]
    fn read(path: &Path, paid: &PaidReservation, occupied: usize) -> Option<Self> {
        Self::read_with(path, paid, occupied, None, || {})
    }

    fn read_with(
        path: &Path,
        paid: &PaidReservation,
        occupied: usize,
        kind: Option<ReadKind>,
        after_open: impl FnOnce(),
    ) -> Option<Self> {
        if !heap_layout_bound::layout_supported() {
            return None;
        }
        let before = api_file_generation(&fs::metadata(path).ok()?)?;
        #[cfg(test)]
        if matches!(kind, Some(ReadKind::Api)) {
            API_BEFORE_OPEN.with(|hook| {
                if let Some(hook) = hook.borrow_mut().take() {
                    hook(path);
                }
            });
        }
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NONBLOCK);
        }
        let mut file = options.open(path).ok()?;
        #[cfg(test)]
        match kind {
            Some(ReadKind::Api) => API_READ_RECEIPT.with(|receipt| {
                let (opens, bytes, force) = receipt.get();
                receipt.set((opens + 1, bytes, force));
            }),
            Some(ReadKind::Trace) => TRACE_READ_RECEIPT.with(|opens| opens.set(opens.get() + 1)),
            None => {}
        }
        #[cfg(not(test))]
        let _ = kind;
        let opened = api_file_generation(&file.metadata().ok()?)?;
        // This optional whole-input optimization may refuse a large file:
        // callers fall back to the ordinary streaming evidence reader.
        if before != opened || opened.bytes >= MAX_EVIDENCE_FILE_BYTES {
            return None;
        }
        let length = usize::try_from(opened.bytes).ok()?;
        if !paid.permits(occupied.checked_add(length)?) {
            return None;
        }
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(length).ok()?;
        // On the admitted allocator/toolchain reserve_exact requests exactly
        // length bytes. Check capacity too; never subsequently grow this Vec.
        if bytes.capacity() != length {
            return None;
        }
        bytes.resize(length, 0);
        after_open();
        let mut offset = 0usize;
        while offset < length {
            let consumed = file.read(&mut bytes[offset..]).ok()?;
            if consumed == 0 {
                return None;
            }
            offset += consumed;
            #[cfg(test)]
            if matches!(kind, Some(ReadKind::Api)) {
                API_READ_RECEIPT.with(|receipt| {
                    let (opens, bytes, force) = receipt.get();
                    receipt.set((opens, bytes + consumed, force));
                });
            }
        }
        let mut sentinel = [0u8; 1];
        let extra = file.read(&mut sentinel).ok()?;
        #[cfg(test)]
        if matches!(kind, Some(ReadKind::Api)) {
            API_READ_RECEIPT.with(|receipt| {
                let (opens, bytes, force) = receipt.get();
                receipt.set((opens, bytes + extra, force));
            });
            API_AFTER_READ.with(|hook| {
                if let Some(hook) = hook.borrow_mut().take() {
                    hook(path);
                }
            });
        }
        if extra != 0
            || api_file_generation(&file.metadata().ok()?)? != opened
            || api_file_generation(&fs::metadata(path).ok()?)? != opened
        {
            return None;
        }
        Some(Self {
            bytes,
            generation: opened,
        })
    }

    fn lines(&self) -> impl Iterator<Item = &[u8]> {
        self.bytes.split_inclusive(|byte| *byte == b'\n')
    }
}

#[derive(Default)]
struct Shape {
    lines: usize,
    strings: usize,
    longest_string: usize,
    longest_line: usize,
    largest_row_strings: usize,
}

impl Shape {
    fn read(input: &Input) -> Option<Self> {
        let mut shape = Self::default();
        for line in input.lines() {
            shape.lines = shape.lines.checked_add(1)?;
            shape.longest_line = shape.longest_line.max(line.len());
            let mut string = None;
            let mut row_strings = 0usize;
            for (offset, byte) in line.iter().copied().enumerate() {
                // serde_json 1.0.149 SliceRead returns borrowed string slices
                // without decoder scratch on this subset. Escapes/unicode are
                // ordinary BASE, never interpreted differently or discarded.
                if byte == b'\\' || !byte.is_ascii() {
                    return None;
                }
                if byte == b'"' {
                    if let Some(start) = string.take() {
                        let length = offset - start;
                        row_strings = row_strings.checked_add(length)?;
                        shape.longest_string = shape.longest_string.max(length);
                    } else {
                        string = Some(offset + 1);
                    }
                } else if string.is_some() && byte.is_ascii_control() {
                    return None;
                }
            }
            if string.is_some() {
                return None;
            }
            shape.strings = shape.strings.checked_add(row_strings)?;
            shape.largest_row_strings = shape.largest_row_strings.max(row_strings);
        }
        Some(shape)
    }

    fn api_peak(&self, input: &Input) -> Option<usize> {
        let mut counter = self.common_peak::<ClaudeLocalOtelEvidence>(input)?;
        heap_layout_bound::tree_nodes::<String, ()>(self.lines, &mut counter)?; // seen
        heap_layout_bound::tree_nodes::<String, usize>(self.lines, &mut counter)?; // request rows
        heap_layout_bound::tree_nodes::<String, ()>(self.lines, &mut counter)?; // conflicts
                                                                                // Distinct owned strings: typed rows, seen fingerprints, request-map
                                                                                // keys, conflicting IDs. Each is a subset of captured string bytes.
        for _ in 0..4 {
            counter.add(self.strings)?;
        }
        counter.add(self.largest_row_strings)?; // current request_id clone
                                                // identity_upgrade_replay's two temporary typed row clones. A previous
                                                // row and the incoming row each fit the largest captured row strings.
        counter.add(self.largest_row_strings)?;
        counter.add(self.largest_row_strings)?;
        Some(counter.bytes)
    }

    fn trace_peak(&self, input: &Input) -> Option<usize> {
        let mut counter = self.common_peak::<ClaudeTraceOwnershipEvidence>(input)?;
        heap_layout_bound::tree_nodes::<String, ()>(self.lines, &mut counter)?;
        heap_layout_bound::tree_nodes::<String, String>(self.lines, &mut counter)?;
        heap_layout_bound::tree_nodes::<String, ()>(self.lines, &mut counter)?;
        // Rows, seen, (request key + fingerprint value), conflicting IDs.
        for _ in 0..4 {
            counter.add(self.strings)?;
        }
        Some(counter.bytes)
    }

    fn common_peak<T>(&self, input: &Input) -> Option<Counter> {
        let mut counter = Counter::new(usize::MAX);
        counter.add(input.bytes.capacity())?;
        counter.add(self.lines.checked_mul(size_of::<T>())?)?;
        // Unknown nested values use serde_json's one-byte-per-enclosing-frame
        // ignore_value scratch. Long-number scratch is bounded by input bytes
        // too on the locked default features. Vec's old + replacement buffers
        // require three times that *scratch length*, not a file-size heuristic.
        let scratch = self.longest_line.max(8);
        counter.add(scratch)?;
        counter.add(scratch.checked_mul(2)?)?;
        // Derived typed errors have one unescaped unexpected string plus fixed
        // field/variant/type wording (<256 bytes for these two row schemas).
        // String formatting's old+replacement and boxed-string shrink overlap
        // are charged separately. ErrorImpl itself fits 256 bytes.
        let error = self.longest_string.checked_add(256)?;
        counter.add(error)?;
        counter.add(error.checked_mul(2)?)?;
        counter.add(256)?;
        Some(counter)
    }
}

/// The existing owner has already paid `occupied`; this call borrows its one
/// reservation. It never creates a second allowance or retains a raw input.
pub(super) fn api(
    path: &Path,
    session_id: &str,
    paid: &mut PaidReservation,
    occupied: usize,
) -> Option<(Vec<ClaudeLocalOtelEvidence>, ApiReadWitness)> {
    let opened_bytes = usize::try_from(fs::metadata(path).ok()?.len()).ok()?;
    if !paid.grow_for(occupied.checked_add(opened_bytes)?) {
        return None;
    }
    let input = Input::read_with(path, paid, occupied, Some(ReadKind::Api), || {})?;
    let shape = Shape::read(&input)?;
    if !paid.grow_for(occupied.checked_add(shape.api_peak(&input)?)?) {
        return None;
    }
    let mut rows = Vec::new();
    rows.try_reserve_exact(shape.lines).ok()?;
    if rows.capacity() != shape.lines {
        return None;
    }
    let mut decoder = ApiSidecarDecoder::new(session_id, rows);
    for line in input.lines() {
        if line.ends_with(b"\n") {
            decoder.push_line(line);
        } else {
            decoder.finish_eof(Some(line));
        }
    }
    let (rows, health) = decoder.into_output();
    let witness = ApiReadWitness {
        generation: health.is_complete().then_some(input.generation),
        health,
    };
    drop(input.bytes);
    let mut retained = Counter::new(usize::MAX);
    rows.completed_heap_bound(&mut retained)?;
    witness.completed_heap_bound(&mut retained)?;
    paid.record_allocated(occupied.checked_add(retained.bytes)?)
        .then_some((rows, witness))
}

pub(super) fn trace(
    path: &Path,
    session_id: &str,
    paid: &mut PaidReservation,
    occupied: usize,
) -> Option<(ClaudeTraceOwnershipLoadReport, ClaudeTraceReadGeneration)> {
    let opened_bytes = usize::try_from(fs::metadata(path).ok()?.len()).ok()?;
    if !paid.grow_for(occupied.checked_add(opened_bytes)?) {
        return None;
    }
    let input = Input::read_with(path, paid, occupied, Some(ReadKind::Trace), || {})?;
    let shape = Shape::read(&input)?;
    let mut outer = Counter::new(usize::MAX);
    heap_layout_bound::tree_nodes::<String, Vec<ClaudeTraceOwnershipEvidence>>(1, &mut outer)?;
    outer.add(session_id.len())?;
    if !paid.grow_for(
        occupied
            .checked_add(shape.trace_peak(&input)?)?
            .checked_add(outer.bytes)?,
    ) {
        return None;
    }
    let mut rows = Vec::new();
    rows.try_reserve_exact(shape.lines).ok()?;
    if rows.capacity() != shape.lines {
        return None;
    }
    let mut decoder = TraceSidecarDecoder::new(session_id, rows);
    for line in input.lines() {
        // Shape admission already excludes non-ASCII input.
        if line.ends_with(b"\n") {
            decoder.push_line(line);
        } else {
            decoder.finish_eof(Some(line));
        }
    }
    let (rows, mut report) = decoder.into_output();
    if !rows.is_empty() {
        report.evidence.insert(session_id.to_owned(), rows);
    }
    drop(input.bytes);
    let retained = heap_layout_bound::completed_bound(&report, usize::MAX)?;
    paid.record_allocated(occupied.checked_add(retained)?)
        .then_some((
            report,
            ClaudeTraceReadGeneration {
                opened: input.generation,
            },
        ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn paid(bytes: usize) -> PaidReservation {
        PaidReservation::from_remainder(Some(bytes), bytes, 0).unwrap()
    }

    #[test]
    fn native_comparison_paid_input_growth_replacement_and_truncation_refuse() {
        if !heap_layout_bound::layout_supported() {
            eprintln!("UNEXECUTED paid opened-input positive: unsupported layout");
            return;
        }
        let dir = std::env::temp_dir().join(format!(
            "ottto-paid-input-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&dir).unwrap();
        let path = dir.join("evidence.jsonl");
        for change in ["grow", "replace", "truncate"] {
            fs::write(&path, b"{}\n").unwrap();
            let result = Input::read_with(&path, &paid(3), 0, None, || match change {
                "grow" => OpenOptions::new()
                    .append(true)
                    .open(&path)
                    .unwrap()
                    .write_all(b"{}\n")
                    .unwrap(),
                "replace" => {
                    fs::rename(&path, dir.join("old")).unwrap();
                    fs::write(&path, b"{}\n").unwrap();
                }
                _ => fs::write(&path, b"{}").unwrap(),
            });
            assert!(result.is_none(), "{change} cannot qualify a prefix");
        }
        fs::write(&path, b"{}\n").unwrap();
        assert!(Input::read(&path, &paid(3), 0).is_some());
        assert!(Input::read(&path, &paid(2), 0).is_none());
        assert!(Input::read(&path, &paid(3), 1).is_none());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn native_comparison_paid_decoder_measured_unknown_and_error_scratch_stays_paid() {
        if !heap_layout_bound::layout_supported() {
            eprintln!("UNEXECUTED paid decoder requested allocation: unsupported layout");
            return;
        }
        let dir = crate::test_scratch::private_dir("paid-decoder-scratch");
        let path = dir.join("rows.jsonl");
        // These exercise canonical serde's ignored-value scratch and dynamic
        // error text, not a replacement JSON parser or a cleaned usage fixture.
        for (name, bytes) in [
            (
                "nested_unknown",
                format!(
                    "{{\"unknown\":{}0{},\"fingerprint\":\"f\"}}\n",
                    "[".repeat(8192),
                    "]".repeat(8192)
                )
                .into_bytes(),
            ),
            (
                "large_unexpected_string",
                format!("{{\"input_tokens\":\"{}\"}}\n", "a".repeat(32768)).into_bytes(),
            ),
            (
                "long_integer",
                format!("{{\"input_tokens\":{}}}\n", "9".repeat(32768)).into_bytes(),
            ),
        ] {
            fs::write(&path, bytes).unwrap();
            let input = Input::read(&path, &paid(1024 * 1024), 0).unwrap();
            let planned = Shape::read(&input).unwrap().api_peak(&input).unwrap();
            drop(input);
            let mut reservation = paid(planned);
            let (result, measured) =
                crate::retry_allocation_probe::measure(|| api(&path, "scope", &mut reservation, 0));
            let (rows, witness) = result.expect("exact preflight allowance");
            assert!(rows.is_empty());
            assert_eq!(witness.health.malformed_lines, 1);
            assert!(witness.generation.is_none());
            assert!(
                measured.requested_peak_with_overlap <= planned,
                "{name}: {} > {planned}",
                measured.requested_peak_with_overlap
            );
            assert!(api(&path, "scope", &mut paid(planned - 1), 0).is_none());
            eprintln!("paid decoder allocation: case={name} planned={planned} requested_peak_with_overlap={} exact_admitted=true one_byte_less_refused=true not_RSS=true", measured.requested_peak_with_overlap);
        }
        fs::remove_dir_all(dir).unwrap();
    }
}
