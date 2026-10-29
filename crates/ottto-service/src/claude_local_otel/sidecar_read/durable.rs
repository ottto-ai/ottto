//! Executable contract skeleton, not a second store or an enabled Tail reader.
use super::*;
use crate::durable_tail_store::{Digest32, DurableTailStore, SingleWriter};
use crate::transcript_acquisition::DurableCertificate;
use std::io;

struct Slot<D> {
    continuation: D,
    // Reuse the shared identity/birth and head/boundary hashes. Its
    // sealed_offset is A; length is observed L. None means never receipted.
    // DECISION(19b-§8-SOURCE): approve certificate/key/typed field classes
    // before these shapes acquire a durable encoding. No serde in phase 1.
    certificate: Option<DurableCertificate>,
    // DECISION(19b-§8-LeadA): changed [A,L) replay needs the EOF exception.
    // DECISION(19b-§8-E1): pair this hash with the approved reversible typed
    // EOF overlay; never finish_eof on the retained sealed continuation.
    fragment_sha256: Option<Digest32>,
}

struct Slots<'a> {
    api: Slot<ApiSidecarDecoder<'a>>,
    trace: Slot<TraceSidecarDecoder<'a>>,
}

impl<'a> Slots<'a> {
    fn cold(session_id: &'a str) -> Self {
        Self {
            api: Slot {
                continuation: ApiSidecarDecoder::new(session_id, Vec::new()),
                certificate: None,
                fragment_sha256: None,
            },
            trace: Slot {
                // P3-2: constructor-default report, never the whole-loader's
                // cross-session report (which also contains evidence maps).
                continuation: TraceSidecarDecoder::new(session_id, Vec::new()),
                certificate: None,
                fragment_sha256: None,
            },
        }
    }

    fn load(
        &mut self,
        support_dir: &Path,
    ) -> (ClaudeLocalOtelLoadReport, ClaudeTraceOwnershipLoadReport) {
        let session = self.api.continuation.session_id;
        assert_eq!(session, self.trace.continuation.session_id);
        // Current fallback drives the real public loaders, not a copied fold.
        // No retained progress is claimed by this phase-1 delegation.
        (
            load_claude_api_request_evidence_report(support_dir, [session.into()]),
            load_claude_trace_ownership_evidence(support_dir, [session.into()]),
        )
    }

    fn receipt<W: SingleWriter>(
        &self,
        _store: &mut DurableTailStore,
        _writer: &W,
    ) -> io::Result<()> {
        // DECISION(19b-§8-E1): real shared encode/receipt/page barrier, before
        // publication; write_after_save is not a substitute for write-ahead.
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "19b: pending E1 sidecar receipt",
        ))
    }

    fn restore(_store: &mut DurableTailStore, _session: &'a str) -> io::Result<Self> {
        // DECISION(19b-§8-SOURCE): no speculative sidecar tag or allowlist.
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "19b: pending SOURCE/E1 sidecar record",
        ))
    }
}

thread_local! {
    static TRACE_BYTES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

// Counts actual Read bytes under the production BufReader, not decoder rows.
pub(in crate::claude_local_otel) struct CountedTrace(pub(in crate::claude_local_otel) File);

impl Read for CountedTrace {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        let count = self.0.read(bytes)?;
        TRACE_BYTES.with(|receipt| receipt.set(receipt.get() + count));
        Ok(count)
    }
}

fn reset_bytes() {
    API_READ_RECEIPT.with(|receipt| receipt.set((0, 0, false)));
    TRACE_BYTES.with(|receipt| receipt.set(0));
}

fn read_bytes() -> (usize, usize) {
    (
        API_READ_RECEIPT.with(|receipt| receipt.get().1),
        TRACE_BYTES.with(|receipt| receipt.get()),
    )
}

fn frozen_reports(
    api: &[u8],
    trace: &[u8],
) -> (ClaudeLocalOtelLoadReport, ClaudeTraceOwnershipLoadReport) {
    let (rows, health) = crate::claude_local_otel::decoder_tests::baseline_api(api).into_output();
    let api = ClaudeLocalOtelLoadReport {
        evidence: BTreeMap::from([("scope".into(), rows)]),
        health,
    };
    let (rows, mut trace) =
        crate::claude_local_otel::decoder_tests::baseline_trace(trace).into_output();
    trace.evidence.insert("scope".into(), rows);
    (api, trace)
}

fn pair_bytes(request: &str) -> (Vec<u8>, Vec<u8>) {
    let api = ClaudeLocalOtelEvidence {
        capture_revision: API_REQUEST_CAPTURE_REVISION.into(),
        session_id: "scope".into(),
        request_id: request.into(),
        fingerprint: request.into(),
        input_tokens: 17,
        output_tokens: 9,
        request_count: 1,
        cost_usd_micros: Some(123),
        ..Default::default()
    };
    let trace = ClaudeTraceOwnershipEvidence {
        capture_revision: TRACE_OWNERSHIP_CAPTURE_REVISION.into(),
        session_id: "scope".into(),
        request_id: request.into(),
        fingerprint: request.into(),
        ..Default::default()
    };
    let mut api = serde_json::to_vec(&api).unwrap();
    let mut trace = serde_json::to_vec(&trace).unwrap();
    api.push(b'\n');
    trace.push(b'\n');
    (api, trace)
}

fn write_pair(dir: &Path, api: &[u8], trace: &[u8]) {
    for (path, bytes) in [
        (evidence_path(dir, "scope"), api),
        (trace_evidence_path(dir, "scope"), trace),
    ] {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, bytes).unwrap();
    }
}

#[test]
fn whole_file_default_uses_clean_per_file_slots_and_frozen_reports() {
    let dir = crate::test_scratch::private_dir("sidecar-slot-default");
    let (api, trace) = pair_bytes("first");
    write_pair(&dir, &api, &trace);
    let mut slots = Slots::cold("scope");
    assert_eq!(
        slots.api.continuation,
        ApiSidecarDecoder::new("scope", Vec::new())
    );
    assert_eq!(
        slots.trace.continuation,
        TraceSidecarDecoder::new("scope", Vec::new())
    );
    assert_eq!(slots.api.certificate, None);
    assert_eq!(slots.trace.certificate, None);
    assert_eq!(slots.api.fragment_sha256, None);
    assert_eq!(slots.trace.fragment_sha256, None);
    reset_bytes();
    assert_eq!(slots.load(&dir), frozen_reports(&api, &trace));
    assert_eq!(read_bytes(), (api.len(), trace.len()));
    reset_bytes();
    assert_eq!(slots.load(&dir), frozen_reports(&api, &trace));
    assert_eq!(
        read_bytes(),
        (api.len(), trace.len()),
        "phase 1 remains whole-file"
    );
    fs::remove_dir_all(dir).unwrap();
}

#[test]
#[ignore = "19b: pending E1 sidecar receipt/page barrier and SOURCE record/EOF approval"]
fn loader_full_append_tail_store_restart_equals_frozen_whole_file() {
    use crate::durable_tail_store::{store_dir_for_index, DurableSource};
    use crate::locked_state_dir::LockedStateDir;

    let dir = crate::test_scratch::private_dir("sidecar-slot-durable");
    let state = dir.join("state");
    let writer = LockedStateDir::acquire(&state).unwrap();
    let store_dir = store_dir_for_index(&state.join("index.json"));
    let mut store = DurableTailStore::new(store_dir.clone(), DurableSource::ClaudeCode);
    let (mut api, mut trace) = pair_bytes("first");
    write_pair(&dir, &api, &trace);
    let mut slots = Slots::cold("scope");

    reset_bytes();
    let cold = slots.load(&dir);
    assert_eq!(cold, frozen_reports(&api, &trace));
    assert!(cold.0.health.is_complete() && cold.1.is_complete());
    assert_eq!(cold.0.evidence["scope"].len(), 1);
    assert_eq!(cold.1.evidence["scope"].len(), 1);
    assert_eq!(read_bytes(), (api.len(), trace.len()));
    // This currently returns Unsupported. Never substitute a fake success or
    // a test-only codec: the test must acquire a genuine shared-store receipt.
    slots.receipt(&mut store, &writer).expect("cold receipt");

    let (api_append, trace_append) = pair_bytes("late-old-event-time");
    for (path, bytes) in [
        (evidence_path(&dir, "scope"), &api_append),
        (trace_evidence_path(&dir, "scope"), &trace_append),
    ] {
        OpenOptions::new()
            .append(true)
            .open(path)
            .unwrap()
            .write_all(bytes)
            .unwrap();
    }
    api.extend(&api_append);
    trace.extend(&trace_append);
    reset_bytes();
    let tail = slots.load(&dir);
    assert_eq!(tail, frozen_reports(&api, &trace));
    assert_eq!(tail.0.evidence["scope"].len(), 2);
    assert_eq!(tail.1.evidence["scope"].len(), 2);
    assert_eq!(
        read_bytes(),
        (api_append.len(), trace_append.len()),
        "only append bytes"
    );
    slots.receipt(&mut store, &writer).expect("tail receipt");
    drop(slots);
    drop(store);
    drop(writer);

    // Twice: a restored projection must itself remain restorable. No RAM
    // continuation, inherited store handle or successful empty output stands
    // in for the on-disk API+trace continuation.
    for _ in 0..2 {
        let writer = LockedStateDir::acquire(&state).unwrap();
        let mut store = DurableTailStore::new(store_dir.clone(), DurableSource::ClaudeCode);
        reset_bytes();
        let mut restored = Slots::restore(&mut store, "scope").expect("real disk restore");
        let actual = restored.load(&dir);
        assert_eq!(actual, frozen_reports(&api, &trace));
        assert_eq!(actual, tail);
        assert_eq!(
            read_bytes(),
            (0, 0),
            "quiet restore reads no old body bytes"
        );
        restored
            .receipt(&mut store, &writer)
            .expect("restored receipt");
    }
    fs::remove_dir_all(dir).unwrap();
}
