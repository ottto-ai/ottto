# Per-file effective projection adoption

An unchanged current scan index can already contain the same semantic and
additive body hashes that a corrected upload projection prepares. Comparing
those hashes alone can skip the correction before upload.

`ScanIndex::activate_effective_upload_body_witness_revision(revision)` selects a
nonzero local projection revision before the committed baseline and scan. Each
file whose stored revision differs is parsed once, even under an already admitted
upload context. Its pending finalization excludes the previous semantic/body
hashes from no-op suppression. Only complete, eligible file finalization stamps
the producing revision; existing exact file-group settlement and index save
remain authoritative. Capped pages adopt independently.

After local dispositions, callers pass every source file containing a held item
to `exclude_effective_upload_body_witness_revision_for_source_files`. Call this
before `finalize_scan_after_policy_with_body_witness`, using the effective upload
projection for its body witness. Held and mixed groups keep their old revision.
The existing Claude authority retry gate precedes adoption selection, preserving
bounded retries for unchanged held families.

The persisted per-file revision defaults to zero and omits zero in serialized
indexes. Active revision and exclusions are transient. Activation zero preserves
default behavior without downgrading adopted checkpoints. Parser, semantic entity,
wire, ACK, state-only, and digest contracts retain their existing meaning.

Five focused adoption tests passed, plus thirteen existing scanner, finalizer,
quarantine, paging, state-only, and settlement checks. The current-identity fixture
first reproduced zero selected files instead of 143, then proved all 143 survive
finalization with equal prepared hashes, retry after unsettled save/reload, and
skip after settlement/save/reload. Other tests cover partial files, capped pages,
held/mixed groups, and default zero. Offline tests used an isolated build directory;
touched-file formatting and diff whitespace checks passed.
