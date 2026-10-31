# Optional Claude and Pi oversized-file admission

The owner-set `claude_pi_oversized_admission_enabled` support-directory marker
opts Claude and Pi into admitting transcripts above their existing 512 MiB and
256 MiB thresholds. The shared local-switch policy defaults OFF and pins the
setting for the process. Codex admission remains unchanged.

ON retains `oversized_file_count` as a pressure observation while the existing
native reader consumes the file through its per-line continuations. Oversized
sightings alone do not veto traversal health, native comparison or terminal
receipt classification. Actual read/parser failures keep their usual behavior.
The line limit, reducer state limits and scheduling budgets are unchanged.

A retained walk with OFF-era oversized loss keeps that loss until the next
ordinary walk. A shared, defaulted count-provenance flag distinguishes those
skipped files from ON pressure observations and is omitted from OFF state.
Enabling admission never changes the traversal context or re-arms families.
No parser/scan-identity version or upload format changes.

Regression coverage scales the existing JSONL-limit fixture seam instead of
allocating a transcript above 512 MiB. It checks OFF admission/refusal and ON
recovery from a retained oversized walk, native continuation yields, pressure
visibility, completed census, and exact request/token fields in the final body.
