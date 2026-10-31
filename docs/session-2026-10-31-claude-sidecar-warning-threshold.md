# Claude sidecar size is a warning, not an evidence limit

API and trace sidecars continue appending and streaming after 64 MiB. The existing
`oversized_files` counter is pressure information; it no longer makes otherwise
complete evidence unusable. File fingerprints continue tracking large files.

The ordinary streaming readers retain the existing decoded rows and deduplication
maps, with input bounded by the opened file length plus a growth sentinel. A root
whose paired sidecars exceed its normal allowance gets a protected allowance for
that pair and emits `oversized_root_alone` through existing resource diagnostics.
Explicit pass budgets use the actual largest selected pair when necessary. The
cohort scheduler is unchanged; its separate oversized-root scheduling change must
supply actual paired bytes when choosing a protected allowance.

The optional whole-input native-comparison reader may still decline large inputs
under its existing reservation; callers use the ordinary streaming path. Support
inspection remains bounded and diagnostic-only. Genuine read, growth and generation
failures remain incomplete evidence.

No serialized fields, parser version, scan identity version or privacy data class
changed. Existing canonical filenames, owner-only permissions, retention behavior
and recursive uninstall coverage remain. No segment discovery or new store exists.

Validation adds two focused cases: a regression for API/trace capture and decode
past the size warning, and exact under-cap tokens, reported cost and request-owned
accounts. Existing write-error, race and malformed-evidence checks stay. Tests run
in Linux CI; no local tests or builds.
