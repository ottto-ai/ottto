# Local session labels and upload settings

Local durable passes always enable native skill-label storage, restore and retention.
Upload settings continue to filter the emitted snapshots before finalization; their
fingerprints and acknowledgements still bind to the filtered bytes. Field codecs,
allowlist pins, durable bindings, record formats and actual erasure paths are unchanged.

The Companion active-session list reconciles after account binding and before upload
filtering, using the existing snapshot vector without a clone. Quiet recent sessions
survive an upload-setting change. Source disable still clears the list. The list cache
is consumed locally; diagnostics and support uploads select their existing allowlists.

Session-link collection and storage are unchanged. Retaining links requires an old-record
compatible codec reader before changing the allowlist; no new Full-read cause is introduced.

Validation: changed-file rustfmt checks locally; Linux CI covers the updated consent,
byte-parity, active-list and key-erasure regressions plus existing money and diagnostics
canaries. Native macOS checks and independent money review remain separate release gates.
