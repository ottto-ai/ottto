# Local rejection attribution

Per-entity rejection logs now include `session_hash`, the first eight lowercase hexadecimal characters of SHA-256 of the offered source session ID. Attribution matches the rejected fingerprint to exactly one item in the current bounded upload page. Missing or ambiguous associations report `session_hash=unavailable`; the log never substitutes a fingerprint hash or trusts an identity supplied by the response.

The hash is formatted from four stack bytes. Association scans only the already selected page (existing maximum50items); no additional source reads, account calls or identity lookup. Both ordinary uploads and cache-head probes pass their original offered session identity. Logging stays after durable upload-progress persistence. ACK validation, accepted sibling checkpointing, refusal ledgers, retry behavior, canonical bodies and wire fields remain unchanged.

Regression tests cover the known SHA-256 prefix for a synthetic identity, changed fingerprints with the same identity, rejected fingerprints absent from the offered page, duplicate/ambiguous matches, missing identities and invalid bounds. Validation runs in existing Public CI; no local Cargo builds or tests. Source test results do not establish installed performance or proof coverage.
