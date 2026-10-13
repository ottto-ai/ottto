# Cache-head bootstrap source progress

A snapshot source could repeatedly reparse unchanged history after cache-head bootstrap failed before its scan index was committed. The partitioned uploader already suppresses an exact quarantined probe body. Bootstrap then required an accepted head for that unsent body, turning one held entity into a whole-source failure. A retained cache cannot compensate for repeated selection of a corpus larger than its capacity.

Bootstrap now applies the same exact-body hold predicate as the existing uploader. A permanently refused or unleased quarantined probe carries its exact no-cache body into ordinary settlement; it acquires neither acceptance nor an invented head. The hold check precedes head lookup, so a sibling for the same session cannot bypass that body's backoff. Healthy siblings still obtain independent head proofs and use the normal upload and index writers.

New probe conflicts remain durable exact quarantines. Their deferred count is carried into the main result so accepted siblings can checkpoint without reporting the source wholly settled. Existing source/account authority, body-witness validation, head-required policy, index CAS, cache limits and retry cadence remain unchanged. Legacy acknowledgements, never-attempted headless bodies, mismatched witnesses and local persistence failures still fail closed. Bootstrap shedding and disabled outcomes retain their existing behavior.

Failure diagnostics at the probe/apply boundaries use the existing typed, content-free error vocabulary. A count-only held-probe message makes source continuation visible without printing identities, paths or payloads.

## Validation

Targeted offline regression fixtures cover known holds, healthy siblings, exact wire acknowledgements, persistence and restart. Rust 1.95.0 targeted H357/H359/H360 validation passed 20 tests; the existing healthy bootstrap control also passed. Checks exercised synthetic bodies and acknowledgements only. Review results are recorded with the final source revision. These checks do not establish installed resource savings. After a containing signed release, verify source finish and index commit, then measure subsequent scan selection counts, bytes, CPU and memory.
