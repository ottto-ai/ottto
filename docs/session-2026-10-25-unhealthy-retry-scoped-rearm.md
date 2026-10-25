# Scoped Claude unhealthy retries

A failed traversal previously re-armed every stale pending family when any page had an unsettled upload, or when a full retry appeared able to reopen the duplicate fence. Unchanged accepted history could therefore be read in full again at every unhealthy retry.

Ordinary same-context unhealthy retries now carry each independently accepted, complete, witness-equal family when every member retains a matching current request record and an accepted committed head. Missing, damaged, old-version, incomplete or mismatched request evidence and missing or mismatched acceptance keep that family on the re-arm path. Protected sessions, authority/account holds, invalid pending and identity-contract changes retain their existing exclusions.

The existing candidate scan fingerprint still selects changed, truncated or replaced members. Its funded family cancellation and replay handle changed members; timestamps alone never authorize a skip. Carried request records, authority witnesses, accepted bodies and account bindings stay unchanged. Pending is compacted using the existing carry mechanism and receives no new-window coverage; the duplicate fence and withheld status remain closed and disclosed.

The exception requires a present, bounded future full-replay deadline. Missing, invalid or due deadlines and scheduled full-replay windows keep their existing behavior. RetryPending families use their own retry deadline, including overdue work on the next cycle. Terminal holds retain their disclosure and binding. The local stale-evidence log reports carried and re-armed family counts; no wire field or persisted format is added.

Validation covers the unchanged synthetic baseline, 9 held plus 32 accepted healthy families with zero healthy full reads, missing/mismatched acceptance and request evidence, changed fingerprints, invalid pending, protection, scratch refusal, due replay, overdue and terminal holds, evidence/binding preservation after reload, and late identity sidecar evidence through the upload/ACK pipeline.
