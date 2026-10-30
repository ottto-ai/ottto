# Large-record restore: bounded content and shared recovery integration

The large-record restore branch merges the bounded workspace extractor and
structural active-budget fallback into the existing restore/custody contract.
Workspace captures remain bounded to 4096 bytes and require the original digest;
other content obligations still refuse. Metadata and bounded certificate samples
run before repeatable resource refusals. Content buffers, captures and parsing
scratch are charged before extractor input. This ordering supersedes the earlier
standalone extractor note's refusal-before-certificate expectation.

Retail exhaustion, resource recovery and structural fallback share one paid
source/file pacing map. The six-hour pace uses SystemTime; backward time and
excessive forward jumps expire toward reading. Map overflow evicts the oldest
stamp, admits the new read, and emits one source-attributed pace_evicted event.
The irrevocable retail spend map is neither evicted nor refunded. Growth at
90% of the existing source cap bypasses pacing; existing oversized-file rejection
still applies above the cap. Structural Full retains no optional replacement.

Independent native Full decisions are planned under restore's transfer funding
before the retail allowance is consulted. The same plan is moved into native
preparation, keeping its reason and avoiding repeated certificate samples. An
exhausted or full spend ledger and a live recovery stamp cannot veto an audit or
clock decision inherited from main. Those inherited causes remain disclosed
pending the acquisition-cause policy change. Authored scanner controls compare
exact output bodies and preserve both spend entries and the existing pace stamp.

Warm transfer Busy preserves traversal residue and aged census evidence. Codex
structural eligibility spends its pace only after page and cursor start checks.
The accepted-body floor, counted missing-record successor, all-member refusal
accounting, delayed positive receipt reconciliation, and funding before classifier
or cursor settlement remain intact. Persisted fields, format, allowlists, source
caps, account attribution and ACK semantics are unchanged.

Formatting and package Clippy compile these fixtures; no local test executes.
Native fixture execution, owner money review, complete growth discovery through
the owning main change, and the shared transition-fixture API remain integration
qualification. The component exceeds the earlier approximate size guideline
because content funding, graph custody, native start and shared pacing form one
release boundary with their discriminating scanner/restart controls.
