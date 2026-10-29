# Archive settlement and scoped census contracts

This prerequisite separates terminal upload failures from the durable six-decode
first-read recovery budget. Three bounds durably recorded terminal failures;
crash-lost outcomes may instead reach decode_budget at six. Exact current-body
ACK revives settlement holds without inventing settlement or replacing money.
Reservation persistence precedes bytes and the retry count/alarm.

Terminal archive residue protects only affected sessions, including real compressed
keys without counting owners, while healthy siblings can finish/retire normally.
Admission starvation uses the existing bounded RAM map; restart/eviction can lose
its streak. No durable lifetime admission bound is claimed.

The named codex_zst_first_read_retry exception (Lead A approved 2026-10-29) exits
in 11b-1b retained-acquisition resume. A3/A4 is deferred to 11a.4b. Discovery stays
off until the 1 GiB catch-up bound and real pacing are installed. Static fixtures
cover reservation/terminal-outcome crash windows, save refusal, exact ACK,
scoped removal hints and starvation. Tests/compiler/CI remain unexecuted.

The three native RU exits are covered by dedicated synthetic scan fixtures:
quiet terminal stamps, settlement-exhausted parser construction, and native
OutputHeld finish. Parser construction now distinguishes a typed admission yield
from other errors; only Z-ADMISSION and bodyless Z-PENDING use archive RU there.
The fixtures check zero terminal RU, named residue and healthy state-only progress;
execution remains deferred to the authorized validation lane.
