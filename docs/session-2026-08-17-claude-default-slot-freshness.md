# Claude default-slot freshness repair

## Production finding

Signed stable `0.1.115` collected two distinct, strongly bound Claude accounts
with fresh session, weekly, and model-scoped limits. The default Team account
also had a fresh usage-credit balance. The account-status upload was correct,
but the Companion still showed that account as a partial reading with an older
`Full limits read` timestamp.

The local slot projection computed a fresh full default-slot status and then
called `retain_verified_claude_slot_binding`. That helper correctly rechecked
the current config identity, but it also unconditionally copied the prior
slot's meter flags, timestamp, and quota snapshot over the newly collected
values. The backend upload therefore remained correct while the Companion's
machine-local view stayed stale.

## Repair

`retain_verified_claude_slot_binding` now retains only the verified strong
account and organization binding. It does not copy meter state. The existing
locked slot-state merge remains the single authority for bounded same-account
retention, including its freshness horizon and identity checks.

Regression coverage proves both sides of the boundary:

- a degraded observation can retain the verified account binding without
  inheriting meters before the bounded merge; and
- a current full read keeps its own full-read timestamp and quota snapshot
  instead of being replaced by the prior slot state; and
- a newer partial exact read retains one coherent, bounded prior full bundle
  instead of mixing historical full flags with an incomplete snapshot.

No OAuth lifecycle, login, credential write, inference call, config discovery,
wire contract, or backend behavior changed.
