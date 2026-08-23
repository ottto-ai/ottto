# How Ottto sees your Claude accounts

One Mac often uses more than one Claude account: a work account in the
terminal, a personal account in the Claude desktop app. Ottto's rule for all
of them is the same: **a number is shown under an account only when Ottto can
prove it belongs to that account. Anything unproven shows as unknown - it is
never guessed and never borrowed from another account.**

This page explains what Ottto can and cannot see, per surface, and why the
app sometimes shows a plan without numbers or a "Partial view" badge.

## Where your Claude accounts live

- **Claude Code credential slots.** The normal terminal login is the default
  slot. Ottto can also collect from explicitly registered
  `CLAUDE_CONFIG_DIR` paths, up to ten slots total. Running `/login` without a
  custom config directory still replaces the default terminal account. Ottto
  never runs `/login`, calls a token/refresh endpoint, or writes a credential.
- **The desktop app login.** Separate from the terminal login. Chat sessions
  in the app run under whichever account the app is signed into - which can
  be a different account than the terminal, at the same time.

Sessions started from the app bill the app's account. Sessions started from a
terminal bill the terminal's account. Ottto tracks them separately.

## What Ottto can read, per surface

**Verified Claude Code slots - the full picture, while valid.** For each
registered slot whose exact local identity agrees with `claude auth status`,
Ottto reads Claude's own usage summary:
the 5-hour session window, the weekly window, per-model weekly limits (a
single model can be exhausted while the account-level weekly still looks
fine), and usage-credit balances such as an organization's monthly spend
limit. This is the most complete view Claude exposes, and it is only
readable while that slot's credential stays valid. Each quota window and
credit balance carries strong hashes of both the provider account and
organization. If identity cannot be proved, that slot contributes no full
meters. Authenticated machine-local account status returns the same already
collected values per exact slot, together with when Ottto captured the local
snapshot, the oldest provider/cache observation represented, and a typed
`fresh`, `stale`, or `partial` state. It never returns a token, credential blob,
or Desktop state.

**Status line renders - a partial view.** Claude Code's status line reports
only the session and weekly percentages. It carries no per-model limits and
no credit balances, so a status-line-sourced reading can say "weekly 18%,
fine" while a model limit sits at 100% or a monthly spend cap is already
hit. Ottto marks quota that comes only from this source with a **Partial
view** badge rather than presenting it as the whole picture.
Status-line data belongs only to the default current-login surface. Registered
custom slots never inherit it.

**Desktop app account - identity, but no numbers.** The app keeps its login
sealed (its tokens are encrypted by the app, and Ottto does not decrypt
anything). Ottto can see which account the app is signed into and attribute
the app's sessions and their cost to it, but it cannot read that account's
quota. This is why a desktop-only account shows its plan as "not verified"
with no meters: Ottto knows the account exists and what it spends, and
honestly does not know its limits.

## What this looks like on one two-account Mac

- The terminal account shows a full card: plan, session and weekly meters,
  per-model limits, credits.
- The app account shows its own card with sessions and cost attributed to
  it, plan unverified, no meters.
- The two never mix. If Ottto cannot tell which account a reading belongs
  to, the reading is dropped or shown as unattributed - not assigned to
  whichever account happens to be signed in.

When several Claude Code slots are registered, one collection pass uses one
capture time and produces one row per distinct strong **account + organization**
binding. The same account identifier under two organizations remains two quota
subscriptions with independent caches, cadence, retries, and circuit breakers.
One failed slot does not stop healthy siblings. If a registered slot
temporarily fails after Ottto has already proved both its account and
organization, the daemon sends a degraded witness for that same strong
identity. When the last exact coherent bundle is still inside the 24-hour local
retention bound, that witness may carry those meters explicitly marked stale;
otherwise it is meterless. Its typed quota-access state says whether collection is full,
partial, temporarily unavailable, paused, needs reconnection, or needs local
attention. This lets a dashboard distinguish "already configured and retrying"
from "not configured" without receiving a config path, slot id, credential
deadline, token, or local diagnostic payload. A healthy reading for the same
binding always wins over a failed duplicate slot.

Meter authority and anchor durability are separate. The best coherent meter
bundle wins in this order: fresh complete, fresh partial, stale complete, stale
partial; newer provider observation wins inside a tier. A registered anchor
wins only an exact quality-and-time tie. Therefore a freshly switched default
slot may temporarily supply the displayed meters while the registered slot
remains the durable anchor and still reports its own reconnect or paused health.
The default slot is then locally marked `shadowed_by_anchor`; its truthful
collection state is not rewritten. A second registered directory for the same
binding remains an actionable duplicate instead of being silently treated as
another account.

The `claude_quota_access_state_v1` capability marks daemon versions that know
this contract. On an older daemon, or for a desktop/status-line observation
that is not an exact strongly bound slot, an absent state means unknown; it
does not prove that setup is required. Weak identity failures and slots beyond
the ten-account cap remain machine-local typed diagnostics. A same-account
and same-organization cached reading may remain visible for up to 24 hours with
stale freshness; it is never borrowed or relabeled under another organization.
When a same-slot read temporarily fails, authenticated machine-local status may
retain that slot's last full values only if both its strong account and
organization hashes still match; the retained values and every meter are marked
stale. Identity mismatch, another
organization, or another slot never inherits the retained values.

A fresh default-slot status-line observation is lower fidelity, not a failure:
it has session and weekly percentages but no model-scoped limits or credits. If
the same account's exact full snapshot is still inside its normal freshness
horizon, local account status keeps that full snapshot and its original provider
observation time instead of downgrading it during a concurrent scan. Once that
horizon elapses, the retained bundle becomes stale normally. A different account
or organization can never use this rule.

## Connecting another account

Authenticated local control can prepare a private managed directory and return
one exact command of the form `CLAUDE_CONFIG_DIR='<path>' claude`. Ottto never
runs or types `/login`: the customer opens official Claude Code with that
command and completes `/login` there. A check then validates only that exact
registered slot and completes only after fresh session, weekly, and at least one
model-scoped limit are attributed to the same strong account identity. Credits
are reported when available but are not required for completion.

Prepare is idempotent by opaque operation id, including across daemon restarts.
Stop Waiting stops only Ottto's observation; it does not terminate Claude Code,
delete a registration, or erase credentials. A queued check cannot silently
resume a stopped operation. Replaying prepare for the same operation explicitly
resumes it on the same path. Removing a managed registration also preserves its
directory; customers remain in control of credential deletion.

When an already registered custom slot reaches `needs_login`, Reconnect starts
a new persisted observation for that exact opaque slot and returns the same
carefully quoted `CLAUDE_CONFIG_DIR='<exact path>' claude` launch command. It
does not create another config directory or registration. Spaces, quotes,
shell metacharacters, Unicode spelling, and a trailing slash remain data in the
exact stored string; reconnect never normalizes or substitutes a sibling slot.
The customer opens official Claude Code and types `/login`. Reconnect refuses
the default slot, an unknown or removed registration, a weak/missing account
binding, and a login that resolves to a different strong account. Stop Waiting
and daemon restart retain the same operation/slot binding. After completion,
another reconnect may start for the same slot; prior operation ids remain
retired in bounded fail-closed state and can never be rebound.

Ottto does not assign special “Team” or “Personal” directories. Every distinct
account-and-organization binding can receive its own daemon-managed anchor,
whether a Mac has two personal accounts, several organizations, or a mixture.
The daemon presents an opaque setup target, atomically binds the operation to
that exact composite identity, and allows only one setup or reconnect operation
to be active at a time. The customer performs official `/login` once in each
returned directory. After that, changing or repeatedly replacing the default
Claude Code login does not replace those anchors. Up to nine custom anchors can
coexist with the default slot (ten slots total).

Account-only evidence is not enough to merge two organizations. It attaches to
an existing binding only when exactly one organization is possible; otherwise
it remains an explicit ambiguous-identity setup blocker. Capacity is a separate
blocker, so the UI can explain both truths at once. Authenticated local status
also includes a bounded, secret-free transition history using opaque slot ids
and typed events such as default identity changed, anchor remained bound,
refresh deadline advanced, or official reconnect completed. It contains no
account hashes, paths, tokens, or token fingerprints.

When the machine off-switch is enabled, exact-slot usage collection reports
`collection_paused`, makes no provider request, and retains registrations,
consent, and account-scoped caches with their original age. Re-enabling resumes
normal collection without another login prompt.

## Consented background upkeep

Registered custom slots can stay readable after their short-lived access
credential expires without keeping the Companion app open. One explicit
machine-level consent applies to every registered custom slot and persists until
revoked. It does not apply to Claude Code's default slot.

At daemon startup, after wake/network restoration, after registry or consent
changes, and on the daemon's bounded five-minute collection cadence, Ottto
checks persisted slot deadlines without synchronously reading Keychain. Due
slots are coalesced into one background queue, so five due anchors cannot turn a
settings request or snapshot pass into five serial 20-second waits. The worker
owns the authoritative credential reads and vendor command outside the snapshot
and settings locks, and schedules a normal collection/upload after each
successful slot rather than waiting for later siblings. Ottto does nothing
before the exact access expiry. After expiry, and only while the
absolute refresh deadline remains valid, the daemon may run the resolved
installed Claude binary once with argument `doctor` and the exact registered
`CLAUDE_CONFIG_DIR`. The command receives a cleared minimal environment, closed
stdin, discarded output, and a bounded timeout. It receives no prompt, login,
model, or inference flag. Ottto treats the attempt as successful only when a
second read-only deadline observation proves `expiresAt` advanced into the
future; exit status zero alone is not success.

Each due expiry is atomically claimed before the command starts. Startup, wake,
collection, daemon restart, and multiple daemon processes therefore cannot
start duplicate commands. A failed same-expiry attempt can retry only after a
durable five-minute exponential backoff, capped at six hours. The local witness
contains only the opaque slot id, safe deadlines/attempt times, a typed result,
and a failure count—never a token, token fingerprint, account UUID, or config
path.

The existing **Read subscription usage** off-switch always wins: while it is
off, Ottto performs neither provider usage reads nor background upkeep, but it
keeps registrations, consent, caches, and their honest age. Turning collection
back on resumes the prior consent automatically. Operators can also create the
absent-by-default `claude-background-upkeep-disabled` sentinel in Ottto's
support directory to stop only new `doctor` commands while investigating a
vendor-command problem; it does not change consent or provider collection.

`refreshTokenExpiresAt` is an absolute login horizon. Within 72 hours the slot
reports `relogin_approaching`; once elapsed it reports `needs_login` and waits
for the customer to complete official Claude Code `/login` again. Claude Code
may also clear the refresh grant while leaving an old future deadline in its
credential record. Ottto treats a missing refresh grant as `needs_login`
immediately and does not keep running `doctor` against a login it cannot
recover. Background upkeep cannot promise an indefinitely fresh login.

## Tips

- To get full quota visibility for an account, its default or explicitly
  registered Claude Code credential must remain valid. Claude Code credentials
  are the only full-picture source.
- Background upkeep is post-expiry catch-up, not proactive renewal. The
  absolute refresh deadline still requires customer-owned official login.
- Remember `/login` replaces the terminal account rather than adding one.
  After switching, the previous account's terminal readings stop refreshing
  and will show their age honestly.
- For another account, use the exact managed-slot command returned by Ottto;
  do not run `/login` in the default terminal slot unless replacing it is your
  intent.
- The badge and the "not verified" label are not errors. They are Ottto
  telling you exactly how much it can prove.
