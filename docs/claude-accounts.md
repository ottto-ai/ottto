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
  custom config directory still replaces the default terminal account. When
  you explicitly choose **Keep limits available**, Ottto may start the resolved
  official Claude CLI with `auth login --claudeai` for one exact isolated root.
  Claude owns the browser, callback, credential, and persistence. Ottto never
  constructs an OAuth URL, receives a password or code, captures provider
  output, or writes credential material itself.
- **The desktop app login.** Separate from the terminal login. Chat sessions
  in the app run under whichever account the app is signed into - which can
  be a different account than the terminal, at the same time.

Sessions started from the app bill the app's account. Sessions started from a
terminal bill the terminal's account. Ottto tracks them separately.

## What Ottto can read, per surface

**Verified Claude Code slots - the full picture, while valid.** For each
registered slot whose exact local login is signed in and strongly identified,
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
collection state is not rewritten. When a managed slot has proved on its last
pass that it reads the same account and organization as the default login, the
slot's credential is the only one that asks Anthropic for that account's
limits; the default login reuses the shared local reading instead of sending
its own token. A rejected credential (HTTP 401 or 403) backs off on its own,
starting at 15 minutes, and does not pause a different credential for the same
account. A second registered directory for the same
binding remains an actionable duplicate instead of being silently treated as
another account.

When usage checks for a connected account are paused (its credential is held
back after the provider rejected sign-in, or the provider stopped answering and
only older readings remain) and no other credential still serves that account,
`ottto apps` grades the Claude Code source `warning` with one problem titled
"Claude usage checks paused" that names how many accounts are affected and the
next automatic check. The source stays `healthy`, the problem asks for no
sign-in, and Ottto keeps its own schedule; nothing forces an earlier check.

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

Choose **Keep limits available** on an observed account, or **Keep another
account's limits available** when Ottto has evidence of another account. The
daemon creates one private provisional root and starts the resolved official
Claude CLI directly with `auth login --claudeai`. Claude opens and owns the
browser sign-in. The root does not count as an account, consume registered-slot
capacity, participate in collection, or upload anything until local evidence
proves both the account and organization.

Strong identity admission is atomic. A new account-and-organization binding
promotes that exact root to one registered durable connection. If the same
binding already exists, Ottto reports **Already connected**, keeps the existing
account row, and retains the provisional root in a bounded reusable quarantine;
it never deletes or logs out provider credentials automatically. A successful
identity admission remains saved even when quota reading is paused or the
provider is temporarily unavailable. Limits appear once a usable exact-slot
reading succeeds.

Retained provisional roots are not accounts and never appear as connection or
usage rows. Authenticated v23 local status exposes only an identifier-free
count for the app's Advanced section; it exposes no root id, path, service
alias, account hash, organization hash, logout, or delete action.

Current local-service versions do not return a Terminal fallback. The daemon
privately drains the official CLI's output and recognizes only its explicit
authorization-code prompt. Authenticated local status then reports
`waiting_for_code`; after a v25 in-app submission it reports `submitting_code`.
If the provider emits its exact rejection sentence after submission, status
returns to `waiting_for_code` with `code_error: invalid_code`. A terminal
`timed_out` outcome tells the app that the ceremony expired. Browser completion
remains automatic when the provider finishes without asking for a code.

The v25 request is exact-operation-bound:

```json
{
  "request_id": "req_opaque",
  "protocol_version": 25,
  "command": "claude_account_submit_auth_code",
  "schema_version": 1,
  "operation_id": "claude_setup_<opaque>",
  "code": "<one-time code>"
}
```

`auth_code_entry_supported: true` is the additive status capability. The code
must be one non-empty printable line of at most 2,048 bytes and is accepted only
while that exact active operation is `waiting_for_code`. It is carried as a
redacted, zeroizing secret, forwarded through anonymous pipes, and never written
to state, logs, diagnostics, backend payloads, provider-output fields, or the
local-control response. Raw provider output is likewise discarded after a
bounded private prompt scan.

Browser setup is idempotent by opaque operation id, including across daemon
restarts. The daemon persists lifecycle and exact-root identity, never adopts a
process from a prior daemon instance by PID, and does not relaunch during crash
recovery. A small supervisor and its provider child share separate
process-lifetime evidence plus one owned process group; the child retains that
evidence even if the supervisor crashes. Recovery cannot release the global
ceremony or reuse its root until the old provider process has exited. **Stop waiting**
asks that supervisor, with a daemon-owned process-group fallback, to terminate
only its owned Claude process; it never
deletes a credential. A retry uses a fresh operation id and may safely reuse
the retained exact root. Removing a managed registration also preserves its
directory; customers remain in control of credential deletion.

When an already registered custom slot reaches `needs_login`, **Sign in again**
starts browser authentication for that exact opaque slot on a v23 daemon. It
does not create another config directory or registration. A v25-capable app
submits an explicitly requested authorization code to that exact operation;
current daemons never substitute a Terminal ceremony or sibling slot.
Reconnect refuses
the default slot, an unknown or removed registration, a weak/missing account
binding, and a login that resolves to a different strong account. Stop Waiting
and daemon restart retain the same operation/slot binding. After completion,
another reconnect may start for the same slot; prior operation ids remain
retired in bounded fail-closed state and can never be rebound.

Each registered connection remembers the account it is approved for: the
strong account and organization hashes only, never an email or credential,
stored with its registration together with how it was approved
(`approved_from`: `setup`, `reconnect` or `observed`). A setup or reconnect
that completes with verified identity records that approval. A connection saved
before approvals existed is back-filled once: from its latest completed,
verified setup or reconnect; else from the last verified identity in local
collection state; else from its first verified identity. A connection whose
setup or reconnect is still pending, or ended without verified identity, is
never back-filled from an observation.

The last two back-fills are trust on first use (`observed`). They approve
whatever account was signed in, including one that drifted there before this
version, so local status shows a notice on that connection: "Approved from the
current Claude login (<plan>). If this is the wrong account, sign in again with
the right one." The next completed verified reconnect replaces an observed
approval, even when it proves a different account, because signing in through
a reconnect is the user's explicit choice; the notice then disappears. An
approval from a verified setup or reconnect is never replaced by another
account that way. Any completed verified reconnect re-records its own verified
pair; one started without an expected organization (a same-account
organization change) therefore re-approves the new organization. Otherwise,
switching a verified connection to another account or organization means
removing and re-adding it.

Running `CLAUDE_CONFIG_DIR=<that directory> claude` and `/login` with another
account replaces the Claude login inside that connection. Ottto then reports
`identity_mismatch` for it, with a local message that names both plans (for
example a Claude Max 20x login in a Claude Team Premium connection). Until the
approved account signs in again, Ottto starts no Claude command, credential
refresh or usage request for that connection and uploads nothing for the other
account; the approved account keeps its own profile and its last full reading,
marked stale, so its card shows that it needs attention. Accounts are never
merged. Signing in again with the approved account, from Terminal or the app,
resumes collection on the next pass. If the connection's Claude account file
(`.claude.json`) is missing, unreadable or lacks strong ids, Ottto fails closed
the same way and reports `identity_unknown`: no command, refresh or usage
request runs for a login it cannot identify. A browser reconnect of a verified
connection that returns another account leaves the mismatch state: Claude's own sign-in ran in that directory, so
the saved Claude login there was replaced even though Ottto kept the
connection's approval. The default `~/.claude` login is unchanged: it follows
whichever account is signed in there.

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

## Login state without running Claude Code

Ottto decides each slot's login state from local metadata only, and never runs
`claude auth status`. It reads the slot's `.claude.json` account, then the
stored Claude Code credential, then `.claude.json` again (a change between the
two reads is a concurrent login). From the credential it uses only token
presence, the access and refresh deadlines, the scopes and the stored plan;
`claude auth status` printed exactly these fields. The credential is read with
`security find-generic-password -w`, so it passes through a pipe into daemon
memory; Ottto keeps only the access token, for the usage request, and never
stores, logs or uploads it.

- No stored login: `credential_unavailable`.
- A keychain error, a locked keychain, no `security` tool, unparseable JSON,
  or a refresh token without an access deadline, without an access token or
  without the `user:inference` scope: the read fails closed (`probe_failed`,
  "cannot confirm").
- No refresh token, a passed `refreshTokenExpiresAt`, or the blanked item
  Claude Code writes after a rejected refresh: `needs_login`.
- A valid access token: collect as usual.
- An access token that expired (or expires within 60 seconds) while the
  refresh grant is alive: the background refresher below runs (`refresh_due`,
  upkeep `in_progress`). With "Keep my Claude accounts signed in" off, the slot
  is **paused** instead (`refresh_due`, upkeep `upkeep_disabled`, quota access
  `paused`). Either way it keeps its last reading marked stale, and Ottto sends
  no usage request with an expired token.

For the default login, Claude Code's own precedence is checked first. Settings
layers apply from user to managed (the highest layer that sets a value wins,
and settings `env` outranks the daemon's environment). A Bedrock or Vertex
route, `ANTHROPIC_AUTH_TOKEN` or an `apiKeyHelper` is used ahead of OAuth.
`ANTHROPIC_API_KEY` outranks a usable OAuth login only once the user approved
that key in Claude Code (`.claude.json` `customApiKeyResponses.approved`), and
a Console API key saved by `/login` counts only when no OAuth login is usable;
a Max user who declined a key stays on the subscription.

The decision uses a fresh read on every pass, never a persisted deadline. When
the login is refreshed (or the customer signs in again), the next pass collects
again without a reconnect.

## Keep my Claude accounts signed in

`claude doctor` upkeep is off: a short Claude Code command that starts near or
after access expiry begins a token refresh and can exit, or be killed, before
the rotated token is saved, and Claude Code then signs the login out
(anthropics/claude-code issue 95822). Ottto never runs `claude auth status`
either.

Instead, when "Keep my Claude accounts signed in" is on (the existing
`background_upkeep_consent` setting, on by default until the customer turns it
off), Ottto keeps each registered slot and the default login signed in:

- When a login's access token is within 5 minutes of expiry (Claude Code's own
  refresh window) or already expired, for example on the first pass after the
  Mac wakes, Ottto starts exactly one
  `claude -p /usage --no-session-persistence --strict-mcp-config` for that
  login, in an empty working directory and its own process group, and keeps
  the Mac awake while it runs. `/usage` reads plan usage and uses no model
  quota; Claude Code refreshes the token before it.
- The refresher is never killed. After 120 seconds it is reported as still
  running and left to finish. Concurrency is left to Claude Code's own refresh
  lock.
- Success is proved only by a new, later `expiresAt`. If the expiry did not
  advance, or the login was blanked, that login is not refreshed again and
  asks to sign in again until a new credential appears.

The daemon's other short Claude runs (the `-p /context` footprint read and the
Verify smoke) do not start from 15 minutes before a login's access expiry until
the refresh has advanced it, nor while it is expired or Claude Code holds its
refresh lock. A skipped `/context` read retries in 30 minutes; a skipped Verify
returns a warning asking to open Claude Code once (or wait), then Verify.

`refreshTokenExpiresAt` (about 28 days after a browser sign-in) is an absolute
login horizon. Three days and one day before it, the slot (and the default
login) report `relogin_approaching`; once elapsed it reports `needs_login` and
waits for the customer to sign in again.

Residual risks not removed: a server-side 401 makes Claude Code refresh
regardless of the local clock; a crash or power loss between the provider
rotating the token and Claude Code saving it; the customer's own short Claude
Code commands; and Claude processes started under user MCP servers or hooks of
the `/context` read.

## Tips

- To get full quota visibility for an account, its default or explicitly
  registered Claude Code credential must remain valid. Claude Code credentials
  are the only full-picture source.
- With "Keep my Claude accounts signed in" on, Ottto refreshes each login once
  near its access expiry; the absolute refresh deadline (about 28 days) always
  requires customer-owned official login.
- Remember `/login` replaces the terminal account rather than adding one.
  After switching, the previous account's terminal readings stop refreshing
  and will show their age honestly.
- For another account, use **Keep limits available** in the Ottto app. Current
  versions keep supported Claude sign-in completion in the browser and Ottto
  app; update Ottto if an older local service cannot do so. Do not run `/login`
  in the default terminal slot unless replacing it is your intent.
- The badge and the "not verified" label are not errors. They are Ottto
  telling you exactly how much it can prove.
