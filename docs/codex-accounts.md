# How Ottto keeps Codex limits available

One Mac can use several ChatGPT subscriptions through Codex. Ottto treats the
normal Codex login as the **default connection** and leaves it under the user's
control. Durable connections are additive: changing the default login never
replaces them.

The identity key is the exact composite of the ChatGPT user and active ChatGPT
workspace. Email is display evidence, not an identity key. The same user in a
personal workspace and a business workspace therefore represents two valid
subscriptions; two durable connections for the same exact composite are a
duplicate. A default connection may temporarily shadow a matching durable
connection without becoming a duplicate registration.

Authenticated local-control protocol v21 exposes every workspace already
observed in the Codex ID token as a typed `target_coverage.targets` row. Each
row has a daemon-authored opaque target id, hashed account/workspace identity,
the provider-supplied workspace title, durability and health, and explicit
setup blockers. A membership without both hashes remains visible as
`identity_unconfirmed`; it is never silently omitted or accepted for setup.
Clients pass the opaque id back through `codex_account_prepare_target` and do
not send identity hashes selected or reconstructed from UI state.

One workspace is named two ways by the provider: a credential is bound by
`chatgpt_account_id`, which is what a durable slot registers, while the same
credential's ID token lists `organizations[].id`. Those are different identifier
spaces, so the organization flagged `is_default` - the one the credential is
actually signed into - is aliased onto the binding identity before targets are
assembled. Without that alias the current login and every durable connection
appear twice, and the duplicate offers to connect a subscription that is already
connected. Aliases are collected across all candidates, so a workspace seen as
non-default on one credential still collapses onto the slot that connected it.

`account_label` carries the signed-in email from the ID token so two connected
Codex accounts are distinguishable on screen. It is the only raw provider string
in this payload: `codex_accounts_status` answers the local Unix socket only and
is never uploaded, and raw account ids, workspace ids, and token material stay
absent. Credentials that claim no email fall back to a generic label.

`hasCredits: false` states that the credits program does not apply to an
account, not that a balance ran out. The `balance: "0"` the provider sends
alongside it is filler, so no credit row is emitted for that case; a positive
balance, an `unlimited` grant, and a reached spend control are all still shown.

## Connecting another subscription

Authenticated local control creates one opaque, owner-only Codex home and
returns an exact launch command for the official `codex login` flow. The user
completes OpenAI's browser login and workspace selection; Ottto never receives
or types an email, password, MFA code, cookie, access token, or refresh token.

The setup check accepts the connection only when all of these are true:

- the signed-in ChatGPT user hash matches the selected target;
- the active ChatGPT workspace hash matches the selected target;
- Codex App Server returns fresh quota for that exact home;
- another accepted durable connection does not own the same composite; and
- after Ottto writes Codex's supported `forced_chatgpt_workspace_id`
  restriction, a new App Server process reports the same identity and quota.

An incorrect account or workspace remains unaccepted and can be retried in the
same home. A stopped or failed setup also reuses its existing home. An accepted
binding cannot be prepared again. Removing an Ottto-managed connection
permanently deletes only that daemon-created credential home; recovery requires
a fresh provider login. The default Codex home is never a deletion target.

The default connection plus up to nine durable connections can coexist. Every
directory and settings file is owner-only. Settings persist only opaque slot
ids and hashed account/workspace bindings; the raw workspace id is written only
to that slot's local Codex config because Codex requires it for the workspace
restriction.

## Quota collection and failure isolation

Each collection pass probes the default and durable homes independently using
the installed Codex binary with exact per-slot `CODEX_HOME` and
`CODEX_SQLITE_HOME` values, a cleared environment, and no ambient provider API
keys. Durable homes never use Ottto's legacy OAuth
HTTP fallback. Collection uses the documented local Codex App Server
`account/rateLimits/read` method and preserves every reported
`rateLimitsByLimitId` bucket. Every window key combines its limit id, field,
reported duration, and reset availability; unknown durations remain unique and
no bucket meaning is inferred from position.

Homes are probed concurrently under the ten-slot cap, so one provider timeout
does not serialize or suppress healthy siblings. One backend-safe snapshot is
emitted for each distinct strong user/workspace composite. Every quota window
and credit balance carries the same hashed composite as its account record.
Raw ids, token material, provider responses, credential paths, and local slot
ids are not uploaded.

Canonicalization follows these rules:

- a healthy durable connection wins an exact tie with the default connection;
- the matching default is locally marked `shadowed_by_anchor`;
- two workspaces under one user remain separate subscriptions;
- a second durable connection for the same composite is locally actionable as
  `duplicate_account`; and
- a signed-out, mismatched, or unavailable sibling degrades source health but
  does not remove healthy subscription snapshots.

Codex owns OAuth token persistence and refresh. Ottto does not refresh tokens
directly and does not promise that a provider-revoked login will remain valid.
When Codex reports that a durable home needs login, the app should offer the
same provider-owned reconnect flow for that exact home.

## Product language

The shared Claude Code and Codex action should be phrased as **Keep limits
available**. The supporting text explains that it adds a durable connection
without changing the account currently used for new sessions. Provider names
remain visible in the flow, but both providers use the same concepts: default
connection, exact account/workspace target, provider-owned sign-in, identity
validation, duplicate rejection, independent health, and explicit removal.

This feature is for subscriptions the user is authorized to use. It does not
pool entitlements, bypass provider limits, automate account rotation, share
credentials with another person, scrape browser state, or call undocumented
ChatGPT endpoints. Ottto reports each provider-owned quota independently and
the provider remains the authority for subscription and acceptable-use rules.
