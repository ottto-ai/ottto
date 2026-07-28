# Session: carry account identity on plan observations, never fabricate org pairings

**Date:** 2026-07-28 · **Change:** `crates/ottto-service/src/agent_status.rs`

A 2026-07-28 production investigation traced an oscillating / chimera billing
identity to two collector-side bugs in the same file.

**Bug 1 - the Claude CLI plan observation carried no account hash.**
`claude auth status --json` names the organization but not the account uuid;
the uuid lives in `~/.claude.json` `oauthAccount.accountUuid`, which the daemon
already parsed (and, since #294, stamps as
`billing_identity_hash("anthropic", "account", uuid)` on every served quota
window) but never carried onto the auth-status account. The Team-seat plan
observation therefore reached the backend with an organization hash only,
while the quota evidence from the very same `oauthAccount` carried the account
hash - plan and quota evidence resolved at different ranks and the backend
could not deterministically converge them. New
`stamp_claude_cli_account_identity` populates `account_id` and
`account_identifier_hash` on the auth-status account, under the exact identity
guard the seat/tier refinements use (present-and-different email or org
refuses; a present auth-status account id that disagrees with `accountUuid`
also refuses), using the same `ottto-core` `billing_identity_hash` - never a
second hashing implementation. Both the snapshot account section and the plan
observation built from it now carry the hash.

**Bug 2 - fabricated org pairing for multi-org accounts.**
`claude_desktop_builder_plan_observation` picked
`current_organization_uuid.or_else(|| organization_uuids.iter().next())`. For
a NON-current account whose Desktop session store has buckets under multiple
orgs, `iter().next()` on the BTreeSet picked an arbitrary org, producing
observed cross-pairings like (gmail account hash + employer org hash) - a
chimera billing identity the backend then minted in production. The org is now
attached only when unambiguous: `current_organization_uuid` set, or exactly
one org in the set; otherwise it is omitted entirely. Fail closed, never
guess. `is_current` semantics are unchanged.

Companion work in the product repo: the backend resolver tie-break ("pin
conflicted identity resolution to the prior link") and the effort fragment
`docs/efforts/state/cross-account-quota-attribution.md`.
