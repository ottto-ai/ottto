# Claude slots stay on the account they were set up for

**Date:** 2026-10-03
**Scope:** daemon Claude slot registry, collection and upkeep; no wire or
protocol enum change

## Problem

A registered Claude slot did not remember which account it belonged to. The
registry stored only `slot_id`, `ownership` and `config_dir`. On each pass a
slot became whatever its current credential and `.claude.json` resolved to.

So `CLAUDE_CONFIG_DIR='<slot dir>' claude` followed by `/login` with another
account silently turned the slot into that account. Its state stayed `fresh`,
upkeep kept refreshing the new login, and the original account's card went
stale with no explanation. The identity-change check covered only the default
login. Uploads were never misattributed, because they are keyed by the
resolved account and organization hashes, but the user was never told.

A browser reconnect that returned another account was refused. It then
suppressed the slot until another app reconnect completed, so fixing the login
from Terminal did not resume collection. Its detail also said the saved
connection was not changed. In fact Claude's own sign-in had replaced the
login in that directory.

## Change

- **Approved binding.** Each registered slot now stores optional
  `approved_account_identifier_hash` and
  `approved_organization_identifier_hash` in `claude-config-slots.json`. These
  are hashes only, validated as strong SHA-256 values, both or neither, with
  `serde(default)`. An older daemon ignores them; a downgrade rewrite drops
  them and the next pass back-fills again.
  - A setup or reconnect that reaches `complete` with verified account and
    organization records the approval (`transact_for_operation`).
  - Generic browser admission records it in the same registry transaction
    (`register_managed_path_with_slot_id_and_binding`).
  - Removing a slot removes its approval.
- **Back-fill, exactly.** When a slot has no approval:
  1. Use the latest completed, identity-verified setup or reconnect for that
     exact slot and directory.
  2. Otherwise use the slot's last verified identity in the local collection
     state file.
  3. Otherwise use the first identity that resolves strongly.

  Steps 2 and 3 run only when no setup or reconnect for the slot is pending or
  ended unverified, so a wrong-account sign-in during setup can never become
  the approval. While a setup or reconnect is pending, its own expected pair is
  the gate.
- **Gate.** Before upkeep, before any CLI spawn and before the usage call, the
  collector compares the slot's `.claude.json` identity with the approval. It
  checks again against the identity `claude auth status` resolves. The
  scheduled loop and the direct slot check both use it.

  On a difference the slot reports the existing `identity_mismatch` state and
  diagnostic. Its status keeps the approved hashes, the approved account's
  profile and that account's own last full reading, marked stale. The local
  message names both plans, never emails.

  The slot pushes no candidate and makes no upload under the other account. The
  degraded projection for the approved account carries `attention_required`,
  that account's own stale reading and diagnostic codes; the message stays
  local.
- **No refresh.** The upkeep worker's spawn fence and publication fence refuse
  a slot whose login contradicts its approval.
- **Recovery.** When the approved account signs in again, by Terminal or the
  app, the next pass collects normally. A browser reconnect that ended in
  `identity_mismatch` now hands an approved slot to this gate instead of the
  sticky suppression. A slot with no approval keeps the old behaviour.
- **Truthful reconnect detail.** The core operation message for a reconnect
  mismatch now says the Claude login saved in the connection was replaced, and
  that Ottto kept the approval and assigned no usage to the other account.
- **Unchanged.** The default `~/.claude` login, the protocol enums, the meter
  collision quarantine and the reconnect identity check itself.

## Tests

- Core (`claude_config_slots`):
  - verified completion records the approval, and a mismatch or an
    observation never replaces it;
  - legacy back-fill order, including no trust on first use after an
    unverified operation, and removal;
  - half or weak hashes are rejected.
- Service (`agent_status`), with a fake `claude` that logs every spawn, a
  file credential and cached usage, so no provider call is made:
  - Terminal `/login` with another account gives `identity_mismatch`: no slot
    CLI spawn, no usage call, nothing uploaded under the other account, the
    approved account's projection is `attention_required`, the worker fence
    refuses, and no email or token appears in uploads or persisted state;
  - signing back in recovers to `fresh`;
  - back-fill from the last verified identity;
  - the direct slot check;
  - message wording.

  With the gates disabled, the three behaviour tests fail with `Fresh`.
- Browser auth: an approved slot's mismatched reconnect has truthful detail,
  lifts suppression to the gate and recovers. The existing unapproved-slot
  test still preserves suppression. Generic admission records the approval.

## Follow-up (app, private repo)

The macOS app still hard-codes "Your saved connection was not changed" for
the reconnect `identity_mismatch` outcome (`ClaudeAccountsView.swift`), and it
does not offer "Sign in again" for collection `identity_mismatch`. Both belong
to the app change proposed with this fix.
