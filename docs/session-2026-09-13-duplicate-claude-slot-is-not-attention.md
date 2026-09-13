# A duplicate Claude registration is not a connection that needs attention

2026-09-13, observed on stable `0.1.131`.

## What it looked like

Every registered Claude slot was `fresh` and reporting live limits, both
accounts were at full quota in production, and the macOS Apps pane still said:

- header: **"Some sources need attention"**, 2 sources
- the Claude Code card: **needs attention**
- source problem: `secret_expired`, "Claude Code durable connections need
  attention - The current login remains available. One or more saved account
  connections need attention; their last verified identities remain separate."

Nothing was expired, mismatched, or waiting on a login.

## Cause

A third registered slot resolved to an account another registered slot already
owned, so `collect_claude_status_snapshots` marked it
`ClaudeConfigSlotCollectionStateV1::DuplicateAccount` with relationship
`DuplicateAnchor` - the intended, benign disposition. Its meters come from the
owning slot.

The source-health predicate then counted it as actionable:

```rust
let has_actionable_custom_slot = custom_slot_states.any(|status| {
    !matches!(
        status.state,
        ClaudeConfigSlotCollectionStateV1::Fresh
            | ClaudeConfigSlotCollectionStateV1::Unverified
    )
});
```

`DuplicateAccount` is neither, so one benign duplicate degraded the whole
source and raised a credential-repair problem code.

The sibling provider had this right from the start. `collect_codex_status`
already excludes its own duplicate:

```rust
CodexAccountSlotCollectionStateV1::Fresh
    | CodexAccountSlotCollectionStateV1::DuplicateAccount
```

## Change

`claude_custom_slot_needs_attention` names the predicate and adds
`DuplicateAccount` to the benign set, matching Codex. The duplicate slot stays
visible in the accounts panel with its own state and relationship - it simply
stops claiming the account needs repair.

`a_duplicate_claude_registration_does_not_need_attention` fails on `8f6a7981`
with "DuplicateAccount must not degrade a healthy Claude source", and pins all
fourteen states that must still reach the operator, so narrowing the predicate
further would fail too.

Consent, browser-auth suppression, the network sentinel, and the
disabled-upkeep file are untouched.
