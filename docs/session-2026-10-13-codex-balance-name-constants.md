# Codex credit balance names: one constant each

The Codex adapter spelled two contract-pinned credit balance names as string
literals in several places: `credits` (plan credits) and
`workspace_monthly_credits` (workspace monthly allowance). The saved-reset
balance already had a constant, `RESET_BANK`.

## Change

- `agent_status::codex_credit_grants` now also defines `PLAN_CREDITS`
  (`"credits"`) and `WORKSPACE_MONTHLY_CREDITS`
  (`"workspace_monthly_credits"`), next to `RESET_BANK`.
- The three Codex balance builders in `agent_status.rs` and the Codex
  provider-to-`kind` table use the constants.
- The builder of the saved-reset balance already used `RESET_BANK`; no
  production `"reset_bank"` literal is left.

Not changed: the `credits` capability name, the `credits` keys read from
provider JSON, and the `credits` credit unit. They are other names that happen
to share the spelling. Tests keep literals where they assert the wire shape.

No wire change: a new test asserts each constant equals its contract string.

## Tests

Synthetic only. `cargo fmt --check` and
`cargo clippy --workspace --all-targets -D warnings` clean; the focused
credit and Codex parser tests pass (171), including the new
`balance_names_are_the_contract_wire_names`.
