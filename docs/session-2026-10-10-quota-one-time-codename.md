# One-time credit pool codename check in the credit model

`quota_credit_model::one_time_credit` now owns the rule for a one-time pool's
codename, which becomes the balance `limit_id` (quota contract v2.2 §11.3,
names pinned by §11.7 C4). The codename must be a `^[a-z0-9_.-]{1,64}$` code
that also passes the privacy guard. Otherwise no balance is built and the
function returns `Err(OneTimeCreditRefusal::LimitId)`. Its `diagnostic()` is
the `field_refused` / `limit_id` diagnostic that adapters already record for a
skipped pool. A pool is skipped rather than renamed, because a different
`limit_id` would split that pool's history series.

The success value is unchanged: the balance plus its title and instant
diagnostics. `one_time_credit` now returns
`Result<(AgentCreditBalance, Vec<CreditModelDiagnostic>), OneTimeCreditRefusal>`,
so adapters that call it change their call sites to match.

The quota-coverage fixture sequence step that reads a count of 1 already uses
its own count-1 provider input on main; nothing changed there.

Known leftover: the temporary `#[allow(dead_code)]` on the `quota_credit_model`
module (`crates/ottto-service/src/lib.rs`) and the
`#[allow(unused_imports)]` on the v2.2 credit imports
(`crates/ottto-service/src/agent_status.rs`) stay until the provider adapters
are merged.

Not verified here: provider adapters and live provider reads.
