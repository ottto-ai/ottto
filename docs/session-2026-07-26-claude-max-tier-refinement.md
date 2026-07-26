# Session: refine bare Claude `max` into an explicit 5x/20x tier from local evidence

**Date:** 2026-07-26 · **Change:** `crates/ottto-service/src/agent_status.rs`

`claude auth status` reports `subscriptionType: "max"` for BOTH Max 5x and
Max 20x accounts, so downstream costing had to guess (and the backend guessed
$200/mo Max 20x for every bare `max`, over-costing Max 5x users 2x - fixed
separately in the product repo by pricing bare `max` as the conservative
lower bound).

The disambiguator has been on disk all along: `~/.claude.json`
`oauthAccount.organizationRateLimitTier` (`default_claude_max_5x` /
`default_claude_max_20x`). The daemon already read it but only used it for
Claude Team seat refinement.

New `refine_claude_max_rate_limit_plan` mirrors
`refine_claude_team_seat_plan` exactly: same identity guards (email/org
mismatch refuses; a stale non-max `organizationType` refuses), evidence-only
(an absent or unrecognized tier leaves generic `max` untouched - never a
guess), org-level tier first (Max is an individual plan) with the user-level
tier as a same-shaped fallback. On refinement the account uploads
`plan_type: max_5x|max_20x` and `subscription_product: claude_max_5x|claude_max_20x` -
existing wire fields the backend already prices correctly, so no contract
change. A `claude_max_rate_limit_tier_detected` info diagnostic records the
resolution.

Tests mirror the Team suite: 20x from org tier, 5x from user-tier fallback,
generic left untouched, mismatched-identity refusal, non-max plan/org refusal.
