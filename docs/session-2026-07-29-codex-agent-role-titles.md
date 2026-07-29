# Codex agent-role session titles

Date: 2026-07-29

## Problem

Headless Codex sessions whose only user message is a long role contract such as
`You are the LANDING OWNER AGENT ...` had no display title. The general
first-prompt filter correctly rejects arbitrary `You are ...` setup text, so
these sessions fell back to a model or repository label even though the prompt
contained a short, non-sensitive role name.

## Change

- Extract a title only from the constrained opening form
  `You are [a|an|the] <role> agent|worker|orchestrator`.
- Bound the extracted role to 2–8 words and 64 characters.
- Reject path-like or markup-like role text.
- Normalize common technical initialisms while never exposing the remaining
  prompt body.
- Advance the Codex parser and scan identity to `codex_jsonl:v24` so existing
  affected sessions are revisited.

Examples:

- `You are the LANDING OWNER AGENT ...` → `Landing owner agent`
- `You are a PR REPAIR AGENT ...` → `PR repair agent`

## Validation

Targeted Rust tests cover accepted role forms and rejected unbounded/path-like
forms. The existing first-prompt privacy and continuation-boilerplate tests
remain in the same parser suite.
