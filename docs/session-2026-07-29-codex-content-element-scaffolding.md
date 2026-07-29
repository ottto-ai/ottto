# Codex content-element scaffolding cleanup

Date: 2026-07-29

## Problem

Codex response-item user messages can carry injected `recommended_plugins`,
`AGENTS.md`, and `environment_context` blocks as separate `input_text`
elements. The parser joined those elements and ran the shared title normalizer
before removing injected scaffolding. That normalizer truncates at 255
characters, so a long plugin catalog lost its closing tag and was retained as
the session's template material.

The backend then correctly identified the same opaque template across separate
sessions, but the shared input was product scaffolding rather than a recurring
human prompt. This produced false `Recurring prompt pattern` badges.

## Fix

- Strip injected scaffolding from each complete content element before joining
  or normalizing prompt text.
- Keep the existing bounded normalizer for the remaining human prompt.
- Advance the Codex parser and scan-identity versions to `codex_jsonl:v25` so
  existing indexed sessions are revisited once and stale template groups can
  be replaced.
- Add a response-item regression with a plugin block whose closing tag lies
  beyond the former 255-character boundary.

## Validation

- Focused response-item regression passes.
- Full `ottto-service` suite passes after refreshing the semantic-envelope
  golden for the intentional parser/scan-identity revision change.

No macOS stable release was cut from this machine.
