# Ignore injected prompt scaffolding in session recurrence

## Problem

Codex Desktop writes its injected `AGENTS.md` and environment envelope as an
early user-message record before the human task prompt. Local snapshot parsing
rejected that envelope as a display title but still retained it as
`first_prompt_material`. Because the same envelope appears across many sessions
in one repository, their opaque template identifiers could match and produce a
false recurring-prompt classification.

## Change

- Strip recognized leading instruction/environment scaffolding before selecting
  both first-prompt title and attribution material, preserving any task text
  appended to the same message.
- Continue scanning until the first real task prompt.
- Defensively reject scaffold-shaped material in template normalization.
- Advance Codex, Claude Code, and Pi parser and scan-identity versions so
  already-indexed recent transcripts are revisited. Corrected snapshots remove
  or replace stale template facts through normal semantic reconciliation.

The server recurrence thresholds are unchanged. A template group still needs at
least three distinct timestamps for calendar/fixed-interval classification, or
at least four sessions spanning at least two hours with a median gap of at most
six hours for a bursty recurring-prompt classification.

## Validation

- Focused first-prompt and template-normalization unit tests.
- Full snapshot parser and session-attribution test suites.
- Cross-language semantic-envelope golden regeneration and verification.
- Snapshot-audit revision-key golden refresh for the intentional parser-version
  change.
- Public repository surface validation before merge.
