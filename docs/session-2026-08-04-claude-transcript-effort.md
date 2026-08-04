# Claude reasoning effort comes from the transcript now, not OTLP

2026-08-04. Follow-up to the per-request attribution shipped in `0.1.105`
(session note `2026-08-02-claude-effort-per-request-attribution.md`).

## What changed upstream

That note, and the code it describes, rests on a premise that is no longer true:

- `claude_effort.rs`: "Claude transcripts intentionally omit the effort tier."
- `snapshots.rs`: "Claude Code surfaces per-turn effort via OTLP, not this
  snapshot path."

Current Claude Code writes the applied tier directly on the assistant record:

```json
{"type":"assistant","uuid":"8715f175-…","timestamp":"2026-08-03T15:13:42.572Z",
 "effort":"high","userType":"external","entrypoint":"sdk-cli", … }
```

Measured over two days of local transcripts:

| transcript kind | assistant usage records with `effort` | without |
| --------------- | ------------------------------------- | ------- |
| top-level       | 19,705 (99%)                          | 291     |
| subagent        | 3,995 (72%)                           | 1,521   |

The records without it are almost entirely Haiku (1,533), which has no effort
tier, plus 254 Opus 4.8 and 25 `<synthetic>`. Coverage is effectively complete
for every model that has a tier. Observed on Claude Code 2.1.215 through 2.1.221.

Cross-checked against the OTLP sidecar on the 7,020 records both sources
describe: **7,020 agree, 0 disagree.**

## Why the transcript is the better source

The sidecar path works, but it exists to undo a problem the transcript does not
have. Claude Code stamps the top-level `session.id` on subagent OTLP records, so
evidence pooled per session had to be routed back to the right transcript by
`request_id`. The transcript field is already on the record whose usage it
describes, in parent and sidechain transcripts alike, so:

- no loopback OTLP relay dependency, which is a moving part that can be off,
  stripped, or unsupported on a given machine;
- no cross-session pooling, therefore no parent/subagent misattribution to fix;
- no sidecar read, no fit gate, no residual row, no request-id index.

## Change

`apply_claude_code_line` now reads the tier from the record and only falls back
to the sidecar when the transcript omits it:

```rust
let reasoning_effort = claude_transcript_effort(value)
    .or_else(|| accumulator.claude_effort_for_line(value));
```

`claude_transcript_effort` lower-cases and validates against
`CLAUDE_EFFORT_TIERS`, the single vocabulary both sources now share. An
unrecognised tier degrades to effort-unknown rather than widening the value the
backend stores.

The OTLP sidecar, its request-id index, and the legacy aggregate reconciliation
are all retained unchanged for transcripts that predate the field.

`CLAUDE_CODE_SNAPSHOT_PARSER_VERSION` moves to `claude_code_jsonl:v28`. Scan
identity does not move: which session a file maps to is unchanged.

## Verification

- `cargo test -p ottto-service --lib`: 1263 pass, including four new tests for
  reading the tier with no sidecar at all, transcript precedence over the
  sidecar, fallback to the sidecar when the field is absent, and rejecting an
  unknown tier.
- `cargo clippy --all-targets` and `cargo fmt --check` clean.
- Semantic-envelope golden moves only `parser_version` and its two derived
  revision hashes; `content_hash` is unchanged.
