# GPT-5.6 cache-write and model metadata compatibility

Date: 2026-07-11

## Outcome

The local service now preserves structured Codex bundled-model metadata and accepts
the official nested OpenAI prompt-usage detail shapes used for cache reads and cache
writes. These changes make the collector ready for GPT-5.6 model details and for a
future Codex local record that carries `cache_write_tokens`.

## Evidence boundary

A controlled GPT-5.6 Sol Codex OTLP turn reported total input, cached input, output,
and reasoning usage, but did not report prompt-cache write tokens. Existing local
Codex JSONL history likewise exposes cached input without a structured cache-write
field. The runtime does not infer writes from other token counters or from a pricing
multiplier; missing write usage remains unknown.

## Changes

- `codex debug models --bundled` output is parsed into structured model identifiers,
  context windows, output limits, reasoning support, and image support.
- The active configured model selects its matching structured context window.
- Local Codex usage accepts cache fields nested under either
  `input_tokens_details` or `prompt_tokens_details`, while retaining existing root
  aliases. Codex input remains explicitly inclusive in the snapshot; backend ingest
  performs the single normalization into mutually exclusive token classes.
- Tests reject description text as a model identifier and verify nested usage
  normalization.

## Release boundary

This code requires the next signed stable macOS release to reach installed users.
The release improves future collection and model metadata, but cannot recover
historical write tokens or a field the Codex CLI does not emit.
