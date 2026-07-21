# 2026-07-21 — privacy-gated session attribution labels

## Outcome

Local snapshots can add a small readable label to an otherwise opaque
`template_group_id` or `skill_id` attribution fact. This is an additive wire
change; opaque identifiers and evidence remain authoritative grouping keys.

## Wire contract

An attribution fact may now contain:

```json
{
  "field": "template_group_id",
  "value": "hmac-sha256:v1:…",
  "display_label": "Inspect the landing queue and report failures",
  "display_label_source": "prompt_prefix",
  "evidence": { "kind": "local_template", "strength": "direct", "observed_at": "…", "source_version": "…", "evidence_ref": "…" }
}
```

Allowed pairs are:

- `template_group_id` + `prompt_prefix`: collapsed to one line, path-like
  tokens replaced with `[path]`, maximum 96 UTF-8 bytes;
- `skill_id` + `skill_name`: ASCII letters, numbers, `-`, `_`, `.`, or `:`,
  maximum 64 bytes.

Both fields are omitted together when no safe label exists. The established
24-fact and 2 KiB attribution-payload limits still apply and are revalidated
immediately before upload.

## Privacy and compatibility gates

The backend activity hint adds
`session_attribution_labels_enabled` as a capability, defaulting to `false` in
the daemon when absent. A label reaches the wire only when all three are true:

1. session attribution is enabled;
2. the existing `session_titles_enabled` privacy choice is enabled;
3. the backend advertises attribution-label support.

This is not a new user setting. A new daemon connected to an older backend
therefore emits the original v1 fact shape, and old daemons remain compatible
with a backend accepting the optional fields. Switching the capability on uses
a distinct scan-index namespace so unchanged historical sessions are revisited
once; it does not add a watcher or polling loop.

The implementation reuses the first-user prompt and provider-native skill name
already held briefly by the incremental scanner. It never uploads a transcript,
response, scheduled-task file, process tree, or filesystem path and requires no
new macOS permission.

## Release implication

Deploy backend parsing, validation, storage, and activity-hint support before
publishing the macOS build. After that, the public app change requires the next
stable macOS release; it cannot appear in an already published binary such as
v0.1.89. The intended release is v0.1.90.
