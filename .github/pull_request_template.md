## Summary

<!-- What changes and why. Link the issue it fixes, if any (for example "Fixes #123"). -->

## Validation

<!-- Commands you ran and their result, for example `cargo fmt --check`,
`cargo test -p <crate>`, `jq empty` on changed JSON, or the script test for the
file you changed. See CONTRIBUTING.md for the full list. -->

## Compatibility

<!-- Does this change CLI help or JSON output, exit codes, the local-control
protocol, schemas, connector manifests, or release metadata? If yes, list the
fixtures and docs you updated. Otherwise write "None". -->

## Checklist

- [ ] No secrets, tokens, cookies, raw prompts or model output, customer data,
      account or machine identifiers, or paths that include a user name in the
      code, tests, docs, or this description.
- [ ] Tests and docs are updated for any behavior or contract change.
- [ ] Rust changes: this description has a reuse line (see the note below).

<!--
Rust changes need a line that starts with "Reuse:" at the start of the line,
saying what you searched for and which existing code you reused or extended.
CI checks for it. Example (remove the indent when you use it):
  Reuse: searched ottto-core for a redaction helper; extended the existing one.
-->
