# Claude authority preflight family scope

Date: 2026-09-14

## Problem

A production QA Mac running daemon `0.1.131` had a healthy, actively growing
Claude/Fable root transcript whose cloud session stopped advancing. The local
scan index still described the root's September 12 revision while the file and
its content-free OTEL ownership sidecars continued through September 14. The
latest collector receipt was fail-closed with a `parse_error`, and the scan
reported a candidate disappearing during the Claude authority prepass.

The authority prepass is source-wide whenever any Claude family is in the
durable authority quarantine. It opens candidates once to freeze the member
revisions used by the quarantined-family reconstruction, then opens candidates
again for parsing. The equality check between those phases was also applied to
unrelated healthy families. A healthy Fable session can legitimately advance
its transcript or shared usage/trace sidecars between the two opens, so an
unrelated old quarantine repeatedly prevented that live session from reaching
the parser.

## Fix

Keep the prepass-to-parse equality fence only for a candidate whose own root
family is present in `claude_usage_authority_quarantine`. The second open and
all ordinary opened-object validation remain authoritative for healthy
families. The quarantined family still requires an identical cross-member
snapshot and continues to fail closed on any change.

This changes no payload, parser semantics, privacy boundary, backend contract,
or release setting. It only prevents one family's quarantine from imposing its
cross-member freeze on unrelated live sessions.

## Verification

- `cargo fmt --all -- --check`
- `cargo test -p ottto-service claude_authority_ -- --nocapture`
- New unit coverage proves the quarantined family retains the exact preflight
  fingerprint while an unrelated healthy family does not inherit it.

