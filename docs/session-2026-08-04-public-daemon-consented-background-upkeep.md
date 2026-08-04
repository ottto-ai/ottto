# Public daemon consented Claude background upkeep

**Date:** 2026-08-04
**Scope:** W3 Slice C public daemon runtime, local protocol, tests, and docs

## Runtime contract

The existing per-user `net.ottto.service` daemon now gives registered custom
Claude Code config slots a lazy post-expiry freshness opportunity at startup,
after the existing macOS wake/network-transition debounce, and immediately
before ordinary quota collection. The Companion app does not need to stay
open, and no scheduler or LaunchAgent was added.

Eligibility requires the persisted machine-level consent, the existing
subscription-usage network switch to be on, an expired exact access deadline,
and an unelapsed absolute refresh deadline. The true default slot is never
eligible. Consent, registrations, caches, and credential files remain unchanged
when collection is paused or an attempt fails.

The only process shape is the already-resolved installed Claude binary with
argv `doctor`. It reuses the exact-slot sanitized command builder used by auth
observation: cleared environment, effective `HOME`/`USER`, resolved `PATH`, safe
locale, exact raw `CLAUDE_CONFIG_DIR`, closed stdin, discarded stdout/stderr,
and a 20-second timeout. There is no shell, prompt, model/inference flag, login
subcommand, raw OAuth call, Keychain mutation, Desktop decryption, or statusLine
change. Exit zero is insufficient: a second read-only credential metadata
observation must prove the access expiry advanced beyond the claimed due expiry
and current time before collection proceeds with the refreshed credential.

## Durable admission and rollback

An owner-only versioned state file maps opaque slot ids to the due access
expiry, absolute refresh expiry, attempt time, next allowed time, typed result,
and consecutive failure count. It contains no token, token fingerprint, raw
account identifier, or config path. A process mutex plus exclusive filesystem
lock wraps validation and atomic claim-before-spawn. Completion compare-checks
the exact due expiry and attempt. A crash therefore leaves a durable claim;
restart cannot repeat it before backoff, and a fresh post-crash credential
prevents another probe even if completion was never recorded.

Same-expiry failures may retry only after five-minute exponential backoff,
capped at six hours. A new access-expiry boundary is independent. The
absent-by-default `claude-background-upkeep-disabled` sentinel stops only new
`doctor` processes for operational rollback; the customer network switch still
controls provider reads and upkeep together. A downgrade ignores the separate
upkeep witness and preserves the existing registration/consent schema, managed
directories, and account caches.

## Local status and validation

Command-scoped protocol v18 gains an optional secret-free upkeep witness plus
typed results/states for due, not consented, stale/backoff, probe failure,
approaching relogin, and needs login. No backend snapshot field or global
protocol version changed. An absolute refresh deadline within 72 hours is
reported as advisory upkeep metadata without replacing a successful `fresh`
quota state; an elapsed deadline is the blocking `needs_login` state.

Focused fixtures cover pre-expiry refusal, exact expiry, expiry-advance proof,
exit-zero-without-advance, process failures/timeouts, consent/network/kill
switches, default-slot exclusion, deadline states, thread and true-process
single-flight, crash/restart/backoff, startup+wake+collection storms, shared
sanitized argv/environment/stdio, output secrecy, sibling independence, and
downgrade preservation. The isolated experiment fixture uses synthetic paths
and deadlines only; no operator credential, token, or machine path is included.
