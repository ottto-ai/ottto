# Public daemon Claude config-slot foundation

**Date:** 2026-08-04
**Scope:** W3 Slice A only; no multi-account snapshot fanout or scheduler

This slice establishes the machine-local and local-control contracts needed for
future background upkeep of multiple Claude Code accounts. It deliberately does
not enumerate or poll the registered slots yet.

## Exact slot identity

`ottto-core::ClaudeConfigDirSlot` is the single boundary for a slot's Keychain
service name, plaintext identity file, and file-backed credential location.

- `Default` means `CLAUDE_CONFIG_DIR` is unset and uses the bare Keychain
  service `Claude Code-credentials`.
- A registered slot preserves the exact raw string. Service naming is
  `Claude Code-credentials-<suffix>`, where `suffix` is the first eight
  lowercase hexadecimal characters of SHA-256 over the string's NFC form.
- No `realpath`, canonicalization, tilde expansion, whitespace trimming, or
  trailing-slash removal occurs. `/path/account` and `/path/account/` remain
  distinct. NFC-equivalent strings resolve to the same credential service and
  are rejected together in one registry because they would be ambiguous.
- Independent known values are pinned in tests: `/Users/test/.claude` maps to
  `462977e4`, `/Users/test/.claude-work` to `03abf0ee`, and the same path with a
  trailing slash to `8bd6f0f5`.

The boundary is read-only. Existing default-slot token reads now obtain their
service name and credential path from it. macOS Keychain reads select both the
exact service and the daemon owner's account name resolved from its effective
UID; they do not depend on a LaunchAgent inheriting `$USER`. An unresolved or
empty account fails closed rather than accepting a same-service item for
another account. No code in this slice refreshes OAuth, writes Keychain, logs
in, runs setup, or invokes an agent/model.

## Versioned machine-local settings and consent

`~/Library/Application Support/Ottto/claude-config-slots.json` is an atomic,
owner-only (`0600`) settings file with schema version 1:

```json
{
  "schema_version": 1,
  "background_upkeep_consent": true,
  "registered_slots": [
    {
      "slot_id": "claude_slot_<opaque-id>",
      "ownership": "external",
      "config_dir": "/exact/value/used/by/CLAUDE_CONFIG_DIR"
    }
  ]
}
```

The absent-file state is `consent_required`, with no registered custom dirs.
The true default slot is implicit and always returned first. One explicit
`background_upkeep_consent` value governs the entire registry; there is no
beta/internal-customer gate and no inferred per-slot consent. Each public
mutation is applied through one internal read/validate/atomic-write transaction.
Validation rejects unsupported schemas, empty/NUL/oversized strings, more than
nine custom slots (ten total including the implicit default), exact duplicates,
service-name aliases, non-opaque or duplicate slot ids, and non-absolute
registered paths. Absolute-path validation does not normalize the value. It
does not require the path to exist, resolve it, or validate a login because
deterministic setup belongs to a later slice and remains an operator action.
Advanced path registration records `external` ownership; only a later setup
workflow may create a `managed` entry.

Authenticated local control adds:

- `claude_accounts_status`
- `claude_account_set_upkeep_consent { schema_version, consent }`
- `claude_account_register_path { schema_version, config_dir }` (Advanced)
- `claude_account_remove { schema_version, slot_id }`

All four use command-specific local-control protocol version 18 and reject the
base version 15. This prevents an older client from silently losing ownership
or opaque-id semantics.

Both accept the normal daemon control token or the already trusted Companion
identity. A missing/bad authority cannot read local paths or mutate consent.
No operation performs a refresh. The typed status separates consent, an idle
setup-operation placeholder, the default slot, managed slots, unresolved
accounts, external slots, and explicit capacity. The unresolved-account type
contains only an opaque unresolved id, an optional display-safe account hash,
and typed evidence; it has no path, slot, or Keychain service requirement.
Slice A returns that list empty. Exact raw paths remain in authenticated local
control and are never added to backend snapshot payloads. Automated
config-directory preparation and registration belong to a later slice.
Authentication does not: Ottto never runs or cancels `/login`; the user runs
the official Claude `/login`.

## Physical account state and migration

The existing Claude OAuth usage cache and circuit breaker were tagged with an
account hash but each still occupied one machine-global file. They now live in
separate physical account directories:

```text
<support>/claude-oauth-usage/accounts/<opaque-account-key>/usage-cache.json
<support>/claude-oauth-usage/accounts/<opaque-account-key>/breaker.json
```

The directory component is a domain-separated SHA-256 of the existing
display-safe account identifier hash; unresolved identity has its own explicit
`unresolved` directory. Account A and account B can coexist without overwriting
each other's cache or breaker. Cache and breaker writes reuse the core atomic
owner-only writer (`0600` file in a `0700` leaf directory). Per-account process
locks cover cache migration and the breaker's full read/modify/write transaction
so concurrent local-control work cannot lose failure counts or adopt the same
legacy file twice.

On first matching read, released global files
`claude-code-oauth-usage-cache.json` and `claude-oauth-usage-breaker.json` are
copied into the exact account store and removed only after the new write
succeeds. A legacy file for another account is left untouched so it cannot be
adopted or destroyed by the wrong identity. Schema, account, and breaker config
fingerprint checks remain fail-closed.

## Tests

- Exact default/custom service naming, NFC, raw path preservation, and trailing
  slash negative control, including an independently computed synthetic suffix
  vector.
- Settings default, stable opaque ids, typed ownership, absolute registration,
  exact-string round trip, ten-slot capacity, `0600` mode, schema/duplicate/
  service-alias rejection.
- Local-control wire round trip, bad-token rejection for every account
  operation, version-15 fail-closed checks, and authenticated
  register/consent/status/remove persistence.
- Physical cache coexistence plus cache and breaker legacy migration that
  refuses the wrong account; concurrent breaker RMW, concurrent single-copy
  migration, owner-only mode, atomic JSON, and symlink replacement safety.

No test fixture contains an OAuth access token, refresh token, login session,
cookie, or Keychain secret.
