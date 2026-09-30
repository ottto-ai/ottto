# Claude stale authentication-root selection

The generic **Add Claude account** path previously stopped at the first
unclaimed provisional root retained in the browser-auth sidecar. If that record
belonged to an older support directory and its directory no longer existed, the
strict managed-root validator rejected it before the official Claude login could
start. Later valid reusable roots and the existing fresh-root path were never
considered.

Reusable-root discovery now skips unusable **unclaimed** records without
rewriting their paths, aliases, sidecar records, or filesystem locations. It
then uses a later valid unclaimed root or lets the existing bounded allocator
create a fresh root under the current managed parent. The existing validator
may still enforce owner-only `0700` mode on a same-parent candidate before a
later eligibility check rejects it. Claimed replays remain bound to their
original exact root and still fail closed when that root, alias, registration, or
pending-removal state cannot be revalidated. The direct-parent, no-symlink,
owner-only, service-alias, canonical-registration, ceremony, and capacity
guards are unchanged.

Focused tests reproduce a missing root under a retired support directory,
verify fresh current-root preparation, verify selection of a valid candidate
after an invalid one, and verify strict same-operation replay failure. The full
Claude browser-auth module tests and the existing managed-root ownership and
symlink tests pass. No stored account, credential, provider config, or
quarantined directory is migrated, deleted, or rewritten.
