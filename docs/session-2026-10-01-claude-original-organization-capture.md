# Claude original organization evidence capture

The Collector previously kept Claude request account evidence but dropped its organization, and its Desktop title index collapsed different organizations under the same account. This change preserves optional local account/organization evidence using the existing canonical provider hash and bounded index.

Request evidence records resource and log-record origins separately, including missing, invalid and conflicting UUID observations. It remains a request observation, not a declaration of original whole-session ownership or subscription membership. The existing usage-ledger revision and request counters stay unchanged. An otherwise identical old/new request replay retains the richer evidence once; differing observed identities or usage still fail strict reconciliation.

Desktop entries retain the native account and organization directory pair separately from coding paths. Any importedFrom marker marks destination evidence as imported. The provider stores this marker as an origin string and creates a new session id, so it does not identify the original imported account or organization. Incomplete and conflicting buckets remain explicit. New local fields contain hashes and a boolean, without raw identity or import labels. Legacy entries without the optional field keep their old fingerprint.

This is local capture and retention only. Session upload contracts, automatic subscription binding, money arithmetic, billing and production state are unchanged. Actual emitted CLI organization coverage, original-session continuity, the paired upload contract and source-to-screen acceptance remain separate validation requirements.

Validation on the combined runtime change:

- Actual service tests: 22 selected Claude Desktop tests, 20 local OTLP tests and one late account-evidence reselection test passed, offline.
- New counterexamples cover resource/log conflicts, malformed UUIDs, same-account/different-organization evidence, imported metadata, strict request replay and legacy omitted evidence.
- Existing canonical UUID and provider hash owners are reused; no new loader, index or store.

Independent review identified unsupported identity AnyValue presence being dropped. JSON/protobuf extraction now preserves that presence as invalid without retaining opaque content; symmetric actual decoding regressions cover it.
