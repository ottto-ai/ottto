# Retain the stale older upload rejection reason

The server can refuse an older snapshot revision with
`accepted_log_stale_older_upload`. The local response sanitizer and receipt
reason vocabulary previously reduced this recognized reason to `other`.
Register the exact token in both existing mappings and the closed diagnostic
enum, including its exhaustive heap-accounting match.

This changes reason disclosure only. Unknown wire reasons still become `other`;
old `other` receipt evidence still decodes. Exact entity partitions, body and
fingerprint checks, destination binding, permanence, retry and quarantine
decisions, accepted witnesses and terminal health are unchanged. A refusal is
not acceptance, and the reason alone does not prove all refused contributions
exist in a stored revision.

Regressions cover the token through a validated rejected receipt and JSON
roundtrip, retained rejection/permanence/fingerprint evidence, rejection of a
foreign fingerprint, sanitization of unknown reasons and old `other` decoding.
Existing mixed-partition, invalid-ACK and settlement tests remain in scope.

No live receipt or terminal witness is collected here. Settlement-to-terminal
binding and missing-tail conservation remain unproved when that evidence is
absent. No status-copy, provider, configuration or lifecycle change is included.
