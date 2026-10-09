# Codex orphaned fence recovery

An orphan `# ottto:end` with no opening marker previously caused Verify to
recommend Repair while Repair refused the file, even when the remaining
exporters were Ottto's generated loopback exporters.

Cleanup now accepts a valid TOML document with exactly one real orphan end
marker and at least one recognized exporter before it. The exporter must use
an exact loopback `/v1/logs`, `/v1/traces`, or `/v1/metrics` endpoint, the sole
`X-Ottto-Local-Relay = "codex"` header, and binary protocol when specified.
Recognized exporters must share one nonzero port. The supported forms are
generated dotted inline assignments and a sole inline exporter under `[otel]`.
Cleanup removes only their original assignment byte ranges and the marker;
other fields, external exporters, comments, line endings, and table scope stay
unchanged. The existing backup and compare-before-replace writer is reused.

Malformed TOML, duplicate markers/tables, extra exporter fields/headers,
mixed inline parents, nested exporter sections, inconsistent ports, and
exporters after the marker require manual review without changing the file or
creating a backup. Marker-looking lines inside parsed string values are data.
Verify gives manual-review guidance instead of repeatedly recommending Repair
for a file Repair cannot safely modify. Normal complete fences and unfenced
cleanup retain their existing behavior.

Regression tests cover exact byte preservation, CRLF/LF, comments, user table
scope, external exporters, misleading marker strings, adversarial ownership,
repair/verify convergence, backup behavior, and idempotence. Tests use only
synthetic temporary files, never live Codex configuration or provider calls.

Release QA: on the next containing candidate, reproduce the orphan-end fixture
under each supported install owner; Verify should offer Repair, Repair should
remove only proven exporters, Verify should clear that drift, and a second
Repair should be unchanged. Ambiguous fixtures should retain every byte and
show manual-review guidance. Restarting an existing Codex process, if needed,
belongs to the separately authorized release QA. This change does not prove
live upload acceptance or stop an already running process's inherited config.
