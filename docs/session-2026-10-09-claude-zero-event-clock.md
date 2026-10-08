# Claude OTLP log zero timestamps

JSON API-request logs with `timeUnixNano: "0"` previously reduced to
`1970-01-01`, even when `observedTimeUnixNano` was nonzero. Protobuf selected the
observed timestamp for event zero, but still created epoch evidence when both
fields were zero. Native regressions reproduced both failures before the fix.

Both encodings now select a nonzero unsigned event clock, otherwise a nonzero
observed clock. If neither is usable, the existing required-clock reduction
omits the row. Genuine positive instants, including one nanosecond after epoch,
remain unchanged. JSON strings and numeric clocks yield identical full rows and
fingerprints to protobuf; invalid unsigned JSON values cannot create event time.

This follows the [OTLP LogRecord definition](https://github.com/open-telemetry/opentelemetry-proto/blob/main/opentelemetry/proto/logs/v1/logs.proto)
and [log data model](https://opentelemetry.io/docs/specs/otel/logs/data-model/).
The existing v2 sidecar does not record event versus observer provenance, so its
selected timestamp cannot prove an original event clock. This correction adds
no provenance authority, capture revision, wall-clock fallback, historical
rewrite, or migration. Existing sidecar bytes and independent raw forwarding
remain unchanged. Incidence and installed acceptance are unknown; fixtures are
synthetic and no provider corpus was sampled.
