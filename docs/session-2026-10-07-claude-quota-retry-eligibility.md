# Claude quota retry eligibility

A recent collector check-in does not make a retained provider quota reading fresh.
The existing `claude_oauth_usage_cache_reused` diagnostic now optionally carries
`retry_after`, a UTC RFC3339 clock describing earliest retry eligibility during an
evidenced rate-limit hold. It does not promise a scheduled or successful refresh.

The producer requires stale exact-account/organization cache evidence, a future
cache gate, matching breaker rate-limit evidence, a present locally unexpired
credential, and no competing caller auth or open circuit hold. Ordinary cache
reuse and missing, expired, auth-held, or foreign-organization evidence omit the
deadline. Quota values, original observation times, cache format, account binding,
network admission, polling cadence, and retry behavior are unchanged.

The registered-slot diagnostic sanitizer retains only a canonical clock following
the outcome's actual observation time, for an already matched account and
organization. Existing canonical diagnostic text remains static. Older wire
payloads omit the field or carry null. The protocol's heap accounting includes
the optional timestamp.

Focused synthetic tests exercise the disclosure boundary, including zero provider
calls and unchanged stale quota observations. Protocol tests cover old/null/new
decoding and backend-upload preservation. No live provider request is needed.

Release dependency: the receiving backend must accept the optional field before a
containing daemon release emits it. A backend that forbids unknown diagnostic
fields otherwise rejects the upload. Independent releases without this change
retain their existing sequence. Source validation alone is not installed UI or
backend acceptance proof.
