# Managed Claude relay settings

Managed Claude account roots previously collected transcripts without receiving
the Claude relay environment installed in the default settings file. Ordinary
sessions in those roots could therefore omit forward local telemetry.

The service now extends the existing canonical relay environment to managed
setup/reconnect roots and provisional browser roots before login starts. Source
install/config repair and explicit status refresh reconcile registered managed
roots. Advanced external paths remain outside this settings lifecycle. Provisioning
rechecks current registration or the exact active provisional browser root.
Removing a managed registration clears owned relay settings before forgetting
its ownership; unsafe settings prevent removal so cleanup can be retried.
Browser retirement, duplicate-target settlement and admission rollback use the
same serialized cleanup before registration removal.

Provisioning requires the non-secret device binding to select `claude_code`,
existing approved default relay settings, a local machine binding, and no
`OTTTO_PATCH_CLAUDE_CODE_DISABLED` opt-out. It uses the approved loopback relay
port and existing renderer, including JSON logs and the local relay header.
It does not inspect credentials, call providers, or infer account attribution.

Managed writes are env-only. Unrelated settings, status-line commands and env
keys survive. Explicit per-root off values, signal opt-outs and external telemetry configurations
are preserved. Invalid JSON and unsafe paths fail closed; edits are rechecked before commit.
The bounded writer opens path components and files without following symlinks,
rejects hard-linked/non-regular files, serializes writers, and replaces settings
atomically through a private unique temporary file. Replays keep existing bytes.

Authorized Disable removes owned relay entries from registered managed roots
and saves an explicit off setting in the default JSON, preventing refresh from
re-enabling telemetry. Authorized Enable restores default approval while keeping
root-specific user opt-outs. Existing backend authorization remains unchanged.
Cleanup recognizes individual canonical relay values and exact signal endpoints.
Custom protocols, exporters and resource attributes survive; external collectors
retain the protocol/exporter settings their preserved routes depend on.
Refresh requires approval before status-line repair and preserves customized
telemetry defaults, preventing that repair from creating managed-folder approval.

Validation uses synthetic settings/registry/machine/device fixtures and native
filesystem tests with network and sensitive live stores denied. Hosted CI covers
the runtime workspace and existing control contracts. Source validation does
not establish installed acceptance: the containing release must demonstrate an
ordinary new managed-folder session emitting the approved local telemetry.
Historical request evidence is not reconstructed by settings provisioning.
