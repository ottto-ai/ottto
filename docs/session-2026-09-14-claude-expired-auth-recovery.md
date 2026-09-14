# Claude expired-login recovery

Claude Code can fail a bounded smoke command with an explicit expired OAuth
session while the Ottto account and Mac binding remain healthy. The runtime
previously reduced that diagnostic to `smoke_command_failed`, leaving clients
unable to distinguish provider re-authentication from config, network, or
setup-run failures.

The verification boundary now recognizes a narrow set of explicit Claude
expiry diagnostics and emits:

- status `reconnect_required`;
- message/error code `claude_oauth_reauth_required`;
- customer-safe guidance that Ottto itself remains connected; and
- recommended action `reauth_provider`.

This classification is source-scoped. It never mutates the local Ottto account
or setup-run binding. Provider re-auth also takes presentation priority over
simultaneous telemetry config drift, so consumers do not send customers into a
generic repair or Mac-claim loop before fixing the failed login.

Focused tests cover the live diagnostic (`OAuth session expired and could not
be refreshed`), the `/login` wording variant, negative network/quota cases,
the `reconnect_required` result, provider action projection, and preservation
of the connected Ottto account.
