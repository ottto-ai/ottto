# Claude browser-auth supervisor support-directory fix

**Date:** 2026-09-10
**Scope:** Public Claude browser-auth supervisor

Stable `0.1.128` proved the Companion UI and authorization-code state machine,
but a production-shaped Add Claude account attempt failed before the official
CLI could open a browser. The parent daemon prepared and journaled the exact
isolated operation correctly. Its hardened supervisor then started with an
empty environment and did not receive `HOME` or an explicit Ottto support
directory. `default_support_dir()` therefore fell back to the temporary
directory, could not find the parent operation journal, and exited before
launching Claude Code.

The daemon now resolves its support directory before clearing the supervisor
environment and passes that exact path through
`OTTTO_LOCAL_PLATFORM_SUPPORT_DIR`. The provider subprocess remains separately
sanitized by the existing exact-slot command builder; no provider credentials,
browser state, or ambient token-shaped variables are added to the supervisor.

Regression coverage removes the explicit test override and asserts that a
production-shaped `HOME` still becomes an explicit support-directory binding
after the supervisor environment is cleared. Existing PTY interactivity,
authorization-code forwarding, parent-EOF termination, and provider-lifetime
tests remain green.
