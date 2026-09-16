# The Companion code requirement was optional, so in production it never ran

2026-09-16, found while auditing token-less local-control authorization.

## What it looked like

`ottto-service` lets the Companion app drive the local control API without the
0600 control token, if the connecting peer passes `companion_peer_is_trusted`.
That check has three layers:

1. the peer must run as the daemon's own effective uid (`getpeereid` on the unix
   socket, `xpc_connection_get_euid` on the Mach service);
2. the peer's code path, resolved through `SecCode::copy_guest_with_attribues`,
   must be one of `trusted_companion_paths()`;
3. the peer's signature must satisfy a code requirement.

Layer 3 was conditional:

```rust
let Some(requirement_text) = companion_code_requirement() else {
    return true;
};
```

and `companion_code_requirement()` only returned `Some` when
`OTTTO_COMPANION_CODE_REQUIREMENT` or `OTTTO_COMPANION_TEAM_ID` was set in the
daemon's environment. Nothing set either one. The installed LaunchAgent
(`~/Library/LaunchAgents/net.ottto.service.plist`) carries `PATH` and the socket
path, and neither the packaging scripts nor the Homebrew formula added a team
id. So on every real install, layer 3 was skipped and the answer was "yes" as
soon as the path matched.

`trusted_companion_paths()` includes `$HOME/Applications/Ottto.app`, which is
user-writable. Verified on macOS 15 by putting an ad-hoc-signed bundle with
`CFBundleIdentifier = net.ottto.Companion` at that path: the daemon accepted it
as the Companion.

## Why it was only part of a hole

Layer 1 keeps the blast radius small. To reach the PID check at all, a process
must already run as the daemon's uid — and a process with that uid can simply
read the 0600 control token out of the daemon's state directory. So this did not
let anyone cross a uid boundary. What it did do was make the signature check —
the thing that is supposed to say "this is *our* app" — dead code in production,
and the only reason a wrongly-signed build was ever rejected was that it sat at
the wrong path.

## Fix

The requirement is now baked into the binary at build time and enforced
unconditionally.

```rust
const OTTTO_COMPANION_DEFAULT_TEAM_ID: &str =
    match option_env!("OTTTO_COMPANION_DEFAULT_TEAM_ID") {
        Some(team_id) => team_id,
        None => "YRNP9UD7WY",
    };
```

`companion_code_requirement()` resolves, in order: the
`OTTTO_COMPANION_CODE_REQUIREMENT` env var, the `OTTTO_COMPANION_TEAM_ID` env
var, then the baked-in team id. Blank values are treated as unset and fall
through to the next source, so an empty env var cannot silently switch
enforcement off. The result is an enum with exactly two shapes:

```rust
enum CompanionCodeRequirement {
    Enforced(String),
    Disabled,
}
```

There is no "trust the path, skip the signature" outcome any more. A build with
no baked-in team id and no override resolves to `Disabled` and grants no
token-less Companion trust at all, rather than degrading to path-only trust.

The team id is not a secret: it is the `subject.OU` of the Developer ID
certificate in every signed release, printed by `codesign -dv --verbose=4
/Applications/Ottto.app`. Baking it in, rather than having the installer write
`OTTTO_COMPANION_TEAM_ID` into the LaunchAgent, is deliberate:

- the LaunchAgent plist is user-writable, so it is a poor place to keep the
  control that decides who is trusted;
- an install that predates any installer change still gets enforcement as soon
  as the daemon binary is updated;
- an installer regression cannot silently turn enforcement off again, which is
  exactly how the original hole appeared.

Forks override it at build time:

```
OTTTO_COMPANION_DEFAULT_TEAM_ID=ABCDE12345 cargo build --release -p ottto-service
```

Building with an empty value disables token-less Companion trust instead of
weakening it.

## Blast radius: the Companion has no token fallback

`LocalDaemonClient` sends `token: nil` on every request — token-less trust is
the Companion's only auth path, not a fast path with a fallback. So a Companion
that fails the requirement does not degrade; it stops working, with an opaque
`local_client_not_trusted`. That cuts both ways:

- the Developer ID signed app had to be validated against the real code path
  before this could ship (see Validation below), and
- an internal tester running an ad-hoc-signed dev build loses the app entirely
  until their LaunchAgent carries the override.

The daemon therefore logs, once per run, when something at a trusted Companion
path fails the requirement, and names the dev flag in the message. Without that
the only symptom is an app that silently does nothing.

## Developing against a dev Companion

`scripts/macos_package.sh` ad-hoc seals dev and preview bundles, and an ad-hoc
signature carries no Apple team, so a locally built Companion cannot satisfy the
Developer ID requirement. The replacement for "copy the dev build to
`~/Applications/Ottto.app` and it just works" is an explicit override in the dev
LaunchAgent:

```bash
./scripts/macos_dev_install.sh --bootstrap-launch-agent --trust-dev-companion
```

That writes `OTTTO_COMPANION_CODE_REQUIREMENT` into the LaunchAgent's
`EnvironmentVariables`:

```
identifier "net.ottto.Companion"
```

— same bundle identifier, no team assertion. The daemon prints a warning when it
writes that override, and `macos_dev_install.sh` tells you to pass the flag when
it installs a bundle that is not Developer ID signed. Customer installs never
get the key: `LaunchAgentConfig::companion_code_requirement` defaults to `None`
and a blank value is not written at all.

Setting the env var in your own shell does not help — the daemon runs under
launchd and does not inherit it.

## Validation

On a Mac with the real signed app installed, against the shipped code path
(`trusted_companion_pid`, `SecCode` + `check_validity`), not just `codesign`:

| Peer | Default build | With `OTTTO_COMPANION_CODE_REQUIREMENT` |
| --- | --- | --- |
| `/Applications/Ottto.app` (Developer ID, notarized) | trusted | trusted |
| ad-hoc-signed bundle at `~/Applications/Ottto.app` | **rejected** | trusted |
| the test binary itself | rejected | rejected |

The first row is the one that matters for "do not break legitimate signed
Companion auth". The second is the finding, closed.

## PID-reuse TOCTOU: still open, now less interesting

`kSecGuestAttributePid` identifies the guest by a recyclable PID; the robust fix
is `kSecGuestAttributeAudit` with the peer's `audit_token_t`. That is still not
wired up, for the reasons already recorded in `control.rs`: `set_audit_token`
wants a `CFDataRef`, which means taking `core-foundation` as a direct dependency
and writing the audit-token FFI, and the XPC side needs
`xpc_connection_get_audit_token`, a libxpc symbol that is not declared in the
public SDK. Getting that wrong breaks legitimate Companion auth, which is worse
than the bug.

Enforcing the requirement shrinks the payoff. Winning the PID race is no longer
enough: whatever process holds the recycled PID must also live at a trusted
Companion path *and* carry a valid Ottto Developer ID signature — that is, it
must be the real Companion. The residual is "a same-uid attacker substitutes one
legitimately signed Ottto build for another", against a principal who can
already read the control token.

## Tests

- `control.rs`: the resolver's precedence (requirement override, team id
  override, baked default), blank inputs falling through instead of disabling
  enforcement, `Disabled` when nothing supplies a requirement, no input
  combination yielding path-only trust, the shipped constant being non-empty and
  reaching `companion_code_requirement()`, and both shipped requirement strings
  parsing as `SecRequirement`s.
- `macos_service.rs`: a customer LaunchAgent carries no
  `OTTTO_COMPANION_CODE_REQUIREMENT` key, a dev one does, and a blank override
  is not written.
