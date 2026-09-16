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
user-writable. Verified by putting an ad-hoc-signed bundle with
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

## The constraint that shaped the fix

`LocalDaemonClient` sends `token: nil` on every request. Token-less trust is the
Companion's only auth path, not a fast path with a fallback. A Companion that
fails the requirement does not degrade; it stops working, with an opaque
`local_client_not_trusted`.

That makes "just enforce Developer ID" too blunt. `macos_package.sh` ad-hoc
seals dev, preview, and RC artifacts, and an ad-hoc signature carries no Apple
team, so a flat Developer ID rule would break every internal tester the moment
they took a new daemon.

The obvious patch — have the installers write `OTTTO_COMPANION_TEAM_ID` or an
override into the LaunchAgent — does not hold either:

- the LaunchAgent plist is user-writable, so it is a poor place to keep the
  control that decides who is trusted;
- `LocalServiceRegistrar.runBundledServiceBootstrap` in the Companion re-runs
  `service bootstrap` on refresh and recovery, rewriting the plist without any
  override, so an app-owned install would silently lose it;
- an installer regression cannot be detected, which is exactly how the original
  hole appeared.

Anything a human or an installer has to remember will be forgotten. The decision
has to live in the artifact.

## Fix

The daemon derives the requirement from its own code signature.

```rust
const OTTTO_COMPANION_DEFAULT_TEAM_ID: &str =
    match option_env!("OTTTO_COMPANION_DEFAULT_TEAM_ID") {
        Some(team_id) => team_id,
        None => "YRNP9UD7WY",
    };
```

`resolve_companion_code_requirement` then applies, in order:

1. `OTTTO_COMPANION_CODE_REQUIREMENT` — a full requirement string.
2. `OTTTO_COMPANION_TEAM_ID` — a team id to build the standard requirement from.
3. an empty baked-in team id — a fork opting out; fails closed, no token-less
   trust at all.
4. **this daemon is itself signed by the baked-in team** → the Companion must be
   `identifier "net.ottto.Companion" and anchor apple generic and certificate
   leaf[field.1.2.840.113635.100.6.1.13] and certificate leaf[subject.OU] =
   "<team>"`.
5. otherwise → the Companion must be `identifier "net.ottto.Companion"`.

Blank env values are treated as unset and fall through, so an accidentally-empty
var cannot silently change the outcome. The result is an enum with exactly two
shapes — `Enforced(String)` and `Disabled` — so there is no "trust the path, skip
the signature" outcome any more.

Rule 4 vs 5 is the whole point. The daemon and the Companion beside it come out
of the same `macos_package.sh` run and carry the same kind of signature, so the
daemon's own signature already says which kind of install this is:

| Installed daemon | Companion must be |
| --- | --- |
| Developer ID signed (stable, Homebrew) | Developer ID signed, same team |
| ad-hoc sealed (dev, preview, RC) | signed with identifier `net.ottto.Companion` |

Nothing in the installers, the LaunchAgent, or the app's own re-bootstrap has to
carry the decision, and no tester has to be told anything.

Be honest about rule 5: on Apple Silicon every running process already carries
at least an ad-hoc signature, and whoever can place a bundle at a trusted path
also writes its `Info.plist`, so the identifier is not a boundary against a
deliberate attacker. Internal builds keep exactly the posture they have today —
same-uid only. The real boundary lands where the customers are. Tightening rule 5
further would mean pinning a cdhash the daemon cannot know for an app it does
not ship with, and that pin would break on the next Sparkle update.

All three clauses in rule 4 matter, and `subject.OU` alone is the trap. A code
requirement only checks the fields it names, so
`certificate leaf[subject.OU] = "TEAM"` on its own is satisfied by *any*
certificate carrying that OU — including a self-signed one, and the team id is
public. A same-uid attacker could mint a cert with `OU=YRNP9UD7WY`, sign a
bundle as `net.ottto.Companion`, drop it at `~/Applications/Ottto.app`, and pass
the "Developer ID" rule — reopening the exact hole this change closes.
`anchor apple generic` forces the chain back to Apple, and the leaf marker OID
`1.2.840.113635.100.6.1.13` makes it Developer ID rather than a development or
Mac App Store certificate from the same team. This is the shape of Apple's own
generated designated requirement; `codesign -d -r- /Applications/Ottto.app`
prints it. The first draft of this change carried the bare `subject.OU` clause
inherited from the old `OTTTO_COMPANION_TEAM_ID` path — where it was at least
opt-in — and promoting it to the default is what made it a real defect. A unit
test now asserts both clauses are present in every requirement the daemon builds.

The team id is not a secret: it is the `subject.OU` of the Developer ID
certificate in every signed release, printed by `codesign -dv --verbose=4
/Applications/Ottto.app`. Forks override it at build time:

```
OTTTO_COMPANION_DEFAULT_TEAM_ID=ABCDE12345 cargo build --release -p ottto-service
```

Building with an empty value disables token-less Companion trust instead of
weakening it.

## The one combination that needs a flag

A Developer ID daemon next to a locally built app — for example testing app
changes against an already-installed Homebrew daemon. That is a genuine
mismatch, and it is explicit:

```bash
./scripts/macos_dev_install.sh --bootstrap-launch-agent --trust-dev-companion
```

which passes `--companion-code-requirement 'identifier "net.ottto.Companion"'`
to `service write-launch-agent` / `service bootstrap`, writing
`OTTTO_COMPANION_CODE_REQUIREMENT` into the LaunchAgent's
`EnvironmentVariables`. The daemon warns when it writes that override, and the
installer only prints its "rerun with --trust-dev-companion" hint for that exact
mismatch, so a normal dev install stays quiet. Customer installs never get the
key: `LaunchAgentConfig::companion_code_requirement` defaults to `None` and a
blank value is not written at all.

Setting the env var in your own shell does not help — the daemon runs under
launchd and does not inherit it.

When the daemon does refuse, it says so once per run in
`~/Library/Logs/Ottto/ottto-service.err.log`, naming the path, the reason, and
which of the two expectations applied. Without that the only symptom is an app
that silently does nothing.

## Validation

On a Mac with the real signed app installed (`/Applications/Ottto.app`,
Developer ID `YRNP9UD7WY`, notarized, stapled), driving the shipped code path —
`trusted_companion_pid` → `SecCode` → `check_validity` — not `codesign`. The
"release daemon" column is a test binary re-signed with the Developer ID
identity; the "internal daemon" column is the ordinary `cargo test` binary,
which is ad-hoc.

| Peer | Internal daemon | Release daemon |
| --- | --- | --- |
| `/Applications/Ottto.app` (Developer ID) | trusted | trusted |
| ad-hoc bundle at `~/Applications/Ottto.app` | trusted | **rejected** |
| with `OTTTO_COMPANION_CODE_REQUIREMENT` set | trusted | trusted |
| the test binary itself | rejected | rejected |

Row 1 is "do not break legitimate signed Companion auth". Row 2, right column,
is the finding, closed; row 2, left column, is the internal tester who is not
disturbed by closing it.

The anchored requirement was checked directly against the real artifacts too:
it accepts `/Applications/Ottto.app`, the bundled
`Contents/Helpers/ottto-service`, and the Homebrew
`/opt/homebrew/opt/ottto/bin/ottto-service`; it rejects the same app under a
different team id, and the daemon self-requirement rejects an Apple-signed
system app, which shows the Developer ID leaf marker bites rather than passing
anything Apple-chained.

Not reproduced: signing a bundle with a self-signed `OU=YRNP9UD7WY`
certificate, which is what the missing-anchor defect would have accepted. Doing
that needs an identity in the keychain search list, i.e. changing the operator's
keychain configuration for a test. The evidence stands without it — Apple's own
designated requirement for this app pins the anchor and the leaf marker
alongside the OU, which is only necessary if the OU clause alone is
insufficient.

`daemon_is_release_signed()` was also confirmed on both binaries directly:
`false` for the cargo build, `true` after `codesign --sign "Developer ID
Application: …"`. A release `cargo build --release` embeds the team id, and
`OTTTO_COMPANION_DEFAULT_TEAM_ID=… cargo build --release` replaces it (the
`rerun-if-env-changed` in `build.rs` makes the rebuild happen).

## PID-reuse TOCTOU: still open, now less interesting

`kSecGuestAttributePid` identifies the guest by a recyclable PID; the robust fix
is `kSecGuestAttributeAudit` with the peer's `audit_token_t`. That is still not
wired up, for the reasons already recorded in `control.rs`: `set_audit_token`
wants a `CFDataRef`, which means taking `core-foundation` as a direct dependency
and writing the audit-token FFI, and the XPC side needs
`xpc_connection_get_audit_token`, a libxpc symbol that is not declared in the
public SDK. Getting that wrong breaks legitimate Companion auth, which is worse
than the bug.

Enforcing the requirement shrinks the payoff on customer installs. Winning the
PID race is no longer enough there: whatever process holds the recycled PID must
also live at a trusted Companion path *and* carry a valid Ottto Developer ID
signature — that is, it must be the real Companion. The residual is "a same-uid
attacker substitutes one legitimately signed Ottto build for another", against a
principal who can already read the control token.

## Tests

- `control.rs`: every requirement the daemon can build carrying
  `anchor apple generic` plus the Developer ID leaf marker as well as the team
  OU; each resolution rule, including a release daemon requiring the team and an
  internal daemon not requiring it with otherwise identical inputs;
  blank inputs falling through; `Disabled` only for a fork that bakes in no team;
  no input combination yielding path-only trust; the shipped constant being
  non-empty and reaching `companion_code_requirement()`; every requirement string
  the daemon can produce parsing as a `SecRequirement`; and an anchor asserting
  the `cargo test` binary is not release-signed, so the branch those tests
  exercise is known.
- `macos_service.rs`: a customer LaunchAgent carries no
  `OTTTO_COMPANION_CODE_REQUIREMENT` key, a dev one does, and a blank override is
  not written.
- `scripts/test_macos_installer_channel_policy.sh`: the `--trust-dev-companion`
  escape hatch cannot be dropped without failing, since the daemon's refusal
  message and the docs both point at it.
