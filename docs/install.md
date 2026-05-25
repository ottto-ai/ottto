# Install

Ottto installs a user-scoped macOS local runtime:

- `ottto`: public CLI for developers, support, CI, and agents.
- `ottto-service`: per-user daemon that owns local state, setup, repair,
  diagnostics, update, and uninstall behavior.
- `Ottto.app`: native macOS app when the release channel ships a signed app
  bundle.

Do not install by copying binaries from a mutable directory. Use the install
owner named by the release channel.

## LaunchAgent Ownership

`net.ottto.service` is a single-owner user LaunchAgent. Normal install, launch,
upgrade, restart, and repair commands may refresh only the current owner. A
Homebrew-owned LaunchAgent stays managed by `brew services`; a signed
`Ottto.app` launch connects to that service instead of rewriting the plist. To
switch owners, stop or uninstall the old owner first, or run an explicit
operator migration command with the new owner selected. Do not install both the
app bundle and Homebrew as independent service owners.

## Homebrew Install Owner

When a stable release advertises Homebrew support, install through the published
tap and let Homebrew own service lifecycle:

```bash
brew install <published-tap>/ottto
brew services start ottto
ottto status --json
```

Update and uninstall through Homebrew:

```bash
brew update
brew upgrade ottto
brew services restart ottto
brew services stop ottto
brew uninstall ottto
```

The formula must pin immutable artifact URLs and SHA-256 hashes from the stable
release manifest. Do not self-overwrite a Homebrew-managed install; use
`brew services restart ottto` after upgrades so launchd points at the updated
Homebrew opt path.

## Verified Native DMG Helper

When a stable release advertises a verified native installer helper, download
the public script from the release notes and verify the published checksum
before running it:

```bash
curl -fsSL <published-install-macos-url> -o install-macos.sh
shasum -a 256 install-macos.sh
sh install-macos.sh
ottto status --json
```

The helper verifies and opens the signed native DMG or PKG. It must not install
mutable shell payloads, clear quarantine, or bootstrap launchd itself. After the
user installs from the DMG or PKG, the runtime install owner is `app_bundle`.

## Direct Native Package

If release notes provide a DMG or PKG directly, verify the SHA-256 from the
release manifest before opening it:

```bash
shasum -a 256 Ottto.dmg
open Ottto.dmg
```

After installation:

```bash
ottto status --json
ottto update check --json
```

## Agent Notes

Agents may check `command -v ottto` and run `ottto status --json`. If the CLI is
missing on a customer machine, point the user to the active public install owner.
Do not use development install scripts unless the user explicitly asks for
internal QA on a trusted machine.
