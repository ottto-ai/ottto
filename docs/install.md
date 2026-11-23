# Install

Ottto installs a user-scoped macOS local runtime:

- `ottto`: public CLI for developers, support, CI, and agents.
- `ottto-service`: per-user daemon that owns local state, setup, repair,
  diagnostics, update, and uninstall behavior.
- `Ottto.app`: native macOS app when the release channel ships a signed app
  bundle.

Do not install by copying binaries from a mutable directory. Use the install
owner named by the release channel.

## Two Variants, One Per Mac

Ottto ships two install variants. Install one per Mac:

- **The app** (`Ottto.app`, from the DMG, the verified installer, or
  `brew install --cask ottto-ai/tap/ottto-app`): for a person at the Mac. It
  includes the CLI, runs the service from its bundle and updates itself.
- **Headless** (the `ottto-ai/tap/ottto` formula with `brew services`): for a
  Mac without the app, such as a server, an SSH-only Mac or a
  command-line-only setup.

Both use the per-user LaunchAgent `net.ottto.service`, so only one can run,
and the app wins:

- A headless service that starts while this user's installed `Ottto.app`
  (in `/Applications` or `~/Applications`) is running hands over: it waits,
  holding no state, for the app to take the service back, and serves if the
  app quits or does not take over within a few minutes. A `brew services
  start` or `restart` on that Mac is therefore harmless. While the app is
  quit, or if the app could not take the service over (it then restores the
  Homebrew service and offers Retry), the headless service keeps running, so
  the Mac is never left without a service.
- When the app finds the Homebrew copy, it shows one notice with one button
  that moves the service to the app and removes the formula
  (`brew services stop ottto`, the app's own service registration, then
  `brew uninstall ottto`). It never runs Homebrew without that click.
  The one exception: when its own takeover fails, it restarts the Homebrew
  service, so the Mac keeps a collector.
- `ottto doctor` names a second variant and its fix.

Moving between variants:

- **Headless to app:** install the app and open it, then use its button. By
  hand: `brew services stop ottto && brew uninstall ottto`, then open the app.
  Stop first: `brew uninstall` alone leaves launchd a job whose program is
  gone.
- **App to headless:** uninstall the app first (its own Uninstall, or
  `brew uninstall --cask ottto-app`), then install the formula and run
  `brew services restart ottto` (`start` reports "already started" while the
  app's old job is still loaded).

Normal install, launch, upgrade, restart and repair commands refresh only the
current owner's service; switching owners is the explicit migration above.

## Headless Homebrew Install

On a Mac without the app, install through the published tap and let Homebrew
own service lifecycle:

```bash
brew install ottto-ai/tap/ottto
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
Homebrew opt path. On a Mac with the app, don't run `brew services` for ottto
at all; remove the formula instead.

System Settings → General → Login Items lists the Homebrew service under the
name on its signing certificate, not under Ottto. Homebrew writes the
LaunchAgent from the formula's `service` block, which has no setting for the
app a background item belongs to (`AssociatedBundleIdentifiers`). The app and
hosted installs write that key themselves.

## Verified Native DMG Helper

When a stable release advertises a verified native installer helper, the
stable release manifest publishes the helper's immutable URL and SHA-256 under
`install_methods.verified_native_installer`. Download the helper from that URL
and check it against the manifest before running it. These commands use built-in
`plutil`, available on every supported macOS version (14 or later):

```bash
(
set -e
curl -fsSL https://install.ottto.net/ottto-local-platform/releases/stable/latest/release-manifest.json \
  -o release-manifest.json
helper_url="$(plutil -extract install_methods.verified_native_installer.url raw -expect string -o - release-manifest.json)"
helper_sha="$(plutil -extract install_methods.verified_native_installer.sha256 raw -expect string -o - release-manifest.json)"
curl -fsSL "$helper_url" -o install-macos.sh
printf '%s  install-macos.sh\n' "$helper_sha" | shasum -a 256 -c -
bash install-macos.sh
ottto status --json
)
```

Stop if any command fails, including extraction of a missing `sha256` or a
`shasum` mismatch. The SHA-256 is part of the signed manifest bytes, so
`release-manifest.json.sig` covers it; see
[Release Verification](release-verification.md).

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

## Uninstall

Uninstalling with `ottto uninstall` or Homebrew leaves Ottto's Open at Login
entry in System Settings → General → Login Items. It does nothing once the app
is gone; remove it there if you like. Uninstall from Ottto's Settings removes it
for you.

## Agent Notes

Agents may check `command -v ottto` and run `ottto status --json`. If the CLI is
missing on a customer machine, point the user to the active public install owner.
Do not use development install scripts unless the user explicitly asks for
internal QA on a trusted machine.
