# Multi-user app launch and diagnostics app version

A second macOS user could not open Ottto while another user had it open.
Finder showed "You can't open the application because someone else is using
it". The packaged Info.plist declared `LSMultipleInstancesProhibited`. Apple
documents that key as "whether more than one user can launch the app
simultaneously". Launch Services rejects a launch from another session with
`kLSMultipleSessionsNotSupportedErr`, so the key enforced a machine-wide limit
where only a per-user one was intended. Packaging no longer declares the key.
The app still runs as one process per user. The service, LaunchAgent (`gui/<uid>`
domain), control socket and support directory are all under the user's home.
The local OTLP relay already falls back to a per-user port when another user
holds the default.

The shared app bundle is the one cross-user surface. Sparkle does not
coordinate updaters across processes. After one user's update replaces the
bundle, another user's running app and service keep the old code until they
relaunch. No automated gate covers this case. Release verification now says
multi-user updates must not be called verified without a manual two-user check.

Diagnostics previously reported `versions.app_version` as the literal
`unknown`. The value now comes only from an Info.plist whose identifier is
`net.ottto.Companion`:

- an app-owned service reports its enclosing bundle;
- a Homebrew, installer or development service reports the app in
  `~/Applications` or `/Applications` when every copy agrees.

Anything else stays `unknown`, and the service or CLI compiled version is
never used. The reader accepts plain XML only, at most 64 KiB, nested at most
16 collections deep, with no comments, CDATA, processing instructions,
namespaces, attributes or other DOCTYPEs. It deserializes just the two keys.
Binary plists are refused because their shared references can expand far
beyond the file size. Unit tests use synthetic bundles and never read the
host's bundles. No Keychain or process state is read.

Validation:

- the packaging fixture asserts that the rendered Info.plist omits the key;
- it fails against the previous script;
- unit tests cover app-owned, Homebrew-coexisting, conflicting, foreign,
  missing, malformed, binary and hostile XML inputs.

Not verified:

- installed behavior;
- a signed release;
- launching from Finder in two real macOS users;
- multi-user Sparkle updates.
