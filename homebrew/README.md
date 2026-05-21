# Ottto Homebrew Tap Contract

This directory documents the Homebrew tap publishing path for the Ottto local
platform. The tap formula is generated from a stable
`release-manifest.json`; do not hand-write URLs or checksums.

The intended public tap is `ottto-ai/homebrew-ottto`, which Homebrew users
install through the short tap name `ottto-ai/ottto`:

```bash
brew install ottto-ai/ottto/ottto
brew services start ottto
ottto --no-autostart status --json
```

Homebrew documents taps as Git repositories that can store formulae under a
`Formula/` directory, and formulae support pinned `url`/`sha256`, `service do`,
`test do`, and `caveats` blocks. Keep the generated formula in
`Formula/ottto.rb` in the tap repository.

## Generate Formula

After `macos_package.sh`, notarization, `macos_release_gate.sh`, and
`macos_stable_preflight.sh` pass for the exact stable manifest, generate the
tap formula:

```bash
tools/ottto-local-platform/scripts/homebrew_formula.sh \
  --manifest tools/ottto-local-platform/dist/macos/release-manifest.json \
  --output /path/to/homebrew-ottto/Formula/ottto.rb
```

The generator refuses a manifest unless it:

- uses schema version `1`, product `ottto-local-platform`, and channel
  `stable`
- advertises `homebrew` in `supported_install_owners`
- points rollback metadata at the immutable stable version prefix and stable
  `latest/release-manifest.json`
- includes exactly one macOS CLI artifact and exactly one macOS daemon artifact
  for Apple Silicon
- pins HTTPS zip artifact URLs under the rollback immutable prefix, not
  `latest/`
- carries 64-character lowercase SHA-256 values
- marks CLI and daemon artifacts as signed, notarized, and Gatekeeper-assessed

The formula installs the public CLI as `ottto` and the service executable as
`ottto-service`. Current release archives still carry the daemon helper inside
the daemon resource; the formula renames the installed executable and does not
install a public `ottto-service` alias.

## Service Lifecycle

The Homebrew formula owns the per-user launchd service label
`net.ottto.service`. It runs:

```bash
ottto-service serve --socket "$HOME/Library/Application Support/Ottto/ottto-service.sock"
```

Use Homebrew to manage that service:

```bash
brew services start ottto
brew services restart ottto
brew services stop ottto
```

The CLI should be checked after the service starts:

```bash
ottto --no-autostart status --json
```

The current CLI autostart path still targets the app/dev LaunchAgent while
Phase 2 service identity work is incomplete. For Homebrew installs, start the
service with `brew services start ottto` instead of relying on CLI autostart.

## Update And Uninstall

Homebrew-managed installs update only through Homebrew:

```bash
brew update
brew upgrade ottto
```

Stop the service before uninstalling:

```bash
brew services stop ottto
brew uninstall ottto
```

Do not make `ottto update` overwrite Homebrew-managed files. Runtime update
checks should keep reporting the owner-aware command:

```bash
brew update && brew upgrade ottto
```

## Tap QA

Run these checks from a clean Apple Silicon Mac before publishing a stable tap
change:

```bash
cd /path/to/homebrew-ottto
ruby -c Formula/ottto.rb
brew update
brew install --build-from-source ./Formula/ottto.rb
brew services start ottto
ottto --no-autostart status --json
brew services restart ottto
ottto --no-autostart doctor --json
brew update && brew upgrade ottto
brew services stop ottto
brew uninstall ottto
```

Attach the formula diff, `ruby -c`, install, service start, status, update, and
uninstall output to the stable release record.
