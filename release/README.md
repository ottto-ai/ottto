# Ottto Local Platform Release Contract

This is the clean-slate release contract for `ottto-service`, the `ottto` CLI,
and `Ottto.app`. It is the customer artifact path for the local
platform.

## Stable Gate

A stable macOS release must fail unless every local-platform artifact is:

- present on disk
- recorded in `release-manifest.json`
- assigned an HTTPS publish URL
- SHA-256 verified
- covered by manifest rollback metadata that points at the immutable release
  prefix and channel `latest` manifest pointer
- signed with a distribution identity
- signed with hardened runtime and a secure timestamp
- notarized
- stapled where Apple supports stapling
- accepted by Gatekeeper assessment, using the app execution assessment for
  `Ottto.app` and the install assessment for standalone CLI/service executables

Only the `Ottto.app` executable carries an entitlement: Apple Events
(`com.apple.security.automation.apple-events`), so "Terminal folder" can read
the front Terminal, iTerm2 or Ghostty tab's folder, and Claude Code sign-in can
open Terminal, once the person allows Automation. It comes from the app subtree's `Companion.entitlements.plist`,
which packaging refuses if it grants anything else, and the packaged
`Info.plist` carries `NSAppleEventsUsageDescription`. The bundled `ottto`,
`ottto-service` and Sparkle helpers are signed without it; there is no App
Sandbox and no Accessibility entitlement.

Development and preview builds are ad-hoc signed for internal bundle integrity,
but their manifests must still mark `signed: false` and `notarized: false`
because ad-hoc signing is not a distribution identity. Do not publish a
non-Developer ID artifact as `stable`, and do not present the app DMG as a
normal browser-download-and-double-click customer path while the release still
requires Developer ID signing.

## Local Rehearsal

From this directory's parent:

```bash
./scripts/macos_package.sh --app-root /path/to/app-checkout/AppPackage \
  --version 0.1.0 --channel dev
./scripts/macos_release_gate.sh --manifest dist/macos/release-manifest.json
./scripts/macos_dev_install.sh --manifest dist/macos/release-manifest.json
```

`--app-root` names the macOS app's Swift package: a tracked subdirectory of
its clean Git checkout, not the checkout root. Stable-candidate and stable
builds also take `--app-source-commit`, the 40-hex commit that checkout must be
at.

The app source is private. The manifest records it as
`supply_chain.materials[1]`, a `private_source` entry with a fixed name
(`ottto-macos-app`), `visibility: private`, the app commit, the package's Git
tree and `clean: true`, and no repository name or path. The packager checks
that the package is a clean tracked subdirectory at the pinned commit and
records its tree. It cannot tell from public data which subdirectory is the
canonical app source; the release operator's own source check proves that
before the run starts.

Release records name every local file (artifact archives, verification
targets, the SBOM and evidence files) by plain filename. Each file sits beside
`release-manifest.json`. The notarization, attestation, release, preflight and
RC gates resolve it in the manifest's directory, whatever the working
directory, so a release folder can be moved or downloaded and still verify. A
filename starts with a letter, digit or underscore and contains no slash; those
gates refuse absolute paths, traversal and symlinks, and name the field, not the
rejected value, when they refuse one. A downloaded release folder holds the
archives but not the unpacked app and binaries the verification targets name:
`macos_release_verification_folder.sh --manifest <download>/release-manifest.json --output <new folder>`
stages a disposable copy, outside the download, with the manifest byte for byte
and each target unpacked from its checked archive, for the release and RC gates. The stable closeout gate
reads its QA summary by the same rule: a plain file name beside the manifest,
never a symlink. The
recorded `gh attestation verify ./<file>` commands are examples to run from the
release folder; no gate evaluates them. Manifests from releases before this
contract hold absolute build-host paths: check them with the scripts from their
own release tag.

The package manifest uses URL-safe artifact names such as
`Ottto-macos-arm64.dmg`, `ottto-macos-arm64.zip`, and
`ottto-service-macos-arm64.zip`. Pass `--artifact-base-url` when rehearsing a
specific CDN prefix; otherwise the manifest points at
`https://install.ottto.net/ottto-local-platform/releases/<channel>/<version>/`.

The dev installer refuses `stable` manifests. It verifies the manifest and
checksums, installs `Ottto.app` into `~/Applications`, installs
`ottto` and `ottto-service` into `~/.ottto/bin`, and can optionally write the
per-user LaunchAgent:

```bash
./scripts/macos_dev_install.sh \
  --manifest dist/macos/release-manifest.json \
  --write-launch-agent
```

`macos_package.sh` also emits `dist/macos/install-macos-dev.sh` for hosted
dev/preview builds and internal stable-candidate RCs. `/apps` copies this
command for trusted testers while stable signing is unavailable:

```bash
curl -fsSL https://ottto.net/install.sh | bash
```

`ottto.net/install.sh` is a 302 redirect to the current channel's
`install-macos-dev.sh` under `install.ottto.net`. The redirect is configured in
`frontend/next.config.ts` and reads
`NEXT_PUBLIC_OTTTO_LOCAL_PLATFORM_RELEASE_CHANNEL` /
`NEXT_PUBLIC_OTTTO_LOCAL_PLATFORM_RELEASE_BASE_URL`.

The hosted preview/stable-candidate installer downloads
`release-manifest.json`, verifies checksums for the app, CLI, and daemon
archives, quits an already-running Companion, installs into user-scoped
locations, clears quarantine for that explicit internal install, bootstraps
`ottto-service`, waits for the CLI status path to reach the daemon, retries
bootstrap once if launchd is slow, and opens `Ottto.app`.

For a full installed dev/preview/stable-candidate smoke after installing and
bootstrapping the LaunchAgent, run:

```bash
./scripts/dev_e2e_smoke.sh
```

That smoke validates the installed app bundle, Rust CLI, daemon LaunchAgent,
setup claim handoff, Codex verification command, diagnostics redaction, and app
launch. It is the current preview-build substitute for production
notarization/Gatekeeper validation until Developer ID credentials are available.

### Companion Trust On Internal Builds

`ottto-service` grants the Companion token-less local-control access based on
the app's code signature. What it demands depends on the daemon's own signature,
so internal channels need no configuration:

| Installed daemon | Companion must be |
| --- | --- |
| Developer ID signed (stable, Homebrew) | Developer ID signed, same team |
| ad-hoc sealed (dev, preview, RC) | signed with identifier `net.ottto.Companion` |

Both halves of a channel come out of the same `macos_package.sh` run, so they
always match. A tester on a dev or preview build needs no flag, and the app's
own LaunchAgent re-bootstrap cannot drop the setting, because there is no
setting to drop.

The one combination that does not work is a mismatch: a Developer ID daemon next
to a locally built app. Pass `--trust-dev-companion` to `macos_dev_install.sh`
for that, which writes `OTTTO_COMPANION_CODE_REQUIREMENT` into the LaunchAgent.
The daemon logs the refusal and the fix once per run to
`~/Library/Logs/Ottto/ottto-service.error.log` (Homebrew) or
`ottto-service.err.log` (app or dev-installed LaunchAgent). Never pass it for a customer
install. See [`docs/troubleshooting.md`](../docs/troubleshooting.md).

For internal QA on local dev/preview/stable-candidate artifacts,
`--clear-quarantine` removes the quarantine attribute from installed artifacts.
The hosted internal installer does this by default because running the installer
command is already the explicit tester action. Stable customer releases must
rely on Developer ID signing and notarization instead.

## Dev And Preview Publish

Dev and preview publishes use the manual
`Ottto Local Platform Release` workflow. Run it from `master` only. The workflow
builds on GitHub's macOS 15 arm64 runner, runs `macos_release_gate.sh`, smokes
the packaged `ottto claude-code-statusline` helper so raw statusLine fields do
not persist, assumes the scoped `ottto-production-github-deploy` role, uploads
the immutable versioned prefix, optionally updates the channel `latest/`
pointer, invalidates CloudFront, and curls the public CDN manifest.

Default versions are `0.1.0-<channel>-<short-sha>`, for example
`0.1.0-dev-244f7ea9`. A custom version must be URL-safe. The workflow refuses
`stable`; stable releases must follow the Developer ID, notarization, stapling,
and Gatekeeper checklist below.

The publish helper uploads these files to both
`ottto-local-platform/releases/<channel>/<version>/` and, when
`promote_latest=true`, `ottto-local-platform/releases/<channel>/latest/`:

- `release-manifest.json`
- `install-macos-dev.sh`
- each artifact listed in the manifest

The generated latest installer embeds the immutable versioned release URL, so a
customer who runs the current `/apps` install command receives the exact package
that passed the release gate.

Every generated release manifest also carries `min_supported_version`,
`min_protocol_version`, `supported_install_owners`, and a `rollback` block with
the immutable artifact prefix, channel `latest` manifest URL, preserve-failed
version policy, operator steps, and verification commands. Local update checks
use the version/protocol/owner fields to soft-warn ordinary stale installs,
hard-block only below-min-supported or protocol-incompatible installs, and
present owner-aware instructions for Homebrew, hosted-installer, and
app-bundled installs without self-overwriting files managed by another owner.
The manifest also carries a `supply_chain` block for SLSA Build Track
provenance and CycloneDX SBOM evidence. `macos_package.sh` generates
`ottto-local-platform-sbom.cdx.json` and records it in the manifest. The SBOM
lists the Apple Silicon build graph of the CLI and daemon (normal and build
dependencies, with each crate's declared license), the closed-source Companion
app, the Sparkle version pinned by the app source commit (which must match the
embedded framework) and the fonts bundled in the app. The release
workflow writes `subject.checksums.txt`, calls `actions/attest@v4` for build
provenance and SBOM attestations, verifies those attestations with
`gh attestation verify`, and runs `macos_attestation_bind.sh` before any stable
preflight can pass. `macos_release_gate.sh`, `macos_stable_preflight.sh`, and
the publish helper reject manifests missing the public-v1 update, rollback,
SBOM, and supply-chain fields.

The dispatch-only `.github/workflows/macos-stable-release.yml` workflow builds
stable-candidate or stable macOS artifacts on a protected signing runner,
notarizes them, creates SLSA/SBOM GitHub attestations, binds the verified
supply-chain manifest fields, signs `release-manifest.json` with
`macos_manifest_signature.sh`, and uploads workflow artifacts. It is output-only:
`publish_intent` is fixed to `none`, it has no CDN/AWS write permissions, and it
never promotes the stable channel pointer. Final publication remains a private,
manual operator step after stable preflight and clean-machine closeout evidence
are green.

The workflow runs only when dispatched on a protected release tag
`refs/tags/v<X.Y.Z>`; any other ref fails the dispatch policy step. The tag is an
annotated tag on a `main` commit whose own merge-queue `Public CI` run passed,
and its message carries one `App-Source-Commit: <40-hex>` trailer naming the
macOS app source commit. Both legs of a release, `X.Y.Z-rcN` (stable-candidate)
and `X.Y.Z` (stable), dispatch on the same tag, so they build the same public and
app source commits. `scripts/macos_release_source_check.sh` checks the tag, the
first-parent position on `main`, and the CI run before packaging; the packager
then requires the app source checkout to be at the pinned commit and that commit
to be on the first-parent line of the app source `master`. Protected release
tags cannot be moved or deleted: a release that needs new code uses a new
version and tag. Stable preflight requires the stable manifest's version,
public commit, and app source commit to match the candidate in the verified RC
evidence (its version without `-rcN`).

Before cutting a stable build, build an internal stable-candidate RC from the
same commit and attach redacted stable-candidate evidence. Generate the
evidence skeleton from the exact `stable-candidate` manifest:

```bash
./scripts/macos_public_rc_evidence_template.sh \
  --candidate-manifest dist/macos/release-manifest.json \
  --output dist/macos/stable-candidate-rc-qa.json
```

Fill only redacted pass/fail facts after internal stable-candidate RC QA, then
run:

```bash
./scripts/macos_public_rc_gate.sh \
  --candidate-manifest dist/macos/release-manifest.json \
  --evidence dist/macos/stable-candidate-rc-qa.json
```

The gate runs the candidate `macos_release_gate.sh`, binds evidence to the
exact candidate manifest SHA-256, rejects placeholders, private paths, and
secret-like material, and requires candidate checks for public surface CI,
candidate manifest download, artifact checksums, hosted candidate installer,
app launch, service readiness, `status --json`, browser-claim setup, Codex
verification, diagnostics redaction, update check, rollback notes, and static
stable formula and hosted-installer review. The evidence must also bind the
exercised local runtime to `ottto-service`, `net.ottto.service`, protocol v15,
the stable-candidate version/channel, and candidate release-manifest SHA-256,
and name the candidate's app source commit. Stable preflight refuses a stable
manifest unless `quality_gates.stable_candidate_rc` points at passing evidence
from a stable-candidate manifest with the same base version, commit, app source
commit, and local-runtime binding.

To produce a distribution-signed package, pass a Developer ID identity and a
private dSYM folder. Stable and stable-candidate packaging refuse to run
without `OTTTO_MACOS_DSYM_DIR`: an absolute folder outside this checkout, the
release output, the app checkout and the runner's folders. The packager keeps
the Companion's dSYM and the build tools' logs there, and never uploads them:

```bash
OTTTO_MACOS_DSYM_DIR=/path/to/private/release-work/dsym \
OTTTO_MACOS_CODESIGN_IDENTITY="Developer ID Application: Ottto Inc (...)" \
  ./scripts/macos_package.sh --app-root /path/to/app-checkout/AppPackage \
    --app-source-commit <40-hex app commit> --version 0.1.0 --channel stable
```

Then submit the exact generated archives to Apple and update the manifest only
after validation passes:

```bash
./scripts/macos_notarize.sh \
  --manifest dist/macos/release-manifest.json \
  --keychain-profile OTTTO_NOTARY_PROFILE
```

When Apple accepts the upload but leaves processing stuck, pass
`--timeout 30m` or set `OTTTO_NOTARY_WAIT_TIMEOUT=30m`. The local command exits
after that wait window while Apple's Notary service keeps processing the
submission.

If one artifact completes outside the script and the remaining artifacts still
need notarization, pass `--artifact-name <name>` or `--artifact-kind <kind>` to
submit only the remaining manifest entries. If an artifact already completed
outside the script, pass `--validate-only` with an artifact filter to staple,
Gatekeeper-check, and update only that manifest entry without submitting it
again. For example, after an accepted app DMG:

```bash
./scripts/macos_notarize.sh \
  --manifest dist/macos/release-manifest.json \
  --artifact-name Ottto.app \
  --validate-only
```

Then submit only the remaining CLI and daemon archives:

```bash
./scripts/macos_notarize.sh \
  --manifest dist/macos/release-manifest.json \
  --keychain-profile "$OTTTO_NOTARY_PROFILE" \
  --artifact-kind cli \
  --artifact-kind daemon
```

Notarization submission, stapling, and Gatekeeper validation are intentionally
not faked by the packaging script. The stable gate should remain red until the
Developer ID identity and notarytool profile are present.

Before uploading or promoting any stable manifest, run the stable preflight:

```bash
./scripts/macos_stable_preflight.sh \
  --manifest dist/macos/release-manifest.json \
  --sign-identity "$OTTTO_MACOS_CODESIGN_IDENTITY" \
  --keychain-profile "$OTTTO_NOTARY_PROFILE"
```

Generate the Homebrew tap formula from the same stable manifest only after the
stable release gate and stable preflight pass:

```bash
./scripts/homebrew_formula.sh \
  --manifest dist/macos/release-manifest.json \
  --output /path/to/homebrew-tap/Formula/ottto.rb
```

The formula generator refuses non-stable manifests, `latest/` artifact URLs,
artifacts outside the rollback immutable prefix, missing Homebrew owner support,
invalid SHA-256 values, unsigned artifacts, unnotarized artifacts, and artifacts
without Gatekeeper assessment. The generated formula installs `ottto` plus the
per-user `ottto-service`, owns Homebrew launchd label `net.ottto.service`,
starts through `brew services start ottto`, updates through
`brew update && brew upgrade ottto`, and uninstalls through
`brew services stop ottto && brew uninstall ottto`.

See `../homebrew/README.md` for the tap layout and clean-Mac install, service,
update, and uninstall QA checklist.

Generate the stable hosted native installer wrapper from the same stable
manifest before stable preflight, attestation binding, and manifest signing:

```bash
./scripts/hosted_native_installer.sh \
  --manifest dist/macos/release-manifest.json \
  --output dist/macos/install-macos.sh \
  --record-sha256
```

`--record-sha256` writes the generated wrapper's SHA-256 into the manifest at
`install_methods.verified_native_installer.sha256`. Run it before attestation
binding and manifest signing so the signed manifest publishes the exact digest
of the served `install-macos.sh`. The release workflow passes
`--require-installer-sha256` to stable preflight to reject a missing field.
Without that flag, preflight accepts older manifests without the field for
rollback verification; a present field must always be valid and match the file.

The wrapper is a terminal convenience around the native signed artifact. It
downloads the immutable `release-manifest.json`, verifies that the manifest is
stable-only and advertised for `hosted_installer`, downloads the manifest's
native macOS app artifact from the rollback immutable prefix, checks its
SHA-256, validates the notarization ticket with `xcrun stapler validate`, runs
Gatekeeper assessment with `spctl --assess`, and opens the DMG or PKG. It does
not copy files into user directories, install CLI/daemon zips, clear quarantine,
write or bootstrap a LaunchAgent, or collect a password in the terminal.

The generator refuses non-stable manifests, `latest/` base or artifact URLs,
artifacts outside the rollback immutable prefix, missing hosted-installer owner
support, invalid SHA-256 values, unsigned artifacts, unnotarized artifacts,
artifacts without Gatekeeper assessment, and non-native app artifacts. Upload
`install-macos.sh` beside the immutable manifest and artifact payloads, then the
stable `latest` installer pointer can safely serve this exact wrapper because
its embedded default base URL stays pinned to the immutable versioned prefix.

For stable releases, the generated supply-chain defaults are intentionally not
publishable. After the trusted stable release workflow creates attestations,
verify each native artifact with GitHub CLI from the release folder:

```bash
cd dist/macos
gh attestation verify ./Ottto-macos-arm64.dmg \
  -R ottto-ai/ottto \
  --predicate-type https://slsa.dev/provenance/v1 \
  --signer-workflow ottto-ai/ottto/.github/workflows/macos-stable-release.yml \
  --source-ref refs/tags/v<version> \
  --source-digest <release-commit>
gh attestation verify ./Ottto-macos-arm64.dmg \
  -R ottto-ai/ottto \
  --predicate-type https://cyclonedx.org/bom \
  --signer-workflow ottto-ai/ottto/.github/workflows/macos-stable-release.yml \
  --source-ref refs/tags/v<version> \
  --source-digest <release-commit>
```

Releases built before tag-based releases verify with `--source-ref refs/heads/main`.

Then bind the exact manifest with the same subject checksum file. The source ref
is required (`--source-ref` or `OTTTO_RELEASE_SOURCE_REF`); the workflow sets it
to the release tag:

```bash
./scripts/macos_attestation_bind.sh \
  --manifest dist/macos/release-manifest.json \
  --subject-checksums dist/macos/subject.checksums.txt \
  --repo ottto-ai/ottto \
  --signer-workflow .github/workflows/macos-stable-release.yml \
  --source-ref refs/tags/v<version>
```

The binder updates only `supply_chain.slsa_build` and `supply_chain.sbom`. It
sets both `attested`/`verified` pairs only after `gh attestation verify`
succeeds for every release subject and both predicate types, and stable
preflight stays red until it does. Releases are built on a self-hosted signing
Mac, so the manifest records SLSA Build L1 (`build_l1`): the verified GitHub
attestations add signed provenance and SBOM evidence for that build without
raising its level. Historical L2 manifests remain valid inputs.

After attestation binding, sign and verify the final manifest bytes:

```bash
./scripts/macos_manifest_signature.sh sign \
  --manifest dist/macos/release-manifest.json \
  --identity "$OTTTO_MACOS_CODESIGN_IDENTITY"
./scripts/macos_manifest_signature.sh verify \
  --manifest dist/macos/release-manifest.json \
  --identity "$OTTTO_MACOS_CODESIGN_IDENTITY"
```

To check whether the current Mac has the non-secret Apple toolchain before any
signing private key or notarization credential exists, run:

```bash
./scripts/macos_signing_readiness.sh --host-only
```

Run the full credential readiness check only on the trusted signing Mac:

```bash
./scripts/macos_signing_readiness.sh
```

For local CI or operator rehearsal without Apple credentials, use dry-run mode.
It validates stable channel metadata, rollback metadata, artifact presence,
HTTPS stable URLs, and SHA-256 integrity, but intentionally skips identity,
notarytool, stapler, and Gatekeeper checks:

```bash
./scripts/macos_stable_preflight.sh \
  --manifest dist/macos/release-manifest.json \
  --dry-run
```

## Stable Prerequisites

Local Apple prerequisites:

- macOS with Xcode command line tools installed.
- A signing host that is owned or explicitly approved for Ottto production
  signing credentials. Do not create the Developer ID private key or store
  `notarytool` credentials on a company-managed or otherwise unapproved Mac.
- A `Developer ID Application` signing identity in the login keychain.
- `OTTTO_MACOS_CODESIGN_IDENTITY` set to that exact Developer ID identity, or
  pass `--sign-identity`.
- A notarytool keychain profile created with `xcrun notarytool store-credentials`.
- `OTTTO_NOTARY_PROFILE` set to that profile name, or pass `--keychain-profile`.
- `OTTTO_MACOS_DSYM_DIR` set to a private absolute folder outside the public
  checkout, the release output, the app checkout and the runner's folders,
  for example `/path/to/private/release-work/dsym`. It keeps the Companion
  dSYM and the private build logs; stable packaging fails without it.

AWS/CDN prerequisites before publish:

- AWS credentials with permission to upload the stable artifact prefix under
  `install.ottto.net/ottto-local-platform/releases/stable/<version>/`.
- Permission to update the stable `latest/` pointer only after the immutable
  versioned prefix passes preflight.
- CloudFront invalidation permission for the installer distribution when the
  stable `latest/` manifest or installer path changes.

## Stable Artifact Checklist

1. Build an internal stable-candidate RC from the same commit and run
   `macos_public_rc_gate.sh` with passing redacted
   `stable-candidate-rc-qa.json` evidence.
2. Build stable artifacts with `macos_package.sh --channel stable` and the
   Developer ID identity.
3. Submit the generated archives with `macos_notarize.sh`.
4. Confirm the manifest marks every artifact `signed=true`, `notarized=true`,
   and `gatekeeper_assessed=true`.
5. Confirm the manifest includes `min_supported_version`,
   `min_protocol_version: 15`, non-empty `supported_install_owners`, and
   rollback metadata for the immutable versioned prefix plus channel latest
   pointer.
6. Update `quality_gates.stable_candidate_rc` in the stable manifest to point
   at the passing stable-candidate RC evidence file and the candidate manifest
   SHA-256 from the same commit.
7. Generate `install-macos.sh` from the exact manifest with
   `hosted_native_installer.sh --record-sha256` and run its dry-run/static QA
   before attestation generation, attestation binding, and manifest signing.
8. Confirm `ottto-local-platform-sbom.cdx.json` exists in the release folder,
   matches the manifest SHA-256, and is attested with predicate
   `https://cyclonedx.org/bom`. It is uploaded with the rest of the folder in
   step 16, after the closeout gate.
9. Confirm SLSA provenance uses `https://slsa.dev/provenance/v1`, records the
   signing-Mac build as SLSA Build L1, covers every artifact plus
   `release-manifest.json` and the SBOM, and has verified GitHub attestation
   evidence for each subject (both `attested`/`verified` pairs true). Bind that evidence
   and sign the final manifest with `macos_manifest_signature.sh`.
10. Run `macos_release_gate.sh` and
   `macos_stable_preflight.sh --require-installer-sha256` against the exact
   manifest to publish.
11. Generate the Homebrew tap formula from the exact manifest. Nothing is
    uploaded to the immutable versioned prefix yet: the publisher runs the
    closeout gate first (the pre-hosted gate for the immutable stage of a
    two-stage publish, see Two-stage publish below), and an existing
    versioned prefix must already hold the exact file set and bytes, so an
    early upload outside those stages leaves the version unable to take its
    summary. To test the formula before publishing, use an
    isolated QA tap that holds the unmodified generated formula, and seed a
    disposable `HOMEBREW_CACHE` with the verified stable archives from this
    release folder under the cache file names Homebrew derives from the
    formula's URLs. Homebrew still checks each archive's SHA-256 against the
    formula. (`HOMEBREW_ARTIFACT_DOMAIN` does not help here: it rewrites only
    GitHub Packages URLs.) For the upgrade check, install the previous published
    formula first, then switch the QA tap to the target.
12. Generate the private clean-machine QA record from the exact manifest,
    outside the release folder (the template refuses a path inside it, a
    symlink, or a path through a symlink in the folder):

    ```bash
    ./scripts/macos_stable_qa_evidence_template.sh \
      --manifest dist/macos/release-manifest.json \
      --host-class <clean_vm|clean_macos|qa_user_on_shared_mac|signing_mac|developer_mac> \
      --output <private-folder>/stable-clean-machine-qa.record.json
    ```

13. Run clean-machine QA for every supported install owner in the stable
    manifest: Homebrew, hosted installer, and direct app bundle where
    advertised. Fill each check in the private record with what happened in
    this release; notes and raw terminal output stay in the private record.
14. Never edit the signed manifest: it already names
    `stable-clean-machine-qa.json` as its `evidence_path` (the only summary
    name the tools accept). Write the public summary beside the manifest from
    the record, then run the closeout gate before the immutable CDN upload:

    ```bash
    ./scripts/macos_stable_qa_summary.sh \
      --record <private-folder>/stable-clean-machine-qa.record.json \
      --manifest dist/macos/release-manifest.json
    ./scripts/macos_stable_closeout_gate.sh \
      --manifest dist/macos/release-manifest.json
    ```

15. The release folder must hold plain files and directories only. The
    closeout gate fails on any symlink in it, on a private QA record under any
    name, and when it cannot read part of the folder.
16. After closeout passes, give the complete gated release folder to the
    standard release publisher. It verifies the signed manifest and the
    required release inventory, generates the appcast, and uploads the
    complete set to the immutable versioned prefix.
    When the hosted installer lane must run against the real prefix, publish
    in two stages instead (see Two-stage publish below).
17. Update the stable `latest/` pointer only after download, checksum, stapler,
    Gatekeeper, install, service, update, uninstall, rollback, and closeout-gate
    evidence are attached to the release record.
18. The GitHub Release verification mirror is disabled for now: the
    `github_release_mirror` input has no effect until the step publishes the
    operator-checked release folder. When enabled, it publishes a public GitHub
    Release verification mirror for the stable channel only. The mirror is verification-only: it never writes to the CDN and never
    promotes a channel pointer, and it refuses to overwrite an existing
    `v<version>` release. It publishes the release for the existing release tag
    only and never creates a tag. It attaches the app, CLI, and daemon archives, the
    CycloneDX SBOM, `release-manifest.json`, `release-manifest.json.sig`, and
    `subject.checksums.txt`, and intentionally omits `install-macos.sh`, the
    Homebrew formula, and QA evidence files. Immutable GitHub releases are
    desirable but not a hard gate; record the immutability state as informational
    evidence. See `docs/release-verification.md`.

## Stable Closeout Evidence

`macos_stable_closeout_gate.sh` is the final stable release evidence gate. It
does not replace signing, notarization, `macos_release_gate.sh`, or
`macos_stable_preflight.sh`; it runs on the finished release folder before
anything is uploaded to the immutable stable prefix and before stable `latest`
promotion.

### Two-stage publish

The hosted installer downloads only from the immutable versioned prefix, so
its clean-machine lane cannot run before that prefix exists. A stable release
then publishes in two stages:

1. **Pre-hosted (immutable) stage.** Every check except the `hosted_installer`
   ones is filled; those stay `not_run`, with that owner's status and the
   top-level status. Write the pre-hosted summary outside the release folder
   and run the pre-hosted gate on it:

   ```bash
   ./scripts/macos_stable_qa_summary.sh \
     --record <private-folder>/stable-clean-machine-qa.record.json \
     --manifest dist/macos/release-manifest.json \
     --stage pre-hosted --output <private-folder>/stable-clean-machine-qa.pre-hosted.json
   ./scripts/macos_stable_closeout_gate.sh \
     --manifest dist/macos/release-manifest.json \
     --stage pre-hosted --evidence <private-folder>/stable-clean-machine-qa.pre-hosted.json
   ```

   The pre-hosted summary has the final schema plus `"stage": "pre-hosted"`.
   The pre-hosted gate applies every final rule, except that each required
   `hosted_installer` check must be exactly `{"result":"not_run"}`, and it
   refuses a release folder that already holds
   `stable-clean-machine-qa.json`. Its last line is `Stable closeout
   pre-hosted gate passed for <version> (<commit>)`. The publisher runs the
   release privacy gate with `--profile publish --lane stable --stage
   pre-hosted`, then uploads the immutable versioned prefix without the
   summary. Nothing points to it yet: no appcast, no `latest` pointer.
2. **Hosted lane.** The hosted installer lane runs live against that prefix
   and its checks are filled in the private record.
3. **Final stage.** Write the final summary beside the manifest and run the
   final gate, both without `--stage`; the final gate refuses a summary with a
   `stage` field. The publisher re-verifies the bytes already in the prefix,
   adds the summary as the one late file (the manifest's `evidence_path`
   names it there) and then promotes the release.

A hosted lane failure after the immutable stage burns that version; the next
release uses the next patch number. `macos_stable_closeout_gate.sh
--supports-stages` prints `pre-hosted final`; a gate without that option has
only the single final stage.

The release manifest must carry:

```json
{
  "quality_gates": {
    "stable_clean_machine_qa": {
      "status": "passed",
      "checked_at": "2026-05-21T19:00:00Z",
      "evidence_path": "stable-clean-machine-qa.json",
      "required_install_owners": ["homebrew", "hosted_installer", "app_bundle"]
    }
  }
}
```

QA evidence has two forms with one schema (`schema_version: 2`):

- The **private record** (`evidence_kind: private_record`) is what the QA
  operator fills. It may hold `operator_notes`, a `note` per check and host
  details such as a VM image digest. It never sits in the release folder,
  because the publisher uploads that whole folder and follows links. The
  closeout gate refuses any private record anywhere in the folder, under any
  name, and any symlink in it; the template and the summary writer refuse a
  record path that is a symlink or passes through one in the folder.
- The **public summary** is `stable-clean-machine-qa.json`, written beside the
  manifest by `macos_stable_qa_summary.sh`. It copies only allowlisted fields,
  so notes and any other record field are dropped, and it writes atomically.
  It refuses any other name, so it never replaces the manifest or another
  release file, even with `--force`.

The summary is a closed schema: exactly the keys `schema_version`, `gate`,
`status`, `checked_at`, `manifest` (`product`, `channel`, `version`, `commit`,
`sha256` of the exact manifest), `environment` (`host_class`, `macos_version`
as a numeric product version, `arch`) and `install_owners`. Each owner entry has
exactly `owner`, `status`, `local_platform` and `checks`. Any other key, a
wrong value type or free text fails the gate. String values must match as a
whole (a value with an extra line fails), and `schema_version` and
`protocol_version` must be JSON integers (`2.0` fails), the same rules the
release API applies when it reads the summary. The gate reports fixed
messages: a name from the files appears only when it is one the gate already
knows.

`environment.host_class` is the least clean class that fits the QA host:
`clean_vm` (a clean guest VM), `clean_macos` (a clean physical Mac),
`qa_user_on_shared_mac`, `signing_mac` (the release signing host, for every
user on it) or `developer_mac`.

Each check is `{"result": "passed", "method": "live" | "scripted" | "static"}`.
`passed` means the check ran in this release against this manifest's
artifacts. `static` (inspection without running) is allowed only for
`artifact_checksum`, `formula_syntax`, `gatekeeper` and `native_gatekeeper`.
The schema also has `{"result": "carried", "method": "live" | "scripted",
"from": "<X.Y.Z or X.Y.Z-rcN>"}` for a check that did not run here: `from` names
the release where it last ran, on the same X.Y line at most 5 patches back. The
gate validates that shape but does not accept a carried check yet, so every
check must pass in the release until carry can be verified against the earlier
published summary. `macos_stable_closeout_gate.sh --list-never-carry-checks`
prints the checks that bind the release's own bytes, install and runtime and
can never be carried.

Each owner entry must bind the installed local runtime to `ottto-service`,
`net.ottto.service`, protocol v15, the exact stable version/channel, that install
owner, and the release-manifest SHA-256. The gate rejects extra required install
owners, unknown per-owner check names, private repo paths, local user paths,
claim codes, setup-run tokens, account IDs, machine IDs, passwords, and
secret-like material.

Use `macos_stable_qa_evidence_template.sh` to generate the private record from
the exact manifest before QA. It binds the manifest SHA-256, the required
install-owner checks and the per-owner local-runtime binding, and starts every
check as `not_run`. The gate rejects unfilled placeholders, so a summary of an
unfilled record cannot pass.

## Rollback

Stable rollback is pointer-based and manifest-owned. Keep immutable versioned
prefixes intact. The release manifest `rollback` block records the immutable
prefix that artifact URLs must live under, the channel `latest` manifest URL,
the requirement to preserve failed versioned artifacts, operator steps, and
verification commands. To roll back, repoint the stable `latest/` manifest or
installer to the last known good version, invalidate CloudFront for the changed
`latest` paths, and run the download plus Gatekeeper smoke again. Do not delete
or overwrite the failed versioned artifacts; preserve them for audit and
notarization troubleshooting. To re-verify an older release record before
pointing `latest/` back at it, run its gates from a checkout of that release's
own tag: a release's scripts read the record shape of their own release.

## QA Evidence

A stable release record should include:

- package command, version, channel, commit, and artifact base URL
- notarization command and Apple submission result
- `macos_release_gate.sh` output
- `macos_stable_preflight.sh` output
- owner-aware update-check evidence for Homebrew, hosted-installer, and
  app-bundled install paths
- generated Homebrew formula diff and clean-Mac Homebrew install, service,
  update, and uninstall evidence
- generated hosted native installer diff plus dry-run/static test evidence
- `release-manifest.json.sig` CMS signature verification for the final
  manifest bytes
- clean-Mac hosted native installer evidence that Gatekeeper accepts the native
  artifact and that app launch, LaunchAgent creation, service readiness, and
  uninstall behavior are owned by the native app path
- `macos_stable_closeout_gate.sh` output for the exact manifest and redacted
  `stable-clean-machine-qa.json`
- CycloneDX SBOM path, URL, SHA-256, and predicate
  `https://cyclonedx.org/bom`
- SLSA v1.2 Build Track level, `https://slsa.dev/provenance/v1` predicate,
  GitHub attestation verification commands, signer workflow, and subject list
- SHA-256 values from the manifest
- rollback metadata from the manifest and evidence that artifact URLs are under
  the recorded immutable prefix
- `codesign --verify`, `xcrun stapler validate`, and `spctl --assess` results
- installed Companion smoke evidence for launch, daemon status, setup/verify,
  diagnostics redaction, update manifest visibility, uninstall plan, and
  re-onboard after a local Keychain wipe on a previously claimed Mac
