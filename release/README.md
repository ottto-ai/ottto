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

Development and preview builds are ad-hoc signed for internal bundle integrity,
but their manifests must still mark `signed: false` and `notarized: false`
because ad-hoc signing is not a distribution identity. Do not publish a
non-Developer ID artifact as `stable`, and do not present the app DMG as a
normal browser-download-and-double-click customer path while the release still
requires Developer ID signing.

## Local Rehearsal

From this directory's parent:

```bash
./scripts/macos_package.sh --version 0.1.0 --channel dev
./scripts/macos_release_gate.sh --manifest dist/macos/release-manifest.json
./scripts/macos_dev_install.sh --manifest dist/macos/release-manifest.json
```

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
`ottto-local-platform-sbom.cdx.json` and records it in the manifest; the release
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
exercised local runtime to `ottto-service`, `net.ottto.service`, protocol v11,
the stable-candidate version/channel, and candidate release-manifest SHA-256.
Stable preflight refuses a stable manifest unless
`quality_gates.stable_candidate_rc` points at passing evidence from a
stable-candidate manifest with the same commit and local-runtime binding.

To produce a distribution-signed package, pass a Developer ID identity:

```bash
OTTTO_MACOS_CODESIGN_IDENTITY="Developer ID Application: Ottto Inc (...)" \
  ./scripts/macos_package.sh --version 0.1.0 --channel stable
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
  --output /path/to/homebrew-ottto/Formula/ottto.rb
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
manifest only after the stable release gate and stable preflight pass:

```bash
./scripts/hosted_native_installer.sh \
  --manifest dist/macos/release-manifest.json \
  --output dist/macos/install-macos.sh
```

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
verify each native artifact with GitHub CLI:

```bash
gh attestation verify dist/macos/Ottto-macos-arm64.dmg \
  -R ottto-ai/ottto
gh attestation verify dist/macos/Ottto-macos-arm64.dmg \
  -R ottto-ai/ottto \
  --predicate-type https://cyclonedx.org/bom
```

Then bind the exact manifest with the same subject checksum file:

```bash
./scripts/macos_attestation_bind.sh \
  --manifest dist/macos/release-manifest.json \
  --subject-checksums dist/macos/subject.checksums.txt \
  --repo ottto-ai/ottto \
  --signer-workflow .github/workflows/macos-stable-release.yml
```

The binder updates only `supply_chain.slsa_build` and `supply_chain.sbom`, sets
Build L2 verified metadata only after `gh attestation verify` succeeds for the
release subjects, and leaves stable preflight red while those fields still
describe only local Build L1 metadata.

After attestation binding, sign and verify the final manifest bytes:

```bash
./scripts/macos_manifest_signature.sh sign \
  --manifest dist/macos/release-manifest.json \
  --identity "$OTTTO_MACOS_CODESIGN_IDENTITY"
./scripts/macos_manifest_signature.sh verify \
  --manifest dist/macos/release-manifest.json
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
   `min_protocol_version: 11`, non-empty `supported_install_owners`, and
   rollback metadata for the immutable versioned prefix plus channel latest
   pointer.
6. Confirm `ottto-local-platform-sbom.cdx.json` exists, matches the manifest
   SHA-256, is uploaded under the immutable prefix, and is attested with
   predicate `https://cyclonedx.org/bom`.
7. Confirm SLSA provenance uses `https://slsa.dev/provenance/v1`, reaches SLSA
   Build L2 or better, covers every artifact plus `release-manifest.json` and
   the SBOM, and has verified GitHub attestation evidence.
8. Update `quality_gates.stable_candidate_rc` in the stable manifest to point
   at the passing stable-candidate RC evidence file and the candidate manifest
   SHA-256 from the same commit.
9. Run `macos_release_gate.sh` and `macos_stable_preflight.sh` against the exact
   manifest to publish.
10. Generate the Homebrew tap formula from the exact manifest and run the tap QA
   checklist.
11. Generate `install-macos.sh` from the exact manifest with
   `hosted_native_installer.sh` and run its dry-run/static QA.
12. Upload the app, CLI, daemon archives, `release-manifest.json`, the
    CycloneDX SBOM, the Homebrew formula output, and `install-macos.sh` to the
    immutable versioned prefix.
13. Generate the redacted clean-machine QA evidence skeleton from the exact
    manifest:

    ```bash
    ./scripts/macos_stable_qa_evidence_template.sh \
      --manifest dist/macos/release-manifest.json \
      --output dist/macos/stable-clean-machine-qa.json
    ```

14. Run clean-machine QA for every supported install owner in the stable
    manifest: Homebrew, hosted installer, and direct app bundle where
    advertised. Fill only redacted pass/fail facts in
    `stable-clean-machine-qa.json`; leave raw terminal output in the internal
    release record, not in the evidence file.
15. Update `quality_gates.stable_clean_machine_qa` in the exact stable manifest
    to point at the redacted `stable-clean-machine-qa.json` evidence file, then
    run:

    ```bash
    ./scripts/macos_stable_closeout_gate.sh \
      --manifest dist/macos/release-manifest.json
    ```

16. Update the stable `latest/` pointer only after download, checksum, stapler,
    Gatekeeper, install, service, update, uninstall, rollback, and closeout-gate
    evidence are attached to the release record.
17. Optionally publish a public GitHub Release verification mirror by dispatching
    the stable release workflow with `github_release_mirror: true` (stable channel
    only). The mirror is verification-only: it never writes to the CDN and never
    promotes a channel pointer, and it refuses to overwrite an existing
    `v<version>` release. It attaches the app, CLI, and daemon archives, the
    CycloneDX SBOM, `release-manifest.json`, `release-manifest.json.sig`, and
    `subject.checksums.txt`, and intentionally omits `install-macos.sh`, the
    Homebrew formula, and QA evidence files. Immutable GitHub releases are
    desirable but not a hard gate; record the immutability state as informational
    evidence. See `docs/release-verification.md`.

## Stable Closeout Evidence

`macos_stable_closeout_gate.sh` is the final stable release evidence gate. It
does not replace signing, notarization, `macos_release_gate.sh`, or
`macos_stable_preflight.sh`; it runs after the immutable stable prefix is
available and before stable `latest` promotion.

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

The evidence file must use `schema_version: 1`, `gate:
stable_clean_machine_qa`, `status: passed`, match the exact manifest
`product`, `channel`, `version`, `commit`, and SHA-256, declare
`environment.host_kind: clean_macos`, and include one passing entry for each
supported install owner. Each owner entry must bind the installed local runtime
to `ottto-service`, `net.ottto.service`, protocol v11, the exact stable
version/channel, that install owner, and the release-manifest SHA-256. The gate
rejects extra required install owners, unknown per-owner check names, private
repo paths, local user paths, claim codes, setup-run tokens, account IDs,
machine IDs, passwords, and secret-like material. Store only redacted status
facts and command names in the evidence file; keep raw terminal output in the
internal release record if it is needed for operator audit.

Use `macos_stable_qa_evidence_template.sh` to generate the skeleton from the
exact manifest before QA. The template binds the manifest SHA-256 and required
install-owner checks plus the per-owner local-runtime binding, but writes
`status: not_run` placeholders by design. The closeout gate rejects unfilled
placeholders, so a generated template cannot serve as passing evidence until
the clean-machine operator records real passed results.

## Rollback

Stable rollback is pointer-based and manifest-owned. Keep immutable versioned
prefixes intact. The release manifest `rollback` block records the immutable
prefix that artifact URLs must live under, the channel `latest` manifest URL,
the requirement to preserve failed versioned artifacts, operator steps, and
verification commands. To roll back, repoint the stable `latest/` manifest or
installer to the last known good version, invalidate CloudFront for the changed
`latest` paths, and run the download plus Gatekeeper smoke again. Do not delete
or overwrite the failed versioned artifacts; preserve them for audit and
notarization troubleshooting.

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
  diagnostics redaction, update manifest visibility, and uninstall plan
