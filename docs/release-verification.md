# Release Verification

Stable local-platform releases must be verifiable without trusting mutable
installer state.

## Current Release Version

The current published version is served from the CDN, not from GitHub. The
source of truth is the per-channel release manifest — the same record the
daemon's own update check reads:

```bash
curl -fsS \
  https://install.ottto.net/ottto-local-platform/releases/stable/latest/release-manifest.json \
  | jq '{version, channel, commit}'
```

Swap `stable` for `stable-candidate`, `preview`, or `dev` to read another
channel (the URL shape is `default_release_manifest_url` in
`crates/ottto-service/src/control.rs`). The Sparkle appcast beside it at
`.../releases/stable/latest/appcast.xml` carries the same version, and it is the
app's `SUFeedURL`. On a machine with Ottto installed, the daemon reports both
sides of the comparison:

```bash
ottto update --json   # {current_version, latest_version, update_available, channel}
```

Do **not** read the current version from GitHub Releases: that is an optional,
`stable`-only verification mirror (see below) that is opt-in per run and
regularly lags the CDN by many releases.

## Release Manifest

A stable release manifest must include:

- immutable artifact URLs;
- SHA-256 for every artifact;
- install-owner metadata;
- optional install-method metadata for helpers that are not runtime owners;
- rollback metadata;
- signing, notarization, stapling, and Gatekeeper state for macOS artifacts;
- CycloneDX SBOM URL and SHA-256;
- SLSA provenance and SBOM attestation references.

Do not trust a release where the manifest omits required public-v1 metadata.

## Verify Checksums

Download the artifact and compare against the manifest:

```bash
shasum -a 256 Ottto.dmg
shasum -a 256 ottto
shasum -a 256 ottto-service
```

The computed digest must exactly match the manifest.

## Verify macOS Trust

For a native app bundle:

```bash
codesign --verify --deep --strict --verbose=2 /Applications/Ottto.app
spctl -a -vv --type execute /Applications/Ottto.app
xcrun stapler validate /Applications/Ottto.app
```

For CLI or daemon artifacts, verify code signatures and Gatekeeper state before
publishing the release channel.

## Verify Supply Chain Evidence

The release should publish a CycloneDX SBOM and artifact attestations covering
the app, CLI, daemon, release manifest, and SBOM.

When GitHub artifact attestations are used, verify the attestation against the
expected repository and subject digest from the release manifest:

```bash
gh attestation verify <artifact> --repo <owner>/<repo> \
  --predicate-type https://slsa.dev/provenance/v1 \
  --signer-workflow <owner>/<repo>/.github/workflows/macos-stable-release.yml \
  --source-ref refs/heads/main \
  --source-digest <release-commit>
gh attestation verify <artifact> --repo <owner>/<repo> \
  --predicate-type https://cyclonedx.org/bom \
  --signer-workflow <owner>/<repo>/.github/workflows/macos-stable-release.yml \
  --source-ref refs/heads/main \
  --source-digest <release-commit>
```

The attestation subject must match the artifact digest. The SLSA provenance must
use the expected source repository, workflow, commit, and Build L2-or-better
predicate.

Stable manifests should be bound with `macos_attestation_bind.sh` using the
published `subject.checksums.txt`; the helper updates only the SLSA and SBOM
manifest fields and refuses `verified=true` if GitHub attestation verification
fails. Verify `release-manifest.json.sig` with
`macos_manifest_signature.sh verify --manifest release-manifest.json --identity "$OTTTO_MACOS_CODESIGN_IDENTITY"`
before trusting the manifest as the stable release record so the CMS payload is
bound to the expected Ottto Developer ID identity.

## GitHub Release Verification Mirror

The macOS stable release workflow can optionally publish a public GitHub Release
as a **verification mirror only**. The mirror is opt-in per run via the
`github_release_mirror` workflow input, runs for the `stable` channel only, and
refuses to overwrite an existing `v<version>` release. The CDN at
`install.ottto.net` remains the install and update source of truth; the GitHub
Release never promotes a channel pointer and the workflow never writes to the
CDN. Because the mirror is opt-in per run, the newest GitHub Release (and its
`v<version>` tag) can trail the live CDN by many releases — never use it to
determine the current version; read the channel release manifest instead (see
[Current Release Version](#current-release-version)).

A stable verification mirror is expected to carry exactly these assets:

- `Ottto-macos-*.dmg`
- `ottto-macos-*.zip`
- `ottto-service-macos-*.zip`
- `ottto-local-platform-sbom.cdx.json`
- `release-manifest.json`
- `release-manifest.json.sig`
- `subject.checksums.txt`

`release-manifest.json.sig` and `subject.checksums.txt` let anyone verify a
downloaded build's manifest signature and per-artifact checksums independently of
the CDN. Stable-candidate builds are not mirrored, and installer helpers
(`install-macos.sh`, `homebrew/ottto.rb`) and QA evidence files are intentionally
not attached.

GitHub immutable releases (which protect tags/assets and add release
attestations) are desirable for this mirror, but are not a hard verification gate
unless the feature is enabled on the repository. Record the release immutability
state as informational evidence rather than requiring it.

## Verify Stable Candidate RC

Before a stable public release, the same commit must first pass internal
stable-candidate RC QA. Generate a redacted evidence skeleton from the exact
`stable-candidate` manifest, fill real pass/fail facts, and run:

```bash
macos_public_rc_gate.sh \
  --candidate-manifest release-manifest.json \
  --evidence stable-candidate-rc-qa.json
```

Stable preflight requires `quality_gates.stable_candidate_rc.status: passed`,
the candidate manifest SHA-256, and an evidence file whose candidate commit
matches the stable manifest commit. The stable-candidate manifest must mark
every macOS artifact as signed, notarized, and Gatekeeper-assessed, and the
evidence must include passed `artifact_signatures`, `notarization`, and
`gatekeeper_assessment` checks. It must also bind the exercised local runtime to
`ottto-service`, `net.ottto.service`, protocol v15, the stable-candidate
version/channel, and the candidate release-manifest SHA-256. The evidence must
not include private repo paths, local user paths, raw claim/setup tokens,
account or machine identifiers, passwords, API keys, or bearer credentials.

`mixed_owner_app_version_truth` must pass on a real lower-to-higher update when
the signed GUI uses Sparkle and Homebrew owns the service. After Homebrew reaches
the target but before Sparkle replaces the app, the UI must still show the lower
bundle version and an update pending/in progress. A target-version or `up to
date` claim while the lower bundle still runs fails the gate. Pass only after
Sparkle installs the target bundle, relaunches a new app process, and GUI plus
service versions converge without losing the account or sources.

`mixed_owner_sparkle_autonomous_lifecycle` must also pass, backed by the
structured `update_lifecycle` evidence object. Launch the lower app through
LaunchServices from its canonical bundle, perform exactly one foreground update
action, and require Sparkle to terminate the old process and relaunch the target
bundle with a new process ID. Any manual process signal, force quit,
executable-path launch, or manual reopen fails the gate. Diagnostics and Verify
must pass through the Homebrew-owned service socket, account and source
continuity must hold, and owner, prefix, protocol, schema, and version must
converge before stable promotion.

## Verify Installed Runtime

After installation:

```bash
ottto status --json
ottto update check --json
```

The JSON should report the expected version, install owner, update state, and
daemon reachability.

## Verify Stable Closeout

Before a stable release is promoted as the public `latest` release, Ottto
requires clean-machine evidence for every install owner advertised by the
manifest. The release operator should attach the redacted
`stable-clean-machine-qa.json` evidence file and run:

```bash
macos_stable_qa_evidence_template.sh \
  --manifest release-manifest.json \
  --output stable-clean-machine-qa.json
```

The template binds the exact manifest SHA-256, adds each required owner, and
records the expected local-runtime binding for `ottto-service`,
`net.ottto.service`, protocol v15, stable version/channel, install owner, and
release-manifest SHA-256. It leaves every owner check as `not_run`. Fill those
values with real clean-machine pass/fail facts; do not paste raw terminal
output or local identifiers into the evidence file. Then run:

```bash
macos_stable_closeout_gate.sh --manifest release-manifest.json
```

The gate checks that every advertised runtime owner passed the required
owner-specific trust checks and the full lifecycle matrix. The verified native
installer helper is not a runtime owner; it verifies and opens the native
DMG/PKG and then binds to the `app_bundle` owner after installation. Homebrew
must remain absent from `supported_install_owners` until its clean-machine
lifecycle evidence passes. Owner checks include: install, service/app readiness,
browser setup claim, app detection, Codex verify, doctor, fix, diagnostics,
logout, update check, upgrade, uninstall, reinstall, post-reinstall status, and
re-onboard after a local Keychain wipe. The re-onboard check must start from a
previously claimed Mac, remove local runtime state and all local telemetry
device-secret Keychain rows, use dashboard Start fresh to remove the stale
machine, reinstall, complete browser claim, and prove relay-device
provisioning, snapshot creation, and connected account state recover.
Homebrew evidence also has to prove that launching `Ottto.app` before and after
upgrade preserves the Homebrew-owned LaunchAgent, that doctor reports no owner
drift, and that update JSON reports the Homebrew install owner. App-bundle
evidence has to prove a second Homebrew install/start attempt is either a safe
refusal with instructions or an explicit migration, not silent owner takeover.
The evidence file must match the exact manifest version, commit, and SHA-256,
prove the expected per-owner local-runtime binding, and it must not contain
extra required install owners, unknown per-owner check names, local user paths,
private repo paths, raw claim codes, account IDs, machine IDs, passwords, or
tokens.
