# Release Verification

Stable local-platform releases must be verifiable without trusting mutable
installer state.

## Release Manifest

A stable release manifest must include:

- immutable artifact URLs;
- SHA-256 for every artifact;
- install-owner metadata;
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
gh attestation verify <artifact> --repo <owner>/<repo>
```

The attestation subject must match the artifact digest. The SLSA provenance must
use the expected source repository, workflow, commit, and Build L2-or-better
predicate.

## Verify Public Release Candidate

Before a stable public release, the same commit must first pass preview
release-candidate QA. Generate a redacted evidence skeleton from the preview
manifest, fill real pass/fail facts, and run:

```bash
macos_public_rc_gate.sh \
  --preview-manifest release-manifest.json \
  --evidence public-release-candidate-qa.json
```

Stable preflight requires `quality_gates.public_release_candidate.status:
passed`, the preview manifest SHA-256, and an evidence file whose preview commit
matches the stable manifest commit. The preview manifest must mark every macOS
artifact as signed, notarized, and Gatekeeper-assessed, and the evidence must
include passed `artifact_signatures`, `notarization`, and
`gatekeeper_assessment` checks. It must also bind the exercised local runtime to
`ottto-service`, `net.ottto.service`, protocol v11, the preview version/channel,
and the preview release-manifest SHA-256. The evidence must not include private
repo paths, local user paths, raw claim/setup tokens, account or machine
identifiers, passwords, API keys, or bearer credentials.

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
`net.ottto.service`, protocol v11, stable version/channel, install owner, and
release-manifest SHA-256. It leaves every owner check as `not_run`. Fill those
values with real clean-machine pass/fail facts; do not paste raw terminal
output or local identifiers into the evidence file. Then run:

```bash
macos_stable_closeout_gate.sh --manifest release-manifest.json
```

The gate checks that Homebrew, hosted installer, and direct app-bundle install
paths passed the required owner-specific trust checks and the full lifecycle
matrix when those owners are advertised: install, service/app readiness,
browser setup claim, app detection, Codex verify, doctor, fix, diagnostics,
logout, update check, upgrade, uninstall, reinstall, and post-reinstall status.
The evidence file must match the exact manifest version, commit, and SHA-256,
prove the expected per-owner local-runtime binding, and it must not contain
extra required install owners, unknown per-owner check names, local user paths,
private repo paths, raw claim codes, account IDs, machine IDs, passwords, or
tokens.
