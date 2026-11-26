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
- optional install-method metadata for helpers that are not runtime owners,
  including each helper's immutable URL and SHA-256;
- rollback metadata;
- signing, notarization, stapling, and Gatekeeper state for macOS artifacts;
- CycloneDX SBOM URL and SHA-256;
- SLSA provenance and SBOM attestation references.

Do not trust a release where the manifest omits required public-v1 metadata.

## Operator-Waived Manual Stable Release

`release_mode: manual-no-sparkle` is a narrow emergency path for a stable build
that remains Developer ID signed, notarized, stapled, checksummed, and
manifest-signed, but is intentionally distributed without a Sparkle appcast.
It is accepted only when the workflow receives the exact operator approval
phrase and the manifest records explicit `waived` RC/clean-machine/attestation
gates plus a `disabled` Sparkle gate with reasons.

This mode is not eligible for automatic in-app upgrades or a claim of complete
QA/supply-chain verification. Users must install the notarized DMG manually or
use the published Homebrew formula. Never represent its waived gates as passed.

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
  --source-ref refs/tags/v<version> \
  --source-digest <release-commit>
gh attestation verify <artifact> --repo <owner>/<repo> \
  --predicate-type https://cyclonedx.org/bom \
  --signer-workflow <owner>/<repo>/.github/workflows/macos-stable-release.yml \
  --source-ref refs/tags/v<version> \
  --source-digest <release-commit>
```

Releases are built from the protected release tag `v<version>`; releases built
before tag-based releases verify with `--source-ref refs/heads/main`.

The attestation subject must match the artifact digest. The SLSA provenance must
use the `https://slsa.dev/provenance/v1` predicate and authenticate the
artifact digest, source repository, workflow, source ref and source commit.
Releases are built on a self-hosted signing Mac, so the manifest records SLSA
Build L1 for that build; the verified attestations are signed evidence about it,
not a higher build level.

Stable manifests should be bound with `macos_attestation_bind.sh` using the
published `subject.checksums.txt`; the helper updates only the SLSA and SBOM
manifest fields and refuses `verified=true` if GitHub attestation verification
fails. Verify `release-manifest.json.sig` with
`macos_manifest_signature.sh verify --manifest release-manifest.json --identity "$OTTTO_MACOS_CODESIGN_IDENTITY"`
before trusting the manifest as the stable release record so the CMS payload is
bound to the expected Ottto Developer ID identity.

## Releases before 0.1.262

Ottto 0.1.262 and earlier were built before this repository's history begins
(see [CHANGELOG.md](../CHANGELOG.md)). For those releases:

- Releases 0.1.255 through 0.1.262 keep their artifacts, release manifests and
  `release-manifest.json.sig` at their versioned CDN URLs, for example
  `https://install.ottto.net/ottto-local-platform/releases/stable/0.1.262/release-manifest.json`.
  [Verify Checksums](#verify-checksums), [Verify macOS Trust](#verify-macos-trust)
  and the manifest signature check above apply to them unchanged.
- Releases 0.1.254 and earlier are no longer offered for download.
- Their GitHub artifact attestations name commits from the earlier history as
  the source digest. Those commits are not in this repository, so
  `gh attestation verify` against this repository does not apply to them.
- The file tree of this repository's first commit is identical to the source of
  0.1.262.

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

The mirror step is disabled for now and the input has no effect: the step would
publish the runner's build before the release folder's privacy check. It comes
back only together with a gate on the exact files it publishes.

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

## Release Privacy Gate

`scripts/macos_privacy_gate.py` (Python 3 standard library, run with
`python3 -I`) checks every file the stable release workflow sends out. It
looks for the release owner's private strings (a marker list), for strings
taken from the build machine (home folder, user and full name, host names,
runner name, work and temp folders) and for home, temp and runner paths in
general. A release stops before any bytes leave the build machine for Apple
notarization, GitHub attestations or the Actions artifact upload. A publisher
that copies the workflow's files to the CDN runs the same gate on the exact
bytes it is about to upload.

The gate prints fixed lines only: stage, role, finding class, error code and
counts. It never prints a marker, an excerpt, a file name it did not expect,
a raw path or tool output.

### Policy value

The `macos-stable-release` environment holds one variable,
`OTTTO_RELEASE_PRIVACY_POLICY`, a JSON object:

```json
{"version":1,"mode":"enforce","advisory_xattrs":["macl","provenance"],"leaf_sha256":["<64 lowercase hex>"],"markers_sha256":"<64 lowercase hex>","accept_runner_machine_name_line":false}
```

| Key | Rule |
|---|---|
| `version` | The integer `1`. |
| `mode` | `enforce` (the workflow and publishers accept only this) or `rehearsal` (local exercises; never with outbound credentials). |
| `advisory_xattrs` | A subset of `macl` and `provenance`. A listed attribute's presence on a shipped file is counted but does not stop the release. Any marker in any attribute name or value still blocks. |
| `leaf_sha256` | One or two distinct SHA-256 digests of the Developer ID leaf certificate (DER). Every signature the gate trusts must chain to Apple's Developer ID root and end in one of these leaves. Two entries cover a certificate rotation; both release lanes use the same list. |
| `markers_sha256` | The marker list digest (below). |
| `accept_runner_machine_name_line` | Optional, default `false`. When `true`, the runner log line `Machine name: '…'` is counted as `host_runner_line` instead of blocking. Everything else in a log still blocks. |

Duplicate keys, unknown keys, wrong types and missing required keys are
refused. The canonical form is the object with every key (including the
default), sorted keys, sorted arrays, compact separators and ASCII escapes;
`policy_sha256` is the SHA-256 of those bytes.

### Marker list

The marker list is UTF-8 text of at most 48 KiB with LF or CRLF line ends
(not mixed, no bare CR). The workflow reads it from the environment secret
`OTTTO_PRIVACY_MARKERS`; a local copy must be a regular file owned by the
user with mode `0600`.

- The first line is `id:` and 32 lowercase hex digits (a random salt).
- Blank lines and lines starting with `#` are ignored.
- Every other line is one literal of 4 to 256 characters with no control
  characters and no leading or trailing space. A line that starts with
  `<word>:` is tagged; the only tags are `owner:` (a legal name that may appear
  in the shipped license files), `signer:` (a name that is public through the
  Developer ID certificate) and `owner+signer:` (both). Other lines are plain
  private literals. At least one literal is required.
- Two literals that are equal after Unicode case folding and NFC are refused.

`markers_sha256` is the SHA-256 of the UTF-8 bytes of the `id:` line and
then every literal line, in file order with its tag as written, each followed
by LF. Host-derived strings are not part of it.
`python3 -I scripts/macos_privacy_gate.py markers --store <file>` prints that
digest and counts, never a literal.

### Matching

- Each literal is searched in UTF-8, UTF-16LE and UTF-16BE at every byte
  offset, in its NFC, NFD and Unicode case-folded forms, ignoring ASCII case.
  Every literal is matched on its own, including overlapping matches.
- JSON keys and values, property list keys, strings and data, XML text and
  attributes, HTML entities in the license page and percent escapes in URL
  fields are decoded and searched again after case folding and NFC.
- A home folder (`/Users/<name>` other than `/Users/Shared`, `/home/<name>`),
  a per-user temp folder (`/var/folders/…`) or a runner work folder
  (`/_work/`, `actions-runner`) blocks wherever it appears.
- File and folder names, symbolic link targets and extended attribute names
  and values are searched too. `com.apple.provenance` and `com.apple.macl` on
  a shipped file (inside the DMG or a ZIP) block unless the policy lists them
  as advisory; other attributes are allowed only where the role expects them.
- `owner:` and `owner+signer:` literals inside the four approved license
  files are not reported: `LICENSE`, `NOTICE` and `LICENSE-THIRD-PARTY.html`
  with the bytes of the public source commit (the committed blobs in a git
  checkout, the files themselves in an exported tree; a missing file stops
  the scan as `incomplete`), and `LICENSE-Sparkle.txt` with its recorded
  SHA-256, at `Ottto.app/Contents/Resources/` or a binary ZIP's root. Every
  other marker in those files still blocks.
- `signer:` and `owner+signer:` literals are not reported in signed bytes
  whose signature the gate verified (code signature, Developer ID chain and
  pinned leaf): signed Mach-O files, the signed DMG file and its decoded disk,
  and the CMS manifest signature. They are searched everywhere else, including
  the decoded manifest, mounted files, names and attributes. So the owner's
  name inside signed bytes is not flagged; it is public through `NOTICE` and
  every signature. A legal name that appears in the license files must be
  tagged `owner+signer:`, because the decoded disk has no per-file exception.
- A string the gate reads from the build machine (user, full name, host)
  that equals a listed literal (NFC, case-folded) takes that literal's tag
  and omissions and is still searched in its own spelling; other machine
  strings are searched as their own literals with no omissions.

### Roles and lanes

Every file has a fixed role and name; anything else in a scanned folder is a
finding.

| Role | File |
|---|---|
| `app_dmg` | `Ottto-macos-arm64.dmg` |
| `cli_zip` | `ottto-macos-arm64.zip` |
| `service_zip` | `ottto-service-macos-arm64.zip` |
| `sbom` | `ottto-local-platform-sbom.cdx.json` |
| `launch_smoke` | `packaged-app-launch-smoke.json` |
| `manifest` | `release-manifest.json` |
| `manifest_sig` | `release-manifest.json.sig` |
| `checksums` | `subject.checksums.txt` |
| `installer` | `install-macos.sh` |
| `formula` | `homebrew/ottto.rb` |
| `rc_evidence` | `stable-candidate-rc-qa.json` |
| `clean_machine_evidence` | `stable-clean-machine-qa.json` |
| `appcast` | `appcast.xml` |
| `privacy_receipt` | `privacy-receipt.json` |

| Lane | Workflow upload (`upload` profile) | Publisher (`publish` profile) |
|---|---|---|
| `candidate` | `app_dmg`, `cli_zip`, `service_zip`, `sbom`, `launch_smoke`, `manifest`, `manifest_sig`, `checksums`, `privacy_receipt` | the upload set without `privacy_receipt`; `appcast` optional |
| `stable` | candidate set plus `installer`, `formula`, `rc_evidence` | the upload set without `privacy_receipt`, plus `clean_machine_evidence` and `appcast` |
| `manual` | candidate set plus `installer`, `formula` | the upload set without `privacy_receipt`; `appcast`, `rc_evidence` and `clean_machine_evidence` are refused |

`python3 -I scripts/macos_privacy_gate.py roles --profile <profile> --lane <lane>`
prints the role table for a lane as JSON.

### Scan command and response

```sh
python3 -I scripts/macos_privacy_gate.py scan --profile <profile> --root <folder> \
  [--lane candidate|stable|manual] [--appcast present|absent] \
  [--seal-from <folder>] [--markers-fd <n> | --markers-store <file>] \
  [--response-fd <n>] [--state <folder>]
```

Profiles: `unsigned` (`Ottto.app`, `ottto`, `ottto-service` before signing),
`notary` (one of `app_notary_zip`, `app_dmg`, `cli_zip`, `service_zip`),
`attest` (the attestation subjects, SBOM and checksums), `upload`, `publish`,
`dispatch` and `logs` (every text file under `--root`). `dispatch` reads the
workflow inputs from `OTTTO_DISPATCH_VERSION`, `OTTTO_DISPATCH_CHANNEL`,
`OTTTO_DISPATCH_ARTIFACT_BASE_URL`, `OTTTO_DISPATCH_RELEASE_NOTES`,
`OTTTO_DISPATCH_RELEASE_MODE`, `OTTTO_DISPATCH_OPERATOR_APPROVAL` and
`OTTTO_DISPATCH_PUBLISH_INTENT`, so a caller can check them before it
dispatches; the artifact base URL must be exactly
`https://install.ottto.net/ottto-local-platform/releases/<channel>/<version>`. The policy comes from
`OTTTO_RELEASE_PRIVACY_POLICY`; the markers from a file descriptor, a local
store, or, only inside the release workflow, `OTTTO_PRIVACY_MARKERS`.
With `--seal-from`, the gate copies the role files into the new `--root`
folder, scans the copies and makes the folder and files immutable
(`uchg`); consumers read only the sealed copies.

The response is one JSON object, written to `--response-fd` (or standard
output) and nothing else:

```json
{"schema":"ottto.release-privacy-scan","schema_version":1,"profile":"publish","lane":"stable",
 "verdict":"clean","policy_sha256":"<hex>","markers_sha256":"<hex>",
 "roles":[{"role":"app_dmg","path":"Ottto-macos-arm64.dmg","size":123,"sha256":"<hex>"}],
 "findings":{"private":0},"advisory_xattrs":{"macl":0,"provenance":0},"incomplete":0}
```

`roles` has exactly one row per expected role, sorted by role. `verdict` is
`clean`, `blocked` (at least one finding) or `incomplete` (a file could not be
fully checked). A consumer accepts a scan only when the exit status is 0, the
response is the only output on its descriptor, `verdict` is `clean`, both
digests equal its own policy and marker digests, and every row's size and
SHA-256 equal the bytes it is about to send.

| Exit | Meaning |
|---|---|
| 0 | `clean`: nothing found, everything covered. |
| 1 | `blocked`: at least one finding. |
| 2 | Usage, policy or marker list error; no scan ran. |
| 3 | `incomplete`: an unsupported, unreadable or over-limit input. |

### Receipt

The workflow's upload carries `privacy-receipt.json`, one JSON object:

| Key | Value |
|---|---|
| `schema`, `schema_version` | `"ottto.release-privacy-receipt"`, `1` |
| `workflow` | `".github/workflows/macos-stable-release.yml"` |
| `run_id`, `run_attempt` | integers |
| `source_commit`, `app_source_commit` | 40 lowercase hex; equal to the manifest's `git_repository` and `private_source` materials |
| `lane` | `candidate`, `stable` or `manual` |
| `version` | the manifest version |
| `policy_sha256`, `markers_sha256` | the attempt's digests |
| `stages` | stage name → `"clean"`, exactly the lane's stages (below) |
| `advisory_xattrs` | advisory attribute counts on shipped files |
| `files` | one `{role, path, size, sha256}` row per uploaded file other than the receipt, sorted by role |

Stages: `dispatch`, `unsigned`, `notary:app_notary_zip`, `notary:app_dmg`,
`notary:cli_zip`, `notary:service_zip`, then `attest-1` and `attest-2` for
`candidate` and `stable` (the `manual` lane makes no attestations), then
`upload`. The gate writes the receipt only when every recorded stage is
clean and was scanned with the attempt's policy and marker digests, and the
set of stages is exactly the lane's; otherwise the upload stage is
`incomplete`. The Actions artifact is named
`ottto-macos-<channel>-<version>-attempt-<n>`. A publisher accepts only a
receipt from that exact run attempt whose digests equal its own policy and
marker digests.

## Verify Stable Candidate RC

Before a stable public release, the same commit must first pass internal
stable-candidate RC QA. Generate a redacted evidence skeleton from the exact
`stable-candidate` manifest, fill real pass/fail facts, and run:

```bash
macos_public_rc_gate.sh \
  --candidate-manifest release-manifest.json \
  --evidence stable-candidate-rc-qa.json
```

The gate needs the app bundle and the two binaries the manifest names as
verification targets beside the manifest. A downloaded candidate holds only the
archives, so first stage a disposable verification folder outside the download
and run the gate on its byte-identical manifest:

```bash
macos_release_verification_folder.sh \
  --manifest <download>/release-manifest.json \
  --output <new folder outside the download>
macos_public_rc_gate.sh \
  --candidate-manifest <new folder>/release-manifest.json \
  --evidence stable-candidate-rc-qa.json
```

The script checks each archive against its manifest SHA-256 before it mounts
the DMG read-only or unpacks a ZIP. Never publish or upload the verification
folder.

Stable preflight requires `quality_gates.stable_candidate_rc.status: passed`,
the candidate manifest SHA-256, and an evidence file whose candidate version
(without `-rcN`), commit, and app source commit match the stable manifest. The stable-candidate manifest must mark
every macOS artifact as signed, notarized, and Gatekeeper-assessed, and the
evidence must include passed `artifact_signatures`, `notarization`, and
`gatekeeper_assessment` checks. It must also bind the exercised local runtime to
`ottto-service`, `net.ottto.service`, protocol v15, the stable-candidate
version/channel, and the candidate release-manifest SHA-256. The evidence must
not include private repo paths, local user paths, raw claim/setup tokens,
account or machine identifiers, passwords, API keys, or bearer credentials.

`app_owner_version_truth` must pass on a real lower-to-higher update when
the lower app owns `net.ottto.service`. Until Sparkle replaces the app, the UI
must show the lower bundle version and an update pending or in progress. A
target-version or `up to date` claim while the lower bundle still runs fails the
gate. Pass only after Sparkle installs the target bundle, relaunches a new app
process, the app's service runs the target version, and GUI plus service
versions converge without losing the account or sources.

`app_owner_sparkle_autonomous_lifecycle` must also pass, backed by the
structured `update_lifecycle` evidence object. Start from a lower app that owns
`net.ottto.service` (`starting_service_owner` is `app_bundle`). Launch it through
LaunchServices from its canonical bundle, perform exactly one foreground update
action, and require Sparkle to terminate the old process and relaunch the target
bundle with a new process ID. The service must restart on the target version and
still be owned by the app (`final_service_owner` is `app_bundle`). Any manual
process signal, force quit, executable-path launch, or manual reopen fails the
gate. Diagnostics and Verify must pass through the app-owned service socket,
account and source continuity must hold, and owner, install path, protocol,
schema, and version must converge before stable promotion. A machine where the
Homebrew formula owns the service is not valid evidence for this check: an
installed app moves the service to itself before it updates.

The packaged app does not declare `LSMultipleInstancesProhibited`, so several
macOS users can run Ottto from one shared app bundle at the same time. The app
keeps one process per user. Each user's service, LaunchAgent, control socket and
support files are separate. Sparkle does not coordinate updaters across
processes. When one user's Sparkle replaces the shared bundle, other users' running
app and service keep the old code until they relaunch. No automated gate covers
this case. Do not describe multi-user updates as verified until a manual
two-user check has passed and been recorded. In that check, both users open
the app, one updates it, the other relaunches, and both keep their account and
sources.

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
manifest. The published `stable-clean-machine-qa.json` is a closed public
summary (evidence `schema_version: 2`) of a private QA record that is never
published. The release operator writes the record outside the release folder,
fills it, writes the summary beside the manifest, and runs the gate:

```bash
macos_stable_qa_evidence_template.sh \
  --manifest release-manifest.json \
  --host-class signing_mac \
  --output <private-folder>/stable-clean-machine-qa.record.json
macos_stable_qa_summary.sh \
  --record <private-folder>/stable-clean-machine-qa.record.json \
  --manifest release-manifest.json
macos_stable_closeout_gate.sh --manifest release-manifest.json
```

The template binds the exact manifest SHA-256, adds each required owner, and
records the expected local-runtime binding for `ottto-service`,
`net.ottto.service`, protocol v15, stable version/channel, install owner, and
release-manifest SHA-256. It leaves every owner check as `not_run`. The summary
copies only allowlisted fields, so the record's notes never reach the release
folder. The gate refuses a private record anywhere in that folder and any
symlink in it, and fails if it cannot read the whole folder; publishers that
upload an explicit file list add defense in depth.

To check a published summary, download it beside its manifest and run the
gate. `environment.host_class` says where QA ran: `clean_vm` (a clean guest
VM), `clean_macos` (a clean physical Mac), `qa_user_on_shared_mac`,
`signing_mac` (the release signing host, for every user on it) or
`developer_mac`. Each check is `passed` with a `method`: `live` (driven by
hand), `scripted` (run by an automated script), or `static` (inspection only,
allowed just for `artifact_checksum`, `formula_syntax`, `gatekeeper` and
`native_gatekeeper`). `passed` means the check ran in this release against
this manifest. The schema can also say `carried` with `from` (the release
where the check last ran), but the gate does not accept a carried check yet.

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
device-secret Keychain rows, remove that exact installation from the
dashboard (a fresh install alone does not count), reinstall, complete browser
claim, and prove relay-device
provisioning, snapshot creation, and connected account state recover.
The Homebrew owner is checked headless: `headless_no_app_process` proves the QA
user has no Ottto app process for the whole Homebrew lane, including after a
service restart, and `post_upgrade_service_restarts_owned` proves that after
`brew upgrade ottto` and a service restart launchd runs a new process at the
target version with `install_owner` still `homebrew`. Homebrew evidence also has
to prove that doctor reports no owner drift and that update JSON reports the
Homebrew install owner. App-bundle `upgrade` includes the target app relaunch
and the app keeping ownership.

App-bundle `move_service_to_app` is the one explicit migration. It starts from
a serving Homebrew job. The QA user launches the installed target app in their
own desktop session, the app must offer Move, and the operator clicks Move.
Afterwards exactly one app-owned launchd job serves the target version and no
Homebrew process remains. On the isolated QA VM, the operator also checks,
after the app reports healthy, that the formula was removed.

App-bundle `homebrew_second_install_safe_refusal` is a separate run, not a
Move. App-bundle
evidence has to prove a second Homebrew install/start attempt is a safe
refusal with instructions, not a second serving job or silent owner takeover:
a formula beside a running app never gets a second serving job and never
silently takes ownership (the keg may exist). The release gate checks a
related decision on the packaged app: `macos_release_gate.sh` asks the app's
bundled `ottto-service` to decide as a launchd-started Homebrew copy
(`service step-aside-check`), and a stable release fails unless that copy
hands over to the packaged app and serves when no app is there. That packaged
check is distinct from Move and is not live ownership evidence for this check.
The evidence file must match the exact manifest version, commit, and SHA-256,
prove the expected per-owner local-runtime binding, and it must not contain
extra required install owners, unknown per-owner check names, local user paths,
private repo paths, raw claim codes, account IDs, machine IDs, passwords, or
tokens.
