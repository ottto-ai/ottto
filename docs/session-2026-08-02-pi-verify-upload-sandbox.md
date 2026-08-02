# Pi Verify upload sandbox

Date: 2026-08-02

## Problem

The Pi Verify import path recursively followed filesystem symlinks while finding
session transcripts and followed each pathname again while reading it into an
unbounded multipart request. A symlink or discovery-to-read replacement could
therefore upload a readable file outside `~/.pi/agent/sessions`; deep or wide
trees and large files could also drive unbounded traversal and allocation.

## Change

- On Unix, open `HOME` once, then walk `.pi/agent/sessions` one directory
  component at a time with `O_DIRECTORY | O_NOFOLLOW`.
- Keep that rooted directory descriptor through recent-file selection and
  multipart construction. Open every descendant component with `openat` and
  `O_NOFOLLOW`, require a regular final `.jsonl` file, and retain the verified
  descriptor while reading so pathname swaps cannot change the uploaded object.
  Open and consume one session descriptor at a time so the 10,000-file budget
  does not exhaust the macOS LaunchAgent's process descriptor limit.
- Compare the held root descriptor's device/inode identity with the pathname
  root before and after discovery, and reopen every discovered candidate through
  the held root before it can affect selection. A replaced root or descendant
  therefore refuses the import instead of accepting a mixed directory generation.
- Keep the live Verify pre-smoke root descriptor and its complete file census
  through the smoke. The post-smoke difference and upload reuse that descriptor
  and revalidate its pathname identity, so replacing the whole sessions root
  with a different real directory cannot reclassify that directory's existing
  transcripts as newly created. The passive OAuth path likewise carries one
  rooted selection from recent-file discovery through upload without reopening.
- Fail Pi session discovery and import closed as unsupported on non-Unix targets,
  where this service has no equivalent component-wise no-reparse open primitive.
- Skip symlinks found during discovery and refuse failed candidate metadata,
  directory opens, or directory-entry iteration instead of treating a partial
  enumeration as complete. A missing top-level session root remains no data
  because absence is handled before traversal by the rooted opener.
- Bound traversal to depth 32, 20,000 entries, and 10,000 session files. Bound
  uploads to 64 MiB per file, 128 MiB aggregate transcript bytes, 4 KiB per
  route metadata field, and 132 MiB for the complete multipart body. Checked
  arithmetic and fallible reservation keep construction fail-closed.
- Preserve nested `.jsonl` imports and the existing behavior in which passive
  subscription-OAuth import failures are logged but do not become a hard Verify
  failure.

## Final caller repair

The final clean-room review found that the rooted helpers were fail-closed but
the explicit live-Verify caller was not. A missing pre-smoke sessions root and
an actual census error both became `None`; the caller still spawned Pi and then
skipped the held-root import branch. That lost the first transcript on a fresh
Pi installation and weakened the census error boundary.

Non-OAuth live Verify now establishes only missing `.pi`, `agent`, and
`sessions` directories before smoke. It holds `HOME`, uses `mkdirat(0700)` plus
component-wise `openat(O_DIRECTORY | O_NOFOLLOW)`, securely reopens an EEXIST
race winner, and never changes an existing directory's mode. The resulting
empty or populated sessions descriptor is the normal pre-smoke census authority.
Any establishment or census error returns the stable
`pi_session_census_failed` route failure before Pi can spawn. Passive
subscription-OAuth Verify keeps the read-only opener and never creates the Pi
tree.

The live route also derives its post-smoke `local_session_observed` evidence
from the held pre-smoke descriptor. The generic smoke runner's pathname-reopened
file count is overwritten before backend polling, so replacing the sessions
root with a larger real directory cannot verify a route from that directory's
pre-existing files. A post-smoke held-census error returns
`pi_session_census_failed`, and an import error returns a failed route instead
of continuing into the local-only success branch. Post-smoke safety failures
preserve the completed command's outcome and timing, while a failed smoke stays
the primary diagnostic even if the held root is no longer readable afterward.

## Validation

- Focused Pi session tests cover normal nested uploads, symlinked files and
  directories, symlinked `.pi` and `agent` root components, final and
  intermediate path replacement, held-descriptor replacement safety, deep and
  wide traversal refusal, sequential processing beyond 256 files, and per-file,
  aggregate, multipart-field, and total body caps. They also prove a vanished
  candidate refuses traversal, a missing top-level root remains no data, and an
  unreadable before-smoke subtree cannot produce a partial baseline that later
  reclassifies pre-existing files as new. A separate regression replaces the
  whole sessions root with a different real directory between live censuses and
  proves the import refuses it before file selection or upload. A target-platform
  helper and non-Unix-only refusal test keep the unsupported-platform contract
  compilable.
- Caller-level regressions prove a fresh live Verify captures a held empty
  census before a fake Pi creates its first import-ready transcript, while an
  injected census error returns a path-safe failed route without invoking the
  smoke closure. A root-replacement-during-smoke regression proves that the
  legacy reopened count would have reported a new session but the held
  descriptor still fails the route before any evidence can verify it.
  Root-establishment tests cover owner-only creation, preservation of existing
  modes, ordinary symlink refusal, and real-directory versus symlink EEXIST race
  winners. A passive missing-root regression proves that OAuth selection remains
  read-only.
- Full `ottto-service` tests pass (1,241 library tests and 10 binary tests); the
  two explicitly real-local-data service tests remain ignored. `ottto-core`
  passes 83 tests, `ottto-cli` passes 80 tests, and workspace all-target Clippy
  passes with warnings denied.
- Every Rust invocation used a fresh explicit file-only
  `OTTTO_SERVICE_SECRET_FALLBACK_DIR` and verified that directory remained
  empty. No Keychain, daemon, live transcript tree, or production state was
  read or mutated.
