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
- Fail Pi session discovery and import closed as unsupported on non-Unix targets,
  where this service has no equivalent component-wise no-reparse open primitive.
- Skip symlinks found during discovery and refuse unreadable directory-entry
  iteration instead of treating a partial enumeration as complete.
- Bound traversal to depth 32, 20,000 entries, and 10,000 session files. Bound
  uploads to 64 MiB per file, 128 MiB aggregate transcript bytes, 4 KiB per
  route metadata field, and 132 MiB for the complete multipart body. Checked
  arithmetic and fallible reservation keep construction fail-closed.
- Preserve nested `.jsonl` imports and the existing behavior in which passive
  subscription-OAuth import failures are logged but do not become a hard Verify
  failure.

## Validation

- Focused Pi session tests cover normal nested uploads, symlinked files and
  directories, symlinked `.pi` and `agent` root components, final and
  intermediate path replacement, held-descriptor replacement safety, deep and
  wide traversal refusal, sequential processing beyond 256 files, and per-file,
  aggregate, multipart-field, and total body caps. A target-platform helper and
  non-Unix-only refusal test keep the unsupported-platform contract compilable.
- Full `ottto-service` tests pass (1,227 library tests and 10 binary tests); the
  two explicitly real-local-data service tests remain ignored. `ottto-core`
  passes 83 tests, `ottto-cli` passes 80 tests, and workspace all-target Clippy
  passes with warnings denied.
- Every Rust invocation used a fresh explicit file-only
  `OTTTO_SERVICE_SECRET_FALLBACK_DIR` and verified that directory remained
  empty. No Keychain, daemon, live transcript tree, or production state was
  read or mutated.
