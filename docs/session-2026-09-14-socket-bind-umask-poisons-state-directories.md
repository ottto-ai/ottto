# Tightening the umask around a socket bind poisons every directory another thread creates

2026-09-14, found while chasing an intermittent `cargo test` failure on `main`.

## What it looked like

A full `cargo test` failed roughly every other run, always the same way:

```
upload_receipts::tests::corrupt_ring_is_quarantined_and_recovers_on_append
called `Result::unwrap()` on an `Err` value: Os { code: 13, kind: PermissionDenied }
```

The test passed on its own. It only failed in a full parallel run, and it
failed the same way on a clean checkout of `main`, so it was not new.

`$TMPDIR` explained the `EACCES`. Scratch directories from earlier runs were
sitting there with mode `drw-------`:

```
drw-------  2 user  staff  64 ottto-upload-receipts-<pid>-2
```

`0o600` on a **directory** keeps the read bit but drops the execute bit, and a
directory without its execute bit cannot be traversed - so `std::fs::write` of
any file inside it fails with `PermissionDenied`. Removing those leftovers made
the suite green again.

## Cause

Two defects stacked. Only the second one was in the test.

**The daemon narrowed the umask for the whole process.** `bind_user_only_socket`
wrapped `UnixListener::bind` in a scoped `umask(0o177)`, because an AF_UNIX
socket takes its mode from the umask in effect at bind time:

```rust
fn bind_user_only_socket(path: &Path) -> Result<UnixListener> {
    let _guard = RestrictiveSocketUmask::new(); // umask(0o177), restored on drop
    UnixListener::bind(path)
}
```

umask is process-global, not per-thread. `0o777 & !0o177` is `0o600`, so
everything *any* thread created inside that window came out at `0o600` -
correct for a secret file, fatal for a directory.

That is not a test-only hazard. `ottto-service serve` calls
`start_builtin_relays` before it binds, so the snapshot sync, OTLP relay,
inventory and collector threads are already running and already creating state
directories; the XPC path rebinds the socket from a thread that loops forever.
A live daemon can create a state directory it can never write to again.

A regression test that binds in a loop while a second thread creates
directories measured it before the fix: **1968 of ~2000 directories came out
`0o600`**. The window is not narrow - the guard's lifetime covers the whole
bind call, which is most of the loop.

**The test helper then inherited a poisoned directory.** `temp_dir` built
`$TMPDIR/ottto-upload-receipts-<pid>-<counter>` and called `create_dir_all`,
which happily adopts whatever already exists at the path. It also had no
cleanup on panic, only a trailing `remove_dir_all` at the end of each test.
Pids are reused, so a directory left behind by a poisoned, panicking run was
handed straight to a later run that landed on the same pid and counter.

## Change

`bind_user_only_socket` no longer touches the umask. It creates a private
`0o700` staging directory next to the socket, binds inside it, tightens the
socket to `0o600` there, then renames it into place. Renaming keeps the
listening socket's inode, so clients connect through the published path exactly
as before, and that path only ever appears owner-only. The staging directory is
removed by a guard, including when the bind fails. The staged name is shorter
than the final file name, so a path that fits `sockaddr_un::sun_path` still
fits while staged.

`socket_bind_never_narrows_directories_created_by_other_threads` is the guard
against a umask creeping back in. It fails on `cb4fe0c4` and passes after.

The receipts helper returns a `ScratchDir` guard instead of a `PathBuf`:

- the name carries 64 random bits, so it cannot collide with a leftover,
- it uses `create_dir`, not `create_dir_all`, so an existing path is refused
  rather than adopted,
- it pins the mode to `0o700` explicitly rather than trusting the umask,
- `Drop` removes it, so a panicking test cleans up after itself.

Three tests cover it: the directory is owner-traversable, an existing path is
refused with `AlreadyExists`, and a panicking body leaves nothing behind.

## Left alone

`snapshots.rs` has its own `temp_dir` that leaks on panic. It names directories
with a nanosecond timestamp, so it cannot collide with a leftover and cannot
reproduce this failure - but two of its August leftovers are still sitting in
`$TMPDIR` at `drw-------`, which is independent confirmation that the umask
window was poisoning directories across the crate, not just this one helper.
