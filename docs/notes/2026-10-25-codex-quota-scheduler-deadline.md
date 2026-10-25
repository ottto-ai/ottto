# Codex quota scheduler sleeps until the next home is due

The Codex saved-quota scheduler used to wake every 15 seconds, about 5,760
times a day, and on each wake re-read the Codex account settings, every
home's `auth.json`, every saved quota file and the active-session file, and
start one thread per home, even when no home was due.

It now sleeps until the earliest home is due, and at most a minute. The
acquisition cadence is unchanged: 5 minutes for a home in use, 15 minutes
otherwise, a day for a second home with the same login, a minute after a
switched login, and every read is still decided under the home's lock from the
files themselves. Checks keep running whether or not any app is in front.

## Wakes

- Sleep is the time to the earliest due home or process scan, capped at 60 s.
  A login switched outside the daemon, a new session or process, or a changed
  setting is therefore seen within a minute. A switched login is still read
  within a minute of the switch, and at least a minute after the home's
  previous read, as before.
- A round that leaves a home due (its read was refused at the last moment) or
  that panics sleeps 15 s, the old tick.
- A status read that serves "not read yet" and switching background refresh
  on wake the scheduler at once. Rounds stay at least 15 s apart, so a busy
  status poller cannot make it run more often than the old tick, and a round
  only reads homes that are due.
- Idle timer wakes drop from about 5,760 to at most about 1,440 a day.

## Kept planning copies

To decide what is due, a round reuses what it derived from local files while
they are unchanged. A file is compared by device, inode, owner, group, mode,
size, and modification and status-change times; a directory by device, inode,
owner, group and mode.

- Settings: the scheduled slots and the running sign-in's home, kept while the
  settings file and every managed slot's home and slot directory keep their
  stamps and the default home path is the same. Settings that could not be
  read in full are not kept.
- Credentials: a home's login mark, kept while the home directory and its
  `auth.json` keep their stamps. A claimed account lapses when its earliest
  token expires; a credential that could not be read is not kept.
- Saved files: kept while the file keeps its stamp; every write by the daemon
  drops it.
- A file modified in the last 2 s is never kept (Git's "racily clean" rule), so
  a coarse file-system clock cannot hide a rewrite of the same size.

Binding a reading to its login (`read_and_save_at`) and every status read still
read the files. A shared-login grouping built from the copies is re-confirmed
on both current credentials before a status read serves another home's
reading, as before. Only homes that are due by the planning copies get a read
thread.

## Tests

New unit tests cover the next-due time against the existing due check, the
sleep bound, a round's next-due time including a switched login, and both
caches' invalidation by a rewrite, a permission change, a token expiry, a
daemon write and an in-place rewrite of the same size.
