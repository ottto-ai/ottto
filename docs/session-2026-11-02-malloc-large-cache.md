# macOS daemon allocator environment

Service LaunchAgents now set `MallocLargeCache=0` before process startup. The
Rust bootstrap renderer covers hosted installs, reinstalls and Companion-driven
registration/recovery; the packaged service plist and generated Homebrew service
carry the same setting. User-facing apps do not receive the setting.

The setting takes effect on the next service start after installation re-bootstraps the job. It is an
undocumented libmalloc control; if a macOS update ignores it, memory retention
returns to the previous behavior. A copied-state harness over four cycles showed
idle footprint growing from about 340 to 850 MiB by default, versus a flat 25–62
MiB with the setting; CPU was within noise in comparable-load runs.

The startup `local_resources` row reports `malloc_large_cache_set` and the numeric
`malloc_large_cache` value under `counts` (null when absent or nonnumeric), without environment
text or paths. Presence confirms launch configuration, not allocator support.

Validation: generated-plist and formula assertions updated; Rust formatting
checked directly with rustfmt. Tests and Clippy run in CI; no local Cargo or
service execution.

Linux CI exposed an existing relay idle-clock test racing parallel ephemeral-port
users while rebinding its retired listener (`AddrInUse`). It now runs in the
existing serial group; its release, restart and idle-clock assertions are kept.
