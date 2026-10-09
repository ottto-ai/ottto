# Keep recent native tails through historical scan pressure

An optional transcript cache was effectively limited by repeated traversal of
all retained native graphs. On the validated release compiler, 24 small native
first-import scans retained only 18 Claude Code or 16 Codex entries at about
1.16 or 1.26 MB of conservative layout charge. Historical full reads also
promoted cold files over recent sessions. A production-scanner regression lost
a recent session's checkpoint after 272 older native full reads.

The existing shared cache now measures each immutable retained graph at
admission and charges its checked heap allocation without repeatedly walking
that graph. Taking a state transfers ownership out; reinsertion measures the
mutated graph again. Adapters must explicitly permit frozen charges; native
reductions refuse them while either live shared trace/parent input remains.
Container nodes, keys, entry metadata, active copies and live reservations
remain accounted. Failed replacements lose only optional cache state. Rejected
cold admissions still release enough space for the caller's live reservation.

Admission favors recent source modification times over insertion order. This
is only a cache hint, never ownership, usage, account or prefix authority.
Future modification times are clipped to admission time; equal hints use
admission order. Inactive entries expire at the existing one-hour audit interval,
allowing backdated work to regain space. Incorrect clocks, competing hot files,
large reductions or capacity pressure can still cause bounded full reads. No
cache eviction, expiry or admission refusal clears durable source-audit debt.

The compiler gate, per-state 4096-visit bound, 8 MiB entry cap, 256-entry cap,
31 MiB cache/active-copy allowance, 1 MiB scratch reserve, 32 MiB existing
optional overlap allowance, 4 KiB head/boundary samples and hourly full audits
are unchanged. No persisted ledger, source scheduler, upload, receipt or wire
format changed. RAM checkpoints still disappear on process restart.

Validation uses synthetic files with blocked network and account stores. The
both-provider regression compares a recent active append after more than 256
older full admissions with an independent native full reader, including guard
bytes in its read-saving assertion. Cache checks cover aggregate traversal,
mutable-state refusal, remeasurement, oversize replacement, live reservation,
expiry, equal/future/backdated timestamps, clearing and cold restart. Installed
savings require a containing release and ordinary eligible warm scans; source
fixtures do not establish average daemon I/O, elapsed time or RSS savings.

Rust 1.95 native checks: 76 affected checks passed, including the explicit
serial allocation probe; formatting and affected service Clippy with warnings
denied passed. In the pressure fixture, Claude Code read 241 new native bytes
plus 8192 guard bytes versus a 66195-byte full input; Codex read 291 plus 8192
versus 66237. These are logical fixture reads, excluding discovery, sidecars
and independent identity work; they are not physical disk measurements.
