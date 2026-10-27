# Oversized Claude transcript discovery retries

A Claude JSONL transcript larger than the 256 MiB admission limit keeps its
source census incomplete. The existing oversized-file disclosure remains
visible. No session or family is proven absent or complete from that partial
census, and absence retirement remains refused across the entire sweep.

An unchanged oversized file no longer restarts the traversal on the ordinary
retry clock. Its local scan checkpoint records hashed size/content samples. Once the
existing retry deadline is due, changed size or sampled bytes retry that file's
discovery. Metadata-only touches do not wake it. A file still above the limit
keeps its loss disclosure; one that shrinks within the limit joins the parse
queue on its own. These retries share the existing exponential cadence and
hourly ceiling, including when a live oversized transcript grows every minute.

Markers contain only hashes and a sighting count in local index state; they
add no upload fields. Sampling is bounded to three 4 KiB regions. Missing or
unreadable content is never positive absence evidence. A new oversized refusal
whose content marker could not be recorded keeps ordinary retry recovery.
Other retryable scan problems and bound family retry deadlines keep their
existing behavior. A shed page, lost ACK or other unsettled upload cause also
keeps the ordinary clock cadence; only completed blocking holds may wait for
the slower recovery re-walk.

An otherwise oversized-only sweep re-walks once every six hours, anchored to
its persisted census start. Content retries cannot postpone that floor. This
keeps blocking holds eligible for re-offer and discovers files that arrived
without watcher hints, including across daemon restarts. The floor preserves
the incomplete census and oversized disclosure. This scheduling change does
not provide all-size parsing.

Regression coverage uses the bounded scan, local family evidence fold, account
binding, upload/ACK and durable save/reload pipeline. It covers unchanged
oversized files, growth, same-size sampled edits, metadata touches, sustained
growth through the hourly cadence, other retryable loss, and sweep-wide family
completeness and absence fences. Recovery tests pin shed re-offers at the old
deadline, real demotion holds at two successive six-hour floors, no-hint
discovery/upload after reloading an exhausted traversal, and two oversized
files with only one content change.
