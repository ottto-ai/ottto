# Composition run health, audit sample and upload metrics

The incremental composition reader now reports one run-health post per agent
per daily run, re-reads a small daily sample to check its own counting, and logs
what each upload cost. The changed-days reader switch remains off.

## Run health

The worker records each agent's counts in `health.json` under the reader's state
folder: once when the agent starts and again after its scopes have committed.
After the worker process exits, the daemon side posts each agent's entry to
`/api/v1/context-composition/run-health`, with the same device credentials and
relay token as the composition upload. The daemon adds the counts only it knows,
worker timeouts and worker failures, so a worker stopped midway still reports
(the agent it was reading reports zero counts with the timeout).

The body holds exactly the server's fields: `agent_source`, `machine_id`,
`run_date`, `scan_completed_at`, `files_checked`, `audit_differences`,
`full_read_waiting_files`, `full_read_backlog_bytes`, `backlog_growth_days`,
`bytes_read`, `cpu_seconds`, `duration_ms`, `accounted_bytes`,
`collector_version`, `scopes_quarantined`, `files_quarantined`, `agent_resets`,
`checkpoint_restarts`, `worker_timeouts` and `worker_failures`. Each count is
held within the server's bounds. CPU is the reading thread's own CPU time;
memory is the reader's accounted bytes. The full-read waiting files and bytes
come from the pins still waiting at the end of the run, at their current
sizes, and the backlog growth days count consecutive daily runs in which those
bytes grew (kept in `run.json`).

The record names the device, machine and server the run uploaded to; if they
changed before the post, the record is dropped unsent. The record is marked
sent before the first request. A refused or failed post is logged once and
counted in the daemon's metrics line, and is never retried within the day; the
next daily run reports again. A record older than yesterday is dropped rather
than sent late.

## Audit sample

Each daily run may re-read up to 100 MB (and at most 32 files, both shared by
the agents) of transcripts that were already counted. A file is eligible only
when it was counted from its first byte under the current parser, changed
within the last two days (an older file's share is dropped, so it could not be
replaced), holds only known ids, is not otherwise read in this run and has not
changed since its last commit. A pin follows its checkpoint's starting offset,
so a file restarted at its end is never taken for one counted whole. Request 1
records the session-start verdict its reads ran under, so a later verdict change
is not mistaken for a counting fault; a request 1 read under two different
verdicts is never sampled.

The re-read covers exactly the bytes the checkpoint counted and compares events,
tokens, residency and images per (day, kind) with the file's stored share.
Lines without a timestamp count on the day they are read, so when the re-read
meets any, the comparison is per kind over all days. A match changes nothing
and commits nothing. A re-read stopped by the run's wall cap proves nothing and
also changes nothing (counted as an audit failure). A re-read that ends at a
different offset is counted as a difference but cannot replace bytes it did not
cover. Any other difference replaces the file's share and checkpoint with the
re-read's result, as a budgeted full read would, and counts it in
`audit_differences`. No other file is read because of it. Picks rotate through
the pins in key order from where the previous audit stopped, kept in
`run.json`, so every eligible file is sampled in turn. Audit bytes are counted
separately from new and repair bytes.

## Metrics

The per-agent `context_composition_v2_metrics` line adds upload payload bytes,
the daily rows the server reported written, audit bytes, files, differences,
skips and failures, files checked, the full-read backlog and total bytes read.
Each accepted upload also logs one `context_composition_v2_upload` line with its
request bytes and the server's `daily_rollup_rows_written`. Uploads now send
their serialized body directly, so the bytes logged are the bytes sent.
