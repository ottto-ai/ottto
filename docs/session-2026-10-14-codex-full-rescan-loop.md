# Codex full re-read on every scan

On an observed Mac, every ordinary Codex source scan re-read nearly all of about
8,800 rollout files (about 45 GB, 12 to 25 minutes per scan, up to about 2 TB of
reads per day). Watcher-hint scans in between read almost nothing.

## Cause

The scanner already skips an unchanged file when its committed index entry
matches size, modification time and source fingerprint. Two facts defeated that:

1. Projection revision 1 (2026-10-02) requires every indexed file to be re-read
   and its body re-offered once, then records the revision per file. On the
   observed index 7,017 of 7,212 Codex entries were still at revision 0, and
   about 1,600 newer files had never been committed. Together they matched the
   per-scan full-read count.
2. Every such scan stopped in the cache-head bootstrap. Each re-offered entity
   with cache evidence needs an accepted head first. When its probe body was
   already quarantined, the uploader correctly withheld it, and bootstrap then
   failed the whole source before the main upload and before any index save.
   The observed progress ledger held over 1,000 quarantined probe bodies, none
   permanent. Scans with every probe held made no network call and still
   failed. So the adoption was never recorded, and the next scan started over.

The 256-entry in-memory transcript cache cannot cover a corpus this size, so
its acquisition reason was `state_missing` for almost every file. That counter
was a symptom, not the cause.

## Fix

The fix is #559, which carries a held probe body into ordinary settlement. With
it, the adoption scan reaches the main upload and the normal index save. This
change adds a regression test that links that fix to scan cost: a real Codex
scan that needs the adoption, with its probe body quarantined, settles and
saves, and the next scan parses no file. With the old bootstrap behavior
restored, the test fails at the same step as the observed scans.

## Expected effect

After a release that contains #559, the first ordinary Codex scan still re-reads
every file once (about as long as today) and re-offers the bodies. Later scans
parse only new or changed files. Each skipped file is still opened for its
bounded identity sample.

## Not changed / residual

- Claude scans also re-read about 5,300 files per scan, but Claude already
  adopted the revision (8,211 of 8,228 entries). Its repeated selection was not
  traced here; its index holds about 2,700 pending usage-family records, and its
  uploads currently fail with "snapshot ACK lacks exact durable context curve
  body witness proof". Not addressed here.
- If the Codex main upload hits that same ACK failure, only the pages accepted
  before the failure are checkpointed. Re-reads then shrink across scans instead
  of stopping at once.

## Verify after release

In the service log, Codex `native_collection_page` records should drop from
about 8,700 full selections to near zero after one settled scan. The scan should
end without "local snapshot sync skipped for codex: backend snapshot response
was invalid". The per-file revision count in the Codex index should rise to
cover all entries.
