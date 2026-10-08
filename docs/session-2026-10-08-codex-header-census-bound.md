# Codex header census supports bounded native headers

A Codex upload scan first inventories owning headers across current and archived
rollouts so multiple physical files cannot overwrite one session independently.
Native owning headers can contain sizeable instructions. The previous independent
32 MiB cumulative header-read limit made this inventory permanently incomplete
for otherwise-supported populations of individually valid headers. The scanner
then deliberately refused all candidates before body assembly, transport or ACK;
its generic terminal parse error and ownership counters did not mean every
transcript had malformed JSON or an unknown owner.

The cumulative I/O bound now derives from the existing limits: 32,768 headers,
each securely reading at most 65,537 bytes. Maximum complete-census header I/O is
2,147,516,416 bytes (2 GiB plus 32 KiB). This is a disk-read ceiling, not a retained
allocation. Each native scan step still reads one header, discards its decoded
JSON, and retains only the existing bounded path, owner and metadata witnesses.
The maximum witness population was already supported for small headers; it does
not change. No new cache, cursor, persisted field, scheduler or parser revision
is introduced.

Oversized populations and individual headers, malformed or ownerless headers,
changed membership, conflicting ownership and incomplete native contributions
still refuse. Existing account, usage, money, correction, removal, common entity
ACK, partial checkpoint and crash/restart semantics are preserved. The ordinary
age-independent header roster continues to include historical sources before
upload eligibility is selected. Existing indexes and accepted body witnesses
are retained; the correction does not reset indexes or rearm every upload.

A synthetic 720-file census with valid 48 KiB headers failed on the previous code
and completes with the correction. The fixture measures one header per native
step and bounded allocator usage without retaining header payloads. Existing
native joining and transport tests cover lost/stale ACKs, partial refusal,
member loss and restart suppression.

The increased possible census I/O is intentional and must be included in
containing-release resource acceptance. Source tests do not prove installed
ordinary import, positive semantic ACK or end-to-end Results visibility. Those
remain release validation obligations; no live restart, resend or historical
repair is part of this source change.
