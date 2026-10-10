# Rejected usage receipt evidence

Mixed snapshot batches previously retained successful entity evidence before
rejections. Fifty successful siblings could consume the private 50-entity cap
and erase the sole failure from the diagnostic annotation. Rejected entities
now receive slots first; total counts and truncated coverage remain explicit.

Validated private rejection evidence adds a closed reason category, permanent
flag, exclusive-contract flag, machine and entity hashes, eight independent
usage counters (cache creation remains split into 5m/1h), five bounded decimal
cost fields, latest semantic activity, bucket/grain counts and a sorted grain
digest. The entity reference is SHA-256 of UTF-8 source + unit separator +
machine id + unit separator + wire session id, abbreviated to 16 hex digits;
the machine reference is SHA-256 of the wire machine id, abbreviated to 12.
These match retained admission evidence without disclosing raw identities.

The existing owner-only atomic ring remains capped at 500 receipts and 4 MiB;
its bounded retry writer may evict earlier by its existing byte/node budgets.
Old annotations decode with no invented rejection evidence. Public receipt DTOs,
wire requests, body hashes, admission floors and retry/reconstruction decisions
are unchanged. Unknown reason/detail strings, paths, model/selector/account
values and bodies never enter the added fields. Grain dimensions are hashed,
not retained; changed digests cannot by themselves prove a grain regression.

Retained historical checkpoints hold body digests, not complete bodies. A
matched session and older first rejection do not prove today's body was
unchanged. Request/output totals alone cannot distinguish duplicates from
changes to another floor, cost, hourly grain or semantic activity. Additional
source fixes require a demonstrated fault; no permanent retry suppression is
introduced by this evidence repair.

Validation covers mixed-page rejection starvation, legacy annotations,
content exclusion, exact matching hashes, changed counters/grain detection,
order-independent grain hashes, existing validation refusal and ring bounds.
Source tests do not establish installed recovery or production classification;
those require a containing release and matched retained admission evidence.
