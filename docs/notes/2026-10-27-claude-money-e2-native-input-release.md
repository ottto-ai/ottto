# Release native inputs after E2 emission

After the Claude E2 comparison, finalizer, identity/account qualification and
optional shadow consumers finish, request-owned emitted bodies release their
local occurrence maps and request-id sets. These fields are skipped by serde;
the final rows continue to own the upload bytes. The existing emitted-body
predicate protects held and legacy inputs. Disclosure counters survive for ACK
accounting, and the generic upload clone no longer copies these native maps.

The release uses the existing fold cleanup seam. It adds no daemon cache,
background work, retry policy, logging, heap-accounting term or budget change.
A path-twin scheduling experiment was excluded because it changed exact upload
receipts and increased measured memory; this change preserves traversal order.

Two full-shape native benchmark runs kept exact upload receipts across all six
matched before/after rounds. Median peak physical footprint fell by 129.37 MB
and 105.32 MB against the same-corpus main baseline. CPU samples remained noisy:
the repeated run was 0.50% slower than that baseline and 9.06% above the pre-E2
reference. This establishes a memory reduction, not a CPU reduction or a full
performance-gate pass. Existing limits and assertions remain unchanged.

The Linux suite passed with 5,109 service tests and all 55 E2 pipeline cases;
the touched-file Clippy probe was clean. Temporary measurement workflow steps
were removed after receipts were collected. Native contracts validate the final
source separately.
