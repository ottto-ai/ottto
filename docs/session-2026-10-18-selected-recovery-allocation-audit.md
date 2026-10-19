# Selected recovery allocation audit scope

The test-only selected-recovery peak assertion previously measured allocations
from every thread while comparing them with this operation's prepaid recovery
reservation. In a parallel test run, unrelated allocations could inflate that
measurement. An observed process-wide peak of 18,607 requested bytes exceeded
the 16,199-byte operation reservation; those numbers alone do not establish an
operation-owned overspend or a production reservation defect.

The audit now uses the existing caller-thread born-in-scope allocator probe.
`SelectedFallback::restore_selected` synchronously updates the selected index's
maps, sets, owned path queue and moved terminal traversal. Its helper calls
perform local collection/path operations; the measured closure creates no
thread, task, channel or worker transfer. Returned index allocations remain
counted through the end of the measurement. The probe still counts old-plus-new
reallocation overlap and prevents freeing pre-existing allocations from hiding
a new peak.

The exact requested-peak-versus-reservation assertion remains. Recovery planning,
reservation bytes, caps, restore behavior and non-test code are unchanged.
Existing `caller_thread_audit_keeps_born_peak_and_excludes_other_threads` and
`native_comparison_deferred_policy_resource_usefulness` cover the measurement
contract and actual recovery path. Supported CI must execute them. If the scoped
peak still exceeds credit, the reservation gap remains a failure to diagnose;
no margin or assertion relaxation is justified. This change does not establish
installed memory or CPU savings.
