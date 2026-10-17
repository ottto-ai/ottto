# Snapshot packing without retained encoded bodies

Batch packing previously serialized every pending representative into a separate byte vector and retained all those vectors until it formed upload batches. Packing subsequently used only each vector's length. The per-batch limits did not limit this aggregate buffer retention.

The packing stage now counts the same serde JSON output through a checked writer and retains a byte length instead of encoded bytes. It still completes serialization, including errors after an oversize prefix. Fingerprint ordering, first representative, semantic body-witness checks, class splits, 50-item and 2 MiB packing thresholds, single oversize handling and local serialization-error classification stay unchanged. Upload-page cloning, wire serialization, request validation, compression, retry and ACK/checkpoint paths are outside this change.

Five targeted regressions compare actual upload callback batches with a frozen previous buffer-based packing oracle, plus literal boundary/order expectations. They cover escaped/control/Unicode and nested JSON, duplicates, previously accepted items, classes, exactly 50/51 items, exact byte limit and one byte above, oversize singletons, serializer failure after a written prefix, checked counter overflow and a 256-body synthetic allocation comparison. The allocation scope excludes fixture construction and includes unchanged page clones in the new whole-uploader measurement. Requested allocation bytes are distinct from process RSS.

At source publication these tests require hosted CI validation. No local Cargo build or test ran. This removes a concrete avoidable allocation owner; it does not establish the cause of any installed memory peak, installed CPU savings or a whole-daemon memory limit.
