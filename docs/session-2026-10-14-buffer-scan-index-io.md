# Buffered scan-index persistence

The scan index can grow to many megabytes. Direct `serde_json::from_reader(File)` and pretty serialization to `File` issue small reads and writes throughout the JSON stream, making routine load and compare-and-swap save unnecessarily expensive.

The ordinary load and save-time typed parse now use `BufReader`. The temporary-file writer uses `BufWriter` and explicitly flushes before syncing the underlying file, renaming the temporary file and syncing the parent directory. Serialization, complete typed validation, schema and generation fences, checkpoint locking, bounded-read paths and failure cleanup remain unchanged. Buffering does not replace the full parse with a weaker header check.

A large synthetic checkpoint control compares durable bytes with the existing pretty serialization, reloads a replacement and proves that a stale generation cannot overwrite it. Existing corrupt-index recovery and overlapping-writer controls remain applicable. Hosted CI supplies runtime and public-surface validation; no installed latency, CPU or peak-memory saving is inferred from source changes. This change does not correct upload acknowledgement failures or bound the evidence join's live allocations.
