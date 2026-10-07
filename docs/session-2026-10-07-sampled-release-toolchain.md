# Sampled transcript acquisition on the release compiler

The sampled-reader source shipped with a memory-layout guard accepting Rust 1.88.0 on 64-bit macOS. A release built with Rust 1.95.0 therefore fell back to full reads: layout accounting refused the compiler, retained reductions could not enter the optional cache, and acquisition reported missing checkpoints. Source containment alone did not establish that tail reads were active.

Support is limited to explicitly validated compiler versions. Rust 1.95.0 uses the same BTree node capacity relevant to the conservative accounting: 11 key/value slots and 12 edges. Unknown compilers and other platforms continue to refuse optional overlap and reuse. No memory limits, native parser rules, source guards, hourly full-audit obligations, account interpretation or upload acknowledgement contracts change.

The release-compiler regression must actually exercise both Claude Code and Codex native scanners: cold full read, appended suffix, positive guard-byte count and equality with an independent full-read body. This assertion prevents a supported release compiler from silently passing the sampled suite through an unsupported-layout early return. Requested-allocation fixtures also cover nested containers, BTree growth/removal, retained capacity and exact budget refusal on the admitted compiler.

Validation is compiler-specific. Native synthetic source proof does not imply that an older installed release has been repaired; a containing release and an ordinary post-startup tail observation are required for installed acceptance. Logical acquisition counters exclude discovery, sidecars and independent identity reads, and do not measure physical disk traffic.
