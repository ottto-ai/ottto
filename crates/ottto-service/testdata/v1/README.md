# Historical v1 records

These four synthetic records were written by the real production writer at
`53d05a4304f2e87effbaa48661e10286bff01c58`. The throwaway generator commit was
`412cf7a6b8a90f64e5370e70c7011c71fd722dc2` on `i1/goldens-gen-53d05a43`
(never merged).

Generation evidence: [Actions run 41171662029, attempt 1](https://github.com/ottto-ai/ottto/actions/runs/41171662029/attempts/1),
workflow `.github/workflows/linux-tests.yml`, artifact **13031099044** named
`v1-goldens-53d05a43`. The generator log records one passed test. Rust/Cargo
1.95.0 ran on Ubuntu 24.04.5 LTS, Linux x86_64; the manifest records the full
rustc identity. Its top-level `artifact_id` and `artifact_name` add the upload
identity to the original manifest (whose pre-upload `artifact.id` is null).
All other manifest content and all record/input/expected bytes are unchanged.

This round-3 generator artifact supersedes round-1 artifact **13030002873**
(run 41168313249): its Codex expected sidecars incorrectly declared empty
selector maps. Both Codex records carry context `model_provider=openai` and
source `derived_from_codex_source`. The corrected generator cross-checks all
16 persisted facts against the real historical reader before emitting them.

The retained artifact's `generator.patch` is the generation recipe, applied to
the source commit above. Its single test is
`snapshots::sampled_jsonl::durable::tests::generate_53d05a43_v1_goldens`.
The patch, log and toolchain receipt stay in that artifact, outside this tree.
Do not regenerate these bytes with the current writer or update their headers,
certificates or trailers to make a restore pass.

| Case | Historical input/decision |
| --- | --- |
| claude-three-request | Three requests, populated start window, API evidence and accepted body witness |
| claude-selector-unequal | Same input plus explicit context `priority` and source `derived_from_logs_2` |
| codex-legacy-acked | Dated Codex session, real prior Legacy ACK, populated usage/counting state |
| codex-v2-24b | V2 counting, dated header with CLI version `0.148.9`, accepted body witness |

The manifest pins lengths and SHA-256 for records and synthetic sidecars.
Expected JSON distinguishes decoded facts from generation-time API evidence,
index/ACK bindings and live TierReplay settlement; those external facts are
not all serialized into the reduction. The selector case also names exact
record-relative field/map spans. There is no shipped Pi v1 durable record.

These are **record/field format** fixtures. Their device, inode, timestamps,
path-dependent bindings and filesystem certificates belong to the generation
run. Copying them next to a fresh transcript does not prove a native restore.
The current reader's representation dispatch and field codec are the format
authority; native money/restart/receipt tests keep their existing live fixtures
and money oracle. A reader that retires these pins must assert its actual
Repin/rebuild outcome rather than relabeling the records or resurrecting an old
decoder.
