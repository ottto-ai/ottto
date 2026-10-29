//! Genuine v1 records from main's pinned 53d05a43 writer, before R2 (#865).
//! Read the production post-save artifact unchanged: never rewrite its version,
//! binding, allowlist, body or trailer. Source pins below fail on codec drift;
//! a future writer must supply archived bytes rather than relabel its output.
//!
//! Serializer regions are extracted by the single companion Python standard-
//! library tool used for both baseline generation and candidate verification.
//! Only tests launch it; production has no subprocess or dependency change.
//! It balances Rust tokens, preserves literals, removes comments/whitespace,
//! discovers durable macros/trait impls and follows local helpers/constants.
//! Explicit roots cover body encoding, allowlist labels, session-start content
//! hashes, source slugs and owned-container Deref. See the tool docstring for
//! the catalog limits: external helpers/import resolution need owner review.
use super::*;
use sha2::{Digest, Sha256};

pub(crate) fn seed_pinned_v1(
    cache: &SharedCache,
    source: SnapshotSource,
    key: &str,
    index: &ScanIndex,
    pin: &str,
) -> Vec<u8> {
    assert_eq!(pin, "53d05a43");
    assert_pinned_body_writer();
    let checkpoint = cache
        .retained_checkpoint(key)
        .expect("populated native reduction");
    let ds = durable_source(source).unwrap();
    let mut stores = cache.durable().unwrap();
    let slot = stores.slot(ds).as_mut().unwrap();
    let interpretation =
        Interpretation::of(source, key, index, slot.identity_capture, &slot.namespace);
    let expected = expected(ds, source, key, checkpoint.scope(), index, &interpretation).unwrap();
    let record = match slot
        .store
        .read(&expected.binding.key, &codec::allowlist_digest(source))
    {
        ReadOutcome::Found(record) => record,
        other => panic!("pinned writer did not produce a readable record: {other:?}"),
    };
    assert_eq!(record.record.binding, expected.binding);
    assert_eq!(record.index_generation, index.generation);
    let name = expected
        .binding
        .key
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    let bytes = std::fs::read(slot.store.dir().join(format!("{name}.rec"))).unwrap();
    assert_eq!(u16::from_le_bytes(bytes[8..10].try_into().unwrap()), 1);
    assert_eq!(bytes, pinned_bytes(&record.record, record.index_generation));
    bytes
}

// Pin serializer-relevant regions of the 16 baseline compilation units.
// Hashes are generated with the SAME extractor using --baseline 53d05a43;
// unrelated source edits are ignored, and new serializer definitions refuse.
struct SourcePin {
    path: &'static str,
    text: &'static str,
    sha256: &'static str,
}
const PINNED_SOURCES: &[SourcePin] = &[
    SourcePin {
        path: "codex_prelude_footprint.rs",
        text: include_str!("../../codex_prelude_footprint.rs"),
        sha256: "b309171b8f22488d0d471a054a1d69f39425b585b2746c813c92497a4703cde4",
    },
    SourcePin {
        path: "durable_tail_codec.rs",
        text: include_str!("../../durable_tail_codec.rs"),
        sha256: "d74857522993a5c46daf5523d1eaf26edefa51e34c2dbe74ce0952ebc4d4a723",
    },
    SourcePin {
        path: "snapshots/cache_observations.rs",
        text: include_str!("../cache_observations.rs"),
        sha256: "2395f78462fda87e452acdb1b9b11dce2636218c6681c32de998e2dcc023901a",
    },
    SourcePin {
        path: "snapshots/claude_context_file_birth.rs",
        text: include_str!("../claude_context_file_birth.rs"),
        sha256: "4c8ecdba2a1b0cea91dcad8bfff18a87696a6360d856ebf85973d6b274c2cc37",
    },
    SourcePin {
        path: "snapshots/claude_request_identity.rs",
        text: include_str!("../claude_request_identity.rs"),
        sha256: "31193b9227acff19af78364c9ec27e6716a8e744cf3c7ca033892f2d832fc2db",
    },
    SourcePin {
        path: "snapshots/claude_response_records.rs",
        text: include_str!("../claude_response_records.rs"),
        sha256: "77ee17b44a27a48f549ca40ba5455b55b5f72f92162adf366536f58dc95d5fa7",
    },
    SourcePin {
        path: "snapshots/codex_counting_version.rs",
        text: include_str!("../codex_counting_version.rs"),
        sha256: "da1f61e4aa46ebe6761ba910b4fbc4340d96058bdfba9c6758f384846ca76127",
    },
    SourcePin {
        path: "snapshots/codex_usage_occurrence.rs",
        text: include_str!("../codex_usage_occurrence.rs"),
        sha256: "4e8573b957476d37c720ded6a6c8d89f7a15a3e69557ac8813144a5b40fdc4e2",
    },
    SourcePin {
        path: "snapshots/compaction_events.rs",
        text: include_str!("../compaction_events.rs"),
        sha256: "7e2270137d1aa0d104542d03e07e1bea0fb7b1b2bb9707d9e6078fb10f26b56c",
    },
    SourcePin {
        path: "snapshots/context_curve.rs",
        text: include_str!("../context_curve.rs"),
        sha256: "6fb3a00d5dd3ff71364e9303f8b3228e7fea4cbec23cc81420fc636281762ae8",
    },
    SourcePin {
        path: "snapshots/local_context_points.rs",
        text: include_str!("../local_context_points.rs"),
        sha256: "b45880d5789fd5147384d591126d2333141774c931170c251ae47e4a0f9b3bb2",
    },
    SourcePin {
        path: "snapshots/sampled_jsonl/durable.rs",
        text: include_str!("../sampled_jsonl/durable.rs"),
        sha256: "2d35c65818faadc48fd3cdbbb7782eed7ad3e2228b12a1b86859360fbbde19e3",
    },
    SourcePin {
        path: "snapshots/sampled_jsonl.rs",
        text: include_str!("../sampled_jsonl.rs"),
        sha256: "6a91f5ee85d9f58f926232a09cf1460966959fffb80b4c5a970c61affb12dd1f",
    },
    SourcePin {
        path: "snapshots/session_start.rs",
        text: include_str!("../session_start.rs"),
        sha256: "a762a2f77dfddb18e9784b2b780a0a4e21ee73d2c99ca42a081e55ace97c3447",
    },
    SourcePin {
        path: "snapshots.rs",
        text: include_str!("../../snapshots.rs"),
        sha256: "8d957f0c5928181a5d0c544146ac3404ce7d229fdec0f4fe6b3447c9d7e456aa",
    },
    SourcePin {
        path: "owned_heap.rs",
        text: include_str!("../../owned_heap.rs"),
        sha256: "44d81bb377a95a48f38f5b5c0dc44bcfe3ab92bb5f834e8d5db2ecf491a44af4",
    },
];

fn verify_pinned_sources(replacement: Option<(&str, &str)>) -> Result<(), &'static str> {
    use std::io::Write;
    use std::process::{Command, Stdio};
    let sources = PINNED_SOURCES
        .iter()
        .map(|pin| {
            let text = replacement
                .filter(|(path, _)| *path == pin.path)
                .map_or(pin.text, |(_, text)| text);
            (pin.path, text)
        })
        .collect::<BTreeMap<_, _>>();
    let mut child = Command::new("python3")
        .args(["-c", include_str!("transition_serializer_regions.py")])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("test serializer extractor requires Python 3");
    // Python drains the full request before emitting its small response (16 hashes),
    // so writing snapshots.rs before collecting stdout cannot fill both pipes.
    let mut input = child.stdin.take().unwrap();
    input
        .write_all(&serde_json::to_vec(&sources).unwrap())
        .unwrap();
    drop(input);
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "serializer extraction failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let hashes: BTreeMap<String, String> = serde_json::from_slice(&output.stdout).unwrap();
    for pin in PINNED_SOURCES {
        if hashes.get(pin.path).map(String::as_str) != Some(pin.sha256) {
            return Err(pin.path);
        }
    }
    Ok(())
}

fn assert_pinned_body_writer() {
    static VERIFIED: std::sync::OnceLock<Result<(), &'static str>> = std::sync::OnceLock::new();
    VERIFIED
        .get_or_init(|| verify_pinned_sources(None))
        .expect("pinned MAIN 53d05a43 writer changed; provide genuine archived writer bytes");
}

#[test]
fn pinned_v1_serializer_regions_match_main() {
    // Portable positive control: provenance must also run without native layout.
    assert_pinned_body_writer();
}

fn assert_source_drift_refused(path: &str, before: &str, after: &str) {
    let pin = PINNED_SOURCES.iter().find(|pin| pin.path == path).unwrap();
    assert_eq!(pin.text.matches(before).count(), 1, "drift premise");
    let changed = pin.text.replacen(before, after, 1);
    assert_ne!(changed, pin.text);
    // Exercise exactly the complete guard used before the post-save read,
    // substituting only an in-memory source unit. Never edit production files.
    assert_eq!(verify_pinned_sources(Some((path, &changed))), Err(pin.path));
}

#[test]
fn pinned_v1_refuses_enum_tag_drift() {
    assert_source_drift_refused("snapshots.rs", "    0 => Codex,", "    9 => Codex,");
}

#[test]
fn pinned_v1_refuses_handwritten_codec_order_drift() {
    assert_source_drift_refused(
        "snapshots.rs",
        "        context.put(e)?;\n        sources.put(e)",
        "        sources.put(e)?;\n        context.put(e)",
    );
}

#[test]
fn pinned_v1_refuses_nested_counting_version_drift() {
    assert_source_drift_refused(
        "snapshots/codex_counting_version.rs",
        "    1 => V2,",
        "    9 => V2,",
    );
}

#[test]
fn pinned_v1_accepts_unrelated_function_and_comment_edits() {
    let path = "snapshots.rs";
    let pin = PINNED_SOURCES.iter().find(|pin| pin.path == path).unwrap();
    let changed = format!("{}\n// Unrelated comment, with fake durable_struct!(Ignored {{ N n: u64 }});\nfn unrelated_fixture_function() {{ let _text = \"impl Durable for Ignored {{}}\"; }}\n", pin.text);
    assert_ne!(changed, pin.text);
    assert_eq!(verify_pinned_sources(Some((path, &changed))), Ok(()));
}

#[test]
fn pinned_v1_refuses_added_durable_struct() {
    let path = "snapshots.rs";
    let pin = PINNED_SOURCES.iter().find(|pin| pin.path == path).unwrap();
    let changed = format!(
        "{}\ncrate::durable_tail_codec::durable_struct!(Added {{ N n: u64 }});\n",
        pin.text
    );
    assert_eq!(verify_pinned_sources(Some((path, &changed))), Err(path));
}

#[test]
fn pinned_v1_refuses_added_manual_durable_impl() {
    let path = "snapshots.rs";
    let pin = PINNED_SOURCES.iter().find(|pin| pin.path == path).unwrap();
    let changed = format!("{}\nimpl crate::durable_tail_codec::Durable for Added {{ fn put(&self, e: &mut Enc) {{ e.varint(9); }} }}\n", pin.text);
    assert_eq!(verify_pinned_sources(Some((path, &changed))), Err(path));
}

#[test]
fn pinned_v1_refuses_encoding_constant_and_local_helper_drift() {
    assert_source_drift_refused(
        "snapshots/sampled_jsonl/durable.rs",
        "pub(crate) const HEAD_BOUND: u64 = 1024 * 1024;",
        "pub(crate) const HEAD_BOUND: u64 = 2 * 1024 * 1024;",
    );
    assert_source_drift_refused(
        "snapshots/sampled_jsonl/durable.rs",
        "let mut e = Enc::hash(domain);",
        "let mut e = Enc::hash(\"different-domain\");",
    );
}

fn pinned_header(out: &mut Vec<u8>, record: &PendingRecord, generation: u64) {
    let binding = &record.binding;
    let certificate = &record.certificate;
    out.extend_from_slice(b"ottto-dt");
    out.extend_from_slice(&1_u16.to_le_bytes());
    out.extend_from_slice(&record.allowlist);
    out.push(match binding.source {
        DurableSource::ClaudeCode => 1,
        DurableSource::Codex => 2,
    });
    for part in [
        &binding.key,
        &binding.context,
        &binding.scope,
        &binding.entry,
    ] {
        out.extend_from_slice(part);
    }
    out.extend_from_slice(&generation.to_le_bytes());
    for value in [certificate.device, certificate.inode, certificate.length] {
        out.extend_from_slice(&value.to_le_bytes());
    }
    out.extend_from_slice(&certificate.modified.0.to_le_bytes());
    out.extend_from_slice(&certificate.modified.1.to_le_bytes());
    out.extend_from_slice(&certificate.birth_nanos.to_le_bytes());
    out.extend_from_slice(&certificate.sealed_offset.to_le_bytes());
    out.extend_from_slice(&certificate.sample_len.to_le_bytes());
    out.extend_from_slice(&certificate.head_sha256);
    out.extend_from_slice(&certificate.boundary_sha256);
    out.extend_from_slice(&certificate.verified_unix_seconds.to_le_bytes());
    out.push(u8::from(certificate.audit_debt_unix_seconds.is_some()));
    out.extend_from_slice(
        &certificate
            .audit_debt_unix_seconds
            .unwrap_or(0)
            .to_le_bytes(),
    );
    out.extend_from_slice(&(record.body.len() as u32).to_le_bytes());
}

fn pinned_bytes(record: &PendingRecord, generation: u64) -> Vec<u8> {
    let mut bytes = Vec::new();
    pinned_header(&mut bytes, record, generation);
    bytes.extend_from_slice(&record.body);
    let trailer = Sha256::digest(&bytes);
    bytes.extend_from_slice(&trailer);
    bytes
}
