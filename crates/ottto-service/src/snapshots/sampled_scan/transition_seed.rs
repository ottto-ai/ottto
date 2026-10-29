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
//! limits and owner-reviewed rebaseline procedure. Runtime tree walking sees
//! new non-catalog files; cfg(test)-only code is excluded. The adjacent JSON
//! inventory enumerates helper references, pinned providers and exceptions;
//! adding a reference requires an explicit inventory review.
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

// Pin serializer regions of the baseline units, plus one qualified extent helper.
// Discovery walks EVERY src/**/*.rs; non-catalog serializer regions must be empty.
// Hashes are generated with the SAME extractor using --baseline 53d05a43;
// unrelated source edits are ignored, and new serializer definitions refuse.
struct SourcePin {
    path: &'static str,
    text: &'static str,
    sha256: &'static str,
}
const PINNED_SOURCES: &[SourcePin] = &[
    SourcePin {
        path: "codex_scan_diagnostics.rs",
        text: include_str!("../../codex_scan_diagnostics.rs"),
        sha256: "2f1433a7f722a6fed7b0883b6873cc0b9c7b54aed43953ada7b504a8a3a4be34",
    },
    SourcePin {
        path: "codex_prelude_footprint.rs",
        text: include_str!("../../codex_prelude_footprint.rs"),
        sha256: "2459e58e5f2bb58ecf30ac8e27a7bb04e42fb059fe7b1164ab5640958c1a47ef",
    },
    SourcePin {
        path: "durable_tail_codec.rs",
        text: include_str!("../../durable_tail_codec.rs"),
        sha256: "dc56bac8c7a9e478df9df2eff82f83f409429a43750bfb1599c14a0190c4f9a6",
    },
    SourcePin {
        path: "snapshots/cache_observations.rs",
        text: include_str!("../cache_observations.rs"),
        sha256: "8e6149a1d900c8b08fcef32c98dffb2d2068ab693b19c40ac142ba33d1daf0f9",
    },
    SourcePin {
        path: "snapshots/claude_context_file_birth.rs",
        text: include_str!("../claude_context_file_birth.rs"),
        sha256: "860991b52bf5bb2cf8cbfe97cfd0cc718bea4c04b48fe6e5730371f4cf46d588",
    },
    SourcePin {
        path: "snapshots/claude_request_identity.rs",
        text: include_str!("../claude_request_identity.rs"),
        sha256: "1e69a00b4ebee5293c50a5821bd762593d57fcc40a2972194313ef8ce1c0e08c",
    },
    SourcePin {
        path: "snapshots/claude_response_records.rs",
        text: include_str!("../claude_response_records.rs"),
        sha256: "64f73ce9b4efea512629c05a5dc7a1c5becafd869b2d97a585f55672e170d80d",
    },
    SourcePin {
        path: "snapshots/codex_counting_version.rs",
        text: include_str!("../codex_counting_version.rs"),
        sha256: "958f27ce4b7bf9c91290ae7335b51176f0c70f61840fcb797cc6ccec8388dc18",
    },
    SourcePin {
        path: "snapshots/codex_usage_occurrence.rs",
        text: include_str!("../codex_usage_occurrence.rs"),
        sha256: "3a136aa935ea75df886802f9ead0f92c2710a68ef5f6260b7485e138d91148a3",
    },
    SourcePin {
        path: "snapshots/compaction_events.rs",
        text: include_str!("../compaction_events.rs"),
        sha256: "022e30453631e93a71583b9e8cb451620e88685122fb27bfd9e94f5ac29f05ce",
    },
    SourcePin {
        path: "snapshots/context_curve.rs",
        text: include_str!("../context_curve.rs"),
        sha256: "33b96640a27df9c4509a5668ccc1f34a0d4451dcfa2da5b862e2ecdcdaed6392",
    },
    SourcePin {
        path: "snapshots/local_context_points.rs",
        text: include_str!("../local_context_points.rs"),
        sha256: "32ed5c1287c1bb742c10d1920aaaa9e4ac779602deff0c1b1f7519b64a6ea700",
    },
    SourcePin {
        path: "snapshots/sampled_jsonl/durable.rs",
        text: include_str!("../sampled_jsonl/durable.rs"),
        sha256: "6dd31f632b2cf25258a95d346cca8ad12d368715a2be45e88e0f2751bbdd7879",
    },
    SourcePin {
        path: "snapshots/sampled_jsonl.rs",
        text: include_str!("../sampled_jsonl.rs"),
        sha256: "877dc114bbc0b3814961b085864c8f0fb7ee4f6be6566c52ac5393820efe118e",
    },
    SourcePin {
        path: "snapshots/session_start.rs",
        text: include_str!("../session_start.rs"),
        sha256: "2a5639944e4ba77464af196159ceebd26aa471b711240ccf866dd5e07a0afad3",
    },
    SourcePin {
        path: "snapshots.rs",
        text: include_str!("../../snapshots.rs"),
        sha256: "f3f1bd26369ffc30fbc292e9d2d3c093eae55f8ea6e2cf349b56801248550cc2",
    },
    SourcePin {
        path: "owned_heap.rs",
        text: include_str!("../../owned_heap.rs"),
        sha256: "3c49ce9518959f9408a69a50b03d54ed2f480f27049a57d8c18eb593fc427f2c",
    },
];

fn verify_pinned_sources(replacement: Option<(&str, &str)>) -> Result<(), &'static str> {
    use std::io::Write;
    use std::process::{Command, Stdio};
    let sources = replacement.into_iter().collect::<BTreeMap<_, _>>();
    let mut child = Command::new("python3")
        .args([
            "-c",
            include_str!("transition_serializer_regions.py"),
            "--source-root",
        ])
        .arg(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("test serializer extractor requires Python 3");
    // Walking the checkout, rather than embedding a fixed file catalog, notices
    // future source files. CI and native fixture runs have the source tree.
    // Python drains the override request before emitting hashes/reference names;
    // writing the changed snapshots.rs cannot deadlock against a full stdout.
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
    #[derive(serde::Deserialize)]
    struct Extraction {
        hashes: BTreeMap<String, String>,
        references: BTreeSet<String>,
    }
    let extraction: Extraction = serde_json::from_slice(&output.stdout).unwrap();
    let hashes = extraction.hashes;
    for pin in PINNED_SOURCES {
        if hashes.get(pin.path).map(String::as_str) != Some(pin.sha256) {
            return Err(pin.path);
        }
    }
    if hashes.len() != PINNED_SOURCES.len() {
        return Err("serializer regions outside baseline catalog");
    }
    let inventory: BTreeMap<String, String> =
        serde_json::from_str(include_str!("transition_serializer_helpers.json")).unwrap();
    assert!(inventory
        .values()
        .all(|status| status.starts_with("pinned: ") || status.starts_with("exception: ")));
    if extraction.references != inventory.into_keys().collect::<BTreeSet<_>>() {
        return Err("serializer helper reference inventory changed; owner review required");
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
    // The sole cryptographic dependency exception has the standardized SHA-256
    // contract; this independent vector checks its concrete implementation.
    assert_eq!(
        format!("{:x}", Sha256::digest(b"abc")),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
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
        "pub(crate) const NAMED_LINES: usize = 4;",
        "pub(crate) const NAMED_LINES: usize = 5;",
    );
    assert_source_drift_refused(
        "snapshots/sampled_jsonl/durable.rs",
        "let mut e = Enc::hash(domain);",
        "let mut e = Enc::hash(\"different-domain\");",
    );
}

#[test]
fn pinned_v1_refuses_serializer_in_non_catalog_source() {
    for (path, original) in [
        ("canonical_json.rs", include_str!("../../canonical_json.rs")),
        ("fixture_added_source.rs", ""),
    ] {
        assert!(!PINNED_SOURCES.iter().any(|pin| pin.path == path));
        let changed = format!(
            "{original}\ncrate::durable_tail_codec::durable_struct!(Added {{ N n: u64 }});\n"
        );
        assert_eq!(
            verify_pinned_sources(Some((path, &changed))),
            Err("serializer regions outside baseline catalog")
        );
    }
}

#[test]
fn pinned_v1_accepts_test_only_serializers_outside_catalog() {
    // Inline, file-level and externally declared test modules are excluded.
    let changed = "#[cfg(all(test, unix))] mod tests { crate::durable_tail_codec::durable_struct!(Added { N n: u64 }); }";
    assert_eq!(
        verify_pinned_sources(Some(("fixture_added_source.rs", changed))),
        Ok(())
    );
    let changed = "#![cfg(test)]\ncrate::durable_tail_codec::durable_struct!(Added { N n: u64 });";
    assert_eq!(
        verify_pinned_sources(Some(("fixture_added_source.rs", changed))),
        Ok(())
    );
    let changed = "crate::durable_tail_codec::durable_struct!(Added { N n: u64 });";
    assert_eq!(
        verify_pinned_sources(Some(("snapshots/sampled_scan/transition_seed.rs", changed))),
        Ok(())
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
