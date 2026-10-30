//! Genuine v1 records from main's pinned 53d05a43 writer, before R2 (#865).
//! Read the production post-save artifact unchanged: never rewrite its version,
//! binding, allowlist, body or trailer. The seed compares it byte for byte with
//! what a hash-pinned `archived_writers` copy of that writer emits for the
//! retained live reduction (never for the stored body), so current source can
//! move on while a future writer that drifts, even by reordering two same-type
//! fields, refuses instead of being relabeled. Header fields other than the
//! body come from the stored record after the binding checks below.
//!
//! The `PINNED_SOURCES` tests below stay as the separate check on CURRENT code.
//! Serializer regions are extracted by the single companion Python standard-
//! library tool used for both baseline generation and candidate verification.
//! Only tests launch it; production has no subprocess or dependency change.
//! It balances Rust tokens, preserves literals, removes comments/whitespace,
//! discovers durable macros/trait impls and follows local helpers/constants.
//! Trait paths accept qualified prefixes and optional :: before generic args;
//! raw identifiers stay distinct from keywords. Unsupported trait paths fail.
//! Literal macro_rules impls are scanned; generated trait names/token assembly
//! still require owner review (no macro expansion or name resolution here).
//! Explicit roots cover body encoding, allowlist labels, session-start content
//! hashes, source slugs, native body publication/store framing/verification,
//! and owned-container inherent dispatch plus Deref/Default/From. See the tool docstring for
//! limits and owner-reviewed rebaseline procedure. Runtime tree walking sees
//! new non-catalog files; cfg(test)-only code is excluded. The adjacent JSON
//! inventory enumerates helper references, pinned providers and exceptions;
//! adding a reference requires an explicit inventory review.
//! Python 3 and the source checkout are mandatory test prerequisites: missing
//! python3, walk/parse failure or malformed extractor output panics, never skips.
//! There is no environment opt-out. Tests inject an interpreter/root per call;
//! they never change PATH or other process-global environment variables.
use super::*;
use archived_writers::{ArchivedRecord, ArchivedWriter, StateNode, W_53d05a43};
use sha2::{Digest, Sha256};

#[path = "archived_writers/mod.rs"]
pub(crate) mod archived_writers;

/// The fixture rows name writers by pin; `W_53d05a43` is the default row.
pub(crate) fn seed_pinned_v1(
    cache: &SharedCache,
    source: SnapshotSource,
    key: &str,
    index: &ScanIndex,
    pin: &str,
) -> Vec<u8> {
    archived_writers::require_known(pin);
    match pin {
        W_53d05a43::PIN => seed_archived::<W_53d05a43>(cache, source, key, index),
        other => panic!("archived writer {other} has no seed arm"),
    }
}

pub(crate) fn seed_archived<W: ArchivedWriter>(
    cache: &SharedCache,
    source: SnapshotSource,
    key: &str,
    index: &ScanIndex,
) -> Vec<u8> {
    archived_writers::assert_provenance::<W>();
    let (checkpoint, state) = {
        let retained = cache.retained().unwrap();
        let retained = retained.peek(key).expect("populated native reduction");
        (retained.checkpoint.clone(), format!("{:?}", retained.state))
    };
    let state = StateNode::parse(&state)
        .unwrap_or_else(|error| panic!("live reduction rendering did not parse: {error}"));
    let ds = durable_source(source).unwrap();
    let mut stores = cache.durable().unwrap();
    let slot = stores.slot(ds).as_mut().unwrap();
    let interpretation =
        Interpretation::of(source, key, index, slot.identity_capture, &slot.namespace);
    let expected = expected(
        ds,
        source,
        key,
        checkpoint.scope(),
        index,
        &interpretation,
        None,
    )
    .unwrap();
    let record = match slot.store.read(&expected.binding.key) {
        ReadOutcome::Found(record) => record,
        other => panic!("pinned writer did not produce a readable record: {other:?}"),
    };
    let source_tag = match record.record.binding.source {
        DurableSource::ClaudeCode => 1,
        DurableSource::Codex => 2,
    };
    assert_eq!(record.format, W::FORMAT);
    assert_eq!(Ok(record.record.allowlist), W::allowlist(source_tag));
    assert_eq!(record.record.binding, expected.binding);
    assert_eq!(record.index_generation, index.generation);
    let name = expected
        .binding
        .key
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    let bytes = std::fs::read(slot.store.dir().join(format!("{name}.rec"))).unwrap();
    assert_eq!(
        u16::from_le_bytes(bytes[8..10].try_into().unwrap()),
        W::FORMAT
    );
    let binding = &record.record.binding;
    let certificate = &record.record.certificate;
    let archived = W::encode_live(
        &ArchivedRecord {
            source_tag,
            key: binding.key,
            context: binding.context,
            scope: binding.scope,
            entry: binding.entry,
            allowlist: record.record.allowlist,
            generation: record.index_generation,
            device: certificate.device,
            inode: certificate.inode,
            length: certificate.length,
            modified: certificate.modified,
            birth_nanos: certificate.birth_nanos,
            sealed_offset: certificate.sealed_offset,
            sample_len: certificate.sample_len,
            head_sha256: certificate.head_sha256,
            boundary_sha256: certificate.boundary_sha256,
            verified_unix_seconds: certificate.verified_unix_seconds,
            audit_debt: record
                .envelope_audit_debt
                .or(certificate.audit_debt_unix_seconds),
            body: Vec::new(),
        },
        &state,
        crate::snapshots::jsonl_line_cap() as u64,
    )
    .unwrap_or_else(|error| panic!("writer {} refused this live state: {error}", W::PIN));
    assert_eq!(
        bytes,
        archived,
        "production no longer emits writer {}; seed its bytes instead of relabeling",
        W::PIN
    );
    bytes
}

// Pin serializer, body-publication/store-framing regions and qualified helpers.
// Discovery walks EVERY src/**/*.rs; non-catalog serializer regions must be empty.
// Hashes are generated with the SAME extractor using --baseline <reviewed-ref>;
// unrelated source edits are ignored, and new serializer definitions refuse.
struct SourcePin {
    path: &'static str,
    text: &'static str,
    sha256: &'static str,
}
const PINNED_SOURCES: &[SourcePin] = &[
    SourcePin {
        path: "snapshots/sampled_scan/durable_tail.rs",
        text: include_str!("durable_tail.rs"),
        sha256: "2fdd2916a71021bd4ec74568d3a7651df86f07896aa21acae5ec2cd361603e84",
    },
    SourcePin {
        path: "durable_tail_store.rs",
        text: include_str!("../../durable_tail_store.rs"),
        sha256: "1a20538d2cd8cdafb44e6cdc093313cf877ff54cda37f6f79a4168339d4e6fb9",
    },
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
        sha256: "6e83200e5b58c08c228ef1bfad1151b229343bbbb1eef255d1ce4f35477c4f65",
    },
    SourcePin {
        path: "snapshots/sampled_jsonl.rs",
        text: include_str!("../sampled_jsonl.rs"),
        sha256: "d33615424a83737c6f6a38508957ef673421dea4c9e7e645ea7920ce673888d6",
    },
    SourcePin {
        path: "snapshots/session_start.rs",
        text: include_str!("../session_start.rs"),
        sha256: "2a5639944e4ba77464af196159ceebd26aa471b711240ccf866dd5e07a0afad3",
    },
    SourcePin {
        path: "snapshots.rs",
        text: include_str!("../../snapshots.rs"),
        sha256: "df4fa458a11f4e45199884e69baeebeeb83c9a67f410ba9eac50334d384815b8",
    },
    SourcePin {
        path: "owned_heap.rs",
        text: include_str!("../../owned_heap.rs"),
        sha256: "397dd734a76404232b6165da638c9b5ccc53ff73c2e2def4d5cb83fe9253b488",
    },
];

#[derive(serde::Deserialize)]
struct Extraction {
    hashes: BTreeMap<String, String>,
    references: BTreeSet<String>,
}

fn extract_sources(
    replacement: Option<(&str, &str)>,
    interpreter: &std::ffi::OsStr,
    source_root: &std::path::Path,
) -> Extraction {
    extract_overrides(
        &replacement.into_iter().collect::<Vec<_>>(),
        interpreter,
        source_root,
    )
}

fn extract_overrides(
    replacements: &[(&str, &str)],
    interpreter: &std::ffi::OsStr,
    source_root: &std::path::Path,
) -> Extraction {
    let output = run_extractor(&[], replacements, interpreter, source_root, None);
    assert!(
        output.status.success(),
        "python3 serializer extraction failed (walk/parse): {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout)
        .expect("python3 serializer extractor returned invalid JSON")
}

fn run_extractor(
    arguments: &[&std::ffi::OsStr],
    replacements: &[(&str, &str)],
    interpreter: &std::ffi::OsStr,
    source_root: &std::path::Path,
    directory: Option<&std::path::Path>,
) -> std::process::Output {
    use std::io::Write;
    use std::process::{Command, Stdio};
    let sources = replacements.iter().copied().collect::<BTreeMap<_, _>>();
    let mut command = Command::new(interpreter);
    command
        .args([
            "-c",
            include_str!("transition_serializer_regions.py"),
            "--source-root",
        ])
        .arg(source_root)
        .args(arguments);
    if let Some(directory) = directory {
        command.current_dir(directory);
    }
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|error| {
            panic!("serializer extractor requires python3 interpreter {interpreter:?}: {error}")
        });
    // Walking the checkout, rather than embedding a fixed file catalog, notices
    // future source files. CI and native fixture runs have the source tree.
    // Python drains the override request before emitting hashes/reference names;
    // writing the changed snapshots.rs cannot deadlock against a full stdout.
    let mut input = child.stdin.take().unwrap();
    input
        .write_all(&serde_json::to_vec(&sources).unwrap())
        .expect("python3 serializer extractor request could not be written");
    drop(input);
    child
        .wait_with_output()
        .expect("python3 serializer extractor process must complete")
}

fn extract_with_python(replacement: Option<(&str, &str)>) -> Extraction {
    extract_sources(
        replacement,
        std::ffi::OsStr::new("python3"),
        &std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
    )
}

fn verify_pinned_sources(replacement: Option<(&str, &str)>) -> Result<(), &'static str> {
    verify_extraction(extract_with_python(replacement))
}

fn verify_extraction(extraction: Extraction) -> Result<(), &'static str> {
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
        (
            "fixture_with_test_function.rs",
            "fn test_only() { #![cfg(test)] crate::durable_tail_codec::durable_struct!(TestOnly { N n: u64 }); }",
        ),
        (
            "fixture_with_nested_test.rs",
            "mod test_only { #![cfg(test)] crate::durable_tail_codec::durable_struct!(TestOnly { N n: u64 }); }",
        ),
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
    let changed = "mod test_only { #![cfg(test)] crate::durable_tail_codec::durable_struct!(Added { N n: u64 }); }";
    assert_eq!(
        verify_pinned_sources(Some(("fixture_added_source.rs", changed))),
        Ok(())
    );
    let changed = "fn test_only() { #![cfg(test)] crate::durable_tail_codec::durable_struct!(Added { N n: u64 }); }";
    assert_eq!(
        verify_pinned_sources(Some(("fixture_added_source.rs", changed))),
        Ok(())
    );
    let changed = "#![cfg(test)]\ncrate::durable_tail_codec::durable_struct!(Added { N n: u64 });";
    assert_eq!(
        verify_pinned_sources(Some(("fixture_added_source.rs", changed))),
        Ok(())
    );
    // This file owns the archive modules, so a stand-in must still declare them.
    let changed =
        format!("#[path = \"archived_writers/mod.rs\"] mod archived_writers;\n{ADDED_SERIALIZER}");
    assert_eq!(
        verify_pinned_sources(Some((
            "snapshots/sampled_scan/transition_seed.rs",
            &changed
        ))),
        Ok(())
    );
}

const ADDED_DURABLE_METHODS: &str = r#"
    fn put(&self, e: &mut Enc) -> Result<(), Refuse> { e.varint(9) }
    fn take(_: &mut Dec<'_>) -> Result<Self, Corrupt> { Err(Corrupt) }
    fn verify(_: &mut Dec<'_>) -> Result<(), Corrupt> { Ok(()) }
    fn shape(s: &mut Shape) { s.push("added"); }
"#;

fn assert_added_impl_and_body_refused(header: &str) {
    assert_added_source_and_body_refused(&format!("{header} {{ {ADDED_DURABLE_METHODS} }}"));
}

fn assert_added_source_and_body_refused(original: &str) {
    let path = "fixture_added_source.rs";
    assert_eq!(original.matches("e.varint(9)").count(), 1);
    let changed = original.replacen("e.varint(9)", "e.varint(7)", 1);
    assert_ne!(original, changed);
    // Prove that put's changed byte affects a selected region, then run both
    // extractions through exactly the verifier called by the genuine seed.
    let before = extract_with_python(Some((path, original)));
    let after = extract_with_python(Some((path, &changed)));
    assert!(before.hashes.contains_key(path));
    assert!(after.hashes.contains_key(path));
    assert_ne!(before.hashes[path], after.hashes[path]);
    for extraction in [before, after] {
        assert_eq!(
            verify_extraction(extraction),
            Err("serializer regions outside baseline catalog")
        );
    }
}

#[test]
fn pinned_v1_refuses_const_generic_impl_and_body_drift() {
    assert_added_impl_and_body_refused("impl<T: Marker<{ 1 + 1 }>> Durable for Added<T>");
}

#[test]
fn pinned_v1_refuses_where_clause_impl_and_body_drift() {
    assert_added_impl_and_body_refused(
        "impl<T> crate::durable_tail_codec::Durable for Added<T> where T: Marker<{ 1 + 1 }>",
    );
}

#[test]
fn pinned_v1_refuses_trait_path_turbofish_and_body_drift() {
    // E1's exact counterexample, including its actual trait import and type.
    assert_added_source_and_body_refused(&format!(
        "use crate::durable_tail_codec::{{Corrupt, Dec, Durable, Enc, Refuse, Shape}};\nstruct Added;\nimpl Durable::<> for Added {{ {ADDED_DURABLE_METHODS} }}"
    ));
    for header in [
        "impl crate::durable_tail_codec::Durable::<> for Added",
        "impl self::Durable::<> for Added",
        "impl super::Durable::<> for Added",
        "impl ::ottto_service::Durable::<> for Added",
        "impl<'a> Durable::<> for Added<'a>",
    ] {
        assert_added_impl_and_body_refused(header);
    }
}

#[test]
fn pinned_v1_accepts_raw_keyword_identifier_and_discovers_raw_self_type() {
    assert_eq!(
        verify_pinned_sources(Some(("fixture_added_source.rs", "struct r#impl;"))),
        Ok(())
    );
    assert_added_source_and_body_refused(&format!(
        "struct r#impl; impl Durable for r#impl {{ {ADDED_DURABLE_METHODS} }}"
    ));
    // Raw spelling must normalize for trait matching and helper discovery too.
    assert_added_source_and_body_refused(&format!(
        "impl r#Durable for Added {{ {ADDED_DURABLE_METHODS} }}"
    ));
    assert_added_source_and_body_refused(&format!(
        "fn r#put_body(e: &mut Enc) -> Result<(), Refuse> {{ e.varint(9) }} impl Durable for Added {{ {} }}",
        ADDED_DURABLE_METHODS.replace("e.varint(9)", "r#put_body(e)")
    ));
}

#[test]
fn pinned_v1_accepts_negative_and_higher_ranked_self_type_headers() {
    // Previously `!` failed classification even for an unrelated negative impl;
    // a second top-level HRTB `for` falsely looked like a trait separator.
    // These are lexical premises, not assertions that feature-gated negative
    // impls or these synthetic types compile with the workspace's stable Rust.
    for source in [
        "struct Added; impl !Unpin for Added {}",
        "unsafe impl<'a> Send for Added<'a> {}",
        "trait Added {} impl dyn Added {}",
        "trait Added {} impl Added for for<'a> fn(&'a ()) {}",
    ] {
        assert_eq!(
            verify_pinned_sources(Some(("fixture_added_source.rs", source))),
            Ok(())
        );
    }
    assert_added_impl_and_body_refused("impl Durable for for<'a> fn(&'a ())");
}

#[test]
fn pinned_v1_refuses_projected_self_type_and_body_drift() {
    // E1's concrete projection must select Durable independently of the
    // unrelated Select impl; changing put must change this unit's digest.
    assert_added_source_and_body_refused(&format!(
        "use crate::durable_tail_codec::{{Corrupt, Dec, Durable, Enc, Refuse, Shape}};\nstruct Added; struct Carrier;\ntrait Select {{ type Output; }}\nimpl Select for Carrier {{ type Output = Added; }}\nimpl Durable for <Carrier as Select>::Output {{ {ADDED_DURABLE_METHODS} }}"
    ));
}

#[test]
fn pinned_v1_refuses_where_clause_hrtb_impl_and_body_drift() {
    assert_added_impl_and_body_refused("impl<F> Durable for Wrap<F> where F: for<'a> Fn(&'a u8)");
}

#[test]
fn pinned_v1_refuses_impl_with_opaque_header_tokens() {
    // Each form must independently select the impl and its changed put body;
    // a second serializer must not mask an omitted impl.
    for header in [
        "impl<T: Marker<{ /* { */ 2 }>> Durable for Added<T>",
        r##"impl<T: Marker<{ { let _ = r#"{}"#; 2 } }>> Durable for Added<T>"##,
        "#[cfg(unix)] impl<T> Durable for Added<T>",
    ] {
        assert_added_impl_and_body_refused(header);
    }
    assert_added_source_and_body_refused(&format!(
        "macro_rules! nested {{ () => {{ impl<T: Marker<{{ 2 }}>> Durable for Added<T> {{ {ADDED_DURABLE_METHODS} }} }}; }}"
    ));
}

#[test]
#[should_panic(expected = "serializer extractor requires python3 interpreter")]
fn pinned_v1_missing_python_fails_loudly() {
    let missing = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("src/snapshots/sampled_scan/nonexistent-python3-interpreter");
    assert!(!missing.exists(), "missing-tool control premise");
    extract_sources(
        None,
        missing.as_os_str(),
        &std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
    );
}

#[test]
#[should_panic(expected = "serializer source walk requires an existing src directory")]
fn pinned_v1_missing_source_tree_fails_loudly() {
    let missing =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("nonexistent-serializer-source-tree");
    assert!(!missing.exists(), "missing-tree control premise");
    extract_sources(None, std::ffi::OsStr::new("python3"), &missing);
}

#[test]
fn pinned_v1_unparseable_headers_fail_loudly() {
    for (source, expected) in [
        (
            "impl<T: Marker<{ 1 + 1 }> Durable for Added<T> {}",
            "unsupported item header",
        ),
        ("impl Durable for Added;", "unsupported impl header"),
        ("impl for<'a> Added {}", "ambiguous trait/self type"),
        (
            "impl Durable for for<Carrier as Select>::Output {}",
            "unclassifiable higher-ranked binder",
        ),
        (
            "impl Durable::<>: for Added {}",
            "unclassifiable trait TypePath",
        ),
        (
            "impl #[cfg(unix)] Durable for Added {}",
            "cannot classify implementation",
        ),
        (
            "crate::durable_tail_codec::durable_struct! Added;",
            "unsupported durable macro header",
        ),
    ] {
        let failure = std::panic::catch_unwind(|| {
            verify_pinned_sources(Some(("fixture_added_source.rs", source)))
        })
        .expect_err("unsupported headers must panic, never produce an empty region set");
        let message = failure
            .downcast_ref::<String>()
            .expect("diagnostic panic string");
        assert!(
            message.contains("python3 serializer extraction failed"),
            "{message}"
        );
        assert!(message.contains(expected), "{message}");
    }
}

fn verify_source_tree(replacements: &[(&str, &str)]) -> Result<(), &'static str> {
    verify_extraction(extract_overrides(
        replacements,
        std::ffi::OsStr::new("python3"),
        &std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
    ))
}

#[test]
fn pinned_v1_refuses_body_publication_and_shadowed_iterator() {
    assert_source_drift_refused(
        "snapshots/sampled_scan/durable_tail.rs",
        "Ok(body) => {",
        "Ok(mut body) => { body.reverse();",
    );
    assert_source_drift_refused(
        "durable_tail_store.rs",
        "out.extend_from_slice(&record.body);",
        "out.extend(record.body.iter().rev());",
    );
    let path = "owned_heap.rs";
    let pin = PINNED_SOURCES.iter().find(|pin| pin.path == path).unwrap();
    let changed = format!("{}\nimpl<K, V> OwnedMap<K, V> {{ fn iter(&self) -> impl Iterator<Item = (&K, &V)> {{ self.values.iter().rev() }} }}", pin.text);
    assert_eq!(verify_pinned_sources(Some((path, &changed))), Err(path));
}

#[test]
fn pinned_v1_accepts_test_item_with_generic_commas() {
    for source in [
        "#[cfg(test)] fn fixture<T, U>(_: (T, U)) { crate::durable_tail_codec::durable_struct!(Added { N n: u64 }); }",
        "#[cfg(test)] pub fn fixture<T, U>(_: (T, U)) where T: Marker<{ 1 + 1 }> { crate::durable_tail_codec::durable_struct!(Added { N n: u64 }); }",
    ] {
        assert_eq!(verify_pinned_sources(Some(("fixture_generic.rs", source))), Ok(()));
    }
}

const ADDED_SERIALIZER: &str = "crate::durable_tail_codec::durable_struct!(Added { N n: u64 });";

#[test]
fn pinned_v1_accepts_external_tests_in_inline_modules() {
    let lib = format!("{}\nmod fixture_parent;", include_str!("../../lib.rs"));
    assert_eq!(verify_source_tree(&[
        ("lib.rs", &lib),
        ("fixture_parent.rs", "mod inner { #[cfg(test)] mod tests; #[cfg(test)] #[path = \"other.rs\"] mod other; }"),
        ("fixture_parent/inner/tests.rs", ADDED_SERIALIZER),
        ("fixture_parent/inner/other.rs", ADDED_SERIALIZER),
    ]), Ok(()));
    assert_eq!(verify_source_tree(&[
        ("lib.rs", &lib),
        ("fixture_parent.rs", "#[path = \"relocated\"] mod inner { #[cfg(test)] #[path = \"other.rs\"] mod other; }"),
        ("relocated/other.rs", ADDED_SERIALIZER),
    ]), Ok(()));
}

#[test]
fn pinned_v1_production_module_membership_overrides_test_paths() {
    let lib = format!("{}\n#[cfg(test)] #[path = \"fixture_parent.rs\"] mod fixtures; #[path = \"fixture_parent/production.rs\"] mod production_fixture;", include_str!("../../lib.rs"));
    assert_eq!(
        verify_source_tree(&[
            ("lib.rs", &lib),
            ("fixture_parent.rs", "#![cfg(test)]\nmod tests;"),
            ("fixture_parent/tests.rs", ADDED_SERIALIZER),
            ("fixture_parent/production.rs", ADDED_SERIALIZER),
        ]),
        Err("serializer regions outside baseline catalog")
    );
    let lib = format!("{}\n#[cfg(test)] #[path = \"fixture_shared.rs\"] mod test_alias; #[path = \"fixture_shared.rs\"] mod production_alias;", include_str!("../../lib.rs"));
    assert_eq!(
        verify_source_tree(&[("lib.rs", &lib), ("fixture_shared.rs", ADDED_SERIALIZER),]),
        Err("serializer regions outside baseline catalog")
    );
}
