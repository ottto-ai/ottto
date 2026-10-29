//! Genuine v1 records from main's pinned 53d05a43 writer, before R2 (#865).
//! Read the production post-save artifact unchanged: never rewrite its version,
//! binding, allowlist, body or trailer. Source pins below fail on codec drift;
//! a future writer must supply archived bytes rather than relabel its output.
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

// Conservative closure of CachedJsonlReduction + Rederive's serializer graph:
// every 53d05a43 source unit defining a durable struct/enum or handwritten
// Durable/HDigest/key/empty implementation, plus owned_heap's container helpers.
// Whole files pin constants, label tables, helper functions and field order,
// including SelectorCapture and CountingVersion/AckEvidence. A new dependency
// requires editing one of these pinned definitions and therefore refuses too.
// This intentionally also refuses unrelated edits in those units; do not refresh
// hashes from the candidate. Supply historical artifacts when the writer drifts.
struct SourcePin {
    path: &'static str,
    text: &'static str,
    sha256: &'static str,
}
const PINNED_SOURCES: &[SourcePin] = &[
    SourcePin {
        path: "codex_prelude_footprint.rs",
        text: include_str!("../../codex_prelude_footprint.rs"),
        sha256: "9cc88564fc5dca3bc4b710e00ca1d4ddb20eb9ee36d562abe5e9a027fa9f675e",
    },
    SourcePin {
        path: "durable_tail_codec.rs",
        text: include_str!("../../durable_tail_codec.rs"),
        sha256: "c4e15c5d669876f8e92e10db812386bd6bb2d6ed9b543d7d8505c5cda6c1fa7a",
    },
    SourcePin {
        path: "snapshots/cache_observations.rs",
        text: include_str!("../cache_observations.rs"),
        sha256: "2b3965077015d599a07c2508963d97ce4a25873336689a0e41bc9f36671526d9",
    },
    SourcePin {
        path: "snapshots/claude_context_file_birth.rs",
        text: include_str!("../claude_context_file_birth.rs"),
        sha256: "3c89201a5a950afc499e904782b4b47d9e2a111a7edf1437675113c0f678bd49",
    },
    SourcePin {
        path: "snapshots/claude_request_identity.rs",
        text: include_str!("../claude_request_identity.rs"),
        sha256: "0a19f1f84d4612ef560b7b5b80297eed0b2921cfe95983ec5c82bd5758378587",
    },
    SourcePin {
        path: "snapshots/claude_response_records.rs",
        text: include_str!("../claude_response_records.rs"),
        sha256: "85b9bc82c366301cddcb66e3f98233c15ea75fbc46d6fa4efee9aa8d1ad42135",
    },
    SourcePin {
        path: "snapshots/codex_counting_version.rs",
        text: include_str!("../codex_counting_version.rs"),
        sha256: "825f0adb25c9a724c8554f7f94f00ec5e3b05a6f2c265eb9b6c28adc1c11ead1",
    },
    SourcePin {
        path: "snapshots/codex_usage_occurrence.rs",
        text: include_str!("../codex_usage_occurrence.rs"),
        sha256: "d9f07000a832756d7649b282b1689134879cd5b5d570dd88c3e82b5bb783e075",
    },
    SourcePin {
        path: "snapshots/compaction_events.rs",
        text: include_str!("../compaction_events.rs"),
        sha256: "141363c840e4e1162e8aa447b82dbd6b5bdc81ceb7eb418c2121793b85af482c",
    },
    SourcePin {
        path: "snapshots/context_curve.rs",
        text: include_str!("../context_curve.rs"),
        sha256: "8bda8658c184e027b7cd080e7ca43c3f3f1f47e978cec682e15a74035a72bd78",
    },
    SourcePin {
        path: "snapshots/local_context_points.rs",
        text: include_str!("../local_context_points.rs"),
        sha256: "84e4a1768648f2b9b667d0dee738d27942cb7166d74899ff8121b09ecff67755",
    },
    SourcePin {
        path: "snapshots/sampled_jsonl/durable.rs",
        text: include_str!("../sampled_jsonl/durable.rs"),
        sha256: "23aca37dbf2c9fed9b21c39be142d50eeb1e707dbae3539d5113b57c4ddb475b",
    },
    SourcePin {
        path: "snapshots/sampled_jsonl.rs",
        text: include_str!("../sampled_jsonl.rs"),
        sha256: "01c58d7f14b4df3de72d1bcada3230fda08c5af8302bb52c12897bea61028746",
    },
    SourcePin {
        path: "snapshots/session_start.rs",
        text: include_str!("../session_start.rs"),
        sha256: "e27611e8e8036d7bd068c466e86183bc773dd543adddcf9d7989fd7c1f01cf29",
    },
    SourcePin {
        path: "snapshots.rs",
        text: include_str!("../../snapshots.rs"),
        sha256: "21868107bf2022113d8d906f67fa42f94dea8f826e47c7867a4ec8f2d3a2368d",
    },
    SourcePin {
        path: "owned_heap.rs",
        text: include_str!("../../owned_heap.rs"),
        sha256: "aca2f7c2f5c1827968ad04fd3140bf24709c519034e897310ffc5accde5d75e1",
    },
];

// The only source differences allowed from MAIN 53d05a43: the two exact
// cfg(test) byte observers introduced by this fixture. No serializer definition,
// constant, label, enum tag or handwritten codec is removed from the hash.
const CONSUMPTION_OBSERVERS: [&str; 2] = [
    "                    #[cfg(all(test, unix))]\n                    sampled_scan::transition_fixture::record_consumed((offset + 1) as u64);\n",
    "                    #[cfg(all(test, unix))]\n                    sampled_scan::transition_fixture::record_consumed(len as u64);\n",
];

fn verify_pinned_sources(replacement: Option<(&str, &str)>) -> Result<(), &'static str> {
    for pin in PINNED_SOURCES {
        let source = replacement
            .filter(|(path, _)| *path == pin.path)
            .map_or(pin.text, |(_, text)| text);
        let digest = if pin.path == "snapshots.rs" {
            let original = CONSUMPTION_OBSERVERS
                .into_iter()
                .fold(source.to_string(), |text, observer| {
                    text.replace(observer, "")
                });
            Sha256::digest(original.as_bytes())
        } else {
            Sha256::digest(source.as_bytes())
        };
        if format!("{digest:x}") != pin.sha256 {
            return Err(pin.path);
        }
    }
    Ok(())
}

fn assert_pinned_body_writer() {
    verify_pinned_sources(None)
        .expect("pinned MAIN 53d05a43 writer changed; provide genuine archived writer bytes");
}

#[test]
fn pinned_v1_full_serializer_sources_match_main() {
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
