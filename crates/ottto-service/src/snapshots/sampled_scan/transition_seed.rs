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

fn assert_pinned_body_writer() {
    for (source, fields_only, expected) in [
        (
            include_str!("../../codex_prelude_footprint.rs"),
            true,
            "b560d11b3af25043af3992a622427459c91e1043b1d26e5c1fbce8d808ea64bb",
        ),
        (
            include_str!("../../durable_tail_codec.rs"),
            false,
            "c4e15c5d669876f8e92e10db812386bd6bb2d6ed9b543d7d8505c5cda6c1fa7a",
        ),
        (
            include_str!("../cache_observations.rs"),
            true,
            "19fd2b0894369b7e5d4e0ffc4393b2294b2e9ed379fd21905296cd4db34cd699",
        ),
        (
            include_str!("../claude_context_file_birth.rs"),
            true,
            "0e52ab0893ab4a4a496ad37edc0c4569fff994570c6b1ad189ce7e11f8b3cee8",
        ),
        (
            include_str!("../claude_request_identity.rs"),
            true,
            "23ab9428bfc6d0e021767eac4606bd229ad05a7d187b3c779ed23f843e6b5afb",
        ),
        (
            include_str!("../claude_response_records.rs"),
            true,
            "e8912e039a726e34635a20f1a64a2d26d8fc6e5b075635ea5bf4ccdce4070655",
        ),
        (
            include_str!("../codex_usage_occurrence.rs"),
            true,
            "097c935f095cc6098793d90d8abbb77d1c7d528c480ad7967bd7aa69c5777634",
        ),
        (
            include_str!("../compaction_events.rs"),
            true,
            "6f21f3161807b04d0cfab49fdb07bbbabcab166a27d2b49a0ed3d085b95e4503",
        ),
        (
            include_str!("../context_curve.rs"),
            true,
            "8012516f7948d1f9e2998115ea41ee68243f8e1248734112d9b42b2e4322e66c",
        ),
        (
            include_str!("../local_context_points.rs"),
            true,
            "c89ca6f5f4038cb60ea108baf3a5ce41e7e29dcb57930dcdd90151c9b03f07ba",
        ),
        (
            include_str!("../sampled_jsonl/durable.rs"),
            false,
            "23aca37dbf2c9fed9b21c39be142d50eeb1e707dbae3539d5113b57c4ddb475b",
        ),
        (
            include_str!("../sampled_jsonl.rs"),
            true,
            "94c95d6b264ee61d9b37690f4a9f9fc20dbda2d397b0c911c82dc00e5867ba07",
        ),
        (
            include_str!("../session_start.rs"),
            true,
            "798a4510b8bf67497060b9791ef7c7b50ab5a3f097060334cb3928c9c7e6b397",
        ),
        (
            include_str!("../../snapshots.rs"),
            true,
            "df4b5f1955fd99c51f01e8e220e79b4cf47553450f79a69d95e12f0835886d16",
        ),
    ] {
        let text = if fields_only {
            source
                .split("durable_struct!(")
                .skip(1)
                .map(|part| format!("{});", part.split_once(");").unwrap().0))
                .collect::<String>()
        } else {
            source.to_string()
        };
        assert_eq!(
            format!("{:x}", Sha256::digest(text.as_bytes())),
            expected,
            "pinned v1 body writer changed; provide genuine archived writer bytes"
        );
    }
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
