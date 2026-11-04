//! SHA-256 part hashing and the canonical file-set digests that file
//! finalization records.

use sha2::{Digest, Sha256};

pub(in crate::snapshots) fn sha256_hex(parts: &[&str]) -> String {
    format!("{:x}", sha256_digest(parts))
}

pub(in crate::snapshots) fn sha256_digest(parts: &[&str]) -> sha2::digest::Output<Sha256> {
    let mut digest = Sha256::new();
    for part in parts {
        digest.update(part.as_bytes());
        digest.update([0]);
    }
    digest.finalize()
}

/// Feed `bytes` into `digest` behind a 4-byte big-endian length.
///
/// The length prefix is the whole point: a bare concatenation of variable-length
/// fields lets two different field splits produce identical bytes, so the fold
/// would not actually pin the set it claims to summarise.
pub(in crate::snapshots) fn update_length_prefixed(digest: &mut Sha256, bytes: &[u8]) {
    digest.update((bytes.len() as u32).to_be_bytes());
    digest.update(bytes);
}

/// The length-prefixed `domain`, then each member length-prefixed in the
/// order given. Identity-bearing: the persisted file digests pin ascending,
/// deduplicated member order (a `BTreeSet` walk or a sorted, deduplicated
/// slice), so callers must feed exactly that.
fn snapshot_file_set_hasher<I>(domain: &[u8], members: I) -> Sha256
where
    I: IntoIterator,
    I::Item: AsRef<str>,
{
    let mut digest = Sha256::new();
    update_length_prefixed(&mut digest, domain);
    let mut previous: Option<I::Item> = None;
    for member in members {
        if let Some(previous) = &previous {
            debug_assert!(
                previous.as_ref() < member.as_ref(),
                "file-set digest members must be sorted and unique"
            );
        }
        update_length_prefixed(&mut digest, member.as_ref().as_bytes());
        previous = Some(member);
    }
    digest
}

/// Canonical FILE entity-set digest (`last_snapshot_fingerprint`) over the
/// file's sorted, deduplicated entity fingerprints.
#[cfg(test)]
pub(in crate::snapshots) fn snapshot_file_entity_set_digest<I>(fingerprints: I) -> PrefixDigest
where
    I: IntoIterator,
    I::Item: AsRef<str>,
{
    snapshot_file_set_hasher(b"snapshot_file_entity_set:v1", fingerprints)
        .finalize()
        .into()
}

/// Lowercase hex of [`snapshot_file_entity_set_digest`], as finalization
/// records it.
pub(in crate::snapshots) fn snapshot_file_entity_set_hex<I>(fingerprints: I) -> String
where
    I: IntoIterator,
    I::Item: AsRef<str>,
{
    format!(
        "{:x}",
        snapshot_file_set_hasher(b"snapshot_file_entity_set:v1", fingerprints).finalize()
    )
}

/// Canonical FILE upload-body-set digest (`last_upload_body_witness`) over
/// the file's sorted, deduplicated upload-body witnesses.
pub(in crate::snapshots) fn snapshot_file_upload_body_set_digest<I>(witnesses: I) -> PrefixDigest
where
    I: IntoIterator,
    I::Item: AsRef<str>,
{
    snapshot_file_set_hasher(b"snapshot_file_upload_body_set:v1", witnesses)
        .finalize()
        .into()
}

/// Lowercase hex of [`snapshot_file_upload_body_set_digest`], as
/// finalization records it.
pub(in crate::snapshots) fn snapshot_file_upload_body_set_hex<I>(witnesses: I) -> String
where
    I: IntoIterator,
    I::Item: AsRef<str>,
{
    format!(
        "{:x}",
        snapshot_file_set_hasher(b"snapshot_file_upload_body_set:v1", witnesses).finalize()
    )
}

pub(in crate::snapshots) type PrefixDigest = [u8; 32];

pub(in crate::snapshots) fn sha256_hex_owned(parts: &[String]) -> String {
    let mut digest = Sha256::new();
    for part in parts {
        digest.update(part.as_bytes());
        digest.update([0]);
    }
    format!("{:x}", digest.finalize())
}
