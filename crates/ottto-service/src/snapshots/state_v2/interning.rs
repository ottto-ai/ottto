//! Stable local references, complete evidence equality and transactional GC.
//! Lookup digests select candidates; only full bytes authorize reuse.
use super::*;
use anyhow::{ensure, Context};
use sha2::Digest;

const PAGE: usize = 32;
const SET_DOMAIN: &[u8] = b"ottto.scan-index.state-v2.request-set.v1\0";

pub(super) enum RequestEvidence<'a> {
    Account {
        prefixes: &'a str,
        fingerprint: &'a str,
        identity_revision: Option<&'a str>,
        hash_count: Option<u64>,
    },
    Census {
        /// Existing census codec's full hash stream; never account prefixes.
        hashes: &'a dyn Value,
        hash_count: Option<u64>,
    },
}
impl RequestEvidence<'_> {
    fn count(&self) -> Option<u64> {
        match self {
            Self::Account { hash_count, .. } | Self::Census { hash_count, .. } => *hash_count,
        }
    }
}
fn bytes(out: &mut dyn Write, bytes: &[u8]) -> Result<()> {
    ensure!(
        bytes.len() as u64 <= VALUE_BYTES,
        "state_v2_value_admission"
    );
    out.write_all(&(bytes.len() as u64).to_be_bytes())?;
    out.write_all(bytes)?;
    Ok(())
}
impl Value for RequestEvidence<'_> {
    fn write(&self, out: &mut dyn Write) -> Result<()> {
        let count = self.count();
        ensure!(
            count.map_or(true, |n| n <= i64::MAX as u64),
            "state_v2_set_count_admission"
        );
        out.write_all(&[1, u8::from(count.is_some())])?;
        if let Some(count) = count {
            out.write_all(&count.to_be_bytes())?;
        }
        match self {
            Self::Account {
                prefixes,
                fingerprint,
                identity_revision,
                ..
            } => {
                ensure!(
                    fingerprint.len() <= KEY_BYTES
                        && identity_revision.map_or(true, |s| s.len() <= KEY_BYTES),
                    "state_v2_string_admission"
                );
                out.write_all(&[1])?;
                bytes(out, prefixes.as_bytes())?;
                bytes(out, fingerprint.as_bytes())?;
                out.write_all(&[u8::from(identity_revision.is_some())])?;
                if let Some(revision) = identity_revision {
                    bytes(out, revision.as_bytes())?;
                }
            }
            Self::Census { hashes, .. } => {
                out.write_all(&[2])?;
                // Count before writing, without buffering a family. The later
                // checked writer rejects a producer that changes between runs.
                let mut count = BoundedHash::new(std::io::sink());
                hashes.write(&mut count)?;
                out.write_all(&count.bytes.to_be_bytes())?;
                hashes.write(out)?;
            }
        }
        Ok(())
    }
}

struct BoundedHash<W> {
    out: W,
    hash: sha2::Sha256,
    bytes: u64,
}
impl<W: Write> BoundedHash<W> {
    fn new(out: W) -> Self {
        let mut hash = sha2::Sha256::new();
        hash.update(SET_DOMAIN);
        Self {
            out,
            hash,
            bytes: 0,
        }
    }
}
impl<W: Write> Write for BoundedHash<W> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.bytes = self
            .bytes
            .checked_add(bytes.len() as u64)
            .filter(|n| *n <= VALUE_BYTES)
            .ok_or_else(|| std::io::Error::other("state_v2_value_admission"))?;
        self.out.write_all(bytes)?;
        self.hash.update(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.out.flush()
    }
}
fn commitment(value: &dyn Value) -> Result<[u8; 32]> {
    let mut writer = BoundedHash::new(std::io::sink());
    value.write(&mut writer)?;
    Ok(writer.hash.finalize().into())
}
struct Checked<'a> {
    value: &'a dyn Value,
    commitment: [u8; 32],
}
impl Value for Checked<'_> {
    fn write(&self, out: &mut dyn Write) -> Result<()> {
        let mut writer = BoundedHash::new(out);
        self.value.write(&mut writer)?;
        ensure!(
            <[u8; 32]>::from(writer.hash.finalize()) == self.commitment,
            "state_v2_value_changed_after_preflight"
        );
        Ok(())
    }
}

fn allocate(
    tx: &mut impl Transaction,
    name: &str,
    existing: bool,
    owner: impl FnOnce(u64) -> RowKey,
) -> Result<u64> {
    let key = RowKey::Meta(name.into());
    let id = if let Some(h) = tx.get(&key)? {
        ensure!(h.len <= 128, "state_v2_high_water_admission");
        let mut encoded = Vec::with_capacity(h.len as usize);
        tx.read_value(&h, &mut encoded)?;
        let mut raw = Vec::new();
        packed::decode(encoded.as_slice(), &mut raw)?;
        serde_json::from_slice::<u64>(&raw)?
    } else {
        ensure!(!existing, "state_v2_high_water_missing");
        1
    };
    ensure!(
        id > 0 && id <= i64::MAX as u64,
        "state_v2_ordinal_exhausted"
    );
    ensure!(tx.get(&owner(id))?.is_none(), "state_v2_high_water_reused");
    let next = id.checked_add(1).context("state_v2_ordinal_exhausted")?;
    tx.put(RowInput {
        key: &key,
        fixed: &Fixed::None,
        value: &packed::Json(&next),
    })?;
    Ok(id)
}

pub(super) fn intern_request_set(
    tx: &mut impl Transaction,
    evidence: &RequestEvidence<'_>,
) -> Result<u64> {
    let digest = commitment(evidence)?;
    let value = Checked {
        value: evidence,
        commitment: digest,
    };
    let mut after = 0;
    loop {
        let page = tx.request_set_candidates(&digest, after, PAGE)?;
        if page.is_empty() {
            break;
        }
        for h in &page {
            let RowKey::RequestSet(id) = h.key else {
                anyhow::bail!("state_v2_set_key");
            };
            let Fixed::RequestSet {
                hash_count, refs, ..
            } = h.fixed
            else {
                anyhow::bail!("state_v2_set_columns");
            };
            ensure!(id > after && refs > 0, "state_v2_reference_count");
            if tx.value_matches(h, &value)? {
                ensure!(hash_count == evidence.count(), "state_v2_set_count");
                tx.adjust_refs(&h.key, 1)?;
                return Ok(id);
            }
            after = id;
        }
    }
    let existing = !tx
        .scan_prefix(
            RowPrefix {
                table: Table::RequestSets,
            },
            None,
            1,
        )?
        .is_empty();
    let id = allocate(tx, "next_request_set_id", existing, RowKey::RequestSet)?;
    let key = RowKey::RequestSet(id);
    ensure!(tx.get(&key)?.is_none(), "state_v2_high_water_reused");
    tx.put(RowInput {
        key: &key,
        fixed: &Fixed::RequestSet {
            commitment: digest.to_vec(),
            hash_count: evidence.count(),
            refs: 1,
        },
        value: &value,
    })?;
    Ok(id)
}

#[derive(Clone, Copy)]
pub(super) enum Vocabulary {
    Version,
    Model,
    Speed,
    Effort,
}
impl Vocabulary {
    fn kind(self) -> u16 {
        match self {
            Self::Version => 0,
            Self::Model => 1,
            Self::Speed => 2,
            Self::Effort => 3,
        }
    }
    fn high_water(self) -> &'static str {
        match self {
            Self::Version => "next_version_ordinal",
            Self::Model => "next_model_ordinal",
            Self::Speed => "next_speed_ordinal",
            Self::Effort => "next_effort_ordinal",
        }
    }
}
struct Text<'a>(&'a str);
impl Value for Text<'_> {
    fn write(&self, out: &mut dyn Write) -> Result<()> {
        ensure!(
            self.0.len() as u64 <= VALUE_BYTES,
            "state_v2_value_admission"
        );
        out.write_all(self.0.as_bytes())?;
        Ok(())
    }
}

pub(super) fn intern_string(
    tx: &mut impl Transaction,
    kind: Vocabulary,
    text: &str,
) -> Result<u64> {
    ensure!(text.len() as u64 <= VALUE_BYTES, "state_v2_value_admission");
    let value = Text(text);
    let mut after = 0;
    let mut existing = false;
    loop {
        let page = tx.interned_candidates(kind.kind(), after, PAGE)?;
        if page.is_empty() {
            break;
        }
        existing = true;
        for h in &page {
            let RowKey::Interned { ordinal, .. } = h.key else {
                anyhow::bail!("state_v2_ordinal_key");
            };
            ensure!(ordinal > after, "state_v2_ordinal_order");
            if tx.value_matches(h, &value)? {
                tx.adjust_refs(&h.key, 1)?;
                return Ok(ordinal);
            }
            after = ordinal;
        }
    }
    let ordinal = allocate(tx, kind.high_water(), existing, |ordinal| {
        RowKey::Interned {
            kind: kind.kind(),
            ordinal,
        }
    })?;
    let key = RowKey::Interned {
        kind: kind.kind(),
        ordinal,
    };
    ensure!(tx.get(&key)?.is_none(), "state_v2_high_water_reused");
    tx.put(RowInput {
        key: &key,
        fixed: &Fixed::Interned { refs: 1 },
        value: &value,
    })?;
    Ok(ordinal)
}

pub(super) fn release_request_set(tx: &mut impl Transaction, id: u64) -> Result<()> {
    tx.adjust_refs(&RowKey::RequestSet(id), -1)?;
    Ok(())
}
pub(super) fn release_string(
    tx: &mut impl Transaction,
    kind: Vocabulary,
    ordinal: u64,
) -> Result<()> {
    tx.adjust_refs(
        &RowKey::Interned {
            kind: kind.kind(),
            ordinal,
        },
        -1,
    )?;
    Ok(())
}

/// Resolve directly into the final owned graph string, without a dictionary
/// graph or a second text copy. No memo is required for correctness.
pub(super) fn resolve_string(
    tx: &mut impl Transaction,
    kind: Vocabulary,
    ordinal: u64,
) -> Result<String> {
    let h = tx
        .get(&RowKey::Interned {
            kind: kind.kind(),
            ordinal,
        })?
        .context("state_v2_ordinal_missing")?;
    ensure!(
        matches!(h.fixed, Fixed::Interned { refs } if refs > 0),
        "state_v2_reference_count"
    );
    ensure!(h.len <= VALUE_BYTES, "state_v2_value_admission");
    let mut value = Vec::new();
    value.try_reserve_exact(usize::try_from(h.len)?)?;
    tx.read_value(&h, &mut value)?;
    Ok(String::from_utf8(value)?)
}
