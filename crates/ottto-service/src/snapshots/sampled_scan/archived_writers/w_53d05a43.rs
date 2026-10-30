//! Test-only archive of the record writer at `SOURCE_SHA`, the frozen v1 producer.
//!
//! Text between `archive-region` markers is copied from that commit: the record
//! framing, every durable declaration and the codec, with two mechanical changes
//! the extractor reverses before hashing. `crate::` paths gain this module's root,
//! and `#[cfg(test)]` becomes `#[cfg(any())]` so test hooks stay out.
//! `REGIONS` pins each unit; `--archive <sha>` checks them against the archive and
//! against `git show <sha>:<path>`. Never edit a region or refresh a hash: a later
//! writer gets its own `w_<sha8>.rs`.
//!
//! Everything outside the markers is scaffold: the type definitions the
//! declarations imply, stubs for fields that never reach the wire, and the
//! `ArchivedWriter` impl. The `crate::` paths here all stay inside this module,
//! so production changes cannot reach this writer. Regions are not reformatted.
#![allow(
    dead_code,
    non_camel_case_types,
    unused_imports,
    unused_macros,
    unused_variables,
    clippy::all
)]

use super::{
    decode_hex, ArchivedContent, ArchivedRecord, ArchivedWriter, ContentDigests, Golden, Region,
};
use sha2::{Digest, Sha256};

pub(crate) struct W_53d05a43;

impl ArchivedWriter for W_53d05a43 {
    const SOURCE_SHA: &'static str = SOURCE_SHA;
    const PIN: &'static str = "53d05a43";
    const FORMAT: u16 = durable_tail_store::ARCHIVED_FORMAT;

    fn regions() -> &'static [Region] {
        REGIONS
    }

    fn allowlist(source_tag: u8) -> Result<[u8; 32], String> {
        let source = snapshots::archived_source(source_tag)?;
        // Only an `E` field's stringified type mentions a path, so undoing the
        // root here restores the digest the writer computed at SOURCE_SHA.
        let text = snapshots::archived_shape_text(source).replace(ARCHIVE_ROOT, "crate");
        let mut hasher = Sha256::new();
        hasher.update(b"ottto-durable-tail-shape:v1");
        hasher.update(text.as_bytes());
        Ok(hasher.finalize().into())
    }

    fn encode_body(source_tag: u8, body: &[u8]) -> Result<Vec<u8>, String> {
        snapshots::archived_rewrite(snapshots::archived_source(source_tag)?, body)
    }

    fn frame(record: &ArchivedRecord) -> Result<Vec<u8>, String> {
        durable_tail_store::archived_frame(record)
    }

    fn content_digests(
        source_tag: u8,
        content: &ArchivedContent,
    ) -> Result<ContentDigests, String> {
        let body = BODY_GOLDENS
            .iter()
            .find(|(tag, _)| *tag == source_tag)
            .ok_or_else(|| format!("no v1 body source for tag {source_tag}"))?;
        snapshots::archived_content_digests(&decode_hex(body.1), content)
    }

    fn session_start_golden(source_tag: u8) -> Option<&'static str> {
        SESSION_START_GOLDENS
            .iter()
            .find(|(tag, _)| *tag == source_tag)
            .map(|(_, digest)| *digest)
    }

    fn goldens() -> Vec<Golden> {
        goldens()
    }
}

/// Read by `--archive`; keep each `Region` literal in this form.
const SOURCE_SHA: &str = "53d05a4304f2e87effbaa48661e10286bff01c58";
const ARCHIVE_ROOT: &str = "crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43";
const REGIONS: &[Region] = &[
    Region {
        path: "owned_heap.rs",
        roots: &["insert", "new", "push"],
        sha256: "397dd734a76404232b6165da638c9b5ccc53ff73c2e2def4d5cb83fe9253b488",
    },
    Region {
        path: "durable_tail_codec.rs",
        roots: &[],
        sha256: "dc56bac8c7a9e478df9df2eff82f83f409429a43750bfb1599c14a0190c4f9a6",
    },
    Region {
        path: "durable_tail_store.rs",
        roots: &["encode", "encode_header", "encode_parts", "tag"],
        sha256: "bb640410f86dfba3d96409030cf611b7ed9acaa8853b42da97d96365a8577ba6",
    },
    Region {
        path: "codex_scan_diagnostics.rs",
        roots: &[],
        sha256: "2f1433a7f722a6fed7b0883b6873cc0b9c7b54aed43953ada7b504a8a3a4be34",
    },
    Region {
        path: "codex_prelude_footprint.rs",
        roots: &[],
        sha256: "2459e58e5f2bb58ecf30ac8e27a7bb04e42fb059fe7b1164ab5640958c1a47ef",
    },
    Region {
        path: "snapshots.rs",
        roots: &["api_slug"],
        sha256: "f3f1bd26369ffc30fbc292e9d2d3c093eae55f8ea6e2cf349b56801248550cc2",
    },
    Region {
        path: "snapshots/cache_observations.rs",
        roots: &[],
        sha256: "8e6149a1d900c8b08fcef32c98dffb2d2068ab693b19c40ac142ba33d1daf0f9",
    },
    Region {
        path: "snapshots/claude_context_file_birth.rs",
        roots: &[],
        sha256: "860991b52bf5bb2cf8cbfe97cfd0cc718bea4c04b48fe6e5730371f4cf46d588",
    },
    Region {
        path: "snapshots/claude_request_identity.rs",
        roots: &[],
        sha256: "1e69a00b4ebee5293c50a5821bd762593d57fcc40a2972194313ef8ce1c0e08c",
    },
    Region {
        path: "snapshots/claude_response_records.rs",
        roots: &[],
        sha256: "64f73ce9b4efea512629c05a5dc7a1c5becafd869b2d97a585f55672e170d80d",
    },
    Region {
        path: "snapshots/codex_counting_version.rs",
        roots: &[],
        sha256: "958f27ce4b7bf9c91290ae7335b51176f0c70f61840fcb797cc6ccec8388dc18",
    },
    Region {
        path: "snapshots/codex_usage_occurrence.rs",
        roots: &[],
        sha256: "3a136aa935ea75df886802f9ead0f92c2710a68ef5f6260b7485e138d91148a3",
    },
    Region {
        path: "snapshots/compaction_events.rs",
        roots: &[],
        sha256: "022e30453631e93a71583b9e8cb451620e88685122fb27bfd9e94f5ac29f05ce",
    },
    Region {
        path: "snapshots/context_curve.rs",
        roots: &[],
        sha256: "33b96640a27df9c4509a5668ccc1f34a0d4451dcfa2da5b862e2ecdcdaed6392",
    },
    Region {
        path: "snapshots/local_context_points.rs",
        roots: &[],
        sha256: "32ed5c1287c1bb742c10d1920aaaa9e4ac779602deff0c1b1f7519b64a6ea700",
    },
    Region {
        path: "snapshots/sampled_jsonl.rs",
        roots: &["source"],
        sha256: "d33615424a83737c6f6a38508957ef673421dea4c9e7e645ea7920ce673888d6",
    },
    Region {
        path: "snapshots/sampled_jsonl/durable.rs",
        roots: &["allowlist_digest", "encode", "verify"],
        sha256: "f86722f12d225ce09c86ad20029cadbb93e131713fbe6266e642b64be0cc4f59",
    },
    Region {
        path: "snapshots/session_start.rs",
        roots: &["durable_content_digest", "durable_content_hash"],
        sha256: "2a5639944e4ba77464af196159ceebd26aa471b711240ccf866dd5e07a0afad3",
    },
];

/// Allowlists pinned at SOURCE_SHA by `durable_tests.rs` and the store's
/// representation table, independent of this copy.
const ALLOWLISTS: [(u8, &str); 2] = [
    (1, "8d141d534b95e2c5ac6a2e6d8e5ca45f3a852038fa456f5f3216c14bf84e943c"),
    (2, "02206079405b58944e1d6d4d0ed3768c2acb39444d5278f1ba86725a723534a1"),
];
/// Whole records from `full_v1_writer_goldens_preserve_zero_and_nonzero_debt`,
/// checked against both historical writers before this archive existed.
const FRAME_GOLDENS: [(u8, Option<u64>, [&str; 8]); 4] = [
    (
        1,
        Some(23),
        [
            "6f7474746f2d647401008d141d534b95e2c5ac6a2e6d8e5ca45f3a852038fa456f5f3216c14bf84e943c010101010101",
            "010101010101010101010101010101010101010101010101010101020202020202020202020202020202020202020202",
            "0202020202020202020202228abf0ecdfed7a01435a16724305eba6e1f2dcc6a2722489869f2b1c391da840404040404",
            "04040404040404040404040404040404040404040404040404040409000000000000000b000000000000000c00000000",
            "0000000d000000000000000e000000000000000f0000000000000010000000000000000d000000000000000d00000011",
            "111111111111111111111111111111111111111111111111111111111111111212121212121212121212121212121212",
            "12121212121212121212121212121213000000000000000117000000000000000e0000006f70617175652d76312d626f",
            "6479707a28e1469da460d67939716da2859b92f17fb86560d549db9103033f8b2e47",
        ],
    ),
    (
        1,
        None,
        [
            "6f7474746f2d647401008d141d534b95e2c5ac6a2e6d8e5ca45f3a852038fa456f5f3216c14bf84e943c010101010101",
            "010101010101010101010101010101010101010101010101010101020202020202020202020202020202020202020202",
            "0202020202020202020202228abf0ecdfed7a01435a16724305eba6e1f2dcc6a2722489869f2b1c391da840404040404",
            "04040404040404040404040404040404040404040404040404040409000000000000000b000000000000000c00000000",
            "0000000d000000000000000e000000000000000f0000000000000010000000000000000d000000000000000d00000011",
            "111111111111111111111111111111111111111111111111111111111111111212121212121212121212121212121212",
            "12121212121212121212121212121213000000000000000000000000000000000e0000006f70617175652d76312d626f",
            "6479fbc447e4bf44906e1fb96bbd5df2ce9df04970feac39187d52bda7fa482eb7d0",
        ],
    ),
    (
        2,
        Some(23),
        [
            "6f7474746f2d6474010002206079405b58944e1d6d4d0ed3768c2acb39444d5278f1ba86725a723534a1020101010101",
            "010101010101010101010101010101010101010101010101010101020202020202020202020202020202020202020202",
            "0202020202020202020202dda7edd695d91e9829d2937b7a29b89e14710453cde5dc8e42342ae2bb30e8890404040404",
            "04040404040404040404040404040404040404040404040404040409000000000000000b000000000000000c00000000",
            "0000000d000000000000000e000000000000000f0000000000000010000000000000000d000000000000000d00000011",
            "111111111111111111111111111111111111111111111111111111111111111212121212121212121212121212121212",
            "12121212121212121212121212121213000000000000000117000000000000000e0000006f70617175652d76312d626f",
            "6479473cde7f01f33061b20bb07d5a559796576e28935245a9baf21b25b2cf92d1be",
        ],
    ),
    (
        2,
        None,
        [
            "6f7474746f2d6474010002206079405b58944e1d6d4d0ed3768c2acb39444d5278f1ba86725a723534a1020101010101",
            "010101010101010101010101010101010101010101010101010101020202020202020202020202020202020202020202",
            "0202020202020202020202dda7edd695d91e9829d2937b7a29b89e14710453cde5dc8e42342ae2bb30e8890404040404",
            "04040404040404040404040404040404040404040404040404040409000000000000000b000000000000000c00000000",
            "0000000d000000000000000e000000000000000f0000000000000010000000000000000d000000000000000d00000011",
            "111111111111111111111111111111111111111111111111111111111111111212121212121212121212121212121212",
            "12121212121212121212121212121213000000000000000000000000000000000e0000006f70617175652d76312d626f",
            "647909674aab5e763d260115ec23bba8b18f698be4e4a1111bf15df7268ee254e00a",
        ],
    ),
];
/// `store_fixture_body(source, 1, 7)`, captured once from the service writer
/// while its body regions still matched SOURCE_SHA.
const BODY_GOLDENS: [(u8, &str); 2] = [
    (1, "01000000000100000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000010001000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100000000000000000000000100000101010000000000000000000000ffffffffffffffffff01ffffffffffffffffff01ffffffffffffffffff01000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000107000000000000"),
    (2, "00000000000100000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000010001000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100000000000000000000000100000101010000000000000000000000ffffffffffffffffff01ffffffffffffffffff01ffffffffffffffffff01000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000107000000000000"),
];
/// `session_start` digests of the `*_instruction_lines` transcripts, captured the
/// same way. A record cannot carry the parser state behind this digest, so the
/// archive pins its value instead of recomputing it.
const SESSION_START_GOLDENS: [(u8, &str); 2] = [
    (1, "8e8a79c3d053350fe28b2ad8a332f05c012d49a2abf13128b7dd57181944f24f"),
    (2, "a2dd01eb415a98c8558c9ff03d32ce7697c37037a42076fd4bc4284c135fea24"),
];

fn goldens() -> Vec<Golden> {
    let record = |source_tag: u8, debt: Option<u64>, body: Vec<u8>, scope: [u8; 32]| ArchivedRecord {
        source_tag,
        key: [1; 32],
        context: [2; 32],
        scope,
        entry: [4; 32],
        allowlist: decode_hex(
            ALLOWLISTS
                .iter()
                .find(|(tag, _)| *tag == source_tag)
                .expect("archived source")
                .1,
        )
        .try_into()
        .expect("allowlist digest"),
        generation: 9,
        device: 11,
        inode: 12,
        length: 13,
        modified: (14, 15),
        birth_nanos: 16,
        sealed_offset: 13,
        sample_len: 13,
        head_sha256: [17; 32],
        boundary_sha256: [18; 32],
        verified_unix_seconds: 19,
        audit_debt: debt,
        body,
    };
    let mut out = Vec::new();
    for (source_tag, debt, parts) in FRAME_GOLDENS {
        let expected = decode_hex(&parts.concat());
        let scope = expected[107..139].try_into().expect("scope digest");
        out.push(Golden::Frame {
            record: Box::new(record(source_tag, debt, b"opaque-v1-body".to_vec(), scope)),
            expected,
        });
    }
    for (source_tag, body) in BODY_GOLDENS {
        out.push(Golden::Body {
            source_tag,
            body: decode_hex(body),
        });
    }
    out
}

mod transcript_cache {
    // Only fed to the heap stand-in below, which ignores it.
    pub(crate) const ENTRY_BYTES: usize = 0;
}

/// Stand-in: heap accounting admits or refuses allocations and never changes
/// which bytes the containers below emit.
pub(crate) mod heap_layout_bound {
    pub(crate) struct Counter;
    impl Counter { pub(crate) fn add(&mut self, _: usize) -> Option<()> { Some(()) } }
    pub(crate) trait HeapLayoutBound {
        const INLINE_ONLY: bool = false;
        const STABLE_HEAP: bool = true;
        fn heap_bound(&self, _: &mut Counter) -> Option<()> { Some(()) }
        fn stable_heap(&self) -> bool { true }
    }
    pub(crate) fn bound<T: HeapLayoutBound>(_: &T, _: usize) -> Option<usize> { Some(0) }
    impl HeapLayoutBound for String {}
    impl HeapLayoutBound for u32 {}
    impl HeapLayoutBound for () {}
    impl<A, B> HeapLayoutBound for (A, B) {}
}
pub(crate) mod owned_heap {
    use crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::heap_layout_bound::{self, Counter, HeapLayoutBound};
    use std::borrow::Borrow;
    use std::collections::BTreeMap;
    use std::ops::{Deref, DerefMut};
    #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
    pub(crate) struct OwnedVec<T> { values: Vec<T>, elements: Option<usize> }
    #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
    pub(crate) struct OwnedMap<K, V> { values: BTreeMap<K, V>, elements: Option<usize> }
    pub(crate) struct ValueGuard<'a, T> { value: &'a mut T, sum: &'a mut Option<usize>, base: Option<usize> }
// archive-region: owned_heap.rs
fn heap<T: HeapLayoutBound>(value: &T) -> Option<usize> {
    let bytes = heap_layout_bound::bound(value, crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::transcript_cache::ENTRY_BYTES)?;
    value
        .stable_heap()
        .then_some(bytes)?
        .checked_sub(std::mem::size_of_val(value))
}
fn replace(sum: Option<usize>, old: Option<usize>, new: Option<usize>) -> Option<usize> {
    sum?.checked_sub(old?)?.checked_add(new?)
}
// archive-region-end
// archive-region: owned_heap.rs
impl<T> Default for OwnedVec<T> {
    fn default() -> Self {
        Self {
            values: Vec::new(),
            elements: Some(0),
        }
    }
}
impl<T: HeapLayoutBound> OwnedVec<T> {
    pub(crate) fn new() -> Self {
        Self::default()
    }
    pub(crate) fn push(&mut self, value: T) {
        self.elements = self.elements.and_then(|n| n.checked_add(heap(&value)?));
        self.values.push(value);
    }
    pub(crate) fn get_mut(&mut self, index: usize) -> Option<ValueGuard<'_, T>> {
        let value = self.values.get_mut(index)?;
        let base = self
            .elements
            .take()
            .and_then(|n| n.checked_sub(heap(value)?));
        Some(ValueGuard {
            value,
            sum: &mut self.elements,
            base,
        })
    }
    pub(crate) fn clear(&mut self) {
        self.values.clear();
        self.elements = Some(0);
    }
    pub(crate) fn into_vec(self) -> Vec<T> {
        self.values
    }
}
impl<T: HeapLayoutBound> From<Vec<T>> for OwnedVec<T> {
    fn from(values: Vec<T>) -> Self {
        let elements = values
            .iter()
            .try_fold(0usize, |n, x| n.checked_add(heap(x)?));
        Self { values, elements }
    }
}
// archive-region-end
// archive-region: owned_heap.rs
impl<T> Deref for OwnedVec<T> {
    type Target = [T];
    fn deref(&self) -> &Self::Target {
        &self.values
    }
}
// archive-region-end
// archive-region: owned_heap.rs
impl<K, V> Default for OwnedMap<K, V> {
    fn default() -> Self {
        Self {
            values: BTreeMap::new(),
            elements: Some(0),
        }
    }
}
impl<K: Ord + HeapLayoutBound, V: HeapLayoutBound> OwnedMap<K, V> {
    pub(crate) fn new() -> Self {
        Self::default()
    }
    pub(crate) fn insert(&mut self, key: K, value: V) -> Option<V> {
        // BTreeMap::insert preserves the stored key on replacement.
        let old_heap = self.values.get(&key).map(heap);
        let value_heap = heap(&value);
        let key_heap = if old_heap.is_none() {
            heap(&key)
        } else {
            Some(0)
        };
        let old = self.values.insert(key, value);
        self.elements = replace(self.elements, old_heap.unwrap_or(Some(0)), value_heap)
            .and_then(|n| n.checked_add(key_heap?));
        old
    }
    pub(crate) fn get_mut<Q: Ord + ?Sized>(&mut self, key: &Q) -> Option<ValueGuard<'_, V>>
    where
        K: Borrow<Q>,
    {
        let value = self.values.get_mut(key)?;
        let base = self
            .elements
            .take()
            .and_then(|n| n.checked_sub(heap(value)?));
        Some(ValueGuard {
            value,
            sum: &mut self.elements,
            base,
        })
    }
    #[cfg(any())]
    pub(crate) fn remove<Q: Ord + ?Sized>(&mut self, key: &Q) -> Option<V>
    where
        K: Borrow<Q>,
    {
        let (key, value) = self.values.remove_entry(key)?;
        self.elements = self
            .elements
            .and_then(|n| n.checked_sub(heap(&key)?)?.checked_sub(heap(&value)?));
        Some(value)
    }
}
// archive-region-end
// archive-region: owned_heap.rs
impl<K, V> Deref for OwnedMap<K, V> {
    type Target = BTreeMap<K, V>;
    fn deref(&self) -> &Self::Target {
        &self.values
    }
}
// archive-region-end
}
pub(crate) mod durable_tail_codec {
// archive-region: durable_tail_codec.rs
#![cfg_attr(not(test), allow(dead_code))]

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use sha2::{Digest, Sha256};

/// Why a value was not encoded. Carries field paths only, never values.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Refuse {
    /// An `E` field held a value.
    NonEmpty(&'static str),
    /// A static label outside the closed table.
    UnknownLabel,
    /// The encoded body outgrew the record cap.
    TooLarge,
    /// An `X` field cannot be re-derived from the file under the bound.
    NotRederivable(&'static str),
    /// An `H` text field that is not exactly 64 lower-case hex (a 32-byte
    /// SHA-256 or HMAC value).
    NotDigest(&'static str),
}

/// A record body that does not decode. Treated like any corrupt record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Corrupt;

enum Sink {
    Bytes { out: Vec<u8>, limit: usize },
    Hash(Box<Sha256>),
}

/// Encoder. In hash mode it also feeds `X` fields, so a re-derived value can
/// be checked against the digest without storing it.
pub(crate) struct Enc {
    sink: Sink,
}

impl Enc {
    pub(crate) fn bytes(limit: usize) -> Self {
        Self {
            sink: Sink::Bytes {
                out: Vec::new(),
                limit,
            },
        }
    }
    pub(crate) fn hash(domain: &str) -> Self {
        let mut hasher = Sha256::new();
        hasher.update((domain.len() as u64).to_le_bytes());
        hasher.update(domain.as_bytes());
        Self {
            sink: Sink::Hash(Box::new(hasher)),
        }
    }
    pub(crate) fn hashing(&self) -> bool {
        matches!(self.sink, Sink::Hash(_))
    }
    /// Bytes written so far; `None` in hash mode. Tests only.
    #[cfg(any())]
    pub(crate) fn position(&self) -> Option<usize> {
        match &self.sink {
            Sink::Bytes { out, .. } => Some(out.len()),
            Sink::Hash(_) => None,
        }
    }
    pub(crate) fn raw(&mut self, bytes: &[u8]) -> Result<(), Refuse> {
        match &mut self.sink {
            Sink::Bytes { out, limit } => {
                if out.len().saturating_add(bytes.len()) > *limit {
                    return Err(Refuse::TooLarge);
                }
                out.extend_from_slice(bytes);
            }
            Sink::Hash(hasher) => hasher.update(bytes),
        }
        Ok(())
    }
    pub(crate) fn varint(&mut self, mut value: u64) -> Result<(), Refuse> {
        let mut buf = [0_u8; 10];
        let mut len = 0;
        loop {
            let byte = (value & 0x7f) as u8;
            value >>= 7;
            if value == 0 {
                buf[len] = byte;
                len += 1;
                break;
            }
            buf[len] = byte | 0x80;
            len += 1;
        }
        self.raw(&buf[..len])
    }
    pub(crate) fn len_prefixed(&mut self, bytes: &[u8]) -> Result<(), Refuse> {
        self.varint(bytes.len() as u64)?;
        self.raw(bytes)
    }
    /// Bytes mode: the encoded body.
    pub(crate) fn into_bytes(self) -> Vec<u8> {
        match self.sink {
            Sink::Bytes { out, .. } => out,
            Sink::Hash(_) => Vec::new(),
        }
    }
    /// Hash mode: the digest.
    pub(crate) fn finish_hash(self) -> [u8; 32] {
        match self.sink {
            Sink::Hash(hasher) => hasher.finalize().into(),
            Sink::Bytes { out, .. } => Sha256::digest(out).into(),
        }
    }
}

/// Decoder over one record body.
pub(crate) struct Dec<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Dec<'a> {
    pub(crate) fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, at: 0 }
    }
    pub(crate) fn raw(&mut self, len: usize) -> Result<&'a [u8], Corrupt> {
        let end = self.at.checked_add(len).ok_or(Corrupt)?;
        let slice = self.bytes.get(self.at..end).ok_or(Corrupt)?;
        self.at = end;
        Ok(slice)
    }
    pub(crate) fn varint(&mut self) -> Result<u64, Corrupt> {
        #[cfg(any())]
        note_verify_visit(self.at, true);
        let mut value = 0_u64;
        for shift in (0..64).step_by(7) {
            let byte = self.raw(1)?[0];
            let bits = u64::from(byte & 0x7f);
            if shift == 63 && bits > 1 {
                return Err(Corrupt);
            }
            value |= bits << shift;
            if byte & 0x80 == 0 {
                return Ok(value);
            }
        }
        Err(Corrupt)
    }
    /// A length that must fit in what is left, so a corrupt length never
    /// sizes an allocation.
    pub(crate) fn take_len(&mut self) -> Result<usize, Corrupt> {
        let len = usize::try_from(self.varint()?).map_err(|_| Corrupt)?;
        if len > self.remaining() {
            return Err(Corrupt);
        }
        Ok(len)
    }
    pub(crate) fn len_prefixed(&mut self) -> Result<&'a [u8], Corrupt> {
        let len = self.take_len()?;
        self.raw(len)
    }
    pub(crate) fn remaining(&self) -> usize {
        self.bytes.len() - self.at
    }
    pub(crate) fn finish(self) -> Result<(), Corrupt> {
        (self.at == self.bytes.len()).then_some(()).ok_or(Corrupt)
    }
}

/// The shape of every persisted type: names, classes and field types, each
/// named type once.
#[derive(Default)]
pub(crate) struct Shape {
    text: String,
    seen: BTreeSet<&'static str>,
}

impl Shape {
    pub(crate) fn push(&mut self, part: &str) {
        self.text.push_str(part);
        self.text.push(';');
    }
    /// Starts a named type's definition, once. `false` when already written.
    pub(crate) fn enter(&mut self, name: &'static str) -> bool {
        self.push(name);
        if !self.seen.insert(name) {
            return false;
        }
        self.text.push('{');
        true
    }
    pub(crate) fn leave(&mut self) {
        self.text.push('}');
    }
    pub(crate) fn digest(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"ottto-durable-tail-shape:v1");
        hasher.update(self.text.as_bytes());
        hasher.finalize().into()
    }
    #[cfg(any())]
    pub(crate) fn text(&self) -> &str {
        &self.text
    }
}

pub(crate) trait Durable: Sized {
    fn put(&self, e: &mut Enc) -> Result<(), Refuse>;
    fn take(d: &mut Dec<'_>) -> Result<Self, Corrupt>;
    /// Walk the stored fields without constructing the value or allocating.
    fn verify(d: &mut Dec<'_>) -> Result<(), Corrupt>;
    fn shape(s: &mut Shape);
}

/// `H` is a type, not a label: only fixed 32-byte values (a raw
/// `[u8; 32]`, or exactly 64 lower-case hex text, stored as its 32 bytes)
/// and collections of them implement this, so a non-cryptographic digest
/// (u64 words, a rolling hash, a truncated hash) cannot compile as `H`.
/// Which algorithm produced each value (domain-separated SHA-256 or HMAC)
/// is pinned per field by the H audit test (`h_fields_are_audited`).
pub(crate) trait HDigest: Sized {
    fn put_h(&self, e: &mut Enc, path: &'static str) -> Result<(), Refuse>;
    fn take_h(d: &mut Dec<'_>) -> Result<Self, Corrupt>;
    fn verify_h(d: &mut Dec<'_>) -> Result<(), Corrupt>;
    fn shape_h(s: &mut Shape);
}

impl HDigest for [u8; 32] {
    fn put_h(&self, e: &mut Enc, _: &'static str) -> Result<(), Refuse> {
        e.raw(self)
    }
    fn take_h(d: &mut Dec<'_>) -> Result<Self, Corrupt> {
        d.raw(32)?.try_into().map_err(|_| Corrupt)
    }
    fn verify_h(d: &mut Dec<'_>) -> Result<(), Corrupt> {
        d.raw(32).map(|_| ())
    }
    fn shape_h(s: &mut Shape) {
        s.push("digest32");
    }
}

impl HDigest for String {
    fn put_h(&self, e: &mut Enc, path: &'static str) -> Result<(), Refuse> {
        let text = self.as_bytes();
        if text.len() != 64 {
            return Err(Refuse::NotDigest(path));
        }
        let mut bytes = [0_u8; 32];
        for (byte, pair) in bytes.iter_mut().zip(text.chunks_exact(2)) {
            let nibble = |c: u8| match c {
                b'0'..=b'9' => Some(c - b'0'),
                b'a'..=b'f' => Some(c - b'a' + 10),
                _ => None,
            };
            *byte = match (nibble(pair[0]), nibble(pair[1])) {
                (Some(high), Some(low)) => (high << 4) | low,
                _ => return Err(Refuse::NotDigest(path)),
            };
        }
        e.raw(&bytes)
    }
    fn take_h(d: &mut Dec<'_>) -> Result<Self, Corrupt> {
        Ok(d.raw(32)?
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect())
    }
    fn verify_h(d: &mut Dec<'_>) -> Result<(), Corrupt> {
        d.raw(32).map(|_| ())
    }
    fn shape_h(s: &mut Shape) {
        s.push("hex64");
    }
}

impl<T: HDigest> HDigest for Option<T> {
    fn put_h(&self, e: &mut Enc, path: &'static str) -> Result<(), Refuse> {
        match self {
            None => e.varint(0),
            Some(value) => {
                e.varint(1)?;
                value.put_h(e, path)
            }
        }
    }
    fn take_h(d: &mut Dec<'_>) -> Result<Self, Corrupt> {
        match d.varint()? {
            0 => Ok(None),
            1 => Ok(Some(T::take_h(d)?)),
            _ => Err(Corrupt),
        }
    }
    fn verify_h(d: &mut Dec<'_>) -> Result<(), Corrupt> {
        match d.varint()? {
            0 => Ok(()),
            1 => {
                #[cfg(any())]
                VERIFY_PRESENT_OPTIONS.with(|count| count.set(count.get() + 1));
                T::verify_h(d)
            }
            _ => Err(Corrupt),
        }
    }
    fn shape_h(s: &mut Shape) {
        s.push("Option<");
        T::shape_h(s);
        s.push(">");
    }
}

impl<T: HDigestKey + Ord> HDigest for BTreeSet<T> {
    fn put_h(&self, e: &mut Enc, path: &'static str) -> Result<(), Refuse> {
        e.varint(self.len() as u64)?;
        self.iter().try_for_each(|value| value.put_h(e, path))
    }
    fn take_h(d: &mut Dec<'_>) -> Result<Self, Corrupt> {
        let len = d.take_len()?;
        let mut out = BTreeSet::new();
        for _ in 0..len {
            if !out.insert(T::take_h(d)?) {
                return Err(Corrupt);
            }
        }
        Ok(out)
    }
    fn verify_h(d: &mut Dec<'_>) -> Result<(), Corrupt> {
        verify_entries(d, T::key_h, |_| Ok(()))
    }
    fn shape_h(s: &mut Shape) {
        s.push("BTreeSet<");
        T::shape_h(s);
        s.push(">");
    }
}

fn verify_seq(
    d: &mut Dec<'_>,
    mut item: impl FnMut(&mut Dec<'_>) -> Result<(), Corrupt>,
) -> Result<(), Corrupt> {
    for _ in 0..d.take_len()? {
        item(d)?;
    }
    Ok(())
}

impl<T: HDigest + crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::heap_layout_bound::HeapLayoutBound> HDigest
    for crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::owned_heap::OwnedVec<T>
{
    fn put_h(&self, e: &mut Enc, path: &'static str) -> Result<(), Refuse> {
        e.varint(self.len() as u64)?;
        self.iter().try_for_each(|value| value.put_h(e, path))
    }
    fn take_h(d: &mut Dec<'_>) -> Result<Self, Corrupt> {
        let len = d.take_len()?;
        let mut out = Vec::with_capacity(len);
        for _ in 0..len {
            out.push(T::take_h(d)?);
        }
        Ok(Self::from(out))
    }
    fn verify_h(d: &mut Dec<'_>) -> Result<(), Corrupt> {
        verify_seq(d, T::verify_h)
    }
    fn shape_h(s: &mut Shape) {
        s.push("OwnedVec<");
        T::shape_h(s);
        s.push(">");
    }
}

/// Borrowed equality/order views for scalar and product keys. Collections are
/// intentionally not keys: their decoded equality need not match wire order.
pub(crate) trait DurableKey: Durable {
    type View<'a>: Ord;
    fn key<'a>(d: &mut Dec<'a>) -> Result<Self::View<'a>, Corrupt>;
}
pub(crate) trait HDigestKey: HDigest {
    type View<'a>: Ord;
    fn key_h<'a>(d: &mut Dec<'a>) -> Result<Self::View<'a>, Corrupt>;
}
macro_rules! scalar_keys {
    ($($t:ty),*) => {$(
        impl DurableKey for $t {
            type View<'a> = Self;
            fn key<'a>(d: &mut Dec<'a>) -> Result<Self, Corrupt> { Self::take(d) }
        }
    )*};
}
scalar_keys!(
    u8,
    u16,
    u32,
    u64,
    usize,
    i32,
    i64,
    i128,
    u128,
    bool,
    (),
    std::num::NonZeroU64,
    &'static str
);
impl DurableKey for String {
    type View<'a> = &'a str;
    fn key<'a>(d: &mut Dec<'a>) -> Result<Self::View<'a>, Corrupt> {
        std::str::from_utf8(d.len_prefixed()?).map_err(|_| Corrupt)
    }
}
impl<T: DurableKey> DurableKey for Option<T> {
    type View<'a> = Option<T::View<'a>>;
    fn key<'a>(d: &mut Dec<'a>) -> Result<Self::View<'a>, Corrupt> {
        #[cfg(any())]
        note_verify_visit(d.at, false);
        match d.raw(1)?[0] {
            0 => Ok(None),
            1 => T::key(d).map(Some),
            _ => Err(Corrupt),
        }
    }
}
impl<A: DurableKey, B: DurableKey> DurableKey for (A, B) {
    type View<'a> = (A::View<'a>, B::View<'a>);
    fn key<'a>(d: &mut Dec<'a>) -> Result<Self::View<'a>, Corrupt> {
        Ok((A::key(d)?, B::key(d)?))
    }
}
impl<A: DurableKey, B: DurableKey, C: DurableKey> DurableKey for (A, B, C) {
    type View<'a> = (A::View<'a>, B::View<'a>, C::View<'a>);
    fn key<'a>(d: &mut Dec<'a>) -> Result<Self::View<'a>, Corrupt> {
        Ok((A::key(d)?, B::key(d)?, C::key(d)?))
    }
}
macro_rules! digest_keys {
    ($($t:ty),*) => {$(
        impl HDigestKey for $t {
            type View<'a> = &'a [u8];
            fn key_h<'a>(d: &mut Dec<'a>) -> Result<Self::View<'a>, Corrupt> { d.raw(32) }
        }
    )*};
}
digest_keys!(String, [u8; 32]);
impl<T: HDigestKey> HDigestKey for Option<T> {
    type View<'a> = Option<T::View<'a>>;
    fn key_h<'a>(d: &mut Dec<'a>) -> Result<Self::View<'a>, Corrupt> {
        match d.varint()? {
            0 => Ok(None),
            1 => T::key_h(d).map(Some),
            _ => Err(Corrupt),
        }
    }
}

/// Canonically sorted entries take one linear walk. Decode also accepts
/// unsorted unique entries: re-walk earlier borrowed keys in that case to
/// reject duplicates exactly, using constant space (worst-case quadratic time).
fn verify_entries<'a, K: Ord>(
    d: &mut Dec<'a>,
    key: impl Fn(&mut Dec<'a>) -> Result<K, Corrupt>,
    value: impl Fn(&mut Dec<'a>) -> Result<(), Corrupt>,
) -> Result<(), Corrupt> {
    let len = d.take_len()?;
    let start = d.at;
    let mut previous = None;
    let mut sorted = true;
    for i in 0..len {
        let current = key(d)?;
        if let Some(p) = previous.as_ref() {
            sorted &= p < &current;
        }
        if !sorted {
            let mut earlier = Dec {
                bytes: d.bytes,
                at: start,
            };
            for _ in 0..i {
                if key(&mut earlier)? == current {
                    return Err(Corrupt);
                }
                value(&mut earlier)?;
            }
        }
        value(d)?;
        previous = Some(current);
    }
    Ok(())
}

/// The default value an `E` field must hold for the record to be written.
pub(crate) trait DurableEmpty {
    fn durable_empty(&self) -> bool;
}

// Scalar validation stays identical to decode, including ranges and labels.
macro_rules! scalar_verify {
    ($($raw_tag:ident)?) => {
        fn verify(d: &mut Dec<'_>) -> Result<(), Corrupt> {
            $(#[cfg(any())] $raw_tag(d.at, false);)?
            Self::take(d).map(|_| ())
        }
    };
}

impl Durable for u64 {
    fn put(&self, e: &mut Enc) -> Result<(), Refuse> {
        e.varint(*self)
    }
    fn take(d: &mut Dec<'_>) -> Result<Self, Corrupt> {
        d.varint()
    }
    scalar_verify!();
    fn shape(s: &mut Shape) {
        s.push("u64");
    }
}

impl Durable for usize {
    fn put(&self, e: &mut Enc) -> Result<(), Refuse> {
        e.varint(u64::try_from(*self).map_err(|_| Refuse::TooLarge)?)
    }
    fn take(d: &mut Dec<'_>) -> Result<Self, Corrupt> {
        Self::try_from(d.varint()?).map_err(|_| Corrupt)
    }
    scalar_verify!();
    fn shape(s: &mut Shape) {
        s.push("usize");
    }
}

macro_rules! narrow_unsigned {
    ($($t:ty),*) => {$(
        impl Durable for $t {
            fn put(&self, e: &mut Enc) -> Result<(), Refuse> {
                e.varint(u64::from(*self))
            }
            fn take(d: &mut Dec<'_>) -> Result<Self, Corrupt> {
                <$t>::try_from(d.varint()?).map_err(|_| Corrupt)
            }
            scalar_verify!();
            fn shape(s: &mut Shape) {
                s.push(stringify!($t));
            }
        }
    )*};
}
narrow_unsigned!(u8, u16, u32);

macro_rules! empty_when_zero {
    ($($t:ty),*) => {$(
        impl DurableEmpty for $t {
            fn durable_empty(&self) -> bool {
                *self == 0
            }
        }
    )*};
}
empty_when_zero!(u8, u16, u32, u64, usize);

fn put_signed(e: &mut Enc, value: i64) -> Result<(), Refuse> {
    e.varint(((value << 1) ^ (value >> 63)) as u64)
}

fn take_signed(d: &mut Dec<'_>) -> Result<i64, Corrupt> {
    let raw = d.varint()?;
    Ok(((raw >> 1) as i64) ^ -((raw & 1) as i64))
}

impl Durable for i64 {
    fn put(&self, e: &mut Enc) -> Result<(), Refuse> {
        put_signed(e, *self)
    }
    fn take(d: &mut Dec<'_>) -> Result<Self, Corrupt> {
        take_signed(d)
    }
    scalar_verify!();
    fn shape(s: &mut Shape) {
        s.push("i64");
    }
}

impl Durable for i32 {
    fn put(&self, e: &mut Enc) -> Result<(), Refuse> {
        put_signed(e, i64::from(*self))
    }
    fn take(d: &mut Dec<'_>) -> Result<Self, Corrupt> {
        Self::try_from(take_signed(d)?).map_err(|_| Corrupt)
    }
    scalar_verify!();
    fn shape(s: &mut Shape) {
        s.push("i32");
    }
}

impl Durable for i128 {
    fn put(&self, e: &mut Enc) -> Result<(), Refuse> {
        e.raw(&self.to_le_bytes())
    }
    fn take(d: &mut Dec<'_>) -> Result<Self, Corrupt> {
        let bytes: [u8; 16] = d.raw(16)?.try_into().map_err(|_| Corrupt)?;
        Ok(Self::from_le_bytes(bytes))
    }
    scalar_verify!();
    fn shape(s: &mut Shape) {
        s.push("i128");
    }
}

impl Durable for u128 {
    fn put(&self, e: &mut Enc) -> Result<(), Refuse> {
        e.raw(&self.to_le_bytes())
    }
    fn take(d: &mut Dec<'_>) -> Result<Self, Corrupt> {
        let bytes: [u8; 16] = d.raw(16)?.try_into().map_err(|_| Corrupt)?;
        Ok(Self::from_le_bytes(bytes))
    }
    scalar_verify!();
    fn shape(s: &mut Shape) {
        s.push("u128");
    }
}

impl Durable for std::num::NonZeroU64 {
    fn put(&self, e: &mut Enc) -> Result<(), Refuse> {
        e.varint(self.get())
    }
    fn take(d: &mut Dec<'_>) -> Result<Self, Corrupt> {
        Self::new(d.varint()?).ok_or(Corrupt)
    }
    scalar_verify!();
    fn shape(s: &mut Shape) {
        s.push("NonZeroU64");
    }
}

impl Durable for bool {
    fn put(&self, e: &mut Enc) -> Result<(), Refuse> {
        e.raw(&[u8::from(*self)])
    }
    fn take(d: &mut Dec<'_>) -> Result<Self, Corrupt> {
        match d.raw(1)?[0] {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(Corrupt),
        }
    }
    scalar_verify!(note_verify_visit);
    fn shape(s: &mut Shape) {
        s.push("bool");
    }
}
impl DurableEmpty for bool {
    fn durable_empty(&self) -> bool {
        !*self
    }
}

impl Durable for () {
    fn put(&self, _: &mut Enc) -> Result<(), Refuse> {
        Ok(())
    }
    fn take(_: &mut Dec<'_>) -> Result<Self, Corrupt> {
        Ok(())
    }
    scalar_verify!();
    fn shape(s: &mut Shape) {
        s.push("()");
    }
}

impl Durable for String {
    fn put(&self, e: &mut Enc) -> Result<(), Refuse> {
        e.len_prefixed(self.as_bytes())
    }
    fn take(d: &mut Dec<'_>) -> Result<Self, Corrupt> {
        let bytes = d.len_prefixed()?;
        std::str::from_utf8(bytes)
            .map(str::to_string)
            .map_err(|_| Corrupt)
    }
    fn verify(d: &mut Dec<'_>) -> Result<(), Corrupt> {
        std::str::from_utf8(d.len_prefixed()?)
            .map(|_| ())
            .map_err(|_| Corrupt)
    }
    fn shape(s: &mut Shape) {
        s.push("String");
    }
}
impl DurableEmpty for String {
    fn durable_empty(&self) -> bool {
        self.is_empty()
    }
}

/// `X` only (workspace path): hashed, never stored. `put` refuses unless the
/// encoder is hashing, so a path declared `N`, `U`, `L` or `D` refuses its
/// record instead of storing the path. Decode exists for the trait and is
/// never reached for an `X` field.
impl Durable for std::path::PathBuf {
    fn put(&self, e: &mut Enc) -> Result<(), Refuse> {
        if !e.hashing() {
            return Err(Refuse::NonEmpty("PathBuf"));
        }
        e.len_prefixed(self.as_os_str().as_encoded_bytes())
    }
    fn take(d: &mut Dec<'_>) -> Result<Self, Corrupt> {
        String::take(d).map(Self::from)
    }
    fn verify(d: &mut Dec<'_>) -> Result<(), Corrupt> {
        String::verify(d)
    }
    fn shape(s: &mut Shape) {
        s.push("PathBuf");
    }
}

/// The closed set of static labels persisted types carry. A label outside it
/// refuses the record; decode maps back to the same `'static` value.
const STATIC_LABELS: &[&str] = &[
    "anthropic",
    "openai",
    "provider-sha256:v1",
    "claude_desktop_original:v1",
    "codex_creator_header:v1",
    "conflict",
    "missing",
    "complete",
];

impl Durable for &'static str {
    fn put(&self, e: &mut Enc) -> Result<(), Refuse> {
        let index = STATIC_LABELS
            .iter()
            .position(|label| label == self)
            .ok_or(Refuse::UnknownLabel)?;
        e.varint(index as u64)
    }
    fn take(d: &mut Dec<'_>) -> Result<Self, Corrupt> {
        let index = usize::try_from(d.varint()?).map_err(|_| Corrupt)?;
        STATIC_LABELS.get(index).copied().ok_or(Corrupt)
    }
    scalar_verify!();
    fn shape(s: &mut Shape) {
        s.push("static_label");
        for label in STATIC_LABELS {
            s.push(label);
        }
    }
}

impl<T: Durable> Durable for Option<T> {
    fn put(&self, e: &mut Enc) -> Result<(), Refuse> {
        match self {
            None => e.raw(&[0]),
            Some(value) => {
                e.raw(&[1])?;
                value.put(e)
            }
        }
    }
    fn take(d: &mut Dec<'_>) -> Result<Self, Corrupt> {
        match d.raw(1)?[0] {
            0 => Ok(None),
            1 => T::take(d).map(Some),
            _ => Err(Corrupt),
        }
    }
    fn verify(d: &mut Dec<'_>) -> Result<(), Corrupt> {
        #[cfg(any())]
        note_verify_visit(d.at, false);
        match d.raw(1)?[0] {
            0 => Ok(()),
            1 => {
                #[cfg(any())]
                VERIFY_PRESENT_OPTIONS.with(|count| count.set(count.get() + 1));
                T::verify(d)
            }
            _ => Err(Corrupt),
        }
    }
    fn shape(s: &mut Shape) {
        s.push("Option<");
        T::shape(s);
        s.push(">");
    }
}
impl<T> DurableEmpty for Option<T> {
    fn durable_empty(&self) -> bool {
        self.is_none()
    }
}

impl<T: Durable> Durable for Box<T> {
    fn put(&self, e: &mut Enc) -> Result<(), Refuse> {
        (**self).put(e)
    }
    fn take(d: &mut Dec<'_>) -> Result<Self, Corrupt> {
        T::take(d).map(Box::new)
    }
    fn verify(d: &mut Dec<'_>) -> Result<(), Corrupt> {
        T::verify(d)
    }
    fn shape(s: &mut Shape) {
        T::shape(s);
    }
}

fn put_seq<'a, T: Durable + 'a>(
    e: &mut Enc,
    len: usize,
    items: impl Iterator<Item = &'a T>,
) -> Result<(), Refuse> {
    e.varint(len as u64)?;
    for item in items {
        item.put(e)?;
    }
    Ok(())
}

impl<T: Durable> Durable for Vec<T> {
    fn put(&self, e: &mut Enc) -> Result<(), Refuse> {
        put_seq(e, self.len(), self.iter())
    }
    fn take(d: &mut Dec<'_>) -> Result<Self, Corrupt> {
        let len = d.take_len()?;
        let mut out = Vec::with_capacity(len);
        for _ in 0..len {
            out.push(T::take(d)?);
        }
        Ok(out)
    }
    fn verify(d: &mut Dec<'_>) -> Result<(), Corrupt> {
        verify_seq(d, T::verify)
    }
    fn shape(s: &mut Shape) {
        s.push("Vec<");
        T::shape(s);
        s.push(">");
    }
}
impl<T> DurableEmpty for Vec<T> {
    fn durable_empty(&self) -> bool {
        self.is_empty()
    }
}

impl<T: Durable> Durable for VecDeque<T> {
    fn put(&self, e: &mut Enc) -> Result<(), Refuse> {
        put_seq(e, self.len(), self.iter())
    }
    fn take(d: &mut Dec<'_>) -> Result<Self, Corrupt> {
        Vec::<T>::take(d).map(VecDeque::from)
    }
    fn verify(d: &mut Dec<'_>) -> Result<(), Corrupt> {
        Vec::<T>::verify(d)
    }
    fn shape(s: &mut Shape) {
        s.push("VecDeque<");
        T::shape(s);
        s.push(">");
    }
}

impl<T: Durable, const N: usize> Durable for [T; N] {
    fn put(&self, e: &mut Enc) -> Result<(), Refuse> {
        for item in self {
            item.put(e)?;
        }
        Ok(())
    }
    fn take(d: &mut Dec<'_>) -> Result<Self, Corrupt> {
        let mut out = Vec::with_capacity(N);
        for _ in 0..N {
            out.push(T::take(d)?);
        }
        out.try_into().map_err(|_| Corrupt)
    }
    fn verify(d: &mut Dec<'_>) -> Result<(), Corrupt> {
        for _ in 0..N {
            T::verify(d)?;
        }
        Ok(())
    }
    fn shape(s: &mut Shape) {
        s.push(&format!("[{N}]"));
        T::shape(s);
    }
}

impl<T: DurableKey + Ord> Durable for BTreeSet<T> {
    fn put(&self, e: &mut Enc) -> Result<(), Refuse> {
        put_seq(e, self.len(), self.iter())
    }
    fn take(d: &mut Dec<'_>) -> Result<Self, Corrupt> {
        let len = d.take_len()?;
        let mut out = BTreeSet::new();
        for _ in 0..len {
            if !out.insert(T::take(d)?) {
                return Err(Corrupt);
            }
        }
        Ok(out)
    }
    fn verify(d: &mut Dec<'_>) -> Result<(), Corrupt> {
        verify_entries(d, T::key, |_| Ok(()))
    }
    fn shape(s: &mut Shape) {
        s.push("BTreeSet<");
        T::shape(s);
        s.push(">");
    }
}
impl<T> DurableEmpty for BTreeSet<T> {
    fn durable_empty(&self) -> bool {
        self.is_empty()
    }
}

fn put_map<'a, K: Durable + 'a, V: Durable + 'a>(
    e: &mut Enc,
    len: usize,
    items: impl Iterator<Item = (&'a K, &'a V)>,
) -> Result<(), Refuse> {
    e.varint(len as u64)?;
    for (key, value) in items {
        key.put(e)?;
        value.put(e)?;
    }
    Ok(())
}

impl<K: DurableKey + Ord, V: Durable> Durable for BTreeMap<K, V> {
    fn put(&self, e: &mut Enc) -> Result<(), Refuse> {
        put_map(e, self.len(), self.iter())
    }
    fn take(d: &mut Dec<'_>) -> Result<Self, Corrupt> {
        let len = d.take_len()?;
        let mut out = BTreeMap::new();
        for _ in 0..len {
            let key = K::take(d)?;
            let value = V::take(d)?;
            if out.insert(key, value).is_some() {
                return Err(Corrupt);
            }
        }
        Ok(out)
    }
    fn verify(d: &mut Dec<'_>) -> Result<(), Corrupt> {
        verify_entries(d, K::key, V::verify)
    }
    fn shape(s: &mut Shape) {
        s.push("BTreeMap<");
        K::shape(s);
        V::shape(s);
        s.push(">");
    }
}
impl<K, V> DurableEmpty for BTreeMap<K, V> {
    fn durable_empty(&self) -> bool {
        self.is_empty()
    }
}

impl<T: Durable + crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::heap_layout_bound::HeapLayoutBound> Durable
    for crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::owned_heap::OwnedVec<T>
{
    fn put(&self, e: &mut Enc) -> Result<(), Refuse> {
        put_seq(e, self.len(), self.iter())
    }
    fn take(d: &mut Dec<'_>) -> Result<Self, Corrupt> {
        Vec::<T>::take(d).map(Self::from)
    }
    fn verify(d: &mut Dec<'_>) -> Result<(), Corrupt> {
        Vec::<T>::verify(d)
    }
    fn shape(s: &mut Shape) {
        s.push("OwnedVec<");
        T::shape(s);
        s.push(">");
    }
}
impl<T> DurableEmpty for crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::owned_heap::OwnedVec<T> {
    fn durable_empty(&self) -> bool {
        self.is_empty()
    }
}

impl<K, V> Durable for crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::owned_heap::OwnedMap<K, V>
where
    K: DurableKey + Ord + crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::heap_layout_bound::HeapLayoutBound,
    V: Durable + crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::heap_layout_bound::HeapLayoutBound,
{
    fn put(&self, e: &mut Enc) -> Result<(), Refuse> {
        put_map(e, self.len(), self.iter())
    }
    fn take(d: &mut Dec<'_>) -> Result<Self, Corrupt> {
        let len = d.take_len()?;
        let mut out = Self::new();
        for _ in 0..len {
            let key = K::take(d)?;
            let value = V::take(d)?;
            if out.insert(key, value).is_some() {
                return Err(Corrupt);
            }
        }
        Ok(out)
    }
    fn verify(d: &mut Dec<'_>) -> Result<(), Corrupt> {
        verify_entries(d, K::key, V::verify)
    }
    fn shape(s: &mut Shape) {
        s.push("OwnedMap<");
        K::shape(s);
        V::shape(s);
        s.push(">");
    }
}
impl<K, V> DurableEmpty for crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::owned_heap::OwnedMap<K, V> {
    fn durable_empty(&self) -> bool {
        self.is_empty()
    }
}

impl<A: Durable, B: Durable> Durable for (A, B) {
    fn put(&self, e: &mut Enc) -> Result<(), Refuse> {
        self.0.put(e)?;
        self.1.put(e)
    }
    fn take(d: &mut Dec<'_>) -> Result<Self, Corrupt> {
        let a = A::take(d)?;
        Ok((a, B::take(d)?))
    }
    fn verify(d: &mut Dec<'_>) -> Result<(), Corrupt> {
        A::verify(d)?;
        B::verify(d)
    }
    fn shape(s: &mut Shape) {
        s.push("(");
        A::shape(s);
        B::shape(s);
        s.push(")");
    }
}

impl<A: Durable, B: Durable, C: Durable> Durable for (A, B, C) {
    fn put(&self, e: &mut Enc) -> Result<(), Refuse> {
        self.0.put(e)?;
        self.1.put(e)?;
        self.2.put(e)
    }
    fn take(d: &mut Dec<'_>) -> Result<Self, Corrupt> {
        let a = A::take(d)?;
        let b = B::take(d)?;
        Ok((a, b, C::take(d)?))
    }
    fn verify(d: &mut Dec<'_>) -> Result<(), Corrupt> {
        A::verify(d)?;
        B::verify(d)?;
        C::verify(d)
    }
    fn shape(s: &mut Shape) {
        s.push("(");
        A::shape(s);
        B::shape(s);
        C::shape(s);
        s.push(")");
    }
}

/// One field of a persisted type, by class. Internal to the macros below.
#[doc(hidden)]
macro_rules! durable_field {
    (put N, $e:ident, $f:ident, $ty:ty, $path:expr) => {{
        let value: &$ty = $f;
        $crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::Durable::put(value, $e)?;
    }};
    (put H, $e:ident, $f:ident, $ty:ty, $path:expr) => {{
        let value: &$ty = $f;
        $crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::HDigest::put_h(value, $e, $path)?;
    }};
    (put U, $e:ident, $f:ident, $ty:ty, $path:expr) => {
        $crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::durable_field!(put N, $e, $f, $ty, $path)
    };
    (put L, $e:ident, $f:ident, $ty:ty, $path:expr) => {{
        let value: &$ty = $f;
        #[cfg(any())]
        let start = $e.position();
        $crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::Durable::put(value, $e)?;
        #[cfg(any())]
        $crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::note_l_span($e, start, $path);
    }};
    (put D, $e:ident, $f:ident, $ty:ty, $path:expr) => {
        $crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::durable_field!(put N, $e, $f, $ty, $path)
    };
    (put P, $e:ident, $f:ident, $ty:ty, $path:expr) => {
        $crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::durable_field!(put N, $e, $f, $ty, $path)
    };
    (put X, $e:ident, $f:ident, $ty:ty, $path:expr) => {{
        let value: &$ty = $f;
        if $e.hashing() {
            $crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::Durable::put(value, $e)?;
        }
    }};
    (put E, $e:ident, $f:ident, $ty:ty, $path:expr) => {{
        let value: &$ty = $f;
        if !$crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::DurableEmpty::durable_empty(value) {
            return Err($crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::Refuse::NonEmpty($path));
        }
    }};
    (put I, $e:ident, $f:ident, $ty:ty, $path:expr) => {{
        let _: &$ty = $f;
    }};
    (take N, $d:ident, $ty:ty) => {
        <$ty as $crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::Durable>::take($d)?
    };
    (take H, $d:ident, $ty:ty) => {
        <$ty as $crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::HDigest>::take_h($d)?
    };
    (take U, $d:ident, $ty:ty) => {
        <$ty as $crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::Durable>::take($d)?
    };
    (take L, $d:ident, $ty:ty) => {
        <$ty as $crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::Durable>::take($d)?
    };
    (take D, $d:ident, $ty:ty) => {
        <$ty as $crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::Durable>::take($d)?
    };
    (take P, $d:ident, $ty:ty) => {
        <$ty as $crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::Durable>::take($d)?
    };
    (take $other:ident, $d:ident, $ty:ty) => {
        <$ty as ::std::default::Default>::default()
    };
    (verify H, $d:ident, $ty:ty) => { <$ty as $crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::HDigest>::verify_h($d)? };
    (verify X, $d:ident, $ty:ty) => {};
    (verify E, $d:ident, $ty:ty) => {};
    (verify I, $d:ident, $ty:ty) => {};
    (verify N, $d:ident, $ty:ty) => { <$ty as $crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::Durable>::verify($d)? };
    (verify U, $d:ident, $ty:ty) => { <$ty as $crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::Durable>::verify($d)? };
    (verify L, $d:ident, $ty:ty) => { <$ty as $crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::Durable>::verify($d)? };
    (verify D, $d:ident, $ty:ty) => { <$ty as $crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::Durable>::verify($d)? };
    (verify P, $d:ident, $ty:ty) => { <$ty as $crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::Durable>::verify($d)? };
    (verify $other:ident, $d:ident, $ty:ty) => { compile_error!("unknown durable field class in verify") };
    (key_type X, $ty:ty, $lt:lifetime) => { compile_error!("X/E/I fields cannot appear in durable keys") };
    (key_type E, $ty:ty, $lt:lifetime) => { compile_error!("X/E/I fields cannot appear in durable keys") };
    (key_type I, $ty:ty, $lt:lifetime) => { compile_error!("X/E/I fields cannot appear in durable keys") };
    (key X, $d:ident, $ty:ty) => { compile_error!("X/E/I fields cannot appear in durable keys") };
    (key E, $d:ident, $ty:ty) => { compile_error!("X/E/I fields cannot appear in durable keys") };
    (key I, $d:ident, $ty:ty) => { compile_error!("X/E/I fields cannot appear in durable keys") };
    (key_type H, $ty:ty, $lt:lifetime) => { <$ty as $crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::HDigestKey>::View<$lt> };
    (key_type $c:ident, $ty:ty, $lt:lifetime) => { <$ty as $crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::DurableKey>::View<$lt> };
    (key H, $d:ident, $ty:ty) => { <$ty as $crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::HDigestKey>::key_h($d)? };
    (key $c:ident, $d:ident, $ty:ty) => { <$ty as $crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::DurableKey>::key($d)? };
    (shape X, $s:ident, $f:ident, $ty:ty) => {{
        $s.push(concat!("X ", stringify!($f)));
        <$ty as $crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::Durable>::shape($s);
    }};
    (shape H, $s:ident, $f:ident, $ty:ty) => {{
        $s.push(concat!("H ", stringify!($f)));
        <$ty as $crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::HDigest>::shape_h($s);
    }};
    (shape E, $s:ident, $f:ident, $ty:ty) => {
        $s.push(concat!("E ", stringify!($f), ": ", stringify!($ty)))
    };
    (shape I, $s:ident, $f:ident, $ty:ty) => {
        $s.push(concat!("I ", stringify!($f), ": ", stringify!($ty)))
    };
    (shape $c:ident, $s:ident, $f:ident, $ty:ty) => {{
        $s.push(concat!(stringify!($c), " ", stringify!($f)));
        <$ty as $crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::Durable>::shape($s);
    }};
}
pub(crate) use durable_field;

/// `durable_struct!(T { N a: u64, X b: Option<String> })`, or for a tuple
/// struct `durable_struct!(T(N a: u64, H b: [u8; 32]))` with names chosen
/// for the positions.
macro_rules! durable_struct {
    (key $t:ident $body:tt) => {
        $crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::durable_struct!($t $body);
        $crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::durable_struct!(@key $t $body);
    };
    (@key $t:ident { $($c:ident $f:ident : $ty:ty),* $(,)? }) => {
        $crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::durable_struct!(@key $t ($($c $f: $ty),*));
    };
    (@key $t:ident ( $($c:ident $f:ident : $ty:ty),* $(,)? )) => {
        impl $crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::DurableKey for $t {
            type View<'a> = ($($crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::durable_field!(key_type $c, $ty, 'a),)*);
            fn key<'a>(d: &mut $crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::Dec<'a>) -> Result<Self::View<'a>, $crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::Corrupt> {
                Ok(($($crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::durable_field!(key $c, d, $ty),)*))
            }
        }
    };
    ($t:ident { $($c:ident $f:ident : $ty:ty),* $(,)? }) => {
        impl $crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::Durable for $t {
            #[allow(unused_variables)]
            fn put(
                &self,
                e: &mut $crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::Enc,
            ) -> Result<(), $crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::Refuse> {
                let Self { $($f),* } = self;
                $($crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::durable_field!(
                    put $c, e, $f, $ty, concat!(stringify!($t), ".", stringify!($f))
                );)*
                Ok(())
            }
            #[allow(unused_variables)]
            fn take(
                d: &mut $crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::Dec<'_>,
            ) -> Result<Self, $crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::Corrupt> {
                Ok(Self { $($f: $crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::durable_field!(take $c, d, $ty)),* })
            }
            #[allow(unused_variables)]
            fn verify(d: &mut $crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::Dec<'_>) -> Result<(), $crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::Corrupt> {
                $($crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::durable_field!(verify $c, d, $ty);)*
                Ok(())
            }
            fn shape(s: &mut $crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::Shape) {
                if s.enter(stringify!($t)) {
                    $($crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::durable_field!(shape $c, s, $f, $ty);)*
                    s.leave();
                }
            }
        }
    };
    ($t:ident ( $($c:ident $f:ident : $ty:ty),* $(,)? )) => {
        impl $crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::Durable for $t {
            #[allow(unused_variables)]
            fn put(
                &self,
                e: &mut $crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::Enc,
            ) -> Result<(), $crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::Refuse> {
                let Self($($f),*) = self;
                $($crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::durable_field!(
                    put $c, e, $f, $ty, concat!(stringify!($t), ".", stringify!($f))
                );)*
                Ok(())
            }
            #[allow(unused_variables)]
            fn take(
                d: &mut $crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::Dec<'_>,
            ) -> Result<Self, $crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::Corrupt> {
                Ok(Self($($crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::durable_field!(take $c, d, $ty)),*))
            }
            #[allow(unused_variables)]
            fn verify(d: &mut $crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::Dec<'_>) -> Result<(), $crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::Corrupt> {
                $($crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::durable_field!(verify $c, d, $ty);)*
                Ok(())
            }
            fn shape(s: &mut $crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::Shape) {
                if s.enter(stringify!($t)) {
                    $($crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::durable_field!(shape $c, s, $f, $ty);)*
                    s.leave();
                }
            }
        }
    };
}
pub(crate) use durable_struct;

/// `durable_enum!(T { 0 => A, 1 => B(N x: u64), 2 => C { N p: u8 } })`.
/// Tags are explicit and never reused.
macro_rules! durable_enum {
    ($t:ident { $($tag:literal => $v:ident
        $(( $($tc:ident $tf:ident : $tty:ty),* $(,)? ))?
        $({ $($sc:ident $sf:ident : $sty:ty),* $(,)? })?
    ),* $(,)? }) => {
        impl $crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::Durable for $t {
            #[allow(unused_variables)]
            fn put(
                &self,
                e: &mut $crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::Enc,
            ) -> Result<(), $crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::Refuse> {
                match self {
                    $(Self::$v $(( $($tf),* ))? $({ $($sf),* })? => {
                        e.varint($tag)?;
                        $($($crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::durable_field!(
                            put $tc, e, $tf, $tty,
                            concat!(stringify!($t), "::", stringify!($v), ".", stringify!($tf))
                        );)*)?
                        $($($crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::durable_field!(
                            put $sc, e, $sf, $sty,
                            concat!(stringify!($t), "::", stringify!($v), ".", stringify!($sf))
                        );)*)?
                    })*
                }
                Ok(())
            }
            #[allow(unused_variables)]
            fn take(
                d: &mut $crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::Dec<'_>,
            ) -> Result<Self, $crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::Corrupt> {
                Ok(match d.varint()? {
                    $($tag => Self::$v
                        $(( $($crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::durable_field!(take $tc, d, $tty)),* ))?
                        $({ $($sf: $crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::durable_field!(take $sc, d, $sty)),* })?,)*
                    _ => return Err($crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::Corrupt),
                })
            }
            fn verify(d: &mut $crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::Dec<'_>) -> Result<(), $crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::Corrupt> {
                match d.varint()? {
                    $($tag => {
                        $($($crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::durable_field!(verify $tc, d, $tty);)*)?
                        $($($crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::durable_field!(verify $sc, d, $sty);)*)?
                        Ok(())
                    },)*
                    _ => Err($crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::Corrupt),
                }
            }
            fn shape(s: &mut $crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::Shape) {
                if s.enter(stringify!($t)) {
                    $(
                        s.push(concat!(stringify!($tag), "=", stringify!($v)));
                        $($($crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::durable_field!(shape $tc, s, $tf, $tty);)*)?
                        $($($crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::durable_field!(shape $sc, s, $sf, $sty);)*)?
                    )*
                    s.leave();
                }
            }
        }
    };
}
pub(crate) use durable_enum;

/// Where each re-derived (`X`) field was last assigned, as absolute byte
/// offsets in the transcript (`N`). Restore re-reads the file only up to these
/// lines and checks each re-derived value against its stored hash.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct DurableMarks {
    /// End of the last line that set the first prompt material or title.
    pub(crate) first_prompt: Option<u64>,
    /// End of the line that set the workspace path.
    pub(crate) workspace: Option<u64>,
    /// End of the last line that assigned the Codex agent label.
    pub(crate) agent_label: Option<u64>,
    /// The last line that changed the title: (offset, length).
    pub(crate) title_line: Option<(u64, u64)>,
    /// A re-derived field was assigned by a line whose position was unknown.
    pub(crate) unknown: bool,
}
durable_struct!(DurableMarks {
    N first_prompt: Option<u64>,
    N workspace: Option<u64>,
    N agent_label: Option<u64>,
    N title_line: Option<(u64, u64)>,
    N unknown: bool,
});
impl crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::heap_layout_bound::HeapLayoutBound for DurableMarks {
    const INLINE_ONLY: bool = true;
    const STABLE_HEAP: bool = true;
    // Plain integers: no heap, one walker visit for the whole struct.
    fn heap_bound(&self, c: &mut crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::heap_layout_bound::Counter) -> Option<()> {
        c.add(0)
    }
}

impl DurableMarks {
    /// Records the current line's end as the latest assignment.
    /// An unknown position clears the mark: the field is then not
    /// re-derivable and its entry reads in Full.
    pub(crate) fn note_end(&mut self, mark: fn(&mut Self) -> &mut Option<u64>) {
        let line = current_line();
        *mark(self) = line.map(|(offset, len)| offset.saturating_add(len));
        self.unknown |= line.is_none();
    }
    pub(crate) fn note_title_line(&mut self) {
        let line = current_line();
        self.title_line = line;
        self.unknown |= line.is_none();
    }
}

thread_local! {
    /// The physical line the JSONL reader is applying: (offset, length) in
    /// the file. `None` outside a positioned read.
    static LINE: std::cell::Cell<Option<(u64, u64)>> = const { std::cell::Cell::new(None) };
}

/// Runs `apply` with `line` as the current line, then restores the previous.
pub(crate) fn with_line<T>(line: Option<(u64, u64)>, apply: impl FnOnce() -> T) -> T {
    let previous = LINE.with(|cell| cell.replace(line));
    let out = apply();
    LINE.with(|cell| cell.set(previous));
    out
}

pub(crate) fn current_line() -> Option<(u64, u64)> {
    LINE.with(std::cell::Cell::get)
}
// archive-region-end
    impl Shape {
        pub(crate) fn archived_text(&self) -> &str {
            &self.text
        }
    }
}
pub(crate) mod durable_tail_store {
    use sha2::{Digest, Sha256};
    pub(crate) type Digest32 = [u8; 32];
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) enum DurableSource { ClaudeCode, Codex }
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub(crate) struct Binding { pub(crate) source: DurableSource, pub(crate) key: Digest32, pub(crate) context: Digest32, pub(crate) scope: Digest32, pub(crate) entry: Digest32 }
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub(crate) struct DurableCertificate { pub(crate) device: u64, pub(crate) inode: u64, pub(crate) length: u64, pub(crate) modified: (i64, i64), pub(crate) birth_nanos: u64, pub(crate) sealed_offset: u64, pub(crate) sample_len: u32, pub(crate) head_sha256: Digest32, pub(crate) boundary_sha256: Digest32, pub(crate) verified_unix_seconds: u64, pub(crate) audit_debt_unix_seconds: Option<u64> }
    pub(crate) struct PendingRecord { pub(crate) binding: Binding, pub(crate) certificate: DurableCertificate, pub(crate) body: Vec<u8>, pub(crate) allowlist: Digest32 }
    pub(crate) struct DurableRecord { pub(crate) record: PendingRecord, pub(crate) index_generation: u64 }
// archive-region: durable_tail_store.rs
const FORMAT_VERSION: u16 = 1;
const MAGIC: [u8; 8] = *b"ottto-dt";
// archive-region-end
// archive-region: durable_tail_store.rs
const HEADER_BYTES: usize = 8 // magic
    + 2 // format_version
    + 32 // allowlist_digest
    + 1 // source
    + 32 * 4 // key, context, scope, entry digests
    + 8 // index generation
    + CERTIFICATE_BYTES
    + 4; // body length
const CERTIFICATE_BYTES: usize = 8 * 3 // device, inode, length
    + 8 * 2 // mtime seconds, nanos
    + 8 // birth
    + 8 // sealed offset
    + 4 // sample length
    + 32 * 2 // sample digests
    + 8 // verified
    + 1 // debt flag
    + 8; // debt
const TRAILER_BYTES: usize = 32;
// archive-region-end
impl DurableSource {
// archive-region: durable_tail_store.rs
fn tag(self) -> u8 {
        match self {
            Self::ClaudeCode => 1,
            Self::Codex => 2,
        }
    }
// archive-region-end
}
// archive-region: durable_tail_store.rs
fn encode(record: &DurableRecord) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER_BYTES + record.record.body.len() + TRAILER_BYTES);
    encode_parts(&mut out, &record.record, record.index_generation);
    let trailer: Digest32 = Sha256::digest(&out).into();
    out.extend_from_slice(&trailer);
    out
}

fn encode_parts(out: &mut Vec<u8>, record: &PendingRecord, generation: u64) {
    encode_header(out, record, generation);
    out.extend_from_slice(&record.body);
}

/// Everything before the body, ending with the body length: exactly
/// `HEADER_BYTES`.
fn encode_header(out: &mut Vec<u8>, record: &PendingRecord, generation: u64) {
    let binding = &record.binding;
    let certificate = &record.certificate;
    out.extend_from_slice(&MAGIC);
    out.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
    out.extend_from_slice(&record.allowlist);
    out.push(binding.source.tag());
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
// archive-region-end
    pub(super) const ARCHIVED_FORMAT: u16 = FORMAT_VERSION;

    pub(super) fn archived_frame(record: &super::ArchivedRecord) -> Result<Vec<u8>, String> {
        let source = match record.source_tag {
            1 => DurableSource::ClaudeCode,
            2 => DurableSource::Codex,
            other => return Err(format!("no v1 store source for tag {other}")),
        };
        Ok(encode(&DurableRecord {
            record: PendingRecord {
                binding: Binding {
                    source,
                    key: record.key,
                    context: record.context,
                    scope: record.scope,
                    entry: record.entry,
                },
                certificate: DurableCertificate {
                    device: record.device,
                    inode: record.inode,
                    length: record.length,
                    modified: record.modified,
                    birth_nanos: record.birth_nanos,
                    sealed_offset: record.sealed_offset,
                    sample_len: record.sample_len,
                    head_sha256: record.head_sha256,
                    boundary_sha256: record.boundary_sha256,
                    verified_unix_seconds: record.verified_unix_seconds,
                    audit_debt_unix_seconds: record.audit_debt,
                },
                body: record.body.clone(),
                allowlist: record.allowlist,
            },
            index_generation: record.generation,
        }))
    }
}
// archive-region: codex_scan_diagnostics.rs
const PARENT_UNRESOLVABLE_CAUSES: usize = 12;
// archive-region-end
pub(crate) mod codex_scan_diagnostics { pub(super) use super::PARENT_UNRESOLVABLE_CAUSES; }
pub(crate) mod codex_prelude_footprint {
    use crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::*;
    use std::collections::{BTreeMap, BTreeSet};
    use crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::snapshots::*;
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct LoadedAgentsMd {
    pub(crate) directory: Option<String>,
    pub(crate) text: String,
}
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Default)]
pub(crate) struct CodexPrelude {
    pub(crate) cwd: Option<String>,
    pub(crate) started_at: Option<i64>,
    pub(crate) is_fork: bool,
    pub(crate) complete: bool,
    pub(crate) model: Option<String>,
    pub(crate) context_window: Option<u64>,
    pub(crate) first_input_tokens: Option<u64>,
    pub(crate) base_instructions_chars: u64,
    pub(crate) other_harness_chars: u64,
    pub(crate) hook_chars: u64,
    pub(crate) block_chars: [u64; BLOCK_KINDS],
    pub(crate) blocks_incomplete: bool,
    pub(crate) input_closed: bool,
    pub(crate) world_state_seen: bool,
    pub(crate) agents_md: Option<LoadedAgentsMd>,
    pub(crate) agents_md_capped: bool,
    pub(crate) skills_body: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct CodexPreludeParser {
    pub(crate) prelude: CodexPrelude,
    pub(crate) session_id: Option<String>,
    pub(crate) rows_after_first_request: usize,
    pub(crate) agents_md_cap: usize,
    pub(crate) keep_skills_body: bool,
}

// archive-region: codex_prelude_footprint.rs
const BLOCK_KINDS: usize = 8;
// archive-region-end
// archive-region: codex_prelude_footprint.rs
crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::durable_struct!(LoadedAgentsMd {
    X directory: Option<String>,
    X text: String,
})
// archive-region-end
;
// archive-region: codex_prelude_footprint.rs
crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::durable_struct!(CodexPrelude {
    X cwd: Option<String>,
    N started_at: Option<i64>,
    N is_fork: bool,
    N complete: bool,
    U model: Option<String>,
    N context_window: Option<u64>,
    N first_input_tokens: Option<u64>,
    N base_instructions_chars: u64,
    N other_harness_chars: u64,
    N hook_chars: u64,
    N block_chars: [u64; BLOCK_KINDS],
    N blocks_incomplete: bool,
    N input_closed: bool,
    N world_state_seen: bool,
    X agents_md: Option<LoadedAgentsMd>,
    N agents_md_capped: bool,
    E skills_body: Option<String>,
})
// archive-region-end
;
// archive-region: codex_prelude_footprint.rs
crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::durable_struct!(CodexPreludeParser {
    X prelude: CodexPrelude,
    U session_id: Option<String>,
    N rows_after_first_request: usize,
    N agents_md_cap: usize,
    N keep_skills_body: bool,
})
// archive-region-end
;
}
pub(crate) mod claude_status_coverage {
    #[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
    pub(crate) struct HomeKey;
}
pub(crate) mod snapshots {
    use crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::{self, Corrupt, Dec, Durable, Enc, Refuse, Shape, DurableMarks};
    use std::collections::{BTreeMap, BTreeSet, VecDeque};
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};
    use std::num::NonZeroU64;
    use crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::codex_prelude_footprint::*;
    use crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::owned_heap::{OwnedVec, OwnedMap};
    pub(crate) type PrefixDigest = [u8; 32];
    pub(crate) type T6 = [u64; 6];
    pub(crate) mod session_start { pub(crate) use super::*; }
    pub(crate) mod codex_usage_occurrence { pub(crate) use super::*; }
    pub(crate) mod claude_request_identity { pub(crate) use super::*; }
    pub(crate) mod codex_file_join { #[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord)] pub(crate) struct TierReplay; }
    pub(crate) mod claude_request_money { pub(crate) mod e2 { #[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord)] pub(crate) struct FileFold; } }
    macro_rules! absent_on_wire { ($($t:ident),* $(,)?) => { $(#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord)] pub(crate) struct $t;)* } }
    absent_on_wire!(Value, SessionArtifact, ProofRefusal, PiUsageDedupState, CodexTurnTraceMap, CodexParentPrefix, CodexParentOwnershipLedger, ClaudeTranscriptUsageOccurrence, ClaudeDesktopSpawnLineage, CacheObservations, CodexParentPrefixProof);
    #[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord)]
    pub(crate) struct SelectorCapture { pub(crate) context: BTreeMap<String, String>, pub(crate) sources: BTreeMap<String, String> }
    use crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::heap_layout_bound::HeapLayoutBound;
    macro_rules! heap_elements { ($($t:ty),* $(,)?) => { $(impl HeapLayoutBound for $t {})* } }
    heap_elements!(SelectorCapture, PendingRow, OwnedRequest, ContextCurveCandidatePoint, ContextCurveCandidateBoundary, CompactClaudeResponseRecord, ClaudeResponseObservation, ClaudeCompactionObservation);
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Default, Copy)]
pub(crate) enum ClaudeCompactionKind {
    #[default]
    LegacySummary,
    CurrentBoundary,
}
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Default, Copy)]
pub(crate) enum SnapshotSource {
    #[default]
    Codex,
    ClaudeCode,
    Pi,
}
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Default)]
pub(crate) enum CodexOwnershipBoundary {
    #[default]
    Undetermined,
    AllLocal,
    AwaitingLegacyTrigger,
    AwaitingParentPrefix,
    Ordinal { start: u64 },
    NativeCreatedThread,
    AmbiguousFork,
}
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Default, Copy)]
pub(crate) enum CodexParentUnresolvable {
    #[default]
    Absent,
    Duplicated,
    NotRegular,
    Oversize,
    NoLedger,
    LedgerCapped,
    ParentHeld,
    ParentLossy,
    OutOfWindow,
    ForkCycle,
    DeferredRef,
    DeferredRestart,
}
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct BucketRowAccumulator {
    pub(crate) selector_context: BTreeMap<String, String>,
    pub(crate) selector_sources: BTreeMap<String, String>,
    pub(crate) usage: UsageTotals,
    pub(crate) reasoning_effort: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct ClaudeCompactionObservation {
    pub(crate) kind: ClaudeCompactionKind,
    pub(crate) timestamp: Option<String>,
    pub(crate) pre_tokens: Option<u64>,
    pub(crate) post_tokens: Option<u64>,
    pub(crate) cumulative_dropped_tokens: Option<u64>,
    pub(crate) duration_ms: Option<u64>,
    pub(crate) response_count_before: u64,
    pub(crate) pair_key: Option<u64>,
    pub(crate) has_parent_link: bool,
    pub(crate) trigger: Option<ClaudeCompactionTrigger>,
    pub(crate) id_less_before: bool,
    pub(crate) id_less_after: bool,
}
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct ClaudeResponseObservation {
    pub(crate) sequence: u64,
    pub(crate) preceding_user_timestamp: Option<String>,
    pub(crate) records: crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::owned_heap::OwnedVec<CompactClaudeResponseRecord>,
    pub(crate) record_limit_exceeded: bool,
    pub(crate) desktop_request: bool,
}
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct CodexPathSidecarCandidate {
    pub(crate) identity: String,
    pub(crate) recorded_evidence: bool,
    pub(crate) created_thread: bool,
    pub(crate) identity_conflict: bool,
    pub(crate) detail_incomplete: bool,
    pub(crate) rollout_file_matches: bool,
    pub(crate) parent: Option<String>,
    pub(crate) child_created_at_nanos: Option<i128>,
    pub(crate) projected_next_ordinal: Option<u64>,
}
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct RowKey {
    pub(crate) model: String,
    pub(crate) selector_hash: String,
    pub(crate) reasoning_effort: Option<String>,
    pub(crate) auth_mode: Option<String>,
    pub(crate) billing_channel: Option<String>,
    pub(crate) billing_provider: Option<String>,
    pub(crate) gateway_provider: Option<String>,
    pub(crate) model_provider: Option<String>,
    pub(crate) subscription_product: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct ActivityCallId {
    pub(crate) id: String,
}
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct ActivityCallTool {
    pub(crate) name: String,
}
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct SessionAccountEvidence {
    pub(crate) provider: &'static str,
    pub(crate) account_identifier_hash: Option<String>,
    pub(crate) provider_workspace_hash: Option<String>,
    pub(crate) identity_hash_scheme: &'static str,
    pub(crate) evidence_source: &'static str,
    pub(crate) identity_disposition: Option<&'static str>,
    pub(crate) source_created_at: Option<String>,
}
#[derive(Clone, Debug)]
pub(crate) struct SnapshotAccumulator {
    pub(crate) source: SnapshotSource,
    pub(crate) cache_configuration_witness: Option<String>,
    pub(crate) cache_task_complete_at: Option<String>,
    pub(crate) cache_pending_idle: Option<u64>,
    pub(crate) cache_active_turns: BTreeSet<String>,
    pub(crate) context_curve_enabled: bool,
    pub(crate) source_session_id: Option<String>,
    pub(crate) account_identifier_hash: Option<String>,
    pub(crate) title: Option<String>,
    pub(crate) title_source: Option<String>,
    pub(crate) first_prompt_title: Option<String>,
    pub(crate) first_prompt_material: Option<String>,
    pub(crate) provider_skills: BTreeSet<String>,
    pub(crate) started_at: Option<String>,
    pub(crate) ended_at: Option<String>,
    pub(crate) last_activity_at: Option<String>,
    pub(crate) workspace_hash: Option<String>,
    pub(crate) workspace_path: Option<PathBuf>,
    pub(crate) latest_model: Option<String>,
    pub(crate) latest_reasoning_effort: Option<String>,
    pub(crate) latest_turn_id: Option<String>,
    pub(crate) codex_turn_traces: Option<Arc<CodexTurnTraceMap>>,
    pub(crate) codex_observed_priority_turns: Option<BTreeMap<String, bool>>,
    pub(crate) codex_priority_witnesses_uncapped: bool,
    pub(crate) codex_tier_replay: Option<codex_file_join::TierReplay>,
    pub(crate) codex_counting: Option<Box<codex_usage_occurrence::CodexCounting>>,
    pub(crate) current_selector: SelectorCapture,
    pub(crate) session_cumulative_usage: Option<UsageTotals>,
    pub(crate) codex_session_meta_seen: bool,
    pub(crate) codex_record_seen: bool,
    pub(crate) codex_creator_header_id: Option<String>,
    pub(crate) codex_creator_evidence: Option<SessionAccountEvidence>,
    pub(crate) codex_creator_evidence_conflicted: bool,
    pub(crate) claude_desktop_identity: Option<SessionAccountEvidence>,
    pub(crate) claude_desktop_spawn_lineage: Option<ClaudeDesktopSpawnLineage>,
    pub(crate) claude_owned_session_id_observed: bool,
    pub(crate) claude_owned_session_id_conflicted: bool,
    pub(crate) codex_ownership_boundary: CodexOwnershipBoundary,
    pub(crate) codex_legacy_trigger_seen: bool,
    pub(crate) codex_legacy_bootstrap_valid: bool,
    pub(crate) codex_parent_ownership_ledgers: Option<Arc<Mutex<BTreeMap<String, CodexParentOwnershipLedger>>>>,
    pub(crate) codex_sidecar_created_thread: bool,
    pub(crate) codex_path_sidecar_candidates: Vec<CodexPathSidecarCandidate>,
    pub(crate) codex_resolved_path_identity: Option<String>,
    pub(crate) codex_sidecar_identity_ambiguous: bool,
    pub(crate) codex_sidecar_parent: Option<(String, String)>,
    pub(crate) codex_sidecar_child_created_at_nanos: Option<i128>,
    pub(crate) codex_bind_seed_len: Option<u64>,
    pub(crate) codex_sidecar_projected_next_ordinal: Option<u64>,
    pub(crate) codex_parent_session_ref: Option<String>,
    pub(crate) codex_parent_signatures: Option<CodexParentPrefix>,
    pub(crate) codex_parent_prefix_digest: PrefixDigest,
    pub(crate) codex_parent_prefix_decided: Option<(u64, PrefixDigest, bool)>,
    pub(crate) codex_parent_prefix_proof: Option<(CodexParentPrefixProof, PrefixDigest)>,
    pub(crate) codex_parent_proof_used: Option<(CodexParentPrefixProof, Option<CodexParentUnresolvable>)>,
    pub(crate) codex_parent_proof_mismatch: bool,
    pub(crate) codex_parent_proof_refusal: Option<ProofRefusal>,
    pub(crate) codex_proof_decision_only: bool,
    pub(crate) codex_boundary_buffer_count: u8,
    pub(crate) codex_proof_ledger_row: Option<String>,
    pub(crate) codex_parent_ledger_identity_used: Option<String>,
    pub(crate) codex_parent_unresolvable: Option<CodexParentUnresolvable>,
    pub(crate) codex_parent_ledger_consulted: bool,
    pub(crate) codex_parent_signature_index: usize,
    pub(crate) codex_native_created_thread_valid: bool,
    pub(crate) codex_created_thread_native_only: bool,
    pub(crate) codex_native_created_thread_header_nanos: Option<i128>,
    pub(crate) codex_native_created_thread_last_nanos: Option<i128>,
    pub(crate) codex_native_created_thread_task_turn_id: Option<String>,
    pub(crate) codex_native_created_thread_first_turn_bound: bool,
    pub(crate) codex_physical_signatures: crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::owned_heap::OwnedVec<String>,
    pub(crate) codex_physical_signatures_complete: bool,
    pub(crate) codex_ordinal_expected: Option<u64>,
    pub(crate) codex_ordinal_sequence_valid: bool,
    pub(crate) codex_owned_record_seen: bool,
    pub(crate) codex_is_fork: bool,
    pub(crate) codex_inherited_usage_records_skipped: u64,
    pub(crate) codex_duplicate_usage_records_skipped: u64,
    pub(crate) codex_cumulative_reset_count: u64,
    pub(crate) codex_context_curve_candidates: crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::owned_heap::OwnedVec<ContextCurveCandidatePoint>,
    pub(crate) codex_context_curve_boundaries: crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::owned_heap::OwnedVec<ContextCurveCandidateBoundary>,
    pub(crate) codex_context_curve_exact_supported: bool,
    pub(crate) codex_last_usage_event_identity: Option<String>,
    pub(crate) codex_legacy_bootstrap_buffer: Vec<Value>,
    pub(crate) accepted_usage_totals: UsageTotals,
    pub(crate) usage_buckets: BTreeMap<String, UsageBucketState>,
    pub(crate) origin: SnapshotOrigin,
    pub(crate) codex_root_session_ref: Option<String>,
    pub(crate) codex_spawn_depth: Option<u64>,
    pub(crate) codex_agent_label: Option<String>,
    pub(crate) activity_tool_counts: BTreeMap<String, u64>,
    pub(crate) activity_call_tools: BTreeMap<ActivityCallId, ActivityCallTool>,
    pub(crate) activity_mcp_tool_counts: BTreeMap<String, u64>,
    pub(crate) activity_mcp_tool_usage_counts: BTreeMap<String, u64>,
    pub(crate) activity_mcp_call_ids: BTreeMap<String, bool>,
    pub(crate) activity_capability_buckets: BTreeMap<(String, String, String), u64>,
    pub(crate) seen_claude_capability_tool_uses: crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::owned_heap::OwnedMap<String, ()>,
    pub(crate) activity_skills: BTreeSet<String>,
    pub(crate) skill_detector_incomplete: bool,
    pub(crate) activity_changed_file_hashes: BTreeSet<String>,
    pub(crate) activity_patch_operations: u64,
    pub(crate) activity_lines_added: u64,
    pub(crate) activity_lines_deleted: u64,
    pub(crate) activity_web_searches: u64,
    pub(crate) activity_mcp_calls: u64,
    pub(crate) activity_subagent_spawns: u64,
    pub(crate) artifacts: Vec<SessionArtifact>,
    pub(crate) artifacts_enabled: bool,
    pub(crate) latency_duration_ms_sum: u64,
    pub(crate) latency_duration_ms_count: u64,
    pub(crate) latency_ttft_ms_sum: u64,
    pub(crate) latency_ttft_ms_count: u64,
    pub(crate) latency_duration_ms_max: u64,
    pub(crate) latency_ttft_ms_max: u64,
    pub(crate) claude_responses: ClaudeResponseBook,
    pub(crate) claude_response_sequence: u64,
    pub(crate) claude_response_record_count: usize,
    pub(crate) claude_usage_request_ids: BTreeSet<String>,
    pub(crate) claude_usage_occurrences: BTreeMap<String, ClaudeTranscriptUsageOccurrence>,
    pub(crate) claude_request_identity_capture: bool,
    pub(crate) claude_org_markers: Option<Box<claude_request_identity::OrgMarkers>>,
    pub(crate) cache_observations: Option<CacheObservations>,
    pub(crate) cache_requests: crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::owned_heap::OwnedVec<OwnedRequest>,
    pub(crate) cache_requests_complete: bool,
    pub(crate) claude_context_curve_identity_complete: bool,
    pub(crate) claude_context_curve_request_index_complete: bool,
    pub(crate) claude_context_curve_owned_start_proven: bool,
    pub(crate) claude_file_birth: ClaudeFileBirth,
    pub(crate) claude_fork_parent: Option<String>,
    pub(crate) claude_money: Option<Box<claude_request_money::e2::FileFold>>,
    pub(crate) tool_usage_counts: BTreeMap<String, u64>,
    pub(crate) tool_usage_truncated: bool,
    pub(crate) seen_pi_usage_keys: BTreeMap<String, PiUsageDedupState>,
    pub(crate) dropped_usage_record_count: u64,
    pub(crate) claude_last_user_ts: Option<String>,
    pub(crate) peak_context_fill_tokens: u64,
    pub(crate) first_turn_context_tokens: Option<u64>,
    pub(crate) last_turn_context_tokens: Option<u64>,
    pub(crate) first_turn_context_window_tokens: Option<u64>,
    pub(crate) peak_context_fill_window_tokens: Option<u64>,
    pub(crate) last_turn_context_window_tokens: Option<u64>,
    pub(crate) compaction_count: u64,
    pub(crate) compaction_timestamps: crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::owned_heap::OwnedVec<String>,
    pub(crate) codex_compaction_sizes: CodexCompactionSizes,
    pub(crate) local_context_points: LocalContextPoints,
    pub(crate) claude_compaction_observations: crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::owned_heap::OwnedVec<ClaudeCompactionObservation>,
    pub(crate) claude_compaction_link_tip: Option<(u64, String)>,
    pub(crate) session_start: Box<session_start::SessionStartState>,
    pub(crate) durable_marks: crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::DurableMarks,
}
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct SnapshotOrigin {
    pub(crate) thread_source: Option<String>,
    pub(crate) source: Option<String>,
    pub(crate) source_subagent: Option<bool>,
    pub(crate) originator: Option<String>,
    pub(crate) agent_role: Option<String>,
    pub(crate) entrypoint: Option<String>,
    pub(crate) is_sidechain: Option<bool>,
    pub(crate) session_kind: Option<String>,
    pub(crate) used_workflow_orchestration: Option<bool>,
    pub(crate) parent_session_ref: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct UsageBucketState {
    pub(crate) rows: BTreeMap<RowKey, BucketRowAccumulator>,
    pub(crate) first_activity_at: Option<String>,
    pub(crate) last_activity_at: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct UsageCosts {
    pub(crate) observed: bool,
    pub(crate) reported: bool,
    pub(crate) total: Option<u128>,
    pub(crate) input: Option<u128>,
    pub(crate) output: Option<u128>,
    pub(crate) cache_read: Option<u128>,
    pub(crate) cache_creation: Option<u128>,
}
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct UsageTotals {
    pub(crate) input_tokens: u64,
    pub(crate) output_tokens: u64,
    pub(crate) cache_read_tokens: u64,
    pub(crate) cache_creation_5m_tokens: u64,
    pub(crate) cache_creation_1h_tokens: u64,
    pub(crate) reasoning_output_tokens: u64,
    pub(crate) unattributed_total_tokens: u64,
    pub(crate) request_count: u64,
    pub(crate) costs: UsageCosts,
}
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct JsonlReadReport {
    pub(crate) physical_line_count: usize,
    pub(crate) parsed_json_line_count: usize,
    pub(crate) malformed_json_line_count: usize,
    pub(crate) invalid_utf8_line_count: usize,
    pub(crate) over_line_cap_count: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct OwnedRequest {
    pub(crate) slot: RequestSlot,
    pub(crate) ordering: String,
    pub(crate) compaction_before: bool,
    pub(crate) configuration_changed: bool,
    pub(crate) configuration_witness: Option<String>,
    pub(crate) idle_seconds: Option<u64>,
}
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct RequestSlot {
    pub(crate) request_ref: String,
    pub(crate) occurred_at: String,
    pub(crate) model: Option<String>,
    pub(crate) effort: Option<String>,
    pub(crate) prompt_tokens: Option<u64>,
    pub(crate) cache_read_tokens: Option<u64>,
    pub(crate) cache_creation_tokens: Option<u64>,
    pub(crate) uncached_tokens: Option<u64>,
    pub(crate) output_tokens: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct ClaudeWriterRun(pub(crate) u8);
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct ClaudeOwnWriters {
    pub(crate) latest: i64,
    pub(crate) others: [i64; KNOWN_COPY_WRITERS.len()],
}
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Default)]
pub(crate) struct ClaudeOpenedBirth {
    pub(crate) birth: u64,
    pub(crate) device: u64,
    pub(crate) inode: u64,
    pub(crate) size: u64,
}
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Default)]
pub(crate) enum ClaudeBirthScope {
    #[default]
    NotObserved,
    Subagent,
    RootUnknownBirth,
    Root(i128),
}
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct ClaudeFileBirth {
    pub(crate) scope: ClaudeBirthScope,
    pub(crate) path_key_hash: u64,
    pub(crate) tagged_in_opening: bool,
    pub(crate) tagged_responses: u64,
    pub(crate) own_responses: u64,
    pub(crate) untimed_records: u64,
    pub(crate) first_own_sequence: Option<u64>,
    pub(crate) own_first_context: Option<u64>,
    pub(crate) own_peak_context: u64,
    pub(crate) own_last_context: Option<u64>,
    pub(crate) tagged_before_first_own: bool,
    pub(crate) writer: ClaudeOwnWriters,
    pub(crate) all_response_writers: ClaudeWriterRun,
    pub(crate) opened: ClaudeOpenedBirth,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct OrgMarkers {
    pub(crate) entries: Vec<OrgMarker>,
    pub(crate) starting_marker: Option<OrgMarker>,
    pub(crate) overflowed: bool,
    pub(crate) context_digest: Option<String>,
    pub(crate) context_changed: bool,
    pub(crate) context_position: Option<u64>,
    pub(crate) context_flip_position: Option<u64>,
    pub(crate) home: Option<crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::claude_status_coverage::HomeKey>,
}
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct OrgMarker {
    pub(crate) position: u64,
    pub(crate) org: Option<String>,
    pub(crate) terminal_trusted: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum CompactClaudeSelector {
    Interned(u32),
    Inline(Box<SelectorCapture>),
}
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Default)]
pub(crate) enum ClaudeRecordText {
    #[default]
    SameAsFirstRecord,
    Own(Option<String>),
}
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum ClaudeSlot {
    Derived(ClaudeSlotTokens),
    Explicit(Box<RequestSlot>),
}
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct ClaudeResponseBook {
    pub(crate) index: OwnedMap<String, u32>,
    pub(crate) responses: OwnedVec<ClaudeResponseObservation>,
    pub(crate) selectors: ClaudeSelectorTable,
}
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct ClaudeSelectorTable {
    pub(crate) selectors: OwnedVec<SelectorCapture>,
}
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct CompactClaudeUsage {
    pub(crate) input_tokens: u64,
    pub(crate) output_tokens: u64,
    pub(crate) cache_read_tokens: u64,
    pub(crate) cache_creation_5m_tokens: u64,
    pub(crate) cache_creation_1h_tokens: u64,
    pub(crate) reasoning_output_tokens: u64,
    pub(crate) unattributed_total_tokens: u64,
    pub(crate) request_count: u64,
    pub(crate) costs: Option<Box<UsageCosts>>,
}
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct ClaudeSlotTokens {
    pub(crate) prompt_tokens: Option<u64>,
    pub(crate) cache_read_tokens: Option<u64>,
    pub(crate) cache_creation_tokens: Option<u64>,
    pub(crate) uncached_tokens: Option<u64>,
    pub(crate) output_tokens: Option<u64>,
}
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct ClaudeToolUse {
    pub(crate) id: String,
    pub(crate) name: String,
}
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct CompactClaudeResponseRecord {
    pub(crate) usage: CompactClaudeUsage,
    pub(crate) slot: ClaudeSlot,
    pub(crate) physical_sequence: u16,
    pub(crate) model: ClaudeRecordText,
    pub(crate) reasoning_effort: ClaudeRecordText,
    pub(crate) request_id: ClaudeRecordText,
    pub(crate) timestamp: Option<String>,
    pub(crate) computed_effective_input_context: Option<u64>,
    pub(crate) selector: CompactClaudeSelector,
    pub(crate) tool_uses: Vec<ClaudeToolUse>,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Default, Copy)]
pub(crate) enum CountingVersion {
    #[default]
    Legacy,
    V2,
}
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Default, Copy)]
pub(crate) enum AckEvidence {
    #[default]
    None,
    V2Marked,
    LegacyAcked,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct ClosedTurnFilter(pub(crate) Box<[u64; CLOSED_TURN_FILTER_WORDS]>);
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct CodexCounting {
    pub(crate) evidence: AckEvidence,
    pub(crate) cutover_unix_ms: Option<i64>,
    pub(crate) version: Option<CountingVersion>,
    pub(crate) reducer: Option<Box<OccurrenceReducer>>,
}
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct OccurrenceReducer {
    pub(crate) epoch: Option<Epoch>,
    pub(crate) last_native: Option<LastNative>,
    pub(crate) prev_ui: Option<UiTuple>,
    pub(crate) native_since_prev_ui: bool,
    pub(crate) line_ui: Option<(T6, T6)>,
    pub(crate) turn: Option<BoundTurn>,
    pub(crate) closed_turns: VecDeque<String>,
    pub(crate) closed_filter: Option<ClosedTurnFilter>,
    pub(crate) counters: OccurrenceCounters,
}
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Epoch {
    pub(crate) base: T6,
    pub(crate) hwm: T6,
    pub(crate) first_id: String,
    pub(crate) contiguous: bool,
}
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct LastNative {
    pub(crate) id: String,
    pub(crate) usage: T6,
    pub(crate) after: T6,
}
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct UiTuple {
    pub(crate) last: UsageTotals,
    pub(crate) total: UsageTotals,
    pub(crate) last_t6: T6,
    pub(crate) total_t6: T6,
}
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct BoundTurn {
    pub(crate) id: String,
    pub(crate) native: bool,
    pub(crate) ui_published: bool,
    pub(crate) staged_events: u64,
    pub(crate) pending: OwnedMap<(String, RowKey), PendingRow>,
}
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct PendingRow {
    pub(crate) selector_context: BTreeMap<String, String>,
    pub(crate) selector_sources: BTreeMap<String, String>,
    pub(crate) usage: UsageTotals,
    pub(crate) events: u64,
    pub(crate) first_activity_at: String,
    pub(crate) last_activity_at: String,
}
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct OccurrenceCounters {
    pub(crate) native_counted: u64,
    pub(crate) native_not_authority: u64,
    pub(crate) native_restated: u64,
    pub(crate) native_inside_holed_coverage: u64,
    pub(crate) native_inside_holed_coverage_usage: T6,
    pub(crate) native_chain_gap: u64,
    pub(crate) native_chain_overlap: u64,
    pub(crate) native_chain_overlap_covered: T6,
    pub(crate) native_epoch_reset: u64,
    pub(crate) native_conflict: u64,
    pub(crate) native_outside_open_turn: u64,
    pub(crate) native_outside_open_turn_usage: T6,
    pub(crate) native_after_turn_closed: u64,
    pub(crate) native_after_turn_closed_usage: T6,
    pub(crate) native_after_ui_flush: u64,
    pub(crate) native_after_ui_flush_usage: T6,
    pub(crate) ui_equal_total_repeat: u64,
    pub(crate) ui_equal_total_repeat_usage: T6,
    pub(crate) ui_in_native_turn_not_counted: u64,
    pub(crate) ui_in_native_turn_not_counted_usage: T6,
    pub(crate) ui_in_unbound_span: u64,
    pub(crate) v2_cumulative_base_uncounted: u64,
    pub(crate) v2_cumulative_base_uncounted_usage: T6,
    pub(crate) turn_closure_mismatch: u64,
    pub(crate) turn_reopened: u64,
    pub(crate) closed_filter_hit_unconfirmed: u64,
    pub(crate) closed_filter_hit_unconfirmed_native_usage: T6,
    pub(crate) pending_overflow_flushes: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Default, Copy)]
pub(crate) enum ClaudeCompactionTrigger {
    #[default]
    Auto,
    Manual,
    Idle,
}
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct CodexCompactionSize {
    pub(crate) before: Option<NonZeroU64>,
    pub(crate) after: Option<NonZeroU64>,
}
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct CodexCompactionSizes {
    pub(crate) entries: Vec<(String, CodexCompactionSize)>,
    pub(crate) pending_after: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct ContextCurveCandidateBoundary {
    pub(crate) observed_at: Option<String>,
    pub(crate) point_count_before: u64,
}
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct ContextCurveCandidatePoint {
    pub(crate) observed_at: Option<String>,
    pub(crate) effective_input_tokens: u64,
    pub(crate) model: Option<String>,
    pub(crate) context_window_tokens: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct LocalContextPoint {
    pub(crate) at_unix_seconds: u32,
    pub(crate) prompt_tokens: u32,
}
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct LocalContextPoints {
    pub(crate) points: Vec<LocalContextPoint>,
}

#[derive(Clone, Debug)]
pub(crate) struct CachedJsonlReduction {
    pub(crate) accumulator: SnapshotAccumulator,
    pub(crate) report: JsonlReadReport,
    pub(crate) recognized_usage_drop_count: usize,
    pub(crate) positive_recognized_usage_count: usize,
    pub(crate) positive_usage_evidence: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct OpeningRequest {
    pub(crate) context_tokens: u64,
    pub(crate) uncached_input_tokens: u64,
    pub(crate) cache_read_tokens: u64,
    pub(crate) cache_write_5m_tokens: Option<u64>,
    pub(crate) cache_write_1h_tokens: Option<u64>,
    pub(crate) parts_reconcile: bool,
    pub(crate) output_tokens: u64,
}
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct ClaudeBlob {
    pub(crate) parts: [u64; PARTS],
    pub(crate) unmeasurable: bool,
    pub(crate) config_digest: Option<ConfigDigest>,
}
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct ConfigDigest {
    pub(crate) a: u64,
    pub(crate) b: u64,
    pub(crate) len: u64,
}
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct ClaudeRequestKey(pub(crate) [u8; 32]);
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct OpeningCallId {
    pub(crate) id: String,
}
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct OpeningCall {
    pub(crate) response: u8,
    pub(crate) tool: String,
    pub(crate) candidates: u64,
    pub(crate) files: Vec<String>,
    pub(crate) answered: bool,
    pub(crate) truncated: bool,
}
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct OpeningFileState {
    pub(crate) ordinal: u64,
    pub(crate) tool: String,
    pub(crate) repo_path: Option<String>,
    pub(crate) instruction_segments: u8,
    pub(crate) reads: [u64; 2],
    pub(crate) chars: [u64; 2],
    pub(crate) client_loaded: [bool; 2],
    pub(crate) truncated: [bool; 2],
}
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct SessionStartState {
    pub(crate) client_version: Option<String>,
    pub(crate) user_turns: u8,
    pub(crate) inherited_prefix: bool,
    pub(crate) frozen: bool,
    pub(crate) requests: [Option<OpeningRequest>; WINDOW_REQUESTS],
    pub(crate) codex_requests: u8,
    pub(crate) response_tool_calls: [u64; 2],
    pub(crate) truncated_outputs: [u64; 2],
    pub(crate) parts: [u64; PARTS],
    pub(crate) parts_closed: bool,
    pub(crate) parts_unmeasurable: bool,
    pub(crate) codex_tools_logged: bool,
    pub(crate) config_digest: Option<ConfigDigest>,
    pub(crate) claude_shape: Option<(ClaudeRequestKey, u64, u64)>,
    pub(crate) claude_blobs: BTreeMap<ClaudeRequestKey, ClaudeBlob>,
    pub(crate) memory_units: Option<u64>,
    pub(crate) instruction_load_cut: Option<bool>,
    pub(crate) instructions: Option<String>,
    pub(crate) instructions_capped: bool,
    pub(crate) codex_prelude: Option<Box<CodexPreludeParser>>,
    pub(crate) calls: BTreeMap<OpeningCallId, OpeningCall>,
    pub(crate) last_codex_call: Option<String>,
    pub(crate) files: BTreeMap<String, OpeningFileState>,
    pub(crate) files_untracked: [u64; 2],
    pub(crate) held_bytes: usize,
    pub(crate) shell_moved: bool,
    pub(crate) collapsed_requests: bool,
    pub(crate) content_end: Option<u64>,
}

// archive-region: snapshots.rs
const CLAUDE_ATTRIBUTION_MCP_TOOL_FIELD: &str = "attribution_mcp_tool";
/// (raw CC key, canonical selector key). Subagent first (priority dimension).
const CLAUDE_ATTRIBUTION_FIELDS: [(&str, &str); 5] = [
    ("attributionAgent", "attribution_subagent"),
    ("attributionSkill", "attribution_skill"),
    ("attributionPlugin", "attribution_plugin"),
    ("attributionMcpServer", "attribution_mcp_server"),
    ("attributionMcpTool", CLAUDE_ATTRIBUTION_MCP_TOOL_FIELD),
];
/// The selector keys attribution capture writes: raw names, never persisted.
const CLAUDE_ATTRIBUTION_SELECTOR_KEYS: [&str; 5] = [
    CLAUDE_ATTRIBUTION_FIELDS[0].1,
    CLAUDE_ATTRIBUTION_FIELDS[1].1,
    CLAUDE_ATTRIBUTION_FIELDS[2].1,
    CLAUDE_ATTRIBUTION_FIELDS[3].1,
    CLAUDE_ATTRIBUTION_FIELDS[4].1,
];
// archive-region-end
// archive-region: snapshots.rs
crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::durable_enum!(ClaudeCompactionKind {
    0 => LegacySummary,
    1 => CurrentBoundary,
})
// archive-region-end
;
// archive-region: snapshots.rs
crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::durable_enum!(SnapshotSource {
    0 => Codex,
    1 => ClaudeCode,
    2 => Pi,
})
// archive-region-end
;
impl SnapshotSource {
// archive-region: snapshots.rs
fn api_slug(self) -> &'static str {
        match self {
            SnapshotSource::Codex => "codex",
            SnapshotSource::ClaudeCode => "claude_code",
            SnapshotSource::Pi => "pi",
        }
    }
// archive-region-end
}
// archive-region: snapshots.rs
const CAUSE_NO_EVIDENCE: u8 = 255;
// archive-region-end
// archive-region: snapshots.rs
const _: () = assert!(CodexParentUnresolvable::COUNT < CAUSE_NO_EVIDENCE as usize);
// archive-region-end
// archive-region: snapshots.rs
crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::durable_enum!(CodexOwnershipBoundary {
    0 => Undetermined,
    1 => AllLocal,
    2 => AwaitingLegacyTrigger,
    3 => AwaitingParentPrefix,
    4 => Ordinal { N start: u64 },
    5 => NativeCreatedThread,
    6 => AmbiguousFork,
})
// archive-region-end
;
// archive-region: snapshots.rs
crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::durable_enum!(CodexParentUnresolvable {
    0 => Absent,
    1 => Duplicated,
    2 => NotRegular,
    3 => Oversize,
    4 => NoLedger,
    5 => LedgerCapped,
    6 => ParentHeld,
    7 => ParentLossy,
    8 => OutOfWindow,
    9 => ForkCycle,
    10 => DeferredRef,
    11 => DeferredRestart,
})
// archive-region-end
;
impl CodexParentUnresolvable {
// archive-region: snapshots.rs
const COUNT: usize = 12;
// archive-region-end
}
// archive-region: snapshots.rs
const _: () = assert!(
    CodexParentUnresolvable::DeferredRestart as usize + 1 == CodexParentUnresolvable::COUNT
);
const _: () = assert!(
    CodexParentUnresolvable::COUNT == crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::codex_scan_diagnostics::PARENT_UNRESOLVABLE_CAUSES
);
// archive-region-end
// archive-region: snapshots.rs
crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::durable_struct!(BucketRowAccumulator {
    U selector_context: BTreeMap<String, String>,
    U selector_sources: BTreeMap<String, String>,
    N usage: UsageTotals,
    U reasoning_effort: Option<String>,
})
// archive-region-end
;
// archive-region: snapshots.rs
crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::durable_struct!(ClaudeCompactionObservation {
    N kind: ClaudeCompactionKind,
    N timestamp: Option<String>,
    N pre_tokens: Option<u64>,
    N post_tokens: Option<u64>,
    N cumulative_dropped_tokens: Option<u64>,
    N duration_ms: Option<u64>,
    N response_count_before: u64,
    N pair_key: Option<u64>,
    N has_parent_link: bool,
    N trigger: Option<ClaudeCompactionTrigger>,
    N id_less_before: bool,
    N id_less_after: bool,
})
// archive-region-end
;
// archive-region: snapshots.rs
crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::durable_struct!(ClaudeResponseObservation {
    N sequence: u64,
    N preceding_user_timestamp: Option<String>,
    D records: crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::owned_heap::OwnedVec<CompactClaudeResponseRecord>,
    N record_limit_exceeded: bool,
    N desktop_request: bool,
})
// archive-region-end
;
// archive-region: snapshots.rs
crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::durable_struct!(CodexPathSidecarCandidate {
    U identity: String,
    N recorded_evidence: bool,
    N created_thread: bool,
    N identity_conflict: bool,
    N detail_incomplete: bool,
    N rollout_file_matches: bool,
    U parent: Option<String>,
    N child_created_at_nanos: Option<i128>,
    N projected_next_ordinal: Option<u64>,
})
// archive-region-end
;
// archive-region: snapshots.rs
crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::durable_struct!(key RowKey {
    U model: String,
    // "base" or a 16-hex prefix of SHA-256 over `selector_context`, which
    // the upload carries (U): not a 32-byte digest, so not H.
    U selector_hash: String,
    U reasoning_effort: Option<String>,
    U auth_mode: Option<String>,
    U billing_channel: Option<String>,
    U billing_provider: Option<String>,
    U gateway_provider: Option<String>,
    U model_provider: Option<String>,
    U subscription_product: Option<String>,
})
// archive-region-end
;
// archive-region: snapshots.rs
crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::durable_struct!(key ActivityCallId { L id: String })
// archive-region-end
;
// archive-region: snapshots.rs
crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::durable_struct!(ActivityCallTool { U name: String })
// archive-region-end
;
// archive-region: snapshots.rs
impl crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::Durable for SelectorCapture {
    fn put(
        &self,
        e: &mut crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::Enc,
    ) -> Result<(), crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::Refuse> {
        let Self { context, sources } = self;
        if context
            .keys()
            .any(|key| CLAUDE_ATTRIBUTION_SELECTOR_KEYS.contains(&key.as_str()))
        {
            return Err(crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::Refuse::NonEmpty(
                "SelectorCapture.context.attribution",
            ));
        }
        context.put(e)?;
        sources.put(e)
    }
    fn take(
        d: &mut crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::Dec<'_>,
    ) -> Result<Self, crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::Corrupt> {
        type Map = BTreeMap<String, String>;
        Ok(Self {
            context: <Map as crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::Durable>::take(d)?,
            sources: <Map as crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::Durable>::take(d)?,
        })
    }
    fn verify(
        d: &mut crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::Dec<'_>,
    ) -> Result<(), crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::Corrupt> {
        type Map = BTreeMap<String, String>;
        <Map as crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::Durable>::verify(d)?;
        <Map as crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::Durable>::verify(d)
    }
    fn shape(s: &mut crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::Shape) {
        type Map = BTreeMap<String, String>;
        if s.enter("SelectorCapture") {
            s.push("U context");
            <Map as crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::Durable>::shape(s);
            s.push("E context.attribution");
            for key in CLAUDE_ATTRIBUTION_SELECTOR_KEYS {
                s.push(key);
            }
            s.push("U sources");
            <Map as crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::Durable>::shape(s);
            s.leave();
        }
    }
}
// archive-region-end
// archive-region: snapshots.rs
crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::durable_struct!(SessionAccountEvidence {
    N provider: &'static str,
    U account_identifier_hash: Option<String>,
    U provider_workspace_hash: Option<String>,
    N identity_hash_scheme: &'static str,
    N evidence_source: &'static str,
    N identity_disposition: Option<&'static str>,
    N source_created_at: Option<String>,
})
// archive-region-end
;
// archive-region: snapshots.rs
crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::durable_struct!(SnapshotAccumulator {
    N source: SnapshotSource,
    H cache_configuration_witness: Option<String>,
    N cache_task_complete_at: Option<String>,
    N cache_pending_idle: Option<u64>,
    L cache_active_turns: BTreeSet<String>,
    N context_curve_enabled: bool,
    U source_session_id: Option<String>,
    U account_identifier_hash: Option<String>,
    X title: Option<String>,
    N title_source: Option<String>,
    X first_prompt_title: Option<String>,
    X first_prompt_material: Option<String>,
    E provider_skills: BTreeSet<String>,
    N started_at: Option<String>,
    N ended_at: Option<String>,
    N last_activity_at: Option<String>,
    // Uploaded verbatim (`SnapshotItem.workspace_hash`): U, not H.
    U workspace_hash: Option<String>,
    X workspace_path: Option<PathBuf>,
    U latest_model: Option<String>,
    U latest_reasoning_effort: Option<String>,
    L latest_turn_id: Option<String>,
    I codex_turn_traces: Option<Arc<CodexTurnTraceMap>>,
    L codex_observed_priority_turns: Option<BTreeMap<String, bool>>,
    N codex_priority_witnesses_uncapped: bool,
    E codex_tier_replay: Option<codex_file_join::TierReplay>,
    D codex_counting: Option<Box<codex_usage_occurrence::CodexCounting>>,
    D current_selector: SelectorCapture,
    D session_cumulative_usage: Option<UsageTotals>,
    N codex_session_meta_seen: bool,
    N codex_record_seen: bool,
    U codex_creator_header_id: Option<String>,
    D codex_creator_evidence: Option<SessionAccountEvidence>,
    N codex_creator_evidence_conflicted: bool,
    E claude_desktop_identity: Option<SessionAccountEvidence>,
    E claude_desktop_spawn_lineage: Option<ClaudeDesktopSpawnLineage>,
    N claude_owned_session_id_observed: bool,
    N claude_owned_session_id_conflicted: bool,
    D codex_ownership_boundary: CodexOwnershipBoundary,
    N codex_legacy_trigger_seen: bool,
    N codex_legacy_bootstrap_valid: bool,
    I codex_parent_ownership_ledgers: Option<Arc<Mutex<BTreeMap<String, CodexParentOwnershipLedger>>>>,
    N codex_sidecar_created_thread: bool,
    D codex_path_sidecar_candidates: Vec<CodexPathSidecarCandidate>,
    U codex_resolved_path_identity: Option<String>,
    N codex_sidecar_identity_ambiguous: bool,
    U codex_sidecar_parent: Option<(String, String)>,
    N codex_sidecar_child_created_at_nanos: Option<i128>,
    N codex_bind_seed_len: Option<u64>,
    I codex_sidecar_projected_next_ordinal: Option<u64>,
    U codex_parent_session_ref: Option<String>,
    E codex_parent_signatures: Option<CodexParentPrefix>,
    H codex_parent_prefix_digest: PrefixDigest,
    // (N offset, 32-byte domain-seeded SHA-256 chain digest, N flag).
    D codex_parent_prefix_decided: Option<(u64, PrefixDigest, bool)>,
    E codex_parent_prefix_proof: Option<(CodexParentPrefixProof, PrefixDigest)>,
    E codex_parent_proof_used: Option<(CodexParentPrefixProof, Option<CodexParentUnresolvable>)>,
    N codex_parent_proof_mismatch: bool,
    E codex_parent_proof_refusal: Option<ProofRefusal>,
    N codex_proof_decision_only: bool,
    N codex_boundary_buffer_count: u8,
    H codex_proof_ledger_row: Option<String>,
    H codex_parent_ledger_identity_used: Option<String>,
    D codex_parent_unresolvable: Option<CodexParentUnresolvable>,
    N codex_parent_ledger_consulted: bool,
    N codex_parent_signature_index: usize,
    N codex_native_created_thread_valid: bool,
    N codex_created_thread_native_only: bool,
    N codex_native_created_thread_header_nanos: Option<i128>,
    N codex_native_created_thread_last_nanos: Option<i128>,
    L codex_native_created_thread_task_turn_id: Option<String>,
    N codex_native_created_thread_first_turn_bound: bool,
    H codex_physical_signatures: crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::owned_heap::OwnedVec<String>,
    N codex_physical_signatures_complete: bool,
    N codex_ordinal_expected: Option<u64>,
    N codex_ordinal_sequence_valid: bool,
    N codex_owned_record_seen: bool,
    N codex_is_fork: bool,
    N codex_inherited_usage_records_skipped: u64,
    N codex_duplicate_usage_records_skipped: u64,
    N codex_cumulative_reset_count: u64,
    D codex_context_curve_candidates: crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::owned_heap::OwnedVec<ContextCurveCandidatePoint>,
    D codex_context_curve_boundaries: crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::owned_heap::OwnedVec<ContextCurveCandidateBoundary>,
    N codex_context_curve_exact_supported: bool,
    H codex_last_usage_event_identity: Option<String>,
    E codex_legacy_bootstrap_buffer: Vec<Value>,
    D accepted_usage_totals: UsageTotals,
    D usage_buckets: BTreeMap<String, UsageBucketState>,
    D origin: SnapshotOrigin,
    U codex_root_session_ref: Option<String>,
    N codex_spawn_depth: Option<u64>,
    X codex_agent_label: Option<String>,
    U activity_tool_counts: BTreeMap<String, u64>,
    D activity_call_tools: BTreeMap<ActivityCallId, ActivityCallTool>,
    U activity_mcp_tool_counts: BTreeMap<String, u64>,
    U activity_mcp_tool_usage_counts: BTreeMap<String, u64>,
    L activity_mcp_call_ids: BTreeMap<String, bool>,
    U activity_capability_buckets: BTreeMap<(String, String, String), u64>,
    L seen_claude_capability_tool_uses: crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::owned_heap::OwnedMap<String, ()>,
    E activity_skills: BTreeSet<String>,
    N skill_detector_incomplete: bool,
    H activity_changed_file_hashes: BTreeSet<String>,
    N activity_patch_operations: u64,
    N activity_lines_added: u64,
    N activity_lines_deleted: u64,
    N activity_web_searches: u64,
    N activity_mcp_calls: u64,
    N activity_subagent_spawns: u64,
    E artifacts: Vec<SessionArtifact>,
    N artifacts_enabled: bool,
    N latency_duration_ms_sum: u64,
    N latency_duration_ms_count: u64,
    N latency_ttft_ms_sum: u64,
    N latency_ttft_ms_count: u64,
    N latency_duration_ms_max: u64,
    N latency_ttft_ms_max: u64,
    D claude_responses: ClaudeResponseBook,
    N claude_response_sequence: u64,
    N claude_response_record_count: usize,
    E claude_usage_request_ids: BTreeSet<String>,
    E claude_usage_occurrences: BTreeMap<String, ClaudeTranscriptUsageOccurrence>,
    N claude_request_identity_capture: bool,
    D claude_org_markers: Option<Box<claude_request_identity::OrgMarkers>>,
    E cache_observations: Option<CacheObservations>,
    D cache_requests: crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::owned_heap::OwnedVec<OwnedRequest>,
    N cache_requests_complete: bool,
    N claude_context_curve_identity_complete: bool,
    N claude_context_curve_request_index_complete: bool,
    N claude_context_curve_owned_start_proven: bool,
    D claude_file_birth: ClaudeFileBirth,
    E claude_fork_parent: Option<String>,
    E claude_money: Option<Box<claude_request_money::e2::FileFold>>,
    U tool_usage_counts: BTreeMap<String, u64>,
    N tool_usage_truncated: bool,
    E seen_pi_usage_keys: BTreeMap<String, PiUsageDedupState>,
    N dropped_usage_record_count: u64,
    N claude_last_user_ts: Option<String>,
    N peak_context_fill_tokens: u64,
    N first_turn_context_tokens: Option<u64>,
    N last_turn_context_tokens: Option<u64>,
    N first_turn_context_window_tokens: Option<u64>,
    N peak_context_fill_window_tokens: Option<u64>,
    N last_turn_context_window_tokens: Option<u64>,
    N compaction_count: u64,
    N compaction_timestamps: crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::owned_heap::OwnedVec<String>,
    D codex_compaction_sizes: CodexCompactionSizes,
    D local_context_points: LocalContextPoints,
    D claude_compaction_observations: crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::owned_heap::OwnedVec<ClaudeCompactionObservation>,
    L claude_compaction_link_tip: Option<(u64, String)>,
    D session_start: Box<session_start::SessionStartState>,
    D durable_marks: crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::DurableMarks,
})
// archive-region-end
;
// archive-region: snapshots.rs
crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::durable_struct!(SnapshotOrigin {
    U thread_source: Option<String>,
    U source: Option<String>,
    N source_subagent: Option<bool>,
    U originator: Option<String>,
    U agent_role: Option<String>,
    U entrypoint: Option<String>,
    N is_sidechain: Option<bool>,
    U session_kind: Option<String>,
    N used_workflow_orchestration: Option<bool>,
    U parent_session_ref: Option<String>,
})
// archive-region-end
;
// archive-region: snapshots.rs
crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::durable_struct!(UsageBucketState {
    D rows: BTreeMap<RowKey, BucketRowAccumulator>,
    N first_activity_at: Option<String>,
    N last_activity_at: Option<String>,
})
// archive-region-end
;
// archive-region: snapshots.rs
crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::durable_struct!(UsageCosts {
    N observed: bool,
    N reported: bool,
    N total: Option<u128>,
    N input: Option<u128>,
    N output: Option<u128>,
    N cache_read: Option<u128>,
    N cache_creation: Option<u128>,
})
// archive-region-end
;
// archive-region: snapshots.rs
crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::durable_struct!(UsageTotals {
    N input_tokens: u64,
    N output_tokens: u64,
    N cache_read_tokens: u64,
    N cache_creation_5m_tokens: u64,
    N cache_creation_1h_tokens: u64,
    N reasoning_output_tokens: u64,
    N unattributed_total_tokens: u64,
    N request_count: u64,
    N costs: UsageCosts,
})
// archive-region-end
;
// archive-region: snapshots.rs
crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::durable_struct!(JsonlReadReport {
    N physical_line_count: usize,
    N parsed_json_line_count: usize,
    N malformed_json_line_count: usize,
    N invalid_utf8_line_count: usize,
    N over_line_cap_count: usize,
})
// archive-region-end
;
// archive-region: snapshots/cache_observations.rs
crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::durable_struct!(OwnedRequest {
    D slot: RequestSlot,
    N ordering: String,
    N compaction_before: bool,
    N configuration_changed: bool,
    H configuration_witness: Option<String>,
    N idle_seconds: Option<u64>,
})
// archive-region-end
;
// archive-region: snapshots/cache_observations.rs
crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::durable_struct!(RequestSlot {
    L request_ref: String,
    N occurred_at: String,
    U model: Option<String>,
    U effort: Option<String>,
    N prompt_tokens: Option<u64>,
    N cache_read_tokens: Option<u64>,
    N cache_creation_tokens: Option<u64>,
    N uncached_tokens: Option<u64>,
    N output_tokens: Option<u64>,
})
// archive-region-end
;
// archive-region: snapshots/claude_context_file_birth.rs
const KNOWN_COPY_WRITERS: &[&str] = &["2.1.309", "2.1.310"];
// archive-region-end
// archive-region: snapshots/claude_context_file_birth.rs
crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::durable_struct!(ClaudeWriterRun(N x0: u8))
// archive-region-end
;
// archive-region: snapshots/claude_context_file_birth.rs
crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::durable_struct!(ClaudeOwnWriters {
    N latest: i64,
    N others: [i64; KNOWN_COPY_WRITERS.len()],
})
// archive-region-end
;
// archive-region: snapshots/claude_context_file_birth.rs
crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::durable_struct!(ClaudeOpenedBirth {
    N birth: u64,
    N device: u64,
    N inode: u64,
    N size: u64,
})
// archive-region-end
;
// archive-region: snapshots/claude_context_file_birth.rs
crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::durable_enum!(ClaudeBirthScope {
    0 => NotObserved,
    1 => Subagent,
    2 => RootUnknownBirth,
    3 => Root(N x0: i128),
})
// archive-region-end
;
// archive-region: snapshots/claude_context_file_birth.rs
crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::durable_struct!(ClaudeFileBirth {
    N scope: ClaudeBirthScope,
    I path_key_hash: u64,
    N tagged_in_opening: bool,
    N tagged_responses: u64,
    N own_responses: u64,
    N untimed_records: u64,
    N first_own_sequence: Option<u64>,
    N own_first_context: Option<u64>,
    N own_peak_context: u64,
    N own_last_context: Option<u64>,
    N tagged_before_first_own: bool,
    N writer: ClaudeOwnWriters,
    N all_response_writers: ClaudeWriterRun,
    I opened: ClaudeOpenedBirth,
})
// archive-region-end
;
// archive-region: snapshots/claude_request_identity.rs
crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::durable_struct!(OrgMarkers {
    D entries: Vec<OrgMarker>,
    D starting_marker: Option<OrgMarker>,
    N overflowed: bool,
    H context_digest: Option<String>,
    N context_changed: bool,
    N context_position: Option<u64>,
    N context_flip_position: Option<u64>,
    E home: Option<crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::claude_status_coverage::HomeKey>,
})
// archive-region-end
;
// archive-region: snapshots/claude_request_identity.rs
crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::durable_struct!(OrgMarker {
    N position: u64,
    U org: Option<String>,
    N terminal_trusted: bool,
})
// archive-region-end
;
// archive-region: snapshots/claude_response_records.rs
crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::durable_enum!(CompactClaudeSelector {
    0 => Interned(N x0: u32),
    1 => Inline(D x0: Box<SelectorCapture>),
})
// archive-region-end
;
// archive-region: snapshots/claude_response_records.rs
crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::durable_enum!(ClaudeRecordText {
    0 => SameAsFirstRecord,
    1 => Own(P x0: Option<String>),
})
// archive-region-end
;
// archive-region: snapshots/claude_response_records.rs
crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::durable_enum!(ClaudeSlot {
    0 => Derived(N x0: ClaudeSlotTokens),
    1 => Explicit(D x0: Box<RequestSlot>),
})
// archive-region-end
;
// archive-region: snapshots/claude_response_records.rs
crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::durable_struct!(ClaudeResponseBook {
    L index: OwnedMap<String, u32>,
    D responses: OwnedVec<ClaudeResponseObservation>,
    D selectors: ClaudeSelectorTable,
})
// archive-region-end
;
// archive-region: snapshots/claude_response_records.rs
crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::durable_struct!(ClaudeSelectorTable {
    D selectors: OwnedVec<SelectorCapture>,
})
// archive-region-end
;
// archive-region: snapshots/claude_response_records.rs
crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::durable_struct!(CompactClaudeUsage {
    N input_tokens: u64,
    N output_tokens: u64,
    N cache_read_tokens: u64,
    N cache_creation_5m_tokens: u64,
    N cache_creation_1h_tokens: u64,
    N reasoning_output_tokens: u64,
    N unattributed_total_tokens: u64,
    N request_count: u64,
    N costs: Option<Box<UsageCosts>>,
})
// archive-region-end
;
// archive-region: snapshots/claude_response_records.rs
crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::durable_struct!(ClaudeSlotTokens {
    N prompt_tokens: Option<u64>,
    N cache_read_tokens: Option<u64>,
    N cache_creation_tokens: Option<u64>,
    N uncached_tokens: Option<u64>,
    N output_tokens: Option<u64>,
})
// archive-region-end
;
// archive-region: snapshots/claude_response_records.rs
crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::durable_struct!(ClaudeToolUse {
    L id: String,
    U name: String,
})
// archive-region-end
;
// archive-region: snapshots/claude_response_records.rs
crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::durable_struct!(CompactClaudeResponseRecord {
    N usage: CompactClaudeUsage,
    D slot: ClaudeSlot,
    N physical_sequence: u16,
    U model: ClaudeRecordText,
    U reasoning_effort: ClaudeRecordText,
    L request_id: ClaudeRecordText,
    N timestamp: Option<String>,
    N computed_effective_input_context: Option<u64>,
    D selector: CompactClaudeSelector,
    D tool_uses: Vec<ClaudeToolUse>,
})
// archive-region-end
;
// archive-region: snapshots/codex_counting_version.rs
crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::durable_enum!(CountingVersion {
    0 => Legacy,
    1 => V2,
})
// archive-region-end
;
// archive-region: snapshots/codex_counting_version.rs
crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::durable_enum!(AckEvidence {
    0 => None,
    1 => V2Marked,
    2 => LegacyAcked,
})
// archive-region-end
;
// archive-region: snapshots/codex_usage_occurrence.rs
const CLOSED_TURN_FILTER_BYTES: usize = 8 * 1024;
// archive-region-end
// archive-region: snapshots/codex_usage_occurrence.rs
const CLOSED_TURN_FILTER_WORDS: usize = CLOSED_TURN_FILTER_BYTES / 8;
// archive-region-end
// archive-region: snapshots/codex_usage_occurrence.rs
crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::durable_struct!(ClosedTurnFilter(L x0: Box<[u64; CLOSED_TURN_FILTER_WORDS]>))
// archive-region-end
;
// archive-region: snapshots/codex_usage_occurrence.rs
crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::durable_struct!(CodexCounting {
    N evidence: AckEvidence,
    N cutover_unix_ms: Option<i64>,
    N version: Option<CountingVersion>,
    D reducer: Option<Box<OccurrenceReducer>>,
})
// archive-region-end
;
// archive-region: snapshots/codex_usage_occurrence.rs
crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::durable_struct!(OccurrenceReducer {
    D epoch: Option<Epoch>,
    D last_native: Option<LastNative>,
    N prev_ui: Option<UiTuple>,
    N native_since_prev_ui: bool,
    N line_ui: Option<(T6, T6)>,
    D turn: Option<BoundTurn>,
    L closed_turns: VecDeque<String>,
    // A membership filter over closed turn ids: a nested type whose one
    // field is L (provider ids; it carries strictly less than the ids, so
    // it is L, not H (F1)).
    D closed_filter: Option<ClosedTurnFilter>,
    N counters: OccurrenceCounters,
})
// archive-region-end
;
// archive-region: snapshots/codex_usage_occurrence.rs
crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::durable_struct!(Epoch {
    N base: T6,
    N hwm: T6,
    L first_id: String,
    N contiguous: bool,
})
// archive-region-end
;
// archive-region: snapshots/codex_usage_occurrence.rs
crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::durable_struct!(LastNative {
    L id: String,
    N usage: T6,
    N after: T6,
})
// archive-region-end
;
// archive-region: snapshots/codex_usage_occurrence.rs
crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::durable_struct!(UiTuple {
    N last: UsageTotals,
    N total: UsageTotals,
    N last_t6: T6,
    N total_t6: T6,
})
// archive-region-end
;
// archive-region: snapshots/codex_usage_occurrence.rs
crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::durable_struct!(BoundTurn {
    L id: String,
    N native: bool,
    N ui_published: bool,
    N staged_events: u64,
    D pending: OwnedMap<(String, RowKey), PendingRow>,
})
// archive-region-end
;
// archive-region: snapshots/codex_usage_occurrence.rs
crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::durable_struct!(PendingRow {
    U selector_context: BTreeMap<String, String>,
    U selector_sources: BTreeMap<String, String>,
    N usage: UsageTotals,
    N events: u64,
    N first_activity_at: String,
    N last_activity_at: String,
})
// archive-region-end
;
// archive-region: snapshots/codex_usage_occurrence.rs
crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::durable_struct!(OccurrenceCounters {
    N native_counted: u64,
    N native_not_authority: u64,
    N native_restated: u64,
    N native_inside_holed_coverage: u64,
    N native_inside_holed_coverage_usage: T6,
    N native_chain_gap: u64,
    N native_chain_overlap: u64,
    N native_chain_overlap_covered: T6,
    N native_epoch_reset: u64,
    N native_conflict: u64,
    N native_outside_open_turn: u64,
    N native_outside_open_turn_usage: T6,
    N native_after_turn_closed: u64,
    N native_after_turn_closed_usage: T6,
    N native_after_ui_flush: u64,
    N native_after_ui_flush_usage: T6,
    N ui_equal_total_repeat: u64,
    N ui_equal_total_repeat_usage: T6,
    N ui_in_native_turn_not_counted: u64,
    N ui_in_native_turn_not_counted_usage: T6,
    N ui_in_unbound_span: u64,
    N v2_cumulative_base_uncounted: u64,
    N v2_cumulative_base_uncounted_usage: T6,
    N turn_closure_mismatch: u64,
    N turn_reopened: u64,
    N closed_filter_hit_unconfirmed: u64,
    N closed_filter_hit_unconfirmed_native_usage: T6,
    N pending_overflow_flushes: u64,
})
// archive-region-end
;
// archive-region: snapshots/compaction_events.rs
crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::durable_enum!(ClaudeCompactionTrigger {
    0 => Auto,
    1 => Manual,
    2 => Idle,
})
// archive-region-end
;
// archive-region: snapshots/compaction_events.rs
crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::durable_struct!(CodexCompactionSize {
    N before: Option<NonZeroU64>,
    N after: Option<NonZeroU64>,
})
// archive-region-end
;
// archive-region: snapshots/compaction_events.rs
crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::durable_struct!(CodexCompactionSizes {
    N entries: Vec<(String, CodexCompactionSize)>,
    N pending_after: bool,
})
// archive-region-end
;
// archive-region: snapshots/context_curve.rs
crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::durable_struct!(ContextCurveCandidateBoundary {
    N observed_at: Option<String>,
    N point_count_before: u64,
})
// archive-region-end
;
// archive-region: snapshots/context_curve.rs
crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::durable_struct!(ContextCurveCandidatePoint {
    N observed_at: Option<String>,
    N effective_input_tokens: u64,
    U model: Option<String>,
    N context_window_tokens: Option<u64>,
})
// archive-region-end
;
// archive-region: snapshots/local_context_points.rs
crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::durable_struct!(LocalContextPoint {
    N at_unix_seconds: u32,
    N prompt_tokens: u32,
})
// archive-region-end
;
// archive-region: snapshots/local_context_points.rs
crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::durable_struct!(LocalContextPoints {
    N points: Vec<LocalContextPoint>,
})
// archive-region-end
;
// archive-region: snapshots/sampled_jsonl.rs
crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::durable_struct!(CachedJsonlReduction {
    D accumulator: SnapshotAccumulator,
    D report: JsonlReadReport,
    N recognized_usage_drop_count: usize,
    N positive_recognized_usage_count: usize,
    N positive_usage_evidence: bool,
})
// archive-region-end
;
impl CachedJsonlReduction {
// archive-region: snapshots/sampled_jsonl.rs
fn source(&self) -> SnapshotSource {
        self.accumulator.source
    }
// archive-region-end
}
// archive-region: snapshots/sampled_jsonl/durable.rs
const HEAD_BOUND: u64 = 1024 * 1024;
// archive-region-end
// archive-region: snapshots/sampled_jsonl/durable.rs
const NAMED_LINES: usize = 4;

/// Digests (`H`) of the re-derived values. `None`: the field is empty.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Rederive {
    first_prompt: Option<[u8; 32]>,
    workspace: Option<[u8; 32]>,
    agent_label: Option<[u8; 32]>,
    session_start: Option<[u8; 32]>,
    title: Option<[u8; 32]>,
}
crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::durable_struct!(Rederive {
    H first_prompt: Option<[u8; 32]>,
    H workspace: Option<[u8; 32]>,
    H agent_label: Option<[u8; 32]>,
    H session_start: Option<[u8; 32]>,
    H title: Option<[u8; 32]>,
})
// archive-region-end
;
// archive-region: snapshots/sampled_jsonl/durable.rs
fn digest(
    domain: &str,
    put: impl FnOnce(&mut Enc) -> Result<(), Refuse>,
) -> Result<[u8; 32], Refuse> {
    let mut e = Enc::hash(domain);
    put(&mut e)?;
    Ok(e.finish_hash())
}

fn first_prompt_digest(acc: &SnapshotAccumulator) -> Result<[u8; 32], Refuse> {
    digest("ottto-dt-rederive:first_prompt:v1", |e| {
        acc.first_prompt_material.put(e)?;
        acc.first_prompt_title.put(e)
    })
}

fn workspace_digest(acc: &SnapshotAccumulator) -> Result<[u8; 32], Refuse> {
    digest("ottto-dt-rederive:workspace:v1", |e| {
        acc.workspace_path.put(e)
    })
}

fn agent_label_digest(acc: &SnapshotAccumulator) -> Result<[u8; 32], Refuse> {
    digest("ottto-dt-rederive:agent_label:v1", |e| {
        acc.codex_agent_label.put(e)
    })
}

fn title_digest(acc: &SnapshotAccumulator) -> Result<[u8; 32], Refuse> {
    digest("ottto-dt-rederive:title:v1", |e| acc.title.put(e))
}
// archive-region-end
// archive-region: snapshots/sampled_jsonl/durable.rs
fn allowlist_digest(source: SnapshotSource) -> [u8; 32] {
    let mut shape = Shape::default();
    shape.push("ottto-dt-reduction:v1");
    shape.push(source.api_slug());
    shape.push(&format!(
        "head_bound={HEAD_BOUND};named_lines={NAMED_LINES}"
    ));
    CachedJsonlReduction::shape(&mut shape);
    Rederive::shape(&mut shape);
    shape.digest()
}
// archive-region-end
// archive-region: snapshots/sampled_jsonl/durable.rs
fn head_mark(mark: Option<u64>, field: &'static str) -> Result<u64, Refuse> {
    mark.filter(|end| *end <= HEAD_BOUND)
        .ok_or(Refuse::NotRederivable(field))
}

fn rederive_digests(acc: &SnapshotAccumulator, line_cap: u64) -> Result<Rederive, Refuse> {
    let marks = acc.durable_marks;
    let mut out = Rederive::default();
    if acc.first_prompt_material.is_some() || acc.first_prompt_title.is_some() {
        head_mark(
            marks.first_prompt,
            "SnapshotAccumulator.first_prompt_material",
        )?;
        out.first_prompt = Some(first_prompt_digest(acc)?);
    }
    if acc.workspace_path.is_some() {
        head_mark(marks.workspace, "SnapshotAccumulator.workspace_path")?;
        out.workspace = Some(workspace_digest(acc)?);
    }
    if acc.codex_agent_label.is_some() {
        head_mark(marks.agent_label, "SnapshotAccumulator.codex_agent_label")?;
        out.agent_label = Some(agent_label_digest(acc)?);
    }
    out.session_start = acc
        .session_start
        .durable_content_digest(HEAD_BOUND)?
        .map(|(digest, _)| digest);
    if acc.title.is_some() {
        marks
            .title_line
            .filter(|(_, len)| *len <= line_cap)
            .ok_or(Refuse::NotRederivable("SnapshotAccumulator.title"))?;
        out.title = Some(title_digest(acc)?);
    }
    Ok(out)
}
// archive-region-end
// archive-region: snapshots/sampled_jsonl/durable.rs
fn encode(
    reduction: &CachedJsonlReduction,
    limit: usize,
    line_cap: u64,
) -> Result<Vec<u8>, Refuse> {
    let acc = &reduction.accumulator;
    if !matches!(
        acc.source,
        SnapshotSource::ClaudeCode | SnapshotSource::Codex
    ) {
        return Err(Refuse::NotRederivable("SnapshotAccumulator.source"));
    }
    let rederive = rederive_digests(acc, line_cap)?;
    let mut e = Enc::bytes(limit);
    reduction.put(&mut e)?;
    rederive.put(&mut e)?;
    Ok(e.into_bytes())
}
// archive-region-end
// archive-region: snapshots/sampled_jsonl/durable.rs
fn verify(body: &[u8]) -> Result<(), Corrupt> {
    let mut d = Dec::new(body);
    CachedJsonlReduction::verify(&mut d)?;
    Rederive::verify(&mut d)?;
    d.finish()
}
// archive-region-end
// archive-region: snapshots/session_start.rs
const WINDOW_REQUESTS: usize = 3;
// archive-region-end
// archive-region: snapshots/session_start.rs
const PARTS: usize = 11;
// archive-region-end
// archive-region: snapshots/session_start.rs
crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::durable_struct!(OpeningRequest {
    N context_tokens: u64,
    N uncached_input_tokens: u64,
    N cache_read_tokens: u64,
    N cache_write_5m_tokens: Option<u64>,
    N cache_write_1h_tokens: Option<u64>,
    N parts_reconcile: bool,
    N output_tokens: u64,
})
// archive-region-end
;
// archive-region: snapshots/session_start.rs
crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::durable_struct!(ClaudeBlob {
    N parts: [u64; PARTS],
    N unmeasurable: bool,
    // A reversible rolling digest of instruction text (F1): content, never
    // stored; re-derived with the opening content and hash-verified.
    X config_digest: Option<ConfigDigest>,
})
// archive-region-end
;
// archive-region: snapshots/session_start.rs
crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::durable_struct!(ConfigDigest {
    X a: u64,
    X b: u64,
    X len: u64,
})
// archive-region-end
;
// archive-region: snapshots/session_start.rs
crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::durable_struct!(key ClaudeRequestKey(H digest: [u8; 32]))
// archive-region-end
;
// archive-region: snapshots/session_start.rs
crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::durable_struct!(key OpeningCallId { L id: String })
// archive-region-end
;
// archive-region: snapshots/session_start.rs
crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::durable_struct!(OpeningCall {
    N response: u8,
    U tool: String,
    N candidates: u64,
    E files: Vec<String>,
    N answered: bool,
    N truncated: bool,
})
// archive-region-end
;
// archive-region: snapshots/session_start.rs
crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::durable_struct!(OpeningFileState {
    N ordinal: u64,
    U tool: String,
    X repo_path: Option<String>,
    N instruction_segments: u8,
    N reads: [u64; 2],
    N chars: [u64; 2],
    N client_loaded: [bool; 2],
    N truncated: [bool; 2],
})
// archive-region-end
;
// archive-region: snapshots/session_start.rs
crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::durable_struct!(SessionStartState {
    U client_version: Option<String>,
    N user_turns: u8,
    N inherited_prefix: bool,
    N frozen: bool,
    N requests: [Option<OpeningRequest>; WINDOW_REQUESTS],
    N codex_requests: u8,
    N response_tool_calls: [u64; 2],
    N truncated_outputs: [u64; 2],
    N parts: [u64; PARTS],
    N parts_closed: bool,
    N parts_unmeasurable: bool,
    N codex_tools_logged: bool,
    X config_digest: Option<ConfigDigest>,
    D claude_shape: Option<(ClaudeRequestKey, u64, u64)>,
    D claude_blobs: BTreeMap<ClaudeRequestKey, ClaudeBlob>,
    N memory_units: Option<u64>,
    N instruction_load_cut: Option<bool>,
    X instructions: Option<String>,
    N instructions_capped: bool,
    X codex_prelude: Option<Box<CodexPreludeParser>>,
    D calls: BTreeMap<OpeningCallId, OpeningCall>,
    L last_codex_call: Option<String>,
    X files: BTreeMap<String, OpeningFileState>,
    N files_untracked: [u64; 2],
    N held_bytes: usize,
    N shell_moved: bool,
    N collapsed_requests: bool,
    N content_end: Option<u64>,
})
// archive-region-end
;
impl SessionStartState {
// archive-region: snapshots/session_start.rs
fn durable_content_digest(
        &self,
        bound: u64,
    ) -> Result<Option<([u8; 32], u64)>, crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::Refuse> {
        use crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::Refuse;
        if self.instructions.is_none()
            && self.codex_prelude.is_none()
            && self.files.is_empty()
            && self.config_digest.is_none()
            && self
                .claude_blobs
                .values()
                .all(|blob| blob.config_digest.is_none())
        {
            return Ok(None);
        }
        let end = self
            .content_end
            .filter(|end| *end <= bound)
            .ok_or(Refuse::NotRederivable("SessionStartState.content_end"))?;
        Ok(Some((self.durable_content_hash()?, end)))
    }
// archive-region-end
}
impl SessionStartState {
// archive-region: snapshots/session_start.rs
fn durable_content_hash(
        &self,
    ) -> Result<[u8; 32], crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::Refuse> {
        use crate::snapshots::sampled_scan::durable_tail::transition_seed::archived_writers::w_53d05a43::durable_tail_codec::{Durable, Enc};
        let mut e = Enc::hash("ottto-dt-rederive:session_start:v2");
        self.instructions.put(&mut e)?;
        self.codex_prelude.put(&mut e)?;
        self.files.put(&mut e)?;
        self.config_digest.put(&mut e)?;
        // The blobs' own digests, by key (their keys and parts are stored).
        e.varint(self.claude_blobs.len() as u64)?;
        for blob in self.claude_blobs.values() {
            blob.config_digest.put(&mut e)?;
        }
        Ok(e.finish_hash())
    }
// archive-region-end
}

    pub(super) fn archived_source(source_tag: u8) -> Result<SnapshotSource, String> {
        match source_tag {
            1 => Ok(SnapshotSource::ClaudeCode),
            2 => Ok(SnapshotSource::Codex),
            other => Err(format!("no v1 body source for tag {other}")),
        }
    }

    /// `allowlist_digest`'s walk, stopping before the digest.
    pub(super) fn archived_shape_text(source: SnapshotSource) -> String {
        let mut shape = Shape::default();
        shape.push("ottto-dt-reduction:v1");
        shape.push(source.api_slug());
        shape.push(&format!("head_bound={HEAD_BOUND};named_lines={NAMED_LINES}"));
        CachedJsonlReduction::shape(&mut shape);
        Rederive::shape(&mut shape);
        shape.archived_text().to_string()
    }

    /// The digests `rederive_digests` stores for `content`, through the copied
    /// functions. `session_start` stays empty: its state is not in `content`.
    pub(super) fn archived_content_digests(
        base: &[u8],
        content: &super::ArchivedContent,
    ) -> Result<super::ContentDigests, String> {
        let mut d = Dec::new(base);
        let mut reduction =
            CachedJsonlReduction::take(&mut d).map_err(|_| "base body refused".to_string())?;
        let acc = &mut reduction.accumulator;
        acc.title = content.title.clone();
        acc.first_prompt_title = content.first_prompt_title.clone();
        acc.first_prompt_material = content.first_prompt_material.clone();
        acc.workspace_path = content.workspace_path.clone();
        acc.codex_agent_label = content.agent_label.clone();
        // Position marks only gate refusal, and these digests never read them.
        acc.durable_marks = DurableMarks {
            first_prompt: Some(0),
            workspace: Some(0),
            agent_label: Some(0),
            title_line: Some((0, 0)),
            unknown: false,
        };
        let rederive = rederive_digests(acc, 0).map_err(|refuse| format!("refused: {refuse:?}"))?;
        Ok(super::ContentDigests {
            first_prompt: rederive.first_prompt,
            workspace: rederive.workspace,
            agent_label: rederive.agent_label,
            title: rederive.title,
        })
    }

    /// Re-emit a body through this writer's own field walk. `encode` is not the
    /// entry point because the content digests need live fields that a record
    /// never carries, so the stored `Rederive` is written back as it was and
    /// `archived_content_digests` checks those digests separately.
    /// Bytes this writer could not have produced refuse here.
    pub(super) fn archived_rewrite(source: SnapshotSource, body: &[u8]) -> Result<Vec<u8>, String> {
        let mut d = Dec::new(body);
        let corrupt = |_| "body is not this writer's wire".to_string();
        let reduction = CachedJsonlReduction::take(&mut d).map_err(corrupt)?;
        let rederive = Rederive::take(&mut d).map_err(corrupt)?;
        d.finish().map_err(corrupt)?;
        if reduction.accumulator.source != source {
            return Err("body belongs to another source".to_string());
        }
        let mut e = Enc::bytes(body.len());
        let refused = |refuse| format!("refused: {refuse:?}");
        reduction.put(&mut e).map_err(refused)?;
        rederive.put(&mut e).map_err(refused)?;
        Ok(e.into_bytes())
    }
}
