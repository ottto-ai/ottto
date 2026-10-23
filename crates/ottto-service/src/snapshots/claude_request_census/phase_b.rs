//! Optional shadow machinery. No switch implies no new retained evidence.
use super::*;

pub(super) fn enabled() -> bool {
    #[cfg(test)]
    {
        TEST_SHADOW.with(|mode| mode.get())
    }
    #[cfg(not(test))]
    {
        static ENABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
        *ENABLED.get_or_init(|| {
            std::env::var_os("OTTTO_CLAUDE_D2_SHADOW").is_some_and(|value| value == "1")
        })
    }
}
#[cfg(test)]
thread_local! { static TEST_SHADOW: std::cell::Cell<bool> = const { std::cell::Cell::new(true) }; }
#[cfg(test)]
pub(super) struct ShadowMode(pub(super) bool);
#[cfg(test)]
impl ShadowMode {
    pub(super) fn set(enabled: bool) -> Self {
        Self(TEST_SHADOW.with(|mode| mode.replace(enabled)))
    }
}
#[cfg(test)]
impl Drop for ShadowMode {
    fn drop(&mut self) {
        TEST_SHADOW.with(|mode| mode.set(self.0));
    }
}

const CHUNK_HASHES: usize = 256;
/// Immutable bounded chunks form a persistent suffix. A checkpoint clone is O(1),
/// and reclaim advances the head without copying any retained hash. A partial
/// first chunk retains at most 255 unused hashes; resident accounting includes it.
#[derive(Debug, Clone)]
pub(super) struct SafetyHashes {
    head: Arc<HashChunk>,
    start: usize,
    len: usize,
}
#[derive(Debug)]
struct HashChunk {
    hashes: Box<[u64]>,
    next: Option<Arc<HashChunk>>,
    resident: usize,
}
impl Drop for HashChunk {
    fn drop(&mut self) {
        // Large single-record buffers must not recursively drop thousands of nodes.
        let mut next = self.next.take();
        while let Some(node) = next {
            match Arc::try_unwrap(node) {
                Ok(mut owned) => next = owned.next.take(),
                Err(_) => break,
            }
        }
    }
}
impl PartialEq for SafetyHashes {
    fn eq(&self, other: &Self) -> bool {
        self.len == other.len && self.iter().eq(other.iter())
    }
}
impl Eq for SafetyHashes {}
impl SafetyHashes {
    pub(super) fn from_slice(hashes: &[u64]) -> Option<Self> {
        let mut next: Option<Arc<HashChunk>> = None;
        for chunk in hashes.chunks(CHUNK_HASHES).rev() {
            let resident = std::mem::size_of::<HashChunk>()
                + 2 * std::mem::size_of::<usize>()
                + std::mem::size_of_val(chunk)
                + next.as_ref().map_or(0, |node| node.resident);
            next = Some(Arc::new(HashChunk {
                hashes: chunk.into(),
                next,
                resident,
            }));
        }
        next.map(|head| Self {
            head,
            start: 0,
            len: hashes.len(),
        })
    }
    pub(super) fn len(&self) -> usize {
        self.len
    }
    pub(super) fn resident_bytes(&self) -> usize {
        self.head.resident
    }
    pub(super) fn iter(&self) -> HashIter<'_> {
        HashIter {
            current: &self.head.hashes[self.start..],
            next: self.head.next.as_deref(),
            remaining: self.len,
        }
    }
    pub(super) fn reclaim(&self, count: usize) -> Option<Self> {
        if count >= self.len {
            return None;
        }
        let mut result = self.clone();
        result.len -= count;
        let mut advance = count;
        while advance >= result.head.hashes.len() - result.start {
            advance -= result.head.hashes.len() - result.start;
            result.head = result.head.next.as_ref().expect("remaining suffix").clone();
            result.start = 0;
        }
        result.start += advance;
        Some(result)
    }
}
#[derive(Clone, Copy)]
pub(super) struct HashIter<'a> {
    current: &'a [u64],
    next: Option<&'a HashChunk>,
    remaining: usize,
}
impl<'a> HashIter<'a> {
    pub(super) fn slice(current: &'a [u64]) -> Self {
        Self {
            current,
            next: None,
            remaining: current.len(),
        }
    }
}
impl Iterator for HashIter<'_> {
    type Item = u64;
    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        while self.current.is_empty() {
            let node = self.next?;
            self.current = &node.hashes;
            self.next = node.next.as_deref();
        }
        let (first, rest) = self.current.split_first()?;
        self.current = rest;
        self.remaining -= 1;
        Some(*first)
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining, Some(self.remaining))
    }
}
impl ExactSizeIterator for HashIter<'_> {}

pub(super) struct SafetyBase64<'a>(pub(super) &'a SafetyHashes);
impl fmt::Display for SafetyBase64<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use base64::Engine;
        let mut hashes = self.0.iter();
        loop {
            let mut bytes = [0_u8; 24];
            let mut count = 0;
            for slot in bytes.chunks_exact_mut(8) {
                let Some(hash) = hashes.next() else {
                    break;
                };
                slot.copy_from_slice(&hash.to_be_bytes());
                count += 8;
            }
            if count == 0 {
                return Ok(());
            }
            let mut text = [0_u8; 32];
            let written = base64::engine::general_purpose::STANDARD
                .encode_slice(&bytes[..count], &mut text)
                .map_err(|_| fmt::Error)?;
            f.write_str(std::str::from_utf8(&text[..written]).map_err(|_| fmt::Error)?)?;
        }
    }
}
impl Serialize for SafetyBase64<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}
