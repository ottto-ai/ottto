//! TODO(E1 r23): replace with the shared codec.
//!
//! Local stand-ins for the names E1's shared codec provides, so the Pi side
//! builds until it merges: `PlText`, `HmacKeyEpoch`, `current_hmac_key_epoch`,
//! the key-mismatch helper and the wire digest domain. On the swap, the `N`
//! class of the `PlText` fields in `durable_pi.rs` becomes `PL`.
use super::*;
use std::fmt;

/// `ottto-dt-rederive:pi_wire_prompt:v1`: the digest over the carried wire
/// values, kept where a Pi record would otherwise hold the shared first-prompt
/// digest.
pub(super) const WIRE_PROMPT_DOMAIN: &str = "ottto-dt-rederive:pi_wire_prompt:v1";

/// An uploaded literal of at most `CAP` bytes. No `Display`, and `Debug` prints
/// no content: it must never reach a log, a diagnostic or an error.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct PlText<const CAP: usize>(String);

impl<const CAP: usize> PlText<CAP> {
    /// `None` over the cap: an oversized value is refused, never truncated.
    pub(super) fn new(value: &str) -> Option<Self> {
        (value.len() <= CAP).then(|| Self(value.to_owned()))
    }
    /// The bytes as uploaded, for the same upload field only.
    pub(super) fn wire(&self) -> &str {
        &self.0
    }
}

impl<const CAP: usize> fmt::Debug for PlText<CAP> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PlText(redacted)")
    }
}

impl<const CAP: usize> crate::heap_layout_bound::HeapLayoutBound for PlText<CAP> {
    const STABLE_HEAP: bool = true;
    fn heap_bound(&self, c: &mut crate::heap_layout_bound::Counter) -> Option<()> {
        self.0.heap_bound(c)
    }
}

impl<const CAP: usize> Durable for PlText<CAP> {
    fn put(&self, e: &mut Enc) -> Result<(), Refuse> {
        if self.0.len() > CAP {
            return Err(Refuse::TooLarge);
        }
        self.0.put(e)
    }
    // The bound is checked before the value allocates or charges anything.
    fn take(d: &mut Dec<'_>) -> Result<Self, Corrupt> {
        if d.peek_len()? > CAP {
            return Err(Corrupt);
        }
        String::take(d).map(Self)
    }
    fn verify(d: &mut Dec<'_>) -> Result<(), Corrupt> {
        if d.peek_len()? > CAP {
            return Err(Corrupt);
        }
        String::verify(d)
    }
    fn shape(s: &mut Shape) {
        s.push(&format!("PlText;utf8;max_bytes={CAP}"));
    }
}

/// A domain-separated digest of the upload HMAC key, never the key.
pub(crate) type HmacKeyEpoch = [u8; 32];

/// The epoch of the key the upload HMAC uses, `None` without a key. Derived
/// from the checkpoint namespace, which is itself a digest of that key.
pub(crate) fn current_hmac_key_epoch(
    context: Option<&crate::session_attribution::SessionAttributionContext>,
) -> Option<HmacKeyEpoch> {
    context.map(|context| {
        let mut digest = Sha256::new();
        digest.update(b"ottto-dt:hmac-key-epoch:v1\0");
        digest.update(context.checkpoint_namespace().as_bytes());
        digest.finalize().into()
    })
}

/// A stored epoch that is not the current one. The caller drops the stored
/// first-prompt set, so a template id made under an old key is never uploaded.
pub(super) fn key_epoch_changed(
    stored: Option<HmacKeyEpoch>,
    current: Option<HmacKeyEpoch>,
) -> bool {
    stored != current
}
