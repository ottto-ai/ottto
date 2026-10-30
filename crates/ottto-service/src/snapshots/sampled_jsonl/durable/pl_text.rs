//! Private local literals for the durable record codec. No serde or Display.
use crate::durable_tail_codec::{Corrupt, Dec, Durable, Enc, PlLiteral, Refuse, Shape};

/// A byte-bounded literal. Creating one does not authorize its persistence:
/// its field still needs an approved PL use and the current consent gate.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct PlText<const CAP: usize>(String);

impl<const CAP: usize> PlText<CAP> {
    pub(crate) fn new(text: String) -> Result<Self, Refuse> {
        if text.len() > CAP {
            return Err(Refuse::TooLarge);
        }
        Ok(Self(text))
    }

    /// Only the restore module can recover literal text. Callers outside it
    /// can encode a record or observe redacted Debug, never extract its text.
    pub(in crate::snapshots::sampled_jsonl::durable) fn as_str(&self) -> &str {
        &self.0
    }
}

impl<const CAP: usize> std::fmt::Debug for PlText<CAP> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PlText")
            .field("len", &self.0.len())
            .finish()
    }
}

impl<const CAP: usize> Durable for PlText<CAP> {
    fn put(&self, e: &mut Enc) -> Result<(), Refuse> {
        e.len_prefixed(self.0.as_bytes())
    }
    fn take(d: &mut Dec<'_>) -> Result<Self, Corrupt> {
        d.bounded_text(CAP).map(Self)
    }
    fn verify(d: &mut Dec<'_>) -> Result<(), Corrupt> {
        d.bounded_text_bytes(CAP).map(|_| ())
    }
    fn shape(s: &mut Shape) {
        s.push(&format!("PlText<{CAP}>"));
    }
}
impl<const CAP: usize> PlLiteral for PlText<CAP> {}
impl<const CAP: usize> crate::heap_layout_bound::HeapLayoutBound for PlText<CAP> {
    const STABLE_HEAP: bool = true;
    fn heap_bound(&self, c: &mut crate::heap_layout_bound::Counter) -> Option<()> {
        let Self(text) = self;
        crate::heap_layout_bound::HeapLayoutBound::heap_bound(text, c)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Record {
        literal: PlText<4>,
    }
    crate::durable_tail_codec::durable_struct!(Record { PL literal: PlText<4> });

    #[test]
    fn pl_decode_refuses_over_cap_before_allocating_and_never_truncates() {
        let mut encoded = Enc::bytes(100);
        encoded.len_prefixed(b"12345").unwrap();
        let encoded = encoded.into_bytes();
        let mut charged = 0;
        let mut credit = |n| {
            charged += n;
            true
        };
        let mut decoder = Dec::bounded(&encoded, &mut credit);
        assert!(Record::take(&mut decoder).is_err());
        assert_eq!(charged, 0);
        assert!(Record::verify(&mut Dec::new(&encoded)).is_err());
        assert!(PlText::<4>::new("12345".into()).is_err());
        assert!(PlText::<4>::new("ééé".into()).is_err());
    }

    #[test]
    fn pl_roundtrip_keeps_exact_bytes_and_debug_reports_only_length() {
        let record = Record {
            literal: PlText::new("éé".into()).unwrap(),
        };
        assert_eq!(format!("{:?}", record.literal), "PlText { len: 4 }");
        let body = Enc::count_write(100, |e| record.put(e)).unwrap();
        Record::verify(&mut Dec::new(&body)).unwrap();
        let mut decoder = Dec::new(&body);
        let decoded = Record::take(&mut decoder).unwrap();
        decoder.finish().unwrap();
        assert_eq!(decoded.literal.as_str(), "éé");
        let mut shape = Shape::default();
        Record::shape(&mut shape);
        assert!(shape.text().contains("PL literal;PlText<4>"));
    }

    #[test]
    fn pl_decode_charges_exact_bytes_and_reports_budget_refusal() {
        let body = [4, b'a', b'b', b'c', b'd'];
        let mut requested = 0;
        let mut credit = |n| {
            requested += n;
            false
        };
        let mut decoder = Dec::bounded(&body, &mut credit);
        let value = Record::take(&mut decoder);
        assert!(matches!(
            decoder.outcome(value),
            Err(crate::durable_tail_codec::DecodeFailure::Budget)
        ));
        assert_eq!(requested, 4);
    }

    #[test]
    fn pl_decode_and_verify_refuse_invalid_utf8() {
        let mut body = Enc::bytes(100);
        body.len_prefixed(&[0xff]).unwrap();
        let body = body.into_bytes();
        assert!(Record::take(&mut Dec::new(&body)).is_err());
        assert!(Record::verify(&mut Dec::new(&body)).is_err());
    }
}
