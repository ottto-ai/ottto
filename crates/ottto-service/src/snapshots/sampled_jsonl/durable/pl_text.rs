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

    pub(in crate::snapshots::sampled_jsonl::durable) fn into_string(self) -> String {
        self.0
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

// The native sets remain Strings with their original normalization and cap.
// Only this record bridge admits them as <=33 bounded private label literals.
impl PlLiteral for std::collections::BTreeSet<String> {
    fn put_pl(&self, e: &mut Enc, path: &'static str) -> Result<(), Refuse> {
        validate_skill_labels(self, path)?;
        e.varint(self.len() as u64)?;
        for text in self {
            e.len_prefixed(text.as_bytes())?;
        }
        Ok(())
    }
    fn take_pl(d: &mut Dec<'_>) -> Result<Self, Corrupt> {
        let len = d.take_len()?;
        if len > 33 {
            return Err(Corrupt);
        }
        d.tree::<String, ()>(len)?;
        d.note_pl_labels(len);
        let mut out = Self::new();
        for _ in 0..len {
            let text = PlText::<96>::take(d)?.into_string();
            if !skill_label(&text)
                || out
                    .iter()
                    .any(|old: &String| old.eq_ignore_ascii_case(&text))
                || out.last().is_some_and(|old| old >= &text)
            {
                return Err(Corrupt);
            }
            out.insert(text);
        }
        Ok(out)
    }
    fn verify_pl(d: &mut Dec<'_>) -> Result<(), Corrupt> {
        let len = d.take_len()?;
        if len > 33 {
            return Err(Corrupt);
        }
        d.note_pl_labels(len);
        let mut previous: [Option<&str>; 33] = [None; 33];
        for i in 0..len {
            let text = d.bounded_text_bytes(96)?;
            if !skill_label(text)
                || previous[..i]
                    .iter()
                    .flatten()
                    .any(|old| old.eq_ignore_ascii_case(text))
                || i > 0 && previous[i - 1].is_some_and(|old| old >= text)
            {
                return Err(Corrupt);
            }
            previous[i] = Some(text);
        }
        Ok(())
    }
    fn shape_pl(s: &mut Shape) {
        s.push("PlSkillSet<33>");
        PlText::<96>::shape(s);
        s.push("directory-label-ascii:v1");
    }
}
fn skill_label(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= 96
        && text != "."
        && text != ".."
        && text
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-' | b'.' | b':'))
}
pub(in crate::snapshots::sampled_jsonl::durable) fn validate_skill_labels(
    set: &std::collections::BTreeSet<String>,
    path: &'static str,
) -> Result<(), Refuse> {
    if set.len() > 33
        || set.iter().any(|s| !skill_label(s))
        || set
            .iter()
            .enumerate()
            .any(|(i, s)| set.iter().take(i).any(|old| old.eq_ignore_ascii_case(s)))
    {
        return Err(Refuse::NonEmpty(
            if path == "SnapshotAccumulator.provider_skills" {
                "skill_label_out_of_bounds{set=provider}"
            } else {
                "skill_label_out_of_bounds{set=activity}"
            },
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Record {
        literal: PlText<4>,
    }
    crate::durable_tail_codec::durable_struct!(Record { PL literal: PlText<4> });

    /// [format] pl decode refuses over cap before allocating and never truncates.
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

    /// [format] pl roundtrip keeps exact bytes and debug reports only length.
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

    /// [format] pl decode charges exact bytes and reports budget refusal.
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

    /// [format] pl decode and verify refuse invalid utf8.
    #[test]
    fn pl_decode_and_verify_refuse_invalid_utf8() {
        let mut body = Enc::bytes(100);
        body.len_prefixed(&[0xff]).unwrap();
        let body = body.into_bytes();
        assert!(Record::take(&mut Dec::new(&body)).is_err());
        assert!(Record::verify(&mut Dec::new(&body)).is_err());
    }
}
