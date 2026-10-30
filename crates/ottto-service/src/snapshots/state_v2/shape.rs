//! Allocation-bounded raw inventory BEFORE lenient decoding. It cannot grant
//! custody or fix a value: unsupported/unknown/malformed input pauses conversion.
use super::*;
use std::io::BufRead;
#[path = "shape_inventory.rs"]
mod inventory;

#[derive(Clone, Copy)]
pub(super) enum Rule {
    Scalar,
    Struct(&'static [(&'static str, &'static str)]),
    Map(&'static str),
    Unsupported,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Pause {
    Unknown,
    Malformed,
    Oversize,
    UnmappedMoney,
    Unsupported,
}
impl Pause {
    pub(super) fn label(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Malformed => "malformed",
            Self::Oversize => "oversize",
            Self::UnmappedMoney => "unmapped_money",
            Self::Unsupported => "unsupported_shape",
        }
    }
}
#[derive(Debug)]
struct Refusal(Pause);
impl std::fmt::Display for Refusal {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        out.write_str(self.0.label())
    }
}
impl std::error::Error for Refusal {}
fn refuse<T>(why: Pause) -> Result<T> {
    Err(Refusal(why).into())
}

struct Walk<R> {
    input: R,
    depth: u8,
}
impl<R: BufRead> Walk<R> {
    fn peek(&mut self) -> Result<Option<u8>> {
        Ok(self.input.fill_buf()?.first().copied())
    }
    fn byte(&mut self) -> Result<u8> {
        let b = self.peek()?.ok_or(Refusal(Pause::Malformed))?;
        self.input.consume(1);
        Ok(b)
    }
    fn spaces(&mut self) -> Result<()> {
        while self.peek()?.is_some_and(|b| b.is_ascii_whitespace()) {
            self.input.consume(1);
        }
        Ok(())
    }
    fn expect(&mut self, expected: u8) -> Result<()> {
        self.spaces()?;
        if self.byte()? != expected {
            return refuse(Pause::Malformed);
        }
        Ok(())
    }
    fn string(&mut self, capture: bool) -> Result<Option<String>> {
        self.expect(b'"')?;
        let mut raw = if capture { vec![b'"'] } else { Vec::new() };
        let mut escaped = false;
        let mut count = 0_u64;
        loop {
            let b = self.byte()?;
            count += 1;
            if count > if capture { 16 * 1024 } else { VALUE_BYTES } {
                return refuse(Pause::Oversize);
            }
            if capture {
                raw.push(b);
            }
            if b == b'"' && !escaped {
                break;
            }
            if b < 0x20 {
                return refuse(Pause::Malformed);
            }
            escaped = b == b'\\' && !escaped;
        }
        if capture {
            Ok(Some(
                serde_json::from_slice(&raw).map_err(|_| Refusal(Pause::Malformed))?,
            ))
        } else {
            Ok(None)
        }
    }
    fn scalar(&mut self) -> Result<()> {
        self.spaces()?;
        if self.peek()? == Some(b'"') {
            self.string(false)?;
            return Ok(());
        }
        let mut raw = Vec::with_capacity(32);
        while self
            .peek()?
            .is_some_and(|b| !b.is_ascii_whitespace() && !b",]}".contains(&b))
        {
            if raw.len() >= 128 {
                return refuse(Pause::Oversize);
            }
            raw.push(self.byte()?);
        }
        let value: serde_json::Value =
            serde_json::from_slice(&raw).map_err(|_| Refusal(Pause::Malformed))?;
        if value.is_object() || value.is_array() {
            return refuse(Pause::Unknown);
        }
        Ok(())
    }
    fn value(&mut self, typ: &'static str) -> Result<()> {
        self.spaces()?;
        if self.depth >= 64 {
            return refuse(Pause::Oversize);
        }
        self.depth += 1;
        let result = self.inner(typ);
        self.depth -= 1;
        result
    }
    fn inner(&mut self, typ: &'static str) -> Result<()> {
        if let Some(typ) = generic(typ, "Option") {
            return if self.peek()? == Some(b'n') {
                self.scalar()
            } else {
                self.inner(typ)
            };
        }
        for wrapper in ["Box", "Arc"] {
            if let Some(inner) = generic(typ, wrapper) {
                return self.inner(inner);
            }
        }
        if let Some(inner) = generic(typ, "BTreeMap") {
            let (_, value) = pair(inner).ok_or(Refusal(Pause::Unsupported))?;
            return self.object(None, Some(value));
        }
        for container in ["Vec", "VecDeque", "BTreeSet"] {
            if let Some(inner) = generic(typ, container) {
                return self.sequence(inner, None);
            }
        }
        if typ.starts_with('[') && typ.ends_with(']') {
            let inner = &typ[1..typ.len() - 1];
            if let Some((typ, len)) = inner.split_once(';') {
                let len = len
                    .parse::<usize>()
                    .map_err(|_| Refusal(Pause::Unsupported))?;
                return self.sequence(typ, Some(len));
            }
            return self.sequence(inner, None);
        }
        if typ.starts_with('(') && typ.ends_with(')') {
            return self.tuple(&typ[1..typ.len() - 1]);
        }
        let name = typ.rsplit("::").next().unwrap_or(typ);
        match inventory::named(name) {
            Some(Rule::Struct(fields)) => {
                if self.peek()? == Some(b'[') {
                    self.positional(name, fields)
                } else {
                    self.object(Some(fields), None)
                }
            }
            Some(Rule::Map(value)) => self.object(None, Some(value)),
            Some(Rule::Unsupported) => refuse(Pause::Unsupported),
            Some(Rule::Scalar) => self.scalar(),
            None if matches!(
                name,
                "String"
                    | "str"
                    | "bool"
                    | "u8"
                    | "u16"
                    | "u32"
                    | "u64"
                    | "u128"
                    | "i8"
                    | "i16"
                    | "i32"
                    | "i64"
                    | "i128"
                    | "usize"
                    | "f32"
                    | "f64"
                    | "IgnoredAny"
            ) =>
            {
                if matches!(self.peek()?, Some(b'{') | Some(b'[')) {
                    refuse(Pause::Unknown)
                } else {
                    self.scalar()
                }
            }
            // No recursive "any JSON" escape: an unknown custom decoder is a
            // conversion refusal, not authority to discard its future fields.
            None => refuse(Pause::Unsupported),
        }
    }
    fn object(
        &mut self,
        fields: Option<&'static [(&'static str, &'static str)]>,
        map_value: Option<&'static str>,
    ) -> Result<()> {
        self.expect(b'{')?;
        self.spaces()?;
        if self.peek()? == Some(b'}') {
            self.byte()?;
            return Ok(());
        }
        loop {
            let key = self.string(true)?.expect("captured key");
            self.expect(b':')?;
            // TODO(S1 cond-b): owning PRs add explicit ~lost/saturation and E2
            // copy-removal mappings. Pause conversion, never v1 collection.
            if key.starts_with('~') || key == "claude_copy_removals" {
                return refuse(Pause::UnmappedMoney);
            }
            let typ = if let Some(fields) = fields {
                field(fields, &key).ok_or(Refusal(Pause::Unknown))?
            } else {
                map_value.ok_or(Refusal(Pause::Unsupported))?
            };
            self.value(typ)?;
            self.spaces()?;
            match self.byte()? {
                b'}' => return Ok(()),
                b',' => {}
                _ => return refuse(Pause::Malformed),
            }
            self.spaces()?;
        }
    }
    fn sequence(&mut self, typ: &'static str, exact: Option<usize>) -> Result<()> {
        self.expect(b'[')?;
        self.spaces()?;
        let mut count = 0;
        if self.peek()? != Some(b']') {
            loop {
                if exact.is_some_and(|n| count >= n) {
                    return refuse(Pause::Unknown);
                }
                self.value(typ)?;
                count += 1;
                self.spaces()?;
                match self.peek()? {
                    Some(b']') => break,
                    Some(b',') => {
                        self.byte()?;
                    }
                    _ => return refuse(Pause::Malformed),
                }
            }
        }
        self.expect(b']')?;
        if exact.is_some_and(|n| count != n) {
            return refuse(Pause::Malformed);
        }
        Ok(())
    }
    fn tuple(&mut self, mut types: &'static str) -> Result<()> {
        self.expect(b'[')?;
        loop {
            let (typ, rest) = pair(types).unwrap_or((types, ""));
            if typ.is_empty() {
                break;
            }
            self.value(typ)?;
            if rest.is_empty() {
                break;
            }
            self.expect(b',')?;
            types = rest;
        }
        self.expect(b']')
    }
    fn positional(
        &mut self,
        name: &str,
        fields: &'static [(&'static str, &'static str)],
    ) -> Result<()> {
        self.expect(b'[')?;
        self.spaces()?;
        let mut pos = 0;
        if self.peek()? != Some(b']') {
            loop {
                let key = if name == "ScanIndex" {
                    super::super::lenient_decode::FIELDS
                        .get(pos)
                        .copied()
                        .ok_or(Refusal(Pause::Unknown))?
                } else {
                    fields
                        .get(pos)
                        .map(|(k, _)| *k)
                        .ok_or(Refusal(Pause::Unknown))?
                };
                self.value(field(fields, key).ok_or(Refusal(Pause::Unsupported))?)?;
                pos += 1;
                self.spaces()?;
                match self.peek()? {
                    Some(b']') => break,
                    Some(b',') => {
                        self.byte()?;
                    }
                    _ => return refuse(Pause::Malformed),
                }
            }
        }
        self.expect(b']')
    }
}
fn field(fields: &'static [(&'static str, &'static str)], key: &str) -> Option<&'static str> {
    for &(name, typ) in fields {
        if name == key {
            return Some(typ);
        }
        if name == "@flatten" {
            if let Some(Rule::Struct(inner)) = inventory::named(typ) {
                if let Some(typ) = field(inner, key) {
                    return Some(typ);
                }
            }
        }
    }
    None
}
fn generic(typ: &'static str, name: &str) -> Option<&'static str> {
    typ.strip_prefix(name)?.strip_prefix('<')?.strip_suffix('>')
}
fn pair(types: &'static str) -> Option<(&'static str, &'static str)> {
    let mut depth = 0;
    for (i, b) in types.bytes().enumerate() {
        match b {
            b'<' | b'[' | b'(' => depth += 1,
            b'>' | b']' | b')' => depth -= 1,
            b',' if depth == 0 => return Some((&types[..i], &types[i + 1..])),
            _ => {}
        }
    }
    None
}
pub(super) fn inventory(input: impl BufRead) -> std::result::Result<(), Pause> {
    let mut walk = Walk { input, depth: 0 };
    let result = walk.value("ScanIndex").and_then(|_| {
        walk.spaces()?;
        if walk.peek()?.is_some() {
            return refuse(Pause::Malformed);
        }
        Ok(())
    });
    result.map_err(|error| {
        error
            .downcast_ref::<Refusal>()
            .map_or(Pause::Malformed, |r| r.0)
    })
}

#[cfg(test)]
pub(super) fn assert_root_registry_for_test() {
    let Rule::Struct(fields) = inventory::named("ScanIndex").unwrap() else {
        panic!("root shape");
    };
    for name in super::super::lenient_decode::FIELDS {
        assert!(
            field(fields, name).is_some(),
            "unregistered root slot {name}"
        );
    }
}
