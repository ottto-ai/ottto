//! Dependency-free serde_ignored guard with observed serde field names.
//! Observed names let the opaque-value fallback recognize aliases and fields
//! omitted by skip_serializing_if without maintaining a second type schema.
use serde::de::{self, DeserializeSeed, EnumAccess, MapAccess, SeqAccess, VariantAccess, Visitor};
use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet},
    rc::Rc,
};
#[derive(Default)]
pub(super) struct Observed {
    pub fields: BTreeMap<Vec<String>, &'static [&'static str]>,
    pub opaque: BTreeSet<Vec<String>>,
    key: Option<String>,
}
struct Guard<T> {
    inner: T,
    observed: Rc<RefCell<Observed>>,
    path: Vec<String>,
    key: bool,
}
impl<T> Guard<T> {
    fn wrap<U>(&self, inner: U) -> Guard<U> {
        Guard {
            inner,
            observed: self.observed.clone(),
            path: self.path.clone(),
            key: self.key,
        }
    }
    fn child<U>(&self, inner: U, name: String) -> Guard<U> {
        let mut g = self.wrap(inner);
        g.path.push(name);
        g.key = false;
        g
    }
}
pub(super) fn deserialize<'de, T: de::Deserialize<'de>, D: de::Deserializer<'de>>(
    d: D,
) -> Result<(T, Observed), D::Error> {
    let observed = Rc::new(RefCell::new(Observed::default()));
    let value = T::deserialize(Guard {
        inner: d,
        observed: observed.clone(),
        path: Vec::new(),
        key: false,
    })?;
    let observed = Rc::try_unwrap(observed)
        .ok()
        .expect("serde guard released")
        .into_inner();
    Ok((value, observed))
}
impl<'de, D: de::Deserializer<'de>> de::Deserializer<'de> for Guard<D> {
    type Error = D::Error;
    fn deserialize_ignored_any<V: Visitor<'de>>(self, _: V) -> Result<V::Value, D::Error> {
        Err(de::Error::custom("state_v2_ignored_field"))
    }
    fn is_human_readable(&self) -> bool {
        self.inner.is_human_readable()
    }
    fn deserialize_any<V: Visitor<'de>>(self, v: V) -> Result<V::Value, D::Error> {
        self.observed.borrow_mut().opaque.insert(self.path.clone());
        let v = self.wrap(v);
        self.inner.deserialize_any(v)
    }
    fn deserialize_bool<V: Visitor<'de>>(self, v: V) -> Result<V::Value, D::Error> {
        let v = self.wrap(v);
        self.inner.deserialize_bool(v)
    }
    fn deserialize_i8<V: Visitor<'de>>(self, v: V) -> Result<V::Value, D::Error> {
        let v = self.wrap(v);
        self.inner.deserialize_i8(v)
    }
    fn deserialize_i16<V: Visitor<'de>>(self, v: V) -> Result<V::Value, D::Error> {
        let v = self.wrap(v);
        self.inner.deserialize_i16(v)
    }
    fn deserialize_i32<V: Visitor<'de>>(self, v: V) -> Result<V::Value, D::Error> {
        let v = self.wrap(v);
        self.inner.deserialize_i32(v)
    }
    fn deserialize_i64<V: Visitor<'de>>(self, v: V) -> Result<V::Value, D::Error> {
        let v = self.wrap(v);
        self.inner.deserialize_i64(v)
    }
    fn deserialize_i128<V: Visitor<'de>>(self, v: V) -> Result<V::Value, D::Error> {
        let v = self.wrap(v);
        self.inner.deserialize_i128(v)
    }
    fn deserialize_u8<V: Visitor<'de>>(self, v: V) -> Result<V::Value, D::Error> {
        let v = self.wrap(v);
        self.inner.deserialize_u8(v)
    }
    fn deserialize_u16<V: Visitor<'de>>(self, v: V) -> Result<V::Value, D::Error> {
        let v = self.wrap(v);
        self.inner.deserialize_u16(v)
    }
    fn deserialize_u32<V: Visitor<'de>>(self, v: V) -> Result<V::Value, D::Error> {
        let v = self.wrap(v);
        self.inner.deserialize_u32(v)
    }
    fn deserialize_u64<V: Visitor<'de>>(self, v: V) -> Result<V::Value, D::Error> {
        let v = self.wrap(v);
        self.inner.deserialize_u64(v)
    }
    fn deserialize_u128<V: Visitor<'de>>(self, v: V) -> Result<V::Value, D::Error> {
        let v = self.wrap(v);
        self.inner.deserialize_u128(v)
    }
    fn deserialize_f32<V: Visitor<'de>>(self, v: V) -> Result<V::Value, D::Error> {
        let v = self.wrap(v);
        self.inner.deserialize_f32(v)
    }
    fn deserialize_f64<V: Visitor<'de>>(self, v: V) -> Result<V::Value, D::Error> {
        let v = self.wrap(v);
        self.inner.deserialize_f64(v)
    }
    fn deserialize_char<V: Visitor<'de>>(self, v: V) -> Result<V::Value, D::Error> {
        let v = self.wrap(v);
        self.inner.deserialize_char(v)
    }
    fn deserialize_str<V: Visitor<'de>>(self, v: V) -> Result<V::Value, D::Error> {
        let v = self.wrap(v);
        self.inner.deserialize_str(v)
    }
    fn deserialize_string<V: Visitor<'de>>(self, v: V) -> Result<V::Value, D::Error> {
        let v = self.wrap(v);
        self.inner.deserialize_string(v)
    }
    fn deserialize_bytes<V: Visitor<'de>>(self, v: V) -> Result<V::Value, D::Error> {
        let v = self.wrap(v);
        self.inner.deserialize_bytes(v)
    }
    fn deserialize_byte_buf<V: Visitor<'de>>(self, v: V) -> Result<V::Value, D::Error> {
        let v = self.wrap(v);
        self.inner.deserialize_byte_buf(v)
    }
    fn deserialize_option<V: Visitor<'de>>(self, v: V) -> Result<V::Value, D::Error> {
        let v = self.wrap(v);
        self.inner.deserialize_option(v)
    }
    fn deserialize_unit<V: Visitor<'de>>(self, v: V) -> Result<V::Value, D::Error> {
        let v = self.wrap(v);
        self.inner.deserialize_unit(v)
    }
    fn deserialize_unit_struct<V: Visitor<'de>>(
        self,
        name: &'static str,
        v: V,
    ) -> Result<V::Value, D::Error> {
        let v = self.wrap(v);
        self.inner.deserialize_unit_struct(name, v)
    }
    fn deserialize_newtype_struct<V: Visitor<'de>>(
        self,
        name: &'static str,
        v: V,
    ) -> Result<V::Value, D::Error> {
        if name == "$serde_json::private::RawValue" {
            self.observed.borrow_mut().opaque.insert(self.path.clone());
        }
        let v = self.wrap(v);
        self.inner.deserialize_newtype_struct(name, v)
    }
    fn deserialize_seq<V: Visitor<'de>>(self, v: V) -> Result<V::Value, D::Error> {
        let v = self.wrap(v);
        self.inner.deserialize_seq(v)
    }
    fn deserialize_tuple<V: Visitor<'de>>(self, len: usize, v: V) -> Result<V::Value, D::Error> {
        let v = self.wrap(v);
        self.inner.deserialize_tuple(len, v)
    }
    fn deserialize_tuple_struct<V: Visitor<'de>>(
        self,
        name: &'static str,
        len: usize,
        v: V,
    ) -> Result<V::Value, D::Error> {
        let v = self.wrap(v);
        self.inner.deserialize_tuple_struct(name, len, v)
    }
    fn deserialize_map<V: Visitor<'de>>(self, v: V) -> Result<V::Value, D::Error> {
        let v = self.wrap(v);
        self.inner.deserialize_map(v)
    }
    fn deserialize_struct<V: Visitor<'de>>(
        self,
        name: &'static str,
        fields: &'static [&'static str],
        v: V,
    ) -> Result<V::Value, D::Error> {
        self.observed
            .borrow_mut()
            .fields
            .insert(self.path.clone(), fields);
        let v = self.wrap(v);
        self.inner.deserialize_struct(name, fields, v)
    }
    fn deserialize_enum<V: Visitor<'de>>(
        self,
        name: &'static str,
        variants: &'static [&'static str],
        v: V,
    ) -> Result<V::Value, D::Error> {
        let v = self.wrap(v);
        self.inner.deserialize_enum(name, variants, v)
    }
    fn deserialize_identifier<V: Visitor<'de>>(self, v: V) -> Result<V::Value, D::Error> {
        let v = self.wrap(v);
        self.inner.deserialize_identifier(v)
    }
}
impl<'de, S: DeserializeSeed<'de>> DeserializeSeed<'de> for Guard<S> {
    type Value = S::Value;
    fn deserialize<D: de::Deserializer<'de>>(self, d: D) -> Result<S::Value, D::Error> {
        let d = self.wrap(d);
        self.inner.deserialize(d)
    }
}
impl<'de, V: Visitor<'de>> Visitor<'de> for Guard<V> {
    type Value = V::Value;
    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.inner.expecting(f)
    }
    fn visit_bool<E: de::Error>(self, v: bool) -> Result<V::Value, E> {
        if self.key {
            self.observed.borrow_mut().key = Some(v.to_string());
        }
        self.inner.visit_bool(v)
    }
    fn visit_i8<E: de::Error>(self, v: i8) -> Result<V::Value, E> {
        if self.key {
            self.observed.borrow_mut().key = Some(v.to_string());
        }
        self.inner.visit_i8(v)
    }
    fn visit_i16<E: de::Error>(self, v: i16) -> Result<V::Value, E> {
        if self.key {
            self.observed.borrow_mut().key = Some(v.to_string());
        }
        self.inner.visit_i16(v)
    }
    fn visit_i32<E: de::Error>(self, v: i32) -> Result<V::Value, E> {
        if self.key {
            self.observed.borrow_mut().key = Some(v.to_string());
        }
        self.inner.visit_i32(v)
    }
    fn visit_i64<E: de::Error>(self, v: i64) -> Result<V::Value, E> {
        if self.key {
            self.observed.borrow_mut().key = Some(v.to_string());
        }
        self.inner.visit_i64(v)
    }
    fn visit_i128<E: de::Error>(self, v: i128) -> Result<V::Value, E> {
        if self.key {
            self.observed.borrow_mut().key = Some(v.to_string());
        }
        self.inner.visit_i128(v)
    }
    fn visit_u8<E: de::Error>(self, v: u8) -> Result<V::Value, E> {
        if self.key {
            self.observed.borrow_mut().key = Some(v.to_string());
        }
        self.inner.visit_u8(v)
    }
    fn visit_u16<E: de::Error>(self, v: u16) -> Result<V::Value, E> {
        if self.key {
            self.observed.borrow_mut().key = Some(v.to_string());
        }
        self.inner.visit_u16(v)
    }
    fn visit_u32<E: de::Error>(self, v: u32) -> Result<V::Value, E> {
        if self.key {
            self.observed.borrow_mut().key = Some(v.to_string());
        }
        self.inner.visit_u32(v)
    }
    fn visit_u64<E: de::Error>(self, v: u64) -> Result<V::Value, E> {
        if self.key {
            self.observed.borrow_mut().key = Some(v.to_string());
        }
        self.inner.visit_u64(v)
    }
    fn visit_u128<E: de::Error>(self, v: u128) -> Result<V::Value, E> {
        if self.key {
            self.observed.borrow_mut().key = Some(v.to_string());
        }
        self.inner.visit_u128(v)
    }
    fn visit_f32<E: de::Error>(self, v: f32) -> Result<V::Value, E> {
        if self.key {
            self.observed.borrow_mut().key = Some(v.to_string());
        }
        self.inner.visit_f32(v)
    }
    fn visit_f64<E: de::Error>(self, v: f64) -> Result<V::Value, E> {
        if self.key {
            self.observed.borrow_mut().key = Some(v.to_string());
        }
        self.inner.visit_f64(v)
    }
    fn visit_char<E: de::Error>(self, v: char) -> Result<V::Value, E> {
        if self.key {
            self.observed.borrow_mut().key = Some(v.to_string());
        }
        self.inner.visit_char(v)
    }
    fn visit_str<E: de::Error>(self, v: &str) -> Result<V::Value, E> {
        if self.key {
            self.observed.borrow_mut().key = Some(v.to_string());
        }
        self.inner.visit_str(v)
    }
    fn visit_borrowed_str<E: de::Error>(self, v: &'de str) -> Result<V::Value, E> {
        if self.key {
            self.observed.borrow_mut().key = Some(v.to_string());
        }
        self.inner.visit_borrowed_str(v)
    }
    fn visit_string<E: de::Error>(self, v: String) -> Result<V::Value, E> {
        if self.key {
            self.observed.borrow_mut().key = Some(v.to_string());
        }
        self.inner.visit_string(v)
    }
    fn visit_bytes<E: de::Error>(self, v: &[u8]) -> Result<V::Value, E> {
        self.inner.visit_bytes(v)
    }
    fn visit_borrowed_bytes<E: de::Error>(self, v: &'de [u8]) -> Result<V::Value, E> {
        self.inner.visit_borrowed_bytes(v)
    }
    fn visit_byte_buf<E: de::Error>(self, v: Vec<u8>) -> Result<V::Value, E> {
        self.inner.visit_byte_buf(v)
    }
    fn visit_unit<E: de::Error>(self) -> Result<V::Value, E> {
        self.inner.visit_unit()
    }
    fn visit_none<E: de::Error>(self) -> Result<V::Value, E> {
        self.inner.visit_none()
    }
    fn visit_some<D: de::Deserializer<'de>>(self, d: D) -> Result<V::Value, D::Error> {
        let d = self.wrap(d);
        self.inner.visit_some(d)
    }
    fn visit_newtype_struct<D: de::Deserializer<'de>>(self, d: D) -> Result<V::Value, D::Error> {
        let d = self.wrap(d);
        self.inner.visit_newtype_struct(d)
    }
    fn visit_map<A: MapAccess<'de>>(self, a: A) -> Result<V::Value, A::Error> {
        let a = self.wrap(a);
        self.inner.visit_map(a)
    }
    fn visit_seq<A: SeqAccess<'de>>(self, a: A) -> Result<V::Value, A::Error> {
        let a = Sequence {
            guard: self.wrap(a),
            index: 0,
        };
        self.inner.visit_seq(a)
    }
    fn visit_enum<A: EnumAccess<'de>>(self, a: A) -> Result<V::Value, A::Error> {
        let a = self.wrap(a);
        self.inner.visit_enum(a)
    }
}
struct Sequence<A> {
    guard: Guard<A>,
    index: usize,
}
impl<'de, A: SeqAccess<'de>> SeqAccess<'de> for Sequence<A> {
    type Error = A::Error;
    fn next_element_seed<S: DeserializeSeed<'de>>(
        &mut self,
        s: S,
    ) -> Result<Option<S::Value>, A::Error> {
        let s = self.guard.child(s, self.index.to_string());
        self.index += 1;
        self.guard.inner.next_element_seed(s)
    }
    fn size_hint(&self) -> Option<usize> {
        self.guard.inner.size_hint()
    }
}
impl<'de, A: MapAccess<'de>> MapAccess<'de> for Guard<A> {
    type Error = A::Error;
    fn next_key_seed<S: DeserializeSeed<'de>>(
        &mut self,
        s: S,
    ) -> Result<Option<S::Value>, A::Error> {
        self.observed.borrow_mut().key = None;
        let mut s = self.wrap(s);
        s.key = true;
        self.inner.next_key_seed(s)
    }
    fn next_value_seed<S: DeserializeSeed<'de>>(&mut self, s: S) -> Result<S::Value, A::Error> {
        let name = self.observed.borrow_mut().key.take().unwrap_or_default();
        let s = self.child(s, name);
        self.inner.next_value_seed(s)
    }
    fn size_hint(&self) -> Option<usize> {
        self.inner.size_hint()
    }
}
impl<'de, A: EnumAccess<'de>> EnumAccess<'de> for Guard<A> {
    type Error = A::Error;
    type Variant = Guard<A::Variant>;
    fn variant_seed<S: DeserializeSeed<'de>>(
        self,
        s: S,
    ) -> Result<(S::Value, Self::Variant), A::Error> {
        let seed = self.wrap(s);
        let observed = self.observed.clone();
        let path = self.path.clone();
        let (v, inner) = self.inner.variant_seed(seed)?;
        Ok((
            v,
            Guard {
                inner,
                observed,
                path,
                key: false,
            },
        ))
    }
}
impl<'de, A: VariantAccess<'de>> VariantAccess<'de> for Guard<A> {
    type Error = A::Error;
    fn unit_variant(self) -> Result<(), A::Error> {
        self.inner.unit_variant()
    }
    fn newtype_variant_seed<S: DeserializeSeed<'de>>(self, s: S) -> Result<S::Value, A::Error> {
        let s = self.wrap(s);
        self.inner.newtype_variant_seed(s)
    }
    fn tuple_variant<V: Visitor<'de>>(self, len: usize, v: V) -> Result<V::Value, A::Error> {
        let v = self.wrap(v);
        self.inner.tuple_variant(len, v)
    }
    fn struct_variant<V: Visitor<'de>>(
        self,
        f: &'static [&'static str],
        v: V,
    ) -> Result<V::Value, A::Error> {
        self.observed
            .borrow_mut()
            .fields
            .insert(self.path.clone(), f);
        let v = self.wrap(v);
        self.inner.struct_variant(f, v)
    }
}
