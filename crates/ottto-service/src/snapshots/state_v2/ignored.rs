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
/// Forwards each listed `deserialize_*` method through a wrapped visitor.
macro_rules! forward_deserialize {
    ($($name:ident($($arg:ident: $ty:ty),*);)*) => {$(
        fn $name<V: Visitor<'de>>(self, $($arg: $ty,)* v: V) -> Result<V::Value, D::Error> {
            let v = self.wrap(v);
            self.inner.$name($($arg,)* v)
        }
    )*};
}
/// Records a scalar map key, then forwards each listed `visit_*` method.
macro_rules! capture_key {
    ($($name:ident($ty:ty);)*) => {$(
        fn $name<E: de::Error>(self, v: $ty) -> Result<V::Value, E> {
            if self.key {
                self.observed.borrow_mut().key = Some(v.to_string());
            }
            self.inner.$name(v)
        }
    )*};
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
    forward_deserialize! {
        deserialize_bool();
        deserialize_i8();
        deserialize_i16();
        deserialize_i32();
        deserialize_i64();
        deserialize_i128();
        deserialize_u8();
        deserialize_u16();
        deserialize_u32();
        deserialize_u64();
        deserialize_u128();
        deserialize_f32();
        deserialize_f64();
        deserialize_char();
        deserialize_str();
        deserialize_string();
        deserialize_bytes();
        deserialize_byte_buf();
        deserialize_option();
        deserialize_unit();
        deserialize_unit_struct(name: &'static str);
        deserialize_seq();
        deserialize_tuple(len: usize);
        deserialize_tuple_struct(name: &'static str, len: usize);
        deserialize_map();
        deserialize_enum(name: &'static str, variants: &'static [&'static str]);
        deserialize_identifier();
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
    capture_key! {
        visit_bool(bool);
        visit_i8(i8);
        visit_i16(i16);
        visit_i32(i32);
        visit_i64(i64);
        visit_i128(i128);
        visit_u8(u8);
        visit_u16(u16);
        visit_u32(u32);
        visit_u64(u64);
        visit_u128(u128);
        visit_f32(f32);
        visit_f64(f64);
        visit_char(char);
        visit_str(&str);
        visit_borrowed_str(&'de str);
        visit_string(String);
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
