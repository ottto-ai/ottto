//! Copy-on-write state for `ScanIndex`, so a whole-index clone costs only the
//! values a pass goes on to write. Values keep plain-value semantics: a write
//! through `make_mut` never shows through another clone. The JSON is the bare
//! value's, byte for byte.
use crate::heap_layout_bound::{Counter, HeapLayoutBound};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::borrow::Borrow;
use std::collections::{btree_map, btree_set, BTreeMap, BTreeSet};
use std::fmt;
use std::iter::Map;
use std::mem::{align_of, size_of};
use std::ops::{Deref, Index, RangeBounds};
use std::sync::Arc;

/// One value held by pointer. `make_mut` is the only write path.
pub struct Shared<T>(Arc<T>);

impl<T> Shared<T> {
    pub fn new(value: T) -> Self {
        Self(Arc::new(value))
    }
    /// Whether both handles still hold the same allocation.
    pub fn ptr_eq(this: &Self, other: &Self) -> bool {
        Arc::ptr_eq(&this.0, &other.0)
    }
}
impl<T: Clone> Shared<T> {
    /// Copies the value first if another handle still shares it. Call this only
    /// when the value will really change: it is what a pass pays for.
    pub fn make_mut(&mut self) -> &mut T {
        Arc::make_mut(&mut self.0)
    }
    pub fn into_inner(self) -> T {
        Arc::unwrap_or_clone(self.0)
    }
}
impl<T> Clone for Shared<T> {
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}
impl<T: Default> Default for Shared<T> {
    fn default() -> Self {
        Self::new(T::default())
    }
}
impl<T> Deref for Shared<T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.0
    }
}
impl<T> From<T> for Shared<T> {
    fn from(value: T) -> Self {
        Self::new(value)
    }
}
impl<T: PartialEq> PartialEq for Shared<T> {
    fn eq(&self, other: &Self) -> bool {
        Self::ptr_eq(self, other) || **self == **other
    }
}
impl<T: Eq> Eq for Shared<T> {}
impl<T: fmt::Debug> fmt::Debug for Shared<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        (**self).fmt(f)
    }
}
impl<T: Serialize> Serialize for Shared<T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        (**self).serialize(serializer)
    }
}
impl<'de, T: Deserialize<'de>> Deserialize<'de> for Shared<T> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        T::deserialize(deserializer).map(Self::new)
    }
}
/// The `Arc` allocation around one `T`: its two counts, plus alignment slack.
fn charge_header<T>(c: &mut Counter) -> Option<()> {
    c.charge(
        size_of::<T>()
            .checked_add(align_of::<T>())?
            .checked_add(2 * size_of::<usize>())?,
    )
}
impl<T: HeapLayoutBound> HeapLayoutBound for Shared<T> {
    fn stable_heap(&self) -> bool {
        (**self).stable_heap()
    }
    fn heap_bound(&self, c: &mut Counter) -> Option<()> {
        // The shared allocation's header, then the value's own walk: one visit.
        charge_header::<T>(c)?;
        (**self).heap_bound(c)
    }
    // Unlike a plain `Arc`, a large collection in here keeps its per-element
    // completion counters: this owner is the only one the walk ever charges.
    fn completed_heap_bound(&self, c: &mut Counter) -> Option<()> {
        charge_header::<T>(c)?;
        (**self).completed_heap_bound(c)
    }
}
impl<'a, T> IntoIterator for &'a Shared<T>
where
    &'a T: IntoIterator,
{
    type Item = <&'a T as IntoIterator>::Item;
    type IntoIter = <&'a T as IntoIterator>::IntoIter;
    fn into_iter(self) -> Self::IntoIter {
        (&**self).into_iter()
    }
}

/// A whole set by pointer. A write that changes nothing copies nothing.
impl<T: Ord + Clone> Shared<BTreeSet<T>> {
    pub fn insert(&mut self, value: T) -> bool {
        !self.contains(&value) && self.make_mut().insert(value)
    }
    pub fn remove<Q>(&mut self, value: &Q) -> bool
    where
        T: Borrow<Q>,
        Q: Ord + ?Sized,
    {
        self.contains(value) && self.make_mut().remove(value)
    }
    pub fn clear(&mut self) {
        if !self.is_empty() {
            *self = Self::default();
        }
    }
    pub fn retain(&mut self, mut keep: impl FnMut(&T) -> bool) {
        let dropped: Vec<T> = self.iter().filter(|v| !keep(v)).cloned().collect();
        for value in &dropped {
            self.remove(value);
        }
    }
    pub fn extend(&mut self, values: impl IntoIterator<Item = T>) {
        for value in values {
            self.insert(value);
        }
    }
}
impl<T: Ord> FromIterator<T> for Shared<BTreeSet<T>> {
    fn from_iter<I: IntoIterator<Item = T>>(values: I) -> Self {
        Self::new(values.into_iter().collect())
    }
}
impl<T: Ord + Clone> IntoIterator for Shared<BTreeSet<T>> {
    type Item = T;
    type IntoIter = btree_set::IntoIter<T>;
    fn into_iter(self) -> Self::IntoIter {
        self.into_inner().into_iter()
    }
}

type Iter<'a, K, V> =
    Map<btree_map::Iter<'a, K, Shared<V>>, fn((&'a K, &'a Shared<V>)) -> (&'a K, &'a V)>;
type Range<'a, K, V> =
    Map<btree_map::Range<'a, K, Shared<V>>, fn((&'a K, &'a Shared<V>)) -> (&'a K, &'a V)>;
type Values<'a, K, V> = Map<btree_map::Values<'a, K, Shared<V>>, fn(&'a Shared<V>) -> &'a V>;
type IntoIter<K, V> = Map<btree_map::IntoIter<K, Shared<V>>, fn((K, Shared<V>)) -> (K, V)>;

fn unshared_value<V>(value: &Shared<V>) -> &V {
    value
}
fn unshared<'a, K, V>((key, value): (&'a K, &'a Shared<V>)) -> (&'a K, &'a V) {
    (key, &**value)
}

/// A map with each value by pointer, and its keys and tree by pointer too: a
/// clone costs one reference count. The first write after a clone copies the
/// tree (keys and value pointers) and the one value written.
///
/// Reads match `BTreeMap<K, V>`. There is deliberately no `values_mut` outside
/// tests: a loop over every value uses `slots_mut` and unshares only the values
/// it changes. `Deref` serves the read methods that do not name `V`.
pub struct SharedMap<K, V>(Shared<BTreeMap<K, Shared<V>>>);

impl<K, V> SharedMap<K, V> {
    pub fn iter(&self) -> Iter<'_, K, V> {
        self.0.iter().map(unshared)
    }
    pub fn values(&self) -> Values<'_, K, V> {
        self.0.values().map(unshared_value)
    }
    /// The value handles, to move a value to another map without copying it.
    pub fn iter_shared(&self) -> btree_map::Iter<'_, K, Shared<V>> {
        self.0.iter()
    }
}
impl<K: Ord, V> SharedMap<K, V> {
    pub fn get<Q>(&self, key: &Q) -> Option<&V>
    where
        K: Borrow<Q>,
        Q: Ord + ?Sized,
    {
        self.0.get(key).map(|value| &**value)
    }
    pub fn get_shared<Q>(&self, key: &Q) -> Option<&Shared<V>>
    where
        K: Borrow<Q>,
        Q: Ord + ?Sized,
    {
        self.0.get(key)
    }
    pub fn range<T, R>(&self, range: R) -> Range<'_, K, V>
    where
        T: Ord + ?Sized,
        K: Borrow<T>,
        R: RangeBounds<T>,
    {
        self.0.range(range).map(unshared)
    }
}
impl<K: Ord + Clone, V: Clone> SharedMap<K, V> {
    /// A miss copies nothing; a hit unshares the value, so ask only to write.
    pub fn get_mut<Q>(&mut self, key: &Q) -> Option<&mut V>
    where
        K: Borrow<Q>,
        Q: Ord + ?Sized,
    {
        if !self.0.contains_key(key) {
            return None;
        }
        self.0.make_mut().get_mut(key).map(Shared::make_mut)
    }
    /// Every value handle for one loop. Copies the tree but no value: reads go
    /// through `Deref`, and only `make_mut` on a handle copies its value.
    pub fn slots_mut(&mut self) -> btree_map::IterMut<'_, K, Shared<V>> {
        self.0.make_mut().iter_mut()
    }
    pub fn insert(&mut self, key: K, value: V) -> Option<Shared<V>> {
        self.insert_shared(key, Shared::new(value))
    }
    pub fn insert_shared(&mut self, key: K, value: Shared<V>) -> Option<Shared<V>> {
        self.0.make_mut().insert(key, value)
    }
    /// `entry(key).or_insert_with(value)` for a caller that only wants the slot
    /// filled: a key already present copies nothing.
    pub fn insert_if_absent(&mut self, key: K, value: impl FnOnce() -> V) {
        if !self.0.contains_key(&key) {
            self.insert(key, value());
        }
    }
    /// Returns the value's handle, so dropping it copies nothing.
    pub fn remove<Q>(&mut self, key: &Q) -> Option<Shared<V>>
    where
        K: Borrow<Q>,
        Q: Ord + ?Sized,
    {
        if !self.0.contains_key(key) {
            return None;
        }
        self.0.make_mut().remove(key)
    }
    pub fn clear(&mut self) {
        if !self.0.is_empty() {
            self.0 = Shared::default();
        }
    }
    /// Keeps `BTreeMap::retain`'s visit order; a pass that drops nothing copies
    /// nothing. The closure reads: a value it changes goes through `slots_mut`.
    pub fn retain(&mut self, mut keep: impl FnMut(&K, &V) -> bool) {
        let dropped: Vec<K> = self
            .iter()
            .filter(|(key, value)| !keep(key, value))
            .map(|(key, _)| key.clone())
            .collect();
        for key in &dropped {
            self.0.make_mut().remove(key);
        }
    }
    pub fn extend(&mut self, entries: impl IntoIterator<Item = (K, V)>) {
        for (key, value) in entries {
            self.insert(key, value);
        }
    }
    pub fn entry(&mut self, key: K) -> SharedEntry<'_, K, V> {
        SharedEntry { map: self, key }
    }
}
#[cfg(test)]
impl<K: Ord + Clone, V: Clone> SharedMap<K, V> {
    pub fn into_values(self) -> impl DoubleEndedIterator<Item = V> {
        self.0.into_inner().into_values().map(Shared::into_inner)
    }
    pub fn pop_first(&mut self) -> Option<(K, V)> {
        let (key, value) = self.0.make_mut().pop_first()?;
        Some((key, value.into_inner()))
    }
    pub fn values_mut(&mut self) -> impl Iterator<Item = &mut V> {
        self.0.make_mut().values_mut().map(Shared::make_mut)
    }
    pub fn iter_mut(&mut self) -> impl Iterator<Item = (&K, &mut V)> {
        self.0
            .make_mut()
            .iter_mut()
            .map(|(key, value)| (key, value.make_mut()))
    }
}
#[cfg(test)]
impl<'a, K: Ord + Clone, V: Clone> IntoIterator for &'a mut SharedMap<K, V> {
    type Item = (&'a K, &'a mut V);
    type IntoIter = Box<dyn Iterator<Item = (&'a K, &'a mut V)> + 'a>;
    fn into_iter(self) -> Self::IntoIter {
        Box::new(self.iter_mut())
    }
}
#[cfg(test)]
impl<T: PartialEq> PartialEq<T> for Shared<T> {
    fn eq(&self, other: &T) -> bool {
        **self == *other
    }
}
#[cfg(test)]
impl<K: Ord, V, const N: usize> From<[(K, V); N]> for SharedMap<K, V> {
    fn from(entries: [(K, V); N]) -> Self {
        entries.into_iter().collect()
    }
}
#[cfg(test)]
impl<K: PartialEq, V: PartialEq> PartialEq<BTreeMap<K, V>> for SharedMap<K, V> {
    fn eq(&self, other: &BTreeMap<K, V>) -> bool {
        self.len() == other.len() && self.iter().eq(other.iter())
    }
}

/// The entry forms the map's callers use. Each returns the value for writing,
/// so each unshares it.
pub struct SharedEntry<'a, K, V> {
    map: &'a mut SharedMap<K, V>,
    key: K,
}
impl<'a, K: Ord + Clone, V: Clone> SharedEntry<'a, K, V> {
    pub fn or_insert_with(self, value: impl FnOnce() -> V) -> &'a mut V {
        self.map
            .0
            .make_mut()
            .entry(self.key)
            .or_insert_with(|| Shared::new(value()))
            .make_mut()
    }
    pub fn or_default(self) -> &'a mut V
    where
        V: Default,
    {
        self.or_insert_with(V::default)
    }
}

impl<K, V> Clone for SharedMap<K, V> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}
impl<K, V> Default for SharedMap<K, V> {
    fn default() -> Self {
        Self(Shared::new(BTreeMap::new()))
    }
}
impl<K, V> Deref for SharedMap<K, V> {
    type Target = BTreeMap<K, Shared<V>>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl<K: Ord, V, Q> Index<&Q> for SharedMap<K, V>
where
    K: Borrow<Q>,
    Q: Ord + ?Sized,
{
    type Output = V;
    fn index(&self, key: &Q) -> &V {
        &self.0[key]
    }
}
impl<K: Ord, V> From<BTreeMap<K, V>> for SharedMap<K, V> {
    fn from(map: BTreeMap<K, V>) -> Self {
        map.into_iter().collect()
    }
}
impl<K, V> From<BTreeMap<K, Shared<V>>> for SharedMap<K, V> {
    fn from(map: BTreeMap<K, Shared<V>>) -> Self {
        Self(Shared::new(map))
    }
}
impl<K: Ord, V> FromIterator<(K, V)> for SharedMap<K, V> {
    fn from_iter<I: IntoIterator<Item = (K, V)>>(entries: I) -> Self {
        let map = entries
            .into_iter()
            .map(|(key, value)| (key, Shared::new(value)));
        Self(Shared::new(map.collect()))
    }
}
impl<'a, K, V> IntoIterator for &'a SharedMap<K, V> {
    type Item = (&'a K, &'a V);
    type IntoIter = Iter<'a, K, V>;
    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}
impl<K: Clone, V: Clone> IntoIterator for SharedMap<K, V> {
    type Item = (K, V);
    type IntoIter = IntoIter<K, V>;
    fn into_iter(self) -> Self::IntoIter {
        let owned: fn((K, Shared<V>)) -> (K, V) = |(key, value)| (key, value.into_inner());
        self.0.into_inner().into_iter().map(owned)
    }
}
impl<K: PartialEq, V: PartialEq> PartialEq for SharedMap<K, V> {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}
impl<K: Eq, V: Eq> Eq for SharedMap<K, V> {}
impl<K: fmt::Debug, V: fmt::Debug> fmt::Debug for SharedMap<K, V> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}
impl<K: Serialize, V: Serialize> Serialize for SharedMap<K, V> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(serializer)
    }
}
impl<'de, K: Ord + Deserialize<'de>, V: Deserialize<'de>> Deserialize<'de> for SharedMap<K, V> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Shared::deserialize(deserializer).map(Self)
    }
}
impl<K: HeapLayoutBound, V: HeapLayoutBound> HeapLayoutBound for SharedMap<K, V> {
    fn stable_heap(&self) -> bool {
        self.0.stable_heap()
    }
    fn heap_bound(&self, c: &mut Counter) -> Option<()> {
        self.0.heap_bound(c)
    }
    fn completed_heap_bound(&self, c: &mut Counter) -> Option<()> {
        self.0.completed_heap_bound(c)
    }
}
