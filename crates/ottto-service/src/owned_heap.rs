//! Incremental requested-layout summaries for private, wholly owned collections.
//! No mutable collection escape: mutation guards remeasure only changed values.
use crate::heap_layout_bound::{self, Counter, HeapLayoutBound};
use std::borrow::Borrow;
use std::collections::BTreeMap;
use std::ops::{Deref, DerefMut};

fn heap<T: HeapLayoutBound>(value: &T) -> Option<usize> {
    let bytes = heap_layout_bound::bound(value, crate::transcript_cache::ENTRY_BYTES)?;
    value
        .stable_heap()
        .then_some(bytes)?
        .checked_sub(std::mem::size_of_val(value))
}
fn replace(sum: Option<usize>, old: Option<usize>, new: Option<usize>) -> Option<usize> {
    sum?.checked_sub(old?)?.checked_add(new?)
}

#[derive(Debug)]
pub(crate) struct OwnedVec<T> {
    values: Vec<T>,
    elements: Option<usize>,
}
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
impl<T: Clone + HeapLayoutBound> Clone for OwnedVec<T> {
    fn clone(&self) -> Self {
        self.values.clone().into()
    }
}
impl<T> Deref for OwnedVec<T> {
    type Target = [T];
    fn deref(&self) -> &Self::Target {
        &self.values
    }
}
impl<T> IntoIterator for OwnedVec<T> {
    type Item = T;
    type IntoIter = std::vec::IntoIter<T>;
    fn into_iter(self) -> Self::IntoIter {
        self.values.into_iter()
    }
}
impl<T: HeapLayoutBound> HeapLayoutBound for OwnedVec<T> {
    fn stable_heap(&self) -> bool {
        self.elements.is_some()
    }
    fn heap_bound(&self, c: &mut Counter) -> Option<()> {
        c.add(
            self.values
                .capacity()
                .checked_mul(std::mem::size_of::<T>())?,
        )?;
        c.add(self.elements?)
    }
}

#[derive(Debug)]
pub(crate) struct OwnedMap<K, V> {
    values: BTreeMap<K, V>,
    elements: Option<usize>,
}
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
    #[cfg(test)]
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
    pub(crate) fn into_values(self) -> std::collections::btree_map::IntoValues<K, V> {
        self.values.into_values()
    }
}
impl<K: Ord + Clone + HeapLayoutBound, V: Clone + HeapLayoutBound> Clone for OwnedMap<K, V> {
    fn clone(&self) -> Self {
        let values = self.values.clone();
        let elements = values.iter().try_fold(0usize, |n, (k, v)| {
            n.checked_add(heap(k)?)?.checked_add(heap(v)?)
        });
        Self { values, elements }
    }
}
impl<K, V> Deref for OwnedMap<K, V> {
    type Target = BTreeMap<K, V>;
    fn deref(&self) -> &Self::Target {
        &self.values
    }
}
impl<K: HeapLayoutBound, V: HeapLayoutBound> HeapLayoutBound for OwnedMap<K, V> {
    fn stable_heap(&self) -> bool {
        self.elements.is_some()
    }
    fn heap_bound(&self, c: &mut Counter) -> Option<()> {
        heap_layout_bound::tree_nodes::<K, V>(self.values.len(), c)?;
        c.add(self.elements?)
    }
}
pub(crate) struct ValueGuard<'a, V: HeapLayoutBound> {
    value: &'a mut V,
    sum: &'a mut Option<usize>,
    base: Option<usize>,
}
impl<V: HeapLayoutBound> Deref for ValueGuard<'_, V> {
    type Target = V;
    fn deref(&self) -> &V {
        self.value
    }
}
impl<V: HeapLayoutBound> DerefMut for ValueGuard<'_, V> {
    fn deref_mut(&mut self) -> &mut V {
        self.value
    }
}
impl<V: HeapLayoutBound> Drop for ValueGuard<'_, V> {
    fn drop(&mut self) {
        *self.sum = self.base.and_then(|n| n.checked_add(heap(self.value)?));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::retry_allocation_probe as probe;
    fn charge<T: HeapLayoutBound>(value: &T) -> usize {
        heap_layout_bound::bound(value, crate::transcript_cache::ENTRY_BYTES).unwrap()
    }
    #[test]
    fn owned_heap_mutation_clone_reset_and_forget_are_conservative() {
        if !heap_layout_bound::layout_supported() {
            return;
        }
        let (mut map, alloc) = probe::measure(|| {
            let mut map = OwnedMap::new();
            for n in 0..1200 {
                map.insert(format!("k{n}"), String::with_capacity(128));
            }
            map
        });
        assert!(charge(&map) >= alloc.requested_live as usize);
        let first = charge(&map);
        map.get_mut("k0").unwrap().reserve(8192);
        assert!(charge(&map) > first);
        let ((cloned, copy), alloc) = probe::measure(|| (map.clone(), map.clone()));
        assert!(charge(&cloned) + charge(&copy) >= alloc.requested_live as usize);
        let before = charge(&map);
        map.insert("k0".into(), "replacement".into());
        assert!(charge(&map) < before);
        map.remove("k0");
        let mut guard = map.get_mut("k1").unwrap();
        guard.reserve(8192);
        std::mem::forget(guard);
        assert!(heap_layout_bound::bound(&map, usize::MAX).is_none());
        let (mut values, alloc) = probe::measure(|| {
            let mut values = OwnedVec::new();
            for _ in 0..1200 {
                values.push(String::with_capacity(256));
            }
            values
        });
        assert!(charge(&values) >= alloc.requested_live as usize);
        values.clear();
        assert!(charge(&values) >= values.values.capacity() * std::mem::size_of::<String>());
        values.push("reset".into());
        assert!(heap_layout_bound::bound(&values, charge(&values) - 1).is_none());
    }
    #[test]
    fn owned_vec_element_guard_remeasures_and_forget_is_conservative() {
        if !heap_layout_bound::layout_supported() {
            return;
        }
        let (mut grown, alloc) = probe::measure(|| {
            let mut values = OwnedVec::from(vec![String::new(); 64]);
            values.get_mut(7).unwrap().reserve(8192);
            values
        });
        assert!(charge(&grown) >= alloc.requested_live as usize);
        let before = charge(&grown);
        let mut guard = grown.get_mut(7).unwrap();
        guard.clear();
        guard.shrink_to_fit();
        drop(guard);
        assert!(charge(&grown) < before);
        assert!(grown.get_mut(64).is_none());
        std::mem::forget(grown.get_mut(0).unwrap());
        assert!(heap_layout_bound::bound(&grown, usize::MAX).is_none());
    }
    #[test]
    fn owned_heap_nested_charges_refuse_external_mutability_and_over_budget() {
        if !heap_layout_bound::layout_supported() {
            return;
        }
        let (nested, alloc) = probe::measure(|| {
            let mut map = OwnedMap::new();
            for n in 0..1200 {
                map.insert(n, OwnedVec::from(vec![String::with_capacity(128)]));
            }
            map
        });
        assert!(charge(&nested) >= alloc.requested_live as usize);
        let external = std::sync::Arc::new(std::sync::Mutex::new(String::from("external")));
        let mut map = OwnedMap::new();
        map.insert(1u64, external.clone());
        assert!(heap_layout_bound::bound(&map, usize::MAX).is_none());
        let opaque = OwnedVec::from(vec![serde_json::json!({"opaque":true})]);
        assert!(heap_layout_bound::bound(&opaque, usize::MAX).is_none());
        let large = OwnedVec::from(vec![String::with_capacity(
            crate::transcript_cache::ENTRY_BYTES,
        )]);
        assert!(heap_layout_bound::bound(&large, crate::transcript_cache::ENTRY_BYTES).is_none());
    }
    #[test]
    fn owned_heap_per_step_visits_are_independent_of_history_length() {
        if !heap_layout_bound::layout_supported() {
            return;
        }
        for count in [100, 1200, 2400] {
            let mut values = OwnedVec::new();
            for _ in 0..count {
                values.push(String::from("history"));
            }
            let mut c = Counter::new(crate::transcript_cache::ENTRY_BYTES);
            values.heap_bound(&mut c).unwrap();
            assert_eq!(c.visits_for_test(), 2);
        }
    }
}
