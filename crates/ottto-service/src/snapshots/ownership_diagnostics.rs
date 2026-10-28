use super::*;
use std::hash::{Hash, Hasher};
pub(super) const INVENTORY: usize = 0;
pub(super) const CREATED: usize = 1;
pub(super) const PARENT: usize = 2;
pub(super) const ABSENT: usize = 3;
pub(super) const GROUP: usize = 4;
pub(super) const PARSER: usize = 5;
const N: usize = PARSER + 1;
const NAMES: &str = "inventory_hold created_thread_proof parent_unresolvable protected_absent other_group_receipt_legacy other_parser";
type Distinct = (BTreeSet<u64>, [usize; N + 1], Option<usize>);
pub(crate) type Summary = ([usize; N + 2], [usize; N + 1], usize);
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub(crate) struct Counts {
    contributions: [usize; N + 2],
    #[serde(skip)]
    distinct: Arc<Mutex<Distinct>>,
}
impl Counts {
    fn state(&self) -> std::sync::MutexGuard<'_, Distinct> {
        self.distinct.lock().unwrap_or_else(|e| e.into_inner())
    }
    pub(super) fn page(&self, index_size: usize) -> Self {
        self.state().2.get_or_insert(index_size.min(65_536));
        Self {
            distinct: Arc::clone(&self.distinct),
            ..Self::default()
        }
    }
    pub(super) fn add<P: AsRef<Path>>(&mut self, cause: usize, keys: impl IntoIterator<Item = P>) {
        let mut d = self.distinct.lock().unwrap_or_else(|e| e.into_inner());
        for path in keys {
            let path = path.as_ref();
            self.contributions[cause] += 1;
            self.contributions[N + usize::from(is_compressed_codex_rollout(Some(path), None))] += 1;
            let mut hash = std::collections::hash_map::DefaultHasher::new();
            local_index_key(path).hash(&mut hash);
            let key = hash.finish();
            if !d.0.contains(&key) {
                if d.0.len() < d.2.unwrap_or(0) {
                    d.0.insert(key);
                    d.1[cause] += 1;
                } else {
                    d.1[N] = 1;
                }
            }
        }
    }
    pub(super) fn merge(&mut self, page: Self) {
        for (a, b) in self.contributions.iter_mut().zip(page.contributions) {
            *a += b;
        }
    }
    pub(crate) fn summary(&self, total: usize) -> Summary {
        let unknown = total.saturating_sub(self.contributions[..N].iter().sum());
        (self.contributions, self.state().1, unknown)
    }
}
pub(crate) fn line((c, d, unattributed): Summary) -> String {
    let mut line = String::new();
    for (i, name) in NAMES.split(' ').enumerate() {
        line.push_str(&format!(
            " ownership_{name}={} ownership_{name}_distinct={}",
            c[i], d[i]
        ));
    }
    line.push_str(&format!(" ownership_unattributed={unattributed} ownership_input_plain={} ownership_input_compressed={} ownership_distinct_capped={}", c[N], c[N + 1], d[N] != 0));
    line
}
crate::heap_layout_bound::fields!(Counts; contributions, distinct);
#[cfg(test)]
#[path = "ownership_diagnostics_tests.rs"]
mod tests;
