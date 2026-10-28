use super::*;
pub(super) const INVENTORY: usize = 0;
pub(super) const CREATED: usize = 1;
pub(super) const PARENT: usize = 2;
pub(super) const ABSENT: usize = 3;
pub(super) const GROUP: usize = 4;
pub(super) const PARSER: usize = 5;
const N: usize = PARSER + 1;
const NAMES: &str = "inventory_hold created_thread_proof parent_unresolvable protected_absent other_group_receipt_legacy other_parser";
pub(crate) type Summary = ([usize; N + 2], [usize; 3]);
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub(crate) struct Counts {
    // Last two slots retain the prior input counters; no longer incremented or emitted.
    contributions: [usize; N + 2],
    #[serde(skip)]
    observation: [usize; 2], // generation marker, diagnostic resets; process-only
}
impl Counts {
    pub(super) fn is_empty(&self) -> bool {
        self.contributions == [0; N + 2]
    }
    fn reset(&mut self) {
        self.contributions = [0; N + 2];
        self.observation[1] = self.observation[1].saturating_add(1);
    }
    pub(super) fn page(&mut self, started: Option<u64>) -> Self {
        self.observation[0] = usize::try_from(started.unwrap_or(0)).unwrap_or(0);
        Self {
            observation: [self.observation[0], 0],
            ..Self::default()
        }
    }
    pub(super) fn add(&mut self, cause: usize, count: usize) {
        match self.contributions[cause].checked_add(count) {
            Some(n) => self.contributions[cause] = n,
            None => self.reset(),
        }
    }
    pub(super) fn merge(&mut self, page: &Self) {
        self.observation[1] = self.observation[1].saturating_add(page.observation[1]);
        for (i, count) in page.contributions.iter().enumerate() {
            self.add(i, *count);
        }
    }
    pub(crate) fn summary(&self, total: usize) -> Summary {
        let mut c = self.clone();
        let remainder = c.contributions[..N]
            .iter()
            .try_fold(0usize, |n, v| n.checked_add(*v))
            .and_then(|n| total.checked_sub(n));
        if remainder.is_none() {
            c.reset();
        }
        let meta = [
            remainder.unwrap_or(total),
            c.observation[0],
            c.observation[1],
        ];
        (c.contributions, meta)
    }
}
pub(crate) fn line((c, [unattributed, generation, invalid]): Summary) -> String {
    let mut line = String::new();
    for (name, count) in NAMES
        .split(' ')
        .chain(["unattributed"])
        .zip(c[..N].iter().copied().chain([unattributed]))
    {
        if count != 0 {
            line.push_str(&format!(
                " ownership_incomplete_contributions{{bucket=\"{name}\"}}={count}"
            ));
        }
    }
    for (name, count) in [
        ("generation_start", generation),
        ("invalid_resets", invalid),
    ] {
        if count != 0 {
            line.push_str(&format!(" ownership_incomplete_{name}={count}"));
        }
    }
    line
}
crate::heap_layout_bound::fields!(Counts; contributions, observation);
#[cfg(test)]
#[path = "ownership_diagnostics_tests.rs"]
mod tests;
