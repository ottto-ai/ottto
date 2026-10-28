#[derive(Clone, Debug, Default)]
pub(crate) struct Pass {
    pub started: bool,
    pub cpu: u64,
    pub work: u64,
    pub power: bool,
}
crate::heap_layout_bound::fields!(Pass; started, cpu, work, power);
impl Pass {
    pub fn prepare(&mut self) {
        *self = Self::default();
        self.power = crate::snapshot_sync::archive_power_ready();
    }
    pub fn ready(&self, remaining: u64) -> bool {
        self.power && self.cpu < 30_000_000 && remaining > 0 && self.work <= 20_000_000
    }
    pub fn observe(&mut self, cpu: Option<u64>, wall: u64) {
        if self.started || cpu.is_none() {
            self.cpu = cpu.map_or(u64::MAX, |cpu| self.cpu.saturating_add(cpu));
        }
        self.work = self.work.max(wall);
    }
}
