//! Append notifications only. No timer, startup census or persisted duplicate catalogue.
use super::*;

#[derive(Default)]
struct Notices {
    active: bool,
    roots: BTreeSet<String>,
}
fn notices() -> &'static Mutex<BTreeMap<PathBuf, Notices>> {
    static VALUE: OnceLock<Mutex<BTreeMap<PathBuf, Notices>>> = OnceLock::new();
    VALUE.get_or_init(Mutex::default)
}

pub(crate) fn configure(support: &Path, active: bool) -> Result<()> {
    let _append = append_lock()
        .lock()
        .map_err(|_| anyhow::anyhow!("evidence lock poisoned"))?;
    let mut all = notices()
        .lock()
        .map_err(|_| anyhow::anyhow!("notice lock poisoned"))?;
    if active {
        all.entry(support.to_owned()).or_default().active = true;
    } else if let Some(state) = all.get_mut(support) {
        state.active = false;
    }
    Ok(())
}

pub(super) fn appended(support: &Path, root: &str) {
    if let Ok(mut all) = notices().lock() {
        if let Some(state) = all.get_mut(support).filter(|state| state.active) {
            state.roots.insert(root.to_owned());
        }
    }
}

pub(crate) struct Batch {
    support: PathBuf,
    pub(crate) roots: BTreeSet<String>,
}
pub(crate) fn detach(support: &Path) -> Result<Batch> {
    let _append = append_lock()
        .lock()
        .map_err(|_| anyhow::anyhow!("evidence lock poisoned"))?;
    let mut all = notices()
        .lock()
        .map_err(|_| anyhow::anyhow!("notice lock poisoned"))?;
    let roots = all
        .get_mut(support)
        .map(|state| std::mem::take(&mut state.roots))
        .unwrap_or_default();
    Ok(Batch {
        support: support.to_owned(),
        roots,
    })
}
impl Batch {
    pub(crate) fn committed(mut self) {
        self.roots.clear();
    }
}
impl Drop for Batch {
    fn drop(&mut self) {
        if let Ok(mut all) = notices().lock() {
            if let Some(state) = all.get_mut(&self.support) {
                state.roots.append(&mut self.roots);
            }
        }
    }
}
