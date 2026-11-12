//! Append notifications only; admitted roots detect growth through their pair generations.
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
pub(crate) fn pending(support: &Path) -> Result<BTreeSet<String>> {
    Ok(notices()
        .lock()
        .map_err(|_| anyhow::anyhow!("notice lock poisoned"))?
        .get(support)
        .map(|state| state.roots.clone())
        .unwrap_or_default())
}
pub(crate) fn forget(support: &Path, saved: &BTreeSet<String>) -> Result<()> {
    if let Some(state) = notices()
        .lock()
        .map_err(|_| anyhow::anyhow!("notice lock poisoned"))?
        .get_mut(support)
    {
        state.roots.retain(|root| !saved.contains(root));
    }
    Ok(())
}
