//! Append notifications only; admitted roots detect growth through their pair generations.
use super::*;
#[derive(Default)]
struct Notices {
    active: bool,
    roots: BTreeSet<String>,
    /// Roots captured while active whose rows are not yet readable; noticed
    /// when they are, even if notices were deactivated meanwhile.
    captured: BTreeSet<String>,
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
/// Rest-heap diagnostics: support dirs tracked and roots awaiting a save.
pub(crate) fn rest_entries() -> Option<(usize, usize)> {
    let all = notices().try_lock().ok()?;
    Some((all.len(), all.values().map(|state| state.roots.len()).sum()))
}
/// The relay stored a row of `root`: eligible for a notice only if notices
/// are active now.
pub(super) fn captured(support: &Path, root: &str) {
    if let Ok(mut all) = notices().lock() {
        if let Some(state) = all.get_mut(support).filter(|state| state.active) {
            state.captured.insert(root.to_owned());
        }
    }
}
/// The rows of `root` reached its per-session file: notice an eligible root.
pub(super) fn readable(support: &Path, root: &str) {
    if let Ok(mut all) = notices().lock() {
        if let Some(state) = all.get_mut(support) {
            if state.captured.remove(root) {
                state.roots.insert(root.to_owned());
            }
        }
    }
}
/// One appended row's notice, as the relay records it.
#[cfg(test)]
pub(crate) fn appended_for_test(support: &Path, root: &str) {
    captured(support, root);
    readable(support, root);
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
