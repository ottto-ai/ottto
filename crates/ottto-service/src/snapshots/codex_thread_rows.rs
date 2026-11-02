//! Compact census references; title payloads live only while a consumer uses them.
use super::*;

#[derive(Clone)]
pub(super) struct TitleLookup {
    pub database: Arc<PathBuf>,
    pub raw_id: String,
    pub digest: Option<[u8; 32]>,
}

impl std::fmt::Debug for TitleLookup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TitleLookup").finish_non_exhaustive()
    }
}

pub(super) fn digest(title: Option<&str>) -> Option<[u8; 32]> {
    title.map(|title| Sha256::digest(title.as_bytes()).into())
}

/// Short-lived query handles for one census, candidate batch or fallback pass.
/// No transaction or reader is stored in scan metadata or retained reductions.
#[derive(Default)]
pub(super) struct TitleReads(BTreeMap<PathBuf, codex_sqlite_read::CodexSqliteRead>);
impl TitleReads {
    fn connection(&mut self, path: &Path) -> Result<&codex_sqlite_read::CodexSqliteRead> {
        use std::collections::btree_map::Entry;
        Ok(match self.0.entry(path.to_path_buf()) {
            Entry::Vacant(entry) => {
                entry.insert(open_codex_sidecar_database(path, &mut Default::default())?)
            }
            Entry::Occupied(entry) => entry.into_mut(),
        })
    }
}

impl TitleLookup {
    fn read(&self, reads: &mut TitleReads) -> Result<Option<String>> {
        if self.digest.is_none() {
            return Ok(None);
        }
        let connection = reads.connection(&self.database)?;
        connection.read(|connection| {
            // The provider's id index is used verbatim, including UUID aliases.
            let mut statement =
                connection.prepare_cached("SELECT title FROM threads WHERE id = ?1")?;
            let mut rows = statement.query([&self.raw_id])?;
            while let Some(row) = rows.next()? {
                let title: Option<String> = row.get(0)?;
                if digest(title.as_deref()) == self.digest {
                    return Ok(title);
                }
            }
            anyhow::bail!("Codex title changed after census")
        })
    }
}

impl CodexTitleCandidate {
    pub(super) fn display_title(&self) -> Result<String> {
        self.display_title_with(&mut TitleReads::default())
    }
    pub(super) fn display_title_with(&self, reads: &mut TitleReads) -> Result<String> {
        match &self.lookup {
            Some(lookup) => lookup
                .read(reads)?
                .and_then(|title| normalize_display_title_ref(&title, &self.source))
                .context("Codex display title unavailable"),
            None => Ok(self.title.clone()),
        }
    }
}

impl CodexStateThread {
    pub(super) fn raw_title(&self, reads: &mut TitleReads) -> Result<Option<String>> {
        match &self.title_lookup {
            Some(lookup) => lookup.read(reads),
            None => Ok(self.title.clone()),
        }
    }

    pub(super) fn same_title(&self, other: &Self, reads: &mut TitleReads) -> Result<bool> {
        let title_digest = |thread: &Self| {
            thread
                .title_lookup
                .as_ref()
                .map_or_else(|| digest(thread.title.as_deref()), |lookup| lookup.digest)
        };
        if title_digest(self) != title_digest(other) {
            return Ok(false);
        }
        // A digest rejects unequal titles cheaply; equality always uses original bytes.
        Ok(self.raw_title(reads)? == other.raw_title(reads)?)
    }

    pub(super) fn same_row(&self, other: &Self, reads: &mut TitleReads) -> Result<bool> {
        Ok(self.tokens_used == other.tokens_used
            && self.archived == other.archived
            && self.created_at == other.created_at
            && self.updated_at == other.updated_at
            && self.model == other.model
            && self.rollout_path == other.rollout_path
            && self.same_title(other, reads)?)
    }
}

impl PartialEq for CodexStateThread {
    fn eq(&self, other: &Self) -> bool {
        self.same_row(other, &mut TitleReads::default())
            .unwrap_or(false)
    }
}
impl Eq for CodexStateThread {}

pub(super) fn normalize_display_title_ref(value: &str, source: &str) -> Option<String> {
    let normalized = normalize_title_ref(value)?;
    is_safe_display_title(&normalized, source).then_some(normalized)
}

pub(super) fn normalize_title_ref(value: &str) -> Option<String> {
    let mut words = value.split_whitespace();
    let first = words.next()?;
    Some(
        first
            .chars()
            .chain(words.flat_map(|word| std::iter::once(' ').chain(word.chars())))
            .take(255)
            .collect(),
    )
}

crate::heap_layout_bound::fields!(TitleLookup; database, raw_id, digest);
