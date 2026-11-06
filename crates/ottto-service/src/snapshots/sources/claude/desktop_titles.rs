//! Claude Desktop session titles: the desktop store's per-session titles,
//! account and original-identity evidence and spawn lineage, the transcript
//! live window, and the bounded store census and path selection.

use crate::snapshots::*;

/// Claude Code sidecar title metadata read from the Claude desktop app's
/// per-session store — the Claude analogue of `CodexTitleMetadata`.
///
/// The desktop app persists one JSON file per session under
/// `~/Library/Application Support/Claude/claude-code-sessions/<accountCtx>/
/// <workspace>/*.json` whose `cliSessionId` field equals the transcript file
/// stem under `~/.claude/projects/**` and whose `title` field is the
/// human-readable session title shown in the app (LLM-generated
/// `titleSource=auto` or user-renamed `titleSource=user`). Transcripts almost
/// never carry `ai-title`/`summary` records, so this store is the only local
/// source of the real title for most Claude Code sessions — including
/// CLI-launched sessions later opened in the app.
///
/// Privacy: only session/title metadata and the presence of an import tag are read;
/// the account/organization directory UUIDs are retained only as canonical hashes. The rest
/// of the file (MCP tool catalogs, permission state) is never retained. Title
/// upload stays governed by the org/user `session_titles_enabled` policy via
/// `apply_upload_policy`, exactly like Codex titles.
///
/// Candidate identity is derived per session from extracted title content (not
/// file stats): rewriting one store file can select only its matching session.
#[derive(Debug, Clone, Default)]
pub(in crate::snapshots) struct ClaudeTitleMetadata {
    pub(in crate::snapshots) titles: BTreeMap<String, ClaudeTitleCandidate>,
    account_identifier_hashes: BTreeMap<String, BTreeSet<String>>,
    pub(in crate::snapshots) original_identity_evidence:
        BTreeMap<String, BTreeSet<ClaudeDesktopIdentityEvidence>>,
    /// Child transcript id -> the session that started it from the desktop app
    /// (`spawnedFrom`), resolved through the store to the parent's own
    /// transcript id. Only unambiguous, acyclic links are kept.
    pub(in crate::snapshots) spawn_lineage: BTreeMap<String, ClaudeDesktopSpawnLineage>,
    /// This cycle's existing held retries with recovered proof; counts only.
    pub(in crate::snapshots) recovered_account_holds: BTreeSet<String>,
    pub(in crate::snapshots) legacy_sidecar_fingerprint: String,
    pub(in crate::snapshots) sidecar_census_incomplete: bool,
    pub(in crate::snapshots) original_identity_census_incomplete: bool,
}

/// A launched session's direct starting session. No root or depth: the child
/// is a separate top-level session whose usage family is its own transcript.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::snapshots) struct ClaudeDesktopSpawnLineage {
    pub(in crate::snapshots) parent_session_id: String,
}

#[derive(Debug, Clone)]
pub(in crate::snapshots) struct ClaudeTitleCandidate {
    pub(in crate::snapshots) title: String,
    /// True when the desktop `titleSource` is `user` (an explicit rename). A
    /// user-set title overrides transcript-derived titles; an auto title only
    /// fills absences.
    pub(in crate::snapshots) user_set: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(in crate::snapshots) struct ClaudeDesktopTitleIndexEntry {
    pub(in crate::snapshots) cli_session_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(in crate::snapshots) title: Option<String>,
    pub(in crate::snapshots) user_set: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(in crate::snapshots) account_identifier_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(in crate::snapshots) original_identity: Option<ClaudeDesktopIdentityEvidence>,
    /// The desktop app's own id for this session (`local_<uuid>`), which is
    /// what another session's `spawnedFrom` names.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(in crate::snapshots) desktop_session_id: Option<String>,
    /// `spawnedFrom.sessionId`: the desktop id of the session that started
    /// this one with the app's `start_session` tool.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(in crate::snapshots) spawned_from_desktop_session_id: Option<String>,
    /// `spawnedFrom` is present but its session id is missing or malformed:
    /// the starting session is unknown, which is not the same as none.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub(in crate::snapshots) spawned_from_unresolved: bool,
}

/// Directory identity is original only for a native, unimported session. Desktop's
/// `importedFrom` is an origin tag, not a reference to the original account or org.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub(in crate::snapshots) struct ClaudeDesktopIdentityEvidence {
    pub(in crate::snapshots) account_identifier_hash: Option<String>,
    pub(in crate::snapshots) provider_workspace_hash: Option<String>,
    #[serde(default)]
    pub(in crate::snapshots) source_created_at: Option<String>,
    pub(in crate::snapshots) imported: bool,
}

// The desktop store holds one ~80KB JSON per session; both caps are far above
// anything observed and exist only to bound a pathological store. Tests use a
// small page so pagination fixtures need dozens of files, not thousands.
#[cfg(not(test))]
pub(in crate::snapshots) const MAX_CLAUDE_DESKTOP_SESSION_FILES: usize = 5_000;
#[cfg(test)]
pub(in crate::snapshots) const MAX_CLAUDE_DESKTOP_SESSION_FILES: usize = 32;
pub(in crate::snapshots) const MAX_CLAUDE_DESKTOP_SESSION_FILE_BYTES: u64 = 2 * 1024 * 1024;
const MAX_CLAUDE_DESKTOP_STORE_DEPTH: usize = 3;
const MAX_CLAUDE_DESKTOP_STORE_ENTRIES_PER_SCAN: usize = 10_000;

impl ClaudeTitleMetadata {
    pub(in crate::snapshots) fn session_account_evidence(
        &self,
        session_id: &str,
    ) -> SessionAccountEvidence {
        let mut evidence = SessionAccountEvidence {
            provider: "anthropic",
            account_identifier_hash: None,
            provider_workspace_hash: None,
            identity_hash_scheme: "provider-sha256:v1",
            evidence_source: "claude_desktop_original:v1",
            identity_disposition: Some("missing"),
            source_created_at: None,
        };
        let Some(entries) = self.original_identity_evidence.get(session_id) else {
            return evidence;
        };
        let accounts = entries
            .iter()
            .filter_map(|entry| entry.account_identifier_hash.as_ref())
            .collect::<BTreeSet<_>>();
        let organizations = entries
            .iter()
            .filter_map(|entry| entry.provider_workspace_hash.as_ref())
            .collect::<BTreeSet<_>>();
        if accounts.len() == 1 {
            evidence.account_identifier_hash = accounts.first().map(|value| (*value).clone());
        }
        if organizations.len() == 1 {
            evidence.provider_workspace_hash = organizations.first().map(|value| (*value).clone());
        }
        if entries.len() == 1 {
            evidence.source_created_at = entries
                .first()
                .and_then(|entry| entry.source_created_at.clone());
        }
        if accounts.len() > 1 || organizations.len() > 1 {
            evidence.identity_disposition = Some("conflict");
        } else if !self.original_identity_census_incomplete
            && entries.len() == 1
            && entries.first().is_some_and(|entry| {
                !entry.imported
                    && entry.account_identifier_hash.is_some()
                    && entry.provider_workspace_hash.is_some()
            })
        {
            evidence.identity_disposition = Some("complete");
        }
        evidence
    }

    pub(in crate::snapshots) fn account_identifier_hash(
        &self,
        source_session_id: &str,
    ) -> Option<&str> {
        let hashes = self.account_identifier_hashes.get(source_session_id)?;
        (hashes.len() == 1)
            .then(|| hashes.first().map(String::as_str))
            .flatten()
    }

    pub(in crate::snapshots) fn session_sidecar_fingerprint(
        &self,
        source_session_id: &str,
    ) -> String {
        let candidate = self.titles.get(source_session_id);
        let account_identity = match self.account_identifier_hashes.get(source_session_id) {
            Some(hashes) if hashes.len() == 1 => hashes.first().map(String::as_str).unwrap_or(""),
            Some(_) => "ambiguous",
            None => "",
        };
        let original_identity = self
            .original_identity_evidence
            .get(source_session_id)
            .map(|evidence| serde_json::to_string(evidence).expect("identity fields serialize"))
            .unwrap_or_default();
        let mut parts = vec![
            "claude_session_sidecar:v2",
            source_session_id,
            candidate.map(|value| value.title.as_str()).unwrap_or(""),
            candidate
                .map(|value| if value.user_set { "user" } else { "auto" })
                .unwrap_or(""),
            account_identity,
        ];
        // Per-session carrier revision revisits reachable indexed files once
        // through the existing bounded scan; no accepted-history repair. Census
        // recovery/loss must also re-evaluate the retained original witness.
        parts.extend([
            "original_session_carrier:v1",
            &original_identity,
            if self.original_identity_census_incomplete {
                "incomplete"
            } else {
                "complete"
            },
        ]);
        // Appended only when a link exists, so sessions nobody spawned keep
        // their fingerprint and only spawned children re-emit once.
        if let Some(lineage) = self.spawn_lineage.get(source_session_id) {
            parts.extend([
                "desktop_spawn_lineage:v1",
                lineage.parent_session_id.as_str(),
            ]);
        }
        sha256_hex(&parts)
    }

    pub(in crate::snapshots) fn spawn_lineage(
        &self,
        source_session_id: &str,
    ) -> Option<&ClaudeDesktopSpawnLineage> {
        self.spawn_lineage.get(source_session_id)
    }

    pub(in crate::snapshots) fn note_completed_account_holds(&mut self, index: &ScanIndex) {
        for key in index.claude_account_deferred_holds.keys() {
            let Some(session) = Path::new(key).file_stem().and_then(|name| name.to_str()) else {
                continue;
            };
            if index.files.contains_key(key)
                && self.session_account_evidence(session).identity_disposition == Some("complete")
            {
                self.recovered_account_holds.insert(key.clone());
            }
        }
    }

    #[cfg(test)]
    pub(in crate::snapshots) fn load_from_roots(roots: &[PathBuf]) -> Self {
        let mut index = ScanIndex::default();
        Self::load_from_roots_with_index(roots, &mut index, "2026-07-31T00:00:00Z")
    }

    pub(in crate::snapshots) fn load_from_roots_with_index(
        roots: &[PathBuf],
        index: &mut ScanIndex,
        collected_at: &str,
    ) -> Self {
        let mut store_dirs = BTreeSet::new();
        let mut census = ClaudeDesktopStoreCensus::default();
        let homes = roots
            .iter()
            .filter_map(|root| root.parent().and_then(Path::parent))
            .collect::<BTreeSet<_>>();
        for home in homes {
            let discovery = crate::claude_desktop::discover_support_roots(home);
            census.profile_read_count += discovery.roots.len();
            census.profile_discovery_incomplete_count +=
                usize::from(discovery.capped || discovery.error);
            store_dirs.extend(
                discovery
                    .roots
                    .into_iter()
                    .map(|root| root.join("claude-code-sessions")),
            );
        }
        Self::load_from_store_dirs_with_census(&store_dirs, index, collected_at, census)
    }

    #[cfg(test)]
    pub(in crate::snapshots) fn load_from_store_dirs_with_index(
        store_dirs: &BTreeSet<PathBuf>,
        index: &mut ScanIndex,
        collected_at: &str,
    ) -> Self {
        Self::load_from_store_dirs_with_census(
            store_dirs,
            index,
            collected_at,
            ClaudeDesktopStoreCensus::default(),
        )
    }

    fn load_from_store_dirs_with_census(
        store_dirs: &BTreeSet<PathBuf>,
        index: &mut ScanIndex,
        collected_at: &str,
        mut census: ClaudeDesktopStoreCensus,
    ) -> Self {
        let now = rfc3339_unix_seconds(collected_at);
        let retry_due = match (
            now,
            index.claude_desktop_store_retry_not_before_unix_seconds,
        ) {
            (_, None) => true,
            (Some(now), Some(deadline)) => {
                now >= deadline || deadline > now.saturating_add(UNHEALTHY_SCAN_RETRY_MAX_SECONDS)
            }
            (None, Some(_)) => true,
        };
        // Keep the existing 64-byte inventory decoder boundary. The non-hex
        // version marker distinguishes this 248-bit cursor fence from #851's
        // legacy SHA-256 digest. This is never account/identity proof.
        let mut inventory = claude_request_identity::inventory_digest(store_dirs);
        inventory.replace_range(..2, "p1");
        if index.claude_desktop_store_inventory.as_ref() != Some(&inventory) {
            index.claude_desktop_store_inventory = Some(inventory);
            census.inventory_sweep_restart_count += 1;
            index.claude_desktop_store_cursor = None;
            index.claude_desktop_store_upper_bound = None;
            index.claude_desktop_store_sweep_had_errors = false;
            index.claude_desktop_identity_census_complete = false;
            index.claude_desktop_lineage_census_complete = false;
        }
        // A newly discovered profile may hold a conflicting copy. Until the
        // whole inventory is read, an old census cannot prove uniqueness.
        if census.has_errors() {
            index.claude_desktop_identity_census_complete = false;
            index.claude_desktop_lineage_census_complete = false;
        }
        if !retry_due {
            crate::local_resource_diagnostics::traversal_point(
                "claude_desktop_store_deferred_alarm",
                "claude_code",
                &census,
            );
            return Self::from_durable_index_with_metadata(
                index,
                Self {
                    sidecar_census_incomplete: true,
                    original_identity_census_incomplete: !index
                        .claude_desktop_identity_census_complete,
                    ..Self::default()
                },
            );
        }

        let mut metadata = Self::default();
        let mut selection = BoundedPathSelection::new(
            index.claude_desktop_store_cursor.clone(),
            index.claude_desktop_store_upper_bound.clone(),
            MAX_CLAUDE_DESKTOP_SESSION_FILES,
        );
        let mut remaining_entries = MAX_CLAUDE_DESKTOP_STORE_ENTRIES_PER_SCAN;
        for (position, dir) in store_dirs.iter().enumerate() {
            collect_claude_desktop_session_files(
                dir,
                0,
                &mut remaining_entries,
                &mut selection,
                &mut census,
            );
            if remaining_entries == 0 {
                if position + 1 < store_dirs.len() {
                    census.entry_budget_exceeded_count += 1;
                }
                break;
            }
        }
        let (session_files, sweep_complete, next_cursor, next_upper_bound) =
            selection.finish(census.discovered_file_count);
        // The retained store entries already record which profile sources were
        // read. Count a profile once when its first valid session is acquired;
        // later refreshes are not new-source reads. No new persistent registry.
        let mut new_profiles = store_dirs
            .iter()
            .filter(|dir| {
                !index
                    .claude_desktop_title_files
                    .keys()
                    .any(|path| Path::new(path).starts_with(dir))
            })
            .cloned()
            .collect::<BTreeSet<_>>();
        let mut original_identity_changed = false;
        let mut lineage_changed = false;
        for path in &session_files {
            let account_identifier_hash = store_dirs
                .iter()
                .find_map(|store_dir| claude_desktop_account_identifier_hash(store_dir, path));
            let original_identity = store_dirs
                .iter()
                .find_map(|store_dir| claude_desktop_original_identity(store_dir, path));
            match load_claude_desktop_session_title(
                path,
                account_identifier_hash,
                original_identity,
            ) {
                Ok(Some(entry)) => {
                    if let Some(profile) = new_profiles
                        .iter()
                        .find(|dir| path.starts_with(dir))
                        .cloned()
                    {
                        new_profiles.remove(&profile);
                        census.profile_new_source_read_count += 1;
                    }
                    let previous = index.claude_desktop_title_files.get(&local_index_key(path));
                    original_identity_changed |= previous.map_or(true, |previous| {
                        previous.cli_session_id != entry.cli_session_id
                            || previous.original_identity != entry.original_identity
                    });
                    lineage_changed |= previous.map_or(true, |previous| {
                        previous.cli_session_id != entry.cli_session_id
                            || previous.desktop_session_id != entry.desktop_session_id
                            || previous.spawned_from_desktop_session_id
                                != entry.spawned_from_desktop_session_id
                            || previous.spawned_from_unresolved != entry.spawned_from_unresolved
                            || previous
                                .original_identity
                                .as_ref()
                                .and_then(|identity| identity.source_created_at.as_ref())
                                != entry
                                    .original_identity
                                    .as_ref()
                                    .and_then(|identity| identity.source_created_at.as_ref())
                    });
                    index
                        .claude_desktop_title_files
                        .insert(local_index_key(path), entry);
                }
                Ok(None) => {
                    original_identity_changed |= index
                        .claude_desktop_title_files
                        .get(&local_index_key(path))
                        .is_some_and(|entry| entry.original_identity.is_some());
                    lineage_changed |= index
                        .claude_desktop_title_files
                        .get(&local_index_key(path))
                        .is_some_and(|entry| {
                            entry.desktop_session_id.is_some()
                                || entry.spawned_from_desktop_session_id.is_some()
                                || entry.spawned_from_unresolved
                        });
                    index
                        .claude_desktop_title_files
                        .remove(&local_index_key(path));
                }
                Err(_) => census.invalid_file_count += 1,
            }
        }
        let sweep_had_errors = index.claude_desktop_store_sweep_had_errors || census.has_errors();
        if sweep_complete && !sweep_had_errors {
            index
                .claude_desktop_title_files
                .retain(|path, _| census.observed_paths.contains(path));
        }
        metadata.sidecar_census_incomplete = !sweep_complete || sweep_had_errors;
        if sweep_had_errors || (!sweep_complete && original_identity_changed) {
            index.claude_desktop_identity_census_complete = false;
        } else if sweep_complete {
            index.claude_desktop_identity_census_complete = true;
        }
        metadata.original_identity_census_incomplete =
            !index.claude_desktop_identity_census_complete;
        if sweep_had_errors || (!sweep_complete && lineage_changed) {
            index.claude_desktop_lineage_census_complete = false;
        } else if sweep_complete {
            index.claude_desktop_lineage_census_complete = true;
        }
        index.claude_desktop_store_cursor = next_cursor;
        index.claude_desktop_store_upper_bound = next_upper_bound;
        index.claude_desktop_store_sweep_had_errors = if sweep_complete {
            false
        } else {
            sweep_had_errors
        };

        if metadata.sidecar_census_incomplete {
            index.claude_desktop_store_retry_attempt =
                index.claude_desktop_store_retry_attempt.saturating_add(1);
            let now = now.unwrap_or_default();
            index.claude_desktop_store_retry_not_before_unix_seconds = Some(now.saturating_add(
                unhealthy_scan_retry_delay_seconds(index.claude_desktop_store_retry_attempt),
            ));
        } else {
            index.claude_desktop_store_retry_attempt = 0;
            index.claude_desktop_store_retry_not_before_unix_seconds = None;
        }

        crate::local_resource_diagnostics::traversal_point(
            if metadata.sidecar_census_incomplete {
                "claude_desktop_store_deferred_alarm"
            } else {
                "claude_desktop_store_census"
            },
            "claude_code",
            &census,
        );
        Self::from_durable_index_with_metadata(index, metadata)
    }

    #[cfg(test)]
    pub(in crate::snapshots) fn from_durable_index(
        index: &ScanIndex,
        sidecar_census_incomplete: bool,
    ) -> Self {
        Self::from_durable_index_with_metadata(
            index,
            Self {
                sidecar_census_incomplete,
                original_identity_census_incomplete: sidecar_census_incomplete,
                ..Self::default()
            },
        )
    }

    fn from_durable_index_with_metadata(index: &ScanIndex, mut metadata: Self) -> Self {
        for entry in index.claude_desktop_title_files.values() {
            if let Some(original_identity) = &entry.original_identity {
                metadata
                    .original_identity_evidence
                    .entry(entry.cli_session_id.clone())
                    .or_default()
                    .insert(original_identity.clone());
            }
            if let Some(account_identifier_hash) = &entry.account_identifier_hash {
                metadata
                    .account_identifier_hashes
                    .entry(entry.cli_session_id.clone())
                    .or_default()
                    .insert(account_identifier_hash.clone());
            }
            let Some(title) = &entry.title else {
                continue;
            };
            let candidate = ClaudeTitleCandidate {
                title: title.clone(),
                user_set: entry.user_set,
            };
            match metadata.titles.get(entry.cli_session_id.as_str()) {
                Some(existing) if existing.user_set && !candidate.user_set => {}
                _ => {
                    metadata
                        .titles
                        .insert(entry.cli_session_id.clone(), candidate);
                }
            }
        }
        if index.claude_desktop_lineage_census_complete {
            metadata.spawn_lineage = claude_desktop_spawn_lineage(
                index.claude_desktop_title_files.values(),
                |cli_session_id| {
                    let file_name = format!("{cli_session_id}.jsonl");
                    claude_transcript_live_window(index.files.keys().map(Path::new).filter(
                        |path| {
                            path.file_name().and_then(|name| name.to_str())
                                == Some(file_name.as_str())
                        },
                    ))
                },
            );
        }
        let sidecar_parts = metadata
            .titles
            .iter()
            .map(|(id, candidate)| format!("{id}:{}:{}", candidate.user_set, candidate.title))
            .collect::<Vec<_>>();
        metadata.legacy_sidecar_fingerprint = sha256_hex_owned(&sidecar_parts);
        metadata
    }
}

/// When the earliest and latest event of one transcript were written, as far
/// as a bounded read of its head and tail shows. Both ends lean wide: copied
/// history pulls the start earlier and a later record only moves the end out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::snapshots) struct ClaudeTranscriptLiveWindow {
    pub(in crate::snapshots) first_unix_nanos: i128,
    pub(in crate::snapshots) last_unix_nanos: i128,
}

/// A transcript counts as live this long before its first and after its last
/// event, so a boundary case refuses instead of picking.
const CLAUDE_DESKTOP_SPAWN_LIVE_MARGIN_NANOS: i128 = 60 * 1_000_000_000;
pub(in crate::snapshots) const CLAUDE_TRANSCRIPT_WINDOW_READ_BYTES: u64 = 256 * 1024;
const CLAUDE_TRANSCRIPT_WINDOW_CACHE_ENTRIES: usize = 256;

/// Resolve each desktop `spawnedFrom` link to the parent's transcript id.
///
/// The edge is kept only when every store file for the child agrees on one
/// parent desktop id, that desktop id leads to exactly one other transcript,
/// both transcript ids are canonical UUIDs (the only form a fact may carry, so
/// a path or malformed `cliSessionId` never leaves the device), and the child
/// is not on a cycle. The chain above the parent is walked only to refuse
/// cycles; no root or depth is derived from it.
///
/// A desktop session that switched transcripts keeps one `cliSessionId` per
/// store copy. Only then is `transcript_window` consulted: the parent is the
/// one candidate whose live window holds the child's single store `createdAt`.
/// A missing time or window, or more than one live candidate, refuses.
fn claude_desktop_spawn_lineage<'a>(
    entries: impl Iterator<Item = &'a ClaudeDesktopTitleIndexEntry>,
    mut transcript_window: impl FnMut(&str) -> Option<ClaudeTranscriptLiveWindow>,
) -> BTreeMap<String, ClaudeDesktopSpawnLineage> {
    let exportable = |session: &str| {
        crate::claude_local_otel::canonical_uuid(session).as_deref() == Some(session)
    };
    let mut cli_by_desktop: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    let mut parent_desktop_by_cli: BTreeMap<&str, BTreeSet<Option<&str>>> = BTreeMap::new();
    let mut created_at_by_cli: BTreeMap<&str, BTreeSet<Option<&str>>> = BTreeMap::new();
    let mut unresolved_parent: BTreeSet<&str> = BTreeSet::new();
    for entry in entries {
        if let Some(desktop_id) = entry.desktop_session_id.as_deref() {
            cli_by_desktop
                .entry(desktop_id)
                .or_default()
                .insert(entry.cli_session_id.as_str());
        }
        parent_desktop_by_cli
            .entry(entry.cli_session_id.as_str())
            .or_default()
            .insert(entry.spawned_from_desktop_session_id.as_deref());
        created_at_by_cli
            .entry(entry.cli_session_id.as_str())
            .or_default()
            .insert(
                entry
                    .original_identity
                    .as_ref()
                    .and_then(|identity| identity.source_created_at.as_deref()),
            );
        if entry.spawned_from_unresolved {
            unresolved_parent.insert(entry.cli_session_id.as_str());
        }
    }
    let mut windows: BTreeMap<&str, Option<ClaudeTranscriptLiveWindow>> = BTreeMap::new();
    // The one transcript that started `session`, or None when nobody did or
    // the store is missing, conflicting, self-referential, undatable or not
    // exportable.
    let mut resolve = |session: &str| -> Option<&str> {
        if unresolved_parent.contains(session) {
            return None;
        }
        let parents = parent_desktop_by_cli.get(session)?;
        let [Some(parent_desktop_id)] = parents.iter().copied().collect::<Vec<_>>()[..] else {
            return None;
        };
        let clis = cli_by_desktop.get(parent_desktop_id)?;
        if clis.contains(session) {
            return None;
        }
        let parent = match clis.iter().copied().collect::<Vec<_>>()[..] {
            [parent] => parent,
            _ => {
                let [Some(created_at)] = created_at_by_cli
                    .get(session)?
                    .iter()
                    .copied()
                    .collect::<Vec<_>>()[..]
                else {
                    return None;
                };
                let created_at = rfc3339_unix_nanos(created_at)?;
                let mut live = None;
                for &candidate in clis {
                    let window = *windows
                        .entry(candidate)
                        .or_insert_with(|| transcript_window(candidate));
                    let window = window?;
                    if window.first_unix_nanos - CLAUDE_DESKTOP_SPAWN_LIVE_MARGIN_NANOS
                        <= created_at
                        && created_at
                            <= window.last_unix_nanos + CLAUDE_DESKTOP_SPAWN_LIVE_MARGIN_NANOS
                        && live.replace(candidate).is_some()
                    {
                        return None;
                    }
                }
                live?
            }
        };
        exportable(parent).then_some(parent)
    };
    let mut lineage = BTreeMap::new();
    'children: for &child in parent_desktop_by_cli.keys() {
        if !exportable(child) {
            continue;
        }
        let Some(parent) = resolve(child) else {
            continue;
        };
        // Bounded by `seen`, so cycle membership is decided at any length.
        let mut seen = BTreeSet::from([child, parent]);
        let mut ancestor = parent;
        while let Some(next) = resolve(ancestor) {
            if next == child {
                // The child is on a cycle: no edge it is part of is real.
                continue 'children;
            }
            if !seen.insert(next) {
                break;
            }
            ancestor = next;
        }
        lineage.insert(
            child.to_string(),
            ClaudeDesktopSpawnLineage {
                parent_session_id: parent.to_string(),
            },
        );
    }
    lineage
}

/// The live window across every indexed transcript file of one session, or
/// None when there is none or any of them cannot be dated.
fn claude_transcript_live_window<'p>(
    paths: impl Iterator<Item = &'p Path>,
) -> Option<ClaudeTranscriptLiveWindow> {
    let mut union: Option<ClaudeTranscriptLiveWindow> = None;
    for path in paths {
        let window = claude_transcript_file_live_window(path)?;
        union = Some(match union {
            None => window,
            Some(union) => ClaudeTranscriptLiveWindow {
                first_unix_nanos: union.first_unix_nanos.min(window.first_unix_nanos),
                last_unix_nanos: union.last_unix_nanos.max(window.last_unix_nanos),
            },
        });
    }
    union
}

/// Cached per path on size, mtime and birth time, so an idle transcript costs
/// one stat per scan and only a written one is read again.
pub(in crate::snapshots) fn claude_transcript_file_live_window(
    path: &Path,
) -> Option<ClaudeTranscriptLiveWindow> {
    type StatKey = (u64, Option<SystemTime>, Option<SystemTime>);
    type Cached = (StatKey, Option<ClaudeTranscriptLiveWindow>);
    static CACHE: OnceLock<Mutex<BTreeMap<PathBuf, Cached>>> = OnceLock::new();
    let stat_key = |metadata: &fs::Metadata| -> StatKey {
        (
            metadata.len(),
            metadata.modified().ok(),
            metadata.created().ok(),
        )
    };
    let metadata = fs::symlink_metadata(path).ok()?;
    if !metadata.is_file() {
        return None;
    }
    let cache = CACHE.get_or_init(Mutex::default);
    let key = stat_key(&metadata);
    if let Some((cached_key, window)) = cache
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .get(path)
    {
        if *cached_key == key {
            return *window;
        }
    }
    let (key, window) = match read_claude_transcript_live_window(path) {
        Ok((metadata, window)) => (stat_key(&metadata), window),
        Err(_) => (key, None),
    };
    let mut cache = cache
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if cache.len() >= CLAUDE_TRANSCRIPT_WINDOW_CACHE_ENTRIES && !cache.contains_key(path) {
        cache.clear();
    }
    cache.insert(path.to_path_buf(), (key, window));
    window
}

/// Reads at most the first and last `CLAUDE_TRANSCRIPT_WINDOW_READ_BYTES` and
/// takes the top-level `timestamp` of each whole line there; each read must
/// yield one. The start is also capped by the file's birth time where the
/// platform has one.
fn read_claude_transcript_live_window(
    path: &Path,
) -> Result<(fs::Metadata, Option<ClaudeTranscriptLiveWindow>)> {
    #[derive(Deserialize)]
    struct Stamp {
        timestamp: Option<String>,
    }
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
    let mut file = options.open(path).context("open Claude transcript")?;
    let metadata = file.metadata().context("stat Claude transcript")?;
    if !metadata.is_file() {
        return Err(anyhow::anyhow!("Claude transcript was not a file"));
    }
    crate::local_resource_diagnostics::claude_reread::desktop_lineage_window_read();
    let len = metadata.len();
    let bound = CLAUDE_TRANSCRIPT_WINDOW_READ_BYTES;
    // (bytes, starts at a line start, ends at a line end)
    let mut regions = Vec::new();
    let mut head = Vec::new();
    (&mut file)
        .take(bound.min(len))
        .read_to_end(&mut head)
        .context("read Claude transcript head")?;
    let head_is_whole = len <= bound.saturating_mul(2);
    if head_is_whole {
        file.take(len.saturating_sub(head.len() as u64))
            .read_to_end(&mut head)
            .context("read Claude transcript")?;
        regions.push((head, true, true));
    } else {
        regions.push((head, true, false));
        let mut tail = Vec::new();
        file.seek(SeekFrom::Start(len - bound))
            .context("seek Claude transcript tail")?;
        file.take(bound)
            .read_to_end(&mut tail)
            .context("read Claude transcript tail")?;
        regions.push((tail, false, true));
    }
    let mut first: Option<i128> = None;
    let mut last: Option<i128> = None;
    for (bytes, starts_whole, ends_whole) in &regions {
        let mut lines = bytes.split(|byte| *byte == b'\n').collect::<Vec<_>>();
        if !ends_whole {
            lines.pop();
        }
        let skip = usize::from(!starts_whole);
        let mut region_dated = false;
        for line in lines.into_iter().skip(skip) {
            let Some(stamp) = serde_json::from_slice::<Stamp>(line)
                .ok()
                .and_then(|stamp| stamp.timestamp)
                .and_then(|stamp| rfc3339_unix_nanos(&stamp))
            else {
                continue;
            };
            region_dated = true;
            first = Some(first.map_or(stamp, |first| first.min(stamp)));
            last = Some(last.map_or(stamp, |last| last.max(stamp)));
        }
        // A head or tail filled by one oversized record cannot place that
        // end; the other region's stamps would understate the window.
        if !region_dated {
            return Ok((metadata, None));
        }
    }
    let born = metadata
        .created()
        .ok()
        .and_then(|born| born.duration_since(UNIX_EPOCH).ok())
        .map(|born| born.as_nanos() as i128);
    let window = first
        .zip(last)
        .map(|(first, last)| ClaudeTranscriptLiveWindow {
            first_unix_nanos: born.map_or(first, |born| born.min(first)),
            last_unix_nanos: last,
        });
    Ok((metadata, window))
}

pub(in crate::snapshots) fn claude_desktop_store_inventory_is_legacy(
    inventory: &Option<String>,
) -> bool {
    inventory
        .as_deref()
        .map_or(true, |value| value.len() != 64 || !value.starts_with("p1"))
}

#[derive(Debug, Default, Serialize)]
struct ClaudeDesktopStoreCensus {
    profile_read_count: usize,
    profile_new_source_read_count: usize,
    store_found_count: usize,
    inventory_sweep_restart_count: usize,
    profile_discovery_incomplete_count: usize,
    discovered_file_count: usize,
    unreadable_path_count: usize,
    symlink_rejected_count: usize,
    depth_exceeded_count: usize,
    invalid_file_count: usize,
    entry_budget_exceeded_count: usize,
    #[serde(skip)]
    observed_paths: BTreeSet<String>,
}

impl ClaudeDesktopStoreCensus {
    fn has_errors(&self) -> bool {
        self.profile_discovery_incomplete_count > 0
            || self.unreadable_path_count > 0
            || self.symlink_rejected_count > 0
            || self.depth_exceeded_count > 0
            || self.invalid_file_count > 0
            || self.entry_budget_exceeded_count > 0
    }
}

#[derive(Debug)]
struct BoundedPathSelection {
    cursor: Option<String>,
    upper_bound: Option<String>,
    limit: usize,
    selected: BTreeMap<String, PathBuf>,
    observed_max: Option<String>,
}

impl BoundedPathSelection {
    fn new(cursor: Option<String>, upper_bound: Option<String>, limit: usize) -> Self {
        let cursor = cursor.filter(|_| upper_bound.is_some());
        Self {
            cursor,
            upper_bound,
            limit,
            selected: BTreeMap::new(),
            observed_max: None,
        }
    }

    fn insert(&mut self, path: PathBuf) {
        let key = local_index_key(&path);
        if self
            .observed_max
            .as_ref()
            .map_or(true, |maximum| key > *maximum)
        {
            self.observed_max = Some(key.clone());
        }
        if self.limit == 0
            || self
                .upper_bound
                .as_ref()
                .is_some_and(|upper_bound| key > *upper_bound)
            || self.cursor.as_ref().is_some_and(|cursor| key <= *cursor)
        {
            return;
        }
        self.selected.insert(key, path);
        if self.selected.len() > self.limit {
            self.selected.pop_last();
        }
    }

    fn finish(self, discovered: usize) -> (Vec<PathBuf>, bool, Option<String>, Option<String>) {
        let upper_bound = self.upper_bound.or(self.observed_max);
        let selected = self.selected.into_values().collect::<Vec<_>>();
        let next_cursor = selected.last().map(|path| local_index_key(path));
        let reached_upper_bound = next_cursor
            .as_ref()
            .zip(upper_bound.as_ref())
            .is_some_and(|(cursor, upper_bound)| cursor >= upper_bound);
        let complete = if self.limit == 0 {
            discovered == 0
        } else {
            selected.len() < self.limit || reached_upper_bound
        };
        (
            selected,
            complete,
            (!complete).then_some(next_cursor).flatten(),
            (!complete).then_some(upper_bound).flatten(),
        )
    }
}

fn collect_claude_desktop_session_files(
    dir: &Path,
    depth: usize,
    remaining_entries: &mut usize,
    selection: &mut BoundedPathSelection,
    census: &mut ClaudeDesktopStoreCensus,
) {
    if depth > MAX_CLAUDE_DESKTOP_STORE_DEPTH {
        census.depth_exceeded_count += 1;
        return;
    }
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return,
        Err(_) => {
            census.unreadable_path_count += 1;
            return;
        }
    };
    if depth == 0 {
        census.store_found_count += 1;
    }
    for entry in entries {
        if *remaining_entries == 0 {
            census.entry_budget_exceeded_count += 1;
            return;
        }
        *remaining_entries -= 1;
        let entry = match entry {
            Ok(entry) => entry,
            Err(_) => {
                census.unreadable_path_count += 1;
                continue;
            }
        };
        let path = entry.path();
        let file_type = match entry.file_type() {
            Ok(file_type) => file_type,
            Err(_) => {
                census.unreadable_path_count += 1;
                continue;
            }
        };
        if file_type.is_symlink() {
            census.symlink_rejected_count += 1;
            continue;
        }
        if file_type.is_dir() {
            collect_claude_desktop_session_files(
                &path,
                depth + 1,
                remaining_entries,
                selection,
                census,
            );
            continue;
        }
        if !file_type.is_file() {
            continue;
        }
        if path.extension().and_then(|value| value.to_str()) != Some("json") {
            continue;
        }
        census.discovered_file_count += 1;
        census.observed_paths.insert(local_index_key(&path));
        selection.insert(path);
    }
}

pub(in crate::snapshots) fn claude_desktop_account_identifier_hash(
    store_dir: &Path,
    path: &Path,
) -> Option<String> {
    let account_uuid = path
        .strip_prefix(store_dir)
        .ok()
        .and_then(|relative| relative.components().next())
        .and_then(|component| match component {
            Component::Normal(value) => value.to_str(),
            _ => None,
        });
    account_uuid.and_then(|uuid| ottto_core::billing_identity_hash("anthropic", "account", uuid))
}

pub(in crate::snapshots) fn claude_desktop_original_identity(
    store_dir: &Path,
    path: &Path,
) -> Option<ClaudeDesktopIdentityEvidence> {
    let relative = path.strip_prefix(store_dir).ok()?;
    let mut parts = relative.components();
    let mut native_hash = |role: &str| {
        let Component::Normal(part) = parts.next()? else {
            return None;
        };
        let value = crate::claude_local_otel::canonical_uuid(part.to_str()?)?;
        ottto_core::billing_identity_hash("anthropic", role, &value)
    };
    Some(ClaudeDesktopIdentityEvidence {
        account_identifier_hash: native_hash("account"),
        provider_workspace_hash: native_hash("organization"),
        source_created_at: None,
        imported: false,
    })
}

pub(in crate::snapshots) fn load_claude_desktop_session_title(
    path: &Path,
    account_identifier_hash: Option<String>,
    mut original_identity: Option<ClaudeDesktopIdentityEvidence>,
) -> Result<Option<ClaudeDesktopTitleIndexEntry>> {
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
    let file = options
        .open(path)
        .context("open Claude desktop title sidecar")?;
    let metadata = file
        .metadata()
        .context("stat Claude desktop title sidecar")?;
    if !metadata.is_file() || metadata.len() > MAX_CLAUDE_DESKTOP_SESSION_FILE_BYTES {
        return Err(anyhow::anyhow!("Claude desktop title sidecar was invalid"));
    }
    let mut bytes = Vec::new();
    file.take(MAX_CLAUDE_DESKTOP_SESSION_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .context("read Claude desktop title sidecar")?;
    if bytes.len() as u64 > MAX_CLAUDE_DESKTOP_SESSION_FILE_BYTES {
        return Err(anyhow::anyhow!("Claude desktop title sidecar exceeded cap"));
    }
    let value =
        serde_json::from_slice::<Value>(&bytes).context("parse Claude desktop title sidecar")?;
    // Non-session JSONs in the store (e.g. scheduled-tasks.json) lack these
    // fields and fall out here.
    let cli_session_id = match string_at(&value, &["cliSessionId"]) {
        Some(cli_session_id) => cli_session_id,
        None if value.get("cliSessionId").is_none() => return Ok(None),
        None => {
            return Err(anyhow::anyhow!(
                "Claude desktop title sidecar session id was invalid"
            ));
        }
    };
    let title = match string_at(&value, &["title"]) {
        Some(title) => Some(title),
        None if value.get("title").is_none() => None,
        None => {
            return Err(anyhow::anyhow!(
                "Claude desktop title sidecar title was invalid"
            ));
        }
    };
    let user_set =
        title.is_some() && string_at(&value, &["titleSource"]).as_deref() == Some("user");
    if let Some(identity) = &mut original_identity {
        // Any present import marker (including malformed/unknown tags) vetoes
        // treating the destination bucket as original. Never retain its raw value.
        identity.imported = value.get("importedFrom").is_some();
        // Native creation is separate from minimum retained transcript activity:
        // a resumed or truncated suffix must never manufacture a later creator.
        identity.source_created_at = value.get("createdAt").and_then(|value| {
            if let Some(text) = value.as_str() {
                if OffsetDateTime::parse(text, &Rfc3339).is_ok() {
                    return Some(text.to_string());
                }
            }
            let millis = value.as_i64().or_else(|| value.as_str()?.parse().ok())?;
            bounded_rfc3339_millis(millis)
        });
    }
    // Lineage ids are optional: a missing or malformed one leaves the session
    // unlinked and never invalidates its title. They are identities, so they are
    // read byte-exact rather than through the trimming `string_at`: a padded id
    // is malformed, never normalized into a link. A padded `cliSessionId` keeps
    // its trimmed title match but contributes no lineage in either direction.
    let lineage_ids_exact =
        codex_identity_at(&value, &["cliSessionId"]).as_deref() == Some(cli_session_id.as_str());
    let lineage_id_at = |path: &[&str]| {
        codex_identity_at(&value, path)
            .filter(|id| lineage_ids_exact && is_claude_desktop_session_id(id))
    };
    let desktop_session_id = lineage_id_at(&["sessionId"]);
    let spawned_from_desktop_session_id = lineage_id_at(&["spawnedFrom", "sessionId"]);
    let spawned_from_unresolved = spawned_from_desktop_session_id.is_none()
        && value
            .get("spawnedFrom")
            .is_some_and(|value| !value.is_null());
    Ok(Some(ClaudeDesktopTitleIndexEntry {
        cli_session_id,
        title,
        user_set,
        account_identifier_hash,
        original_identity,
        desktop_session_id,
        spawned_from_desktop_session_id,
        spawned_from_unresolved,
    }))
}

/// Desktop session ids are compact `local_<uuid>`-style tokens; anything else
/// is not retained.
fn is_claude_desktop_session_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 96
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
}

crate::heap_layout_bound::fields!(ClaudeDesktopIdentityEvidence; account_identifier_hash, provider_workspace_hash, source_created_at, imported);
crate::heap_layout_bound::fields!(ClaudeDesktopSpawnLineage; parent_session_id);
crate::heap_layout_bound::fields!(ClaudeDesktopTitleIndexEntry; cli_session_id, title, user_set, account_identifier_hash, original_identity, desktop_session_id, spawned_from_desktop_session_id, spawned_from_unresolved);
crate::heap_layout_bound::fields!(ClaudeTitleCandidate; title, user_set);
crate::heap_layout_bound::fields!(ClaudeTitleMetadata; titles, account_identifier_hashes, original_identity_evidence, spawn_lineage, recovered_account_holds, legacy_sidecar_fingerprint, sidecar_census_incomplete, original_identity_census_incomplete);
