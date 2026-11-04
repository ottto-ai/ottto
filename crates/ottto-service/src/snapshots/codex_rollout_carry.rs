//! Proven Codex rollout path/encoding changes, before selection or retirement.
//! Logical progress and delivery witnesses move unchanged. Physical inventory
//! is independent: compression never certifies a replacement plaintext inode.
use super::sampled_scan::codex_cursor::OpenStamp;
use super::*;
use anyhow::{ensure, Context};

fn root_of(path: &Path) -> Option<&Path> {
    path.ancestors().find(|root| {
        matches!(
            root.file_name().and_then(|name| name.to_str()),
            Some("sessions" | "archived_sessions")
        )
    })
}
fn absent(path: &Path) -> bool {
    matches!(fs::symlink_metadata(path), Err(error) if error.kind() == std::io::ErrorKind::NotFound)
}
pub(super) fn physical_matches(head: &state_v2::TailHead, metadata: &fs::Metadata) -> bool {
    // A header refresh must never make newly appended bytes look applied.
    // Its inventory stamp is seeded only at the logical checkpoint or carry;
    // a later ordinary checkpoint can supersede that older physical stamp.
    head.common.inventory.as_ref().is_some_and(|facts| {
        crate::transcript_acquisition::FileStamp::capture(metadata.clone())
            .is_ok_and(|stamp| facts.stamp.matches_acquisition(&stamp))
    }) || tail_source::certified_physical_matches(&head.body, metadata)
}

impl ScanIndex {
    /// One physical equality seam for listing, hints, selection and freshness.
    /// A legacy head uses its existing object certificate; no historical read.
    pub(super) fn codex_physical_matches(
        &self,
        key: &str,
        metadata: &fs::Metadata,
    ) -> Result<Option<bool>> {
        if state_v2::runtime_path(self)?.is_none() {
            return Ok(None);
        }
        let head = state_v2::load_head(
            self,
            key,
            <tail_source::codex::Codex as tail_source::TailSource>::REDUCTION_REVISION,
        )?;
        Ok(head
            .as_ref()
            .filter(|head| !head.metadata_only)
            .map(|head| physical_matches(head, metadata)))
    }

    /// Physical equality refines the ordinary decision without replacing its
    /// audit, evidence, exact-body/context or sidecar dependency authority.
    pub(super) fn codex_unchanged_decision(
        &self,
        candidate: &CandidateFile,
        metadata: &CodexTitleMetadata,
        now: u64,
        body_witness_adoption: bool,
    ) -> Result<Option<(CandidateDecision, Option<CandidateParseReason>)>> {
        let key = local_index_key(&candidate.path);
        let file = open_candidate_beneath_root(candidate)?;
        let stat = file.metadata()?;
        if self.codex_physical_matches(&key, &stat)? != Some(true) {
            return Ok(None);
        }
        let revision = <tail_source::codex::Codex as tail_source::TailSource>::REDUCTION_REVISION;
        let head = state_v2::load_head(self, &key, revision)?.context("codex_carry_certificate")?;
        let binding = Some(metadata.path_reduction_fingerprint(&candidate.path))
            .filter(|value| !value.is_empty());
        if tail_source::codex::header_facts(head.revision, &head.body)
            .map_err(|_| anyhow::anyhow!("codex_carry_certificate"))?
            .0
            != binding
        {
            return Ok(None);
        }
        let entry = self.files.get(&key).context("codex_carry_progress")?;
        let mut logical = candidate.clone();
        logical.size_bytes = entry.size_bytes;
        logical.modified_unix_seconds = entry.modified_unix_seconds;
        logical.modified_unix_nanos = entry
            .modified_unix_nanos
            .unwrap_or(entry.modified_unix_seconds.saturating_mul(1_000_000_000));
        logical
            .source_file_fingerprint
            .clone_from(&entry.source_file_fingerprint);
        Ok(Some(self.candidate_decision_with_reason_gated(
            &logical,
            now,
            body_witness_adoption,
        )))
    }

    /// One pass after both discovery routes, before selection and absence.
    /// Only unindexed paths naming an existing owner need a physical probe.
    pub(super) fn prepare_codex_carries(
        &mut self,
        sampling: Option<(
            &sampled_scan::SharedCache,
            Option<&crate::transcript_acquisition::Scope>,
        )>,
    ) -> BTreeSet<String> {
        let candidates = {
            let Some(walk) = self.traversal.as_ref() else {
                return BTreeSet::new();
            };
            let owners = self
                .files
                .values()
                .filter_map(|entry| codex_counting_version::proven_owner(entry))
                .collect::<BTreeSet<_>>();
            walk.codex_rollout_paths
                .iter()
                .filter_map(|key| {
                    let path = Path::new(key);
                    if self.files.contains_key(key)
                        || codex_file_join::shadowed_compressed_path(
                            path,
                            &walk.codex_rollout_paths,
                        )
                        || !codex_session_id_candidates_from_path(path)
                            .iter()
                            .any(|id| owners.contains(codex_protected_owner(id).as_str()))
                    {
                        return None;
                    }
                    Some(codex_file_join::header_candidate(
                        walk.owning_scan_root(path)?.clone(),
                        path.to_path_buf(),
                        &fs::symlink_metadata(path).ok()?,
                    ))
                })
                .collect::<Vec<_>>()
        };
        let Ok(Some(route)) = state_v2::runtime_path(self) else {
            return BTreeSet::new();
        };
        candidates
            .into_iter()
            .filter_map(|candidate| {
                self.carry_codex_rollout_with_cache(&route, &candidate, sampling)
                    .err()
                    .map(|_| local_index_key(&candidate.path))
            })
            .collect()
    }

    /// Called once after discovery, before any selection or absence consumer.
    pub(super) fn carry_codex_rollout_with_cache(
        &mut self,
        index_path: &Path,
        candidate: &CandidateFile,
        sampling: Option<(
            &sampled_scan::SharedCache,
            Option<&crate::transcript_acquisition::Scope>,
        )>,
    ) -> Result<bool> {
        let to = local_index_key(&candidate.path);
        if self.files.contains_key(&to) {
            return Ok(false);
        }
        let home = codex_file_join::member_home(&candidate.scan_root);
        let sessions = codex_session_id_candidates_from_path(&candidate.path);
        let owners: BTreeSet<_> = sessions
            .iter()
            .map(|session| codex_protected_owner(session))
            .collect();
        let possible: Vec<_> = self
            .files
            .iter()
            .filter_map(|(from, entry)| {
                let owner = codex_counting_version::proven_owner(entry)
                    .filter(|owner| owners.contains(*owner))?;
                let path = Path::new(from);
                let root = self
                    .traversal
                    .as_ref()
                    .and_then(|walk| walk.owning_scan_root(path))
                    .map(PathBuf::as_path)
                    .or_else(|| root_of(path))?;
                (codex_file_join::member_home(root) == home
                    && codex_session_id_candidates_from_path(path)
                        .iter()
                        .any(|session| codex_protected_owner(session) == owner)
                    && (absent(path)
                        || codex_file_join::shadowed_compressed_path(
                            path,
                            &BTreeSet::from([to.clone()]),
                        )))
                .then(|| (from.clone(), root.to_path_buf(), owner.to_owned()))
            })
            .collect();
        if possible.is_empty() {
            return Ok(false);
        }
        // Existing observation custody also fences either retirement path if
        // a carry precondition cannot be proved in this pass.
        if let Some(walk) = self.traversal.as_mut() {
            walk.observed_index_keys
                .extend(possible.iter().map(|(from, _, _)| from.clone()));
        }
        let route = state_v2::runtime_path(self)?.context("codex_carry_route")?;
        ensure!(
            route == index_path && fs::canonicalize(&home)? == home,
            "codex_carry_route"
        );
        let file = open_candidate_beneath_root(candidate)?;
        let metadata = file.metadata()?;
        ensure!(metadata.is_file(), "codex_carry_nonregular");
        let stamp = OpenStamp::of(&metadata).content_stamp();
        let revision = <tail_source::codex::Codex as tail_source::TailSource>::REDUCTION_REVISION;
        let mut proven = Vec::new();
        for (from, old_root, owner) in possible {
            let old_path = Path::new(&from);
            let mut compressed_name = old_path.as_os_str().to_os_string();
            compressed_name.push(".zst");
            let compression = old_path.extension().is_some_and(|ext| ext == "jsonl")
                && candidate.path.as_os_str() == compressed_name.as_os_str()
                && old_path.parent() == candidate.path.parent();
            let head = state_v2::load_head(self, &from, revision)?;
            ensure!(!compression || head.is_some(), "codex_carry_certificate");
            let Some(head) = head else {
                continue;
            };
            // The two approved proofs: exact provider compression, or the same
            // object and content. Unrelated stale paths are not proof candidates.
            if compression || physical_matches(&head, &metadata) {
                ensure!(
                    !self.decode_holds_file(&from)
                        && !head.metadata_only
                        && tail_source::certified_content_stamp(&head.body).is_ok(),
                    "codex_carry_certificate"
                );
                proven.push((from, old_root, owner, head));
            }
        }
        ensure!(proven.len() <= 1, "codex_carry_ambiguous");
        let [(from, old_root, owner, head)] = proven.as_slice() else {
            return Ok(false);
        };
        let old_path = Path::new(from);
        let session = sessions
            .into_iter()
            .find(|session| codex_protected_owner(session) == *owner)
            .context("codex_carry_owner")?;
        let rebound = tail_source::carry_codex_head(
            index_path,
            old_root,
            old_path,
            &candidate.scan_root,
            &candidate.path,
            &head.body,
        )?;
        let inventory = state_v2::InventoryFacts {
            owner: session,
            created_unix_ms: head
                .common
                .inventory
                .as_ref()
                .and_then(|facts| facts.created_unix_ms),
            read_bytes: head
                .common
                .inventory
                .as_ref()
                .map_or(0, |facts| facts.read_bytes),
            stamp,
        };
        // Bracket the metadata-only proof, including predecessor absence.
        let reopened = open_candidate_beneath_root(candidate)?;
        ensure!(
            OpenStamp::capture(&reopened)?.content_stamp() == stamp
                && (absent(old_path)
                    || codex_file_join::shadowed_compressed_path(
                        old_path,
                        &BTreeSet::from([to.clone()])
                    )),
            "codex_carry_changed"
        );
        ensure!(
            !self.file_snapshot_fingerprints.contains_key(&to)
                && !self.accepted_rebuild_incidence.contains_key(&to)
                && !self.terminal_jsonl_dispositions.contains_key(&to)
                && !self.v2().growth_retention.contains_key(&to)
                && !self.confirmed_empty_files.contains(&to)
                && !self.codex_state_only_blocked_by_file.contains_key(&to),
            "codex_carry_destination_custody"
        );
        if let Some((cache, namespace)) = sampling {
            // A live job must finish or fail its ordinary path revalidation
            // before this pass can rehome its committed checkpoint.
            ensure!(
                !cache.cursor_job_owns(from) && !cache.cursor_job_owns(&to),
                "codex_carry_active_job"
            );
            for key in [from.as_str(), to.as_str()] {
                cache.refresh_header(key.to_owned(), None);
                if let Some(namespace) = namespace {
                    cache.memo_forget(&sampled_scan::codex_cursor::memo_key(namespace, key));
                }
                drop(cache.take(key));
            }
        }
        state_v2::carry_tail(
            index_path,
            &to,
            state_v2::PathCarry {
                from: from.clone(),
                scan_root: candidate.scan_root.clone(),
                head: rebound,
                inventory,
            },
        )?;
        self.rekey_account_custody(from, &to, Some(&candidate.scan_root));
        Ok(true)
    }

    pub(crate) fn has_pending_codex_carry(&self) -> Result<bool> {
        Ok(!state_v2::pending_carries(self)?.is_empty())
    }

    /// Align an owned committed baseline before local-hold/partial restoration.
    /// The paired stage is the authority; this never settles or copies ACKs.
    pub(crate) fn rehome_codex_carry_baseline(&mut self, working: &ScanIndex) -> Result<()> {
        for (to, carry) in state_v2::pending_carries(working)? {
            ensure!(
                !self.files.contains_key(&carry.from) || !self.files.contains_key(&to),
                "codex_carry_baseline_conflict"
            );
            self.rekey_account_custody(&carry.from, &to, Some(&carry.scan_root));
        }
        Ok(())
    }
}
