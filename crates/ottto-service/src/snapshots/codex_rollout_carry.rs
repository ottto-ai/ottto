//! Proven Codex rollout path/encoding changes, before selection or retirement.
//! Logical progress and delivery witnesses move unchanged. Physical inventory
//! is independent: compression never certifies a replacement plaintext inode.
use super::sampled_scan::codex_cursor::OpenStamp;
use super::*;
use anyhow::{ensure, Context};

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
    ) -> Result<Option<(bool, state_v2::TailHead)>> {
        if state_v2::runtime_path(self)?.is_none() {
            return Ok(None);
        }
        let head = state_v2::load_head(
            self,
            key,
            <tail_source::codex::Codex as tail_source::TailSource>::REDUCTION_REVISION,
        )?;
        Ok(head
            .filter(|head| !head.metadata_only)
            .map(|head| (physical_matches(&head, metadata), head)))
    }

    /// Physical equality refines the ordinary decision without replacing its
    /// audit, evidence, exact-body/context or sidecar dependency authority.
    pub(super) fn codex_unchanged_decision(
        &self,
        candidate: &CandidateFile,
        stat: &fs::Metadata,
        metadata: &CodexTitleMetadata,
        now: u64,
        body_witness_adoption: bool,
    ) -> Result<Option<(CandidateDecision, Option<CandidateParseReason>)>> {
        let key = local_index_key(&candidate.path);
        let Some((true, head)) = self.codex_physical_matches(&key, stat)? else {
            return Ok(None);
        };
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
    ) -> (BTreeSet<String>, BTreeSet<String>) {
        let candidates = {
            let Some(walk) = self.traversal.as_ref() else {
                return Default::default();
            };
            let mut predecessors = BTreeMap::<String, Vec<(String, PathBuf)>>::new();
            for (from, entry) in &self.files {
                if let Some(owner) = codex_counting_version::proven_owner(entry) {
                    if let Some(root) = walk.owning_scan_root(Path::new(from)) {
                        predecessors
                            .entry(owner.to_owned())
                            .or_default()
                            .push((from.clone(), root.clone()));
                    }
                }
            }
            walk.codex_rollout_paths
                .iter()
                .filter_map(|key| {
                    let path = Path::new(key);
                    if self.files.contains_key(key)
                        || codex_file_join::shadowed_compressed_path(
                            path,
                            &walk.codex_rollout_paths,
                        )
                    {
                        return None;
                    }
                    let root = walk.owning_scan_root(path)?;
                    let home = &codex_file_join::member_home(root);
                    let possible = codex_session_id_candidates_from_path(path)
                        .into_iter()
                        .flat_map(|session| {
                            let owner = codex_protected_owner(&session);
                            predecessors.get(&owner).into_iter().flatten().filter_map(
                                move |(from, old_root)| {
                                    let old = Path::new(from);
                                    (codex_file_join::member_home(old_root) == *home
                                        && (absent(old)
                                            || codex_file_join::shadowed_compressed_path(
                                                old,
                                                &walk.codex_rollout_paths,
                                            )))
                                    .then(|| (from.clone(), old_root.clone(), session.clone()))
                                },
                            )
                        })
                        .collect::<Vec<_>>();
                    if possible.is_empty() {
                        return None;
                    }
                    Some((
                        codex_file_join::header_candidate(
                            root.clone(),
                            path.to_path_buf(),
                            &fs::symlink_metadata(path).ok()?,
                        ),
                        possible,
                    ))
                })
                .collect::<Vec<_>>()
        };
        let Ok(Some(route)) = state_v2::runtime_path(self) else {
            return Default::default();
        };
        let mut deferred = BTreeSet::new();
        let mut held = BTreeSet::new();
        for (candidate, possible) in candidates {
            let owners = possible
                .iter()
                .map(|(_, _, owner)| owner.clone())
                .collect::<BTreeSet<_>>();
            if self
                .carry_codex_rollout_with_cache(&route, &candidate, possible, sampling)
                .is_err()
            {
                deferred.insert(local_index_key(&candidate.path));
                // The predecessor's proven owner is the only publication scope
                // this failed carry can constrain. Unknown headers stay wildcard.
                held.extend(owners);
                if let Some(walk) = self.traversal.as_mut() {
                    walk.counts.causes.add(ownership::INVENTORY, 1);
                }
            }
        }
        (deferred, held)
    }

    /// Called once after discovery, before any selection or absence consumer.
    pub(super) fn carry_codex_rollout_with_cache(
        &mut self,
        index_path: &Path,
        candidate: &CandidateFile,
        possible: Vec<(String, PathBuf, String)>,
        sampling: Option<(
            &sampled_scan::SharedCache,
            Option<&crate::transcript_acquisition::Scope>,
        )>,
    ) -> Result<bool> {
        let to = local_index_key(&candidate.path);
        let home = codex_file_join::member_home(&candidate.scan_root);
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
                        && tail_source::certified_certificate(&head.body).is_ok(),
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
        let rebound = tail_source::carry_codex_head(
            index_path,
            old_root,
            old_path,
            &candidate.scan_root,
            &candidate.path,
            &head.body,
        )?;
        let inventory = state_v2::InventoryFacts {
            owner: owner.clone(),
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
        if let Some((cache, _)) = sampling {
            // A live job must finish or fail its ordinary path revalidation
            // before this pass can rehome its committed checkpoint.
            ensure!(
                !cache.cursor_job_owns(from) && !cache.cursor_job_owns(&to),
                "codex_carry_active_job"
            );
        }
        state_v2::carry_tail(
            self,
            &to,
            state_v2::PathCarry {
                from: from.clone(),
                scan_root: candidate.scan_root.clone(),
                head: rebound,
                inventory,
            },
        )?;
        if let Some((cache, namespace)) = sampling {
            for key in [from.as_str(), to.as_str()] {
                cache.refresh_header(key.to_owned(), None);
                if let Some(namespace) = namespace {
                    cache.memo_forget(&sampled_scan::codex_cursor::memo_key(namespace, key));
                }
                drop(cache.take(key));
            }
        }
        Ok(true)
    }
}
