//! Account binding and upload-context activation for the scan index.

use crate::snapshots::*;

impl ScanIndex {
    /// Records the process's first persistent load of this destination path.
    pub(in crate::snapshots) fn note_first_index_load(&self, path: &Path) -> bool {
        if !self.persistence_available() {
            return false;
        }
        static LOADED: std::sync::OnceLock<Mutex<BTreeSet<PathBuf>>> = std::sync::OnceLock::new();
        LOADED
            .get_or_init(|| Mutex::new(BTreeSet::new()))
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(path.to_path_buf())
    }

    pub(crate) fn local_codex_census_aggregates(
        &self,
    ) -> codex_scan_diagnostics::CensusIndexAggregates {
        let traversal = self.traversal.as_ref();
        let directory = traversal
            .and_then(|t| t.codex_join_directory_census.as_ref())
            .map(codex_file_join::DirectoryCensus::local_diagnostic_counts);
        let bounded = self.files.len() <= codex_scan_diagnostics::MAX_FENCED_CENSUS_ENTRIES
            && traversal.map_or(true, |t| {
                t.codex_rollout_paths.len() <= codex_scan_diagnostics::MAX_FENCED_CENSUS_ENTRIES
            });
        let mut result = codex_scan_diagnostics::CensusIndexAggregates {
            schema_version: self.schema_version,
            generation: self.generation,
            file_count: self.files.len() as u64,
            traversal_present: traversal.is_some(),
            pending_directories: traversal.map(|t| t.pending_directories.len() as u64),
            pending_candidates: traversal.map(|t| t.pending_candidates.len() as u64),
            directory_census_present: directory.is_some(),
            directory_census_stable: directory.map(|(stable, _)| stable),
            directory_count: directory.map(|(_, count)| count),
            reconciliation_started: traversal.map(|t| t.reconciliation_started),
            watcher_hint_seen: traversal.map(|t| t.watcher_hint_seen),
            retry_attempt: traversal.map(|t| t.unhealthy_retry_attempt),
            retry_not_before_unix_seconds: traversal
                .and_then(|t| t.unhealthy_retry_not_before_unix_seconds),
            protected_aggregation_complete: bounded,
            protected_history: bounded.then_some(0),
            protected_absent_from_observed_rollouts: (bounded && traversal.is_some()).then_some(0),
            protected_absent_valid_owner: (bounded && traversal.is_some()).then_some(0),
        };
        if bounded {
            // One capped pass, borrowed set membership, no index/key clone or IO.
            for (key, entry) in &self.files {
                if !entry.codex_history_is_protected() {
                    continue;
                }
                *result.protected_history.as_mut().expect("bounded") += 1;
                if traversal.is_some_and(|t| !t.codex_rollout_paths.contains(key)) {
                    *result
                        .protected_absent_from_observed_rollouts
                        .as_mut()
                        .expect("traversal") += 1;
                    if entry
                        .codex_protected_owner
                        .as_deref()
                        .is_some_and(valid_codex_protected_owner)
                    {
                        *result
                            .protected_absent_valid_owner
                            .as_mut()
                            .expect("traversal") += 1;
                    }
                }
            }
        }
        result
    }

    /// Attach only the owner proved for this session. A missing or conflicting
    /// Claude revision is held for a later complete scan; the durable proof
    /// remains intact.
    pub(crate) fn bind_session_accounts(
        &mut self,
        source: SnapshotSource,
        machine_id: &str,
        snapshots: &mut [SnapshotItem],
        codex_homes: &[crate::agent_status::CodexHomeBinding],
    ) -> BTreeSet<String> {
        self.bind_session_accounts_with_mixed(
            source,
            machine_id,
            snapshots,
            codex_homes,
            (&[], &mut [0; 9]),
            &claude_request_accounts::MixedUploads::default(),
        )
    }

    /// `codex_slots`: (account, workspace, login cause) a Codex creator may name.
    pub(crate) fn bind_session_accounts_with_mixed(
        &mut self,
        source: SnapshotSource,
        machine_id: &str,
        snapshots: &mut [SnapshotItem],
        codex_homes: &[crate::agent_status::CodexHomeBinding],
        (codex_slots, creator_counts): (&[(String, String, usize)], &mut [u64; 9]),
        mixed: &claude_request_accounts::MixedUploads,
    ) -> BTreeSet<String> {
        let mut deferred = BTreeSet::new();
        for item in snapshots {
            let session_id = &item.source_session_id;
            let key = sha256_hex(&["session_owner:v1", machine_id, session_id]);
            let existing = self.session_account_bindings.get(&key);
            match source {
                SnapshotSource::Codex => {
                    let mut creator_slot = None;
                    if !codex_rows_all(item, |mode| matches!(mode, Some("oauth" | "chatgpt"))) {
                        // No recorded mode: only the creator's slot names a session
                        // never emitted before, never the home (forward only).
                        if !codex_rows_all(item, |mode| mode.is_none()) {
                            set_session_account_hash(item, None);
                            continue;
                        }
                        let decided = match (codex_creator_pair(item), existing) {
                            (None, _) => Err(CREATOR_NO_PAIR),
                            (Some((account, _)), Some(owner))
                                if owner.account_identifier_hash == account =>
                            {
                                Ok(None)
                            }
                            (Some(_), Some(_)) => Err(CREATOR_DIFFERENT_OWNER),
                            (Some(_), None) if !self.codex_file_never_emitted(item) => {
                                Err(CREATOR_PREVIOUSLY_UPLOADED)
                            }
                            (Some((account, workspace)), None) => {
                                codex_creator_slot(account, workspace, codex_slots).map(Some)
                            }
                        };
                        match decided {
                            Ok(owner) => {
                                creator_counts[CREATOR_NAMED] += u64::from(owner.is_some());
                                creator_slot = owner;
                            }
                            Err(cause) => {
                                creator_counts[cause] += 1;
                                set_session_account_hash(item, None);
                                continue;
                            }
                        }
                    }
                    // An explicit creator-negative is a source decision, not
                    // the legacy absence of an optional witness. Neither a
                    // cached owner nor today's home login can override it.
                    if item
                        .session_account_evidence
                        .as_ref()
                        .is_some_and(|evidence| {
                            evidence.evidence_source == "codex_creator_header:v1"
                                && matches!(
                                    evidence.identity_disposition,
                                    Some("missing" | "conflict")
                                )
                        })
                    {
                        set_session_account_hash(item, None);
                        continue;
                    }
                    let owner = existing
                        .cloned()
                        .or(creator_slot)
                        .or_else(|| self.codex_owner_for_item(item, codex_homes));
                    if let Some(owner) = owner {
                        self.session_account_bindings
                            .entry(key.clone())
                            .or_insert_with(|| owner.clone());
                        set_session_account_hash(item, Some(&owner.account_identifier_hash));
                    }
                }
                SnapshotSource::ClaudeCode
                    if item.provenance.collector == {
                        #[cfg(not(test))]
                        {
                            claude_request_identity::COLLECTOR
                        }
                        #[cfg(test)]
                        {
                            claude_request_identity::cycle_contract(true)
                        }
                    } =>
                {
                    // Contract-5 row identities are request facts, never the
                    // creator/owner: no row login, even one equal to the owner,
                    // admits the body, and none binds an unbound session. A bound
                    // session admits only this scan's exact qualified body, and
                    // only when creator proof is absent or names the retained
                    // owner; a contradicting creator defers. The owner is never
                    // rewritten.
                    let Some(owner) = existing else { continue };
                    let creator = item
                        .session_account_evidence
                        .as_ref()
                        .and_then(|evidence| evidence.account_identifier_hash.as_deref());
                    if !(mixed.permits_request_identity(item)
                        && creator.map_or(true, |creator| creator == owner.account_identifier_hash))
                    {
                        deferred.insert(session_id.clone());
                    }
                }
                SnapshotSource::ClaudeCode => {
                    let observed = exact_session_account_hash(item);
                    match (existing, observed.as_deref()) {
                        (Some(owner), Some(hash)) if owner.account_identifier_hash == hash => {}
                        (Some(owner), _)
                            if mixed.permits(item)
                                && item.session_account_evidence.as_ref().and_then(
                                    |evidence| evidence.account_identifier_hash.as_deref(),
                                ) == Some(owner.account_identifier_hash.as_str()) =>
                        {
                            // A genuine complete mixed body may replace current
                            // usage without rewriting its retained creator/owner.
                            // Eligibility is scan-local and exact-body-bound;
                            // neither marker-only imports nor restart restore it.
                        }
                        // A body whose owner
                        // account this scan cleared for a non-discard unhealthy
                        // read uploads Unknown now; the owner is never rewritten.
                        (Some(owner), None)
                            if mixed.permits_unhealthy_unknown(
                                item,
                                &owner.account_identifier_hash,
                            ) => {}
                        (Some(_), _) => {
                            deferred.insert(session_id.clone());
                        }
                        (None, Some(hash)) => {
                            self.session_account_bindings.insert(
                                key.clone(),
                                SessionAccountBinding {
                                    account_identifier_hash: hash.to_string(),
                                    workspace_identifier_hash: None,
                                },
                            );
                        }
                        (None, None) => {}
                    }
                }
                SnapshotSource::Pi => {}
            }
        }
        deferred
    }

    /// `item`'s one file has emitted no snapshot before this scan.
    fn codex_file_never_emitted(&self, item: &SnapshotItem) -> bool {
        let fingerprint = item.source_file_fingerprint.as_deref();
        let mut keys = self
            .files
            .iter()
            .filter(|(_, entry)| Some(entry.source_file_fingerprint.as_str()) == fingerprint);
        let (Some((key, _)), None) = (keys.next(), keys.next()) else {
            return false;
        };
        // Compressed rollouts are cold history, even when their new path
        // has no emission record. Forward-only naming leaves them Unknown.
        if is_compressed_codex_rollout(Some(Path::new(key)), None) {
            return false;
        }
        let emitted = self.file_snapshot_fingerprints.get(key);
        emitted.map_or(true, BTreeSet::is_empty)
    }

    fn codex_owner_for_item(
        &self,
        item: &SnapshotItem,
        homes: &[crate::agent_status::CodexHomeBinding],
    ) -> Option<SessionAccountBinding> {
        let started = OffsetDateTime::parse(item.source_started_at.as_deref()?, &Rfc3339)
            .ok()?
            .unix_timestamp_nanos();
        let fingerprint = item.source_file_fingerprint.as_deref()?;
        let mut paths = self
            .files
            .iter()
            .filter(|(_, entry)| entry.source_file_fingerprint == fingerprint)
            .map(|(path, _)| Path::new(path));
        let path = paths.next()?;
        if paths.next().is_some() {
            return None;
        }
        let mut matches = homes.iter().filter(|home| {
            (path.starts_with(home.home.join("sessions"))
                || path.starts_with(home.home.join("archived_sessions")))
                && home
                    .auth_modified_at
                    .duration_since(UNIX_EPOCH)
                    .is_ok_and(|age| age.as_nanos() <= started.max(0) as u128)
        });
        let home = matches.next()?;
        if matches.next().is_some() {
            return None;
        }
        Some(SessionAccountBinding {
            account_identifier_hash: home.account_identifier_hash.clone(),
            workspace_identifier_hash: Some(home.workspace_identifier_hash.clone()),
        })
    }

    /// Delivery proofs only: no acquisition-reuse decision reads it.
    pub fn activate_upload_context(&mut self, fingerprint: String) {
        self.active_upload_context_fingerprint = Some(fingerprint);
    }

    /// Select before taking the committed baseline and scanning. Nonzero
    /// revisions adopt each unchanged file once; zero opts out of adoption.
    /// A revision with no history-policy row is refused: the previous active
    /// revision stays, and one local alarm is raised and counted.
    pub fn activate_effective_upload_body_witness_revision(&mut self, revision: u64) {
        // A refused revision keeps only the previous revision and its flag;
        // the per-pass resets below run either way (StateMissing R6).
        if claude_history_upgrade::admit_activation(
            revision,
            self.active_effective_upload_body_witness_revision,
        ) {
            self.active_effective_upload_body_witness_revision = revision;
            self.active_effective_upload_body_witness_revision_monotone = false;
        }
        self.effective_upload_body_witness_revision_excluded_source_files
            .clear();
        self.claude_history_emission = HistoryEmission::default();
        self.claude_reemission_exclusions.begin_pass();
    }

    /// Claude only (MONEY P2), after activating: re-read a file only when its
    /// stored revision is below the active one (a missing stored value is 0),
    /// so a newer stored revision is never re-read by an older build.
    pub fn adopt_effective_upload_body_witness_revision_monotonically(&mut self) {
        self.active_effective_upload_body_witness_revision_monotone = true;
    }

    /// Exclude every source file containing a locally held item before finalizing.
    /// A mixed group retains its old revision until all items can use the projection.
    pub fn exclude_effective_upload_body_witness_revision_for_source_files(
        &mut self,
        source_files: &BTreeSet<String>,
    ) {
        self.effective_upload_body_witness_revision_excluded_source_files
            .extend(source_files.iter().cloned());
    }

    /// Claude only, before scanning: read the local list of sessions the
    /// adoption re-read must not re-emit. A list that was installed once and
    /// is now missing pauses adoption and raises the local alarm.
    /// A member-only line is closed over its indexed family root.
    pub fn load_claude_reemission_exclusions(&mut self, support_dir: &Path) {
        let mut exclusions = ReemissionExclusions::load(support_dir);
        exclusions.close_over_roots(self.files.keys().filter_map(|key| {
            let member = claude_index_path_member_ref(Path::new(key))?;
            Some((member.root, member.subagent_stem?))
        }));
        self.claude_reemission_exclusions = exclusions;

        let mut unlisted = Vec::new();
        for key in self.files.keys() {
            if self.claude_family_listed(key) {
                if claude_index_path_member_ref(Path::new(key)).is_some() {
                    let location = claude_money_birth_store::location_key(key);
                    let marks = self.claude_money_birth_store.money_marks(location);
                    self.claude_money_birth_store
                        .set_money_marks(key, marks | claude_request_money::e2::money_mark::LEGACY);
                }
            } else {
                let location = claude_money_birth_store::location_key(key);
                let marks = self.claude_money_birth_store.money_marks(location);
                if marks & claude_request_money::e2::money_mark::LEGACY != 0
                    && !self.claude_reemission_exclusions.pauses_adoption()
                    && self.active_effective_upload_body_witness_revision == 3
                {
                    unlisted.push((
                        key.clone(),
                        marks & !claude_request_money::e2::money_mark::LEGACY,
                    ));
                }
            }
        }
        // The legacy money-rule mark converges even if the file had
        // already reached revision 3 before it was listed. Clear it in
        // the same save as re-owing, so the existing history gate owns
        // the single paced read and retries remain owed.
        for (key, marks) in unlisted {
            self.re_owe_effective_upload_body_witness_revision(&key, 2);
            self.claude_money_birth_store.set_money_marks(&key, marks);
        }

        if let Some(cause) = self.claude_reemission_exclusions.missing_cause() {
            crate::local_resource_diagnostics::claude_reemission_list_missing(cause.as_str());
        }
    }
}
