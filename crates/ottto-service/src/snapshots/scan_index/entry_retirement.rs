//! Scan-index entry retirement and retained lifetime facts.

use crate::snapshots::*;

impl ScanIndex {
    /// Retire only obligations made unfulfillable by positively proven absence.
    /// Codex protection retains the entry and its own lineage/receipt state.
    pub(in crate::snapshots) fn retire_absent_account_hold(
        &mut self,
        key: &str,
        members: &AccountMoveObservations,
    ) -> bool {
        if !self.claude_account_deferred_holds.contains_key(key) {
            return false;
        }
        // Reconciliation/hints may name an imported tail outside the view's
        // bounded prefix. Missing lookup coverage is uncertainty, never absence.
        if members
            .through
            .as_ref()
            .is_some_and(|last| key > last.as_str())
        {
            self.withheld_memo.reset_absence(key);
            return false;
        }
        let Some(walk) = self.traversal.as_ref() else {
            self.withheld_memo.reset_absence(key);
            return false;
        };
        let ambiguous =
            claude_index_path_family_member(Path::new(key)).is_some_and(|(_, member)| {
                members
                    .paths
                    .get(&member)
                    .is_some_and(|paths| paths.iter().any(|other| other != key))
            });
        if ambiguous
            || walk.counts.directory_entry_cap_exceeded_count != 0
            || walk.counts.unreadable_path_count != 0
        {
            if ambiguous {
                line_delivery_unselected("claude_code", UnselectedReason::WithheldAbsenceAmbiguous);
            }
            self.withheld_memo.reset_absence(key);
            return false;
        }
        // Keep the first NotFound across an unfinished later walk, but never
        // retire before that walk completes. No added walk or metadata read.
        if !walk.pending_directories.is_empty() {
            return false;
        }
        let Some(walk_window) = rfc3339_unix_seconds(&walk.census_window_end) else {
            self.withheld_memo.reset_absence(key);
            return false;
        };
        let parent = self
            .traversal
            .as_ref()
            .and_then(|walk| sampled_audit::absence_parent(Path::new(key), &walk.scan_roots));
        if !self
            .withheld_memo
            .absence_eligible(key, parent, walk_window)
        {
            return false;
        }
        // A decode hold keeps the entry, its obligation and memo: nothing is
        // released or disclosed as deleted while its stored record is unread.
        if self.decode_holds_file(key) {
            return false;
        }
        let census_record = self.claude_request_census.get(key).is_some();
        let protected = self
            .files
            .get(key)
            .is_some_and(ScanIndexEntry::codex_history_is_protected);
        let audit = self
            .files
            .get(key)
            .is_some_and(ScanIndexEntry::has_unverified_source);
        if audit {
            if protected {
                self.files
                    .get_mut(key)
                    .expect("audit entry")
                    .scan_identity_version = Some(LOCAL_SCAN_INDEX_IDENTITY_VERSION.into());
            } else {
                // Preserve incidence handling: retiring audit debt
                // does not itself grant authority to prune its fingerprints.
                self.retire_vanished_claude_audit_debt_entry(key);
            }
            crate::local_resource_diagnostics::audit_retired_absent("claude_code");
            disappearance_diagnostics::vanished(
                SnapshotSource::ClaudeCode,
                disappearance_diagnostics::Vanished::AuditDebtDropped,
            );
        }
        self.claude_account_deferred_holds.remove(key);
        self.withheld_memo.released_deleted(key);
        if !protected && !audit {
            self.remove_file_entry_unless_held(key);
        }
        if census_record && self.claude_request_census.get(key).is_none() {
            disappearance_diagnostics::vanished(
                SnapshotSource::ClaudeCode,
                disappearance_diagnostics::Vanished::RequestCensusRemoved,
            );
        }
        true
    }

    /// Retire a Claude entry whose file vanished beneath its
    /// still-present parent together with its unverified audit marker.
    /// Only the page merge calls this, and only for keys the scanner settled
    /// as such a removal; `remove_file_entry` keeps audit debt for every
    /// other caller. Codex-protected entries are never retired here. The
    /// key's snapshot fingerprints and account hold stay, because each
    /// removal path ends in the state main already reaches for the same key:
    /// main's reconciliation keeps an audit-debt entry and its fingerprints
    /// forever, so this path drops only the entry with its lifetime facts
    /// (`drop_file_entry`) and its marker, while a
    /// vanished entry without audit debt goes through `remove_file_entry`,
    /// which drops its fingerprints and hold just as main's reconciliation
    /// does at the next healthy terminal. The hold is later dropped by a
    /// complete census. Returns false, retiring nothing, for an entry
    /// without audit debt or one a decode hold keeps.
    pub(in crate::snapshots) fn retire_vanished_claude_audit_debt_entry(
        &mut self,
        key: &str,
    ) -> bool {
        if !self.persistence_available() || self.decode_holds_file(key) {
            return false;
        }

        if !self.files.get(key).is_some_and(|entry| {
            entry.has_unverified_source() && !entry.codex_history_is_protected()
        }) {
            return false;
        }
        self.drop_file_entry(key);
        self.terminal_jsonl_dispositions.remove(key);
        true
    }

    pub(in crate::snapshots) fn remove_file_entry(&mut self, key: &str) {
        self.remove_file_entry_unless_held(key);
    }

    /// Of `keys`, those whose entry holds a parsed, nonempty body witness that
    /// is not ACKed: deleting the file now loses that usage. Withheld-account
    /// keys keep their own deletion count. Taken before a vanished-key retirement.
    pub(in crate::snapshots) fn unacked_bodies<'a>(
        &self,
        keys: impl IntoIterator<Item = &'a String>,
    ) -> Vec<&'a String> {
        keys.into_iter()
            .filter(|key| {
                !self.claude_account_deferred_holds.contains_key(*key)
                    && self
                        .file_snapshot_fingerprints
                        .get(*key)
                        .is_some_and(|entities| !entities.is_empty())
                    && self.files.get(*key).is_some_and(|entry| {
                        entry.last_upload_body_witness.is_some()
                            && !claude_index_file_body_accepted(self, key, entry)
                    })
            })
            .collect()
    }

    /// Counts each of `unacked` the retirement removed; it holds or resends nothing.
    pub(in crate::snapshots) fn count_unacked_retired(
        &self,
        source: SnapshotSource,
        unacked: Vec<&String>,
    ) {
        for key in unacked
            .into_iter()
            .filter(|key| !self.files.contains_key(*key))
        {
            // The committed head carries the totals when the codec stores
            // them.
            let usage = tail_source::stored_usage(source, self, key);
            crate::local_resource_diagnostics::unacked_usage_lost_to_deletion(
                source.api_slug(),
                usage,
            );
        }
    }

    pub(in crate::snapshots) fn remove_file_entry_unless_held(&mut self, key: &str) {
        if !self.persistence_available() {
            return;
        }

        // Account debt leaves only through a resolving parse or F4. Generic
        // age/removal callers cannot bypass the per-key absence sequence.
        if self.claude_account_deferred_holds.contains_key(key) {
            return;
        }

        if self.decode_holds_file(key) {
            return;
        }
        if self
            .files
            .get(key)
            .is_some_and(ScanIndexEntry::has_unverified_source)
        {
            return;
        }
        self.drop_file_entry(key);
        self.terminal_jsonl_dispositions.remove(key);
        self.file_snapshot_fingerprints.remove(key);
        self.claude_account_deferred_holds.remove(key);
    }

    /// The one lifetime core of a positive-absence exit: the index entry and
    /// the facts that live exactly as long as it (confirmed-empty mark,
    /// request census, money marks, stored copy removals). Every exit calls
    /// it after its own guards; dispositions, fingerprints, holds and Codex
    /// proof stay with each caller. Nothing else ends a census record.
    pub(in crate::snapshots) fn drop_file_entry(&mut self, key: &str) {
        self.files.remove(key);
        self.confirmed_empty_files.remove(key);
        self.claude_request_census.remove(key);
        self.claude_money_birth_store.set_money_marks(key, 0);
        self.claude_copy_removals
            .forget(claude_money_birth_store::location_key(key));
    }

    /// Keep move history for 30 days after the last indexed or held member.
    pub(in crate::snapshots) fn prune_claude_money_births(&mut self, now: u64) {
        if self.claude_money_birth_store.is_empty() {
            return;
        }
        let members = self
            .files
            .keys()
            .map(String::as_str)
            .chain(self.decode_holds.file_keys())
            .filter_map(|path| {
                let member = claude_index_path_member_ref(Path::new(path))?;
                let session = match member.subagent_stem {
                    None => std::borrow::Cow::Borrowed(member.root),
                    Some(_) => std::borrow::Cow::Owned(member.into_owned().1),
                };
                Some((session, path))
            });
        self.claude_money_birth_store.prune(now, members);
    }

    /// Retire terminal JSONL dispositions whose file is no longer indexed.
    ///
    /// A disposition is only ever written together with the `files` entry for
    /// the same key, so a key with no entry means the path was renamed, deleted
    /// or reconciled away. Such a record can never be consulted again - a
    /// candidate at that path already takes `CandidateDecision::Parse` through
    /// the missing-entry arm - so dropping it is behaviour-neutral hygiene that
    /// stops this durable map from growing monotonically with every lossy
    /// transcript the user ever moves.
    ///
    /// This is also the whole bound, and it is structural rather than a cap.
    /// `record_terminal_jsonl_disposition` is called from exactly one place,
    /// inside the `parse_complete` block that inserts the `files` entry for the
    /// same `local_index_key` six lines later, and `remove_file_entry` drops
    /// both together; bounded census reconciliation removes from `files` alone,
    /// which is precisely the orphan this retain sweeps. So
    /// `terminal_jsonl_dispositions` is always a subset of `files` - at most
    /// one small fixed-shape record per transcript the traversal currently
    /// observes, alongside the strictly larger `ScanIndexEntry` the same key
    /// already costs. `committable_subset` preserves that inductively: it
    /// carries `previous.terminal_jsonl_dispositions` beside a `files` map that
    /// unions in all of `previous.files`, so a subset stays a subset across a
    /// partial commit. Whatever bounds `files` therefore bounds this map, and a
    /// separate cap on a strict subset of `files` could not bound the index. It
    /// could only evict a live record, which re-arms the child->parent reparse
    /// override for Codex (re-reading an oversized rollout every cycle) or
    /// silently drops that file's disclosed terminal loss for every source
    /// without one.
    pub(in crate::snapshots) fn prune_terminal_jsonl_dispositions(&mut self) {
        let files = &self.files;
        let holds = &self.decode_holds;
        self.terminal_jsonl_dispositions
            .retain(|key, _| files.contains_key(key) || holds.contains("files", key));
    }

    pub(in crate::snapshots) fn effective_upload_body_witness_revision_requires_adoption(
        &self,
        key: &str,
    ) -> bool {
        let active = self.active_effective_upload_body_witness_revision;
        active != 0
            && self.files.get(key).map_or(true, |entry| {
                let stored = entry.effective_upload_body_witness_revision;
                if self.active_effective_upload_body_witness_revision_monotone {
                    stored < active
                } else {
                    stored != active
                }
            })
    }

    /// Use the existing physical listing stamp, independent of parser, upload
    /// context or retry revisions. A refusal grants no transcript read.
    pub(in crate::snapshots) fn stale_refusal_holds_unchanged_input(
        &self,
        candidate: &CandidateFile,
    ) -> bool {
        let key = local_index_key(&candidate.path);
        self.file_snapshot_fingerprints
            .get(&key)
            .is_some_and(|fps| {
                fps.iter().any(|fp| {
                    self.reason_reoffer_cooldowns
                        .get(fp)
                        .is_some_and(|c| c.input_change_only)
                })
            })
            && self.files.get(&key).is_some_and(|entry| {
                let modified = Some(candidate.modified_unix_nanos);
                let stored = entry.modified_unix_nanos.or_else(|| {
                    modified.filter(|nanos| nanos / 1_000_000_000 == entry.modified_unix_seconds)
                });
                entry.same_stamp_with_mtime(
                    stored,
                    candidate.size_bytes,
                    modified,
                    Some(candidate.fingerprint_birth_nanos),
                    codex_fragment::Stamp::candidate(candidate),
                )
            })
    }
}
